#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManagerAddress,
    [Parameter(Mandatory)][string]$AgentKeyFile,
    [string]$ExpectedComputerName = 'WAZUH-WIN'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [Environment]::Is64BitProcess) { throw 'Run 64-bit Windows PowerShell.' }
if ($env:COMPUTERNAME -ine $ExpectedComputerName) { throw "Run this on the lab endpoint $ExpectedComputerName." }
$address = $null
if (-not [Net.IPAddress]::TryParse($ManagerAddress, [ref]$address) -or $address.AddressFamily -ne 'InterNetwork') {
    throw 'Use the manager IPv4 address.'
}
$key = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $AgentKeyFile).Path).Trim()
if ($key -notmatch '^\d{3,}\s+wazuh-windows\s+\S+\s+[a-fA-F0-9]{64}$') { throw 'Expected the client.keys entry for wazuh-windows.' }
$state = Join-Path $env:ProgramData 'WazuhLab'
New-Item -ItemType Directory -Path $state -Force | Out-Null
& icacls.exe $state /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the lab state directory.' }
$version = '4.14.7'
$agentDir = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$configPath = Join-Path $agentDir 'ossec.conf'
if (-not (Test-Path -LiteralPath $configPath)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $msi = Join-Path $state "wazuh-agent-$version-1.msi"
    Invoke-WebRequest -UseBasicParsing -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$version-1.msi" -OutFile $msi
    $signature = Get-AuthenticodeSignature -FilePath $msi
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Wazuh') {
        throw 'The installer does not have a valid Wazuh signature.'
    }
    $install = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru -WindowStyle Hidden
    if ($install.ExitCode -notin @(0, 3010)) { throw "Agent installation failed with code $($install.ExitCode)." }
}
# ProductVersion reports a leading "v" (for example v4.14.7), so compare without it.
$installed = (Get-Item (Join-Path $agentDir 'wazuh-agent.exe')).VersionInfo.ProductVersion
if ($installed.TrimStart('v', 'V') -notlike "$version*") { throw "Expected Wazuh $version; installed version is $installed." }
Stop-Service WazuhSvc -ErrorAction SilentlyContinue
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
Copy-Item -LiteralPath $configPath -Destination (Join-Path $state "ossec-$stamp.conf")
& auditpol.exe /backup "/file:$state\audit-$stamp.csv" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not back up audit policy.' }
$settings = @(
    @('{0CCE9215-69AE-11D9-BED3-505054503030}', '/failure:enable'),
    @('{0CCE9235-69AE-11D9-BED3-505054503030}', '/success:enable'),
    @('{0CCE9227-69AE-11D9-BED3-505054503030}', '/success:enable')
)
foreach ($setting in $settings) {
    & auditpol.exe /set "/subcategory:$($setting[0])" $setting[1] | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not configure audit subcategory $($setting[0])." }
}
# Wazuh permits more than one ossec_config element in the same file.
$xml = New-Object Xml.XmlDocument
$xml.PreserveWhitespace = $true
$xml.LoadXml('<document>' + [IO.File]::ReadAllText($configPath) + '</document>')
$root = $xml.SelectSingleNode('/document/ossec_config')
if ($null -eq $root) { throw 'The installed agent configuration is invalid.' }
foreach ($node in @($xml.SelectNodes('/document/ossec_config/client'))) { [void]$node.ParentNode.RemoveChild($node) }
$client = $xml.CreateDocumentFragment()
$client.InnerXml = "<client><server><address>$ManagerAddress</address><port>1514</port><protocol>tcp</protocol></server><enrollment><enabled>no</enabled></enrollment></client>"
[void]$root.AppendChild($client)
foreach ($node in @($xml.SelectNodes('/document/ossec_config/localfile[location="Security"]'))) { [void]$node.ParentNode.RemoveChild($node) }
$channel = $xml.CreateDocumentFragment()
$channel.InnerXml = '<localfile><location>Security</location><log_format>eventchannel</log_format><query>Event/System[EventID=4625 or EventID=4720 or EventID=4698]</query></localfile>'
[void]$root.AppendChild($channel)
foreach ($node in @($xml.SelectNodes('/document/ossec_config/active-response'))) { [void]$node.ParentNode.RemoveChild($node) }
$response = $xml.CreateDocumentFragment()
$response.InnerXml = '<active-response><disabled>yes</disabled></active-response>'
[void]$root.AppendChild($response)
$utf8 = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText($configPath, $xml.DocumentElement.InnerXml, $utf8)
[IO.File]::WriteAllText((Join-Path $agentDir 'client.keys'), $key + "`n", $utf8)
& icacls.exe (Join-Path $agentDir 'client.keys') /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the agent key file.' }
Start-Service WazuhSvc
# /get does not accept a wildcard subcategory; enumerate by category instead, which still
# reports every subcategory and its effective setting.
& auditpol.exe /get /category:* /r | Set-Content (Join-Path $state "audit-effective-$stamp.csv")
if ($LASTEXITCODE -ne 0) { throw 'Could not record the effective audit policy.' }
Write-Output 'Windows agent configured. Verify its connection in Wazuh before running scenarios.'
