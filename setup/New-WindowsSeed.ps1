#requires -Version 5.1
<#
    Builds the unattended-setup seed for the Windows endpoint.

    Windows Setup scans attached media for autounattend.xml at the root, so this only needs to
    be a plain data ISO. It carries two files:

        autounattend.xml            partitioning, the local account, the first logon command
        Initialize-LabEndpoint.ps1  what that command runs

    The second exists because the alternative is a four hundred character PowerShell one-liner
    escaped into XML, which is what this used to be and which nobody can read or change safely.

    The ISO carries the local account password in clear, which is how autounattend works. It is
    written into .lab-secrets and never committed.

        .\New-WindowsSeed.ps1
        .\New-WindowsSeed.ps1 -ImageName 'Windows 11 Pro' -ProductKey W269N-WFGWX-YVC9B-4J6C9-T83GX
#>
[CmdletBinding()]
param(
    [ValidateSet('lean', 'full')][string]$Profile,
    [ValidateSet('hyperv', 'virtualbox')][string]$Backend,
    # The edition inside your ISO, as the image list names it. Leave it unset for an ISO that
    # holds one edition, which includes the free Windows 11 Enterprise evaluation image; Setup
    # then installs the only thing there is. Set it for a multi-edition retail or VL ISO, where
    # Setup would otherwise stop on the edition picker and wait for a human.
    [string]$ImageName,
    # Leave unset for the evaluation image, which needs no key and rejects one. Microsoft's
    # published generic Volume License Setup Key for Windows 11 Pro is
    # W269N-WFGWX-YVC9B-4J6C9-T83GX; it selects the edition and activates nothing, so the guest
    # runs unactivated, which is fine for a lab that gets deleted.
    [string]$ProductKey,
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
. (Join-Path $PSScriptRoot 'LabIso.ps1')

$config = if ($Profile) { Get-LabConfig -Profile $Profile } else { Get-LabConfig }
$vms    = if ($Profile) { Get-LabVms -Profile $Profile }    else { Get-LabVms }
if (-not $Backend) { $Backend = $config.backend }
if (-not $vms.Contains('WAZUH-WIN')) {
    throw "The $($config.profile) profile has no Windows endpoint, so there is nothing to seed. Use -Profile full."
}
# An ISO that needs -ImageName is a multi-edition one, and a multi-edition retail ISO also
# stops Setup on the product key page unless the answer file carries a key. That failure
# looks like nothing at all: the guest boots, writes not one byte to its disk, and sits
# there. Worth a warning rather than an hour of wondering why the disk is still empty.
if ($ImageName -and -not $ProductKey) {
    Write-Warning ('No -ProductKey given. If this is a retail multi-edition ISO, Setup will ' +
        'stop on the product key page and wait. The generic Pro Setup key is ' +
        'W269N-WFGWX-YVC9B-4J6C9-T83GX. An evaluation image needs no key and rejects one.')
}

$vm = $vms['WAZUH-WIN']
$net = $config.network

$secrets = Get-LabPath Secrets
if (-not $OutputPath) { $OutputPath = Get-LabPath Seeds }

$password = (Get-Content -LiteralPath (Join-Path $secrets 'console-password.txt') -Raw).Trim()
if ($password -notmatch '^[A-Za-z0-9]+$') {
    throw 'The console password must be alphanumeric so it is safe to embed in XML unescaped. Run New-LabSecrets.ps1.'
}
$publicKey = (Get-Content -LiteralPath (Join-Path $secrets 'lab_ed25519.pub') -Raw).Trim()
if (-not $publicKey.StartsWith('ssh-')) {
    throw 'The public key in .lab-secrets does not look like one. Run New-LabSecrets.ps1.'
}

$user = $config.guest.user
$labMac = Get-LabMacAddress -Address $vm.Address -Separator '-'
$dns = ($net.dns -join ',')

# ---- what runs at first logon ------------------------------------------------------------------
#
# Kept as a file on the seed rather than inlined into the XML. Anything here can be read, diffed
# and fixed; the same logic escaped into a <CommandLine> element cannot.

$firstLogon = @"
#requires -Version 5.1
<#
    Runs once, at the Windows endpoint's first logon, from the unattend seed.

    Three jobs: put the endpoint on its lab address, make it reachable over SSH the same way
    the Linux guests are, and let nothing else in.

    SSH rather than PowerShell Direct. PowerShell Direct is a Hyper-V feature with no
    VirtualBox equivalent, so the dashboard could only ever have reached this endpoint on one
    of the two backends. OpenSSH Server is in Windows as an optional capability and works on
    both.
#>
`$ErrorActionPreference = 'Stop'
`$log = 'C:\Windows\Temp\lab-firstlogon.log'
function Write-Step { param([string]`$Message) Add-Content -Path `$log -Value ("{0}  {1}" -f (Get-Date -Format s), `$Message) }

Write-Step 'start'

# ---- the lab address ---------------------------------------------------------------------------
#
# Matched on the MAC the host assigned, not on "the first adapter that is Up". On VirtualBox
# there are two adapters and the other one is the internet; on Hyper-V there is one, but the
# adapter can still report Down for a few seconds after logon, and the old code's answer to
# that was to take whatever it found first.

`$adapter = `$null
for (`$i = 0; `$i -lt 30 -and -not `$adapter; `$i++) {
    `$adapter = Get-NetAdapter | Where-Object { `$_.MacAddress -eq '$labMac' } | Select-Object -First 1
    if (-not `$adapter) { Start-Sleep -Seconds 2 }
}
if (-not `$adapter) {
    Write-Step 'no adapter with MAC $labMac; leaving the network alone'
} else {
    Write-Step ('adapter {0} (index {1})' -f `$adapter.Name, `$adapter.ifIndex)
    Set-NetIPInterface -InterfaceIndex `$adapter.ifIndex -Dhcp Disabled
    New-NetIPAddress -InterfaceIndex `$adapter.ifIndex -IPAddress '$($vm.Address)' ``
        -PrefixLength $($net.prefixLength) -DefaultGateway '$($net.gateway)'
    Set-DnsClientServerAddress -InterfaceIndex `$adapter.ifIndex -ServerAddresses $dns
    Write-Step 'address set'
}

# ---- OpenSSH Server ----------------------------------------------------------------------------

# The capability comes from Windows Update. On 25H2 it took five and a half minutes and wrote
# nothing until it returned, so the log says so first rather than appearing to stop here.
Write-Step 'installing OpenSSH Server from Windows Update, which takes several minutes'
`$capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
if (`$capability -and `$capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name `$capability.Name | Out-Null
    Write-Step 'OpenSSH Server installed'
}
Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd
Write-Step 'sshd running'

# PowerShell rather than cmd, so the dashboard's remote calls read the same on both endpoints.
New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell ``
    -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null

# An administrator's key does not live in their profile on Windows. sshd reads this one file for
# every member of the Administrators group, and refuses it unless only Administrators and SYSTEM
# can write it.
`$adminKeys = 'C:\ProgramData\ssh\administrators_authorized_keys'
Set-Content -Path `$adminKeys -Value '$publicKey' -Encoding ascii
`$acl = Get-Acl -Path `$adminKeys
`$acl.SetAccessRuleProtection(`$true, `$false)
@(`$acl.Access) | ForEach-Object { [void]`$acl.RemoveAccessRule(`$_) }
foreach (`$who in 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') {
    `$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(`$who, 'FullControl', 'Allow')))
}
Set-Acl -Path `$adminKeys -AclObject `$acl
Write-Step 'key installed'

# ---- the firewall ------------------------------------------------------------------------------
#
# The endpoint answers on 22 to this host and to nothing else. The Linux guests get the same
# treatment from ufw in install-agent.sh.

Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name 'Wazuh-Lab-SSH' -DisplayName 'OpenSSH from the lab host' ``
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow ``
    -LocalPort 22 -RemoteAddress '$($net.gateway)' | Out-Null
Write-Step 'firewall scoped to $($net.gateway)'

Write-Step 'done'
"@

# ---- autounattend.xml ----------------------------------------------------------------------------

# Finds the seed by volume label rather than by drive letter, which Setup assigns and nothing
# here can predict. The ampersand is escaped because this ends up inside an XML element.
$launch = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "&amp; ((Get-Volume -FileSystemLabel LABSEED).DriveLetter + '':\Initialize-LabEndpoint.ps1'')"'

# Omitted entirely when no edition was named. An ISO with one image installs it; naming an
# edition that is not in the ISO fails the install, which is a worse default than not naming one.
$installFrom = ''
if ($ImageName) {
    $installFrom = @"

          <InstallFrom>
            <MetaData wcm:action="add"><Key>/IMAGE/NAME</Key><Value>$ImageName</Value></MetaData>
          </InstallFrom>
"@
}

# Likewise. The evaluation image rejects a key, and a Pro ISO needs one to skip the prompt.
#
# Named $productKeyXml and not $productKey because PowerShell does not distinguish case in a
# variable name: $productKey and the $ProductKey parameter are one variable, so clearing it
# here threw the key away and the test below then never fired. -ProductKey silently did
# nothing, Setup stopped on the product key page, and the guest sat there with an empty disk.
$productKeyXml = ''
if ($ProductKey) {
    $productKeyXml = @"

        <ProductKey><Key>$ProductKey</Key><WillShowUI>OnError</WillShowUI></ProductKey>
"@
}

$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <DiskConfiguration>
        <WillShowUI>OnError</WillShowUI>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>$installFrom
          <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
          <WillShowUI>OnError</WillShowUI>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>$productKeyXml
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <ComputerName>$($vm.Hostname)</ComputerName>
      <TimeZone>$($config.guest.timezone)</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <!-- Locale again, and not a copy-paste of the windowsPE block above. The WinPE
         component covers the installer; without this one OOBE opens on "Is this the right
         country or region?" and then the keyboard layout, and waits, whatever every
         Hide element below says. Setup caches this file and applies the rest of the pass
         on its own, so those two screens were the whole of what needed a human. -->
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>$user</Name>
            <DisplayName>$user</DisplayName>
            <Group>Administrators</Group>
            <Password><Value>$password</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Username>$user</Username>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
        <Password><Value>$password</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Description>Lab address, OpenSSH Server, firewall</Description>
          <CommandLine>$launch</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"@

# ---- build the ISO -------------------------------------------------------------------------------

$staging = Join-Path ([IO.Path]::GetTempPath()) 'labseed-windows'
if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging | Out-Null

# CRLF, unlike the cloud-init seeds. Both files here are read by Windows.
[IO.File]::WriteAllText((Join-Path $staging 'autounattend.xml'), $xml, (New-Object Text.UTF8Encoding $false))
[IO.File]::WriteAllText((Join-Path $staging 'Initialize-LabEndpoint.ps1'), $firstLogon, (New-Object Text.UTF8Encoding $false))

# Both checked here rather than halfway through a Windows install, where the only symptom is a
# guest sitting on a setup screen waiting for a keyboard.
[void][xml](Get-Content -LiteralPath (Join-Path $staging 'autounattend.xml') -Raw)
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $staging 'Initialize-LabEndpoint.ps1'), [ref]$null, [ref]$parseErrors)
if ($parseErrors) {
    throw ("The generated first logon script does not parse:`n  {0}" -f (($parseErrors | ForEach-Object { $_.Message }) -join "`n  "))
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$iso = Join-Path $OutputPath 'windows-unattend.iso'
New-LabDataIso -SourceDirectory $staging -IsoPath $iso -VolumeName 'LABSEED'
Remove-Item -LiteralPath $staging -Recurse -Force

Write-Output ("windows-unattend.iso   {0} bytes  {1}  {2}" -f (Get-Item -LiteralPath $iso).Length, $vm.Hostname, $vm.Address)
Write-Output ''
Write-Output ("XML and first logon script both validated. Built for {0}, adapter {1}." -f $Backend, $labMac)
if (-not $ImageName) {
    Write-Output 'No edition named. Setup will install the only image in the ISO; pass -ImageName for a multi-edition one.'
}
Write-Output 'Next: setup\New-Lab.ps1 -WindowsIso <your Windows 11 ISO>'
