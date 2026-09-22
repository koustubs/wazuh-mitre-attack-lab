#requires -Version 5.1
<#
    Enrols the profile's endpoints against the manager.

    For each endpoint: collect its key from the manager, copy the key and the installer across,
    and run the installer there. The key never touches the repository and is deleted from this
    host as soon as it has been delivered.

    The deployment guide asked you to do this by hand, once per endpoint, which is four SSH
    sessions and a file you have to be careful with. The copying is a chore; what is not a chore
    is the privileged install on the endpoint, so that still asks you for the console password.
    Have it ready. The dashboard's credentials panel will show it, or it is in
    .lab-secrets\console-password.txt.

    Run it after manager\configure-manager.sh, which is what creates the identities.

        .\Install-LabAgents.ps1
        .\Install-LabAgents.ps1 -Only WAZUH-LINUX
#>
[CmdletBinding()]
param(
    [ValidateSet('lean', 'full')][string]$Profile,
    # One endpoint rather than all of them, for when the second one failed and the first did not.
    [string[]]$Only
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabConfig.ps1')

$config = if ($Profile) { Get-LabConfig -Profile $Profile } else { Get-LabConfig }
$vms    = if ($Profile) { Get-LabVms -Profile $Profile }    else { Get-LabVms }

$manager = $vms['WAZUH-MANAGER']
$user = $config.guest.user
$keyPath = Join-Path (Get-LabPath Secrets) 'lab_ed25519'
if (-not (Test-Path -LiteralPath $keyPath)) {
    throw "No SSH key at $keyPath. Run setup\New-LabSecrets.ps1."
}
$ssh = Get-LabSshOptions -KeyPath $keyPath

$endpoints = @(
    foreach ($name in $vms.Keys) {
        if ($name -eq 'WAZUH-MANAGER') { continue }
        if (-not $vms[$name].AgentName) { continue }
        if ($Only -and $name -notin $Only) { continue }
        $vms[$name]
    }
)
if ($endpoints.Count -eq 0) {
    throw "Nothing to enrol. The $($config.profile) profile builds no endpoint matching that."
}

# Somewhere outside the repository. A key that lands in the working tree is a key that can be
# committed, and the whole point of .lab-secrets being gitignored is that this never happens.
$staging = Join-Path ([IO.Path]::GetTempPath()) ('lab-agent-keys-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging | Out-Null

function Invoke-Ssh {
    <#
        Runs ssh and leaves its exit code in $LASTEXITCODE. Deliberately returns nothing.

        Returning $LASTEXITCODE reads well and does not work, because it makes the caller write
        "$code = Invoke-Ssh ...", and assigning the result of a native command is what tells
        PowerShell to give that command a pipe instead of the console. Two things broke at once,
        and neither looked like the other.

        The sudo prompt on the endpoint went into the pipe rather than onto the screen, so the
        one step this script documents as stopping and waiting for you gave no sign that it was
        waiting, and sudo timed out on a password nobody knew to type.

        And $code came back as ssh's captured output with the exit code appended to it, so the
        failure message formatted the first line of that output in place of the number:

            the installer exited [sudo] password for labadmin: .

        which names neither the failure nor the exit code.

        Left unassigned, the native process inherits the console, the prompt appears, and typing
        at it works. The caller reads $LASTEXITCODE on the next line.
    #>
    param([string]$Address, [string]$Command, [switch]$Tty)
    $sshArgs = @($ssh)
    if ($Tty) { $sshArgs += '-t' }
    $sshArgs += @(('{0}@{1}' -f $user, $Address), $Command)
    & ssh.exe @sshArgs
}

try {
    Write-Host ("Enrolling {0} endpoint(s) against the manager at {1}." -f $endpoints.Count, $manager.Address)
    Write-Host ''

    $failed = @()
    foreach ($endpoint in $endpoints) {
        $agent = $endpoint.AgentName
        Write-Host ("{0}  ({1} at {2})" -f $endpoint.Name, $agent, $endpoint.Address)

        # 1. The key, from where configure-manager.sh left a copy the lab account can read.
        $localKey = Join-Path $staging ($agent + '.key')
        $remoteKey = ('{0}@{1}:~/wazuh-lab-keys/{2}.key' -f $user, $manager.Address, $agent)
        & scp.exe @ssh $remoteKey $localKey 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $localKey)) {
            Write-Host ("  could not collect the key. Has manager\configure-manager.sh been run?") -ForegroundColor Red
            $failed += $endpoint.Name
            continue
        }
        # One line, the right agent, and a 64 character key. A truncated scp would otherwise be
        # discovered by the agent failing to connect an hour later.
        $keyLine = (Get-Content -LiteralPath $localKey -Raw).Trim()
        if ($keyLine -notmatch ('^\d{3,}\s+' + [regex]::Escape($agent) + '\s+\S+\s+[a-fA-F0-9]{64}$')) {
            Write-Host '  the key the manager gave back does not look like a client.keys entry.' -ForegroundColor Red
            $failed += $endpoint.Name
            continue
        }
        Write-Host '  key collected'

        # 2. The key and everything the installer needs across to the endpoint.
        #
        # A list rather than one path, because an installer that calls a second file is an
        # installer that needs the second file. Copying only the entry point left
        # install-agent.sh on the endpoint without configure_agent.py, so it installed the agent
        # package, stopped the service, wrote the audit rules, and then died at its own line 65
        # on "can't open file '/home/labadmin/configure_agent.py'".
        #
        # Each $cleanup reads the installer's status before removing anything and re-raises it
        # afterwards. A bare "; rm" makes the removal's own success the exit status of the whole
        # remote command, which is how the failure above was reported back as enrolled.
        if ($endpoint.Os -eq 'windows') {
            $payload = @('..\agents\windows\Install-Agent.ps1')
            $remoteDir = 'C:/Windows/Temp'
            $run = ('powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\Install-Agent.ps1 ' +
                    '-ManagerAddress {0} -AgentKeyFile C:\Windows\Temp\{1}.key -ExpectedComputerName {2} -AgentName {1}' -f
                    $manager.Address, $agent, $endpoint.Hostname)
            $cleanup = ('; $rc = $LASTEXITCODE; Remove-Item C:\Windows\Temp\Install-Agent.ps1, ' +
                        'C:\Windows\Temp\{0}.key -Force -ErrorAction SilentlyContinue; exit $rc') -f $agent
            $tty = $false
        } else {
            $payload = @('..\agents\linux\install-agent.sh', '..\agents\linux\configure_agent.py')
            $remoteDir = '~/'
            # -t, because sudo here is going to ask for the console password and it needs a
            # terminal to ask on. This is the one step that stops and waits for you.
            $run = ('sudo bash ~/install-agent.sh {0} ~/{1}.key' -f $manager.Address, $agent)
            $cleanup = ('; rc=$?; rm -f ~/install-agent.sh ~/configure_agent.py ~/{0}.key; exit $rc' -f $agent)
            $tty = $true
        }
        $payload = @($payload | ForEach-Object {
            (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot $_)).Path
        })

        & scp.exe @ssh @payload $localKey ('{0}@{1}:{2}' -f $user, $endpoint.Address, $remoteDir) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host '  could not copy the installer across. Is the endpoint up and reachable over SSH?' -ForegroundColor Red
            $failed += $endpoint.Name
            continue
        }
        Write-Host ('  {0} file(s) and the key copied' -f $payload.Count)

        # 3. Run it, then take both files back off the endpoint whatever happened.
        Write-Host '  installing, this asks for the console password'
        Invoke-Ssh -Address $endpoint.Address -Command ($run + $cleanup) -Tty:$tty
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            Write-Host ("  the installer exited {0}. Nothing was left behind on the endpoint." -f $code) -ForegroundColor Red
            $failed += $endpoint.Name
            continue
        }
        Write-Host '  enrolled' -ForegroundColor Green
        Write-Host ''
    }
} finally {
    # Not optional, and not conditional on success. These are live agent keys.
    if (Test-Path -LiteralPath $staging) {
        Get-ChildItem -LiteralPath $staging -File | ForEach-Object {
            Set-Content -LiteralPath $_.FullName -Value '' -NoNewline
        }
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}

Write-Host ''
if ($failed.Count -gt 0) {
    Write-Host ("Did not enrol: {0}." -f ($failed -join ', ')) -ForegroundColor Red
    Write-Host 'Fix the reason above and re-run with -Only <name>. Enrolling twice is harmless.'
    exit 1
}
Write-Host 'All endpoints enrolled.' -ForegroundColor Green
Write-Host ("Check them from the manager: ssh -i {0} {1}@{2} 'sudo -n /var/ossec/bin/agent_control -l'" -f
    $keyPath, $user, $manager.Address)
Write-Host 'Or open the dashboard, which lists them under Agents.'
