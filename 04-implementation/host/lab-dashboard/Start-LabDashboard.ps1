#requires -Version 5.1
<#
A small local control panel for the three Wazuh lab VMs.

Serves one page on 127.0.0.1 showing live state and resource usage for each VM, with buttons to
start, shut down, restart or power them off. Everything it needs is built into Windows: the
Hyper-V module, CIM, and System.Net.HttpListener. There is nothing to install.

Three things worth knowing before reading further.

It relaunches itself elevated. Hyper-V will not report VM state to an ordinary session, so the
script asks for administrator rights once at launch instead of failing later.

It never starts anything on its own. Opening the dashboard is read-only. Every power action
requires a click, and the only autostart value this script can write is "Nothing", so it can
disable automatic startup but has no code path that enables it.

Power actions run as jobs. A guest shutdown can take half a minute, and the listener is single
threaded, so blocking on it would freeze the page. The UI catches up on its next poll.
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)][int]$Port = 8077,
    [switch]$NoBrowser,
    # Serve without asking for elevation. The page still loads and the layout is all there, but
    # Hyper-V refuses to answer, so every VM reports "Needs administrator". Useful for looking at
    # the dashboard, or testing it, without a UAC prompt.
    [switch]$NoElevate
)

$ErrorActionPreference = 'Stop'

# Same elevation check as Get-LabHost.ps1, but it asks rather than refusing.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$script:IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $script:IsElevated -and -not $NoElevate) {
    Write-Host 'Hyper-V needs administrator rights. Requesting elevation...'
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-Port', $Port)
    if ($NoBrowser) { $relaunch += '-NoBrowser' }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $relaunch | Out-Null
    } catch {
        Write-Warning 'Elevation was declined. Without it the dashboard cannot read or control the VMs.'
    }
    return
}

Import-Module Hyper-V -ErrorAction Stop

# Names, addresses and roles match New-Lab.ps1 and the deployment guide. This is the only place
# they are written down in this tool; change them here if the lab changes.
$LabVms = [ordered]@{
    'WAZUH-MANAGER' = [ordered]@{
        Role    = 'Manager, indexer and dashboard'
        Address = '172.29.70.10'
        Probes  = @(@{ Label = 'dashboard 443'; Port = 443 }, @{ Label = 'ssh 22'; Port = 22 })
    }
    'WAZUH-WIN' = [ordered]@{
        Role    = 'Windows endpoint, agent 001'
        Address = '172.29.70.20'
        # Nothing to probe. The Windows firewall drops inbound connections by default and the
        # agent connects outbound to the manager, so silence here is correct, not a fault.
        Probes  = @()
    }
    'WAZUH-LINUX' = [ordered]@{
        Role    = 'Linux endpoint, agent 002'
        Address = '172.29.70.30'
        Probes  = @(@{ Label = 'ssh 22'; Port = 22 })
    }
}

# Service health and recent alerts come over SSH using the lab key. Note what is NOT here: the
# Windows endpoint is never contacted. Its agent's connection state is reported by the manager,
# which knows whether each agent is checking in, so this tool never needs Windows guest
# credentials and never opens a port on that machine.
$LabSshKey = Join-Path $PSScriptRoot '..\.lab-secrets\lab_ed25519'
$LabSshUser = 'labadmin'
$ManagerAddress = $LabVms['WAZUH-MANAGER'].Address

# Units the Advanced panel may control, and the only ones the sudoers rule permits. Anything not
# named here cannot be touched from this dashboard.
$ManagerUnits = @('wazuh-manager', 'wazuh-indexer', 'wazuh-dashboard', 'filebeat')
$EndpointUnits = @('wazuh-agent')

$ProbeIntervalSeconds = 15
$HealthIntervalSeconds = 10
$script:HealthCache = $null
$script:HealthStamp = [datetime]::MinValue
$script:ProbeCache = @{}
$script:ProbeStamp = [datetime]::MinValue
$script:Notices = New-Object System.Collections.ArrayList
$script:HasJobs = $false

# Bringing the lab up takes minutes, and this listener is single threaded, so it cannot be a
# loop: a blocking wait would freeze the page for the whole boot. It is a state machine instead,
# advanced one step per poll by Update-LabSequence, using the 3 second cycle the page is already
# running as its clock.
#
# Order matters in both directions. The agents need a manager to connect to, so it starts first.
# Coming down, the manager stops last, so the endpoints are not left talking to nothing and the
# indexer is the final thing to close.
#
# Each phase performs its action once on entry, then is polled until its test passes or its
# deadline expires. A deadline that expires says which phase it was in, rather than hanging.
$LabUpPhases = @(
    [ordered]@{ name = 'manager';          label = 'Starting the manager';                        timeout = 90 }
    [ordered]@{ name = 'manager-ssh';      label = 'Waiting for the manager to finish booting';   timeout = 300 }
    [ordered]@{ name = 'manager-services'; label = 'Waiting for the Wazuh services to come up';   timeout = 300 }
    [ordered]@{ name = 'endpoints';        label = 'Starting both endpoints';                     timeout = 180 }
    [ordered]@{ name = 'agents';           label = 'Waiting for both agents to check in';         timeout = 420 }
)
$LabDownPhases = @(
    [ordered]@{ name = 'endpoints-off'; label = 'Shutting down both endpoints'; timeout = 300 }
    [ordered]@{ name = 'manager-off';   label = 'Shutting down the manager';    timeout = 300 }
)
$script:Sequence = $null
$script:LastSequencePoll = [datetime]::MinValue

# Everything the dashboard knows about the inside of the lab comes from this one script, sent to
# the manager and run there. It is sent rather than installed, for two reasons.
#
# It means the dashboard works the moment SSH does, with no setup step. What it cannot read it
# reports as unavailable rather than leaving a panel mysteriously blank, so the one-time setup
# becomes an upgrade rather than a prerequisite.
#
# It also means changing what the dashboard reports is a change to this file alone. An installed
# copy would have to be pushed out again every time, and would silently go stale if it were not.
#
# It is delivered base64 encoded. Passing shell inline through PowerShell to ssh mangles quoting,
# which has already cost this project a corrupted file on the manager; base64 has no character
# that any shell treats specially.
$RemoteStatusScript = @'
import datetime, json, os, subprocess

def run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or '')
    except Exception:
        return 1, ''

out = {'services': [], 'agents': [], 'alerts': [], 'coverage': {}, 'attack': [],
       'rate': [], 'log': [], 'window': None, 'disk': None, 'indexer': None,
       'missing': []}

for unit in ('wazuh-manager', 'wazuh-indexer', 'wazuh-dashboard', 'filebeat'):
    rc, text = run(['systemctl', 'is-active', unit], 5)
    out['services'].append({'unit': unit, 'state': text.strip() or 'unknown'})

# agent_control needs root. Without the sudoers rule this is refused, which is a missing
# capability rather than an error: say so instead of reporting zero agents, which would look
# like both endpoints had dropped off.
rc, text = run(['sudo', '-n', '/var/ossec/bin/agent_control', '-l'], 10)
if rc != 0:
    out['missing'].append('agents')
else:
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith('ID:'):
            continue
        parts = [p.strip() for p in line.split(',')]
        info = {}
        for p in parts:
            if ':' in p:
                k, v = p.split(':', 1)
                info[k.strip().lower()] = v.strip()
        # The connection state is the trailing field and carries no label of its own.
        status = parts[-1] if parts and ':' not in parts[-1] else 'unknown'
        out['agents'].append({'id': info.get('id', ''), 'name': info.get('name', ''),
                              'status': status})

# Cluster health, alert volume and retention. Installed by Enable-LabDashboard.ps1 because it
# needs the indexer's admin certificate, which is root owned and stays on the manager.
rc, text = run(['sudo', '-n', '/usr/local/bin/lab-dashboard-indexer'], 14)
if rc != 0:
    out['missing'].append('indexer')
else:
    try:
        out['indexer'] = json.loads(text)
    except Exception:
        out['missing'].append('indexer')

alerts_path = '/var/ossec/logs/alerts/alerts.json'
records = []
if not os.access(alerts_path, os.R_OK):
    out['missing'].append('alerts')
else:
    try:
        with open(alerts_path, 'rb') as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 400000))
            lines = fh.read().decode('utf-8', 'replace').splitlines()
        for line in lines[-800:]:
            try:
                records.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        out['missing'].append('alerts')

def shaped(a):
    rule = a.get('rule', {}) or {}
    mitre = rule.get('mitre', {}) or {}
    return {
        'time':  (a.get('timestamp') or '')[11:19],
        'agent': (a.get('agent', {}) or {}).get('name', ''),
        'id':    str(rule.get('id', '')),
        'level': rule.get('level', ''),
        'desc':  (rule.get('description') or '')[:110],
        'tech':  ', '.join(mitre.get('technique', []) or []),
    }

# Always the newest 50, newest first. The page decides how many of them to show, so changing
# that figure is a slice rather than another round trip.
out['alerts'] = [shaped(a) for a in records[-50:]][::-1]

if records:
    first = (records[0].get('timestamp') or '')
    out['window'] = {'from': first[11:16], 'fromDate': first[:10], 'count': len(records)}

# Per rule, how many times it fired in the sample and when it last did. The dashboard crosses
# this with the rule file on the host, which is what makes a rule that has never fired visible.
for a in records:
    rule = a.get('rule', {}) or {}
    rid = str(rule.get('id', ''))
    if not rid:
        continue
    stamp = (a.get('timestamp') or '')
    entry = out['coverage'].setdefault(rid, {'count': 0, 'last': '', 'lastDate': '', 'level': rule.get('level', '')})
    entry['count'] += 1
    if stamp[11:19] and stamp > (entry['lastDate'] + 'T' + entry['last']):
        entry['last'] = stamp[11:19]
        entry['lastDate'] = stamp[:10]

tally = {}
for a in records:
    for tech in ((a.get('rule', {}) or {}).get('mitre', {}) or {}).get('technique', []) or []:
        tally[tech] = tally.get(tech, 0) + 1
out['attack'] = [{'tech': k, 'count': v} for k, v in sorted(tally.items(), key=lambda kv: -kv[1])]

now = datetime.datetime.now()
keys = [(now - datetime.timedelta(hours=i)).strftime('%Y-%m-%dT%H') for i in range(11, -1, -1)]
counts = dict((k, 0) for k in keys)
for a in records:
    k = (a.get('timestamp') or '')[:13]
    if k in counts:
        counts[k] += 1
out['rate'] = [{'hour': k[11:13], 'count': counts[k]} for k in keys]

log_path = '/var/ossec/logs/ossec.log'
if not os.access(log_path, os.R_OK):
    out['missing'].append('log')
else:
    try:
        with open(log_path, 'rb') as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 60000))
            out['log'] = [l[:200] for l in fh.read().decode('utf-8', 'replace').splitlines()[-40:]][::-1]
    except Exception:
        out['missing'].append('log')

try:
    st = os.statvfs('/')
    disk = {'freeGb': round(st.f_bavail * st.f_frsize / 1073741824.0, 1),
            'totalGb': round(st.f_blocks * st.f_frsize / 1073741824.0, 1)}
    rc, text = run(['du', '-sm', '/var/ossec/logs'], 6)
    disk['logsMb'] = int(text.split()[0]) if rc == 0 and text.split() else None
    out['disk'] = disk
except Exception:
    pass

print(json.dumps(out))
'@
$script:StatusB64 = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes(($RemoteStatusScript -replace "`r`n", "`n")))

# The rule file is the source of truth for which detections are supposed to exist. The manager
# only knows which ones have actually fired. Crossing the two is the whole point of the coverage
# panel: a rule that exists and has never fired is invisible in any view built from alerts alone,
# and it is exactly the state worth noticing.
#
# Read once at startup. Editing rules means deploying them to the manager and restarting it, so
# re-reading this file on every poll would be watching for something that cannot change underneath.
$script:LabRules = @()
try {
    $rulePath = Join-Path $PSScriptRoot '..\..\manager\lab_rules.xml'
    if (Test-Path -LiteralPath $rulePath) {
        [xml]$ruleDoc = Get-Content -LiteralPath $rulePath -Raw
        foreach ($rule in $ruleDoc.SelectNodes('//rule')) {
            # Descriptions carry field placeholders like $(win.eventdata.targetUserName), which
            # read badly in a table. Keep the field name, drop the plumbing around it.
            $desc = [regex]::Replace([string]$rule.description, '\$\(([^)]*)\)', {
                param($m) '<' + (($m.Groups[1].Value -split '\.')[-1]) + '>'
            })
            $script:LabRules += [ordered]@{
                id          = [string]$rule.id
                level       = [int]$rule.level
                description = $desc.Trim()
                technique   = [string]$rule.mitre.id
                frequency   = [string]$rule.frequency
                timeframe   = [string]$rule.timeframe
            }
        }
    }
} catch {
    # A malformed rule file is worth knowing about, but not worth refusing to start over.
    $script:LabRules = @()
}

# Host metrics come from performance counters, not WMI. Win32_Processor's LoadPercentage takes
# around a second to answer and Win32_OperatingSystem around 150 ms, which together would be most
# of the cost of every poll. The counters answer in about a millisecond once primed.
$script:CpuCounter = $null
$script:MemCounter = $null
try {
    $script:CpuCounter = New-Object System.Diagnostics.PerformanceCounter('Processor', '% Processor Time', '_Total')
    $script:MemCounter = New-Object System.Diagnostics.PerformanceCounter('Memory', 'Available MBytes')
    $null = $script:CpuCounter.NextValue()
    $null = $script:MemCounter.NextValue()
} catch {
    $script:CpuCounter = $null
    $script:MemCounter = $null
}
# Total physical memory never changes while the machine is up, so read it once.
$script:TotalMemoryGb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)

function Test-TcpPort {
    <#
    Non-blocking connect with a timeout it actually honours.

    The obvious version, BeginConnect followed by WaitOne, does not work. When the host is
    unreachable the wait expires on schedule but EndConnect and Close then block until the
    operating system has finished its SYN retries. Measured against a powered-off lab VM, that
    turned a 400 ms timeout into a 21 second stall, which is fatal inside a polling loop. A
    non-blocking socket polled for writability respects the timeout to the millisecond.
    #>
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 400)
    $socket = New-Object System.Net.Sockets.Socket('InterNetwork', 'Stream', 'Tcp')
    try {
        $socket.Blocking = $false
        # A non-blocking connect always reports "would block" immediately; that is expected.
        try { $socket.Connect($Address, $Port) } catch [System.Net.Sockets.SocketException] { }
        $writable = $socket.Poll($TimeoutMs * 1000, [System.Net.Sockets.SelectMode]::SelectWrite)
        $failed = $socket.Poll(0, [System.Net.Sockets.SelectMode]::SelectError)
        return ($writable -and -not $failed)
    } catch {
        return $false
    } finally {
        $socket.Close()
    }
}

function Invoke-LabSsh {
    <#
    Runs one command on a lab VM and returns its output, or $null on any failure.

    Start-Process with a hard timeout rather than the call operator, because the listener is
    single threaded: an ssh that hangs would freeze the whole dashboard, not just this panel.
    ConnectTimeout only covers the connect phase, so the wait is the real guard.
    #>
    param([string]$Address, [string]$Command, [int]$TimeoutSeconds = 8, [int]$ConnectSeconds = 8)
    if (-not (Test-Path -LiteralPath $LabSshKey)) { return $null }
    $outFile = [IO.Path]::GetTempFileName()
    $errFile = [IO.Path]::GetTempFileName()
    try {
        $sshArgs = @(
            '-i', ('"{0}"' -f $LabSshKey)
            '-o', 'BatchMode=yes'
            '-o', 'StrictHostKeyChecking=no'
            '-o', 'UserKnownHostsFile=NUL'
            '-o', ('ConnectTimeout={0}' -f $ConnectSeconds)
            ('{0}@{1}' -f $LabSshUser, $Address)
            ('"{0}"' -f $Command)
        )
        $proc = Start-Process -FilePath 'ssh.exe' -ArgumentList $sshArgs -NoNewWindow -PassThru `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        # Reading Handle here is not pointless. Start-Process -PassThru hands back a Process
        # object that has not cached the process handle, and once the process exits there is
        # nothing left to read an exit code from: ExitCode comes back empty rather than 0.
        # "$null -ne 0" is true, so every successful call was being thrown away as a failure.
        # Touching Handle while the process is alive makes .NET keep it, and a genuine non-zero
        # exit is still reported correctly.
        $null = $proc.Handle
        if (-not $proc.WaitForExit(($TimeoutSeconds * 1000) + 2000)) {
            try { $proc.Kill() } catch { }
            return $null
        }
        if ($proc.ExitCode -ne 0) { return $null }
        return (Get-Content -LiteralPath $outFile -Raw)
    } catch {
        return $null
    } finally {
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-LabHealth {
    <#
    One SSH round trip to the manager returns everything the dashboard knows about the inside of
    the lab: service state, agent connection state, recent alerts, per rule coverage, ATT&CK
    tally, alert rate, manager log tail and disk. One call rather than several, on its own slower
    cycle, because shelling out to ssh costs far more than anything else this dashboard does.

    The script is sent rather than installed. See the note beside $RemoteStatusScript.
    #>
    param([bool]$ManagerRunning)
    if (-not $ManagerRunning) {
        $script:HealthCache = $null
        return $null
    }
    if ($script:HealthCache -and ([datetime]::UtcNow - $script:HealthStamp).TotalSeconds -lt $HealthIntervalSeconds) {
        return $script:HealthCache
    }
    $command = 'echo {0} | base64 -d | python3 -' -f $script:StatusB64
    $raw = Invoke-LabSsh -Address $ManagerAddress -Command $command -TimeoutSeconds 20 -ConnectSeconds 6
    $script:HealthStamp = [datetime]::UtcNow
    if (-not $raw) {
        $script:HealthCache = [ordered]@{
            reachable = $false
            note      = 'No answer over SSH. The manager may still be booting, or the lab key is not accepted.'
        }
        return $script:HealthCache
    }
    try {
        $parsed = $raw | ConvertFrom-Json
        # "missing" names what the manager could not read, rather than leaving a panel blank and
        # letting an unreadable file look like an empty one.
        $missing = @($parsed.missing)
        $script:HealthCache = [ordered]@{
            reachable = $true
            services  = $parsed.services
            agents    = $parsed.agents
            alerts    = $parsed.alerts
            coverage  = $parsed.coverage
            attack    = $parsed.attack
            rate      = $parsed.rate
            log       = $parsed.log
            window    = $parsed.window
            disk      = $parsed.disk
            indexer   = $parsed.indexer
            missing   = $missing
            setupDone = ($missing.Count -eq 0)
        }
    } catch {
        $script:HealthCache = [ordered]@{ reachable = $false; note = 'The manager returned something unreadable.' }
    }
    return $script:HealthCache
}

function Invoke-ServiceAction {
    <# Only the units named above, and only on a VM that declares them. #>
    param([string]$VmName, [string]$Unit, [string]$Action)
    if ($Action -notin @('start', 'stop', 'restart')) { throw "Unknown service action: $Action" }
    if (-not $LabVms.Contains($VmName)) { throw "Unknown VM: $VmName" }
    $allowed = if ($VmName -eq 'WAZUH-MANAGER') { $ManagerUnits } else { $EndpointUnits }
    if ($Unit -notin $allowed) { throw "This dashboard will not control $Unit on $VmName." }
    if ($VmName -eq 'WAZUH-WIN') { throw 'The Windows agent cannot be controlled from here; it has no SSH access.' }
    $address = $LabVms[$VmName].Address
    $result = Invoke-LabSsh -Address $address -Command ('sudo -n systemctl {0} {1} && systemctl is-active {1}' -f $Action, $Unit)
    if (-not $result) { throw "Could not $Action $Unit on $VmName. Check that the one-time setup has been run." }
    return ('{0} on {1} is now {2}.' -f $Unit, $VmName, $result.Trim())
}

function Invoke-LabScenario {
    <#
    Runs one of the three scenarios on an endpoint and lets the alert show up in the coverage
    panel a few seconds later.

    As a job, always. S1 makes six logon attempts with pauses between them, so it runs for well
    over a minute, and the listener is single threaded.

    Linux goes over SSH to a wrapper the sudoers rule names by exact arguments. Windows goes over
    PowerShell Direct, which needs no network and no open port on that machine, using the console
    credential from .lab-secrets. That credential is read at the moment of the action and not
    held anywhere.
    #>
    param([string]$VmName, [string]$Scenario, [string]$Mode)
    if ($Scenario -notin @('S1', 'S2', 'S3')) { throw "Unknown scenario: $Scenario" }
    if ($Mode -notin @('test', 'comparison')) { throw "Unknown mode: $Mode" }
    if ($VmName -notin @('WAZUH-LINUX', 'WAZUH-WIN')) { throw "Scenarios run on the endpoints, not on $VmName." }
    $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
    if (-not $vm -or $vm.State -ne 'Running') { throw "$VmName is not running." }

    $label = 'Scenario {0} {1} on {2}' -f $Scenario, $Mode, $VmName
    $script:HasJobs = $true

    if ($VmName -eq 'WAZUH-LINUX') {
        Start-Job -Name $label -ScriptBlock {
            param($Key, $User, $Address, $Scenario, $Mode)
            # Without this a failure is a non-terminating error, the job still reports Completed,
            # and the page cheerfully says the scenario finished when nothing happened.
            $ErrorActionPreference = 'Stop'
            $sshArgs = @(
                '-i', $Key, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=NUL', '-o', 'ConnectTimeout=8',
                ('{0}@{1}' -f $User, $Address),
                ('sudo -n /usr/local/bin/lab-scenario {0} {1}' -f $Scenario, $Mode)
            )
            $output = & ssh.exe @sshArgs 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw ('the endpoint refused it: {0}' -f (($output -join ' ').Trim()))
            }
            ($output | Select-Object -Last 1)
        } -ArgumentList $LabSshKey, $LabSshUser, $LabVms[$VmName].Address, $Scenario, $Mode | Out-Null
    } else {
        $passwordFile = Join-Path $PSScriptRoot '..\.lab-secrets\console-password.txt'
        $scriptFile = Join-Path $PSScriptRoot '..\..\windows\Invoke-Scenario.ps1'
        if (-not (Test-Path -LiteralPath $passwordFile)) { throw 'The console password is missing from .lab-secrets.' }
        if (-not (Test-Path -LiteralPath $scriptFile)) { throw 'The Windows scenario driver is missing from the repository.' }
        Start-Job -Name $label -ScriptBlock {
            param($PasswordFile, $ScriptFile, $VmName, $Scenario, $Comparison)
            $ErrorActionPreference = 'Stop'
            $secure = ConvertTo-SecureString ((Get-Content -LiteralPath $PasswordFile -Raw).Trim()) -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential('labadmin', $secure)
            $source = Get-Content -LiteralPath $ScriptFile -Raw
            # The script is sent rather than pre-staged, so nothing has to be kept in sync on the
            # guest.
            $result = Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
                param($Source, $Scenario, $Comparison)
                $temp = Join-Path $env:TEMP 'lab-scenario.ps1'
                Set-Content -LiteralPath $temp -Value $Source -Encoding UTF8
                try {
                    # Run it through powershell.exe rather than dot-sourcing it. The guest's
                    # execution policy blocks a script file outright, and this is also the only
                    # form that still honours the driver's own "#requires -RunAsAdministrator",
                    # which a scriptblock would silently drop. The bypass applies to this one
                    # invocation and changes nothing on the machine.
                    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $temp, '-Scenario', $Scenario)
                    if ($Comparison) { $argv += '-Comparison' }
                    $output = & powershell.exe @argv 2>&1
                    if ($LASTEXITCODE -ne 0) { throw (($output -join ' ').Trim()) }
                    ($output | Select-Object -Last 1)
                } finally {
                    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
                }
            } -ArgumentList $source, $Scenario, $Comparison
            $result
        } -ArgumentList $passwordFile, $scriptFile, $VmName, $Scenario, ($Mode -eq 'comparison') | Out-Null
    }

    $what = if ($Mode -eq 'comparison') { 'the benign comparison' } else { 'the attack case' }
    return ('Running {0}, {1}, on {2}. It takes a minute or two; the alert appears in coverage shortly after.' -f $Scenario, $what, $VmName)
}

function Format-Uptime {
    param($Span)
    if ($null -eq $Span -or $Span.TotalSeconds -lt 1) { return $null }
    if ($Span.TotalDays -ge 1)  { return ('{0}d {1}h' -f [int]$Span.TotalDays, $Span.Hours) }
    if ($Span.TotalHours -ge 1) { return ('{0}h {1}m' -f [int]$Span.TotalHours, $Span.Minutes) }
    return ('{0}m' -f [int]$Span.TotalMinutes)
}

function Get-JobNotices {
    <# Power actions run detached, so failures surface here rather than in the HTTP response. #>
    # Get-Job costs about 70 ms, so skip it entirely on the common path where nothing is running.
    if (-not $script:HasJobs) { return }
    foreach ($job in @(Get-Job | Where-Object { $_.State -eq 'Failed' })) {
        $reason = @($job.ChildJobs | ForEach-Object {
            if ($_.JobStateInfo.Reason) { $_.JobStateInfo.Reason.Message }
        }) -join '; '
        if (-not $reason) { $reason = 'The action failed.' }
        [void]$script:Notices.Add([ordered]@{
            at   = [datetime]::UtcNow.ToString('o')
            kind = 'error'
            text = ('{0}: {1}' -f $job.Name, $reason)
        })
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    foreach ($job in @(Get-Job | Where-Object { $_.State -eq 'Completed' })) {
        # A power action's result is visible on its card, so only a scenario has anything to say.
        # It reports what it did, which is the point of pressing the button.
        if ($job.Name -like 'Scenario*') {
            $said = (@(Receive-Job -Job $job -ErrorAction SilentlyContinue) -join ' ').Trim()
            # A scenario that finishes without saying anything did not run. Reporting that as a
            # success is how a silent failure gets mistaken for a working demonstration.
            [void]$script:Notices.Add([ordered]@{
                at   = [datetime]::UtcNow.ToString('o')
                kind = $(if ($said) { 'ok' } else { 'error' })
                text = $(if ($said) { '{0} finished. {1}' -f $job.Name, $said }
                         else { '{0} returned nothing, so it probably did not run. Check the endpoint.' -f $job.Name })
            })
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    if (@(Get-Job).Count -eq 0) { $script:HasJobs = $false }
    while ($script:Notices.Count -gt 8) { $script:Notices.RemoveAt(0) }
}

function Get-LabState {
    Get-JobNotices
    # Probes run on their own slower cycle, and only against VMs that are actually running. The
    # exception is a sequence in progress, where the port coming up is the thing being waited on,
    # so a 15 second cache would add 15 seconds to the wait for no reason.
    $sequenceActive = $script:Sequence -and $script:Sequence.phase -notin @('done', 'failed')
    $refreshProbes = $sequenceActive -or
        ([datetime]::UtcNow - $script:ProbeStamp).TotalSeconds -ge $ProbeIntervalSeconds

    $cpuLoad = 0
    $memUsedGb = 0
    if ($script:CpuCounter) { try { $cpuLoad = $script:CpuCounter.NextValue() } catch { $cpuLoad = 0 } }
    if ($script:MemCounter) {
        try { $memUsedGb = [math]::Round($script:TotalMemoryGb - ($script:MemCounter.NextValue() / 1024), 1) } catch { }
    }
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [ordered]@{
            name   = $_.DeviceID
            freeGb = [math]::Round($_.FreeSpace / 1GB, 1)
            sizeGb = [math]::Round($_.Size / 1GB, 1)
        }
    })

    $vms = @()
    $runningMemoryBytes = 0
    foreach ($name in $LabVms.Keys) {
        $meta = $LabVms[$name]
        # Without elevation Hyper-V throws rather than returning nothing, so separate "no rights"
        # from "no such VM". Reporting them the same way sends people hunting a missing VM.
        $vm = $null
        $denied = $false
        try {
            $vm = Get-VM -Name $name -ErrorAction Stop
        } catch {
            if (-not $script:IsElevated) { $denied = $true }
        }
        if (-not $vm) {
            $vms += [ordered]@{
                name = $name; role = $meta.Role; address = $meta.Address
                found = $false; state = $(if ($denied) { 'Needs administrator' } else { 'Not found' })
            }
            continue
        }
        $state = $vm.State.ToString()
        if ($state -eq 'Running') { $runningMemoryBytes += $vm.MemoryAssigned }

        # There is nothing to learn from probing a VM that is not running, and a connect to a
        # powered-off address is the most expensive thing this loop can do. Skip it.
        if ($state -ne 'Running') {
            $script:ProbeCache[$name] = @()
        } elseif ($refreshProbes) {
            $results = @()
            foreach ($probe in $meta.Probes) {
                $results += [ordered]@{
                    label = $probe.Label
                    open  = [bool](Test-TcpPort -Address $meta.Address -Port $probe.Port)
                }
            }
            $script:ProbeCache[$name] = $results
        }
        $vms += [ordered]@{
            name        = $name
            role        = $meta.Role
            address     = $meta.Address
            found       = $true
            state       = $state
            status      = $vm.Status
            cpuPercent  = [int]$vm.CPUUsage
            memoryGb    = [math]::Round($vm.MemoryAssigned / 1GB, 1)
            configuredGb = [math]::Round($vm.MemoryStartup / 1GB, 1)
            cpuCount    = [int]$vm.ProcessorCount
            uptime      = Format-Uptime $vm.Uptime
            autostart   = $vm.AutomaticStartAction.ToString()
            autostartOk = ($vm.AutomaticStartAction.ToString() -eq 'Nothing')
            probes      = @($script:ProbeCache[$name])
        }
    }

    if ($refreshProbes) { $script:ProbeStamp = [datetime]::UtcNow }

    # Nothing inside the guests is worth asking for while the manager is down, and asking would
    # cost an SSH timeout on every poll. Hyper-V reports Running the moment the VM is powered on,
    # which is a minute or so before sshd answers, so the port probe is the better gate: during a
    # cold boot it turns roughly eight wasted seconds per cycle into none.
    $manager = @($vms | Where-Object { $_.name -eq 'WAZUH-MANAGER' })
    $managerRunning = ($manager.Count -gt 0 -and $manager[0].state -eq 'Running')
    if ($managerRunning) {
        $sshProbe = @($manager[0].probes | Where-Object { $_.label -like 'ssh*' })
        if ($sshProbe.Count -gt 0 -and -not $sshProbe[0].open) { $managerRunning = $false }
    }
    $health = Get-LabHealth -ManagerRunning $managerRunning

    Update-LabSequence -Vms $vms -Health $health

    [ordered]@{
        ok       = $true
        elevated = [bool]$script:IsElevated
        now      = (Get-Date).ToString('HH:mm:ss')
        sequence = $(if ($script:Sequence) {
            [ordered]@{
                kind    = $script:Sequence.kind
                phase   = $script:Sequence.phase
                label   = $script:Sequence.label
                step    = [int]$script:Sequence.step + 1
                total   = [int]$script:Sequence.total
                running = ($script:Sequence.phase -notin @('done', 'failed'))
                waited  = [int]([datetime]::UtcNow - $script:Sequence.startedAt).TotalSeconds
                elapsed = [int]$script:Sequence.elapsed
                error   = $script:Sequence.error
                note    = $script:Sequence.note
            }
        } else { $null })
        host   = [ordered]@{
            name        = $env:COMPUTERNAME
            cpuPercent  = [int]$cpuLoad
            memUsedGb   = $memUsedGb
            memTotalGb  = $script:TotalMemoryGb
            disks       = $disks
        }
        labMemoryGb = [math]::Round($runningMemoryBytes / 1GB, 1)
        vms      = $vms
        rules    = @($script:LabRules)
        health   = $health
        notices  = @($script:Notices)
    }
}

function Invoke-VmAction {
    param([string]$VmName, [string]$Action)
    if (-not $LabVms.Contains($VmName)) { throw "Unknown VM: $VmName" }
    $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM not found: $VmName" }
    $label = '{0} {1}' -f $Action, $VmName
    $script:HasJobs = $true
    switch ($Action) {
        'start'    { Start-VM   -Name $VmName -AsJob | ForEach-Object { $_.Name = $label } }
        'shutdown' { Stop-VM    -Name $VmName -Force -AsJob | ForEach-Object { $_.Name = $label } }
        'restart'  { Restart-VM -Name $VmName -Force -AsJob | ForEach-Object { $_.Name = $label } }
        'forceoff' { Stop-VM    -Name $VmName -TurnOff -Force -AsJob | ForEach-Object { $_.Name = $label } }
        default    { throw "Unknown action: $Action" }
    }
    return "Requested $Action on $VmName."
}

function Lock-NoAutostart {
    <# The only autostart value this tool can write. There is deliberately no enable path. #>
    $changed = @()
    foreach ($name in $LabVms.Keys) {
        $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
        if (-not $vm) { continue }
        if ($vm.AutomaticStartAction.ToString() -ne 'Nothing') {
            Set-VM -Name $name -AutomaticStartAction Nothing
            $changed += $name
        }
    }
    if ($changed.Count -eq 0) { return 'All VMs were already set to never start automatically.' }
    return ('Autostart disabled on: {0}.' -f ($changed -join ', '))
}

function Get-VmStateFrom {
    <# Reads a state out of the list Get-LabState has already built, rather than calling Hyper-V again. #>
    param($Vms, [string]$Name)
    $match = @($Vms | Where-Object { $_.name -eq $Name })
    if ($match.Count -eq 0) { return 'Not found' }
    return $match[0].state
}

function Get-SequencePhases {
    param([string]$Kind)
    if ($Kind -eq 'up') { return $LabUpPhases }
    return $LabDownPhases
}

function Enter-LabPhase {
    <# Performs the current phase's action once, then hands over to its test. #>
    param($Vms)
    $seq = $script:Sequence
    $phase = (Get-SequencePhases -Kind $seq.kind)[$seq.step]
    $seq.phase = $phase.name
    $seq.label = $phase.label
    $seq.deadline = [datetime]::UtcNow.AddSeconds($phase.timeout)
    switch ($phase.name) {
        'manager' {
            if ((Get-VmStateFrom -Vms $Vms -Name 'WAZUH-MANAGER') -ne 'Running') {
                Invoke-VmAction -VmName 'WAZUH-MANAGER' -Action 'start' | Out-Null
            }
        }
        'endpoints' {
            foreach ($name in @('WAZUH-WIN', 'WAZUH-LINUX')) {
                if ((Get-VmStateFrom -Vms $Vms -Name $name) -eq 'Off') {
                    Invoke-VmAction -VmName $name -Action 'start' | Out-Null
                }
            }
        }
        'endpoints-off' {
            foreach ($name in @('WAZUH-WIN', 'WAZUH-LINUX')) {
                if ((Get-VmStateFrom -Vms $Vms -Name $name) -eq 'Running') {
                    Invoke-VmAction -VmName $name -Action 'shutdown' | Out-Null
                }
            }
        }
        'manager-off' {
            if ((Get-VmStateFrom -Vms $Vms -Name 'WAZUH-MANAGER') -eq 'Running') {
                Invoke-VmAction -VmName 'WAZUH-MANAGER' -Action 'shutdown' | Out-Null
            }
        }
    }
}

function Test-LabPhase {
    <# Whether the current phase is satisfied. Reads only state that has already been gathered. #>
    param($Vms, $Health)
    $seq = $script:Sequence
    switch ($seq.phase) {
        'manager' {
            return ((Get-VmStateFrom -Vms $Vms -Name 'WAZUH-MANAGER') -eq 'Running')
        }
        'manager-ssh' {
            $manager = @($Vms | Where-Object { $_.name -eq 'WAZUH-MANAGER' })
            if ($manager.Count -eq 0) { return $false }
            return @($manager[0].probes | Where-Object { $_.label -like 'ssh*' -and $_.open }).Count -gt 0
        }
        'manager-services' {
            if (-not $Health -or -not $Health.reachable) { return $false }
            $units = @($Health.services | Where-Object { $_.state -eq 'active' } | ForEach-Object { $_.unit })
            foreach ($required in $ManagerUnits) { if ($units -notcontains $required) { return $false } }
            return $true
        }
        'endpoints' {
            foreach ($name in @('WAZUH-WIN', 'WAZUH-LINUX')) {
                if ((Get-VmStateFrom -Vms $Vms -Name $name) -ne 'Running') { return $false }
            }
            return $true
        }
        'agents' {
            if (-not $Health -or -not $Health.reachable) { return $false }
            # Reading agent state needs the one-time setup. Without it there is nothing to wait
            # for, so finish with a note rather than spending seven minutes timing out on a check
            # that was never going to be able to run.
            if (@($Health.missing) -contains 'agents') {
                $script:Sequence.note = 'Agents not checked: the one-time setup has not been run, so the manager will not report them.'
                return $true
            }
            $live = @($Health.agents | Where-Object { $_.status -match 'active' })
            return ($live.Count -ge 2)
        }
        'endpoints-off' {
            foreach ($name in @('WAZUH-WIN', 'WAZUH-LINUX')) {
                if ((Get-VmStateFrom -Vms $Vms -Name $name) -eq 'Running') { return $false }
            }
            return $true
        }
        'manager-off' {
            return ((Get-VmStateFrom -Vms $Vms -Name 'WAZUH-MANAGER') -ne 'Running')
        }
    }
    return $false
}

function Update-LabSequence {
    <# One step per poll. Called from Get-LabState once the VM list and health are in hand. #>
    param($Vms, $Health)
    if (-not $script:Sequence) { return }
    $seq = $script:Sequence
    if ($seq.phase -in @('done', 'failed')) { return }

    # A phase is only observed when someone asks for state. If nothing polled for a while, that
    # time was not spent watching anything, and counting it against the deadline would report a
    # timeout for a boot that went fine and simply had nobody looking. Give the gap back.
    $now = [datetime]::UtcNow
    if ($script:LastSequencePoll -gt [datetime]::MinValue) {
        $gap = ($now - $script:LastSequencePoll).TotalSeconds
        if ($gap -gt 15) { $seq.deadline = $seq.deadline.AddSeconds($gap) }
    }
    $script:LastSequencePoll = $now

    $phases = Get-SequencePhases -Kind $seq.kind
    if (-not (Test-LabPhase -Vms $Vms -Health $Health)) {
        if ($now -gt $seq.deadline) {
            $seq.phase = 'failed'
            $seq.error = ('Gave up while {0}. Nothing was forced; the VMs are wherever they got to.' -f $seq.label.ToLower())
            [void]$script:Notices.Add([ordered]@{
                at = [datetime]::UtcNow.ToString('o'); kind = 'error'; text = $seq.error
            })
        }
        return
    }

    $seq.step++
    if ($seq.step -ge $phases.Count) {
        $seq.phase = 'done'
        $seq.label = if ($seq.kind -eq 'up') { 'The lab is up' } else { 'The lab is down' }
        $seq.elapsed = [int]([datetime]::UtcNow - $seq.startedAt).TotalSeconds
        [void]$script:Notices.Add([ordered]@{
            at = [datetime]::UtcNow.ToString('o'); kind = 'ok'
            text = ('{0} after {1} seconds.' -f $seq.label, $seq.elapsed)
        })
        return
    }
    Enter-LabPhase -Vms $Vms
}

function Start-LabSequence {
    param([string]$Action, $Vms)
    if ($Action -eq 'cancel') {
        if (-not $script:Sequence -or $script:Sequence.phase -in @('done', 'failed')) { return 'Nothing to cancel.' }
        $script:Sequence = $null
        return 'Sequence cancelled. Any VM already asked to start or stop carries on doing it.'
    }
    if ($Action -notin @('up', 'down')) { throw "Unknown lab action: $Action" }
    if ($script:Sequence -and $script:Sequence.phase -notin @('done', 'failed')) {
        throw 'A lab sequence is already running. Cancel it first.'
    }
    $script:Sequence = [ordered]@{
        kind      = $Action
        step      = 0
        phase     = ''
        label     = ''
        total     = (Get-SequencePhases -Kind $Action).Count
        startedAt = [datetime]::UtcNow
        deadline  = [datetime]::UtcNow
        elapsed   = 0
        error     = $null
        note      = $null
    }
    Enter-LabPhase -Vms $Vms
    if ($Action -eq 'up') { return 'Bringing the lab up. The manager goes first so the agents have something to connect to.' }
    return 'Taking the lab down. The endpoints stop first and the manager last, so the indexer closes cleanly.'
}

function Write-Reply {
    param($Response, [string]$Body, [string]$ContentType = 'application/json; charset=utf-8', [int]$Status = 200)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
    $Response.StatusCode = $Status
    $Response.ContentType = $ContentType
    $Response.Headers.Add('Cache-Control', 'no-store')
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

# A random token is generated per run and injected into the page. Every API call must present it.
# No CORS headers are sent, so another site open in the same browser cannot read the token out of
# the page or drive these endpoints.
$token = [guid]::NewGuid().ToString('N')
$pagePath = Join-Path $PSScriptRoot 'dashboard.html'
if (-not (Test-Path -LiteralPath $pagePath)) { throw "Missing page file: $pagePath" }

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
try {
    $listener.Start()
} catch {
    throw "Could not listen on port $Port. Another process may be using it. Try -Port with a different number. ($($_.Exception.Message))"
}

Write-Host ''
Write-Host "  Wazuh lab dashboard is running at http://127.0.0.1:$Port/"
Write-Host '  Leave this window open. Close it, or use "Stop dashboard" on the page, to shut it down.'
Write-Host ''

if (-not $NoBrowser) { Start-Process "http://127.0.0.1:$Port/" | Out-Null }

$running = $true
while ($running -and $listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response
    try {
        $path = $request.Url.AbsolutePath.TrimEnd('/')
        if ($path -eq '') { $path = '/' }

        if ($path -eq '/' -and $request.HttpMethod -eq 'GET') {
            $html = (Get-Content -LiteralPath $pagePath -Raw) -replace '__LAB_TOKEN__', $token
            Write-Reply -Response $response -Body $html -ContentType 'text/html; charset=utf-8'
            continue
        }

        if ($path -eq '/favicon.ico') {
            Write-Reply -Response $response -Body '' -ContentType 'image/x-icon' -Status 404
            continue
        }

        if ($request.Headers['X-Lab-Token'] -ne $token) {
            Write-Reply -Response $response -Body '{"ok":false,"error":"Bad or missing token."}' -Status 403
            continue
        }

        switch ($path) {
            '/api/state' {
                Write-Reply -Response $response -Body ((Get-LabState) | ConvertTo-Json -Depth 8 -Compress)
            }
            '/api/action' {
                $reader = New-Object IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $payload = $reader.ReadToEnd() | ConvertFrom-Json
                $reader.Close()
                $message = Invoke-VmAction -VmName $payload.vm -Action $payload.action
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/service' {
                $reader = New-Object IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $payload = $reader.ReadToEnd() | ConvertFrom-Json
                $reader.Close()
                $message = Invoke-ServiceAction -VmName $payload.vm -Unit $payload.unit -Action $payload.action
                # The next poll would otherwise serve a stale cache and look like nothing happened.
                $script:HealthStamp = [datetime]::MinValue
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/lab' {
                $reader = New-Object IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $payload = $reader.ReadToEnd() | ConvertFrom-Json
                $reader.Close()
                # Three Get-VM calls, only on the button press, so the first phase acts on the
                # states as they are right now rather than whatever the last poll cached.
                $vmStates = @($LabVms.Keys | ForEach-Object {
                    $vm = Get-VM -Name $_ -ErrorAction SilentlyContinue
                    [ordered]@{ name = $_; state = $(if ($vm) { $vm.State.ToString() } else { 'Not found' }) }
                })
                $message = Start-LabSequence -Action $payload.action -Vms $vmStates
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/scenario' {
                $reader = New-Object IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $payload = $reader.ReadToEnd() | ConvertFrom-Json
                $reader.Close()
                $message = Invoke-LabScenario -VmName $payload.vm -Scenario $payload.scenario -Mode $payload.mode
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/lock-autostart' {
                $message = Lock-NoAutostart
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/quit' {
                Write-Reply -Response $response -Body '{"ok":true,"message":"Stopping."}'
                $running = $false
            }
            default {
                Write-Reply -Response $response -Body '{"ok":false,"error":"Not found."}' -Status 404
            }
        }
    } catch {
        $problem = [ordered]@{ ok = $false; error = $_.Exception.Message }
        try { Write-Reply -Response $response -Body ($problem | ConvertTo-Json -Compress) -Status 500 } catch { }
    }
}

$listener.Stop()
$listener.Close()
Write-Host '  Dashboard stopped.'
