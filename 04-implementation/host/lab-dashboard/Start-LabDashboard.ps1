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
    param([string]$Address, [string]$Command, [int]$TimeoutSeconds = 8)
    if (-not (Test-Path -LiteralPath $LabSshKey)) { return $null }
    $outFile = [IO.Path]::GetTempFileName()
    $errFile = [IO.Path]::GetTempFileName()
    try {
        $sshArgs = @(
            '-i', ('"{0}"' -f $LabSshKey)
            '-o', 'BatchMode=yes'
            '-o', 'StrictHostKeyChecking=no'
            '-o', 'UserKnownHostsFile=NUL'
            '-o', ('ConnectTimeout={0}' -f $TimeoutSeconds)
            ('{0}@{1}' -f $LabSshUser, $Address)
            ('"{0}"' -f $Command)
        )
        $proc = Start-Process -FilePath 'ssh.exe' -ArgumentList $sshArgs -NoNewWindow -PassThru `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
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
    One SSH round trip to the manager returns service status, agent connection state and the
    most recent alerts, all as JSON. One call rather than several, on its own slow cycle, because
    shelling out to ssh costs far more than anything else this dashboard does.

    The remote side is /usr/local/bin/lab-dashboard-status, installed by Enable-LabDashboard.ps1.
    #>
    param([bool]$ManagerRunning)
    if (-not $ManagerRunning) {
        $script:HealthCache = $null
        return $null
    }
    if ($script:HealthCache -and ([datetime]::UtcNow - $script:HealthStamp).TotalSeconds -lt $HealthIntervalSeconds) {
        return $script:HealthCache
    }
    $raw = Invoke-LabSsh -Address $ManagerAddress -Command 'lab-dashboard-status'
    $script:HealthStamp = [datetime]::UtcNow
    if (-not $raw) {
        $script:HealthCache = [ordered]@{
            reachable = $false
            note      = 'No answer over SSH. The manager may still be booting, or the one-time setup has not been run.'
        }
        return $script:HealthCache
    }
    try {
        $parsed = $raw | ConvertFrom-Json
        $script:HealthCache = [ordered]@{
            reachable = $true
            services  = $parsed.services
            agents    = $parsed.agents
            alerts    = $parsed.alerts
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
    Get-Job | Where-Object { $_.State -eq 'Completed' } | Remove-Job -Force -ErrorAction SilentlyContinue
    if (@(Get-Job).Count -eq 0) { $script:HasJobs = $false }
    while ($script:Notices.Count -gt 8) { $script:Notices.RemoveAt(0) }
}

function Get-LabState {
    Get-JobNotices
    # Probes run on their own slower cycle, and only against VMs that are actually running.
    $refreshProbes = ([datetime]::UtcNow - $script:ProbeStamp).TotalSeconds -ge $ProbeIntervalSeconds

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
    # cost an SSH timeout on every poll.
    $managerRunning = @($vms | Where-Object { $_.name -eq 'WAZUH-MANAGER' -and $_.state -eq 'Running' }).Count -gt 0
    $health = Get-LabHealth -ManagerRunning $managerRunning

    [ordered]@{
        ok       = $true
        elevated = [bool]$script:IsElevated
        now      = (Get-Date).ToString('HH:mm:ss')
        host   = [ordered]@{
            name        = $env:COMPUTERNAME
            cpuPercent  = [int]$cpuLoad
            memUsedGb   = $memUsedGb
            memTotalGb  = $script:TotalMemoryGb
            disks       = $disks
        }
        labMemoryGb = [math]::Round($runningMemoryBytes / 1GB, 1)
        vms      = $vms
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
