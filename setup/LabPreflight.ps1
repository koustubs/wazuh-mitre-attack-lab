#requires -Version 5.1
<#
    What this machine can and cannot do, and for each thing it cannot, the one command that
    fixes it.

    This used to live inside the dashboard, which meant it only ran after you had cloned the
    repository, enabled a hypervisor, built three VMs, installed two operating systems and got
    far enough to open a web page. Every check it makes is one you want before any of that.

    It is a library. setup\Test-LabHost.ps1 prints it, the dashboard serves it as JSON, and both
    get the same answers because there is only one copy of them. Test-TcpPort lives here for the
    same reason: the dashboard's health polling and the reachability check below both need it.

    Nothing here changes anything. It reads.
#>

Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'LabBackend.ps1')

$script:CpuFacts = $null

function Get-LabCpuFacts {
    <#
        Firmware virtualization and SLAT cannot change without a reboot, and Win32_Processor is
        one of the slower queries here, so this is read once per session.
    #>
    if ($script:CpuFacts) { return $script:CpuFacts }
    $facts = [ordered]@{ vendor = ''; name = ''; firmware = $null; slat = $null; hypervisor = $null }
    try {
        $facts.hypervisor = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent
    } catch { }
    try {
        $cpu = @(Get-CimInstance Win32_Processor -ErrorAction Stop)[0]
        $facts.name     = ([string]$cpu.Name).Trim()
        $facts.vendor   = ([string]$cpu.Manufacturer).Trim()
        $facts.firmware = $cpu.VirtualizationFirmwareEnabled
        $facts.slat     = $cpu.SecondLevelAddressTranslationExtensions
    } catch { }
    $script:CpuFacts = $facts
    return $facts
}

function New-LabCheck {
    param(
        [string]$Id,
        [string]$Label,
        [ValidateSet('pass', 'warn', 'fail', 'unknown')][string]$State,
        [string]$Detail,
        # Always supplied, shown only when the check is not passing. Keeping the instruction
        # attached to the check rather than in the page means it cannot drift from the test.
        [string]$Fix = ''
    )
    [ordered]@{ id = $Id; label = $Label; state = $State; detail = $Detail; fix = $Fix }
}

function Test-TcpPort {
    <#
        Non-blocking connect with a timeout it actually honours.

        The obvious version, BeginConnect followed by WaitOne, does not work. When the host is
        unreachable the wait expires on schedule but EndConnect and Close then block until the
        operating system has finished its SYN retries. Measured against a powered-off lab VM,
        that turned a 400 ms timeout into a 21 second stall, which is fatal inside a polling
        loop. A non-blocking socket polled for writability respects the timeout to the
        millisecond.

        TcpClient.ConnectAsync().Wait(ms) looks like it would do the same job and does not: it
        returned false against hosts that were reachable and answered in well under the timeout.

        The DNS lookup happens before the connect and is not covered by the timeout, so a name
        that does not resolve costs whatever the resolver costs.
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

function Test-LabElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LabPreflight {
    <#
        .PARAMETER Profile
        Check against a profile other than the configured one, to answer "would lean fit here".

        .PARAMETER SkipNetworkTest
        Leave out the internet reachability check, which is the only one that takes a second and
        the only one that reaches off this machine.
    #>
    param(
        [ValidateSet('lean', 'full')][string]$Profile,
        [switch]$SkipNetworkTest
    )

    $config  = if ($Profile) { Get-LabConfig -Profile $Profile } else { Get-LabConfig }
    $vms     = if ($Profile) { Get-LabVms -Profile $Profile }    else { Get-LabVms }
    $budget  = if ($Profile) { Get-LabBudget -Profile $Profile }  else { Get-LabBudget }
    $active  = $config.profile
    $network = $config.network

    $checks = @()
    $cpu = Get-LabCpuFacts
    $elevated = Test-LabElevated

    # Call the setting what the firmware calls it. "Enable virtualization" is not the label in
    # either vendor's UEFI, and hunting for a menu entry that does not exist is a poor first
    # experience of somebody else's project.
    $virt = 'hardware virtualization'
    if ($cpu.vendor -match 'AMD') { $virt = 'SVM' } elseif ($cpu.vendor -match 'Intel') { $virt = 'VT-x' }

    # 1. Elevation. Checked first because on Hyper-V most of what follows cannot be read without
    #    it, and a list full of "unknown" is a worse answer than one line saying why. VirtualBox
    #    answers an ordinary session, so there the reads go ahead and only building needs it:
    #    New-Lab.ps1 creates a host-only interface, which is a host network adapter.
    $readNeedsElevation = ($config.backend -eq 'hyperv')
    $checks += New-LabCheck -Id 'admin' -Label 'Administrator rights' `
        -State $(if ($elevated) { 'pass' } elseif ($readNeedsElevation) { 'fail' } else { 'warn' }) `
        -Detail $(if ($elevated) { 'This session is elevated.' }
                  elseif ($readNeedsElevation) { 'Hyper-V does not answer an ordinary session, so nothing below can be read.' }
                  else { 'VirtualBox answers an ordinary session, so the checks below are read. New-Lab.ps1 needs an elevated one to create the host-only interface.' }) `
        -Fix 'Run this again from an elevated PowerShell. Right click the Start button, then Terminal (Admin).'

    # 2. Hardware virtualization. HypervisorPresent is tested first, and the order matters: once
    #    a hypervisor is running it owns the virtualization extensions and Win32_Processor
    #    reports VirtualizationFirmwareEnabled as false, because the host OS can no longer see
    #    the firmware setting it is already using. Reading that field alone therefore reports
    #    "disabled" on a machine whose VMs are running, which is a confusing thing to be told.
    if ($cpu.hypervisor) {
        $checks += New-LabCheck -Id 'virt' -Label ('Hardware virtualization, {0}' -f $virt) -State 'pass' `
            -Detail ('{0} is on and a hypervisor is running.' -f $virt)
    } elseif ($cpu.firmware -eq $false) {
        $slatNote = ''
        if ($cpu.slat -eq $false) {
            $slatNote = ' Second Level Address Translation also reads as unavailable, which Hyper-V requires.'
        }
        $checks += New-LabCheck -Id 'virt' -Label ('Hardware virtualization, {0}' -f $virt) -State 'fail' `
            -Detail (('{0} is switched off in firmware. No virtual machine on this host can start.' -f $virt) + $slatNote) `
            -Fix ('Reboot into UEFI setup, enable {0}, and boot back into Windows. On AMD it is usually under CPU Configuration, on Intel under Advanced.' -f $virt)
    } elseif ($cpu.firmware -eq $true) {
        $checks += New-LabCheck -Id 'virt' -Label ('Hardware virtualization, {0}' -f $virt) -State 'warn' `
            -Detail ('{0} is enabled in firmware, but no hypervisor is running on this host.' -f $virt) `
            -Fix 'Install or enable a hypervisor. The next check says which ones would work here.'
    } else {
        $checks += New-LabCheck -Id 'virt' -Label ('Hardware virtualization, {0}' -f $virt) -State 'unknown' `
            -Detail 'Windows did not report the processor virtualization state.' `
            -Fix 'Confirm it by hand in Task Manager, Performance, CPU. It reads "Virtualization: Enabled".'
    }

    # 3. The configured backend. Surveying both is worth the extra call: telling someone Hyper-V
    #    is missing is less useful than telling them Hyper-V is missing and the VirtualBox they
    #    already have would do.
    $survey = Get-LabBackendSurvey
    $configured = $config.backend
    $mine = $survey[$configured]
    $other = @($survey.Keys | Where-Object { $_ -ne $configured })[0]

    if ($mine.available -and -not ($mine.Contains('degraded') -and $mine.degraded)) {
        $checks += New-LabCheck -Id 'backend' -Label ('Hypervisor, {0}' -f $configured) -State 'pass' `
            -Detail $mine.detail
    } elseif ($mine.available) {
        $checks += New-LabCheck -Id 'backend' -Label ('Hypervisor, {0}' -f $configured) -State 'warn' `
            -Detail $mine.detail -Fix $mine.fix
    } else {
        $alternative = ''
        if ($survey[$other].available) {
            $alternative = (' {0} is available on this host: set backend to {0} in lab.config.json to use it instead.' -f $other)
        }
        $checks += New-LabCheck -Id 'backend' -Label ('Hypervisor, {0}' -f $configured) -State 'fail' `
            -Detail ($mine.detail + $alternative) -Fix $mine.fix
    }
    $backendUsable = [bool]$mine.available

    # Everything past here needs the hypervisor to answer, so the VMs are read once and reused
    # rather than paying for the lookup in four separate checks.
    $vmLookup = @{}
    $vmReadable = (($elevated -or -not $readNeedsElevation) -and $backendUsable)
    if ($vmReadable) {
        foreach ($name in $vms.Keys) {
            try { $vmLookup[$name] = Get-LabVmInfo -Name $name } catch { $vmLookup[$name] = $null }
        }
    }

    # 4. The lab network. The switch and the NAT are one row because they are one job: without
    #    both, the guests have addresses that reach nothing.
    if (-not $vmReadable) {
        $checks += New-LabCheck -Id 'network' -Label 'Lab network' -State 'unknown' `
            -Detail 'Not read, because the hypervisor is not answering yet.' `
            -Fix 'Clear the checks above first.'
    } else {
        $net = Get-LabNetworkInfo -NetworkName $network.name -Subnet $network.subnet -Gateway $network.gateway
        if (-not $net.SwitchPresent) {
            $checks += New-LabCheck -Id 'network' -Label 'Lab network' -State 'fail' `
                -Detail ('The {0} called {1} does not exist, so the VMs have nothing to attach to.' -f $net.SwitchKind, $network.name) `
                -Fix 'setup\New-Lab.ps1 builds the network and the VMs together. See docs/setup.md.'
        } elseif (-not $net.NatPresent) {
            $checks += New-LabCheck -Id 'network' -Label 'Lab network' -State 'warn' `
                -Detail ('The {0} {1} exists, but no {2} covers {3}. The guests reach this host and each other, but not the internet.' -f $net.SwitchKind, $network.name, $net.NatKind, $network.subnet) `
                -Fix $net.NatFix
        } else {
            $checks += New-LabCheck -Id 'network' -Label 'Lab network' -State 'pass' `
                -Detail ('{0} {1}, with {2} on {3}.' -f $net.SwitchKind, $network.name, $net.NatKind, $network.subnet)
        }
    }

    # 5. The VMs themselves, measured against the profile rather than against three. The lean
    #    profile builds two, and a Windows endpoint absent by design is not a fault.
    if (-not $vmReadable) {
        $checks += New-LabCheck -Id 'vms' -Label 'Lab virtual machines' -State 'unknown' `
            -Detail 'Not read, because the hypervisor is not answering yet.' `
            -Fix 'Clear the checks above first.'
    } else {
        $absentVms = @($vms.Keys | Where-Object { -not $vmLookup[$_] })
        if ($absentVms.Count -eq $vms.Count) {
            $checks += New-LabCheck -Id 'vms' -Label 'Lab virtual machines' -State 'fail' `
                -Detail ('None of the {0} VMs in the {1} profile exist on this host. The lab has not been built here.' -f $vms.Count, $active) `
                -Fix 'Follow docs/setup.md from the start. It builds them.'
        } elseif ($absentVms.Count -gt 0) {
            $checks += New-LabCheck -Id 'vms' -Label 'Lab virtual machines' -State 'fail' `
                -Detail ('Missing: {0}. These names have to match lab.config.json exactly.' -f ($absentVms -join ', ')) `
                -Fix 'Either create the missing VMs, or correct the names in lab.config.json.'
        } else {
            $running = @($vms.Keys | Where-Object { $vmLookup[$_].State -eq 'Running' }).Count
            $checks += New-LabCheck -Id 'vms' -Label 'Lab virtual machines' -State 'pass' `
                -Detail ('All {0} present, {1} profile. {2} running.' -f $vms.Count, $active, $running)
        }
    }

    # 6. The credentials. This is the check that catches a fresh clone: .lab-secrets is correctly
    #    gitignored, so a clone has none of it, and without the key every SSH read fails.
    $secretsDir = Get-LabPath Secrets
    $needed = @('lab_ed25519', 'lab_ed25519.pub', 'console-password.txt', 'console-password.hash')
    $absent = @($needed | Where-Object { -not (Test-Path -LiteralPath (Join-Path $secretsDir $_)) })
    if ($absent.Count -eq 0) {
        $checks += New-LabCheck -Id 'secrets' -Label 'Lab credentials' -State 'pass' `
            -Detail 'The SSH key and console password are present in .lab-secrets.'
    } else {
        $checks += New-LabCheck -Id 'secrets' -Label 'Lab credentials' -State 'fail' `
            -Detail ('Missing from .lab-secrets: {0}. Without the key, nothing inside the guests can be read.' -f ($absent -join ', ')) `
            -Fix 'Run setup\New-LabSecrets.ps1. On a fresh clone that is the first step. If the VMs already exist and the key was deleted, a new key will not match them.'
    }

    # 7. The SSH client. Present on Windows 11 by default, but it is an optional feature and can
    #    be absent, in which case every guest reading in this project fails for one reason.
    $ssh = Get-Command 'ssh.exe' -ErrorAction SilentlyContinue
    if ($ssh) {
        $checks += New-LabCheck -Id 'ssh' -Label 'OpenSSH client' -State 'pass' -Detail $ssh.Source
    } else {
        $checks += New-LabCheck -Id 'ssh' -Label 'OpenSSH client' -State 'fail' `
            -Detail 'ssh.exe was not found on PATH. Service health, alerts and the Linux scenarios all travel over SSH.' `
            -Fix 'Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0'
    }

    # 8. Memory. Advisory rather than blocking: the manager alone is enough to look at the lab.
    #    What is counted is headroom, free plus whatever the lab already holds, so a lab that is
    #    up does not report itself short of the memory it is currently using.
    $freeGb = $null
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $freeGb = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
    } catch { }
    $labHoldingGb = 0
    if ($vmReadable) {
        foreach ($name in $vms.Keys) {
            $vm = $vmLookup[$name]
            if ($vm -and $vm.State -eq 'Running') { $labHoldingGb += $vm.MemoryBytes / 1GB }
        }
    }
    $labNeedsGb = $budget.MemoryGb
    if ($null -eq $freeGb) {
        $checks += New-LabCheck -Id 'memory' -Label 'Memory headroom' -State 'unknown' `
            -Detail 'Windows did not report available physical memory.'
    } else {
        $headroomGb = [math]::Round($freeGb + $labHoldingGb, 1)
        if ($headroomGb -ge $labNeedsGb) {
            $checks += New-LabCheck -Id 'memory' -Label 'Memory headroom' -State 'pass' `
                -Detail ('{0} GB available for a lab that needs {1} GB.' -f $headroomGb, $labNeedsGb)
        } else {
            $checks += New-LabCheck -Id 'memory' -Label 'Memory headroom' -State 'warn' `
                -Detail ('{0} GB available, and the {1} profile starts {2} VMs needing {3} GB. The last one to start would fail.' -f $headroomGb, $active, $vms.Count, $labNeedsGb) `
                -Fix 'Close something, run the manager on its own, or set profile to lean in lab.config.json.'
        }
    }

    # 9. Disk. On the drive the VMs live on once they exist, and on the configured storage root
    #    before then, which is the case that matters to someone who has not built anything yet.
    $vmDrive = $null
    if ($vmReadable -and $vmLookup['WAZUH-MANAGER']) {
        try { $vmDrive = [IO.Path]::GetPathRoot($vmLookup['WAZUH-MANAGER'].StoragePath).TrimEnd('\') } catch { }
    }
    $planned = $false
    if (-not $vmDrive) {
        try { $vmDrive = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($config.storageRoot)).TrimEnd('\'); $planned = $true } catch { }
    }
    if (-not $vmDrive) {
        $checks += New-LabCheck -Id 'disk' -Label 'Disk headroom' -State 'unknown' `
            -Detail 'Could not work out which drive the VMs would live on.'
    } else {
        $vol = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $vmDrive) -ErrorAction SilentlyContinue
        $vmFreeGb = $(if ($vol) { [math]::Round($vol.FreeSpace / 1GB, 1) } else { $null })
        # Before the lab exists, the whole worst case has to fit. Once it exists the disks are
        # already allocated, so what is left to check is room to grow rather than room to build.
        $wantGb = $(if ($planned) { $budget.DiskWithHeadroomGb } else { [math]::Round($budget.DiskWithHeadroomGb / 4, 0) })
        if ($null -eq $vmFreeGb) {
            $checks += New-LabCheck -Id 'disk' -Label 'Disk headroom' -State 'unknown' `
                -Detail ('Drive {0} did not report free space.' -f $vmDrive)
        } elseif ($vmFreeGb -ge $wantGb) {
            $checks += New-LabCheck -Id 'disk' -Label 'Disk headroom' -State 'pass' `
                -Detail ('{0} GB free on {1}, where the VMs {2}.' -f $vmFreeGb, $vmDrive, $(if ($planned) { 'would live' } else { 'live' }))
        } else {
            $checks += New-LabCheck -Id 'disk' -Label 'Disk headroom' -State 'warn' `
                -Detail ('Only {0} GB free on {1}, against {2} GB for the {3} profile. The disks are dynamic and the indexer grows.' -f $vmFreeGb, $vmDrive, $wantGb, $active) `
                -Fix 'Free space, point storageRoot in lab.config.json at another drive, or use the lean profile. A full disk stops the indexer first, which looks like a detection failure rather than a disk problem.'
        }
    }

    # 10. Autostart. Advisory, and fixable from the dashboard. It is checked because it was a
    #     stated requirement of this lab: the whole thing should never come up on its own.
    if (-not $vmReadable) {
        $checks += New-LabCheck -Id 'autostart' -Label 'Autostart locked off' -State 'unknown' `
            -Detail 'Not read, because the hypervisor is not answering yet.'
    } else {
        $waking = @($vms.Keys | Where-Object { $vmLookup[$_] -and $vmLookup[$_].Autostart -ne 'Nothing' })
        if ($waking.Count -eq 0) {
            $checks += New-LabCheck -Id 'autostart' -Label 'Autostart locked off' -State 'pass' `
                -Detail 'No lab VM starts with the host.'
        } else {
            $checks += New-LabCheck -Id 'autostart' -Label 'Autostart locked off' -State 'warn' `
                -Detail ('Set to start with the host: {0}. That is {1} GB waking up without being asked.' -f ($waking -join ', '), $budget.MemoryGb) `
                -Fix 'Use "Lock: never autostart" under Advanced once the dashboard is open.'
        }
    }

    # 11. Reachability. The setup fetches an Ubuntu cloud image and the guests install Wazuh from
    #     packages.wazuh.com, so a machine behind a proxy that blocks either fails late, in the
    #     middle of an install, rather than here.
    if ($SkipNetworkTest) {
        $checks += New-LabCheck -Id 'internet' -Label 'Package sources reachable' -State 'unknown' `
            -Detail 'Not tested.'
    } else {
        $unreachable = @()
        foreach ($target in @('cloud-images.ubuntu.com', 'packages.wazuh.com')) {
            if (-not (Test-TcpPort -Address $target -Port 443 -TimeoutMs 3000)) { $unreachable += $target }
        }
        if ($unreachable.Count -eq 0) {
            $checks += New-LabCheck -Id 'internet' -Label 'Package sources reachable' -State 'pass' `
                -Detail 'cloud-images.ubuntu.com and packages.wazuh.com both answer on 443.'
        } else {
            $checks += New-LabCheck -Id 'internet' -Label 'Package sources reachable' -State 'warn' `
                -Detail ('No answer on 443 from: {0}. The image fetch and the Wazuh install both need these.' -f ($unreachable -join ', ')) `
                -Fix 'If this machine is behind a proxy, the guests are behind it too and will need it configured in cloud-init.'
        }
    }

    $failed = @($checks | Where-Object { $_.state -eq 'fail' })
    $warned = @($checks | Where-Object { $_.state -eq 'warn' })
    [ordered]@{
        ok       = $true
        ready    = ($failed.Count -eq 0)
        failed   = $failed.Count
        warned   = $warned.Count
        checks   = @($checks)
        machine  = $env:COMPUTERNAME
        cpu      = $cpu.name
        profile  = $active
        backend  = $configured
        backends = $survey
        budget   = $budget
    }
}
