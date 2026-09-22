<#
    The VirtualBox implementation of the backend contract in ..\LabBackend.ps1.

    Read this before relying on it. The read paths have been exercised against VirtualBox 7.2
    on the machine this lab was built on: Test-LabBackendAvailable, Get-LabVmInfo,
    Get-LabNetworkInfo and Test-LabNetworkConflict all answer correctly there. The write paths,
    which create the network and the VMs, have not been run, because that machine runs Hyper-V
    and the two cannot own the virtualization extensions at the same time. The Hyper-V backend
    is the one with a built lab behind it. Where the two differ in a way that changes what you
    get rather than how it is spelled, the comment says so.

    Three differences are real rather than cosmetic:

    Networking takes two adapters. Hyper-V gets one internal switch and WinNAT gives it the
    internet. VirtualBox's NAT Network reaches the internet but not this host, and its host-only
    network reaches this host but not the internet, so each guest gets both: NIC1 on the NAT
    network for package installation, NIC2 on the host-only network carrying the lab address.
    The guest configuration binds the static address to the second adapter for this reason.

    There is no dynamic memory. VirtualBox allocates what you give it and holds it. The lean
    profile therefore costs its full 5 GB here where Hyper-V gives some of it back, which is
    what the requirements table means by the VirtualBox column being the same number twice.

    There is no TPM 2.0 before VirtualBox 7.0, and Windows 11 will not install without one.
    Test-LabBackendAvailable refuses 6.x rather than letting the Windows endpoint fail at the
    end of an installation.
#>

Set-StrictMode -Version Latest

$script:VBoxManage = $null

function Get-VBoxManage {
    <#
        VBoxManage.exe, from PATH or from the install directory the installer records in the
        registry. The installer does not add itself to PATH by default, so looking only on PATH
        reports VirtualBox as absent on a machine that has it.
    #>
    if ($script:VBoxManage) { return $script:VBoxManage }

    $cmd = Get-Command 'VBoxManage.exe' -ErrorAction SilentlyContinue
    if ($cmd) { $script:VBoxManage = $cmd.Source; return $script:VBoxManage }

    foreach ($candidate in @(
        (Join-Path $env:VBOX_MSI_INSTALL_PATH 'VBoxManage.exe'),
        "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe",
        "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
    )) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            $script:VBoxManage = $candidate
            return $script:VBoxManage
        }
    }
    return $null
}

function Invoke-VBox {
    <#
        Runs VBoxManage and returns its output and exit code.

        Not thrown on by default. Half the calls here are questions whose answer is "no such VM",
        which VBoxManage reports with a non-zero exit, and treating that as an error would mean a
        try/catch around every read.
    #>
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$ThrowOnError)

    $exe = Get-VBoxManage
    if (-not $exe) { throw 'VBoxManage.exe was not found. Install VirtualBox, or set backend to hyperv in lab.config.json.' }

    $out = & $exe @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($ThrowOnError -and $code -ne 0) {
        throw ('VBoxManage {0} failed: {1}' -f ($Arguments -join ' '), (($out | Out-String) -replace '\s+', ' ').Trim())
    }
    [ordered]@{ Code = $code; Output = @($out | ForEach-Object { "$_" }) }
}

function Get-VBoxVmProperties {
    <#
        showvminfo --machinereadable as a hashtable. Values are quoted, sometimes, and keys
        containing a bracket are array entries rather than scalars; both are handled here so the
        callers can just index.
    #>
    param([Parameter(Mandatory)][string]$Name)

    $r = Invoke-VBox -Arguments @('showvminfo', $Name, '--machinereadable')
    if ($r.Code -ne 0) { return $null }
    $props = @{}
    foreach ($line in $r.Output) {
        $split = $line.IndexOf('=')
        if ($split -lt 1) { continue }
        $key = $line.Substring(0, $split).Trim('"')
        $value = $line.Substring($split + 1).Trim().Trim('"')
        $props[$key] = $value
    }
    return $props
}

function Test-LabBackendAvailable {
    $exe = Get-VBoxManage
    if (-not $exe) {
        return [ordered]@{
            available = $false
            detail    = 'VBoxManage.exe was not found on PATH or in the usual install directories.'
            fix       = 'Install VirtualBox 7.0 or later from virtualbox.org, then open a new shell so PATH is picked up.'
        }
    }

    $r = Invoke-VBox -Arguments @('--version')
    $version = ($r.Output -join '').Trim()
    $major = 0
    if ($version -match '^(\d+)\.') { $major = [int]$Matches[1] }
    if ($major -lt 7) {
        return [ordered]@{
            available = $false
            detail    = ('VirtualBox {0} is installed. The Windows endpoint needs a TPM 2.0 device, which arrived in 7.0.' -f $version)
            fix       = 'Upgrade to VirtualBox 7.0 or later, or use the lean profile, which has no Windows endpoint.'
        }
    }

    # Hyper-V and VirtualBox both want the virtualization extensions. On Windows 10 and 11
    # VirtualBox can run on top of Hyper-V through its own compatibility layer, but it is slow
    # enough that a Wazuh install is an unpleasant way to discover it, so this warns rather than
    # letting someone find out an hour in.
    $hypervisorPresent = $false
    try { $hypervisorPresent = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent } catch { }
    if ($hypervisorPresent) {
        return [ordered]@{
            available = $true
            detail    = ('VirtualBox {0} is installed, but a Windows hypervisor is also running, so VirtualBox will fall back to its slow compatibility layer.' -f $version)
            fix       = 'bcdedit /set hypervisorlaunchtype off, then reboot. Turning it back on is bcdedit /set hypervisorlaunchtype auto. This also disables Windows memory integrity and WSL2, so decide whether you would rather set backend to hyperv.'
            degraded  = $true
        }
    }
    return [ordered]@{ available = $true; detail = ('VirtualBox {0} is installed.' -f $version); fix = '' }
}

function ConvertFrom-VBoxState {
    <# VirtualBox state names mapped onto the ones the rest of the project already uses. #>
    param([string]$State)
    switch ($State) {
        'running'      { 'Running' }
        'poweroff'     { 'Off' }
        'aborted'      { 'Off' }
        'paused'       { 'Paused' }
        'saved'        { 'Saved' }
        'starting'     { 'Starting' }
        'stopping'     { 'Stopping' }
        'guru'         { 'Off' }
        default        { if ($State) { (Get-Culture).TextInfo.ToTitleCase($State) } else { 'Unknown' } }
    }
}

function Get-LabVmInfo {
    param([Parameter(Mandatory)][string]$Name)

    $props = Get-VBoxVmProperties -Name $Name
    if (-not $props) { return $null }

    $state = ConvertFrom-VBoxState $props['VMState']
    $memoryMb = if ($props.ContainsKey('memory')) { [int]$props['memory'] } else { 0 }

    # Uptime is reported as the moment the VM last changed state, not as a duration, and only
    # while it is running. Anywhere else this would be an approximation; here the VM only leaves
    # the running state by being stopped, so the two are the same thing.
    $uptime = $null
    if ($state -eq 'Running' -and $props.ContainsKey('VMStateChangeTime')) {
        try { $uptime = [datetime]::UtcNow - ([datetime]::Parse($props['VMStateChangeTime'])).ToUniversalTime() } catch { }
    }

    [ordered]@{
        Name = $Name
        State = $state
        Status = $state
        # VirtualBox reports CPU load only through its metrics collector, which has to be armed
        # per VM before it records anything and reports the host's view rather than the guest's.
        # Reported as unmeasured rather than as zero, which would read as an idle VM.
        CpuPercent = -1
        # Allocated, not assigned. VirtualBox has no dynamic memory, so a running VM holds
        # exactly what it was configured with and the two numbers are the same by construction.
        MemoryBytes = $(if ($state -eq 'Running') { [int64]$memoryMb * 1MB } else { [int64]0 })
        ConfiguredMb = $memoryMb
        CpuCount = $(if ($props.ContainsKey('cpus')) { [int]$props['cpus'] } else { 0 })
        Uptime = $uptime
        # VirtualBox has no per-VM autostart on Windows without the VBoxAutostart service being
        # installed and configured, which this project never does. Reported in the same words
        # Hyper-V uses so the check reads the same on both.
        Autostart = 'Nothing'
        StoragePath = $(if ($props.ContainsKey('CfgFile')) { Split-Path -Parent $props['CfgFile'] } else { '' })
    }
}

function Invoke-LabVmAction {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('start', 'shutdown', 'restart', 'forceoff')][string]$Action
    )
    # Started as a job to match Hyper-V, whose cmdlets take -AsJob. The page polls the job, so
    # the shape has to be the same even though the work is a process rather than a WMI task.
    $exe = Get-VBoxManage
    Start-Job -ScriptBlock {
        param($Exe, $Vm, $What)
        $ErrorActionPreference = 'Stop'
        function Run { param([string[]]$a) $o = & $Exe @a 2>&1; if ($LASTEXITCODE -ne 0) { throw (($o -join ' ').Trim()) } }
        switch ($What) {
            'start'    { Run @('startvm', $Vm, '--type', 'headless') }
            'shutdown' { Run @('controlvm', $Vm, 'acpipowerbutton') }
            'forceoff' { Run @('controlvm', $Vm, 'poweroff') }
            'restart'  {
                Run @('controlvm', $Vm, 'acpipowerbutton')
                # No -Force equivalent that also restarts, so this waits for the guest to go
                # down rather than pulling the power on a manager mid-write.
                foreach ($i in 1..60) {
                    Start-Sleep -Seconds 2
                    $info = & $Exe showvminfo $Vm --machinereadable 2>&1
                    if ($info -match 'VMState="poweroff"') { break }
                }
                Run @('startvm', $Vm, '--type', 'headless')
            }
        }
    } -ArgumentList $exe, $Name, $Action
}

function Set-LabVmNoAutostart {
    param([Parameter(Mandatory)][string]$Name)
    # Nothing to do: VirtualBox does not start VMs with the host unless the VBoxAutostart
    # service has been installed and given a policy, and this project never installs it.
}

function Get-LabNetworkInfo {
    param(
        [Parameter(Mandatory)][string]$NetworkName,
        [Parameter(Mandatory)][string]$Subnet,
        [Parameter(Mandatory)][string]$Gateway
    )
    $hostOnlyList = (Invoke-VBox -Arguments @('list', 'hostonlyifs')).Output -join "`n"
    $natNets      = (Invoke-VBox -Arguments @('list', 'natnetworks')).Output -join "`n"

    [ordered]@{
        SwitchPresent = ($hostOnlyList -match [regex]::Escape($Gateway))
        NatPresent    = ($natNets -match [regex]::Escape($NetworkName))
        SwitchKind    = 'host-only network'
        NatKind       = 'NAT network'
        NatFix        = ('VBoxManage natnetwork add --netname {0} --network {1} --enable --dhcp off' -f $NetworkName, $Subnet)
    }
}

function Get-LabHostOnlyAdapter {
    <# The host-only interface carrying the lab gateway address, by VirtualBox's name for it. #>
    param([Parameter(Mandatory)][string]$Gateway)

    $current = $null
    foreach ($line in (Invoke-VBox -Arguments @('list', 'hostonlyifs')).Output) {
        if ($line -match '^Name:\s+(.+?)\s*$') { $current = $Matches[1] }
        elseif ($line -match '^IPAddress:\s+(\S+)' -and $Matches[1] -eq $Gateway) { return $current }
    }
    return $null
}

function New-LabNetwork {
    param(
        [Parameter(Mandatory)][string]$NetworkName,
        [Parameter(Mandatory)][string]$Subnet,
        [Parameter(Mandatory)][string]$Gateway,
        [Parameter(Mandatory)][int]$PrefixLength
    )

    # The NAT network is outbound only. Its own range is deliberately not the lab subnet: the
    # guests get an unremarkable DHCP address there and do their installing over it, and every
    # address this project names lives on the host-only network instead.
    Invoke-VBox -ThrowOnError -Arguments @(
        'natnetwork', 'add', '--netname', $NetworkName, '--network', '10.0.201.0/24', '--enable', '--dhcp', 'on'
    ) | Out-Null

    $before = @(Get-LabHostOnlyAdapter -Gateway $Gateway)
    if (-not $before) {
        $created = Invoke-VBox -ThrowOnError -Arguments @('hostonlyif', 'create')
        # "Interface 'VirtualBox Host-Only Ethernet Adapter #2' was successfully created"
        $adapter = $null
        foreach ($line in $created.Output) {
            if ($line -match "Interface '(.+?)' was successfully created") { $adapter = $Matches[1]; break }
        }
        if (-not $adapter) { throw 'VirtualBox created a host-only interface but did not say which one.' }

        # Built from the prefix length a byte at a time. Casting a shifted uint32 to IPAddress
        # produces the mask byte-reversed on a little-endian host, which is a wrong netmask that
        # VBoxManage accepts without complaint.
        $maskBytes = @(0, 0, 0, 0)
        for ($bit = 0; $bit -lt $PrefixLength; $bit++) { $maskBytes[[math]::Floor($bit / 8)] = $maskBytes[[math]::Floor($bit / 8)] -bor (0x80 -shr ($bit % 8)) }
        $mask = $maskBytes -join '.'

        Invoke-VBox -ThrowOnError -Arguments @('hostonlyif', 'ipconfig', $adapter, '--ip', $Gateway, '--netmask', $mask) | Out-Null
        # The guests get static addresses from cloud-init, so a DHCP server here would only
        # compete with them.
        Invoke-VBox -Arguments @('dhcpserver', 'remove', '--ifname', $adapter) | Out-Null
    }
}

function Remove-LabNetwork {
    param([Parameter(Mandatory)][string]$NetworkName)
    Invoke-VBox -Arguments @('natnetwork', 'remove', '--netname', $NetworkName) | Out-Null
}

function Test-LabNetworkConflict {
    param(
        [Parameter(Mandatory)][string]$NetworkName,
        [Parameter(Mandatory)][string]$Subnet,
        [Parameter(Mandatory)][string]$Gateway
    )
    $problems = @()
    $natNets = (Invoke-VBox -Arguments @('list', 'natnetworks')).Output -join "`n"
    if ($natNets -match ('NetworkName:\s+' + [regex]::Escape($NetworkName))) {
        $problems += ("A NAT network called {0} already exists. Remove it, or change network.name in lab.config.json." -f $NetworkName)
    }
    if (Get-LabHostOnlyAdapter -Gateway $Gateway) {
        $problems += ("A host-only interface already holds {0}. Remove it, or change network.gateway in lab.config.json." -f $Gateway)
    }
    return $problems
}

function New-LabVm {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$NetworkName,
        [Parameter(Mandatory)][int]$MemoryMb,
        [Parameter(Mandatory)][int]$MinMemoryMb,
        [Parameter(Mandatory)][int]$MaxMemoryMb,
        [Parameter(Mandatory)][int]$Cpu,
        [Parameter(Mandatory)][int]$DiskGb,
        [Parameter(Mandatory)][ValidateSet('ubuntu', 'windows')][string]$Os,
        # Needed to name the host-only adapter NIC2 attaches to. Hyper-V takes the same
        # parameter and ignores it, so one call site serves both backends.
        [Parameter(Mandatory)][string]$Gateway,
        [string]$BootDiskPath
    )

    $hostOnly = Get-LabHostOnlyAdapter -Gateway $Gateway
    if (-not $hostOnly) { throw ("No host-only interface holds {0}. Create the lab network first." -f $Gateway) }

    $osType = if ($Os -eq 'windows') { 'Windows11_64' } else { 'Ubuntu24_LTS_64' }
    Invoke-VBox -ThrowOnError -Arguments @(
        'createvm', '--name', $Name, '--ostype', $osType, '--basefolder', $Directory, '--register'
    ) | Out-Null

    # MinMemoryMb and MaxMemoryMb are accepted and ignored: there is no ballooning driver in
    # play here, so the VM is given its startup size and holds it. Ignoring them silently would
    # make the two backends look identical when they are not, which is what the requirements
    # table's VirtualBox column exists to say.
    $modify = @(
        'modifyvm', $Name,
        '--memory', "$MemoryMb",
        '--cpus', "$Cpu",
        '--firmware', 'efi',
        '--graphicscontroller', 'vmsvga',
        '--vram', '16',
        '--audio-driver', 'none',
        '--usb', 'off',
        '--clipboard-mode', 'disabled',
        '--drag-and-drop', 'disabled',
        # NIC1 outbound, NIC2 the lab. The order matters: the guest configuration binds the
        # static lab address to the second adapter.
        '--nic1', 'natnetwork', '--nat-network1', $NetworkName,
        '--nic2', 'hostonly', '--host-only-adapter2', $hostOnly
    )
    Invoke-VBox -ThrowOnError -Arguments $modify | Out-Null

    if ($Os -eq 'windows') {
        Invoke-VBox -ThrowOnError -Arguments @('modifyvm', $Name, '--tpm-type', '2.0', '--secure-boot', 'on') | Out-Null
    }

    Invoke-VBox -ThrowOnError -Arguments @(
        'storagectl', $Name, '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci', '--portcount', '4'
    ) | Out-Null

    $diskPath = if ($BootDiskPath) { $BootDiskPath } else { Join-Path (Join-Path $Directory $Name) ($Name + '.vdi') }
    if (-not $BootDiskPath) {
        Invoke-VBox -ThrowOnError -Arguments @(
            'createmedium', 'disk', '--filename', $diskPath, '--size', "$($DiskGb * 1024)", '--variant', 'Standard'
        ) | Out-Null
    }
    Invoke-VBox -ThrowOnError -Arguments @(
        'storageattach', $Name, '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd', '--medium', $diskPath
    ) | Out-Null

    # One IDE controller for the ISOs. SATA would work too, but the Windows installer is
    # happier finding its unattend seed on an optical device it recognises without a driver.
    Invoke-VBox -ThrowOnError -Arguments @(
        'storagectl', $Name, '--name', 'IDE', '--add', 'ide', '--controller', 'PIIX4'
    ) | Out-Null

    return $Name
}

function Add-LabVmDvd {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [switch]$FirstBoot
    )
    # Two IDE ports, two devices each. The first free slot wins, which is how a VM ends up with
    # both its installation media and its seed attached rather than only the first.
    foreach ($port in 0, 1) {
        foreach ($device in 0, 1) {
            $props = Get-VBoxVmProperties -Name $Name
            $key = "IDE-$port-$device"
            if (-not $props.ContainsKey($key) -or $props[$key] -eq 'none') {
                Invoke-VBox -ThrowOnError -Arguments @(
                    'storageattach', $Name, '--storagectl', 'IDE', '--port', "$port", '--device', "$device",
                    '--type', 'dvddrive', '--medium', $Path
                ) | Out-Null
                if ($FirstBoot) {
                    Invoke-VBox -ThrowOnError -Arguments @('modifyvm', $Name, '--boot1', 'dvd', '--boot2', 'disk') | Out-Null
                }
                return
            }
        }
    }
    throw ("No free IDE slot on {0} for {1}." -f $Name, $Path)
}

function Add-LabVmDisk {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$SizeGb
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        Invoke-VBox -ThrowOnError -Arguments @('createmedium', 'disk', '--filename', $Path, '--size', "$($SizeGb * 1024)") | Out-Null
    }
    Invoke-VBox -ThrowOnError -Arguments @(
        'storageattach', $Name, '--storagectl', 'SATA', '--port', '1', '--device', '0', '--type', 'hdd', '--medium', $Path
    ) | Out-Null
}

function Resize-LabVmDisk {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][int]$SizeGb)
    Invoke-VBox -ThrowOnError -Arguments @('modifymedium', 'disk', $Path, '--resize', "$($SizeGb * 1024)") | Out-Null
}

function Remove-LabVm {
    param([Parameter(Mandatory)][string]$Name, [switch]$DeleteDisks)

    $props = Get-VBoxVmProperties -Name $Name
    if (-not $props) { return $false }
    if ((ConvertFrom-VBoxState $props['VMState']) -ne 'Off') {
        Invoke-VBox -Arguments @('controlvm', $Name, 'poweroff') | Out-Null
        Start-Sleep -Seconds 3
    }
    # --delete removes the disks along with the definition, which is the opposite default from
    # Hyper-V, so the flag is inverted here rather than at the call site.
    $remove = @('unregistervm', $Name)
    if ($DeleteDisks) { $remove += '--delete' }
    Invoke-VBox -ThrowOnError -Arguments $remove | Out-Null
    return $true
}

Export-ModuleMember -Function Test-LabBackendAvailable, Get-LabVmInfo, Invoke-LabVmAction,
    Set-LabVmNoAutostart, Get-LabNetworkInfo, New-LabNetwork, Remove-LabNetwork,
    Test-LabNetworkConflict, New-LabVm, Add-LabVmDvd, Add-LabVmDisk, Resize-LabVmDisk, Remove-LabVm
