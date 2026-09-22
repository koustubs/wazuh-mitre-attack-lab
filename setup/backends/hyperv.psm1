<#
    The Hyper-V implementation of the backend contract in ..\LabBackend.ps1.

    Every function here is a thin wrapper over a Hyper-V cmdlet. The wrapping earns its keep in
    two places and is nearly free everywhere else: Get-LabVmInfo flattens a VM object into the
    same shape VirtualBox can produce, and New-LabVm decides Generation 1 against Generation 2,
    which is a Hyper-V concept with no VirtualBox equivalent.

    Nothing in this file reads lab.config.json. It is handed what to do.
#>

Set-StrictMode -Version Latest

function Test-LabBackendAvailable {
    <#
        Whether this host can run the lab on Hyper-V, and if not, the one thing to do about it.

        The service is the honest test. The optional feature can be installed and not running,
        and a running vmms proves SLAT, firmware virtualization and the rest are all satisfied,
        which is a stronger statement than any of them read separately.
    #>
    $vmms = $null
    try { $vmms = Get-Service -Name 'vmms' -ErrorAction Stop } catch { }
    if (-not $vmms) {
        return [ordered]@{
            available = $false
            detail    = 'The Hyper-V Virtual Machine Management service is not installed on this host.'
            fix       = 'Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All, from an elevated prompt, then reboot. Hyper-V needs Windows Pro, Enterprise or Education; on Home, use the VirtualBox backend.'
        }
    }
    if ($vmms.Status -ne 'Running') {
        return [ordered]@{
            available = $false
            detail    = ('The Hyper-V management service is installed but {0}.' -f $vmms.Status.ToString().ToLower())
            fix       = 'Start-Service vmms. If it refuses, reboot: the hypervisor loads at boot, not on demand.'
        }
    }
    if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
        return [ordered]@{
            available = $false
            detail    = 'The hypervisor is running but the Hyper-V PowerShell module is not installed, so nothing here can talk to it.'
            fix       = 'Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell'
        }
    }
    return [ordered]@{ available = $true; detail = 'The Hyper-V management service is running.'; fix = '' }
}

function Get-LabVmInfo {
    <#
        One VM flattened into the shape the dashboard renders, or $null when it does not exist.

        Returning $null for both "absent" and "not permitted to look" would be a lie, so the
        caller checks elevation itself and this only reports what it could read.
    #>
    param([Parameter(Mandatory)][string]$Name)

    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $vm) { return $null }

    [ordered]@{
        Name         = $vm.Name
        State        = $vm.State.ToString()
        Status       = [string]$vm.Status
        CpuPercent   = [int]$vm.CPUUsage
        MemoryBytes  = [int64]$vm.MemoryAssigned
        ConfiguredMb = [int]($vm.MemoryStartup / 1MB)
        CpuCount     = [int]$vm.ProcessorCount
        Uptime       = $vm.Uptime
        Autostart    = $vm.AutomaticStartAction.ToString()
        # Used to work out which drive the disks are really on, rather than assuming one.
        StoragePath  = [string]$vm.Path
    }
}

function Invoke-LabVmAction {
    <#
        Power actions, started as a job so the page does not block on a shutdown that can take a
        minute. The caller names the job; this returns it.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('start', 'shutdown', 'restart', 'forceoff')][string]$Action
    )
    switch ($Action) {
        'start'    { Start-VM   -Name $Name -AsJob }
        'shutdown' { Stop-VM    -Name $Name -Force -AsJob }
        'restart'  { Restart-VM -Name $Name -Force -AsJob }
        'forceoff' { Stop-VM    -Name $Name -TurnOff -Force -AsJob }
    }
}

function Set-LabVmNoAutostart {
    <# The only autostart value this project writes. There is deliberately no enable path. #>
    param([Parameter(Mandatory)][string]$Name)
    Set-VM -Name $Name -AutomaticStartAction Nothing
}

function Send-LabVmKey {
    <#
        Presses a key at a guest's console, for the one place this lab needs one.

        Windows media shows "Press any key to boot from CD or DVD" for about five seconds.
        Unpressed, the boot manager hands back to the firmware, which reports "The boot loader
        failed" against the DVD and falls through to a disk with no operating system on it. The
        guest then sits there having written nothing, and no log on either side says why.

        Repeated rather than timed, because firmware start-up is not a fixed length: the window
        is hit by pressing across it instead of predicting where it falls. Presses outside it go
        nowhere, since the firmware discards them and an unattended Setup takes no input.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('space', 'enter')][string]$Key = 'space',
        [int]$Repeat = 1,
        [int]$IntervalMs = 500
    )

    $code = switch ($Key) { 'space' { 0x20 } 'enter' { 0x0D } }
    $ns = 'root/virtualization/v2'

    $machine = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem `
        -Filter ("ElementName='{0}'" -f $Name) -ErrorAction SilentlyContinue
    if (-not $machine) {
        return [ordered]@{ sent = 0; refused = 0; detail = ("There is no VM called {0}." -f $Name) }
    }

    $keyboard = Get-CimAssociatedInstance -InputObject $machine -ResultClassName Msvm_Keyboard `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $keyboard) {
        return [ordered]@{
            sent = 0; refused = 0
            detail = ("{0} exposes no synthetic keyboard, which a stopped VM does not, so the key has to be pressed at its console." -f $Name)
        }
    }

    $sent = 0; $refused = 0
    for ($i = 0; $i -lt $Repeat; $i++) {
        try {
            $result = Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey `
                -Arguments @{ keyCode = [uint32]$code }
            if ($result.ReturnValue -eq 0) { $sent++ } else { $refused++ }
        } catch {
            # Counted, not thrown. A press refused while the VM is still coming up says nothing
            # about the next one, and one lost press out of sixty is not a failure.
            $refused++
        }
        if ($i -lt ($Repeat - 1)) { Start-Sleep -Milliseconds $IntervalMs }
    }
    [ordered]@{ sent = $sent; refused = $refused; detail = '' }
}

function Get-LabNetworkInfo {
    <#
        Whether the lab network exists, as two separate facts, because they fail separately: a
        switch without a NAT gives the guests each other and this host but no internet, which is
        a working lab that cannot install anything.
    #>
    param(
        [Parameter(Mandatory)][string]$NetworkName,
        [Parameter(Mandatory)][string]$Subnet,
        [Parameter(Mandatory)][string]$Gateway
    )
    $prefix = $Gateway -replace '\.\d+$', '.'
    $sw = Get-VMSwitch -Name $NetworkName -ErrorAction SilentlyContinue
    $nat = @(Get-NetNat -ErrorAction SilentlyContinue |
        Where-Object { $_.InternalIPInterfaceAddressPrefix -like ($prefix + '*') })

    [ordered]@{
        SwitchPresent = [bool]$sw
        NatPresent    = ($nat.Count -gt 0)
        SwitchKind    = 'internal switch'
        NatKind       = 'WinNAT'
        NatFix        = ('New-NetNat -Name {0} -InternalIPInterfaceAddressPrefix {1}' -f $NetworkName, $Subnet)
    }
}

function New-LabNetwork {
    <#
        An internal switch, an address on this host's end of it, and a NAT so the guests can
        reach the internet to install Wazuh.
    #>
    param(
        [Parameter(Mandatory)][string]$NetworkName,
        [Parameter(Mandatory)][string]$Subnet,
        [Parameter(Mandatory)][string]$Gateway,
        [Parameter(Mandatory)][int]$PrefixLength
    )

    New-VMSwitch -Name $NetworkName -SwitchType Internal | Out-Null

    # The host adapter appears asynchronously. The original code read it on the next line with no
    # retry under Set-StrictMode, so a lost race left a switch with no address and a half-built
    # lab that the guards then refused to touch.
    $adapterName = 'vEthernet ({0})' -f $NetworkName
    $adapter = $null
    foreach ($attempt in 1..30) {
        $adapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
        if ($adapter) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $adapter) {
        throw ("The switch {0} was created but its host adapter '{1}' never appeared. Remove the switch and try again." -f $NetworkName, $adapterName)
    }

    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $Gateway -PrefixLength $PrefixLength | Out-Null
    New-NetNat -Name $NetworkName -InternalIPInterfaceAddressPrefix $Subnet | Out-Null
}

function Remove-LabNetwork {
    param([Parameter(Mandatory)][string]$NetworkName)
    Get-NetNat -Name $NetworkName -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false
    Get-VMSwitch -Name $NetworkName -ErrorAction SilentlyContinue | Remove-VMSwitch -Force
}

function Test-LabNetworkConflict {
    <#
        Reasons this host cannot host the lab network, as a list of sentences, empty when there
        are none.

        The original refused if any WinNAT existed at all. WSL2 and Docker Desktop both create
        one, so that was a likely first run failure for anyone who had either installed. What
        matters is a NAT that overlaps this subnet, not a NAT.
    #>
    param(
        [Parameter(Mandatory)][string]$NetworkName,
        [Parameter(Mandatory)][string]$Subnet,
        [Parameter(Mandatory)][string]$Gateway
    )
    $problems = @()
    $prefix = $Gateway -replace '\.\d+$', '.'

    if (Get-VMSwitch -Name $NetworkName -ErrorAction SilentlyContinue) {
        $problems += ("A virtual switch called {0} already exists. Remove it, or change network.name in lab.config.json." -f $NetworkName)
    }
    $clashing = @(Get-NetNat -ErrorAction SilentlyContinue |
        Where-Object { $_.InternalIPInterfaceAddressPrefix -like ($prefix + '*') })
    foreach ($nat in $clashing) {
        $problems += ("The NAT network '{0}' already covers {1}. Remove it, or change network.subnet in lab.config.json." -f $nat.Name, $nat.InternalIPInterfaceAddressPrefix)
    }
    $routed = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -like ($prefix + '*') })
    if ($routed.Count -gt 0 -and $clashing.Count -eq 0) {
        $problems += ("Something already routes {0}. Change network.subnet in lab.config.json to a range this host does not use." -f $routed[0].DestinationPrefix)
    }
    return $problems
}

function New-LabVm {
    <#
        One VM, sized from lab.config.json, attached to the lab network and set never to start
        with the host.

        Generation is decided here rather than configured. The Windows endpoint needs Generation
        2 for TPM and Secure Boot, which Windows 11 requires. The Ubuntu guests are Generation 1.

        The cloud image would boot either way: its GPT carries both a BIOS boot partition and a
        106 MB EFI system partition. Generation 1 is chosen because a Generation 2 VM boots with
        Secure Boot on and rejects Canonical's shim unless it is switched to the Microsoft UEFI
        certificate authority template, which is one more thing to get right for a guest that
        gains nothing from it. A legacy boot is the entire cost.
    #>
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
        # Accepted and unused. VirtualBox needs it to name the host-only adapter its second NIC
        # attaches to; an internal switch has no such thing. Both backends take it so the call
        # site does not have to know which one it is talking to.
        [Parameter(Mandatory)][string]$Gateway,
        # An existing disk to boot from, for the Ubuntu cloud image. Without it an empty disk of
        # DiskGb is created instead, which is what the Windows endpoint needs.
        [string]$BootDiskPath,
        # Twelve hex digits from Get-LabMacAddress. VirtualBox needs it to tell the guest which
        # of its two adapters is the lab one. A Hyper-V guest has one adapter and could manage
        # without, but it is set here too so that the guest-side configuration is the same on
        # both backends, and so a rebuilt VM keeps the address it had.
        [string]$MacAddress
    )

    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory | Out-Null }
    $generation = if ($Os -eq 'windows') { 2 } else { 1 }

    $options = @{
        Name               = $Name
        Generation         = $generation
        MemoryStartupBytes = $MemoryMb * 1MB
        Path               = $Directory
        SwitchName         = $NetworkName
    }
    if ($BootDiskPath) {
        $options.VHDPath = $BootDiskPath
    } else {
        $options.NewVHDPath     = Join-Path $Directory ($Name + '.vhdx')
        $options.NewVHDSizeBytes = $DiskGb * 1GB
    }
    $vm = New-VM @options

    Set-VMProcessor -VM $vm -Count $Cpu
    Set-VM -VM $vm -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -CheckpointType Standard

    # Client Hyper-V has automatic checkpoints on by default, so every start writes a differencing
    # .avhdx under Snapshots and the disk the profile budgeted stops being the disk in use. Off
    # here rather than left as something to go and find. Server 2016 has no such setting and is
    # older than this lab supports, so a host without it is told rather than failed.
    if ((Get-Command Set-VM).Parameters.ContainsKey('AutomaticCheckpointsEnabled')) {
        Set-VM -VM $vm -AutomaticCheckpointsEnabled $false
    } else {
        Write-Warning ("{0}: this host has no automatic checkpoint setting, so Hyper-V may take one on every start." -f $Name)
    }
    if ($MacAddress) { Set-VMNetworkAdapter -VM $vm -StaticMacAddress $MacAddress }

    # Dynamic memory on, reversing the original. A guest that is idle hands its pages back, which
    # is the difference between the full profile fitting a 16 GB host and not. The minimum is the
    # floor Wazuh needs to keep its services up, not a number that sounds small.
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $true `
        -MinimumBytes ($MinMemoryMb * 1MB) -StartupBytes ($MemoryMb * 1MB) -MaximumBytes ($MaxMemoryMb * 1MB)

    if ($generation -eq 2) {
        Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
        Enable-VMTPM -VM $vm
        Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
    }
    return $vm
}

function Add-LabVmDvd {
    <#
        Attaches an ISO. Called more than once per VM: the Windows endpoint takes its
        installation media and its unattend seed, and the original attached only the first, which
        is why the deployment guide carried "attach the seed ISO" as a manual step.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [switch]$FirstBoot
    )
    $vm = Get-VM -Name $Name -ErrorAction Stop
    $dvd = Add-VMDvdDrive -VM $vm -Path $Path -Passthru
    if ($FirstBoot) {
        if ($vm.Generation -eq 2) {
            Set-VMFirmware -VM $vm -FirstBootDevice $dvd
        } else {
            # Generation 1 has no firmware boot order cmdlet; the BIOS one takes device classes.
            Set-VMBios -VM $vm -StartupOrder @('CD', 'IDE', 'LegacyNetworkAdapter', 'Floppy')
        }
    }
    return $dvd
}

function Add-LabVmDisk {
    <# A second disk, for the Ubuntu guests whose boot disk is the cloud image. #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$SizeGb
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-VHD -Path $Path -SizeBytes ($SizeGb * 1GB) -Dynamic | Out-Null
    }
    Add-VMHardDiskDrive -VMName $Name -Path $Path
}

function Resize-LabVmDisk {
    <# Grows the cloud image's disk, which ships at about 3.5 GB, to the profile's size. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][int]$SizeGb)
    $current = (Get-VHD -Path $Path).Size
    if ($current -lt ($SizeGb * 1GB)) { Resize-VHD -Path $Path -SizeBytes ($SizeGb * 1GB) }
}

function ConvertTo-LabBootDisk {
    <#
        Turns the converted cloud image into the disk format this backend boots, at a path of
        the caller's choosing.

        Get-LabImage.ps1 writes a fixed VHD, because a fixed VHD is the one format where a guest
        offset is a file offset and so can be written sparsely from the image's allocated
        clusters. A fixed VHD is also its full declared size on disk, so it is not what the
        guests should be copying. One pass makes it dynamic.
    #>
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)

    # A function in a module does not inherit the calling script's $ErrorActionPreference, so
    # without this line a failed conversion is a non-terminating error the caller never sees.
    # It cost a deleted source image to find that out.
    $ErrorActionPreference = 'Stop'

    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Force }
    Convert-VHD -Path $Source -DestinationPath $Destination -VHDType Dynamic
    if (-not (Test-Path -LiteralPath $Destination)) {
        throw "Convert-VHD reported no error but produced nothing at $Destination."
    }
}

function Copy-LabBootDisk {
    <# One guest's own copy of the prepared image, so the cached one is never written to. #>
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Get-LabBootDiskExtension { '.vhdx' }

function Remove-LabVm {
    <#
        Removes the definition, and the disks only when asked. A teardown that silently deleted
        disks would be the wrong default for something that took an hour to install.
    #>
    param([Parameter(Mandatory)][string]$Name, [switch]$DeleteDisks)

    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $vm) { return $false }
    if ($vm.State.ToString() -ne 'Off') { Stop-VM -Name $Name -TurnOff -Force }

    $disks = @(Get-VMHardDiskDrive -VMName $Name | Select-Object -ExpandProperty Path)
    Remove-VM -Name $Name -Force
    if ($DeleteDisks) {
        foreach ($disk in $disks) {
            if (Test-Path -LiteralPath $disk) { Remove-Item -LiteralPath $disk -Force }
        }
    }
    return $true
}

Export-ModuleMember -Function Test-LabBackendAvailable, Get-LabVmInfo, Invoke-LabVmAction,
    Set-LabVmNoAutostart, Send-LabVmKey, Get-LabNetworkInfo, New-LabNetwork, Remove-LabNetwork,
    Test-LabNetworkConflict, New-LabVm, Add-LabVmDvd, Add-LabVmDisk, Resize-LabVmDisk,
    ConvertTo-LabBootDisk, Copy-LabBootDisk, Get-LabBootDiskExtension, Remove-LabVm
