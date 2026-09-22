#requires -Version 5.1
#requires -RunAsAdministrator
<#
    Creates the lab network and the profile's virtual machines, and attaches everything they
    boot from.

    Nothing here installs an operating system. The Ubuntu guests boot their own copy of the
    cloud image Get-LabImage.ps1 prepared, and cloud-init configures them from the seed
    New-LabSeeds.ps1 built, on their first boot. The Windows endpoint, which the full profile
    includes and the lean one does not, still boots an installer, driven by the unattend seed
    from New-WindowsSeed.ps1.

    This checks the handful of things it is about to depend on and refuses on those.
    Test-LabHost.ps1 is what tells you whether the machine can host the lab at all; run it
    first.

        .\New-Lab.ps1
        .\New-Lab.ps1 -Profile lean
        .\New-Lab.ps1 -WindowsIso D:\iso\Win11_Enterprise_Eval.iso
#>
[CmdletBinding()]
param(
    [ValidateSet('lean', 'full')][string]$Profile,
    [ValidateSet('hyperv', 'virtualbox')][string]$Backend,
    # Only the full profile needs one, because only it builds a Windows endpoint. The free
    # Windows 11 Enterprise evaluation image works and needs no product key; docs\setup.md says
    # where to get it.
    [string]$WindowsIso,
    [string]$StorageRoot,
    # Build part of the profile rather than all of it, for when one guest has to be replaced and
    # the others are fine. Without it the only way to rebuild a dead endpoint is Remove-Lab.ps1,
    # which takes a manager that was half an hour of installing down with it.
    [string[]]$Only
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabBackend.ps1')

$config = if ($Profile) { Get-LabConfig -Profile $Profile } else { Get-LabConfig }
$pass = @{}
if ($Profile) { $pass['Profile'] = $Profile }
if ($Only)    { $pass['Only']    = $Only }
$vms    = Get-LabVms @pass
# Costed over the same subset, so building one endpoint is not refused for wanting the whole
# profile's disk.
$budget = Get-LabBudget @pass
if (-not $Backend) { $Backend = $config.backend }
Import-LabBackend -Backend $Backend | Out-Null

if (-not $StorageRoot) { $StorageRoot = $config.storageRoot }
$root = [IO.Path]::GetFullPath(($StorageRoot -replace '/', '\')).TrimEnd('\')
if ($root -notmatch '^[A-Za-z]:\\[^\\]+') {
    throw "storageRoot has to be a directory on a drive, not a drive root. Got: $root"
}

$net = $config.network
$seeds = Get-LabPath Seeds
$bootImage = Join-Path (Get-LabPath Images) ('ubuntu-cloudimg' + (Get-LabBootDiskExtension))

# ---- everything this is about to depend on, reported together ----------------------------------
#
# Collected rather than thrown one at a time. Being told about the missing image, then about the
# missing seeds, then about the missing ISO, one run each, is three rebuilds of nothing.

$problems = @()

foreach ($name in $vms.Keys) {
    $existingDir = Join-Path $root $name
    if (Get-LabVmInfo -Name $name) {
        # Its directory is almost certainly there too. Saying so as well would be one more line
        # about the same VM, and the fix for both is the same.
        $problems += "A VM called $name already exists. Remove it with setup\Remove-Lab.ps1, or rename it."
    } elseif ((Test-Path -LiteralPath $existingDir) -and
              (Get-ChildItem -LiteralPath $existingDir -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        # Files, not entries. Removing a VM leaves its Snapshots and Virtual Machines folders
        # behind empty, and a directory holding nothing but those is not something to review:
        # it is what a teardown looks like from the outside. Testing the directory's existence
        # instead turned "rebuild with setup\New-Lab.ps1", which is what Remove-Lab.ps1 tells
        # you to do next, into an error on the very next command.
        $problems += "$existingDir already holds files, though no VM uses them. Review it before this writes a disk there."
    }
}

$netInfo = Get-LabNetworkInfo -NetworkName $net.name -Subnet $net.subnet -Gateway $net.gateway
$networkExists = $netInfo.SwitchPresent -and $netInfo.NatPresent
if (-not $networkExists) {
    if ($netInfo.SwitchPresent -or $netInfo.NatPresent) {
        $halfBuilt = 'Half the lab network is there: {0} {1}, {2} {3}. Clear it with setup\Remove-Lab.ps1 and let this build both.'
        $problems += ($halfBuilt -f
            $netInfo.SwitchKind, $(if ($netInfo.SwitchPresent) { 'present' } else { 'missing' }),
            $netInfo.NatKind,    $(if ($netInfo.NatPresent)    { 'present' } else { 'missing' }))
    } else {
        $problems += Test-LabNetworkConflict -NetworkName $net.name -Subnet $net.subnet -Gateway $net.gateway
    }
}

$ubuntuCount = @($vms.Values | Where-Object { $_.Os -eq 'ubuntu' }).Count
if ($ubuntuCount -gt 0 -and -not (Test-Path -LiteralPath $bootImage)) {
    $problems += "No prepared Ubuntu image at $bootImage. Run setup\Get-LabImage.ps1."
}
foreach ($vm in $vms.Values) {
    if ($vm.Os -ne 'ubuntu') { continue }
    $seed = Join-Path $seeds ($vm.Hostname + '-seed.iso')
    if (-not (Test-Path -LiteralPath $seed)) {
        $problems += "No cloud-init seed for $($vm.Name) at $seed. Run setup\New-LabSeeds.ps1."
    }
}

$windowsCount = @($vms.Values | Where-Object { $_.Os -eq 'windows' }).Count
$unattend = Join-Path $seeds 'windows-unattend.iso'
if ($windowsCount -gt 0) {
    if (-not $WindowsIso) {
        $problems += "The $($config.profile) profile includes a Windows endpoint, so it needs -WindowsIso. Run with -Profile lean to build the lab without one."
    } elseif (-not (Test-Path -LiteralPath $WindowsIso -PathType Leaf)) {
        $problems += "No Windows installation ISO at $WindowsIso."
    }
    if (-not (Test-Path -LiteralPath $unattend)) {
        $problems += "No unattend seed at $unattend. Run setup\New-WindowsSeed.ps1."
    }
}

# Disks expand as they are written, so this is the worst case rather than day one. It is still
# the number to check: running out of room part way through a disk write corrupts the guest.
$driveLetter = $root.Substring(0, 2)
$disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $driveLetter) -ErrorAction SilentlyContinue
if ($disk) {
    $freeGb = [math]::Round($disk.FreeSpace / 1GB, 1)
    if ($freeGb -lt $budget.DiskWithHeadroomGb) {
        $tooSmall = 'The {0} profile wants {1} GB on {2} at worst case and there is {3} GB. Use -Profile lean, or point storageRoot in lab.config.json at another drive.'
        $problems += ($tooSmall -f $config.profile, $budget.DiskWithHeadroomGb, $driveLetter, $freeGb)
    }
}

if ($problems.Count -gt 0) {
    Write-Host ''
    Write-Host 'This machine is not ready to build the lab:' -ForegroundColor Red
    foreach ($problem in $problems) { Write-Host ("  - {0}" -f $problem) }
    Write-Host ''
    exit 1
}

# ---- build -------------------------------------------------------------------------------------

$what = "the {0} profile" -f $config.profile
if ($Only) { $what = "{0} of the {1} profile" -f ($vms.Keys -join ', '), $config.profile }
Write-Host ("Building {0} on {1}: {2} VMs, {3} GB of memory at startup, up to {4} GB of disk." -f
    $what, $Backend, $budget.VmCount, $budget.MemoryGb, $budget.DiskGb)

if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root | Out-Null }

if ($networkExists) {
    Write-Host ("  network {0}, already present, reused" -f $net.name)
} else {
    Write-Host ("  network {0}: {1}, gateway {2}" -f $net.name, $net.subnet, $net.gateway)
    New-LabNetwork -NetworkName $net.name -Subnet $net.subnet -Gateway $net.gateway -PrefixLength $net.prefixLength
}

foreach ($name in $vms.Keys) {
    $vm = $vms[$name]
    $vmDir = Join-Path $root $name
    Write-Host ("  {0,-14} {1} MB, {2} vCPU, {3} GB, {4}" -f $name, $vm.MemoryMb, $vm.Cpu, $vm.DiskGb, $vm.Address)
    New-Item -ItemType Directory -Path $vmDir -Force | Out-Null

    $bootDisk = ''
    if ($vm.Os -eq 'ubuntu') {
        $bootDisk = Join-Path $vmDir ($name + (Get-LabBootDiskExtension))
        Write-Host '                 copying the prepared image'
        Copy-LabBootDisk -Source $bootImage -Destination $bootDisk
        # Grown here rather than inside the guest. The image declares about 3.5 GB and
        # cloud-init's growpart extends the root partition to fill whatever it is handed, so the
        # disk has to be the profile's size before the guest boots for the first time.
        Resize-LabVmDisk -Path $bootDisk -SizeGb $vm.DiskGb
    }

    New-LabVm -Name $name -Directory $vmDir -NetworkName $net.name `
        -MemoryMb $vm.MemoryMb -MinMemoryMb $vm.MinMemoryMb -MaxMemoryMb $vm.MaxMemoryMb `
        -Cpu $vm.Cpu -DiskGb $vm.DiskGb -Os $vm.Os -Gateway $net.gateway `
        -BootDiskPath $bootDisk -MacAddress (Get-LabMacAddress -Address $vm.Address) | Out-Null

    if ($vm.Os -eq 'ubuntu') {
        # No -FirstBoot. The seed carries no boot record, so the firmware skips it and falls
        # through to the disk, which is what should happen on every boot and not only the first.
        Add-LabVmDvd -Name $name -Path (Join-Path $seeds ($vm.Hostname + '-seed.iso')) | Out-Null
    } else {
        Add-LabVmDvd -Name $name -Path $WindowsIso -FirstBoot | Out-Null
        Add-LabVmDvd -Name $name -Path $unattend | Out-Null
    }

    Set-LabVmNoAutostart -Name $name
}

$keyPath = Join-Path (Get-LabPath Secrets) 'lab_ed25519'

Write-Host ''
Write-Host ("Built under {0}: {1}." -f $root, ($vms.Keys -join ', ')) -ForegroundColor Green
Write-Host 'Nothing is running and nothing starts with the host. Next:'
Write-Host ''
if ($vms.Contains('WAZUH-MANAGER')) {
    $manager = $vms['WAZUH-MANAGER']
    Write-Host ("  1. Start {0} and give cloud-init a minute or two on its first boot." -f $manager.Name)
    Write-Host "     Either the dashboard's power buttons, or your hypervisor's own console."
    Write-Host ("  2. ssh -i {0} {1}@{2}" -f $keyPath, $config.guest.user, $manager.Address)
    Write-Host '  3. Copy manager\install-manager.sh over and run it with sudo.'
    if ($windowsCount -gt 0) {
        Write-Host '  4. The Windows endpoint installs itself from the unattend seed. It reboots twice.'
    }
} else {
    # A subset build against a manager that is already up, so the install steps above are behind
    # us and what is left is the new guest joining what is already there.
    if ($windowsCount -gt 0) {
        Write-Host '  1. The Windows endpoint installs itself from the unattend seed. It reboots twice.'
        Write-Host '     Give it twenty minutes or so before the next step.'
    } else {
        Write-Host '  1. Start it and give cloud-init a minute or two on its first boot.'
    }
    Write-Host ("  2. Enrol it: setup\Install-LabAgents.ps1 -Only {0}" -f ($vms.Keys -join ','))
}
Write-Host ''
Write-Host 'Teardown, when you are done: setup\Remove-Lab.ps1'
