#requires -Version 5.1
#requires -RunAsAdministrator
<#
    Takes the lab apart: the profile's virtual machines, and the network they sit on.

    Disks are kept unless you ask for them to go. A manager that took half an hour to install
    and forty minutes of campaign to fill is not something a teardown script should decide to
    delete on your behalf, and -DeleteDisks is one word to type when you do mean it.

    Nothing under .lab-secrets or evidence is touched. The keys still work against a rebuilt
    lab, because the seeds carry the same public key.

        .\Remove-Lab.ps1                 the VMs and the network, disks left on disk
        .\Remove-Lab.ps1 -DeleteDisks    and the disks
        .\Remove-Lab.ps1 -KeepNetwork    the VMs only
        .\Remove-Lab.ps1 -Only WAZUH-WIN one machine, to replace a dead endpoint
        .\Remove-Lab.ps1 -Force          no confirmation prompt
#>
[CmdletBinding()]
param(
    [ValidateSet('lean', 'full')][string]$Profile,
    [ValidateSet('hyperv', 'virtualbox')][string]$Backend,
    [string]$StorageRoot,
    [switch]$DeleteDisks,
    [switch]$KeepNetwork,
    # Part of the profile rather than all of it, the other half of New-Lab's -Only. Replacing
    # an endpoint that will not boot should not take down a manager that was half an hour of
    # installing. The network is kept whenever this is given, because removing one guest is
    # not a reason to remove the switch the others are still on.
    [string[]]$Only,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabBackend.ps1')

$config = if ($Profile) { Get-LabConfig -Profile $Profile } else { Get-LabConfig }
$pass = @{}
if ($Profile) { $pass['Profile'] = $Profile }
if ($Only)    { $pass['Only']    = $Only }
$vms = Get-LabVms @pass
if ($Only) { $KeepNetwork = $true }
if (-not $Backend) { $Backend = $config.backend }
Import-LabBackend -Backend $Backend | Out-Null

if (-not $StorageRoot) { $StorageRoot = $config.storageRoot }
$root = [IO.Path]::GetFullPath(($StorageRoot -replace '/', '\')).TrimEnd('\')
$net = $config.network

# ---- what is actually here ---------------------------------------------------------------------
#
# Listed before anything is removed, because "remove the lab" should show you the lab it found
# rather than the lab the configuration describes. Those differ the moment someone renames a VM.

$present = @()
foreach ($name in $vms.Keys) {
    $info = Get-LabVmInfo -Name $name
    if ($info) { $present += $info }
}
$netInfo = Get-LabNetworkInfo -NetworkName $net.name -Subnet $net.subnet -Gateway $net.gateway
$removingNetwork = (-not $KeepNetwork) -and ($netInfo.SwitchPresent -or $netInfo.NatPresent)

# A VM this profile does not build can still be sitting on this network. Running -Profile lean
# against a host that has a full lab on it would otherwise take the switch out from under the
# Windows endpoint, which is not what "remove the lean profile" means.
$strays = @()
foreach ($name in $config.vms.PSObject.Properties.Name) {
    if ($vms.Contains($name)) { continue }
    if (Get-LabVmInfo -Name $name) { $strays += $name }
}
if ($removingNetwork -and $strays.Count -gt 0) {
    Write-Host ''
    Write-Host ("Keeping the {0} network: {1} still exists and is attached to it." -f $net.name, ($strays -join ', ')) -ForegroundColor Yellow
    Write-Host 'Remove that too, or re-run without -Profile, to take the network down as well.'
    $removingNetwork = $false
}

if ($present.Count -eq 0 -and -not $removingNetwork) {
    Write-Host ("Nothing to remove. No {0} profile VM exists and the {1} network is not here." -f $config.profile, $net.name)
    exit 0
}

Write-Host ''
Write-Host 'This will remove:'
foreach ($info in $present) {
    Write-Host ("  {0,-14} {1}" -f $info.Name, $info.State)
    if ($DeleteDisks -and $info.StoragePath) {
        Write-Host ("                 and its disks under {0}" -f $info.StoragePath) -ForegroundColor Yellow
    }
}
if ($removingNetwork) {
    Write-Host ("  {0,-14} the {1} and the {2}" -f $net.name, $netInfo.SwitchKind, $netInfo.NatKind)
}
if (-not $DeleteDisks -and $present.Count -gt 0) {
    Write-Host ''
    Write-Host ("  Disks are kept. They are under {0}, and a rebuild will refuse to overwrite them." -f $root) -ForegroundColor DarkGray
}

if (-not $Force) {
    Write-Host ''
    try {
        $answer = Read-Host 'Type the word remove to go ahead'
    } catch {
        # No console to ask at, which is the case when this runs from a scheduled task or
        # another script. Refusing is the right answer; -Force is how you say you meant it.
        Write-Host 'There is no console to confirm at. Re-run with -Force if that is what you want.' -ForegroundColor Red
        exit 1
    }
    if ($answer -ne 'remove') {
        Write-Host 'Nothing was changed.'
        exit 1
    }
}

# ---- remove --------------------------------------------------------------------------------------

Write-Host ''
foreach ($info in $present) {
    Write-Host ("  removing {0}" -f $info.Name)
    # Remove-LabVm turns a running guest off rather than shutting it down. A teardown that waits
    # on a guest that is not listening waits forever, and nothing in the guest is worth the
    # clean shutdown once the disks are going too.
    Remove-LabVm -Name $info.Name -DeleteDisks:$DeleteDisks | Out-Null

    if ($DeleteDisks) {
        # The VM's own directory under storageRoot, which the backend does not own and so does
        # not remove. Only when it holds no files: anything else in there was put there by hand.
        #
        # Files rather than entries, because Hyper-V leaves an empty Snapshots and an empty
        # Virtual Machines folder behind after the VM is gone. Testing for entries found those,
        # concluded the directory was in use, and left a skeleton that New-Lab.ps1 then refused
        # to build into, so the rebuild this script recommends on its last line failed on the
        # very next command.
        $vmDir = Join-Path $root $info.Name
        if ((Test-Path -LiteralPath $vmDir) -and
            -not (Get-ChildItem -LiteralPath $vmDir -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            Remove-Item -LiteralPath $vmDir -Recurse -Force
        }
    }
}

if ($removingNetwork) {
    Write-Host ("  removing the {0} network" -f $net.name)
    Remove-LabNetwork -NetworkName $net.name
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
if (-not $DeleteDisks -and $present.Count -gt 0) {
    Write-Host ("Disks are still under {0}. Delete them yourself, or re-run with -DeleteDisks." -f $root)
}
Write-Host 'Rebuild with setup\New-Lab.ps1. The keys in .lab-secrets still work; the seeds carry the same one.'
