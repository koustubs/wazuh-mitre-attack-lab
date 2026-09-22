#requires -Version 5.1
#requires -RunAsAdministrator
<#
    Starts the Windows endpoint for its first boot and presses the key its installer waits for.

    Retail and evaluation Windows media both show "Press any key to boot from CD or DVD" for
    about five seconds. With nobody at the console the boot manager returns to the firmware,
    which reports "The boot loader failed" on the DVD and falls through to a disk with no
    operating system on it yet. The guest then sits there having written nothing at all, which
    looks like a VM that is broken rather than one that is waiting, and there is no error
    anywhere to say which it is.

    So this is the Windows endpoint's first boot, with the key pressed across the whole window
    rather than at a guessed point inside it. Later boots need none of this: the installed disk
    sits behind the ISO in the boot order, so the prompt lapses, the firmware moves on to
    Windows, and the cost is five seconds and no attention.

        .\Start-WindowsInstall.ps1
        .\Start-WindowsInstall.ps1 -Profile full
#>
[CmdletBinding()]
param(
    [ValidateSet('lean', 'full')][string]$Profile,
    [ValidateSet('hyperv', 'virtualbox')][string]$Backend,
    # How long to keep pressing. Firmware start-up is not a fixed length, so this covers a slow
    # host with room to spare rather than predicting where the prompt falls. Presses that land
    # outside it go nowhere: the firmware discards them and an unattended Setup takes no input.
    [int]$PressSeconds = 30
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabBackend.ps1')

function Get-LabVmDiskBytes {
    <#
        Every disk file the VM owns, added up, or -1 where they could not be read.

        Separating "measured nothing" from "could not measure" the same way Get-LabVmInfo
        separates an idle CPU from an unmeasured one. This is the only evidence available from
        the host that Setup is running: an installer writes gigabytes within a minute, and a
        guest stopped at the firmware writes nothing at all.
    #>
    param([string]$Path)

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return -1 }
    $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Extension -in '.vhdx', '.vhd', '.avhdx', '.vdi' })
    if (-not $files) { return -1 }
    return [int64](($files | Measure-Object -Property Length -Sum).Sum)
}

$pass = @{}
if ($Profile) { $pass['Profile'] = $Profile }
$vms = Get-LabVms @pass

$name = $null
foreach ($key in $vms.Keys) { if ($vms[$key].Os -eq 'windows') { $name = $key; break } }
if (-not $name) {
    throw 'This profile has no Windows endpoint. The lean profile builds the manager and the Linux endpoint only, and three of the six detection cases run against them.'
}

if (-not $Backend) { $Backend = (Get-LabConfig).backend }
Import-LabBackend -Backend $Backend | Out-Null

$info = Get-LabVmInfo -Name $name
if (-not $info) { throw "There is no VM called $name. Build it with setup\New-Lab.ps1 first." }
if ($info.State -ne 'Off') {
    throw ("{0} is {1}. The prompt this presses through is in the first seconds of a boot, so it has to start from off. Stop it, then run this again." -f
        $name, $info.State.ToLower())
}

$before = Get-LabVmDiskBytes -Path $info.StoragePath

Write-Host ("Starting {0}." -f $name)
$job = Invoke-LabVmAction -Name $name -Action start
Wait-Job -Job $job | Out-Null
try { Receive-Job -Job $job -ErrorAction Stop | Out-Null }
catch { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue; throw }
Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

Write-Host ("Pressing the spacebar for {0} seconds." -f $PressSeconds)
$press = Send-LabVmKey -Name $name -Key space -Repeat ([int]($PressSeconds * 2)) -IntervalMs 500
if ($press.sent -eq 0) {
    Write-Warning ("Not one key press reached {0}. {1}" -f $name, $press.detail)
    Write-Warning 'Open the guest console and press a key there within about five seconds of starting it.'
} else {
    Write-Host ("  {0} accepted, {1} refused." -f $press.sent, $press.refused)
}

Write-Host 'Watching for the installer to start writing.'
$grew = $false
$now  = $before
foreach ($i in 1..6) {
    Start-Sleep -Seconds 20
    $current = Get-LabVmInfo -Name $name
    if (-not $current) { break }
    $now = Get-LabVmDiskBytes -Path $current.StoragePath
    # A guest stopped at the firmware writes nothing, so anything past a couple of hundred
    # megabytes is Setup and not noise.
    if ($before -ge 0 -and $now -gt ($before + 200MB)) { $grew = $true; break }
}

Write-Host ''
if ($grew) {
    Write-Host ("{0} is installing: {1:N0} MB written since it started." -f $name, (($now - $before) / 1MB)) -ForegroundColor Green
    Write-Host '  It reboots twice and takes about twenty minutes. Nothing else needs pressing.'
    Write-Host ("  Then enrol it: setup\Install-LabAgents.ps1 -Only {0}" -f $name)
} elseif ($before -lt 0) {
    Write-Host ("{0} was started and the key was sent, but its disk files could not be read from here," -f $name)
    Write-Host '  so whether Setup is running has to be read off the guest console.'
} else {
    Write-Warning ("{0} has written nothing in two minutes, so Setup is probably not running." -f $name)
    Write-Warning 'Open its console. A boot summary listing "The boot loader failed" against the DVD means the key did not land; a black screen means it is still in firmware and is worth another minute.'
}
