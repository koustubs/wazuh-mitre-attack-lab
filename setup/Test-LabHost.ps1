#requires -Version 5.1
<#
    Run this first. It says what this machine can and cannot do, and for each thing it cannot,
    the one command that fixes it.

    It changes nothing. It does not install a hypervisor, enable a Windows feature or write a
    file. Those are decisions about your own machine, and a script that makes them quietly is a
    script you should not trust with anything larger. What it does is tell you exactly which
    ones are left.

        .\Test-LabHost.ps1                Check against the profile in lab.config.json
        .\Test-LabHost.ps1 -Profile lean  Check whether the smaller profile would fit here
        .\Test-LabHost.ps1 -Json          The same answers as JSON, for a script

    Exit code 0 when nothing failed, 1 when something did. Warnings do not fail it: a warning is
    something worth knowing, not something that stops the lab being built.
#>
[CmdletBinding()]
param(
    [ValidateSet('lean', 'full')][string]$Profile,
    [switch]$Json,
    [switch]$SkipNetworkTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPreflight.ps1')

$result = if ($Profile) {
    Get-LabPreflight -Profile $Profile -SkipNetworkTest:$SkipNetworkTest
} else {
    Get-LabPreflight -SkipNetworkTest:$SkipNetworkTest
}

if ($Json) {
    $result | ConvertTo-Json -Depth 6
    exit $(if ($result.ready) { 0 } else { 1 })
}

$marks = @{ pass = '  ok  '; warn = ' warn '; fail = ' FAIL '; unknown = '  ?   ' }
$colours = @{ pass = 'Green'; warn = 'Yellow'; fail = 'Red'; unknown = 'DarkGray' }

Write-Host ''
Write-Host ('{0}, {1}' -f $result.machine, $result.cpu)
Write-Host ('{0} profile on {1}: {2} VMs, {3} GB of memory, {4} GB of disk' -f
    $result.profile, $result.backend, $result.budget.VmCount,
    $result.budget.MemoryGb, $result.budget.DiskWithHeadroomGb)
Write-Host ''

foreach ($check in $result.checks) {
    Write-Host $marks[$check.state] -ForegroundColor $colours[$check.state] -NoNewline
    Write-Host (' {0}' -f $check.label)
    Write-Host ('        {0}' -f $check.detail) -ForegroundColor DarkGray
    # The instruction is only shown when it is needed. Printing the fix for a passing check
    # would be eleven commands to read through on a machine that needs none of them.
    if ($check.state -ne 'pass' -and $check.fix) {
        Write-Host ('        {0}' -f $check.fix) -ForegroundColor Cyan
    }
}

# What to run next depends on how much of the lab already exists. Telling somebody whose three
# VMs are running to go and generate an SSH key is how a preflight gets ignored.
$vmCheck  = $result.checks | Where-Object { $_.id -eq 'vms' }
$keyCheck = $result.checks | Where-Object { $_.id -eq 'secrets' }
$next =
    if ($vmCheck -and $vmCheck.state -eq 'pass') { '.\Lab.cmd, or docs\setup.md from step 6 to finish enrolment' }
    elseif ($keyCheck -and $keyCheck.state -eq 'pass') { 'setup\Get-LabImage.ps1' }
    else { 'setup\New-LabSecrets.ps1' }

Write-Host ''
if ($result.ready -and $result.warned -eq 0) {
    Write-Host ('Nothing to fix. Next: {0}' -f $next) -ForegroundColor Green
} elseif ($result.ready) {
    Write-Host ('{0} warning(s), nothing that stops you. Next: {1}' -f $result.warned, $next) -ForegroundColor Yellow
} else {
    Write-Host ('{0} failing check(s). Fix those first; the lines in blue are the commands.' -f $result.failed) -ForegroundColor Red
}
Write-Host ''

exit $(if ($result.ready) { 0 } else { 1 })
