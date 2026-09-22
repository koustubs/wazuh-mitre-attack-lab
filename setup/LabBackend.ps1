#requires -Version 5.1
<#
    Picks a hypervisor backend and loads it, so nothing above this line has to know which one.

    The contract. Every function is implemented by both backends\hyperv.psm1 and
    backends\virtualbox.psm1 with the same parameters and the same return shape:

        Test-LabBackendAvailable                    @{ available; detail; fix; degraded? }
        Get-LabVmInfo        -Name                  $null, or the shape below
        Invoke-LabVmAction   -Name -Action          a job, for start|shutdown|restart|forceoff
        Set-LabVmNoAutostart -Name
        Get-LabNetworkInfo   -NetworkName -Subnet -Gateway
                                                    @{ SwitchPresent; NatPresent; SwitchKind;
                                                       NatKind; NatFix }
        Test-LabNetworkConflict -NetworkName -Subnet -Gateway     a list of sentences
        New-LabNetwork       -NetworkName -Subnet -Gateway -PrefixLength
        Remove-LabNetwork    -NetworkName
        New-LabVm            -Name -Directory -NetworkName -MemoryMb -MinMemoryMb -MaxMemoryMb
                             -Cpu -DiskGb -Os -Gateway [-BootDiskPath]
        Add-LabVmDvd         -Name -Path [-FirstBoot]
        Add-LabVmDisk        -Name -Path -SizeGb
        Resize-LabVmDisk     -Path -SizeGb
        Remove-LabVm         -Name [-DeleteDisks]

    Get-LabVmInfo returns:

        Name State Status CpuPercent MemoryBytes ConfiguredMb CpuCount Uptime Autostart StoragePath

    with State one of Running, Off, Paused, Saved, Starting, Stopping, and CpuPercent set to -1
    where the backend cannot measure it, so a caller can tell "not measured" from "idle".

    Loading is a call rather than a top-level Import-Module on purpose. The dashboard used to
    have "Import-Module Hyper-V" near the top of the file, which made it fail to start at all on
    a host without Hyper-V, before it could say why.
#>

Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'LabConfig.ps1')

$script:LabBackendLoaded = $null

function Import-LabBackend {
    <#
        Loads the backend named in lab.config.json, or the one asked for, and returns its name.

        Idempotent, and cheap to call again: the second call through with the same backend does
        nothing. Switching backends inside one session reloads the module, which is what the
        preflight does when it reports on both.
    #>
    param([ValidateSet('hyperv', 'virtualbox')][string]$Backend)

    if (-not $Backend) { $Backend = (Get-LabConfig).backend }
    if ($script:LabBackendLoaded -eq $Backend) { return $Backend }

    $module = Join-Path $PSScriptRoot ('backends\{0}.psm1' -f $Backend)
    if (-not (Test-Path -LiteralPath $module)) { throw "No backend module for '$Backend' at $module." }

    Import-Module -Name $module -Force -Global -DisableNameChecking
    $script:LabBackendLoaded = $Backend
    return $Backend
}

function Get-LabBackendName {
    <# Which backend is loaded, or the configured one if none is. #>
    if ($script:LabBackendLoaded) { return $script:LabBackendLoaded }
    return (Get-LabConfig).backend
}

function Get-LabBackendSurvey {
    <#
        Both backends asked whether they would work here, without committing to either.

        This is what the preflight prints when the configured backend is unavailable: telling
        someone Hyper-V is missing is less useful than telling them Hyper-V is missing and the
        VirtualBox they already have would do.
    #>
    $survey = [ordered]@{}
    foreach ($name in @('hyperv', 'virtualbox')) {
        $module = Join-Path $PSScriptRoot ('backends\{0}.psm1' -f $name)
        try {
            # Loaded into a child scope and discarded, so surveying one backend does not leave
            # the other's functions defined over the top of it.
            $result = & {
                Import-Module -Name $module -Force -DisableNameChecking
                Test-LabBackendAvailable
            }
            $survey[$name] = $result
        } catch {
            $survey[$name] = [ordered]@{
                available = $false
                detail    = ('The {0} backend could not be loaded: {1}' -f $name, $_.Exception.Message)
                fix       = ''
            }
        }
    }
    # Whatever the survey loaded last is not necessarily the configured backend, so put it back.
    $script:LabBackendLoaded = $null
    Import-LabBackend | Out-Null
    return $survey
}
