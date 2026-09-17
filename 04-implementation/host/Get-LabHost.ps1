#requires -Version 5.1
[CmdletBinding()]
param([string]$OutputPath = (Join-Path $PSScriptRoot '..\evidence\host-preflight.json'))
$ErrorActionPreference = 'Stop'
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Hyper-V inventory requires an elevated PowerShell session.'
    }
    $os = Get-CimInstance Win32_OperatingSystem
    $system = Get-CimInstance Win32_ComputerSystem
    $result = [ordered]@{
        recordedAt = [DateTime]::UtcNow.ToString('o')
        os = $os.Caption
        memoryGiB = [math]::Round($system.TotalPhysicalMemory / 1GB, 1)
        freeMemoryGiB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
        vms = @(Get-VM | Select-Object Name, State, Generation, ProcessorCount, MemoryStartup)
        switches = @(Get-VMSwitch | Select-Object Name, SwitchType)
        nat = @(Get-NetNat | Select-Object Name, InternalIPInterfaceAddressPrefix)
        disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID, FreeSpace, Size)
    }
    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Output 'Host inventory saved.'
} catch {
    $failure = [ordered]@{ recordedAt = [DateTime]::UtcNow.ToString('o'); error = $_.Exception.Message }
    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $failure | ConvertTo-Json | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Error $_.Exception.Message
    exit 1
}
