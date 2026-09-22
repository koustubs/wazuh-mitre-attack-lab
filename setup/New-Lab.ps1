#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UbuntuIso,
    [Parameter(Mandatory)][string]$WindowsIso,
    [string]$StorageRoot = 'D:\Wazuh-Lab'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V
foreach ($iso in @($UbuntuIso, $WindowsIso)) {
    if (-not (Test-Path -LiteralPath $iso -PathType Leaf) -or [IO.Path]::GetExtension($iso) -ine '.iso') { throw "Missing installation ISO: $iso" }
}
$root = [IO.Path]::GetFullPath($StorageRoot).TrimEnd('\')
if ($root -notmatch '^[A-Za-z]:\\[^\\]+') { throw 'Use a dedicated directory, not a drive root.' }
if (Test-Path -LiteralPath $root) { throw "Storage directory already exists: $root. Review it before provisioning." }
$drive = Get-PSDrive -Name $root.Substring(0, 1)
if ($drive.Free -lt 220GB) { throw 'Allow at least 220 GiB of free space for VM disks and checkpoints.' }
$specs = @(
    @{ Name='WAZUH-MANAGER'; Ram=8GB; Cpu=4; Disk=80GB; Iso=$UbuntuIso; Windows=$false },
    @{ Name='WAZUH-WIN'; Ram=6GB; Cpu=4; Disk=80GB; Iso=$WindowsIso; Windows=$true },
    @{ Name='WAZUH-LINUX'; Ram=2GB; Cpu=2; Disk=24GB; Iso=$UbuntuIso; Windows=$false }
)
foreach ($spec in $specs) { if (Get-VM -Name $spec.Name -ErrorAction SilentlyContinue) { throw "VM already exists: $($spec.Name)" } }
if (Get-VMSwitch -Name 'Wazuh-Lab' -ErrorAction SilentlyContinue) { throw 'The Wazuh-Lab switch already exists.' }
# WinNAT can conflict with an existing NAT. Never replace another lab's network.
if (@(Get-NetNat).Count -gt 0) { throw 'An existing WinNAT network needs review before adding this lab.' }
if (@(Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -like '172.29.70.*' }).Count) { throw 'The proposed lab subnet is already routed.' }
New-Item -ItemType Directory -Path $root | Out-Null
New-VMSwitch -Name 'Wazuh-Lab' -SwitchType Internal | Out-Null
$adapter = Get-NetAdapter -Name 'vEthernet (Wazuh-Lab)'
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress '172.29.70.1' -PrefixLength 24 | Out-Null
New-NetNat -Name 'Wazuh-Lab' -InternalIPInterfaceAddressPrefix '172.29.70.0/24' | Out-Null
foreach ($spec in $specs) {
    $vmDir = Join-Path $root $spec.Name
    New-Item -ItemType Directory -Path $vmDir | Out-Null
    $vmOptions = @{
        Name = $spec.Name; Generation = 2; MemoryStartupBytes = $spec.Ram; Path = $vmDir
        NewVHDPath = (Join-Path $vmDir ($spec.Name + '.vhdx'))
        NewVHDSizeBytes = $spec.Disk; SwitchName = 'Wazuh-Lab'
    }
    $vm = New-VM @vmOptions
    Set-VMProcessor -VM $vm -Count $spec.Cpu
    Set-VM -VM $vm -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -CheckpointType Standard
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
    if ($spec.Windows) {
        Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
        Enable-VMTPM -VM $vm
        Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
    } else {
        Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    }
    $dvd = Add-VMDvdDrive -VM $vm -Path $spec.Iso -Passthru
    Set-VMFirmware -VM $vm -FirstBootDevice $dvd
}
Write-Output 'Three VM definitions created. Install the operating systems using the deployment guide.'
