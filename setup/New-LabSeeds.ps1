#requires -Version 5.1
<#
Builds cloud-init seed images for the two Ubuntu lab VMs.

Each image is a small ISO labelled CIDATA. Cloud-init finds it by that label, so it does not
matter which drive letter it lands on. The installer still needs "autoinstall" on the kernel
command line, which Start-LabInstall.ps1 supplies at the boot menu.
#>
[CmdletBinding()]
param(
    [string]$SecretsPath = (Join-Path $PSScriptRoot '.lab-secrets'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '.lab-secrets\seeds')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$publicKey = (Get-Content (Join-Path $SecretsPath 'lab_ed25519.pub') -Raw).Trim()
$passwordHash = (Get-Content (Join-Path $SecretsPath 'console-password.hash') -Raw).Trim()
if (-not $publicKey.StartsWith('ssh-')) { throw 'Public key looks wrong.' }
if (-not $passwordHash.StartsWith('$6$')) { throw 'Expected a SHA-512 crypt hash.' }

if (-not ('LabIso' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class LabIso {
    public static void Write(object image, string path) {
        IStream stream = (IStream)image;
        using (FileStream file = File.Create(path)) {
            byte[] buffer = new byte[2048];
            IntPtr read = Marshal.AllocHGlobal(4);
            try {
                int count;
                do {
                    stream.Read(buffer, buffer.Length, read);
                    count = Marshal.ReadInt32(read);
                    if (count > 0) { file.Write(buffer, 0, count); }
                } while (count == buffer.Length);
            } finally { Marshal.FreeHGlobal(read); }
        }
    }
}
'@
}

function New-CidataIso {
    param([string]$SourceDirectory, [string]$IsoPath)
    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    # ISO9660 plus Joliet. Cloud-init only needs the volume label and two files.
    $image.FileSystemsToCreate = 3
    $image.VolumeName = 'CIDATA'
    $image.Root.AddTree($SourceDirectory, $false)
    $result = $image.CreateResultImage()
    [LabIso]::Write($result.ImageStream, $IsoPath)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($image)
}

$hosts = @(
    @{ Name = 'wazuh-manager'; Address = '172.29.70.10' },
    @{ Name = 'wazuh-linux';   Address = '172.29.70.30' }
)

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
foreach ($entry in $hosts) {
    $staging = Join-Path ([IO.Path]::GetTempPath()) ('labseed-' + $entry.Name)
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging | Out-Null

    # Written with LF endings. Cloud-init parses this as YAML and CRLF breaks the block scalars.
    $userData = @"
#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us
  identity:
    hostname: $($entry.Name)
    username: labadmin
    password: "$passwordHash"
  ssh:
    install-server: true
    allow-pw: false
    authorized-keys:
      - "$publicKey"
  network:
    version: 2
    ethernets:
      labnet:
        match:
          name: "e*"
        addresses:
          - $($entry.Address)/24
        routes:
          - to: default
            via: 172.29.70.1
        nameservers:
          addresses: [1.1.1.1, 8.8.8.8]
  storage:
    layout:
      name: direct
  packages:
    - openssh-server
  shutdown: poweroff
"@
    $metaData = @"
instance-id: $($entry.Name)-01
local-hostname: $($entry.Name)
"@
    $lf = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $staging 'user-data'), ($userData -replace "`r`n", "`n"), $lf)
    [IO.File]::WriteAllText((Join-Path $staging 'meta-data'), ($metaData -replace "`r`n", "`n"), $lf)

    $iso = Join-Path $OutputPath ($entry.Name + '-seed.iso')
    if (Test-Path $iso) { Remove-Item $iso -Force }
    New-CidataIso -SourceDirectory $staging -IsoPath $iso
    Remove-Item $staging -Recurse -Force
    Write-Output ("{0} -> {1} bytes" -f (Split-Path $iso -Leaf), (Get-Item $iso).Length)
}
