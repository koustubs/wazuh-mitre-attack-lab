#requires -Version 5.1
<#
    Fetches the Ubuntu cloud image the lab's Linux guests boot from, and verifies it.

    This replaces installing Ubuntu. The old way was a server ISO you sourced yourself, an
    autoinstall directive typed at the GRUB prompt through a framebuffer driver, and about
    fifteen minutes per guest. A cloud image is a disk that has already been installed: it boots
    in seconds, cloud-init configures it on first boot, and it is smaller because it is minimal
    rather than a full server install.

    What it does:
      - reads the file names for the configured backend out of lab.config.json
      - fetches the published SHA256SUMS, and its signature when gpg is available
      - downloads beside the target, never onto it, so an interrupted transfer cannot leave
        something that looks like a verified image
      - checks the hash, and deletes what does not match rather than keeping it
      - unpacks and converts to whatever the backend boots

    The download is about 580 MB. Preparing it needs roughly 36 GB free for a few minutes,
    because the Hyper-V image unpacks to a 30 GB disk before it is compacted. Everything lands
    under the storageRoot from lab.config.json, beside the VM disks rather than inside the
    clone. Run it once.

        .\Get-LabImage.ps1
        .\Get-LabImage.ps1 -Force      Re-fetch even if the cache is already verified
#>
[CmdletBinding()]
param(
    [ValidateSet('hyperv', 'virtualbox')][string]$Backend,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabBackend.ps1')

$config = Get-LabConfig
if (-not $Backend) { $Backend = $config.backend }
Import-LabBackend -Backend $Backend | Out-Null
$image = $config.images.ubuntu
$name = $image.$Backend
if (-not $name) { throw "lab.config.json names no Ubuntu image for the $Backend backend." }

$cache = Get-LabPath Images
if (-not (Test-Path -LiteralPath $cache)) { New-Item -ItemType Directory -Path $cache -Force | Out-Null }

# TLS 1.2 is not the default in .NET Framework 4.x, which is what Windows PowerShell 5.1 runs
# on, and cloud-images.ubuntu.com refuses anything older. Without this the download fails with
# "The request was aborted: Could not create SSL/TLS secure channel", which says nothing useful.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-RemoteFile {
    param([string]$Url, [string]$Target, [string]$Label)

    $part = $Target + '.part'
    if (Test-Path -LiteralPath $part) { Remove-Item -LiteralPath $part -Force }

    Write-Host ("Fetching {0}..." -f $Label)
    # BITS where it is available, because it shows real progress on a 580 MB file and survives a
    # dropped connection. Invoke-WebRequest is the fallback: it works everywhere and reports
    # nothing until it finishes.
    $bits = Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue
    if ($bits) {
        try {
            Start-BitsTransfer -Source $Url -Destination $part -Description $Label -ErrorAction Stop
        } catch {
            Write-Host ('  BITS declined it ({0}). Falling back.' -f $_.Exception.Message)
            Invoke-WebRequest -Uri $Url -OutFile $part -UseBasicParsing
        }
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $part -UseBasicParsing
    }
    if (-not (Test-Path -LiteralPath $part)) { throw "The download of $Label produced no file." }
    Move-Item -LiteralPath $part -Destination $Target -Force
}

function Get-Sha256 {
    param([string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

function Assert-FreeSpace {
    <#
        Checked before the unpack rather than discovered during it. Filling a system drive is
        not a recoverable error for everything else running on the machine, and the unpack has
        no way to know it is about to.
    #>
    param([string]$Path, [int]$RequiredGb, [string]$For)

    $drive = ([IO.Path]::GetPathRoot((Resolve-Path -LiteralPath $Path).Path)).TrimEnd('\')
    $disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $drive) -ErrorAction SilentlyContinue
    if (-not $disk) { return }   # a network or mapped path; let the write fail on its own terms
    $freeGb = [math]::Round($disk.FreeSpace / 1GB, 1)
    if ($freeGb -lt $RequiredGb) {
        throw ("{0} needs about {1} GB free on {2} and there is {3} GB. Free some space, or point storageRoot in lab.config.json at a drive that has it." -f $For, $RequiredGb, $drive, $freeGb)
    }
}

function Assert-FixedVhd {
    <#
        The last 512 bytes of a VHD are its footer, and it records the disk's declared size.

        Worth checking. The unpack below writes whatever tar sends to stdout, so this is what
        would notice if the archive ever gained a second member, and it catches a short write
        before Convert-VHD spends several minutes reading 30 GB to reach the same conclusion.
    #>
    param([string]$Path)

    $length = (Get-Item -LiteralPath $Path).Length
    if ($length -lt 512) { throw "$Path is too small to be a virtual disk." }

    $stream = [IO.File]::OpenRead($Path)
    try {
        [void]$stream.Seek(-512, [IO.SeekOrigin]::End)
        $footer = New-Object byte[] 512
        [void]$stream.Read($footer, 0, 512)
    } finally { $stream.Dispose() }

    if ([Text.Encoding]::ASCII.GetString($footer, 0, 8) -ne 'conectix') {
        throw "$Path does not end in a VHD footer. The unpack produced something other than the disk."
    }

    # The footer is big-endian and BitConverter reads host order, which is little-endian here.
    $sizeBytes = [byte[]]($footer[40..47]); [array]::Reverse($sizeBytes)
    $typeBytes = [byte[]]($footer[60..63]); [array]::Reverse($typeBytes)
    $declared = [BitConverter]::ToUInt64($sizeBytes, 0)
    $diskType = [BitConverter]::ToUInt32($typeBytes, 0)

    if ($diskType -ne 2) { throw "Expected a fixed VHD in $name, found disk type $diskType." }
    if ($length -ne ($declared + 512)) {
        throw ("{0} is {1} bytes but its footer declares {2}. The archive holds more than the one disk this expects." -f $Path, $length, ($declared + 512))
    }
}

# ---- the published checksums -----------------------------------------------------------------

$sumsPath = Join-Path $cache $image.checksums
Get-RemoteFile -Url ($image.baseUrl + $image.checksums) -Target $sumsPath -Label $image.checksums

# Canonical's signature over the checksums. gpg is not shipped with Windows, so this is a real
# verification when it is installed and an honest "not verified" when it is not. The hash below
# still pins the image; what the signature adds is knowing the hash list itself is Canonical's.
$sigName = $image.checksums + '.gpg'
$sigPath = Join-Path $cache $sigName
$signatureState = 'not checked'
try {
    Get-RemoteFile -Url ($image.baseUrl + $sigName) -Target $sigPath -Label $sigName
    $gpg = Get-Command 'gpg.exe' -ErrorAction SilentlyContinue
    if (-not $gpg) {
        $signatureState = 'not checked, gpg is not installed on this host'
    } else {
        $verify = & $gpg.Source --verify $sigPath $sumsPath 2>&1
        if ($LASTEXITCODE -eq 0) {
            $signatureState = 'good'
        } else {
            # A missing public key is not a bad signature, and refusing the image over it would
            # be wrong. Say which one it was.
            $text = ($verify | Out-String)
            if ($text -match 'No public key') {
                $signatureState = 'not checked, Canonical''s cloud image signing key is not in your keyring'
            } else {
                throw ("The signature over {0} did not verify:`n{1}" -f $image.checksums, $text.Trim())
            }
        }
    }
} catch {
    if ($_.Exception.Message -like 'The signature over*') { throw }
    $signatureState = ('not checked, the signature could not be fetched: {0}' -f $_.Exception.Message)
}
Write-Host ("  checksum list signature: {0}" -f $signatureState)

$expected = $null
foreach ($line in (Get-Content -LiteralPath $sumsPath)) {
    # "<hash> *<name>"; the asterisk marks a binary read and is not part of the name.
    if ($line -match ('^([0-9a-f]{64})\s+\*?' + [regex]::Escape($name) + '\s*$')) { $expected = $Matches[1]; break }
}
if (-not $expected) { throw "$name is not listed in $($image.checksums). Check images.ubuntu in lab.config.json against what is published at $($image.baseUrl)." }

# ---- the image ---------------------------------------------------------------------------------

$archive = Join-Path $cache $name
if ((Test-Path -LiteralPath $archive) -and -not $Force) {
    Write-Host ("Checking the cached {0}..." -f $name)
    if ((Get-Sha256 $archive) -ne $expected) {
        Write-Host '  the cached copy does not match the published hash; fetching it again.'
        Remove-Item -LiteralPath $archive -Force
    }
}
if (-not (Test-Path -LiteralPath $archive)) {
    Get-RemoteFile -Url ($image.baseUrl + $name) -Target $archive -Label ('{0} (about {1} MB)' -f $name, 580)
    $actual = Get-Sha256 $archive
    if ($actual -ne $expected) {
        Remove-Item -LiteralPath $archive -Force
        throw ("The downloaded image does not match the published hash and has been deleted.`n  expected {0}`n  actual   {1}" -f $expected, $actual)
    }
}
Write-Host ("  verified {0}" -f $expected)

# ---- unpack into something the backend boots ----------------------------------------------------

$prepared = $null
if ($Backend -eq 'hyperv') {
    # The Azure variant ships as a tar.gz around one fixed-size 30 GB VHD. Hyper-V boots that
    # directly, but a fixed VHD is its full size on disk from the first byte, so it is converted
    # once to a dynamic VHDX that every guest then copies. tar.exe has been in Windows since
    # 10 1803.
    $vhd = Join-Path $cache 'ubuntu-cloudimg.vhd'
    $prepared = Join-Path $cache 'ubuntu-cloudimg.vhdx'

    if ((Test-Path -LiteralPath $prepared) -and -not $Force) {
        Write-Host ("Already prepared: {0}" -f $prepared)
    } else {
        if (Test-Path -LiteralPath $vhd) { Remove-Item -LiteralPath $vhd -Force }
        Assert-FreeSpace -Path $cache -RequiredGb 36 -For 'Unpacking the cloud image'

        Write-Host '  unpacking, about 30 GB and a few minutes...'
        # Deliberately not "tar -xzf". That unpacks the VHD as an NTFS sparse file, and Hyper-V
        # refuses a sparse virtual disk outright: "must be uncompressed and unencrypted and must
        # not be sparse" (0xC03A001A). Clearing the flag afterwards is worse than no help at all,
        # because fsutil allocates the full 30 GB to do it and leaves the drive full when it
        # cannot finish. Unpacking to stdout and redirecting avoids the question: cmd creates an
        # ordinary file and writes the stream through it.
        & cmd.exe /c ('tar.exe -xOzf "{0}" > "{1}"' -f $archive, $vhd)
        if ($LASTEXITCODE -ne 0) {
            if (Test-Path -LiteralPath $vhd) { Remove-Item -LiteralPath $vhd -Force }
            throw "tar could not unpack $name (exit $LASTEXITCODE)."
        }
        Assert-FixedVhd -Path $vhd

        Write-Host '  compacting to a dynamic VHDX...'
        try {
            ConvertTo-LabBootDisk -Source $vhd -Destination $prepared
        } finally {
            if (Test-Path -LiteralPath $vhd) { Remove-Item -LiteralPath $vhd -Force }
        }
    }
} else {
    # The VMDK is a stream-optimised image, which VirtualBox will boot but will not resize. It is
    # cloned to a VDI once so New-Lab.ps1 can grow each guest's copy to the profile's disk size.
    $prepared = Join-Path $cache 'ubuntu-cloudimg.vdi'
    if ((Test-Path -LiteralPath $prepared) -and -not $Force) {
        Write-Host ("Already prepared: {0}" -f $prepared)
    } else {
        Write-Host '  cloning to VDI...'
        ConvertTo-LabBootDisk -Source $archive -Destination $prepared
    }
}

Write-Host ''
Write-Host ("Ready: {0}" -f $prepared) -ForegroundColor Green
Write-Host ("  {0} MB on disk" -f [math]::Round((Get-Item -LiteralPath $prepared).Length / 1MB))
Write-Host 'Next: setup\New-LabSeeds.ps1'
