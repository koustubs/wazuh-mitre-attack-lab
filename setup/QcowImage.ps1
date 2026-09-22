#requires -Version 5.1
<#
    Read a QCOW2 disk image and write its contents into a fixed VHD.

    This exists because of a mismatch between what Ubuntu publishes and what Hyper-V boots.
    Hyper-V wants a VHD or a VHDX. The only VHD Canonical publishes for amd64 is the Azure
    variant, and that image pins itself to one datasource:

        /etc/cloud/cloud.cfg.d/90_dpkg.cfg:  datasource_list: [ Azure ]

    which means it ignores a NoCloud seed entirely. Attached to an internal switch with no
    DHCP and no Azure metadata service, it stops in cloud-init's init-local stage doing
    ephemeral DHCP discovery that can never succeed, so the guest comes up with no address,
    no key and an unresized root filesystem. Nothing from outside the guest fixes that: a
    ds=nocloud kernel argument does not override datasource_list, and an Azure OVF seed still
    walks into the same DHCP wait.

    The generic cloud image has the full datasource list and works, but it ships as QCOW2.
    Converting it normally means qemu-img, and putting an unsigned third-party binary into the
    setup path of a security lab is a worse problem than the one it solves. QCOW2 is a
    published format and the part needed to read one is small, so it is read here.

    Scope, deliberately narrow. Enough to convert a stock cloud image and nothing more:
    no backing files, no encryption, no snapshots, no internal dirty-bit recovery. Every one
    of those is detected and refused by name rather than producing a disk that is quietly
    wrong, because a corrupt guest disk fails later and somewhere else.

    Compressed clusters are read, because Canonical's image is written with them: the 3.5 GB
    disk arrives as a 600 MB file and every data cluster in it is deflated. The payload is raw
    DEFLATE with no zlib wrapper, which is exactly what System.IO.Compression.DeflateStream
    reads, so this needs nothing that is not already in the .NET Framework.
#>

Set-StrictMode -Version Latest

# QCOW2 stores everything big-endian. .NET's BinaryPrimitives would do this in one call but it
# is not in the .NET Framework that Windows PowerShell 5.1 runs on, so it is done by hand.
# Int64 rather than UInt64 throughout: PowerShell 5.1's -shl does not accept UInt64, and every
# offset in a file this size is far inside Int64.
function ConvertFrom-Qcow2BE {
    param(
        [Parameter(Mandatory)][byte[]]$Buffer,
        [Parameter(Mandatory)][int]$Offset,
        [ValidateSet(4, 8)][int]$Width = 8
    )
    $v = [long]0
    for ($i = 0; $i -lt $Width; $i++) { $v = ($v -shl 8) -bor [long]$Buffer[$Offset + $i] }
    return $v
}

function Read-Qcow2Header {
    <#
    The header fields this converter needs, and the checks that decide whether it may proceed.
    Field offsets are from the QCOW2 specification; version 2 and version 3 share the first
    72 bytes, and only version 3 has the feature words after them.
    #>
    param([Parameter(Mandatory)][IO.FileStream]$Stream)

    $head = New-Object byte[] 104
    $Stream.Position = 0
    if ($Stream.Read($head, 0, 104) -ne 104) { throw 'The image is too short to be a QCOW2 file.' }

    if ($head[0] -ne 0x51 -or $head[1] -ne 0x46 -or $head[2] -ne 0x49 -or $head[3] -ne 0xFB) {
        throw ('Not a QCOW2 image: expected the magic QFI\xFB, found {0:X2}{1:X2}{2:X2}{3:X2}.' -f
               $head[0], $head[1], $head[2], $head[3])
    }

    $version = ConvertFrom-Qcow2BE -Buffer $head -Offset 4 -Width 4
    if ($version -ne 2 -and $version -ne 3) {
        throw "QCOW2 version $version is not supported. This reads version 2 and 3."
    }

    $backingOffset = ConvertFrom-Qcow2BE -Buffer $head -Offset 8
    if ($backingOffset -ne 0) {
        throw ('This image has a backing file. Only a standalone image can be converted here, ' +
               'and a stock cloud image is standalone.')
    }

    $cryptMethod = ConvertFrom-Qcow2BE -Buffer $head -Offset 32 -Width 4
    if ($cryptMethod -ne 0) { throw 'This image is encrypted. Nothing here can read it.' }

    $snapshots = ConvertFrom-Qcow2BE -Buffer $head -Offset 60 -Width 4
    if ($snapshots -ne 0) {
        throw "This image carries $snapshots internal snapshot(s), which this converter does not read."
    }

    if ($version -eq 3) {
        # Any bit set here is a feature a reader must understand to read the file correctly.
        # Refusing an unknown one is the whole point of the field.
        $incompatible = ConvertFrom-Qcow2BE -Buffer $head -Offset 72
        if ($incompatible -ne 0) {
            throw ('This image sets incompatible feature bits 0x{0:X} that this converter does ' +
                   'not implement. Refusing rather than reading it wrongly.' -f $incompatible)
        }
    }

    $clusterBits = ConvertFrom-Qcow2BE -Buffer $head -Offset 20 -Width 4
    if ($clusterBits -lt 9 -or $clusterBits -gt 21) {
        throw "Implausible cluster size: 2^$clusterBits bytes."
    }

    return [pscustomobject]@{
        Version       = $version
        ClusterBits   = [int]$clusterBits
        ClusterSize   = [long]1 -shl [int]$clusterBits
        VirtualSize   = ConvertFrom-Qcow2BE -Buffer $head -Offset 24
        L1Size        = [int](ConvertFrom-Qcow2BE -Buffer $head -Offset 36 -Width 4)
        L1TableOffset = ConvertFrom-Qcow2BE -Buffer $head -Offset 40
    }
}

function Get-Qcow2Info {
    <#
    The header alone, without reading a byte of data. The virtual size is needed before the
    destination exists, because the destination has to be created at that size.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { return Read-Qcow2Header -Stream $stream } finally { $stream.Dispose() }
}

function Expand-Qcow2 {
    <#
    Write every allocated cluster of a QCOW2 image into an already-created, already-zeroed
    destination at the offset the guest will read it from.

    Only allocated clusters are written. A cloud image is mostly holes, so the file that comes
    out is written once rather than twice: the destination arrives zeroed and the unallocated
    and explicitly-zero clusters are exactly the parts that should stay that way.

        Expand-Qcow2 -Source ubuntu.img -Destination ubuntu.vhd

    Destination must already exist and be at least VirtualSize bytes. Data is written from
    offset 0, which is where a fixed VHD keeps it; the 512-byte footer lives after the data,
    so nothing here disturbs it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    $in = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $header = Read-Qcow2Header -Stream $in
        $clusterSize = $header.ClusterSize
        # Each L2 table fills one cluster of 8-byte entries, so one L1 entry covers this much.
        $l2Entries = [long]($clusterSize / 8)
        $bytesPerL1 = $clusterSize * $l2Entries

        # A compressed L2 entry splits its 62 usable bits differently from a standard one, and
        # where it splits them depends on the cluster size. Below the boundary is a byte-granular
        # host offset; above it is how many extra 512-byte sectors the compressed run occupies.
        # For the usual 64 KB cluster that is a 54-bit offset and an 8-bit length.
        $csizeShift = 62 - ($header.ClusterBits - 8)
        $csizeMask = ([long]1 -shl ($header.ClusterBits - 8)) - 1
        $compOffsetMask = ([long]1 -shl $csizeShift) - 1
        $compMax = [int](($csizeMask + 1) * 512)

        $out = [IO.File]::Open($Destination, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            if ($out.Length -lt $header.VirtualSize) {
                throw ('{0} is {1} bytes, smaller than the image''s {2} byte virtual size.' -f
                       $Destination, $out.Length, $header.VirtualSize)
            }

            Write-Host ('  {0:N1} GB virtual, {1} KB clusters' -f
                        ($header.VirtualSize / 1GB), ($clusterSize / 1KB))

            $l1 = New-Object byte[] ($header.L1Size * 8)
            $in.Position = $header.L1TableOffset
            if ($in.Read($l1, 0, $l1.Length) -ne $l1.Length) { throw 'Truncated L1 table.' }

            # The offset bits of an L1 or L2 entry. The high bits are flags and the low nine are
            # always zero because everything is cluster aligned; masking is what separates the
            # two, and getting it wrong reads data from the wrong place rather than failing.
            $offsetMask = [long]0x00FFFFFFFFFFFE00

            $l2 = New-Object byte[] $clusterSize
            $buffer = New-Object byte[] $clusterSize
            $packed = New-Object byte[] $compMax
            $written = [long]0
            $sw = [Diagnostics.Stopwatch]::StartNew()

            for ($i = 0; $i -lt $header.L1Size; $i++) {
                $l1Entry = ConvertFrom-Qcow2BE -Buffer $l1 -Offset ($i * 8)
                $l2Offset = $l1Entry -band $offsetMask
                # No L2 table means this whole span of the disk was never written. The
                # destination is already zero there.
                if ($l2Offset -eq 0) { continue }

                $in.Position = $l2Offset
                if ($in.Read($l2, 0, $clusterSize) -ne $clusterSize) { throw "Truncated L2 table at $l2Offset." }

                for ($j = 0; $j -lt $l2Entries; $j++) {
                    $entry = ConvertFrom-Qcow2BE -Buffer $l2 -Offset ($j * 8)
                    if ($entry -eq 0) { continue }

                    $guestOffset = ($i * $bytesPerL1) + ($j * $clusterSize)
                    if ($guestOffset -ge $header.VirtualSize) { continue }

                    if (($entry -band ([long]1 -shl 62)) -ne 0) {
                        # Compressed. The offset is byte-granular, so the run begins partway
                        # into a sector and the length is counted from the start of that sector
                        # rather than from the offset. Getting that subtraction wrong reads a
                        # few bytes too many, which inflate tolerates, or too few, which it
                        # does not, so it is the one line here worth reading twice.
                        $coffset = $entry -band $compOffsetMask
                        $sectors = (($entry -shr $csizeShift) -band $csizeMask) + 1
                        $take = [int](($sectors * 512) - ($coffset -band 511))

                        $in.Position = $coffset
                        $read = 0
                        while ($read -lt $take) {
                            $n = $in.Read($packed, $read, $take - $read)
                            if ($n -le 0) { break }
                            $read += $n
                        }
                        # A short read is only a fault if it left the run incomplete. The last
                        # compressed cluster in the file can have its padding sectors trimmed.
                        if ($read -eq 0) { throw "Truncated compressed cluster at $coffset." }

                        $mem = New-Object IO.MemoryStream($packed, 0, $read)
                        try {
                            $inflate = New-Object IO.Compression.DeflateStream(
                                $mem, [IO.Compression.CompressionMode]::Decompress)
                            try {
                                $inflated = 0
                                while ($inflated -lt $clusterSize) {
                                    $n = $inflate.Read($buffer, $inflated, [int]($clusterSize - $inflated))
                                    if ($n -le 0) { break }
                                    $inflated += $n
                                }
                            } finally { $inflate.Dispose() }
                        } finally { $mem.Dispose() }
                        if ($inflated -ne $clusterSize) {
                            throw ("A compressed cluster at {0} inflated to {1} bytes rather " +
                                   "than {2}." -f $coffset, $inflated, $clusterSize)
                        }
                    } else {
                        # Bit 0 on a standard descriptor means "reads as zeros". Already true.
                        if (($entry -band 1) -ne 0) { continue }

                        $dataOffset = $entry -band $offsetMask
                        if ($dataOffset -eq 0) { continue }

                        $in.Position = $dataOffset
                        $got = $in.Read($buffer, 0, $clusterSize)
                        if ($got -ne $clusterSize) { throw "Truncated cluster at $dataOffset." }
                    }

                    # The last cluster can hang over the end of the declared virtual size.
                    $span = $clusterSize
                    if (($guestOffset + $span) -gt $header.VirtualSize) {
                        $span = $header.VirtualSize - $guestOffset
                    }
                    $out.Position = $guestOffset
                    $out.Write($buffer, 0, [int]$span)
                    $written += $span
                }

                if ($sw.Elapsed.TotalSeconds -ge 5) {
                    Write-Host ('    {0:N0} MB written' -f ($written / 1MB))
                    $sw.Restart()
                }
            }

            $out.Flush()
            Write-Host ('  {0:N0} MB of allocated data written' -f ($written / 1MB))
            return $header.VirtualSize
        } finally {
            $out.Dispose()
        }
    } finally {
        $in.Dispose()
    }
}
