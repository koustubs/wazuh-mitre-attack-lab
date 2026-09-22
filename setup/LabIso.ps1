#requires -Version 5.1
<#
    Writes a small data ISO from a directory, using the ISO authoring COM component that ships
    with Windows.

    Two scripts need this and each had its own byte-identical copy of the C# below. It is here
    once now.

    Nothing outside Windows can run it. IMAPI2FS is a Windows component, which is one of the
    reasons the host side of this project is Windows only.
#>

Set-StrictMode -Version Latest

if (-not ('LabIso' -as [type])) {
    # The COM interface hands back an IStream. PowerShell has no way to read one, so the copy
    # loop is written in C# and compiled once per session.
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

function New-LabDataIso {
    <#
        .PARAMETER VolumeName
        CIDATA for a cloud-init seed, which is how cloud-init finds it whatever drive letter it
        lands on. Anything for a Windows unattend seed, which is found by filename instead.
    #>
    param(
        [Parameter(Mandatory)][string]$SourceDirectory,
        [Parameter(Mandatory)][string]$IsoPath,
        [Parameter(Mandatory)][string]$VolumeName
    )

    if (Test-Path -LiteralPath $IsoPath) { Remove-Item -LiteralPath $IsoPath -Force }
    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    try {
        # ISO9660 plus Joliet. Joliet is what allows a name longer than 8.3, which autounattend
        # .xml needs and which user-data does not.
        $image.FileSystemsToCreate = 3
        $image.VolumeName = $VolumeName
        $image.Root.AddTree($SourceDirectory, $false)
        $result = $image.CreateResultImage()
        [LabIso]::Write($result.ImageStream, $IsoPath)
    } finally {
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($image)
    }
}

function Write-LabLfFile {
    <#
        UTF-8, no BOM, LF endings.

        Every file these ISOs carry is read by something that treats a carriage return as part
        of the value: cloud-init parses YAML, where CRLF breaks a block scalar, and the shell
        env file would otherwise end every variable with a stray \r.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    [IO.File]::WriteAllText($Path, ($Content -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
}
