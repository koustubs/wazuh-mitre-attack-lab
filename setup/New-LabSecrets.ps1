#requires -Version 5.1
<#
Creates the credentials the lab is built on. This is the first step of a rebuild, before
New-LabSeeds.ps1 and New-WindowsSeed.ps1, both of which read the files written here.

Four files land in .lab-secrets, which is gitignored and never reaches the repository:

  lab_ed25519           SSH key for labadmin on both Ubuntu machines
  lab_ed25519.pub       the matching public key, embedded in the cloud-init seed
  console-password.txt  local console password, alphanumeric so it is safe inside autounattend XML
  console-password.hash its SHA-512 crypt hash, which is what cloud-init wants

The hash is computed here rather than shelled out to openssl or WSL, neither of which a clean
Windows machine has. The algorithm is Ulrich Drepper's SHA-512 crypt. Getting it subtly wrong
would produce a hash that does not match the password, and you would only find out at a console
you can no longer log into, so the implementation is checked against the published test vector
before it is used on anything real. If that check fails, nothing is written.

    .\New-LabSecrets.ps1
    .\New-LabSecrets.ps1 -Force      # replace an existing set

Replacing the set invalidates access to any VM already built with the old key, which is why
-Force is needed to do it.
#>
[CmdletBinding()]
param(
    # Where the key and the console password land. Empty means the repository's own
    # .lab-secrets, resolved in the body rather than here for two reasons.
    #
    # $PSScriptRoot is not reliably populated inside a param block on Windows PowerShell 5.1,
    # and an empty string reaches Join-Path as a parameter binding failure naming Join-Path
    # rather than this script, which is the least useful place to start looking. The same
    # defect cost this project a broken Build-Report.ps1.
    #
    # And the default was setup\.lab-secrets, one level below where everything else looks.
    # Get-LabPath Secrets is what the rest of the project resolves, so a key written anywhere
    # else is a key no other script can find.
    [string]$SecretsPath,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $SecretsPath) {
    $here = $PSScriptRoot
    if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
    if (-not $here) { throw 'Cannot resolve the script directory. Run this script by path.' }
    . (Join-Path $here 'LabConfig.ps1')
    $SecretsPath = Get-LabPath Secrets
}

$CryptAlphabet = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

function Get-RandomBytes {
    param([int]$Count)
    $bytes = New-Object byte[] $Count
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return $bytes
}

function New-RandomString {
    <#
    Rejection sampling rather than a plain modulo. With a 62 character alphabet, taking a byte
    modulo 62 makes the first four characters slightly more likely than the rest, and there is no
    reason to accept that when discarding the eight values above the fold costs nothing.
    #>
    param([int]$Length, [string]$Alphabet)
    $n = $Alphabet.Length
    $limit = 256 - (256 % $n)
    $out = New-Object Text.StringBuilder
    while ($out.Length -lt $Length) {
        foreach ($b in (Get-RandomBytes -Count ($Length * 2))) {
            if ($b -ge $limit) { continue }
            [void]$out.Append($Alphabet[$b % $n])
            if ($out.Length -eq $Length) { break }
        }
    }
    return $out.ToString()
}

function Add-Repeated {
    <#
    Appends Length bytes to Target by repeating a 64 byte digest, whole copies first and then a
    partial one. Appends rather than returns: a PowerShell function that returns an array has it
    unrolled into the pipeline and rebuilt as object[], and object[] is not byte[] however much
    it looks like one.
    #>
    param($Target, [byte[]]$Digest, [int]$Length)
    $done = 0
    while ($done + 64 -le $Length) { $Target.AddRange($Digest); $done += 64 }
    for ($k = 0; $k -lt ($Length - $done); $k++) { $Target.Add($Digest[$k]) }
}

function Add-CryptBase64 {
    param($Builder, [int]$B2, [int]$B1, [int]$B0, [int]$Count)
    $w = ($B2 -shl 16) -bor ($B1 -shl 8) -bor $B0
    for ($k = 0; $k -lt $Count; $k++) {
        [void]$Builder.Append($CryptAlphabet[$w -band 0x3f])
        $w = $w -shr 6
    }
}

function ConvertTo-Sha512Crypt {
    <#
    SHA-512 crypt, the "$6$" scheme, at the default 5000 rounds. Follows the reference algorithm
    step for step; the awkward parts are deliberate rather than mistakes.
    #>
    param([string]$Password, [string]$Salt)

    $enc = [Text.Encoding]::ASCII
    $pw = $enc.GetBytes($Password)
    $saltBytes = $enc.GetBytes($Salt)
    $sha = [Security.Cryptography.SHA512]::Create()
    try {
        $buf = New-Object 'System.Collections.Generic.List[byte]'
        $buf.AddRange($pw); $buf.AddRange($saltBytes); $buf.AddRange($pw)
        $b = $sha.ComputeHash($buf.ToArray())

        $buf = New-Object 'System.Collections.Generic.List[byte]'
        $buf.AddRange($pw); $buf.AddRange($saltBytes)
        Add-Repeated -Target $buf -Digest $b -Length $pw.Length
        # One pass over the bits of the password length, low bit first. A 1 contributes digest B,
        # a 0 contributes the password itself.
        for ($i = $pw.Length; $i -gt 0; $i = $i -shr 1) {
            if ($i -band 1) { $buf.AddRange($b) } else { $buf.AddRange($pw) }
        }
        $a = $sha.ComputeHash($buf.ToArray())

        $buf = New-Object 'System.Collections.Generic.List[byte]'
        for ($i = 0; $i -lt $pw.Length; $i++) { $buf.AddRange($pw) }
        $dp = $sha.ComputeHash($buf.ToArray())
        $buf = New-Object 'System.Collections.Generic.List[byte]'
        Add-Repeated -Target $buf -Digest $dp -Length $pw.Length
        $p = $buf.ToArray()

        $buf = New-Object 'System.Collections.Generic.List[byte]'
        for ($i = 0; $i -lt (16 + $a[0]); $i++) { $buf.AddRange($saltBytes) }
        $ds = $sha.ComputeHash($buf.ToArray())
        $buf = New-Object 'System.Collections.Generic.List[byte]'
        Add-Repeated -Target $buf -Digest $ds -Length $saltBytes.Length
        $s = $buf.ToArray()

        $c = $a
        for ($i = 0; $i -lt 5000; $i++) {
            $buf = New-Object 'System.Collections.Generic.List[byte]'
            if ($i -band 1) { $buf.AddRange($p) } else { $buf.AddRange($c) }
            if ($i % 3) { $buf.AddRange($s) }
            if ($i % 7) { $buf.AddRange($p) }
            if ($i -band 1) { $buf.AddRange($c) } else { $buf.AddRange($p) }
            $c = $sha.ComputeHash($buf.ToArray())
        }
    } finally {
        $sha.Dispose()
    }

    # The final encoding is base64 over a fixed, deliberately scrambled byte order. Written out
    # literally so it can be checked against the specification a line at a time.
    $order = @(
        @(0, 21, 42), @(22, 43, 1), @(44, 2, 23), @(3, 24, 45), @(25, 46, 4), @(47, 5, 26),
        @(6, 27, 48), @(28, 49, 7), @(50, 8, 29), @(9, 30, 51), @(31, 52, 10), @(53, 11, 32),
        @(12, 33, 54), @(34, 55, 13), @(56, 14, 35), @(15, 36, 57), @(37, 58, 16), @(59, 17, 38),
        @(18, 39, 60), @(40, 61, 19), @(62, 20, 41)
    )
    $out = New-Object Text.StringBuilder
    foreach ($t in $order) {
        Add-CryptBase64 -Builder $out -B2 $c[$t[0]] -B1 $c[$t[1]] -B0 $c[$t[2]] -Count 4
    }
    Add-CryptBase64 -Builder $out -B2 0 -B1 0 -B0 $c[63] -Count 2

    return ('$6${0}${1}' -f $Salt, $out.ToString())
}

# The published test vector for this scheme. If this does not reproduce exactly, the
# implementation is wrong and no credential it produced could be trusted.
$vector = ConvertTo-Sha512Crypt -Password 'Hello world!' -Salt 'saltstring'
$expected = '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1'
if ($vector -cne $expected) { throw 'The SHA-512 crypt self-test failed. Nothing was written.' }
Write-Host 'Hash implementation verified against the published test vector.'

if (-not (Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue)) {
    throw 'ssh-keygen was not found. Install the Windows OpenSSH client, which the lab needs anyway.'
}

$keyPath = Join-Path $SecretsPath 'lab_ed25519'
$existing = @('lab_ed25519', 'lab_ed25519.pub', 'console-password.txt', 'console-password.hash') |
    Where-Object { Test-Path -LiteralPath (Join-Path $SecretsPath $_) }
if ($existing -and -not $Force) {
    Write-Host ''
    Write-Host ('Credentials already exist in {0}:' -f $SecretsPath)
    $existing | ForEach-Object { Write-Host ("  {0}" -f $_) }
    Write-Host ''
    throw 'Refusing to overwrite. Any VM already built trusts the current key, and replacing it locks you out. Use -Force if that is what you want.'
}

New-Item -ItemType Directory -Path $SecretsPath -Force | Out-Null

# Alphanumeric only. New-WindowsSeed.ps1 embeds this directly in autounattend.xml and rejects
# anything that would need escaping there.
$password = New-RandomString -Length 20 -Alphabet 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
$hash = ConvertTo-Sha512Crypt -Password $password -Salt (New-RandomString -Length 16 -Alphabet $CryptAlphabet)

Set-Content -LiteralPath (Join-Path $SecretsPath 'console-password.txt') -Value $password -Encoding Ascii
Set-Content -LiteralPath (Join-Path $SecretsPath 'console-password.hash') -Value $hash -Encoding Ascii

Remove-Item -LiteralPath $keyPath, "$keyPath.pub" -Force -ErrorAction SilentlyContinue
& ssh-keygen.exe -q -t ed25519 -N '""' -C 'wazuh-lab' -f $keyPath
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $keyPath)) { throw 'ssh-keygen did not produce a key.' }

# OpenSSH refuses a private key other accounts can read, and says so in a way that sends people
# hunting. Same treatment Enable-LabDashboard.ps1 applies.
& icacls.exe $keyPath /inheritance:r | Out-Null
& icacls.exe $keyPath /grant:r ("{0}:R" -f $env:USERNAME) | Out-Null

Write-Host ''
Write-Host ('Credentials written to {0}' -f $SecretsPath)
Write-Host '  lab_ed25519 and lab_ed25519.pub'
Write-Host '  console-password.txt and console-password.hash'
Write-Host ''
Write-Host 'These are the only copies. They are excluded from Git on purpose, so if you lose them'
Write-Host 'the lab has to be rebuilt. Next: New-LabSeeds.ps1, then New-WindowsSeed.ps1.'
