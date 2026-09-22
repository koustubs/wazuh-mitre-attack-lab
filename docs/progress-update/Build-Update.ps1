#requires -Version 5.1
<#
Build the progress update and print it to docs/Wazuh-Lab-Progress-Update.pdf.

Two steps, same arrangement as scoring/report/Build-Report.ps1 and for the
same reasons. build-update.py reads the measurement artefacts and writes update.html; this
prints that page with Edge, which is already on every Windows 11 machine and therefore does
not add a dependency that would stop this being regenerated.

    .\Build-Update.ps1
    .\Build-Update.ps1 -Open
#>
[CmdletBinding()]
param(
    # Where the finished PDF lands. Empty means the docs directory above this one; the default
    # is resolved in the body, because $PSScriptRoot is not reliably populated inside a param
    # block on Windows PowerShell 5.1 and the empty string it leaves behind reaches Join-Path
    # as a binding failure that names Join-Path rather than this script.
    [string]$OutFile,
    [switch]$Open
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $here) { throw 'Cannot resolve the script directory. Run this script by path.' }
if (-not $OutFile) { $OutFile = Join-Path $here '..\Wazuh-Lab-Progress-Update.pdf' }
$html = Join-Path $here 'update.html'

$python = @('python', 'py') |
    ForEach-Object { Get-Command $_ -ErrorAction SilentlyContinue } |
    Select-Object -First 1
if (-not $python) { throw 'No python on PATH. The page is built from the artefacts by build-update.py.' }

# Native stderr is text, never a failure. PowerShell 5.1 wraps each stderr line from a native
# command in an ErrorRecord when the stream is redirected, and ErrorActionPreference Stop then
# turns a harmless warning into a terminating error on exit code 0. The exit code decides.
$buildOut = & $python.Source (Join-Path $here 'build-update.py') 2>&1 | ForEach-Object { "$_" }
if ($LASTEXITCODE -ne 0) { throw ("build-update.py failed:`n" + ($buildOut -join "`n")) }
$buildOut | ForEach-Object { Write-Host "  $_" }
if (-not (Test-Path -LiteralPath $html)) { throw "build-update.py did not write $html." }

$edge = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $edge) {
    throw ('Could not find msedge.exe. The page is at ' + $html + ' and any browser will ' +
           'print it to PDF with Ctrl+P.')
}

$outDir = Split-Path -Parent $OutFile
if (-not (Test-Path -LiteralPath $outDir)) { $null = New-Item -ItemType Directory -Path $outDir }
$OutFile = [IO.Path]::GetFullPath((Join-Path $outDir (Split-Path -Leaf $OutFile)))
if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force }

# Printed into a directory with no space in its path and moved afterwards. This repository
# lives under "cybersec intern", and PowerShell 5.1 hands --print-to-pdf=C:\...\cybersec
# intern\... to a native executable unquoted, so Edge reads it as two targets and refuses the
# run. Move-Item has no such difficulty.
$work = Join-Path ([IO.Path]::GetTempPath()) ("lab-update-" + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
$staged = Join-Path $work 'update.pdf'

Write-Host 'Printing to PDF...'
$edgeArgs = @(
    '--headless=new'
    '--disable-gpu'
    '--no-first-run'
    '--no-default-browser-check'
    '--disable-extensions'
    "--user-data-dir=$(Join-Path $work 'profile')"
    '--no-pdf-header-footer'
    "--print-to-pdf=$staged"
    ([Uri](Resolve-Path -LiteralPath $html).Path).AbsoluteUri
)
try {
    $p = Start-Process -FilePath $edge -ArgumentList $edgeArgs -PassThru -Wait -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "Edge exited with $($p.ExitCode)." }
    if (-not (Test-Path -LiteralPath $staged)) {
        throw "Edge reported success but wrote no file. The page is at $html."
    }
    Move-Item -LiteralPath $staged -Destination $OutFile -Force
} finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host ("Wrote {0} ({1} KB)" -f $OutFile, [math]::Round((Get-Item -LiteralPath $OutFile).Length / 1KB)) -ForegroundColor Green
Write-Host 'Read it before sending it. Nothing here checks the prose.'

if ($Open) { Start-Process -FilePath $OutFile }
