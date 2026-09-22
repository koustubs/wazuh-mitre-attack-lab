#requires -Version 5.1
<#
Build the modelling report and print it to a PDF in docs/.

Two steps, each doing one thing. build-report.py reads the measurement artefacts and writes
report.html; this prints that page with Edge in headless mode.

Edge rather than pandoc, weasyprint or a LaTeX toolchain, for the same reason the modelling
step has no sklearn: it is already on every Windows 11 machine, and a report that needs a
half gigabyte of dependencies installed before anyone can regenerate it will stop being
regenerated. The cost is that this is the one script here that will not run on Linux.

Nothing numeric lives in the template. If a figure in the PDF looks wrong, the artefact it was
read from is wrong, and the fix belongs in the step that produced it.

    .\Build-Report.ps1
    .\Build-Report.ps1 -Open          # and open it when it is done
#>
[CmdletBinding()]
param(
    # Where the finished PDF lands. Empty means docs/, beside the proposal; the default is
    # resolved in the body rather than here, because $PSScriptRoot is not reliably populated
    # inside a param block on Windows PowerShell 5.1 and an empty string reaches Join-Path
    # as a parameter binding failure with no useful message.
    [string]$OutFile,
    [switch]$Open
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $here) { throw 'Cannot resolve the script directory. Run this script by path.' }
if (-not $OutFile) {
    $OutFile = Join-Path $here '..\..\docs\Detection-Modelling-Report.pdf'
}
$html = Join-Path $here 'report.html'

Write-Host 'Reading the measurements...'

# python or py, whichever answers. A machine that has run the modelling step has one of them.
$python = $null
foreach ($candidate in @('python', 'py')) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) { $python = $cmd.Source; break }
}
if (-not $python) {
    throw 'No python on PATH. The report is built from the measurement artefacts by build-report.py.'
}

# Native stderr is read as text, never as a failure. PowerShell 5.1 wraps each stderr line from
# a native command in an ErrorRecord when the stream is redirected, and ErrorActionPreference
# Stop then promotes a harmless warning into a terminating error on exit code 0. This project
# has lost two afternoons to that already, once in Sync-LabCampaign.ps1 and once in
# Enable-LabDashboard.ps1. The exit code is the only thing that decides.
$buildOut = & $python (Join-Path $here 'build-report.py') 2>&1 | ForEach-Object { "$_" }
if ($LASTEXITCODE -ne 0) {
    throw ("build-report.py failed:`n" + ($buildOut -join "`n"))
}
$buildOut | ForEach-Object { Write-Host "  $_" }

if (-not (Test-Path -LiteralPath $html)) { throw "build-report.py did not write $html." }

$edge = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $edge) {
    throw ('Could not find msedge.exe. The page is at ' + $html +
           ' and any browser will print it to PDF with Ctrl+P.')
}

$outDir = Split-Path -Parent $OutFile
if (-not (Test-Path -LiteralPath $outDir)) { $null = New-Item -ItemType Directory -Path $outDir }
# Resolved to a full path because Edge is given an absolute file URL and will not resolve one
# relative to this session's directory.
$OutFile = [IO.Path]::GetFullPath((Join-Path $outDir (Split-Path -Leaf $OutFile)))
if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force }

# A throwaway profile, so this never touches the profile the user browses with and never
# inherits an extension or a policy from it.
$work = Join-Path ([IO.Path]::GetTempPath()) ("lab-report-" + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
$profileDir = Join-Path $work 'profile'

# Printed into the temporary directory and moved afterwards, rather than written straight to
# its destination.
#
# This path contains a space, and PowerShell 5.1 hands --print-to-pdf=C:\...\cybersec intern\...
# to a native executable without quoting the value, so Edge reads it as two arguments and
# refuses the run with "Multiple targets are not supported in headless mode". Quoting it here
# does not survive either: the same re-quoting already cost this project a broken remote
# command in Enable-LabDashboard.ps1. Giving Edge a path with no space in it sidesteps the
# whole class of problem, and Move-Item has no such difficulty.
$staged = Join-Path $work 'report.pdf'

Write-Host 'Printing to PDF...'
# A file URI, so the space in this repository's path arrives percent encoded.
$uri = ([Uri](Resolve-Path -LiteralPath $html).Path).AbsoluteUri
$edgeArgs = @(
    '--headless=new'
    '--disable-gpu'
    '--no-first-run'
    '--no-default-browser-check'
    '--disable-extensions'
    "--user-data-dir=$profileDir"
    '--no-pdf-header-footer'
    "--print-to-pdf=$staged"
    $uri
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

$kb = [math]::Round((Get-Item -LiteralPath $OutFile).Length / 1KB)
Write-Host ""
Write-Host "Wrote $OutFile ($kb KB)" -ForegroundColor Green
Write-Host "Read it before sending it. Nothing here checks the prose."

if ($Open) { Start-Process -FilePath $OutFile }
