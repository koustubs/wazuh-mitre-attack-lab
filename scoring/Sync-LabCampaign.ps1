<#
.SYNOPSIS
    Copies the campaign records off the Linux endpoint so the host holds the dataset.

.DESCRIPTION
    run-campaign.sh appends a line per run as it goes. This brings those lines across and keeps
    them under evidence\campaigns\, which .gitignore already excludes.

    The point of copying continuously rather than once at the end is durability. If the host
    loses power, or the indexer comes back needing a shard repair, the labelled dataset is
    already here and does not have to be reconstructed from the manager. Losing power costs the
    run in flight and nothing before it.

    Safe to run as often as you like. It copies whole files rather than tailing, so a line that
    was half written when the last copy happened is corrected by the next one. Nothing is ever
    deleted on the VM.

.PARAMETER Watch
    Keep running, syncing every IntervalSeconds, until Ctrl+C. This is what you leave open
    overnight beside the campaign.

.PARAMETER IntervalSeconds
    How often to sync in -Watch mode. Default 300.

.EXAMPLE
    .\Sync-LabCampaign.ps1
    One sync, then a summary of everything collected so far.

.EXAMPLE
    .\Sync-LabCampaign.ps1 -Watch
    Sync every five minutes until stopped.
#>
[CmdletBinding()]
param(
    # Empty means "whatever lab.config.json says". Passing one overrides it for this run, which
    # is what you want when the endpoint has been rebuilt at a different address and you have
    # not updated the config yet.
    [string]$Address,
    [string]$User,
    [switch]$Watch,
    [ValidateRange(30, 3600)][int]$IntervalSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\setup\LabConfig.ps1')

$LabConfig = Get-LabConfig
$LabVms = Get-LabVms
if (-not $Address) {
    if (-not $LabVms.Contains('WAZUH-LINUX')) {
        throw "The $($LabConfig.profile) profile has no Linux endpoint, so there is no campaign to sync. Pass -Address to point at one anyway."
    }
    $Address = $LabVms['WAZUH-LINUX'].Address
}
if (-not $User) { $User = $LabConfig.guest.user }

$SshKey = Join-Path (Get-LabPath Secrets) 'lab_ed25519'
$Destination = Join-Path (Get-LabPath Evidence) 'campaigns'
$RemoteRoot = '/var/log/wazuh-lab/campaign'

$SshCommon = Get-LabSshOptions -KeyPath $SshKey

function Invoke-Native {
    <#
    Runs a native executable and returns its output, without letting stderr masquerade as a
    failure.

    Windows PowerShell 5.1 wraps each stderr line from a native command in an ErrorRecord when
    the stream is redirected, and $ErrorActionPreference = 'Stop' then promotes that to a
    terminating error even when the process exited 0. ssh's host key notice alone was enough to
    fail every sync, with the warning text reported as though it were the error. Only the exit
    code decides here.
    #>
    param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Exe @Arguments 2>&1
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Invoke-Remote {
    param([Parameter(Mandatory)][string]$Command)
    $r = Invoke-Native -Exe 'ssh.exe' -Arguments ($SshCommon + @(('{0}@{1}' -f $User, $Address), $Command))
    if ($r.Code -ne 0) {
        throw ("ssh exited {0}: {1}" -f $r.Code, (($r.Output | Out-String) -replace '\s+', ' ').Trim())
    }
    return $r.Output
}

function Sync-Once {
    $campaigns = @(Invoke-Remote "ls -1 $RemoteRoot 2>/dev/null || true" |
        Where-Object { $_ -match '^\d{8}T\d{6}Z-[0-9a-f]{6}$' })

    if ($campaigns.Count -eq 0) {
        Write-Host 'No campaigns on the endpoint yet.' -ForegroundColor DarkYellow
        return @()
    }

    $copied = @()
    foreach ($c in $campaigns) {
        $local = Join-Path $Destination $c
        if (-not (Test-Path -LiteralPath $local)) { New-Item -ItemType Directory -Path $local -Force | Out-Null }
        foreach ($f in 'campaign.jsonl', 'activity.jsonl', 'campaign.state', 'campaign.log') {
            # A campaign that is still starting up has not written every file yet, so a missing
            # one is normal and must not stop the sync of the others. Same stderr rule as above:
            # only the exit code is consulted.
            $null = Invoke-Native -Exe 'scp.exe' -Arguments ($SshCommon + @(
                '-q', ('{0}@{1}:{2}/{3}/{4}' -f $User, $Address, $RemoteRoot, $c, $f),
                (Join-Path $local $f)))
        }
        $copied += $c
    }
    return $copied
}

function Show-Summary {
    if (-not (Test-Path -LiteralPath $Destination)) { return }
    $runs = 0; $ticks = 0
    $labels = @{}; $kinds = @{}; $errors = 0
    $dirs = @(Get-ChildItem -LiteralPath $Destination -Directory -ErrorAction SilentlyContinue)

    foreach ($d in $dirs) {
        $jsonl = Join-Path $d.FullName 'campaign.jsonl'
        if (Test-Path -LiteralPath $jsonl) {
            foreach ($line in [IO.File]::ReadLines($jsonl)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                # A line truncated by a power cut is discarded rather than guessed at.
                try { $r = $line | ConvertFrom-Json } catch { continue }
                $runs++
                $lab = if ($r.PSObject.Properties.Name -contains 'label') { $r.label } else { 'unlabelled' }
                $kind = if ($r.PSObject.Properties.Name -contains 'episodeKind') { $r.episodeKind } else { 'unknown' }
                $labels[$lab] = 1 + ($(if ($labels.ContainsKey($lab)) { $labels[$lab] } else { 0 }))
                $kinds[$kind] = 1 + ($(if ($kinds.ContainsKey($kind)) { $kinds[$kind] } else { 0 }))
                if ($r.PSObject.Properties.Name -contains 'error' -and $r.error) { $errors++ }
            }
        }
        $act = Join-Path $d.FullName 'activity.jsonl'
        if (Test-Path -LiteralPath $act) {
            $ticks += @([IO.File]::ReadAllLines($act) | Where-Object { $_.Trim() }).Count
        }
    }

    Write-Host ''
    Write-Host ('Campaigns on this host: {0}' -f $dirs.Count)
    Write-Host ('Runs recorded:          {0}' -f $runs)
    Write-Host ('Background ticks:       {0}' -f $ticks)
    if ($errors -gt 0) {
        Write-Host ('Runs that errored:      {0}' -f $errors) -ForegroundColor Yellow
    }
    if ($runs -gt 0) {
        Write-Host ''
        Write-Host 'By label:'
        foreach ($k in ($labels.Keys | Sort-Object)) {
            Write-Host ('  {0,-12} {1,5}  ({2}%)' -f $k, $labels[$k], [math]::Round(100 * $labels[$k] / $runs))
        }
        Write-Host 'By episode kind:'
        foreach ($k in ($kinds.Keys | Sort-Object)) {
            Write-Host ('  {0,-22} {1,5}' -f $k, $kinds[$k])
        }
    }
    Write-Host ''
    Write-Host ('Stored in {0}' -f (Resolve-Path -LiteralPath $Destination).Path)
}

if (-not (Test-Path -LiteralPath $SshKey)) {
    throw "The lab SSH key is missing: $SshKey. Run New-LabSecrets.ps1 first."
}
if (-not (Test-Path -LiteralPath $Destination)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
}

if ($Watch) {
    Write-Host ("Syncing every {0}s. Ctrl+C to stop; the campaign on the VM keeps running." -f $IntervalSeconds)
    while ($true) {
        try {
            # @() because a single returned campaign unrolls to a bare string on the way out of
            # the function, and Set-StrictMode makes .Count on one an error.
            $c = @(Sync-Once)
            Write-Host ('{0}  synced {1} campaign(s)' -f (Get-Date -Format 'HH:mm:ss'), $c.Count)
        } catch {
            # The endpoint being briefly unreachable is not a reason to abandon the night.
            Write-Host ('{0}  sync failed: {1}' -f (Get-Date -Format 'HH:mm:ss'), $_.Exception.Message) -ForegroundColor Yellow
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
} else {
    # An unreachable endpoint must not hide what has already been collected. The summary reads
    # the host's own copy, so it is worth printing whether or not this sync got through.
    $reached = $true
    try {
        $c = @(Sync-Once)
        Write-Host ('Synced {0} campaign(s).' -f $c.Count)
    } catch {
        $reached = $false
        Write-Host ('Could not reach {0}: {1}' -f $Address, $_.Exception.Message) -ForegroundColor Yellow
        Write-Host 'Showing what is already on this host.' -ForegroundColor Yellow
    }
    Show-Summary
    # Set explicitly, because ssh's own exit code would otherwise surface as the script's and a
    # successful sync would report 255.
    if ($reached) { exit 0 } else { exit 1 }
}
