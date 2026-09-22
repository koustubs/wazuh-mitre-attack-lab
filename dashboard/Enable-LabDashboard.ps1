#requires -Version 5.1
<#
One-time setup that lets the dashboard read the inside of the lab, and trigger scenarios, without
ever holding a password.

The dashboard works before this runs. It reads Wazuh service state over SSH with no special
rights at all, and reports the rest as "not readable yet" rather than showing an empty panel.
What this adds is everything that needs root on the far side:

  Manager
    - the lab account joins the wazuh group, which is what makes the alert log and ossec.log
      readable.
      Reading alerts is the main thing the dashboard does and it should not need root to do it.
    - a sudoers rule permitting exactly systemctl start, stop and restart on the four Wazuh
      units, agent_control -l, and the indexer summary below. Nothing else.
    - /usr/local/bin/lab-dashboard-indexer, which reports cluster health, alert document count
      and retention policy state. It authenticates to the indexer with the admin certificate,
      so the admin password is not involved in any of it.
    - /usr/local/bin/lab-dashboard-creds, which returns the Wazuh web interface login so the
      dashboard can show it. This is the one thing here that hands over a password. It is read
      from the installer's own log, printed on stdout rather than passed as an argument to
      anything, and travels back over the same SSH connection as everything else. If you would
      rather the dashboard never saw it, leave this file out: the credentials panel then says
      it could not read it, and nothing else changes.

  Linux endpoint
    - the lab account joins the wazuh group.
    - a sudoers rule permitting systemctl on wazuh-agent, and the six exact scenario runs.
    - invoke-scenario.sh installed to a stable path, with a wrapper that accepts only the six
      valid scenario and mode combinations.
    - run-campaign.sh the same way, with a wrapper accepting start, stop and status. Without
      this the dashboard could run a single scenario without a password but not a campaign.

Every sudoers file is checked with visudo before it is installed, and nothing is written if that
check fails, because a broken sudoers file locks you out of sudo entirely.

Run this once after the lab is built. It asks for the lab account's sudo password, uses it for
this run only, and stores nothing.

    .\Enable-LabDashboard.ps1
#>
[CmdletBinding()]
param(
    # Empty means "whatever lab.config.json says". Pass one to override it for this run.
    [string]$ManagerAddress,
    [string]$LinuxAddress,
    [string]$User
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\setup\LabConfig.ps1')

$LabConfig = Get-LabConfig
$LabVms = Get-LabVms
if (-not $ManagerAddress) { $ManagerAddress = $LabVms['WAZUH-MANAGER'].Address }
if (-not $LinuxAddress -and $LabVms.Contains('WAZUH-LINUX')) { $LinuxAddress = $LabVms['WAZUH-LINUX'].Address }
if (-not $User) { $User = $LabConfig.guest.user }

$keyPath = Join-Path (Get-LabPath Secrets) 'lab_ed25519'
if (-not (Test-Path -LiteralPath $keyPath)) { throw "Cannot find the lab SSH key at $keyPath. Run setup\New-LabSecrets.ps1 first." }
$keyPath = (Resolve-Path -LiteralPath $keyPath).Path
$scenarioPath = (Resolve-Path (Join-Path $PSScriptRoot '..\agents\linux\invoke-scenario.sh')).Path
$campaignPath = (Resolve-Path (Join-Path $PSScriptRoot '..\agents\linux\run-campaign.sh')).Path

# Windows OpenSSH refuses a private key that other accounts can read. The key lives in a repo
# folder, so tighten it here rather than leaving people to decode "UNPROTECTED PRIVATE KEY FILE".
Write-Host 'Restricting the SSH key to your account only...'
& icacls.exe $keyPath /inheritance:r | Out-Null
& icacls.exe $keyPath /grant:r ("{0}:R" -f $env:USERNAME) | Out-Null

$sshCommon = Get-LabSshOptions -KeyPath $keyPath

function Invoke-Native {
    <#
    Runs a native executable and decides success from its exit code alone.

    Windows PowerShell 5.1 wraps each stderr line from a native command in an ErrorRecord when
    the stream is redirected, and $ErrorActionPreference = 'Stop' then promotes that to a
    terminating error even though the process exited 0. ssh's host key notice alone was enough
    to abort this script at the first scp, reporting the warning text as though it were the
    failure. Sync-LabCampaign.ps1 hit the same thing and carries the same helper.
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

Write-Host ''
Write-Host 'Enter the sudo password for the lab account. It is used for this run only and not stored.'
$secure = Read-Host -AsSecureString ("Password for {0}" -f $User)
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

# The remote script is written on the far side from a quoted heredoc, so nothing in it is
# expanded by PowerShell or by the shell on the way over. Passing shell commands inline through
# PowerShell to ssh mangles quoting; this project has been bitten by that before.
$setupScript = @'
set -eu
ROLE="$1"

if [ "$ROLE" = "manager" ]; then
  UNITS="wazuh-manager wazuh-indexer wazuh-dashboard filebeat"
else
  UNITS="wazuh-agent"
fi

# 1. Read access to the alert log and ossec.log, without sudo.
if getent group wazuh >/dev/null 2>&1; then
  usermod -aG wazuh "$SUDO_USER"
  echo "  added $SUDO_USER to the wazuh group"
fi

# 2. The helper scripts, before the sudoers rule that names them, so a rule never points at
#    something that is not there.
if [ "$ROLE" = "manager" ]; then
  cat > /usr/local/bin/lab-dashboard-indexer <<'INDEXER'
#!/usr/bin/env python3
# Cluster health, alert volume and retention policy state, as one JSON document.
#
# Authenticates with the indexer's admin certificate rather than the admin password. Querying
# does not need the password, so this does not go near the install log, and the certificate
# never leaves this machine. Handing the password to somebody who asks for it is a separate
# job, done by lab-dashboard-creds.
import json, subprocess

CERTS = '/etc/wazuh-indexer/certs'

def query(path):
    try:
        r = subprocess.run(
            ['curl', '-s', '--max-time', '8', '-k',
             '--cert', CERTS + '/admin.pem', '--key', CERTS + '/admin-key.pem',
             'https://127.0.0.1:9200' + path],
            capture_output=True, text=True, timeout=12)
        if r.returncode != 0:
            return None
        return json.loads(r.stdout)
    except Exception:
        return None

out = {}

health = query('/_cluster/health')
if isinstance(health, dict):
    out['status'] = health.get('status')
    out['nodes'] = health.get('number_of_nodes')

indices = query('/_cat/indices/wazuh-alerts-*?format=json&bytes=b')
if isinstance(indices, list):
    docs = 0
    size = 0
    for i in indices:
        try:
            docs += int(i.get('docs.count') or 0)
            size += int(i.get('store.size') or 0)
        except Exception:
            pass
    out['indices'] = len(indices)
    out['docs'] = docs
    out['storeMb'] = round(size / 1048576.0, 1)

# Retention is not something Wazuh ships, so an index with no policy attached is a real finding
# rather than a cosmetic one: it means the disk fills eventually.
explain = query('/_plugins/_ism/explain/wazuh-alerts-*')
if isinstance(explain, dict):
    policies = set()
    for key, value in explain.items():
        if isinstance(value, dict) and value.get('index.plugins.index_state_management.policy_id'):
            policies.add(value['index.plugins.index_state_management.policy_id'])
    if policies:
        out['retention'] = ', '.join(sorted(policies))
    elif out.get('indices'):
        out['retention'] = 'none attached'

print(json.dumps(out))
INDEXER
  chmod 0755 /usr/local/bin/lab-dashboard-indexer
  echo "  installed /usr/local/bin/lab-dashboard-indexer"

  cat > /usr/local/bin/lab-dashboard-creds <<'CREDS'
#!/usr/bin/env python3
# The Wazuh web interface login, as one JSON document.
#
# The installer generates the admin password and writes it into its own log under /root. Nothing
# else on this machine keeps it anywhere readable, so this is the one value the dashboard cannot
# reach without root.
#
# It is printed on stdout rather than passed as an argument to anything, so it never appears in
# a process list, and it goes back over the SSH connection the dashboard already has open.
#
# The first Password: line is the admin one. configure-dashboard.sh reads it the same way and
# authenticates with the result, so the format is not being guessed at here.
import json, re

LOG = '/root/wazuh-lab-install/install.log'
out = {'username': 'admin'}
try:
    with open(LOG, encoding='utf-8', errors='replace') as handle:
        for line in handle:
            found = re.search(r'Password:\s*(\S+)', line)
            if found:
                out['password'] = found.group(1)
                break
    if 'password' not in out:
        out['error'] = 'No Password: line in ' + LOG
except Exception as problem:
    out['error'] = str(problem)
print(json.dumps(out))
CREDS
  # Root only. It reads a root-owned file, so any other caller would get a traceback rather
  # than an answer, and there is no reason for it to be runnable by anyone else.
  chmod 0750 /usr/local/bin/lab-dashboard-creds
  echo "  installed /usr/local/bin/lab-dashboard-creds"
fi

if [ "$ROLE" = "endpoint" ] && [ -f /tmp/lab-invoke-scenario.sh ]; then
  # /tmp does not survive, and the dashboard needs a path it can rely on.
  mkdir -p /usr/local/lib/wazuh-lab
  install -o root -g root -m 0755 /tmp/lab-invoke-scenario.sh /usr/local/lib/wazuh-lab/invoke-scenario.sh
  rm -f /tmp/lab-invoke-scenario.sh
  cat > /usr/local/bin/lab-scenario <<'SCENARIO'
#!/bin/sh
# Thin wrapper so sudoers can name six exact commands instead of a script plus free arguments.
set -eu
case "${1:-}" in S1|S2|S3) ;; *) echo 'Usage: lab-scenario S1|S2|S3 test|comparison' >&2; exit 2;; esac
case "${2:-}" in test|comparison) ;; *) echo 'Usage: lab-scenario S1|S2|S3 test|comparison' >&2; exit 2;; esac
exec /bin/bash /usr/local/lib/wazuh-lab/invoke-scenario.sh "$1" "$2"
SCENARIO
  chmod 0755 /usr/local/bin/lab-scenario
  echo "  installed /usr/local/bin/lab-scenario"
fi

if [ "$ROLE" = "endpoint" ] && [ -f /tmp/lab-run-campaign.sh ]; then
  # The campaign is hours of scenario runs. Starting one from the dashboard used to prompt for a
  # password, because the sudoers grant named the six scenario runs and not this.
  mkdir -p /usr/local/lib/wazuh-lab
  install -o root -g root -m 0755 /tmp/lab-run-campaign.sh /usr/local/lib/wazuh-lab/run-campaign.sh
  rm -f /tmp/lab-run-campaign.sh
  cat > /usr/local/bin/lab-campaign <<'CAMPAIGN'
#!/bin/sh
# Same shape as lab-scenario: a fixed set of invocations sudoers can name, rather than a script
# plus free arguments. The hour count is checked here so the sudoers rule does not have to
# enumerate 48 of them.
set -eu
case "${1:-}" in
  start)
    hours=${2:-14}
    case "$hours" in ''|*[!0-9]*) echo 'hours must be a whole number' >&2; exit 2;; esac
    [ "$hours" -ge 1 ] && [ "$hours" -le 48 ] || { echo 'hours must be 1 to 48' >&2; exit 2; }
    exec /bin/bash /usr/local/lib/wazuh-lab/run-campaign.sh start --hours "$hours"
    ;;
  stop|status)
    exec /bin/bash /usr/local/lib/wazuh-lab/run-campaign.sh "$1"
    ;;
  *)
    echo 'Usage: lab-campaign start [hours] | stop | status' >&2
    exit 2
    ;;
esac
CAMPAIGN
  chmod 0755 /usr/local/bin/lab-campaign
  echo "  installed /usr/local/bin/lab-campaign"
fi

# 3. A narrow sudoers rule, validated before it is installed. An invalid file here would break
#    sudo entirely, so this never writes to /etc/sudoers.d without visudo agreeing first.
TMP=$(mktemp)
{
  printf 'Cmnd_Alias WAZUH_LAB_SVC = '
  first=1
  for u in $UNITS; do
    for a in start stop restart; do
      if [ $first -eq 1 ]; then first=0; else printf ', '; fi
      printf '/usr/bin/systemctl %s %s' "$a" "$u"
    done
  done
  printf '\n'
  if [ "$ROLE" = "manager" ]; then
    printf 'Cmnd_Alias WAZUH_LAB_READ = /var/ossec/bin/agent_control -l, /usr/local/bin/lab-dashboard-indexer, /usr/local/bin/lab-dashboard-creds\n'
    printf '%s ALL=(root) NOPASSWD: WAZUH_LAB_SVC, WAZUH_LAB_READ\n' "$SUDO_USER"
  elif [ -x /usr/local/bin/lab-scenario ]; then
    # Six exact invocations, arguments included. Not a wildcard: these scripts deliberately
    # create accounts and cron entries, so the grant says precisely which runs are permitted.
    printf 'Cmnd_Alias WAZUH_LAB_SCENARIO = '
    first=1
    for s in S1 S2 S3; do
      for m in test comparison; do
        if [ $first -eq 1 ]; then first=0; else printf ', '; fi
        printf '/usr/local/bin/lab-scenario %s %s' "$s" "$m"
      done
    done
    printf '\n'
    if [ -x /usr/local/bin/lab-campaign ]; then
      # Three verbs, not a wildcard. lab-campaign itself refuses anything but a whole number of
      # hours in range, so the grant does not have to enumerate every hour count.
      printf 'Cmnd_Alias WAZUH_LAB_CAMPAIGN = /usr/local/bin/lab-campaign start *, /usr/local/bin/lab-campaign stop, /usr/local/bin/lab-campaign status\n'
      printf '%s ALL=(root) NOPASSWD: WAZUH_LAB_SVC, WAZUH_LAB_SCENARIO, WAZUH_LAB_CAMPAIGN\n' "$SUDO_USER"
    else
      printf '%s ALL=(root) NOPASSWD: WAZUH_LAB_SVC, WAZUH_LAB_SCENARIO\n' "$SUDO_USER"
    fi
  else
    printf '%s ALL=(root) NOPASSWD: WAZUH_LAB_SVC\n' "$SUDO_USER"
  fi
} > "$TMP"

if visudo -c -f "$TMP" >/dev/null 2>&1; then
  install -o root -g root -m 0440 "$TMP" /etc/sudoers.d/wazuh-lab-dashboard
  echo "  installed /etc/sudoers.d/wazuh-lab-dashboard"
else
  rm -f "$TMP"
  echo "  sudoers rule failed validation; nothing was installed" >&2
  exit 1
fi
rm -f "$TMP"

# An older version of this script installed a status collector on the manager. It is sent over
# the wire now, so a stale copy left behind would only be confusing.
rm -f /usr/local/bin/lab-dashboard-status
'@

function Invoke-Setup {
    param([string]$Address, [string]$Role)
    Write-Host ''
    Write-Host ("Configuring {0} ({1})..." -f $Address, $Role)
    $localFile = Join-Path $env:TEMP ('lab-dashboard-setup-{0}.sh' -f [guid]::NewGuid().ToString('N'))
    # LF only. CRLF in a shell script fails in ways that are miserable to diagnose.
    [IO.File]::WriteAllText($localFile, ($setupScript -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
    try {
        if ($Role -eq 'endpoint') {
            $drivers = @{
                $scenarioPath = '/tmp/lab-invoke-scenario.sh'
                $campaignPath = '/tmp/lab-run-campaign.sh'
            }
            foreach ($local in $drivers.Keys) {
                $r = Invoke-Native -Exe 'scp.exe' -Arguments ($sshCommon + @(
                    $local, ("{0}@{1}:{2}" -f $User, $Address, $drivers[$local])))
                if ($r.Code -ne 0) {
                    throw ("Could not copy {0} to {1}: {2}" -f
                           (Split-Path -Leaf $local), $Address,
                           (($r.Output | Out-String) -replace '\s+', ' ').Trim())
                }
            }
        }
        $r = Invoke-Native -Exe 'scp.exe' -Arguments ($sshCommon + @(
            $localFile, ("{0}@{1}:/tmp/lab-dashboard-setup.sh" -f $User, $Address)))
        if ($r.Code -ne 0) {
            throw ("Could not copy the setup script to {0}: {1}" -f
                   $Address, (($r.Output | Out-String) -replace '\s+', ' ').Trim())
        }
        # Not one double quote in this string, deliberately. PowerShell 5.1 re-quotes an
        # argument on its way to a native executable, and an embedded "" does not survive the
        # trip: the far side received an unbalanced quote and bash refused the whole line with
        # "unexpected EOF while looking for matching". sudo -p "" was the only quoted thing
        # here and it was only silencing the password prompt, which is cosmetic, so it is gone
        # rather than escaped. Anything that genuinely needs quoting belongs in $setupScript,
        # which travels as a file and is never parsed by PowerShell or by a shell in between.
        $remote = 'sudo -S sh /tmp/lab-dashboard-setup.sh {0}; rc=$?; rm -f /tmp/lab-dashboard-setup.sh; exit $rc' -f $Role
        $plain | & ssh.exe @sshCommon ("{0}@{1}" -f $User, $Address) $remote
        if ($LASTEXITCODE -ne 0) { throw "Setup failed on $Address." }
        Write-Host ("  {0} is configured." -f $Address)
    } finally {
        Remove-Item -LiteralPath $localFile -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Setup -Address $ManagerAddress -Role 'manager'
Invoke-Setup -Address $LinuxAddress   -Role 'endpoint'

Write-Host ''
Write-Host 'Checking what the manager will now answer...'
$check = (Invoke-Native -Exe 'ssh.exe' -Arguments ($sshCommon + @(
    ("{0}@{1}" -f $User, $ManagerAddress),
    'sudo -n /var/ossec/bin/agent_control -l >/dev/null 2>&1 && echo agents_ok; sudo -n /usr/local/bin/lab-dashboard-indexer >/dev/null 2>&1 && echo indexer_ok; test -r /var/ossec/logs/alerts/alerts.json && echo alerts_ok'
))).Output
foreach ($capability in @(
    @{ Token = 'agents_ok';  Text = 'agent state' },
    @{ Token = 'indexer_ok'; Text = 'indexer summary' },
    @{ Token = 'alerts_ok';  Text = 'alert log' })) {
    if ($check -match $capability.Token) { Write-Host ("  {0}: yes" -f $capability.Text) }
    else { Write-Host ("  {0}: not yet" -f $capability.Text) }
}

Write-Host ''
Write-Host 'Group membership only takes effect on a new login, so if the alert log still reads "not yet",'
Write-Host 'restart the manager and check the dashboard again. Everything else applies immediately.'

$plain = $null
Write-Host ''
Write-Host 'Done.'
