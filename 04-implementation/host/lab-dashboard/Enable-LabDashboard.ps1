#requires -Version 5.1
<#
One-time setup so the dashboard can read lab health and control Wazuh services without ever
holding a password.

Three things are installed:

1. /usr/local/bin/lab-dashboard-status on the manager. One command that returns service state,
   agent connection state and recent alerts as JSON, so the dashboard makes one SSH round trip
   per cycle instead of several.

2. Membership of the "wazuh" group for labadmin, which is what makes the alert log readable
   without sudo. Reading alerts is the main thing the dashboard does, so it should not need
   elevated rights to do it.

3. A sudoers drop-in permitting exactly systemctl start, stop and restart against the named
   Wazuh units, plus agent_control -l. Nothing else. It is validated with visudo before being
   installed, and nothing is written if validation fails.

Run this once after the lab is built. It asks for the lab account's sudo password, uses it for
this run only, and stores nothing.

    .\Enable-LabDashboard.ps1
#>
[CmdletBinding()]
param(
    [string]$ManagerAddress = '172.29.70.10',
    [string]$LinuxAddress   = '172.29.70.30',
    [string]$User           = 'labadmin'
)

$ErrorActionPreference = 'Stop'
$keyPath = (Resolve-Path (Join-Path $PSScriptRoot '..\.lab-secrets\lab_ed25519')).Path
if (-not (Test-Path -LiteralPath $keyPath)) { throw "Cannot find the lab SSH key at $keyPath" }

# Windows OpenSSH refuses a private key that other accounts can read. The key lives in a repo
# folder, so tighten it here rather than leaving people to decode "UNPROTECTED PRIVATE KEY FILE".
Write-Host 'Restricting the SSH key to your account only...'
& icacls.exe $keyPath /inheritance:r | Out-Null
& icacls.exe $keyPath /grant:r ("{0}:R" -f $env:USERNAME) | Out-Null

$sshCommon = @(
    '-i', $keyPath, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=NUL', '-o', 'ConnectTimeout=8'
)

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

# 1. Read access to the alert log, without sudo.
if getent group wazuh >/dev/null 2>&1; then
  usermod -aG wazuh "$SUDO_USER"
  echo "  added $SUDO_USER to the wazuh group"
fi

# 2. A narrow sudoers rule, validated before it is installed. An invalid file here would break
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
    printf 'Cmnd_Alias WAZUH_LAB_READ = /var/ossec/bin/agent_control -l\n'
    printf '%s ALL=(root) NOPASSWD: WAZUH_LAB_SVC, WAZUH_LAB_READ\n' "$SUDO_USER"
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

# 3. The status command, manager only.
if [ "$ROLE" = "manager" ]; then
  cat > /usr/local/bin/lab-dashboard-status <<'INNER'
#!/bin/sh
python3 - <<'PY'
import json, os, subprocess

def unit_state(u):
    try:
        r = subprocess.run(['systemctl', 'is-active', u], capture_output=True, text=True, timeout=5)
        return (r.stdout or '').strip() or 'unknown'
    except Exception:
        return 'unknown'

services = [{'unit': u, 'state': unit_state(u)}
            for u in ('wazuh-manager', 'wazuh-indexer', 'wazuh-dashboard', 'filebeat')]

agents = []
try:
    out = subprocess.run(['sudo', '-n', '/var/ossec/bin/agent_control', '-l'],
                         capture_output=True, text=True, timeout=10).stdout
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith('ID:'):
            continue
        parts = [p.strip() for p in line.split(',')]
        info = {}
        for p in parts:
            if ':' in p:
                k, v = p.split(':', 1)
                info[k.strip().lower()] = v.strip()
        # The connection state is the trailing field, which carries no label.
        agents.append({'id': info.get('id', ''), 'name': info.get('name', ''),
                       'status': parts[-1] if parts and ':' not in parts[-1] else 'unknown'})
except Exception:
    pass

alerts = []
try:
    path = '/var/ossec/logs/alerts/alerts.json'
    with open(path, 'rb') as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - 300000))
        lines = fh.read().decode('utf-8', 'replace').splitlines()
    for line in lines[-500:]:
        try:
            a = json.loads(line)
        except Exception:
            continue
        rule = a.get('rule', {}) or {}
        mitre = rule.get('mitre', {}) or {}
        alerts.append({
            'time':  (a.get('timestamp') or '')[11:19],
            'agent': (a.get('agent', {}) or {}).get('name', ''),
            'id':    rule.get('id', ''),
            'level': rule.get('level', ''),
            'desc':  (rule.get('description') or '')[:110],
            'tech':  ', '.join(mitre.get('technique', []) or []),
        })
    # Always return 50, newest first. The page decides how many of them to show, so changing
    # that is instant and costs no extra round trip.
    alerts = alerts[-50:][::-1]
except Exception:
    pass

print(json.dumps({'services': services, 'agents': agents, 'alerts': alerts}))
PY
INNER
  chmod 0755 /usr/local/bin/lab-dashboard-status
  echo "  installed /usr/local/bin/lab-dashboard-status"
fi
'@

function Invoke-Setup {
    param([string]$Address, [string]$Role)
    Write-Host ''
    Write-Host ("Configuring {0} ({1})..." -f $Address, $Role)
    $localFile = Join-Path $env:TEMP ('lab-dashboard-setup-{0}.sh' -f [guid]::NewGuid().ToString('N'))
    # LF only. CRLF in a shell script fails in ways that are miserable to diagnose.
    [IO.File]::WriteAllText($localFile, ($setupScript -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
    try {
        & scp.exe @sshCommon $localFile ("{0}@{1}:/tmp/lab-dashboard-setup.sh" -f $User, $Address) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not copy the setup script to $Address." }
        $remote = 'sudo -S -p "" sh /tmp/lab-dashboard-setup.sh {0}; rc=$?; rm -f /tmp/lab-dashboard-setup.sh; exit $rc' -f $Role
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
Write-Host 'Checking that it worked...'
$check = & ssh.exe @sshCommon ("{0}@{1}" -f $User, $ManagerAddress) 'lab-dashboard-status' 2>&1
if ($LASTEXITCODE -eq 0 -and $check -match '"services"') {
    Write-Host '  The manager answered with service, agent and alert data.'
} else {
    Write-Warning '  The status command did not answer as expected. Group membership only takes effect on a new'
    Write-Warning '  login, so if the alert list is empty, reboot the manager and try again.'
}

$plain = $null
Write-Host ''
Write-Host 'Done. Start the dashboard and the Lab health and Recent alerts panels will populate.'
