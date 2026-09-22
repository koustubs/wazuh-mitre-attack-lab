#requires -Version 5.1
<#
A small local control panel for the three Wazuh lab VMs.

Serves one page on 127.0.0.1 showing live state and resource usage for each VM, with buttons to
start, shut down, restart or power them off. Everything it needs is built into Windows: the
Hyper-V module, CIM, and System.Net.HttpListener. There is nothing to install.

Three things worth knowing before reading further.

It relaunches itself elevated. Hyper-V will not report VM state to an ordinary session, so the
script asks for administrator rights once at launch instead of failing later.

It never starts anything on its own. Opening the dashboard is read-only. Every power action
requires a click, and the only autostart value this script can write is "Nothing", so it can
disable automatic startup but has no code path that enables it.

Power actions run as jobs. A guest shutdown can take half a minute, and the listener is single
threaded, so blocking on it would freeze the page. The UI catches up on its next poll.
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)][int]$Port = 8077,
    [switch]$NoBrowser,
    # Serve without asking for elevation. The page still loads and the layout is all there, but
    # Hyper-V refuses to answer, so every VM reports "Needs administrator". Useful for looking at
    # the dashboard, or testing it, without a UAC prompt.
    [switch]$NoElevate
)

$ErrorActionPreference = 'Stop'

# Same elevation check as Get-LabHost.ps1, but it asks rather than refusing.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$script:IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $script:IsElevated -and -not $NoElevate) {
    Write-Host 'Hyper-V needs administrator rights. Requesting elevation...'
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-Port', $Port)
    if ($NoBrowser) { $relaunch += '-NoBrowser' }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $relaunch | Out-Null
    } catch {
        Write-Warning 'Elevation was declined. Without it the dashboard cannot read or control the VMs.'
    }
    return
}

# Names, addresses, roles and sizes all come from lab.config.json at the repository root. They
# used to be written here and in seven other files, which had to agree and which nothing checked.
# Changing the subnet meant finding all eight.
#
# The host checks and the hypervisor come from the same place setup\Test-LabHost.ps1 uses, so the
# two cannot disagree about whether this machine is ready. This file used to open with
# "Import-Module Hyper-V -ErrorAction Stop", which meant the dashboard would not start at all on
# a host without Hyper-V, before it could say why. Loading the backend is a call now, and a
# failure to load it is a check that fails rather than a stack trace.
. (Join-Path $PSScriptRoot '..\setup\LabPreflight.ps1')

$LabConfig  = Get-LabConfig
$LabProfile = $LabConfig.profile
$LabNetwork = $LabConfig.network
$LabBudget  = Get-LabBudget

# The VMs this profile builds, manager first. The lean profile has no Windows endpoint, and its
# absence is correct rather than a VM that has gone missing.
$LabVms = Get-LabVms

# Reported by the preflight rather than thrown, so a host with no usable hypervisor still gets a
# page that explains itself.
$LabBackendReady = $false
try { Import-LabBackend | Out-Null; $LabBackendReady = $true } catch { }

# Service health and recent alerts come over SSH using the lab key. Note what is NOT here: the
# Windows endpoint is never contacted. Its agent's connection state is reported by the manager,
# which knows whether each agent is checking in, so this tool never needs Windows guest
# credentials and never opens a port on that machine.
$LabSshKey = Join-Path (Get-LabPath Secrets) 'lab_ed25519'
$LabSshUser = $LabConfig.guest.user
$LabSshNull = Get-LabNullDevice
$ManagerAddress = $LabVms['WAZUH-MANAGER'].Address

# Everything the profile builds that is not the manager. Written down once because four places
# had @('WAZUH-WIN', 'WAZUH-LINUX') spelled out, and on the lean profile, which has no Windows
# endpoint, every one of them would have waited for a VM that was never going to appear.
$LabEndpoints = @($LabVms.Keys | Where-Object { $_ -ne 'WAZUH-MANAGER' })

# Units the Advanced panel may control, and the only ones the sudoers rule permits. Anything not
# named here cannot be touched from this dashboard.
$ManagerUnits = @('wazuh-manager', 'wazuh-indexer', 'wazuh-dashboard', 'filebeat')
$EndpointUnits = @('wazuh-agent')

$ProbeIntervalSeconds = 15
$HealthIntervalSeconds = 10
$script:HealthCache = $null
$script:HealthStamp = [datetime]::MinValue
$script:ProbeCache = @{}
$script:ProbeStamp = [datetime]::MinValue
$script:Notices = New-Object System.Collections.ArrayList
$script:HasJobs = $false

# Bringing the lab up takes minutes, and this listener is single threaded, so it cannot be a
# loop: a blocking wait would freeze the page for the whole boot. It is a state machine instead,
# advanced one step per poll by Update-LabSequence, using the 3 second cycle the page is already
# running as its clock.
#
# Order matters in both directions. The agents need a manager to connect to, so it starts first.
# Coming down, the manager stops last, so the endpoints are not left talking to nothing and the
# indexer is the final thing to close.
#
# Each phase performs its action once on entry, then is polled until its test passes or its
# deadline expires. A deadline that expires says which phase it was in, rather than hanging.
$LabUpPhases = @(
    [ordered]@{ name = 'manager';          label = 'Starting the manager';                        timeout = 90 }
    [ordered]@{ name = 'manager-ssh';      label = 'Waiting for the manager to finish booting';   timeout = 300 }
    [ordered]@{ name = 'manager-services'; label = 'Waiting for the Wazuh services to come up';   timeout = 300 }
    [ordered]@{ name = 'endpoints';        label = 'Starting both endpoints';                     timeout = 180 }
    [ordered]@{ name = 'agents';           label = 'Waiting for both agents to check in';         timeout = 420 }
)
$LabDownPhases = @(
    [ordered]@{ name = 'endpoints-off'; label = 'Shutting down both endpoints'; timeout = 300 }
    [ordered]@{ name = 'manager-off';   label = 'Shutting down the manager';    timeout = 300 }
)
$script:Sequence = $null
$script:LastSequencePoll = [datetime]::MinValue

# Everything the dashboard knows about the inside of the lab comes from this one script, sent to
# the manager and run there. It is sent rather than installed, for two reasons.
#
# It means the dashboard works the moment SSH does, with no setup step. What it cannot read it
# reports as unavailable rather than leaving a panel mysteriously blank, so the one-time setup
# becomes an upgrade rather than a prerequisite.
#
# It also means changing what the dashboard reports is a change to this file alone. An installed
# copy would have to be pushed out again every time, and would silently go stale if it were not.
#
# It is delivered base64 encoded. Passing shell inline through PowerShell to ssh mangles quoting,
# which has already cost this project a corrupted file on the manager; base64 has no character
# that any shell treats specially.
$RemoteStatusScript = @'
import base64, calendar, datetime, json, math, os, subprocess

def run(cmd, timeout=8, data=None):
    """A command and its output. data goes in on stdin, which is how the baseline is handed
    over: it is a few kilobytes of JSON and an argument list is the wrong place for it."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=data)
        return r.returncode, (r.stdout or '')
    except Exception:
        return 1, ''

out = {'services': [], 'agents': [], 'alerts': [], 'coverage': {}, 'attack': [],
       'rate': [], 'log': [], 'window': None, 'disk': None, 'indexer': None,
       'scoring': None, 'alertSource': None, 'missing': []}

# The deployed model, and the code that evaluates it. Both are substituted in before this
# script is encoded; see the note beside $ScorerPath. Absent, the two markers stay as they
# are and the scoring block below finds no model and reports that rather than failing.
SCORER_MODEL_B64 = '__SCORER_MODEL_B64__'
# __SCORER_MODULE__

for unit in ('wazuh-manager', 'wazuh-indexer', 'wazuh-dashboard', 'filebeat'):
    rc, text = run(['systemctl', 'is-active', unit], 5)
    out['services'].append({'unit': unit, 'state': text.strip() or 'unknown'})

# agent_control needs root. Without the sudoers rule this is refused, which is a missing
# capability rather than an error: say so instead of reporting zero agents, which would look
# like both endpoints had dropped off.
rc, text = run(['sudo', '-n', '/var/ossec/bin/agent_control', '-l'], 10)
if rc != 0:
    out['missing'].append('agents')
else:
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith('ID:'):
            continue
        parts = [p.strip() for p in line.split(',')]
        info = {}
        for p in parts:
            if ':' in p:
                k, v = p.split(':', 1)
                info[k.strip().lower()] = v.strip()
        # The connection state is the trailing field and carries no label of its own.
        status = parts[-1] if parts and ':' not in parts[-1] else 'unknown'
        out['agents'].append({'id': info.get('id', ''), 'name': info.get('name', ''),
                              'status': status})

# Cluster health, alert volume and retention. Installed by Enable-LabDashboard.ps1 because it
# needs the indexer's admin certificate, which is root owned and stays on the manager.
rc, text = run(['sudo', '-n', '/usr/local/bin/lab-dashboard-indexer'], 14)
if rc != 0:
    out['missing'].append('indexer')
else:
    try:
        out['indexer'] = json.loads(text)
    except Exception:
        out['missing'].append('indexer')

# The alerts. From the indexer where it will answer, from the tail of alerts.json where it
# will not.
#
# The tail is the fallback now rather than the path. It read the last 400 KB and the newest
# 800 lines, so a busy window quietly lost its oldest records and was still scored as though
# it were complete, and every hour older than the tail was drawn on the rate chart as quieter
# than it had been. The indexer is asked for an explicit range instead, and it counts with
# aggregations that see every matching document rather than only the ones fetched.
#
# Keeping the tail costs a dozen lines and buys two things worth more: a lab whose indexer is
# down still shows its alerts, and a manager that has not had Enable-LabDashboard.ps1 re-run
# against it still works rather than showing an empty panel and no reason for it.
#
# Eighteen windows at the shipped five minute width. Twelve are displayed and scored; anything
# behind them is what the baseline is folded from, so no window on the page has ever been folded
# into the baseline it is being scored against.
#
# That arithmetic assumed every window in the span holds an alert. On a quiet lab almost none of
# them do: ninety minutes here produced seven populated windows, not eighteen, so the twelve on
# the page were all of them, the fold set was empty on every cycle, and the baseline sat at zero
# windows for as long as the dashboard ran. Nothing reported a fault, because nothing was at
# fault; the rule was simply unreachable below a certain alert rate, which is the rate this lab
# runs at.
#
# Six hours rather than ninety minutes, and the page still shows the last twelve windows, so
# nothing about what is displayed changes. What changes is that there are windows behind the
# twelve for the baseline to fold. Measured on this lab: ninety minutes holds 221 alerts in 8
# populated windows, six hours holds 238 in 21. Seventeen more alerts buys thirteen more windows,
# because the alerts are clustered and the empty stretches between them cost nothing to ask for.
ALERT_SPAN_MINUTES = 360
# A day, for the one fetch that fills an empty baseline rather than growing one. Only issued when
# an endpoint has no baseline at all, which is the only case where it can help: the helper folds
# a window only when it is newer than the newest already folded, so a second pass over the same
# history is rejected window by window and returns nothing. Not a throttle on a useful query, a
# statement of when the query is useful.
WARM_SPAN_MINUTES = 1440
alerts_path = '/var/ossec/logs/alerts/alerts.json'
records = []
indexed = None
rc, text = run(['sudo', '-n', '/usr/local/bin/lab-dashboard-indexer', 'alerts',
                str(ALERT_SPAN_MINUTES)], 20)
if rc == 0:
    try:
        parsed = json.loads(text)
        # The key has to be checked, not just the exit code. A manager still carrying the
        # older helper ignores the subcommand entirely and prints its cluster summary, which
        # is valid JSON and exit 0 and has nothing to do with the question asked. Trusting the
        # exit code alone would read that as a successful search that found no alerts, and the
        # panel would go blank on every lab that has not had Enable-LabDashboard.ps1 re-run
        # against it, which is the one case the fallback exists for.
        if isinstance(parsed, dict) and 'records' in parsed:
            indexed = parsed
            records = indexed.get('records') or []
    except Exception:
        indexed = None

if indexed is not None:
    out['alertSource'] = {'from': 'indexer', 'spanMinutes': ALERT_SPAN_MINUTES,
                          'total': indexed.get('total'), 'returned': indexed.get('returned'),
                          'truncated': bool(indexed.get('truncated'))}
elif not os.access(alerts_path, os.R_OK):
    out['missing'].append('alerts')
else:
    try:
        with open(alerts_path, 'rb') as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 400000))
            lines = fh.read().decode('utf-8', 'replace').splitlines()
        for line in lines[-800:]:
            try:
                records.append(json.loads(line))
            except Exception:
                continue
        # Say that this read has a ceiling and whether it hit one. A window at the old end of
        # a truncated sample is missing records that nothing else on the page can show are
        # missing, and that is exactly the failure this reports rather than hides.
        out['alertSource'] = {'from': 'log-tail', 'returned': len(records),
                              'truncated': bool(len(lines) > 800 or size > 400000)}
    except Exception:
        out['missing'].append('alerts')

def shaped(a):
    rule = a.get('rule', {}) or {}
    mitre = rule.get('mitre', {}) or {}
    return {
        'time':  (a.get('timestamp') or '')[11:19],
        'agent': (a.get('agent', {}) or {}).get('name', ''),
        'id':    str(rule.get('id', '')),
        'level': rule.get('level', ''),
        'desc':  (rule.get('description') or '')[:110],
        'tech':  ', '.join(mitre.get('technique', []) or []),
    }

# Always the newest 50, newest first. The page decides how many of them to show, so changing
# that figure is a slice rather than another round trip.
out['alerts'] = [shaped(a) for a in records[-50:]][::-1]

if records:
    first = (records[0].get('timestamp') or '')
    out['window'] = {'from': first[11:16], 'fromDate': first[:10], 'count': len(records)}

# Per rule, how many times it fired and when it last did. The dashboard crosses this with the
# rule file on the host, which is what makes a rule that exists and has never fired visible.
#
# From the indexer's aggregations where there are any, because a terms aggregation counts every
# matching document over twelve hours rather than only the ones this poll happened to fetch.
# Counted out of the fetch, a rule that fired forty times two hours ago reads as a rule that
# fired twice, which is a different fact about the lab.
if indexed is not None and 'coverage' in indexed:
    for rid, entry in (indexed.get('coverage') or {}).items():
        stamp = entry.get('timestamp') or ''
        out['coverage'][str(rid)] = {'count': entry.get('count', 0), 'last': stamp[11:19],
                                     'lastDate': stamp[:10], 'level': entry.get('level', '')}
    out['attack'] = list(indexed.get('attack') or [])
else:
    for a in records:
        rule = a.get('rule', {}) or {}
        rid = str(rule.get('id', ''))
        if not rid:
            continue
        stamp = (a.get('timestamp') or '')
        entry = out['coverage'].setdefault(rid, {'count': 0, 'last': '', 'lastDate': '', 'level': rule.get('level', '')})
        entry['count'] += 1
        if stamp[11:19] and stamp > (entry['lastDate'] + 'T' + entry['last']):
            entry['last'] = stamp[11:19]
            entry['lastDate'] = stamp[:10]

    tally = {}
    for a in records:
        for tech in ((a.get('rule', {}) or {}).get('mitre', {}) or {}).get('technique', []) or []:
            tally[tech] = tally.get(tech, 0) + 1
    out['attack'] = [{'tech': k, 'count': v}
                     for k, v in sorted(tally.items(), key=lambda kv: -kv[1])]

# Sequence scoring. The rules above judge one event at a time; this judges a run of them.
#
# It runs here, inside the poll that was already happening, because the model that won is
# logistic regression over eleven numbers and the whole of inference is a dot product and one
# exponential. There is no second service, no open port, nothing installed on the manager and
# no extra round trip. Shipping PyTorch to a box whose job is receiving alerts, to evaluate
# 5,458 parameters that lost on all eight folds, would have been the wrong trade twice over.


def _epoch(ts):
    """2026-09-21T03:15:42.123+0000 to seconds.

    The offset is parsed off rather than applied. Every record here comes from one manager and
    carries the same offset, so it cancels out of every gap and duration the model looks at,
    and dropping it avoids depending on a %z that older builds of strptime get wrong.
    """
    try:
        base = datetime.datetime.strptime(ts[:19], '%Y-%m-%dT%H:%M:%S')
        frac = float('0' + ts[19:23]) if len(ts) > 19 and ts[19] == '.' else 0.0
        return calendar.timegm(base.timetuple()) + frac
    except Exception:
        return None


try:
    _model = json.loads(base64.b64decode(SCORER_MODEL_B64).decode('utf-8'))
    if _model.get('columns') != COLUMNS:
        _model = None
except Exception:
    _model = None

# A panel that says why it is empty is worth more than one that is simply empty, and the
# two reasons are different problems: no model means the modelling step was never run on
# the host launching this, no alerts means the lab is quiet.
if _model is None:
    out['scoring'] = {'note': 'no-model'}
elif not records:
    out['scoring'] = {'note': 'no-alerts'}
else:
    width = float(_model.get('windowSeconds') or 300.0)
    # Anchored on the clock rather than on the first alert, so a window boundary is a round
    # five minutes and two polls a second apart describe the same window rather than sliding.
    def _bucket(rows):
        """Alerts grouped into epoch aligned windows.

        Called twice: once for the page, once for the longer span the baseline warms from.
        One function rather than two loops, because a warm window bucketed even slightly
        differently from a live one is a baseline for something other than what is scored.
        """
        grouped = {}
        for a in rows:
            t = _epoch(a.get('timestamp') or '')
            if t is None:
                continue
            rule = a.get('rule', {}) or {}
            try:
                rid = int(rule.get('id'))
            except (TypeError, ValueError):
                continue
            lo = width * math.floor(t / width)
            mitre = rule.get('mitre', {}) or {}
            grouped.setdefault(lo, []).append({
                'at': t - lo, 'ruleId': rid, 'level': int(rule.get('level') or 0),
                # Which endpoint produced it. Dropped here until now, which meant credential
                # access on one machine and a new account on another earned the same chain
                # multiplier as both happening on one machine, and meant there was nothing for
                # a per endpoint baseline to be a baseline of.
                'agent': (a.get('agent') or {}).get('name') or '',
                'desc': (rule.get('description') or '')[:70],
                'tactics': mitre.get('tactic') or [],
                'techniques': mitre.get('id') or mitre.get('technique') or []})
        return grouped

    buckets = _bucket(records)

    # Which window is still filling. Taken from the newest record rather than from the
    # clock, because the manager's idea of now and the timestamps on its own alerts have
    # to agree for this to mean anything, and the alerts are the authority.
    last = _epoch(records[-1].get('timestamp') or '')
    current = width * math.floor(last / width) if last is not None else None

    ordered = sorted(buckets)
    shown = ordered[-12:]
    # Completed and already off the bottom of the page. These are what the baseline is folded
    # from. Holding a window back until it has scrolled off is what keeps anything on the page
    # from being scored against a baseline it is itself part of, and it is also why the score
    # beside a window does not shift under the reader between one poll and the next.
    foldable = [lo for lo in ordered[:-12] if lo != current]

    def _by_agent(al):
        groups = {}
        for one in al:
            groups.setdefault(one.get('agent') or '', []).append(one)
        return groups

    def _observation(name, lo, share):
        """One endpoint's share of one completed window, in the shape the baseline folds.

        Computed here, from the same alerts the scoring reads, rather than recomputed on the
        far side. A baseline derived from a second implementation of these five numbers would
        be a baseline for something slightly other than the thing being scored, and that is
        the failure that looks like a working panel.
        """
        levels = [float(x.get('level') or 0) for x in share]
        times = sorted(float(x.get('at') or 0.0) for x in share)
        burst, right = 0, 0
        for left, t in enumerate(times):
            while right < len(times) and times[right] < t + 60.0:
                right += 1
            burst = max(burst, right - left)
        rules = {}
        for x in share:
            rules[str(x.get('ruleId'))] = rules.get(str(x.get('ruleId')), 0) + 1
        stamp = datetime.datetime.utcfromtimestamp(lo)
        return {
            'agent': name, 'epoch': lo,
            # The manager's own hour. _epoch strips the offset rather than applying it, so
            # these seconds are already local wall clock read as though they were UTC, and
            # utcfromtimestamp is what reads them back the same way.
            'hour': stamp.hour,
            'at': stamp.strftime('%Y-%m-%dT%H:%M:%S'),
            'count': len(share),
            'peak': max(levels) if levels else 0.0,
            'mass': sum(2.0 ** ((L - 7.0) / 2.0) for L in levels if L >= 7.0),
            'burst': burst,
            'distinct': len(set(x.get('ruleId') for x in share)),
            'prob': round(score(_model, features(share)), 4),
            'rules': rules,
        }

    observations = []
    for lo in foldable:
        for name, share in _by_agent(buckets[lo]).items():
            observations.append(_observation(name, lo, share))

    baseline_features = {}

    def _fold(obs):
        """Hand observations to the baseline and get back the baseline as it stood before
        them. An empty list reads without folding, which is how warmth is checked.

        None means the helper could not be run at all, False means it answered something that
        would not parse. The two are different faults and the panel names them differently.
        """
        rc_f, text_f = run(['sudo', '-n', '/usr/local/bin/lab-dashboard-baseline'], 20,
                           json.dumps({'observations': obs}))
        if rc_f != 0:
            return None
        try:
            result = json.loads(text_f) or {}
            baseline_features['preview'] = result.get('supportsPreview') is True
            return result.get('agents') or {}
        except Exception:
            return False

    # Read before folding anything. Whether an endpoint is still short of its warm-up is what
    # decides whether a day of history is worth asking the indexer for, and that cannot be known
    # from a call that has already folded this cycle's windows into the answer.
    warm_folded = 0
    opening = _fold([])
    if opening is None:
        baselines, baseline_note = {}, 'unavailable'
    elif opening is False:
        baselines, baseline_note = {}, 'unreadable'
    else:
        baseline_note = 'ok'
        # Only endpoints this lab is actually producing alerts for. A baseline for a machine
        # that has been off for a week is not worth a query. Read off the buckets rather than
        # off records: the raw rows carry agent as the indexer's object, and it is the bucketing
        # that flattens it to the name everything downstream keys by.
        live = set(x.get('agent') or '' for al in buckets.values() for x in al)
        short = [name for name in live if name
                 and int((opening.get(name) or {}).get('windows') or 0) == 0]
        if short:
            rc_w, text_w = run(['sudo', '-n', '/usr/local/bin/lab-dashboard-indexer',
                                'alerts', str(WARM_SPAN_MINUTES)], 45)
            warm_rows = []
            if rc_w == 0:
                try:
                    parsed_w = json.loads(text_w)
                    if isinstance(parsed_w, dict) and 'records' in parsed_w:
                        warm_rows = parsed_w.get('records') or []
                        # A fetch that reached the document ceiling kept the newest and dropped
                        # the oldest, so its earliest window is a fragment rather than a window.
                        # Folding a fragment teaches the baseline that the endpoint is quieter
                        # than it is, which is the direction that makes real activity look
                        # normal, so the fragment goes.
                        if parsed_w.get('truncated') and warm_rows:
                            stamps = [s for s in (_epoch(r.get('timestamp') or '')
                                                  for r in warm_rows) if s is not None]
                            if stamps:
                                edge = width * math.floor(min(stamps) / width) + width
                                warm_rows = [r for r in warm_rows
                                             if (_epoch(r.get('timestamp') or '') or 0) >= edge]
                except Exception:
                    warm_rows = []
            if warm_rows:
                on_page = set(shown)
                warm_obs = []
                warm_buckets = _bucket(warm_rows)
                for lo in sorted(warm_buckets):
                    # Never a window the page is about to score, and never the one still
                    # filling. The warm span overlaps the page span by ninety minutes, so
                    # without this the twelve on the page would be folded into the baseline
                    # they are scored against.
                    if lo in on_page or lo == current:
                        continue
                    for name, share in _by_agent(warm_buckets[lo]).items():
                        warm_obs.append(_observation(name, lo, share))
                if warm_obs:
                    _fold(warm_obs)

        # The page's own fold set, last, so the value scored against carries the warm history
        # and not this cycle's windows. The helper skips any window it has already seen, so an
        # observation the warm pass folded is not counted twice.
        settled = _fold(observations)
        if isinstance(settled, dict):
            baselines = settled
            # What the warm pass actually folded, which is the difference between the state
            # before it and the state after. Counting the observations handed over instead
            # would report work the helper rejected as work it did, and every window of a
            # repeat pass is rejected.
            def _total(state):
                return sum(int((v or {}).get('windows') or 0) for v in (state or {}).values())
            warm_folded = max(0, _total(settled) - _total(opening))
        else:
            baselines = opening

    preview_before = {}
    preview_latest = baselines
    if baseline_features.get('preview'):
        # One read-only preview produces each window's history before that window is added.
        # The persistent fold still excludes the displayed range, so repeated polls cannot
        # teach an earlier displayed window about its own activity or about later windows.
        preview_obs = [_observation(name, lo, share) for lo in shown if lo != current
                       for name, share in _by_agent(buckets[lo]).items()]
        rc_p, text_p = run(['sudo', '-n', '/usr/local/bin/lab-dashboard-baseline'], 20,
                          json.dumps({'preview': True, 'observations': preview_obs}))
        try:
            preview = json.loads(text_p) if rc_p == 0 else {}
            if preview.get('preview') is not True:
                raise ValueError('Preview unavailable')
            preview_before = preview['before']
            preview_latest = preview['agents']
        except (ValueError, KeyError, TypeError):
            baseline_note = 'preview-unavailable'

    wins = []
    for lo in shown:
        al = buckets[lo]
        p = score(_model, features(al))
        window_baseline = preview_before.get(str(int(lo)), preview_latest if lo == current else baselines)
        sev = severity_by_agent(al, p, _model['threshold'], window_baseline,
                                datetime.datetime.utcfromtimestamp(lo).hour, _model)
        wins.append({
            'severity': sev['score'],
            'band': sev['band'],
            'working': sev,
            # The endpoint the severity belongs to. A window is scored per endpoint and the
            # worst one is what the page leads with, so saying which one it was is the
            # difference between a number and a finding.
            'agent': sev.get('agent') or '',
            'at': datetime.datetime.utcfromtimestamp(lo).strftime('%H:%M'),
            'epoch': lo,
            'score': round(p, 4),
            'alerts': len(al),
            'over': bool(p >= _model['threshold']),
            # The newest window is still filling. Its alert count and duration are therefore
            # low for a reason that has nothing to do with what is happening, so its score is
            # not comparable with the completed ones and the page says so rather than drawing
            # a dip that looks like the attack stopping.
            'partial': bool(lo == current),
        })

    done = [w for w in wins if not w['partial']]
    # Ranked by severity rather than by the model, because severity is what the panel
    # leads with and the model is one of six terms inside it.
    top = max(done or wins, key=lambda w: w['severity']) if wins else None

    def rules_in(epoch):
        seen = {}
        for al in buckets[epoch]:
            e = seen.setdefault(al['ruleId'],
                                {'id': al['ruleId'], 'count': 0, 'level': al['level'],
                                 'desc': al['desc'],
                                 'tech': ', '.join(al.get('techniques') or [])})
            e['count'] += 1
        return sorted(seen.values(), key=lambda e: (-e['level'], -e['count'], e['id']))

    detail = rules_in(top['epoch'])[:8] if top is not None else []

    # A finding is a completed window that reached elevated or above. Completed, because a
    # window still filling has not had its chance to be worse, and reporting it as a finding
    # would mean the list changed under the reader every three seconds.
    findings = []
    for w in done:
        if w['severity'] < 50:
            continue
        f = dict(w)
        f['rules'] = rules_in(w['epoch'])[:12]
        findings.append(f)
    findings.sort(key=lambda f: -f['severity'])

    span = sorted(buckets)
    out['scoring'] = {
        'windowSeconds': width,
        'threshold': _model['threshold'],
        'windows': wins,
        'top': top,
        'topRules': detail,
        'findings': findings,
        # The constants, sent rather than duplicated in the page, so the explainer shows
        # the weights the score was actually built with and cannot drift from them.
        'severityWeights': [{'key': k, 'weight': w, 'label': l}
                            for k, w, l in SEVERITY_WEIGHTS],
        'chainBonus': CHAIN_BONUS,
        'bands': [{'floor': f, 'name': nm} for f, nm in BANDS],
        # The same argument, extended to the denominators. The explainer could print what each
        # component was divided by only if it knew the divisors, and it could not, so it
        # printed the weights and left the halves of the fraction that actually moved per
        # endpoint out of the account entirely.
        'adaptive': {
            'warmupWindows': WARMUP_WINDOWS,
            'fixed': FIXED_DENOMINATORS,
            'bounds': dict((k, list(v)) for k, v in DENOMINATOR_BOUNDS.items()),
            'noveltyBonus': NOVELTY_BONUS,
            'routineDiscount': ROUTINE_DISCOUNT,
            'noveltySeen': NOVELTY_SEEN,
            'routineSeen': ROUTINE_SEEN,
        },
        # Where the alerts came from and whether all of them arrived. A truncated read used to
        # be indistinguishable from a quiet hour.
        'source': out.get('alertSource'),
        'baseline': {
            'note': baseline_note,
            'folded': len(observations),
            # How many windows the warm pass folded, which is zero on every cycle after the
            # baseline reaches its warm-up. A panel that reports this is a panel where "still
            # warming" can be told apart from "warming and getting nowhere".
            'warmed': warm_folded,
            'need': WARMUP_WINDOWS,
            'windows': dict((k, int((v or {}).get('windows') or 0))
                            for k, v in preview_latest.items()),
        },
        'covers': {'from': datetime.datetime.utcfromtimestamp(span[0]).strftime('%H:%M'),
                   'windows': len(span)},
        'model': {
            'ap': _model.get('measured', {}).get('averagePrecision'),
            'baseRate': _model.get('measured', {}).get('baseRate'),
            'protocol': _model.get('measured', {}).get('protocol'),
            'dataset': _model.get('trainedOn', {}).get('dataset'),
            'episodes': _model.get('trainedOn', {}).get('episodes'),
            'caveat': _model.get('caveat'),
            'generated': _model.get('generated'),
            # What the baseline layer itself was measured at, or nothing if it never was.
            # The explainer says which, because a page that shows adaptive denominators and
            # no measurement beside them invites the reader to assume one.
            'adaptive': _model.get('adaptiveLayer'),
        },
    }

now = datetime.datetime.now()
keys = [(now - datetime.timedelta(hours=i)).strftime('%Y-%m-%dT%H') for i in range(11, -1, -1)]
counts = dict((k, 0) for k in keys)
if indexed is not None and 'hourly' in indexed:
    # Epoch seconds out of the date histogram, placed in this manager's own hours. The
    # aggregation could have been asked to bucket by time zone instead, and then the chart
    # would depend on the indexer and the manager agreeing about what that offset is.
    for bucket in indexed.get('hourly') or []:
        k = datetime.datetime.fromtimestamp(bucket.get('at') or 0).strftime('%Y-%m-%dT%H')
        if k in counts:
            counts[k] += int(bucket.get('count') or 0)
else:
    for a in records:
        k = (a.get('timestamp') or '')[:13]
        if k in counts:
            counts[k] += 1
out['rate'] = [{'hour': k[11:13], 'count': counts[k]} for k in keys]

log_path = '/var/ossec/logs/ossec.log'
if not os.access(log_path, os.R_OK):
    out['missing'].append('log')
else:
    try:
        with open(log_path, 'rb') as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 60000))
            out['log'] = [l[:200] for l in fh.read().decode('utf-8', 'replace').splitlines()[-40:]][::-1]
    except Exception:
        out['missing'].append('log')

try:
    st = os.statvfs('/')
    disk = {'freeGb': round(st.f_bavail * st.f_frsize / 1073741824.0, 1),
            'totalGb': round(st.f_blocks * st.f_frsize / 1073741824.0, 1)}
    rc, text = run(['du', '-sm', '/var/ossec/logs'], 6)
    disk['logsMb'] = int(text.split()[0]) if rc == 0 and text.split() else None
    out['disk'] = disk
except Exception:
    pass

print(json.dumps(out))
'@
# The scorer is two files from the modelling step, substituted into the script above rather
# than duplicated here. score.py is the feature code and model.json is the fitted model with
# the measurement that produced it, and keeping them where they were generated is what stops
# the dashboard scoring with weights nobody can trace.
#
# Both travel inside the same base64 payload as everything else, so nothing is installed on
# the manager and there is no second thing to keep in step. The model is encoded separately
# on the way in because it is the one part that is not Python source and does not need to be
# read by anything between here and there.
#
# Missing either file is not an error. The markers stay unsubstituted, the remote script finds
# no model, and the panel says the model file is absent. A lab that has never run the
# modelling step still gets a working dashboard.
$script:ScorerPath = Get-LabPath Scorer
$script:ScorerLoaded = $false
try {
    $modelPath = Join-Path $script:ScorerPath 'model.json'
    $codePath = Join-Path $script:ScorerPath 'score.py'
    if ((Test-Path -LiteralPath $modelPath) -and (Test-Path -LiteralPath $codePath)) {
        $modelText = (Get-Content -LiteralPath $modelPath -Raw)
        $codeText = (Get-Content -LiteralPath $codePath -Raw) -replace "`r`n", "`n"
        # Only the three names the remote script calls. Importing the module is not an option
        # when there is no file on the far side to import.
        $RemoteStatusScript = $RemoteStatusScript -replace '# __SCORER_MODULE__', $codeText
        $RemoteStatusScript = $RemoteStatusScript -replace '__SCORER_MODEL_B64__',
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($modelText))
        $script:ScorerLoaded = $true
    }
} catch {
    # A damaged model file costs the one panel, not the dashboard.
    $script:ScorerLoaded = $false
}

$script:StatusB64 = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes(($RemoteStatusScript -replace "`r`n", "`n")))

# The rule file is the source of truth for which detections are supposed to exist. The manager
# only knows which ones have actually fired. Crossing the two is the whole point of the coverage
# panel: a rule that exists and has never fired is invisible in any view built from alerts alone,
# and it is exactly the state worth noticing.
#
# Read once at startup. Editing rules means deploying them to the manager and restarting it, so
# re-reading this file on every poll would be watching for something that cannot change underneath.
$script:LabRules = @()
try {
    $rulePath = Join-Path $PSScriptRoot '..\manager\lab_rules.xml'
    if (Test-Path -LiteralPath $rulePath) {
        [xml]$ruleDoc = Get-Content -LiteralPath $rulePath -Raw
        foreach ($rule in $ruleDoc.SelectNodes('//rule')) {
            # Descriptions carry field placeholders like $(win.eventdata.targetUserName), which
            # read badly in a table. Keep the field name, drop the plumbing around it.
            $desc = [regex]::Replace([string]$rule.description, '\$\(([^)]*)\)', {
                param($m) '<' + (($m.Groups[1].Value -split '\.')[-1]) + '>'
            })
            $script:LabRules += [ordered]@{
                id          = [string]$rule.id
                level       = [int]$rule.level
                description = $desc.Trim()
                technique   = [string]$rule.mitre.id
                frequency   = [string]$rule.frequency
                timeframe   = [string]$rule.timeframe
            }
        }
    }
} catch {
    # A malformed rule file is worth knowing about, but not worth refusing to start over.
    $script:LabRules = @()
}

# Host metrics come from performance counters, not WMI. Win32_Processor's LoadPercentage takes
# around a second to answer and Win32_OperatingSystem around 150 ms, which together would be most
# of the cost of every poll. The counters answer in about a millisecond once primed.
$script:CpuCounter = $null
$script:MemCounter = $null
try {
    $script:CpuCounter = New-Object System.Diagnostics.PerformanceCounter('Processor', '% Processor Time', '_Total')
    $script:MemCounter = New-Object System.Diagnostics.PerformanceCounter('Memory', 'Available MBytes')
    $null = $script:CpuCounter.NextValue()
    $null = $script:MemCounter.NextValue()
} catch {
    $script:CpuCounter = $null
    $script:MemCounter = $null
}
# Total physical memory never changes while the machine is up, so read it once.
$script:TotalMemoryGb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)

# Test-TcpPort is in setup\LabPreflight.ps1, which this file dot-sources. The health polling
# here and the package-source check there want the same non-blocking connect.

function Invoke-LabSsh {
    <#
    Runs one command on a lab VM and returns its output, or $null on any failure.

    Start-Process with a hard timeout rather than the call operator, because the listener is
    single threaded: an ssh that hangs would freeze the whole dashboard, not just this panel.
    ConnectTimeout only covers the connect phase, so the wait is the real guard.

    -StdinText feeds the far side on standard input instead of putting the payload in argv.
    CreateProcess caps a command line at 32767 characters, and it counts the whole line, not
    the one argument. Get-LabHealth ships a base64 script that passed that cap the moment the
    scorer was folded into it, and the failure is silent: Start-Process throws, the catch below
    returns $null, and the caller reports it as the manager not answering. Anything whose size
    is not fixed goes down this path. Start-Process redirects stdin from a file rather than a
    stream, which also keeps the no-deadlock property the out and err redirections have.
    #>
    param([string]$Address, [string]$Command, [int]$TimeoutSeconds = 8, [int]$ConnectSeconds = 8,
          [string]$StdinText)
    if (-not (Test-Path -LiteralPath $LabSshKey)) { return $null }
    $outFile = [IO.Path]::GetTempFileName()
    $errFile = [IO.Path]::GetTempFileName()
    $inFile = $null
    try {
        $sshArgs = @(
            '-i', ('"{0}"' -f $LabSshKey)
            '-o', 'BatchMode=yes'
            '-o', 'StrictHostKeyChecking=no'
            '-o', ('UserKnownHostsFile={0}' -f $LabSshNull)
            '-o', ('ConnectTimeout={0}' -f $ConnectSeconds)
            ('{0}@{1}' -f $LabSshUser, $Address)
            ('"{0}"' -f $Command)
        )
        $startArgs = @{
            FilePath               = 'ssh.exe'
            ArgumentList           = $sshArgs
            NoNewWindow            = $true
            PassThru               = $true
            RedirectStandardOutput = $outFile
            RedirectStandardError  = $errFile
        }
        if ($PSBoundParameters.ContainsKey('StdinText')) {
            # No BOM and no trailing CR: the far side pipes this straight into base64 -d.
            $inFile = [IO.Path]::GetTempFileName()
            [IO.File]::WriteAllText($inFile, ($StdinText + "`n"),
                (New-Object Text.UTF8Encoding($false)))
            $startArgs.RedirectStandardInput = $inFile
        }
        $proc = Start-Process @startArgs
        # Reading Handle here is not pointless. Start-Process -PassThru hands back a Process
        # object that has not cached the process handle, and once the process exits there is
        # nothing left to read an exit code from: ExitCode comes back empty rather than 0.
        # "$null -ne 0" is true, so every successful call was being thrown away as a failure.
        # Touching Handle while the process is alive makes .NET keep it, and a genuine non-zero
        # exit is still reported correctly.
        $null = $proc.Handle
        if (-not $proc.WaitForExit(($TimeoutSeconds * 1000) + 2000)) {
            try { $proc.Kill() } catch { }
            return $null
        }
        if ($proc.ExitCode -ne 0) { return $null }
        return (Get-Content -LiteralPath $outFile -Raw)
    } catch {
        return $null
    } finally {
        $temps = @($outFile, $errFile)
        if ($inFile) { $temps += $inFile }
        Remove-Item -LiteralPath $temps -Force -ErrorAction SilentlyContinue
    }
}

function Get-LabHealth {
    <#
    One SSH round trip to the manager returns everything the dashboard knows about the inside of
    the lab: service state, agent connection state, recent alerts, per rule coverage, ATT&CK
    tally, alert rate, manager log tail and disk. One call rather than several, on its own slower
    cycle, because shelling out to ssh costs far more than anything else this dashboard does.

    The script is sent rather than installed. See the note beside $RemoteStatusScript.
    #>
    param([bool]$ManagerRunning)
    if (-not $ManagerRunning) {
        $script:HealthCache = $null
        return $null
    }
    if ($script:HealthCache -and ([datetime]::UtcNow - $script:HealthStamp).TotalSeconds -lt $HealthIntervalSeconds) {
        return $script:HealthCache
    }
    # The script arrives on stdin, not in argv. See the -StdinText note on Invoke-LabSsh: at
    # 34,644 base64 characters this payload is past what a Windows command line can carry.
    $raw = Invoke-LabSsh -Address $ManagerAddress -Command 'base64 -d | python3 -' `
        -StdinText $script:StatusB64 -TimeoutSeconds 20 -ConnectSeconds 6
    $script:HealthStamp = [datetime]::UtcNow
    if (-not $raw) {
        $script:HealthCache = [ordered]@{
            reachable = $false
            note      = 'No answer over SSH. The manager may still be booting, or the lab key is not accepted.'
        }
        return $script:HealthCache
    }
    try {
        $parsed = $raw | ConvertFrom-Json
        # "missing" names what the manager could not read, rather than leaving a panel blank and
        # letting an unreadable file look like an empty one.
        $missing = @($parsed.missing)
        $script:HealthCache = [ordered]@{
            reachable = $true
            services  = $parsed.services
            agents    = $parsed.agents
            alerts    = $parsed.alerts
            coverage  = $parsed.coverage
            attack    = $parsed.attack
            rate      = $parsed.rate
            log       = $parsed.log
            window    = $parsed.window
            disk      = $parsed.disk
            indexer   = $parsed.indexer
            scoring   = $parsed.scoring
            missing   = $missing
            setupDone = ($missing.Count -eq 0)
        }
    } catch {
        $script:HealthCache = [ordered]@{ reachable = $false; note = 'The manager returned something unreadable.' }
    }
    return $script:HealthCache
}

function Invoke-ServiceAction {
    <# Only the units named above, and only on a VM that declares them. #>
    param([string]$VmName, [string]$Unit, [string]$Action)
    if ($Action -notin @('start', 'stop', 'restart')) { throw "Unknown service action: $Action" }
    if (-not $LabVms.Contains($VmName)) { throw "Unknown VM: $VmName" }
    $allowed = if ($VmName -eq 'WAZUH-MANAGER') { $ManagerUnits } else { $EndpointUnits }
    if ($Unit -notin $allowed) { throw "This dashboard will not control $Unit on $VmName." }
    $address = $LabVms[$VmName].Address

    if ($VmName -eq 'WAZUH-WIN') {
        # Same transport, different service manager. The agent is a Windows service called
        # WazuhSvc, and $EndpointUnits names it wazuh-agent because that is what it is called
        # everywhere else in this lab, including in the page.
        $verb = @{ start = 'Start-Service'; stop = 'Stop-Service'; restart = 'Restart-Service' }[$Action]
        $command = '{0} -Name WazuhSvc; (Get-Service -Name WazuhSvc).Status' -f $verb
    } else {
        $command = 'sudo -n systemctl {0} {1} && systemctl is-active {1}' -f $Action, $Unit
    }

    $result = Invoke-LabSsh -Address $address -Command $command
    if (-not $result) { throw "Could not $Action $Unit on $VmName. Check that the one-time setup has been run." }
    return ('{0} on {1} is now {2}.' -f $Unit, $VmName, $result.Trim())
}

function Invoke-LabScenario {
    <#
    Runs one of the three scenarios on an endpoint and lets the alert show up in the coverage
    panel a few seconds later.

    As a job, always. S1 makes six logon attempts with pauses between them, so it runs for well
    over a minute, and the listener is single threaded.

    Both endpoints go over SSH. Linux reaches a wrapper the sudoers rule names by exact
    arguments; Windows gets the driver copied across and run, then deleted.

    Windows used to go over PowerShell Direct with the console password out of .lab-secrets.
    PowerShell Direct is a Hyper-V feature with no VirtualBox equivalent, so that path could
    only ever have worked on one of the two backends. The endpoint's first logon installs
    OpenSSH Server and the lab's public key instead, which also means the console password is
    no longer read to run a scenario.
    #>
    param([string]$VmName, [string]$Scenario, [string]$Mode)
    if ($Scenario -notin @('S1', 'S2', 'S3')) { throw "Unknown scenario: $Scenario" }
    if ($Mode -notin @('test', 'comparison')) { throw "Unknown mode: $Mode" }
    if ($VmName -notin @('WAZUH-LINUX', 'WAZUH-WIN')) { throw "Scenarios run on the endpoints, not on $VmName." }
    $vm = Get-LabVmInfo -Name $VmName
    if (-not $vm -or $vm.State -ne 'Running') { throw "$VmName is not running." }

    $label = 'Scenario {0} {1} on {2}' -f $Scenario, $Mode, $VmName
    $script:HasJobs = $true

    if ($VmName -eq 'WAZUH-LINUX') {
        Start-Job -Name $label -ScriptBlock {
            param($Key, $User, $Address, $Scenario, $Mode, $NullDevice)
            # Without this a failure is a non-terminating error, the job still reports Completed,
            # and the page cheerfully says the scenario finished when nothing happened.
            $ErrorActionPreference = 'Stop'
            $sshArgs = @(
                '-i', $Key, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                '-o', ('UserKnownHostsFile={0}' -f $NullDevice), '-o', 'ConnectTimeout=8',
                ('{0}@{1}' -f $User, $Address),
                ('sudo -n /usr/local/bin/lab-scenario {0} {1}' -f $Scenario, $Mode)
            )
            $output = & ssh.exe @sshArgs 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw ('the endpoint refused it: {0}' -f (($output -join ' ').Trim()))
            }
            ($output | Select-Object -Last 1)
        } -ArgumentList $LabSshKey, $LabSshUser, $LabVms[$VmName].Address, $Scenario, $Mode, $LabSshNull | Out-Null
    } else {
        $scriptFile = Join-Path $PSScriptRoot '..\agents\windows\Invoke-Scenario.ps1'
        if (-not (Test-Path -LiteralPath $scriptFile)) { throw 'The Windows scenario driver is missing from the repository.' }
        $scriptFile = (Resolve-Path -LiteralPath $scriptFile).Path
        Start-Job -Name $label -ScriptBlock {
            param($Key, $User, $Address, $ScriptFile, $Scenario, $Comparison, $NullDevice)
            $ErrorActionPreference = 'Stop'
            $common = @(
                '-i', $Key, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                '-o', ('UserKnownHostsFile={0}' -f $NullDevice), '-o', 'ConnectTimeout=8',
                '-o', 'LogLevel=ERROR'
            )
            # Copied rather than pre-staged, so nothing has to be kept in sync on the guest.
            $copy = & scp.exe @common $ScriptFile ('{0}@{1}:C:/Windows/Temp/lab-scenario.ps1' -f $User, $Address) 2>&1
            if ($LASTEXITCODE -ne 0) { throw ('could not copy the driver across: {0}' -f (($copy -join ' ').Trim())) }

            # Run it through powershell.exe rather than dot-sourcing it. That is the only form
            # that still honours the driver's own "#requires -RunAsAdministrator", and the
            # bypass applies to this one invocation and changes nothing on the machine.
            $command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\lab-scenario.ps1 -Scenario ' + $Scenario
            if ($Comparison) { $command += ' -Comparison' }
            # The driver's exit code has to survive the cleanup, or a failed scenario reports
            # whatever Remove-Item thought of the temporary file.
            $command += '; $code = $LASTEXITCODE; Remove-Item C:\Windows\Temp\lab-scenario.ps1 -Force -ErrorAction SilentlyContinue; exit $code'

            $output = & ssh.exe @common ('{0}@{1}' -f $User, $Address) $command 2>&1
            if ($LASTEXITCODE -ne 0) { throw ('the endpoint refused it: {0}' -f (($output -join ' ').Trim())) }
            ($output | Select-Object -Last 1)
        } -ArgumentList $LabSshKey, $LabSshUser, $LabVms[$VmName].Address, $scriptFile, $Scenario, ($Mode -eq 'comparison'), $LabSshNull | Out-Null
    }

    $what = if ($Mode -eq 'comparison') { 'the benign comparison' } else { 'the attack case' }
    return ('Running {0}, {1}, on {2}. It takes a minute or two; the alert appears in coverage shortly after.' -f $Scenario, $what, $VmName)
}

function Format-Uptime {
    param($Span)
    if ($null -eq $Span -or $Span.TotalSeconds -lt 1) { return $null }
    if ($Span.TotalDays -ge 1)  { return ('{0}d {1}h' -f [int]$Span.TotalDays, $Span.Hours) }
    if ($Span.TotalHours -ge 1) { return ('{0}h {1}m' -f [int]$Span.TotalHours, $Span.Minutes) }
    return ('{0}m' -f [int]$Span.TotalMinutes)
}

function Get-JobNotices {
    <# Power actions run detached, so failures surface here rather than in the HTTP response. #>
    # Get-Job costs about 70 ms, so skip it entirely on the common path where nothing is running.
    if (-not $script:HasJobs) { return }
    foreach ($job in @(Get-Job | Where-Object { $_.State -eq 'Failed' })) {
        $reason = @($job.ChildJobs | ForEach-Object {
            if ($_.JobStateInfo.Reason) { $_.JobStateInfo.Reason.Message }
        }) -join '; '
        if (-not $reason) { $reason = 'The action failed.' }
        [void]$script:Notices.Add([ordered]@{
            at   = [datetime]::UtcNow.ToString('o')
            kind = 'error'
            text = ('{0}: {1}' -f $job.Name, $reason)
        })
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    foreach ($job in @(Get-Job | Where-Object { $_.State -eq 'Completed' })) {
        # A power action's result is visible on its card, so only a scenario has anything to say.
        # It reports what it did, which is the point of pressing the button.
        if ($job.Name -like 'Scenario*') {
            $said = (@(Receive-Job -Job $job -ErrorAction SilentlyContinue) -join ' ').Trim()
            # A scenario that finishes without saying anything did not run. Reporting that as a
            # success is how a silent failure gets mistaken for a working demonstration.
            [void]$script:Notices.Add([ordered]@{
                at   = [datetime]::UtcNow.ToString('o')
                kind = $(if ($said) { 'ok' } else { 'error' })
                text = $(if ($said) { '{0} finished. {1}' -f $job.Name, $said }
                         else { '{0} returned nothing, so it probably did not run. Check the endpoint.' -f $job.Name })
            })
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    if (@(Get-Job).Count -eq 0) { $script:HasJobs = $false }
    while ($script:Notices.Count -gt 8) { $script:Notices.RemoveAt(0) }
}

# ---------------------------------------------------------------------------------------------
# Preflight
#
# Every way this lab can be wrong on a given machine fails somewhere later than its cause. No
# elevation surfaces as three VMs that all report "Needs administrator". Virtualization switched
# off in firmware surfaces as a VM that refuses to start. A fresh clone with no .lab-secrets
# surfaces as an SSH timeout on a panel that says only that it cannot reach the manager.
#
# Checking before the page opens means it can name the cause rather than the symptom. Nothing
# here writes, starts or changes anything: it is all reads.

# The preflight, the check constructor and the CPU facts all live in setup\LabPreflight.ps1,
# dot-sourced at the top of this file. They were written here first, which is why they read as
# they do; they moved because every one of these checks is something you want answered before
# cloning the repository, not after building three VMs.

# ---------------------------------------------------------------------------------------------
# Credentials

function ConvertTo-LabPdf {
    <#
    Print an HTML string to a PDF with Edge, headless.

    scoring/report/Build-Report.ps1 does the same thing and they are deliberately
    not shared. That one is a build step run by hand in the modelling directory; this one is
    inside a server that has to keep working on a clone where the modelling step was never run.
    Putting the helper in either place would make the other depend on a directory it cannot
    assume exists, so twenty lines are written twice and this comment names the other copy.

    The page is staged in a temporary directory and the result moved afterwards. This
    repository's path contains a space, and PowerShell 5.1 passes --print-to-pdf=C:\...\cybersec
    intern\... to a native executable without quoting the value, so Edge reads two targets and
    refuses the whole run. Keeping spaces away from native arguments is the fix that works;
    quoting harder is the one that does not.
    #>
    param([Parameter(Mandatory)][string]$Html, [Parameter(Mandatory)][string]$OutFile)

    $edge = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $edge) { throw 'Could not find msedge.exe, so there is nothing here that makes a PDF.' }

    $work = Join-Path ([IO.Path]::GetTempPath()) ("lab-findings-" + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $work
    try {
        $page = Join-Path $work 'findings.html'
        [IO.File]::WriteAllText($page, $Html, (New-Object Text.UTF8Encoding $false))
        $staged = Join-Path $work 'findings.pdf'
        $p = Start-Process -FilePath $edge -WindowStyle Hidden -PassThru -Wait -ArgumentList @(
            '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
            '--disable-extensions', "--user-data-dir=$(Join-Path $work 'profile')",
            '--no-pdf-header-footer', "--print-to-pdf=$staged", ([Uri]$page).AbsoluteUri
        )
        if ($p.ExitCode -ne 0) { throw "Edge exited with $($p.ExitCode)." }
        if (-not (Test-Path -LiteralPath $staged)) { throw 'Edge wrote no file.' }
        $dir = Split-Path -Parent $OutFile
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir }
        Move-Item -LiteralPath $staged -Destination $OutFile -Force
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Export-LabFindings {
    <#
    Write the currently flagged windows to a PDF.

    Built from the last poll rather than by asking the manager again, so what lands in the file
    is exactly what the person was looking at when they pressed the button. Asking again would
    produce a document that disagrees with the screen it came from, which is the one property a
    findings export must not have.

    It goes under evidence/, which is gitignored in full apart from two named files. A finding
    carries account names, source addresses and rule descriptions from a live endpoint, and that
    is evidence rather than documentation.
    #>
    $h = $script:HealthCache
    if (-not $h -or -not $h.reachable) {
        return [ordered]@{ ok = $false; error = 'The manager is not answering, so there is nothing to export.' }
    }
    $sc = $h.scoring
    if (-not $sc -or -not $sc.findings -or @($sc.findings).Count -eq 0) {
        return [ordered]@{ ok = $false; error = 'No window has reached elevated, so there is nothing to export.' }
    }

    $findings = @($sc.findings)
    $stamp = Get-Date
    $name = 'findings-' + $stamp.ToString('yyyyMMdd-HHmmss') + '.pdf'
    $out = Join-Path (Get-LabPath Findings) $name
    $out = [IO.Path]::GetFullPath($out)

    $css = @'
@page { size: A4; margin: 16mm 15mm; }
body { font: 10pt/1.5 "Charter","Georgia","Cambria",serif; color: #17171a; margin: 0; }
h1 { font-size: 17pt; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 11.5pt; margin: 14px 0 6px; padding-bottom: 4px; border-bottom: 1.4px solid #24242a; }
h3 { font-size: 9.5pt; margin: 10px 0 4px; text-transform: uppercase; letter-spacing: .05em; color: #55555e; }
p { margin: 0 0 8px; }
.meta { color: #85858e; font-size: 8.5pt; margin: 0 0 10px; padding-bottom: 7px; border-bottom: 1px solid #d9d9d4; }
.sub { color: #55555e; font-size: 9.5pt; margin: 0 0 3px; }
table { border-collapse: collapse; width: 100%; margin: 7px 0 11px; font-size: 9pt; }
th { text-align: left; font-size: 7.5pt; text-transform: uppercase; letter-spacing: .05em; color: #55555e;
     border-bottom: 1.2px solid #24242a; padding: 0 7px 3px 0; font-weight: 650; }
td { padding: 3px 7px 3px 0; border-bottom: 1px solid #e4e4df; vertical-align: top; }
/* Not padding-right: 0. A right aligned number in the middle of a row butts straight into the
   next cell, which is how the rules table printed "10Linux: repeated incorrect SSH passwords".
   The last-child rule below still takes the trailing column flush to the margin. */
td.n, th.n { text-align: right; padding-right: 7px; padding-left: 11px;
            font-variant-numeric: tabular-nums; white-space: nowrap; }
th:last-child, td:last-child { padding-right: 0; text-align: right; }
.band { display: inline-block; font-size: 8pt; font-weight: 650; text-transform: uppercase;
        letter-spacing: .05em; padding: 1px 6px; border-radius: 999px; border: 1px solid #d9d9d4; }
.band.elevated { color: #854f0b; background: #faeeda; border-color: #e6cfa6; }
.band.high { color: #9d2b2b; background: #fcebeb; border-color: #eec4c4; }
.band.critical { color: #fff; background: #9d2b2b; border-color: #9d2b2b; }
.card { border: 1px solid #d9d9d4; border-radius: 5px; padding: 11px 13px; margin: 0 0 13px;
        break-inside: avoid; page-break-inside: avoid; }
.card .top { display: flex; align-items: baseline; gap: 11px; flex-wrap: wrap; margin-bottom: 3px; }
.card .score { font-size: 15pt; font-weight: 660; font-variant-numeric: tabular-nums; }
.card .when { font-weight: 640; font-variant-numeric: tabular-nums; }
.formula { display: block; background: #f3f3ef; border: 1px solid #e4e4df; border-radius: 4px;
           padding: 8px 10px; margin: 6px 0 9px; font: 8.5pt/1.7 Consolas, monospace;
           white-space: pre-wrap; }
.aside { background: #f5f5f1; border: 1px solid #d9d9d4; border-radius: 4px; padding: 8px 12px;
         margin: 9px 0; font-size: 9pt; }
/* The header block plus the caveat leaves about 600pt, and the first card is about the same.
   These paddings are trimmed so a card clears that line, because break-inside: avoid below
   turns a near miss into an almost empty first page rather than a slightly tight one. */
.aside p:last-child { margin-bottom: 0; }
footer { margin-top: 20px; padding-top: 9px; border-top: 1px solid #d9d9d4; color: #85858e; font-size: 8pt; }
h2, h3 { break-after: avoid; page-break-after: avoid; }
'@

    $esc = {
        param($t)
        [Security.SecurityElement]::Escape([string]$t)
    }

    $cards = foreach ($f in $findings) {
        $wk = $f.working
        $terms = foreach ($c in $wk.components) {
            '<tr><td>{0}</td><td>{1}</td><td class=n>{2}</td><td class=n>{3:N3}</td><td class=n>x{4:N2}</td><td class=n>{5:N2}</td></tr>' -f
                (& $esc $c.key), (& $esc $c.label), (& $esc $c.raw), [double]$c.value, [double]$c.weight, [double]$c.contribution
        }
        $rules = foreach ($r in @($f.rules)) {
            '<tr><td class=n>{0}</td><td class=n>{1}</td><td>{2}</td><td class=n>{3}</td><td class=n>{4}</td></tr>' -f
                (& $esc $r.id), [int]$r.level, (& $esc $r.desc), (& $esc $r.tech), [int]$r.count
        }
        $chain = if ($wk.chained) {
            'Base {0:N2}, multiplied by {1:N4} because credential access and persistence both appear in this window. Severity {2:N1}.' -f [double]$wk.base, [double]$wk.chain, [double]$wk.score
        } else {
            'Base {0:N2}, with no chain multiplier: only one stage is present. Severity {1:N1}.' -f [double]$wk.base, [double]$wk.score
        }
            # Stages rather than raw ATT&CK strings, because a stage can be established from a rule
        # id where the alert carries no ATT&CK metadata, and the score already counts it that way.
        $stages = if (@($wk.stages).Count) { (& $esc (@($wk.stages) -join ', ')) } else { 'none identified' }
        $named = if (@($wk.tactics).Count) { '' } else { ' (from rule identity; these alerts carry no ATT&amp;CK metadata)' }

        @"
<div class="card">
  <div class="top">
    <span class="when">$(& $esc $f.at)</span>
    <span class="score">$('{0:N1}' -f [double]$f.severity)</span>
    <span class="band $(& $esc $f.band)">$(& $esc $f.band)</span>
    <span>$([int]$f.alerts) alerts &middot; model $('{0:N3}' -f [double]$f.score)</span>
  </div>
  <p class="sub">Stages present: $stages$named</p>
  <h3>How this score was reached</h3>
  <table>
    <thead><tr><th>Term</th><th>What it reads</th><th class=n>Raw</th><th class=n>Norm</th><th class=n>Weight</th><th class=n>Points</th></tr></thead>
    <tbody>$($terms -join '')</tbody>
  </table>
  <p>$chain</p>
  <h3>What fired in this window</h3>
  <table>
    <thead><tr><th>Rule</th><th class=n>Level</th><th>Description</th><th class=n>ATT&amp;CK</th><th class=n>Count</th></tr></thead>
    <tbody>$($rules -join '')</tbody>
  </table>
</div>
"@
    }

    $weights = foreach ($w in @($sc.severityWeights)) {
        '<tr><td>{0}</td><td>{1}</td><td class=n>{2:N2}</td></tr>' -f (& $esc $w.key), (& $esc $w.label), [double]$w.weight
    }

    $m = $sc.model
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Lab findings $($stamp.ToString('yyyy-MM-dd HH:mm'))</title><style>$css</style></head><body>
<h1>Alert sequence findings</h1>
<p class="sub">Windows reaching elevated severity or above, from the Wazuh lab at $(& $esc $ManagerAddress)</p>
<p class="meta">Generated $($stamp.ToString('dddd d MMMM yyyy, HH:mm:ss')) &middot;
$($findings.Count) finding$(if ($findings.Count -ne 1) { 's' }) across $([int]$sc.covers.windows) windows of $([int]$sc.windowSeconds) seconds, from $(& $esc $sc.covers.from)</p>

<div class="aside">
<p><b>Read this as triage ordering, not as a detection.</b> The model inside the severity score was
fitted on eight public networks and has never been measured on this lab, because no public dataset
contains this lab's own rules. It scored $('{0:N3}' -f [double]$m.ap) average precision against a
$('{0:N3}' -f [double]$m.baseRate) base rate on networks it had not seen. A window appearing below is
worth looking at before the ones that do not. It is not, on this evidence, an incident.</p>
</div>

<h2>Findings</h2>
$($cards -join '')

<h2>How severity is calculated</h2>
<p>The model answers how unusual a window of alerts is, which is not the same as how bad it is.
Severity is the composite that separates those, and the model is one term inside it. Six terms are
read off the window, each squashed to a value between 0 and 1, then weighted and added. The total
is multiplied once if the window contains both credential access and persistence, because that
pairing is a chain rather than two events, and a chain is what single event rules cannot see.</p>
<span class="formula">base  = 100 &times; sum of ( weight_i &times; norm_i )
chain = 1 + $($sc.chainBonus) &times; sqrt(coverage)   when credential access and persistence both appear
        1                          otherwise

severity = min(100, base &times; chain)</span>
<table>
  <thead><tr><th>Term</th><th>What it reads</th><th class=n>Weight</th></tr></thead>
  <tbody>$($weights -join '')</tbody>
</table>
<p>The weights are judgement rather than fitted parameters, and they live in one file so that
disagreeing with them is an edit rather than an argument:
<code>scoring/scorer/score.py</code>. Bands are informational below 25, then low,
elevated at 50, high at 70 and critical at 85.</p>

<footer>
Written by the lab dashboard from the poll on screen at the time, so this document and that screen
agree. Method and measurements are in the repository under <code>scoring/</code>,
and the full modelling report is at <code>docs/Detection-Modelling-Report.pdf</code>.
</footer>
</body></html>
"@

    ConvertTo-LabPdf -Html $html -OutFile $out
    return [ordered]@{ ok = $true; path = $out; count = $findings.Count }
}

function Get-LabCredentials {
    <#
    Everything needed to log in to the lab, gathered when asked for rather than on the poll.

    When asked for, because the Wazuh password is an SSH round trip and there is no sense paying
    for one every three seconds, and because it keeps the password out of the state payload this
    page fetches continuously in the background whether or not anybody is looking at it.

    The console password is read from disk at the moment of the request and not held. It is
    plaintext on disk already, and already gitignored; this neither improves that nor worsens it.
    #>
    $consolePassword = $null
    $passwordFile = Join-Path (Get-LabPath Secrets) 'console-password.txt'
    if (Test-Path -LiteralPath $passwordFile) {
        try { $consolePassword = (Get-Content -LiteralPath $passwordFile -Raw).Trim() } catch { }
    }
    $keyPresent = Test-Path -LiteralPath $LabSshKey

    # The admin password lives in a root-owned install log on the manager, so this is the one
    # piece that needs the one-time grant. It comes back through a wrapper rather than as a sudo
    # command line, so the password is never an argument to anything and never enters a process
    # list. That is the same reason the indexer wrapper authenticates with a certificate.
    $wazuhPassword = $null
    $wazuhProblem = $null
    $raw = Invoke-LabSsh -Address $ManagerAddress -Command 'sudo -n /usr/local/bin/lab-dashboard-creds' -TimeoutSeconds 10
    if ($raw) {
        try {
            $parsed = $raw | ConvertFrom-Json
            if ($parsed.password) { $wazuhPassword = [string]$parsed.password }
            else { $wazuhProblem = 'The manager answered but had no password to give. Check /root/wazuh-lab-install/install.log.' }
        } catch {
            $wazuhProblem = 'The manager returned something that was not readable as JSON.'
        }
    } else {
        $wazuhProblem = 'Not read. Either the manager is off, or Enable-LabDashboard.ps1 has not been run, so reading the install log is not permitted.'
    }

    $consoleProblem = $(if ($consolePassword) { $null }
                        else { 'Not read. .lab-secrets\console-password.txt is missing. Run setup\New-LabSecrets.ps1.' })

    # Built from the profile rather than listed. The lean profile has no Windows endpoint, and a
    # credentials panel offering a login to a machine that does not exist is worse than one that
    # is short.
    $endpointEntries = foreach ($name in $LabEndpoints) {
        $endpoint = $LabVms[$name]
        [ordered]@{
            id       = $name.ToLower()
            label    = ('{0} endpoint, SSH and console' -f $(if ($endpoint.Os -eq 'windows') { 'Windows' } else { 'Linux' }))
            target   = ('{0}@{1}' -f $LabSshUser, $endpoint.Address)
            link     = $null
            username = $LabSshUser
            secret   = $consolePassword
            problem  = $consoleProblem
            note     = $(if ($endpoint.Os -eq 'windows') {
                            'The same key as the manager. sshd reads it from administrators_authorized_keys, and the firewall there answers only this host.'
                        } else {
                            'The same key and the same console password as the manager.'
                        })
        }
    }

    [ordered]@{
        ok      = $true
        entries = @(
            [ordered]@{
                id       = 'wazuh'
                label    = 'Wazuh web interface'
                target   = ('https://{0}' -f $ManagerAddress)
                link     = ('https://{0}' -f $ManagerAddress)
                username = 'admin'
                secret   = $wazuhPassword
                problem  = $wazuhProblem
                note     = 'The browser will warn about the certificate. The installer signs it itself, so that warning is expected here.'
            }
            [ordered]@{
                id       = 'manager'
                label    = 'Manager, SSH and console'
                target   = ('{0}@{1}' -f $LabSshUser, $ManagerAddress)
                link     = $null
                username = $LabSshUser
                secret   = $consolePassword
                problem  = $consoleProblem
                note     = $(if ($keyPresent) { 'SSH uses the key at .lab-secrets\lab_ed25519. The password below is for the VM console.' }
                             else { 'The SSH key is missing, so only the console password will work.' })
            }
            $endpointEntries
        )
    }
}

function Get-LabState {
    Get-JobNotices
    # Probes run on their own slower cycle, and only against VMs that are actually running. The
    # exception is a sequence in progress, where the port coming up is the thing being waited on,
    # so a 15 second cache would add 15 seconds to the wait for no reason.
    $sequenceActive = $script:Sequence -and $script:Sequence.phase -notin @('done', 'failed')
    $refreshProbes = $sequenceActive -or
        ([datetime]::UtcNow - $script:ProbeStamp).TotalSeconds -ge $ProbeIntervalSeconds

    $cpuLoad = 0
    $memUsedGb = 0
    if ($script:CpuCounter) { try { $cpuLoad = $script:CpuCounter.NextValue() } catch { $cpuLoad = 0 } }
    if ($script:MemCounter) {
        try { $memUsedGb = [math]::Round($script:TotalMemoryGb - ($script:MemCounter.NextValue() / 1024), 1) } catch { }
    }
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [ordered]@{
            name   = $_.DeviceID
            freeGb = [math]::Round($_.FreeSpace / 1GB, 1)
            sizeGb = [math]::Round($_.Size / 1GB, 1)
        }
    })

    $vms = @()
    $runningMemoryBytes = 0
    foreach ($name in $LabVms.Keys) {
        $meta = $LabVms[$name]
        # Without elevation Hyper-V throws rather than returning nothing, so separate "no rights"
        # from "no such VM". Reporting them the same way sends people hunting a missing VM.
        $vm = $null
        $denied = $false
        try {
            $vm = Get-LabVmInfo -Name $name
        } catch {
            if (-not $script:IsElevated) { $denied = $true }
        }
        if (-not $vm) {
            $vms += [ordered]@{
                name = $name; role = $meta.Role; address = $meta.Address
                found = $false; state = $(if ($denied) { 'Needs administrator' } else { 'Not found' })
            }
            continue
        }
        $state = $vm.State
        if ($state -eq 'Running') { $runningMemoryBytes += $vm.MemoryBytes }

        # There is nothing to learn from probing a VM that is not running, and a connect to a
        # powered-off address is the most expensive thing this loop can do. Skip it.
        if ($state -ne 'Running') {
            $script:ProbeCache[$name] = @()
        } elseif ($refreshProbes) {
            $results = @()
            foreach ($probe in $meta.Probes) {
                $results += [ordered]@{
                    label = $probe.Label
                    open  = [bool](Test-TcpPort -Address $meta.Address -Port $probe.Port)
                }
            }
            $script:ProbeCache[$name] = $results
        }
        $vms += [ordered]@{
            name        = $name
            role        = $meta.Role
            address     = $meta.Address
            found       = $true
            state       = $state
            status      = $vm.Status
            # -1 means the backend cannot measure it, which is not the same as idle. VirtualBox
            # reports CPU load only through a metrics collector that has to be armed per VM.
            cpuPercent  = $vm.CpuPercent
            memoryGb    = [math]::Round($vm.MemoryBytes / 1GB, 1)
            configuredGb = [math]::Round($vm.ConfiguredMb / 1024, 1)
            cpuCount    = $vm.CpuCount
            uptime      = Format-Uptime $vm.Uptime
            autostart   = $vm.Autostart
            autostartOk = ($vm.Autostart -eq 'Nothing')
            probes      = @($script:ProbeCache[$name])
        }
    }

    if ($refreshProbes) { $script:ProbeStamp = [datetime]::UtcNow }

    # Nothing inside the guests is worth asking for while the manager is down, and asking would
    # cost an SSH timeout on every poll. Hyper-V reports Running the moment the VM is powered on,
    # which is a minute or so before sshd answers, so the port probe is the better gate: during a
    # cold boot it turns roughly eight wasted seconds per cycle into none.
    $manager = @($vms | Where-Object { $_.name -eq 'WAZUH-MANAGER' })
    $managerRunning = ($manager.Count -gt 0 -and $manager[0].state -eq 'Running')
    if ($managerRunning) {
        $sshProbe = @($manager[0].probes | Where-Object { $_.label -like 'ssh*' })
        if ($sshProbe.Count -gt 0 -and -not $sshProbe[0].open) { $managerRunning = $false }
    }
    $health = Get-LabHealth -ManagerRunning $managerRunning

    Update-LabSequence -Vms $vms -Health $health

    [ordered]@{
        ok       = $true
        elevated = [bool]$script:IsElevated
        now      = (Get-Date).ToString('HH:mm:ss')
        sequence = $(if ($script:Sequence) {
            [ordered]@{
                kind    = $script:Sequence.kind
                phase   = $script:Sequence.phase
                label   = $script:Sequence.label
                step    = [int]$script:Sequence.step + 1
                total   = [int]$script:Sequence.total
                running = ($script:Sequence.phase -notin @('done', 'failed'))
                waited  = [int]([datetime]::UtcNow - $script:Sequence.startedAt).TotalSeconds
                elapsed = [int]$script:Sequence.elapsed
                error   = $script:Sequence.error
                note    = $script:Sequence.note
            }
        } else { $null })
        host   = [ordered]@{
            name        = $env:COMPUTERNAME
            cpuPercent  = [int]$cpuLoad
            memUsedGb   = $memUsedGb
            memTotalGb  = $script:TotalMemoryGb
            disks       = $disks
        }
        labMemoryGb = [math]::Round($runningMemoryBytes / 1GB, 1)
        vms      = $vms
        rules    = @($script:LabRules)
        health   = $health
        notices  = @($script:Notices)
    }
}

function Invoke-VmAction {
    param([string]$VmName, [string]$Action)
    if (-not $LabVms.Contains($VmName)) { throw "Unknown VM: $VmName" }
    if ($Action -notin @('start', 'shutdown', 'restart', 'forceoff')) { throw "Unknown action: $Action" }
    $vm = Get-LabVmInfo -Name $VmName
    if (-not $vm) { throw "VM not found: $VmName" }
    $label = '{0} {1}' -f $Action, $VmName
    $script:HasJobs = $true
    Invoke-LabVmAction -Name $VmName -Action $Action | ForEach-Object { $_.Name = $label }
    return "Requested $Action on $VmName."
}

function Lock-NoAutostart {
    <# The only autostart value this tool can write. There is deliberately no enable path. #>
    $changed = @()
    foreach ($name in $LabVms.Keys) {
        $vm = Get-LabVmInfo -Name $name
        if (-not $vm) { continue }
        if ($vm.Autostart -ne 'Nothing') {
            Set-LabVmNoAutostart -Name $name
            $changed += $name
        }
    }
    if ($changed.Count -eq 0) { return 'All VMs were already set to never start automatically.' }
    return ('Autostart disabled on: {0}.' -f ($changed -join ', '))
}

function Get-VmStateFrom {
    <# Reads a state out of the list Get-LabState has already built, rather than calling Hyper-V again. #>
    param($Vms, [string]$Name)
    $match = @($Vms | Where-Object { $_.name -eq $Name })
    if ($match.Count -eq 0) { return 'Not found' }
    return $match[0].state
}

function Get-SequencePhases {
    param([string]$Kind)
    if ($Kind -eq 'up') { return $LabUpPhases }
    return $LabDownPhases
}

function Enter-LabPhase {
    <# Performs the current phase's action once, then hands over to its test. #>
    param($Vms)
    $seq = $script:Sequence
    $phase = (Get-SequencePhases -Kind $seq.kind)[$seq.step]
    $seq.phase = $phase.name
    $seq.label = $phase.label
    $seq.deadline = [datetime]::UtcNow.AddSeconds($phase.timeout)
    switch ($phase.name) {
        'manager' {
            if ((Get-VmStateFrom -Vms $Vms -Name 'WAZUH-MANAGER') -ne 'Running') {
                Invoke-VmAction -VmName 'WAZUH-MANAGER' -Action 'start' | Out-Null
            }
        }
        'endpoints' {
            foreach ($name in $LabEndpoints) {
                if ((Get-VmStateFrom -Vms $Vms -Name $name) -eq 'Off') {
                    Invoke-VmAction -VmName $name -Action 'start' | Out-Null
                }
            }
        }
        'endpoints-off' {
            foreach ($name in $LabEndpoints) {
                if ((Get-VmStateFrom -Vms $Vms -Name $name) -eq 'Running') {
                    Invoke-VmAction -VmName $name -Action 'shutdown' | Out-Null
                }
            }
        }
        'manager-off' {
            if ((Get-VmStateFrom -Vms $Vms -Name 'WAZUH-MANAGER') -eq 'Running') {
                Invoke-VmAction -VmName 'WAZUH-MANAGER' -Action 'shutdown' | Out-Null
            }
        }
    }
}

function Test-LabPhase {
    <# Whether the current phase is satisfied. Reads only state that has already been gathered. #>
    param($Vms, $Health)
    $seq = $script:Sequence
    switch ($seq.phase) {
        'manager' {
            return ((Get-VmStateFrom -Vms $Vms -Name 'WAZUH-MANAGER') -eq 'Running')
        }
        'manager-ssh' {
            $manager = @($Vms | Where-Object { $_.name -eq 'WAZUH-MANAGER' })
            if ($manager.Count -eq 0) { return $false }
            return @($manager[0].probes | Where-Object { $_.label -like 'ssh*' -and $_.open }).Count -gt 0
        }
        'manager-services' {
            if (-not $Health -or -not $Health.reachable) { return $false }
            $units = @($Health.services | Where-Object { $_.state -eq 'active' } | ForEach-Object { $_.unit })
            foreach ($required in $ManagerUnits) { if ($units -notcontains $required) { return $false } }
            return $true
        }
        'endpoints' {
            foreach ($name in $LabEndpoints) {
                if ((Get-VmStateFrom -Vms $Vms -Name $name) -ne 'Running') { return $false }
            }
            return $true
        }
        'agents' {
            if (-not $Health -or -not $Health.reachable) { return $false }
            # Reading agent state needs the one-time setup. Without it there is nothing to wait
            # for, so finish with a note rather than spending seven minutes timing out on a check
            # that was never going to be able to run.
            if (@($Health.missing) -contains 'agents') {
                $script:Sequence.note = 'Agents not checked: the one-time setup has not been run, so the manager will not report them.'
                return $true
            }
            $live = @($Health.agents | Where-Object { $_.status -match 'active' })
            return ($live.Count -ge $LabEndpoints.Count)
        }
        'endpoints-off' {
            foreach ($name in $LabEndpoints) {
                if ((Get-VmStateFrom -Vms $Vms -Name $name) -eq 'Running') { return $false }
            }
            return $true
        }
        'manager-off' {
            return ((Get-VmStateFrom -Vms $Vms -Name 'WAZUH-MANAGER') -ne 'Running')
        }
    }
    return $false
}

function Update-LabSequence {
    <# One step per poll. Called from Get-LabState once the VM list and health are in hand. #>
    param($Vms, $Health)
    if (-not $script:Sequence) { return }
    $seq = $script:Sequence
    if ($seq.phase -in @('done', 'failed')) { return }

    # A phase is only observed when someone asks for state. If nothing polled for a while, that
    # time was not spent watching anything, and counting it against the deadline would report a
    # timeout for a boot that went fine and simply had nobody looking. Give the gap back.
    $now = [datetime]::UtcNow
    if ($script:LastSequencePoll -gt [datetime]::MinValue) {
        $gap = ($now - $script:LastSequencePoll).TotalSeconds
        if ($gap -gt 15) { $seq.deadline = $seq.deadline.AddSeconds($gap) }
    }
    $script:LastSequencePoll = $now

    $phases = Get-SequencePhases -Kind $seq.kind
    if (-not (Test-LabPhase -Vms $Vms -Health $Health)) {
        if ($now -gt $seq.deadline) {
            $seq.phase = 'failed'
            $seq.error = ('Gave up while {0}. Nothing was forced; the VMs are wherever they got to.' -f $seq.label.ToLower())
            [void]$script:Notices.Add([ordered]@{
                at = [datetime]::UtcNow.ToString('o'); kind = 'error'; text = $seq.error
            })
        }
        return
    }

    $seq.step++
    if ($seq.step -ge $phases.Count) {
        $seq.phase = 'done'
        $seq.label = if ($seq.kind -eq 'up') { 'The lab is up' } else { 'The lab is down' }
        $seq.elapsed = [int]([datetime]::UtcNow - $seq.startedAt).TotalSeconds
        [void]$script:Notices.Add([ordered]@{
            at = [datetime]::UtcNow.ToString('o'); kind = 'ok'
            text = ('{0} after {1} seconds.' -f $seq.label, $seq.elapsed)
        })
        return
    }
    Enter-LabPhase -Vms $Vms
}

function Start-LabSequence {
    param([string]$Action, $Vms)
    if ($Action -eq 'cancel') {
        if (-not $script:Sequence -or $script:Sequence.phase -in @('done', 'failed')) { return 'Nothing to cancel.' }
        $script:Sequence = $null
        return 'Sequence cancelled. Any VM already asked to start or stop carries on doing it.'
    }
    if ($Action -notin @('up', 'down')) { throw "Unknown lab action: $Action" }
    if ($script:Sequence -and $script:Sequence.phase -notin @('done', 'failed')) {
        throw 'A lab sequence is already running. Cancel it first.'
    }
    $script:Sequence = [ordered]@{
        kind      = $Action
        step      = 0
        phase     = ''
        label     = ''
        total     = (Get-SequencePhases -Kind $Action).Count
        startedAt = [datetime]::UtcNow
        deadline  = [datetime]::UtcNow
        elapsed   = 0
        error     = $null
        note      = $null
    }
    Enter-LabPhase -Vms $Vms
    if ($Action -eq 'up') { return 'Bringing the lab up. The manager goes first so the agents have something to connect to.' }
    return 'Taking the lab down. The endpoints stop first and the manager last, so the indexer closes cleanly.'
}

function Write-Reply {
    param($Response, [string]$Body, [string]$ContentType = 'application/json; charset=utf-8', [int]$Status = 200)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
    $Response.StatusCode = $Status
    $Response.ContentType = $ContentType
    $Response.Headers.Add('Cache-Control', 'no-store')
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

# A random token is generated per run and injected into the page. Every API call must present it.
# No CORS headers are sent, so another site open in the same browser cannot read the token out of
# the page or drive these endpoints.
$token = [guid]::NewGuid().ToString('N')
$pagePath = Join-Path $PSScriptRoot 'dashboard.html'
if (-not (Test-Path -LiteralPath $pagePath)) { throw "Missing page file: $pagePath" }

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
try {
    $listener.Start()
} catch {
    throw "Could not listen on port $Port. Another process may be using it. Try -Port with a different number. ($($_.Exception.Message))"
}

Write-Host ''
Write-Host "  Wazuh lab dashboard is running at http://127.0.0.1:$Port/"
Write-Host '  Leave this window open. Close it, or use "Stop dashboard" on the page, to shut it down.'
Write-Host ''

if (-not $NoBrowser) { Start-Process "http://127.0.0.1:$Port/" | Out-Null }

$running = $true
while ($running -and $listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response
    try {
        $path = $request.Url.AbsolutePath.TrimEnd('/')
        if ($path -eq '') { $path = '/' }

        if ($path -eq '/' -and $request.HttpMethod -eq 'GET') {
            $html = (Get-Content -LiteralPath $pagePath -Raw) -replace '__LAB_TOKEN__', $token
            Write-Reply -Response $response -Body $html -ContentType 'text/html; charset=utf-8'
            continue
        }

        if ($path -eq '/favicon.ico') {
            Write-Reply -Response $response -Body '' -ContentType 'image/x-icon' -Status 404
            continue
        }

        if ($request.Headers['X-Lab-Token'] -ne $token) {
            Write-Reply -Response $response -Body '{"ok":false,"error":"Bad or missing token."}' -Status 403
            continue
        }

        switch ($path) {
            '/api/state' {
                Write-Reply -Response $response -Body ((Get-LabState) | ConvertTo-Json -Depth 8 -Compress)
            }
            '/api/preflight' {
                Write-Reply -Response $response -Body ((Get-LabPreflight) | ConvertTo-Json -Depth 6 -Compress)
            }
            '/api/creds' {
                Write-Reply -Response $response -Body ((Get-LabCredentials) | ConvertTo-Json -Depth 6 -Compress)
            }
            '/api/action' {
                $reader = New-Object IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $payload = $reader.ReadToEnd() | ConvertFrom-Json
                $reader.Close()
                $message = Invoke-VmAction -VmName $payload.vm -Action $payload.action
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/service' {
                $reader = New-Object IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $payload = $reader.ReadToEnd() | ConvertFrom-Json
                $reader.Close()
                $message = Invoke-ServiceAction -VmName $payload.vm -Unit $payload.unit -Action $payload.action
                # The next poll would otherwise serve a stale cache and look like nothing happened.
                $script:HealthStamp = [datetime]::MinValue
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/lab' {
                $reader = New-Object IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $payload = $reader.ReadToEnd() | ConvertFrom-Json
                $reader.Close()
                # One read per VM, only on the button press, so the first phase acts on the
                # states as they are right now rather than whatever the last poll cached.
                $vmStates = @($LabVms.Keys | ForEach-Object {
                    $vm = Get-LabVmInfo -Name $_
                    [ordered]@{ name = $_; state = $(if ($vm) { $vm.State } else { 'Not found' }) }
                })
                $message = Start-LabSequence -Action $payload.action -Vms $vmStates
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/scenario' {
                $reader = New-Object IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $payload = $reader.ReadToEnd() | ConvertFrom-Json
                $reader.Close()
                $message = Invoke-LabScenario -VmName $payload.vm -Scenario $payload.scenario -Mode $payload.mode
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/export-findings' {
                $result = Export-LabFindings
                Write-Reply -Response $response -Body ($result | ConvertTo-Json -Depth 4 -Compress)
            }
            '/api/lock-autostart' {
                $message = Lock-NoAutostart
                Write-Reply -Response $response -Body (([ordered]@{ ok = $true; message = $message }) | ConvertTo-Json -Compress)
            }
            '/api/quit' {
                Write-Reply -Response $response -Body '{"ok":true,"message":"Stopping."}'
                $running = $false
            }
            default {
                Write-Reply -Response $response -Body '{"ok":false,"error":"Not found."}' -Status 404
            }
        }
    } catch {
        $problem = [ordered]@{ ok = $false; error = $_.Exception.Message }
        try { Write-Reply -Response $response -Body ($problem | ConvertTo-Json -Compress) -Status 500 } catch { }
    }
}

$listener.Stop()
$listener.Close()
Write-Host '  Dashboard stopped.'
