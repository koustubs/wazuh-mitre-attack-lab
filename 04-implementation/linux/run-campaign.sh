#!/usr/bin/env bash
#
# run-campaign.sh - collect a labelled dataset by driving the lab scenarios for hours.
#
# invoke-scenario.sh produces one run. This produces a night of them: a few hundred labelled
# episodes, spaced and varied, with ordinary activity running underneath so that "normal" in the
# dataset means routine work rather than an absence of events.
#
#   sudo bash run-campaign.sh start [--hours 14]
#   sudo bash run-campaign.sh status
#   sudo bash run-campaign.sh stop
#   bash run-campaign.sh simulate [hours]      # schedule only, no root, no side effects
#
# What it writes, under /var/log/wazuh-lab/campaign/<campaignId>/:
#   campaign.jsonl    one line per scenario run, appended the moment the run finishes
#   activity.jsonl    one line per background tick
#   campaign.state    what this campaign is and when it should end
#   campaign.log      human readable progress
#
# Append-only is deliberate. The host copies these back as they grow, so losing power costs the
# run in flight and nothing before it. A truncated final line is discarded by the reader.
#
# Honest note on the labels, which matters when writing up whatever is trained on this. The
# label is whatever this script decided to do, not a judgement about the events afterwards. The
# separability it builds in is: an attacker brute forces before persisting, and moves between
# steps in seconds, where an administrator does not and takes minutes. Both are true of real
# intrusions, but a model that scores well here has learned those two things and not more.

set -euo pipefail
umask 077

readonly CAMPAIGN_ROOT=/var/log/wazuh-lab/campaign
readonly EVIDENCE_ROOT=/var/log/wazuh-lab/evidence
readonly STAFF_PREFIX=labstaff
readonly MAX_HOURS=48

# Rule 100111 is frequency 6 / timeframe 120. Two S1 runs closer together than the timeframe
# share a counting window, so failures from the first are counted towards the second and a
# benign run can be swept into a composite alert it did not cause. That is a wrong label going
# into training data, which is worse than having less of it. 150 leaves slack for a busy host.
readonly MIN_S1_GAP=150

# Standing accounts that produce the ordinary login traffic. Weighted so the users have
# different shapes: one present all night, one only early, one rare. Without this, normal in the
# dataset is silence, and a model trained on that learns nothing worth knowing.
#   name-suffix : pick weight : first hour of run : last hour of run
readonly STAFF_PLAN=(
    "1:60:0:48"
    "2:30:0:7"
    "3:10:0:48"
)

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { echo "$*" >&2; exit 1; }
now() { date -u +%s; }
iso() { date -u -d "@${1:-$(date -u +%s)}" +%Y-%m-%dT%H:%M:%SZ; }
rand() { echo $(( $1 + RANDOM % ($2 - $1 + 1) )); }

find_generator() {
    local here; here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    local c
    for c in /usr/local/lib/wazuh-lab/invoke-scenario.sh "$here/invoke-scenario.sh"; do
        if [[ -r $c ]]; then echo "$c"; return 0; fi
    done
    return 1
}

# ---------------------------------------------------------------------------- the episode table
#
# An episode is one intent carried out over one or more scenario runs. The label belongs to the
# episode, so a chain is one labelled sample even though it produces several alerts.

pick_episode() {
    local r=$((RANDOM % 100))
    if   (( r < 22 )); then echo admin-failed-login
    elif (( r < 36 )); then echo admin-new-account
    elif (( r < 50 )); then echo admin-new-cronjob
    elif (( r < 62 )); then echo admin-provision
    elif (( r < 80 )); then echo bruteforce
    elif (( r < 92 )); then echo bruteforce-persist
    else                    echo quiet-persist
    fi
}

episode_label() { case $1 in admin-*) echo benign ;; *) echo attack ;; esac; }

plan_episode() {
    # One step per line: "scenario mode logons gap-before-next-step". logons is "-" where the
    # scenario has no logons to make. Administrators are slow between steps and attackers are
    # not, which is the timing signal described in the header.
    case $1 in
        admin-failed-login)  printf 'S1 comparison %s 0\n' "$(rand 1 5)" ;;
        admin-new-account)   printf 'S2 comparison - 0\n' ;;
        admin-new-cronjob)   printf 'S3 comparison - 0\n' ;;
        admin-provision)     printf 'S2 comparison - %s\n' "$(rand 60 300)"
                             printf 'S3 comparison - 0\n' ;;
        bruteforce)          printf 'S1 test %s 0\n' "$(rand 6 14)" ;;
        bruteforce-persist)  printf 'S1 test %s %s\n' "$(rand 6 14)" "$(rand 15 75)"
                             printf 'S2 test - %s\n' "$(rand 15 75)"
                             printf 'S3 test - 0\n' ;;
        quiet-persist)       printf 'S2 test - %s\n' "$(rand 10 45)"
                             printf 'S3 test - 0\n' ;;
        *) die "unknown episode kind: $1" ;;
    esac
}

# ---------------------------------------------------------------------------- standing accounts

staff_name() { echo "${STAFF_PREFIX}$1"; }

remove_staff() {
    local entry suffix name
    for entry in "${STAFF_PLAN[@]}"; do
        suffix=${entry%%:*}
        name=$(staff_name "$suffix")
        if id -u "$name" >/dev/null 2>&1; then userdel -r "$name" 2>/dev/null || userdel "$name" || true; fi
    done
}

create_staff() {
    local entry suffix name
    for entry in "${STAFF_PLAN[@]}"; do
        suffix=${entry%%:*}
        name=$(staff_name "$suffix")
        useradd --create-home --shell /bin/bash --comment 'Wazuh lab standing account' "$name"
    done
}

pick_staff() {
    # Chooses among the accounts whose window covers this hour of the run, by weight. Prints
    # nothing when no account is active, which is a genuinely quiet stretch rather than a bug.
    local hour=$1 total=0 entry suffix weight first last roll acc=0
    local -a eligible=()
    for entry in "${STAFF_PLAN[@]}"; do
        IFS=: read -r suffix weight first last <<<"$entry"
        if (( hour >= first && hour < last )); then
            eligible+=("$suffix:$weight")
            total=$(( total + weight ))
        fi
    done
    (( total > 0 )) || return 0
    roll=$(( RANDOM % total ))
    for entry in "${eligible[@]}"; do
        IFS=: read -r suffix weight <<<"$entry"
        acc=$(( acc + weight ))
        if (( roll < acc )); then staff_name "$suffix"; return 0; fi
    done
}

# ---------------------------------------------------------------------------- running things

record_run() {
    # Merges the campaign's view of a step into the run record the generator wrote, and appends
    # it as one line. Written through python3 because an error string is free text and must be
    # escaped properly; every other field here is a controlled token.
    local dir=$1 jsonl=$2 campaign=$3 episode=$4 kind=$5 label=$6 step=$7 steps=$8 rc=$9
    python3 - "$dir" "$jsonl" "$campaign" "$episode" "$kind" "$label" "$step" "$steps" "$rc" <<'PY'
import json, pathlib, sys
d, jsonl, campaign, episode, kind, label, step, steps, rc = sys.argv[1:]
rec = {}
p = pathlib.Path(d) / 'run.json' if d else None
if p is None:
    rec = {'error': 'the generator left no evidence directory; it failed before it could write one'}
elif not p.exists():
    rec = {'error': 'the evidence directory has no run.json'}
else:
    try:
        rec = json.loads(p.read_text(encoding='utf-8-sig'))
    except ValueError:
        rec = {'error': 'run.json was not readable JSON'}
rec.update(campaignId=campaign, episodeId=episode, episodeKind=kind, label=label,
           stepIndex=int(step), stepCount=int(steps), exitCode=int(rc),
           evidenceDir=d or None)
with open(jsonl, 'a', encoding='utf-8') as fh:
    fh.write(json.dumps(rec, sort_keys=True) + '\n')
    fh.flush()
PY
}

run_step() {
    # Runs one scenario and appends its record. Never fails the campaign: a scenario that errors
    # is a data point about the lab, and fourteen hours should not end because one run did.
    local gen=$1 scenario=$2 mode=$3 logons=$4 campaign=$5 episode=$6 kind=$7 label=$8 \
          step=$9 steps=${10} jsonl=${11}
    local t0 rc=0 dir=''
    t0=$(now)

    if [[ $scenario == S1 ]]; then
        local since=$(( t0 - LAST_S1_END ))
        if (( LAST_S1_END > 0 && since < MIN_S1_GAP )); then
            local wait=$(( MIN_S1_GAP - since ))
            log "  holding ${wait}s so this S1 does not share a counting window with the last one"
            sleep "$wait"
            t0=$(now)
        fi
    fi

    set +e
    if [[ $logons == - ]]; then
        bash "$gen" "$scenario" "$mode" >/dev/null 2>&1
    else
        bash "$gen" "$scenario" "$mode" "$logons" >/dev/null 2>&1
    fi
    rc=$?
    set -e

    if [[ $scenario == S1 ]]; then LAST_S1_END=$(now); fi

    # The generator names its own evidence directory, so find the one it just made rather than
    # parsing stdout, which is absent when a run fails before its last line.
    dir=$(find "$EVIDENCE_ROOT" -maxdepth 1 -type d -name "$scenario-*" -newermt "@$(( t0 - 2 ))" \
          2>/dev/null | sort | tail -1)
    record_run "$dir" "$jsonl" "$campaign" "$episode" "$kind" "$label" "$step" "$steps" "$rc"

    if (( rc == 0 )); then
        log "  $scenario $mode logons=$logons ok"
    else
        log "  $scenario $mode logons=$logons FAILED rc=$rc (recorded, continuing)"
    fi
    return 0
}

background_tick() {
    local hour=$1 activity=$2 campaign=$3 user action rc=0
    user=$(pick_staff "$hour" || true)
    if [[ -z $user ]]; then
        action=idle
    else
        action=session
        set +e
        runuser -l "$user" -c 'true' >/dev/null 2>&1
        rc=$?
        set -e
    fi
    printf '{"campaignId":"%s","at":"%s","kind":"background","action":"%s","user":"%s","exitCode":%d}\n' \
        "$campaign" "$(iso)" "$action" "${user:-}" "$rc" >> "$activity"
}

# ---------------------------------------------------------------------------- commands

cmd_run() {
    # The detached body. Not called directly.
    local dir=$1 hours=$2 campaign
    campaign=$(basename "$dir")
    local jsonl="$dir/campaign.jsonl" activity="$dir/activity.jsonl"
    local gen; gen=$(find_generator) || die 'invoke-scenario.sh not found'

    local start deadline
    start=$(now)
    deadline=$(( start + hours * 3600 ))

    LAST_S1_END=0
    local episodes=0 runs=0

    # One exit path, however the campaign ends: deadline, stop file, signal, or an unexpected
    # error. The standing accounts must come out in every one of those cases, so this hangs off
    # EXIT rather than being called at the end of the loop, and guards against running twice
    # because a signal fires the handler and then EXIT fires it again.
    FINISH_REASON=error
    FINISHED=no
    finish() {
        if [[ $FINISHED == yes ]]; then return 0; fi
        FINISHED=yes
        log "stopping: $FINISH_REASON"
        remove_staff
        python3 - "$dir/campaign.state" "$(iso)" "$episodes" "$runs" "$FINISH_REASON" <<'PY'
import json, pathlib, sys
p, ended, episodes, runs, why = sys.argv[1:]
f = pathlib.Path(p)
s = json.loads(f.read_text(encoding='utf-8-sig')) if f.exists() else {}
s.update(endedAt=ended, episodes=int(episodes), runs=int(runs), finishedBecause=why, running=False)
f.write_text(json.dumps(s, indent=2) + '\n')
PY
        rm -f "$dir/campaign.pid"
        log "standing accounts removed, state written"
    }
    trap finish EXIT
    trap 'FINISH_REASON=interrupted; exit 0' INT TERM

    log "campaign $campaign starting, $hours hours, generator $gen"
    remove_staff          # anything left behind by a campaign that lost power
    create_staff
    log "standing accounts created; waiting out their creation alerts before recording"
    sleep 180             # keep the setup's own 100112 alerts outside the recording window

    python3 - "$dir/campaign.state" "$(iso)" "$(iso "$deadline")" <<'PY'
import json, pathlib, sys
p, recording, planned = sys.argv[1:]
f = pathlib.Path(p)
s = json.loads(f.read_text(encoding='utf-8-sig'))
s.update(recordingFrom=recording, plannedUntil=planned, running=True)
f.write_text(json.dumps(s, indent=2) + '\n')
PY
    log "recording from now"

    local next_episode next_background t hour
    next_episode=$(( $(now) + $(rand 30 120) ))
    next_background=$(( $(now) + $(rand 20 60) ))

    while :; do
        t=$(now)
        if (( t >= deadline )); then FINISH_REASON=deadline; break; fi
        if [[ -e $dir/STOP ]]; then FINISH_REASON=stopped; break; fi
        hour=$(( (t - start) / 3600 ))

        if (( t >= next_background )); then
            background_tick "$hour" "$activity" "$campaign"
            next_background=$(( $(now) + $(rand 20 60) ))
        fi

        if (( t >= next_episode )); then
            local kind label episode steps idx
            kind=$(pick_episode)
            label=$(episode_label "$kind")
            episode=$(python3 -c 'import secrets; print(secrets.token_hex(5))')
            mapfile -t steps < <(plan_episode "$kind")
            episodes=$(( episodes + 1 ))
            log "episode $episodes [$episode] $kind ($label), ${#steps[@]} step(s)"

            idx=0
            local line scenario mode logons gap
            for line in "${steps[@]}"; do
                read -r scenario mode logons gap <<<"$line"
                idx=$(( idx + 1 ))
                run_step "$gen" "$scenario" "$mode" "$logons" "$campaign" "$episode" "$kind" \
                         "$label" "$idx" "${#steps[@]}" "$jsonl"
                runs=$(( runs + 1 ))
                if (( gap > 0 )); then sleep "$gap"; fi
            done
            next_episode=$(( $(now) + $(rand 150 330) ))
        fi

        sleep 5
    done
}

cmd_start() {
    local hours=14
    while (( $# )); do
        case $1 in
            --hours) hours=${2:-}; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done
    [[ $hours =~ ^[0-9]+$ ]] && (( hours >= 1 && hours <= MAX_HOURS )) \
        || die "--hours must be a whole number from 1 to $MAX_HOURS."

    [[ $EUID == 0 ]] || die 'Run with sudo.'
    [[ $(hostname -s) == wazuh-linux ]] || die 'Run this on the wazuh-linux lab VM.'
    systemctl is-active --quiet wazuh-agent || die 'Start the Wazuh agent first.'
    local gen
    gen=$(find_generator) || die 'invoke-scenario.sh is not installed and is not beside this script.'
    # find_generator prefers the installed copy. One from before the logon count was added
    # rejects the third argument, so every varied S1 run would fail and the night would collect
    # nothing but errors. Far cheaper to notice now than at 3am.
    grep -q 'failed-logons' "$gen" || die \
        "$gen predates the logon count and would reject every varied S1 run. Install the current invoke-scenario.sh over it."
    command -v sshpass >/dev/null || die 'sshpass is missing; S1 cannot run without it.'

    local live
    live=$(running_campaign || true)
    [[ -z $live ]] || die "A campaign is already running: $live. Use stop first."

    local campaign dir
    campaign="$(date -u +%Y%m%dT%H%M%SZ)-$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
    dir="$CAMPAIGN_ROOT/$campaign"
    mkdir -p "$dir"
    : > "$dir/campaign.jsonl"
    : > "$dir/activity.jsonl"
    : > "$dir/campaign.log"
    # Readable without root, deliberately and only here. These hold run ids, scenario names,
    # timestamps and labels, and nothing secret. It lets the host copy them back over the
    # existing labadmin key instead of needing a sudo grant of its own. The evidence directories
    # under /var/log/wazuh-lab/evidence keep the script's umask, because an S1 run leaves a
    # throwaway sshd host key in there.
    chmod 0755 "$CAMPAIGN_ROOT" "$dir"
    chmod 0644 "$dir/campaign.jsonl" "$dir/activity.jsonl" "$dir/campaign.log"
    python3 - "$dir/campaign.state" "$campaign" "$(iso)" "$hours" "$(hostname -s)" <<'PY'
import json, pathlib, sys
p, campaign, started, hours, host = sys.argv[1:]
pathlib.Path(p).write_text(json.dumps(dict(
    campaignId=campaign, startedAt=started, hours=int(hours), endpoint=host,
    minS1GapSeconds=150, running=False), indent=2) + '\n')
PY
    chmod 0644 "$dir/campaign.state"

    setsid nohup bash "${BASH_SOURCE[0]}" __run "$dir" "$hours" \
        >> "$dir/campaign.log" 2>&1 < /dev/null &
    echo $! > "$dir/campaign.pid"
    sleep 1

    cat <<EOF
Campaign $campaign started, running for $hours hours.

  records   $dir/campaign.jsonl
  activity  $dir/activity.jsonl
  progress  $dir/campaign.log

Recording begins in 3 minutes, after the standing accounts' own creation alerts have passed.
Expect roughly $(( hours * 15 )) episodes and $(( hours * 22 )) runs.

  sudo bash $0 status
  sudo bash $0 stop
EOF
}

running_campaign() {
    local d pid
    for d in "$CAMPAIGN_ROOT"/*/; do
        [[ -f ${d}campaign.pid ]] || continue
        pid=$(cat "${d}campaign.pid" 2>/dev/null) || continue
        if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then basename "$d"; return 0; fi
    done
    return 1
}

cmd_stop() {
    [[ $EUID == 0 ]] || die 'Run with sudo.'
    local campaign
    campaign=$(running_campaign) || die 'No campaign is running.'
    touch "$CAMPAIGN_ROOT/$campaign/STOP"
    echo "Asked $campaign to stop. It finishes the episode in flight first, then removes the"
    echo "standing accounts. Give it up to three minutes, then check status."
}

cmd_status() {
    local campaign d
    campaign=$(running_campaign || true)
    if [[ -n $campaign ]]; then
        echo "Running: $campaign"
        d="$CAMPAIGN_ROOT/$campaign"
    else
        d=$(ls -1d "$CAMPAIGN_ROOT"/*/ 2>/dev/null | sort | tail -1) || true
        [[ -n $d ]] || die 'No campaigns found.'
        echo "Not running. Most recent: $(basename "$d")"
    fi
    local runs
    runs=$(wc -l < "$d/campaign.jsonl" 2>/dev/null || echo 0)
    echo "Runs recorded: $runs"
    echo "Background ticks: $(wc -l < "$d/activity.jsonl" 2>/dev/null || echo 0)"
    if (( runs > 0 )); then
        echo "By label:"
        python3 -c '
import collections, json, sys
c = collections.Counter()
k = collections.Counter()
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line: continue
    try: r = json.loads(line)
    except ValueError: continue          # a line truncated by a power cut
    c[r.get("label", "?")] += 1
    k[r.get("episodeKind", "?")] += 1
for key, n in c.most_common(): print("  %-8s %d" % (key, n))
print("By episode kind:")
for key, n in k.most_common(): print("  %-20s %d" % (key, n))
' "$d/campaign.jsonl"
    fi
    echo "Disk used by evidence: $(du -sh "$EVIDENCE_ROOT" 2>/dev/null | cut -f1 || echo unknown)"
    echo "Free on /var: $(df -h /var | awk 'NR==2 {print $4}')"
    echo
    echo "Last progress lines:"
    tail -5 "$d/campaign.log" 2>/dev/null | sed 's/^/  /'
}

cmd_simulate() {
    # Walks the schedule with no side effects and no root, so the pacing and the label mix can
    # be checked before committing a night to it.
    local hours=${1:-14} t=0 episodes=0 runs=0 bg=0 last_s1=-9999
    [[ $hours =~ ^[0-9]+$ ]] || die 'simulate takes a whole number of hours.'
    local total=$(( hours * 3600 ))
    local next_episode next_background
    next_episode=$(rand 30 120)
    next_background=$(rand 20 60)
    declare -A bylabel=() bykind=() byscenario=()

    while (( t < total )); do
        if (( t >= next_background )); then
            bg=$(( bg + 1 )); next_background=$(( t + $(rand 20 60) ))
        fi
        if (( t >= next_episode )); then
            local kind label; kind=$(pick_episode); label=$(episode_label "$kind")
            episodes=$(( episodes + 1 ))
            bylabel[$label]=$(( ${bylabel[$label]:-0} + 1 ))
            bykind[$kind]=$(( ${bykind[$kind]:-0} + 1 ))
            local line scenario mode logons gap
            while read -r scenario mode logons gap; do
                if [[ $scenario == S1 ]] && (( t - last_s1 < MIN_S1_GAP )); then
                    t=$(( last_s1 + MIN_S1_GAP ))
                fi
                case $scenario in S1) t=$(( t + 8 + ${logons/-/0} * 3 )); last_s1=$t ;;
                                  S2) t=$(( t + 4 )) ;;
                                  S3) t=$(( t + 19 )) ;; esac
                runs=$(( runs + 1 ))
                byscenario[$scenario]=$(( ${byscenario[$scenario]:-0} + 1 ))
                if (( gap > 0 )); then t=$(( t + gap )); fi
            done < <(plan_episode "$kind")
            next_episode=$(( t + $(rand 150 330) ))
        fi
        t=$(( t + 5 ))
    done

    printf 'Simulated %d hours\n\n  episodes   %d\n  runs       %d\n  background %d\n\n' \
        "$hours" "$episodes" "$runs" "$bg"
    echo 'By label:'
    local k
    for k in "${!bylabel[@]}"; do printf '  %-8s %4d  (%d%%)\n' "$k" "${bylabel[$k]}" \
        $(( bylabel[$k] * 100 / episodes )); done
    echo 'By episode kind:'
    for k in "${!bykind[@]}"; do printf '  %-20s %4d\n' "$k" "${bykind[$k]}"; done
    echo 'Runs by scenario:'
    for k in "${!byscenario[@]}"; do printf '  %-4s %4d\n' "$k" "${byscenario[$k]}"; done
}

case "${1:-}" in
    start)    shift; cmd_start "$@" ;;
    stop)     cmd_stop ;;
    status)   cmd_status ;;
    simulate) shift; cmd_simulate "$@" ;;
    __run)    shift; cmd_run "$@" ;;
    *) cat >&2 <<EOF
Usage:
  sudo bash run-campaign.sh start [--hours N]   collect for N hours (default 14, max $MAX_HOURS)
  sudo bash run-campaign.sh status              progress and the label mix so far
  sudo bash run-campaign.sh stop                finish the current episode, clean up, exit
       bash run-campaign.sh simulate [hours]    schedule only: no root, no side effects
EOF
       exit 2 ;;
esac
