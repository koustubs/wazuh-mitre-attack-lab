#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ $(hostname -s) == wazuh-linux ]] || { echo 'Run this on the wazuh-linux lab VM.' >&2; exit 1; }
scenario=${1:-}
mode=${2:-test}
# Optional third argument: how many failed logons S1 should make. Left off, this script behaves
# exactly as it always has, 6 for test and 1 for comparison, so the recorded evidence and the
# lab-scenario wrapper are unaffected. run-campaign.sh sets it, because a dataset made of only
# two fixed shapes teaches a model the two shapes rather than the behaviour.
#
# The caller owns the pairing of mode to count. Rule 100111 is frequency 6, so comparison must
# stay at or below 5 and test must be 6 or more, or the label stops describing the alert.
logons=${3:-}
[[ $scenario =~ ^S[123]$ && $mode =~ ^(test|comparison)$ ]] || {
    echo 'Usage: sudo bash invoke-scenario.sh S1|S2|S3 [test|comparison] [failed-logons]' >&2; exit 1;
}
[[ -z $logons || $logons =~ ^([1-9]|1[0-9]|20)$ ]] || {
    echo 'Failed logons must be a whole number from 1 to 20.' >&2; exit 1;
}
if [[ -n $logons ]]; then
    { [[ $mode == comparison && $logons -le 5 ]] || [[ $mode == test && $logons -ge 6 ]]; } || {
        echo 'comparison takes 1 to 5 failed logons, test takes 6 or more.' >&2; exit 1;
    }
fi
systemctl is-active --quiet wazuh-agent || { echo 'Start the Wazuh agent first.' >&2; exit 1; }
run_id=$(python3 -c 'import secrets; print(secrets.token_hex(5))')
name=wz$run_id
run_dir=/var/log/wazuh-lab/evidence/$scenario-$run_id
mkdir -p "$run_dir"
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
created_user=no
created_cron=no
sshd_pid=''
attempts=0
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ -n $sshd_pid ]]; then kill "$sshd_pid" 2>/dev/null || true; wait "$sshd_pid" 2>/dev/null || true; fi
    if [[ $created_cron == yes ]]; then rm -f -- "/etc/cron.d/$name"; fi
    if [[ $created_user == yes ]]; then userdel "$name"; fi
    python3 - "$run_dir" "$scenario" "$mode" "$name" "$started" "$attempts" "$rc" <<'PY'
import datetime as dt, json, pathlib, socket, sys
out, scenario, mode, marker, started, attempts, rc = sys.argv[1:]
record = dict(runId=marker[2:], platform='linux', scenario=scenario,
    comparison=mode=='comparison', endpoint=socket.gethostname(), marker=marker,
    startedAt=started, finishedAt=dt.datetime.now(dt.timezone.utc).isoformat(),
    attemptedLogons=int(attempts), error=None if rc=='0' else 'Scenario or source check failed',
    indexedDetection='not_checked')
pathlib.Path(out, 'run.json').write_text(json.dumps(record, indent=2)+'\n')
PY
    exit "$rc"
}
trap cleanup EXIT
if [[ $scenario == S1 || $scenario == S2 ]]; then
    useradd --no-create-home --shell /bin/bash --comment "Wazuh lab $run_id" "$name"
    created_user=yes
fi
if [[ $scenario == S1 ]]; then
    # Known account and wrong passwords. This daemon is local to the disposable VM.
    password=$(python3 -c 'import secrets; print("Wz!9"+secrets.token_hex(20))')
    printf '%s:%s\n' "$name" "$password" | chpasswd
    unset password
    mkdir -p /run/sshd
    ssh-keygen -q -t ed25519 -N '' -f "$run_dir/host_key"
    port=22222
    cat > "$run_dir/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $run_dir/host_key
PidFile $run_dir/sshd.pid
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
UsePAM yes
PermitRootLogin no
AllowUsers $name
MaxAuthTries 1
LogLevel VERBOSE
SyslogFacility AUTH
EOF
    /usr/sbin/sshd -t -f "$run_dir/sshd_config"
    /usr/sbin/sshd -D -f "$run_dir/sshd_config" &
    sshd_pid=$!
    sleep 1
    kill -0 "$sshd_pid"
    read -r key_type key_value _ < "$run_dir/host_key.pub"
    printf '[127.0.0.1]:%s %s %s\n' "$port" "$key_type" "$key_value" > "$run_dir/known_hosts"
    printf '%s\n' 'DeliberatelyWrong!7' > "$run_dir/wrong-password"
    attempts=6
    [[ $mode == comparison ]] && attempts=1
    [[ -n $logons ]] && attempts=$logons
    for ((i=0; i<attempts; i++)); do
        set +e
        sshpass -f "$run_dir/wrong-password" ssh -p "$port" -o StrictHostKeyChecking=yes \
            -o UserKnownHostsFile="$run_dir/known_hosts" -o PreferredAuthentications=password \
            -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5 "$name@127.0.0.1" true >>"$run_dir/ssh-client.log" 2>&1
        rc=$?
        set -e
        [[ $rc == 5 || $rc == 255 ]] || { echo "Unexpected SSH result: $rc" >&2; exit 1; }
    done
elif [[ $scenario == S3 ]]; then
    # A valid recurring job with a harmless command. Remove it after collecting evidence.
    printf '* * * * * root /usr/bin/true # Wazuh lab %s\n' "$run_id" > "/etc/cron.d/$name"
    chmod 644 "/etc/cron.d/$name"
    created_cron=yes
    cp "/etc/cron.d/$name" "$run_dir/cron.txt"
    stat "/etc/cron.d/$name" > "$run_dir/cron-stat.txt"
    sleep 15
fi
sleep 3
if [[ $scenario == S1 ]]; then
    grep -F "Failed password for $name " /var/log/auth.log > "$run_dir/source.log" || true
    [[ $(wc -l < "$run_dir/source.log") -ge $attempts ]] || { echo 'Required SSH failures are absent from auth.log.' >&2; exit 1; }
elif [[ $scenario == S2 ]]; then
    grep -E "useradd.*new user: name=$name," /var/log/auth.log > "$run_dir/source.log"
else
    # --input-logs is required. Without it ausearch reads standard input when it is not a
    # terminal, so over SSH or from a script it reports no matches even though the events
    # are in the audit log.
    ausearch --input-logs -k wazuh_lab_cron -ts recent -i > "$run_dir/audit-context.log" || true
    grep -F "/etc/cron.d/$name" "$run_dir/audit-context.log" > /dev/null || { echo 'Cron audit context is missing.' >&2; exit 1; }
fi
echo "Source evidence saved in $run_dir. Check indexed Wazuh alerts to complete this run."
