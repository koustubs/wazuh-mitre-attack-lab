#!/usr/bin/env bash
# Generates a controlled burst of SSH password failures for one account, using the same
# throwaway daemon technique as invoke-scenario.sh. Unlike that script this one takes the
# account and the count as arguments and leaves the account in place, so several bursts can be
# aimed at the same account with a chosen gap between them. That is what the frequency rule
# edge cases need: rule 100111 is frequency 6 within a 120 second window, so proving the window
# expires requires two bursts either side of that boundary.
#
# Read this before trusting a result from two bursts placed around that boundary. 100111's own
# 120 seconds is not the only window in play and it is not the longest. The stock ruleset
# correlates across bursts as well: 5551 is frequency 8 / timeframe 180, 40111 is 12 / 160, and
# 40501 is 4 / 300. Six failures is one burst's worth, so two bursts inside those spans reach
# thresholds one burst never does, and analysisd, which emits one alert per event, gives the
# event to the stock composite instead of to 100111.
#
# Measured: a second six-failure burst 45 seconds after the first produced no 100111 at all. It
# produced 5551, then 40111, then 40501 at level 15. The same burst after a five minute gap
# produced 100111 as expected. So a pair of bursts 130 seconds apart, which is the natural way
# to probe a 120 second boundary, will show the second one failing to alert for a reason that
# has nothing to do with the boundary being tested. Leave more than 300 seconds between a pair
# and anything before it, and read the rule ids rather than counting alerts.
set -euo pipefail
umask 077
[[ $# == 2 ]] || { echo 'Usage: sudo bash s1-burst.sh <account> <count>' >&2; exit 1; }
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
user=$1
count=$2
[[ $user =~ ^wzfreq[a-z0-9]+$ ]] || { echo 'Account must be named wzfreq*, to keep test accounts identifiable.' >&2; exit 1; }
[[ $count =~ ^[0-9]+$ && $count -ge 1 && $count -le 20 ]] || { echo 'Count must be 1 to 20.' >&2; exit 1; }

port=22222
dir=/run/wazuh-lab-freq/$user
mkdir -p "$dir" /run/sshd

if ! id "$user" >/dev/null 2>&1; then
    useradd --no-create-home --shell /usr/sbin/nologin --comment "Wazuh lab frequency test" "$user"
    password=$(python3 -c 'import secrets; print("Wz!9" + secrets.token_hex(20))')
    printf '%s:%s\n' "$user" "$password" | chpasswd
    unset password
fi

[[ -f $dir/host_key ]] || ssh-keygen -q -t ed25519 -N '' -f "$dir/host_key"
cat > "$dir/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $dir/host_key
PidFile $dir/sshd.pid
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
UsePAM yes
PermitRootLogin no
AllowUsers $user
MaxAuthTries 1
LogLevel VERBOSE
SyslogFacility AUTH
EOF
/usr/sbin/sshd -t -f "$dir/sshd_config"
/usr/sbin/sshd -D -f "$dir/sshd_config" &
sshd_pid=$!
trap 'kill "$sshd_pid" 2>/dev/null || true; wait "$sshd_pid" 2>/dev/null || true' EXIT
sleep 1
kill -0 "$sshd_pid"

read -r key_type key_value _ < "$dir/host_key.pub"
printf '[127.0.0.1]:%s %s %s\n' "$port" "$key_type" "$key_value" > "$dir/known_hosts"
printf '%s\n' 'DeliberatelyWrong!7' > "$dir/wrong-password"

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for ((i = 0; i < count; i++)); do
    set +e
    sshpass -f "$dir/wrong-password" ssh -p "$port" -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$dir/known_hosts" -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5 "$user@127.0.0.1" true >/dev/null 2>&1
    rc=$?
    set -e
    # 5 is authentication failure, 255 is the client giving up after the single prompt.
    [[ $rc == 5 || $rc == 255 ]] || { echo "Unexpected SSH result: $rc" >&2; exit 1; }
    sleep 1
done
printf 'BURST host=%s user=%s count=%s started=%s finished=%s\n' \
    "$(hostname -s)" "$user" "$count" "$started" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
