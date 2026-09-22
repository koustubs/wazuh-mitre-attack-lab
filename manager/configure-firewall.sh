#!/usr/bin/env bash
# The manager's firewall, applied from the profile.
#
# This was eleven lines inside install-manager.sh, run once, before Wazuh was installed, which
# made it unreachable afterwards. Changing the profile from lean to full adds a Windows endpoint
# the manager will not accept a connection from, and the only way to re-apply the rule was to
# re-run the installer, which reinstalls Wazuh. The symptom is an agent that never checks in
# against a manager whose logs say nothing, because the packets never arrived.
#
# Idempotent, and it removes rules for endpoints the profile no longer builds as well as adding
# ones for endpoints it has gained. Going from full back to lean should not leave 1514 open to
# an address nothing answers on any more.
#
# install-manager.sh runs this before it installs anything. Otherwise, after a profile change:
#
#     sudo bash configure-firewall.sh
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }

lab_env=${LAB_ENV_FILE:-/etc/wazuh-lab/lab.env}
if [[ -r $lab_env ]]; then
    # shellcheck disable=SC1090
    . "$lab_env"
else
    echo "No $lab_env. Using the shipped defaults." >&2
fi
: "${LAB_GATEWAY:=172.29.70.1}"
: "${LAB_AGENT_ADDRS:=172.29.70.20 172.29.70.30}"

command -v ufw >/dev/null || { echo 'ufw is not installed.' >&2; exit 1; }

ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null

# The host reaches SSH and the web interface. Nothing else does.
ufw allow from "$LAB_GATEWAY" to any port 22 proto tcp >/dev/null
ufw allow from "$LAB_GATEWAY" to any port 443 proto tcp >/dev/null

# What 1514 is currently open to, so the difference against the profile can be applied rather
# than assumed. Read before anything is changed.
existing=$(ufw status | awk '$1 == "1514/tcp" && $2 == "ALLOW" { print $3 }' | sort -u)

for addr in $existing; do
    if ! printf '%s\n' $LAB_AGENT_ADDRS | grep -qxF "$addr"; then
        ufw delete allow from "$addr" to any port 1514 proto tcp >/dev/null
        echo "  1514 closed to $addr, which this profile does not build"
    fi
done

for addr in $LAB_AGENT_ADDRS; do
    if printf '%s\n' $existing | grep -qxF "$addr"; then
        echo "  1514 already open to $addr"
    else
        ufw allow from "$addr" to any port 1514 proto tcp >/dev/null
        echo "  1514 opened to $addr"
    fi
done

ufw --force enable >/dev/null

# Checked rather than assumed. An enable that silently did nothing leaves the manager wide open,
# and the install that follows would not notice.
ufw status | grep -q '^Status: active' || { echo 'ufw did not come up active.' >&2; exit 1; }
for addr in $LAB_AGENT_ADDRS; do
    ufw status | awk '$1 == "1514/tcp" && $2 == "ALLOW" { print $3 }' | grep -qxF "$addr" ||
        { echo "1514 is still not open to $addr." >&2; exit 1; }
done
echo "Firewall applied for the ${LAB_PROFILE:-unknown} profile."
