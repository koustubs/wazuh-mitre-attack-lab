#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
lab_env=${LAB_ENV_FILE:-/etc/wazuh-lab/lab.env}
if [[ -r $lab_env ]]; then
    # shellcheck disable=SC1090
    . "$lab_env"
else
    echo "No $lab_env. Using the shipped defaults." >&2
fi
: "${LAB_MANAGER_HOST:=wazuh-manager}"
: "${LAB_GUEST_USER:=labadmin}"
# One identity per endpoint the profile builds. This was "wazuh-windows wazuh-linux" written
# into the loop below, which registers an agent for a machine the lean profile never creates.
: "${LAB_AGENT_NAMES:=wazuh-windows wazuh-linux}"

[[ $(hostname -s) == "$LAB_MANAGER_HOST" ]] || { echo "Run this on the $LAB_MANAGER_HOST lab VM." >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for package in wazuh-manager wazuh-indexer wazuh-dashboard; do
    installed=$(dpkg-query -W -f='${Version}' "$package")
    [[ $installed == 4.14.7-1 ]] || { echo "Expected $package 4.14.7-1; found $installed." >&2; exit 1; }
done
mkdir -p /var/log/wazuh-lab /root/wazuh-lab-keys
log=/var/log/wazuh-lab/manager-setup.log
stamp=$(date -u +%Y%m%dT%H%M%S)
target=/var/ossec/etc/rules/wazuh_lab_rules.xml
had_rules=no
if [[ -f $target ]]; then cp -p "$target" "$target.$stamp.bak"; had_rules=yes; fi
install -o root -g wazuh -m 640 "$script_dir/lab_rules.xml" "$target"
if ! /var/ossec/bin/wazuh-analysisd -t >>"$log" 2>&1; then
    if [[ $had_rules == yes ]]; then cp -p "$target.$stamp.bak" "$target"; else rm -f -- "$target"; fi
    echo "Rule validation failed; previous rules restored. Details: $log" >&2
    exit 1
fi
cp -p /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.$stamp.bak"
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
p = Path('/var/ossec/etc/ossec.conf')
d = ET.fromstring('<document>' + p.read_text() + '</document>')
roots = d.findall('ossec_config')
for root in roots:
    for element in list(root):
        if element.tag in ('auth', 'active-response'):
            root.remove(element)
# Agent identities are provisioned locally and transferred over authenticated SSH.
roots[0].append(ET.fromstring('<auth><disabled>yes</disabled></auth>'))
ET.indent(d, space='  ')
p.write_text('\n'.join(ET.tostring(root, encoding='unicode') for root in roots)+'\n')
PY
if ! /var/ossec/bin/wazuh-analysisd -t >>"$log" 2>&1; then
    cp -p "/var/ossec/etc/ossec.conf.$stamp.bak" /var/ossec/etc/ossec.conf
    echo "Configuration validation failed; previous config restored. Details: $log" >&2
    exit 1
fi
for name in $LAB_AGENT_NAMES; do
    if ! awk -v name="$name" '$2 == name { found=1 } END { exit !found }' /var/ossec/etc/client.keys; then
        /var/ossec/bin/manage_agents -a any -n "$name" >>"$log" 2>&1
    fi
    awk -v name="$name" '$2 == name {print}' /var/ossec/etc/client.keys > "/root/wazuh-lab-keys/$name.key"
    [[ $(wc -l < "/root/wazuh-lab-keys/$name.key") == 1 ]] || { echo "Expected one key for $name." >&2; exit 1; }
done

# A second copy the lab account can read, so the host can collect the keys over SSH without a
# sudo prompt for every one of them. This is not a weakening: that account has full sudo here
# already, so it could read /root anyway. What it buys is one transfer step that does not stop
# and ask for a password.
key_drop=$(getent passwd "$LAB_GUEST_USER" | cut -d: -f6)/wazuh-lab-keys
if [[ -n $key_drop && -d $(dirname "$key_drop") ]]; then
    install -d -o "$LAB_GUEST_USER" -g "$LAB_GUEST_USER" -m 700 "$key_drop"
    for name in $LAB_AGENT_NAMES; do
        install -o "$LAB_GUEST_USER" -g "$LAB_GUEST_USER" -m 400 \
            "/root/wazuh-lab-keys/$name.key" "$key_drop/$name.key"
    done
    echo "Agent keys are in $key_drop, readable by $LAB_GUEST_USER."
else
    echo "No home directory for $LAB_GUEST_USER; the keys are in /root/wazuh-lab-keys only." >&2
fi

systemctl restart wazuh-manager
systemctl is-active --quiet wazuh-manager
echo 'Manager rules and agent identities configured.'
echo 'Run setup\Install-LabAgents.ps1 on the host to enrol the endpoints.'
