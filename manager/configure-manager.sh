#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ $(hostname -s) == wazuh-manager ]] || { echo 'Run this on the wazuh-manager lab VM.' >&2; exit 1; }
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
for name in wazuh-windows wazuh-linux; do
    if ! awk -v name="$name" '$2 == name { found=1 } END { exit !found }' /var/ossec/etc/client.keys; then
        /var/ossec/bin/manage_agents -a any -n "$name" >>"$log" 2>&1
    fi
    awk -v name="$name" '$2 == name {print}' /var/ossec/etc/client.keys > "/root/wazuh-lab-keys/$name.key"
    [[ $(wc -l < "/root/wazuh-lab-keys/$name.key") == 1 ]] || { echo "Expected one key for $name." >&2; exit 1; }
done
systemctl restart wazuh-manager
systemctl is-active --quiet wazuh-manager
echo 'Manager rules and agent identities configured. Transfer each endpoint key privately over SSH.'
