#!/usr/bin/env bash
# Development-only rule sandbox. Installs the packaged manager inside WSL Ubuntu so the real
# analysisd engine evaluates lab_rules.xml. This is not the lab VM and not live evidence.
#
# Replaces an earlier chroot approach that ran from /mnt/c. That could not work: DrvFs cannot
# chmod, so analysisd failed to initialise its FTS queue. A normal install on ext4 avoids this.
#
# Windows cases cannot pass here. The windows_eventchannel decoder is built into analysisd and
# is selected by event location, which only a real agent sets. They are reported as errors.
#
# Run as: wsl -d Ubuntu -u root --exec bash <this script>
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run as root: wsl -d Ubuntu -u root' >&2; exit 1; }

project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
deb=$project/.cache/wazuh-manager_4.14.7-1_amd64.deb
# Verified against the signed package index at packages.wazuh.com before caching.
expected=1edd93f49ea1d89edcb7c17eeec750e99f685bc9f88d3c71f7972267c9442de0

[[ -f $deb ]] || { echo "Cached package missing: $deb" >&2; exit 1; }
[[ $(sha256sum "$deb" | cut -d' ' -f1) == "$expected" ]] || {
    echo 'Cached package hash does not match the verified value.' >&2; exit 1;
}

if [[ $(dpkg-query -W -f='${Version}' wazuh-manager 2>/dev/null || true) != 4.14.7-1 ]]; then
    DEBIAN_FRONTEND=noninteractive dpkg -i "$deb"
fi

install -o root -g wazuh -m 640 "$project/manager/lab_rules.xml" \
        /var/ossec/etc/rules/wazuh_lab_rules.xml
/var/ossec/bin/wazuh-analysisd -t

# Idempotent: starting an already-running manager is a no-op.
/var/ossec/bin/wazuh-control start >/dev/null

python3 "$project/tests/test_rules.py" \
    --output "$project/evidence/rule-checks.json" \
    --command /var/ossec/bin/wazuh-logtest
