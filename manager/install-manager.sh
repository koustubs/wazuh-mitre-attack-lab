#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ $(hostname -s) == wazuh-manager ]] || { echo 'Run this on the wazuh-manager lab VM.' >&2; exit 1; }
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && $(dpkg --print-architecture) == amd64 ]] || {
    echo 'This setup targets Ubuntu 24.04 amd64.' >&2; exit 1;
}
[[ ! -d /var/ossec ]] || { echo 'Wazuh already exists. Use configure-manager.sh for rule updates.' >&2; exit 1; }
mkdir -p /root/wazuh-lab-install
cd /root/wazuh-lab-install
log=/root/wazuh-lab-install/install.log
trap 'echo "Installation failed. Details: $log" >&2' ERR
export DEBIAN_FRONTEND=noninteractive
apt-get update >>"$log" 2>&1
apt-get install -y curl ca-certificates ufw >>"$log" 2>&1
curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://packages.wazuh.com/4.14/wazuh-install.sh -o wazuh-install.sh
grep -Fx 'readonly wazuh_version="4.14.7"' wazuh-install.sh >/dev/null || {
    echo 'The upstream installer version changed. Review before installing.' >&2; exit 1;
}
sha256sum wazuh-install.sh > installer.sha256
# Restrict access before starting the platform. Keys are provisioned manually.
ufw default deny incoming >>"$log" 2>&1
ufw default allow outgoing >>"$log" 2>&1
ufw allow from 172.29.70.1 to any port 22 proto tcp >>"$log" 2>&1
ufw allow from 172.29.70.1 to any port 443 proto tcp >>"$log" 2>&1
ufw allow from 172.29.70.20 to any port 1514 proto tcp >>"$log" 2>&1
ufw allow from 172.29.70.30 to any port 1514 proto tcp >>"$log" 2>&1
ufw --force enable >>"$log" 2>&1
bash wazuh-install.sh -a >>"$log" 2>&1
for package in wazuh-manager wazuh-indexer wazuh-dashboard; do
    [[ $(dpkg-query -W -f='${Version}' "$package") == 4.14.7-1 ]] || { echo "Unexpected $package version." >&2; exit 1; }
done
apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard >>"$log" 2>&1
echo 'Wazuh installed. Credentials and installer logs are in /root/wazuh-lab-install.'
echo 'Run configure-manager.sh next.'
