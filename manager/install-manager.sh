#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
# Addresses, hostnames and versions come from lab.config.json on the host. Write-GuestConfig.ps1
# turns it into this file and the seed builder installs it. The defaults below are the shipped
# values, so a script copied here by hand still runs; it just uses the shipped subnet.
lab_env=${LAB_ENV_FILE:-/etc/wazuh-lab/lab.env}
if [[ -r $lab_env ]]; then
    # shellcheck disable=SC1090
    . "$lab_env"
else
    echo "No $lab_env. Using the shipped defaults." >&2
fi
: "${LAB_MANAGER_HOST:=wazuh-manager}"
: "${LAB_GATEWAY:=172.29.70.1}"
: "${LAB_AGENT_ADDRS:=172.29.70.20 172.29.70.30}"
: "${LAB_WAZUH_VERSION:=4.14.7}"
: "${LAB_WAZUH_PKG_VERSION:=4.14.7-1}"

[[ $(hostname -s) == "$LAB_MANAGER_HOST" ]] || { echo "Run this on the $LAB_MANAGER_HOST lab VM." >&2; exit 1; }
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
curl --fail --silent --show-error --proto '=https' --tlsv1.2 "https://packages.wazuh.com/${LAB_WAZUH_VERSION%.*}/wazuh-install.sh" -o wazuh-install.sh
grep -Fx "readonly wazuh_version=\"$LAB_WAZUH_VERSION\"" wazuh-install.sh >/dev/null || {
    echo 'The upstream installer version changed. Review before installing.' >&2; exit 1;
}
sha256sum wazuh-install.sh > installer.sha256
# Restrict access before starting the platform. Keys are provisioned manually.
ufw default deny incoming >>"$log" 2>&1
ufw default allow outgoing >>"$log" 2>&1
ufw allow from "$LAB_GATEWAY" to any port 22 proto tcp >>"$log" 2>&1
ufw allow from "$LAB_GATEWAY" to any port 443 proto tcp >>"$log" 2>&1
# One rule per endpoint the profile actually builds. The lean profile has no Windows endpoint,
# so it gets no rule for one, rather than a rule for an address nothing answers on.
for agent_addr in $LAB_AGENT_ADDRS; do
    ufw allow from "$agent_addr" to any port 1514 proto tcp >>"$log" 2>&1
done
ufw --force enable >>"$log" 2>&1
bash wazuh-install.sh -a >>"$log" 2>&1
for package in wazuh-manager wazuh-indexer wazuh-dashboard; do
    [[ $(dpkg-query -W -f='${Version}' "$package") == "$LAB_WAZUH_PKG_VERSION" ]] || { echo "Unexpected $package version." >&2; exit 1; }
done
apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard >>"$log" 2>&1
echo 'Wazuh installed. Credentials and installer logs are in /root/wazuh-lab-install.'
echo 'Run configure-manager.sh next.'
