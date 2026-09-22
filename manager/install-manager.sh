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
: "${LAB_BACKEND:=hyperv}"
: "${LAB_MANAGER_VM:=WAZUH-MANAGER}"

[[ $(hostname -s) == "$LAB_MANAGER_HOST" ]] || { echo "Run this on the $LAB_MANAGER_HOST lab VM." >&2; exit 1; }
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && $(dpkg --print-architecture) == amd64 ]] || {
    echo 'This setup targets Ubuntu 24.04 amd64.' >&2; exit 1;
}
[[ ! -d /var/ossec ]] || { echo 'Wazuh already exists. Use configure-manager.sh for rule updates.' >&2; exit 1; }
# The Wazuh installation assistant refuses to install below 3700 MB of usable memory or two
# cores, and it does so after this script has already run apt and downloaded the installer.
# Checked here instead, because the failure this catches does not look like a memory problem
# from the outside.
#
# The case that produces it: Hyper-V dynamic memory reclaims an idle guest down to its floor,
# so a manager created with 4096 MB of startup memory is running on its minimum by the time
# anyone gets round to installing. free reports what the balloon left, not what the VM was
# created with, and the assistant reads free.
mem_mb=$(free -m | awk '/^Mem:/{print $2}')
cores=$(nproc)
if (( mem_mb < 3700 || cores < 2 )); then
    echo "This guest has ${mem_mb} MB of usable memory and ${cores} core(s)." >&2
    echo 'The Wazuh installation assistant wants 3700 MB and 2 cores and will refuse.' >&2
    if [[ $LAB_BACKEND == hyperv ]]; then
        echo >&2
        echo 'If the VM was created with more than this, dynamic memory has reclaimed it. The' >&2
        echo 'floor can only be raised while the VM is off. On the host, elevated:' >&2
        echo >&2
        echo "  Stop-VM -Name $LAB_MANAGER_VM -Force" >&2
        echo "  Set-VMMemory -VMName $LAB_MANAGER_VM -MinimumBytes 4GB -StartupBytes 4GB" >&2
        echo "  Start-VM -Name $LAB_MANAGER_VM" >&2
        echo >&2
        echo 'To keep it raised across a rebuild, set minMemoryMb for this VM in lab.config.json.' >&2
    else
        echo 'Raise the memory for this VM in lab.config.json and rebuild it.' >&2
    fi
    exit 1
fi
# Resolved before the cd below, not after it. readlink -f resolves a relative path against
# the current directory, and $0 is relative for the documented invocation, which is
# "sudo bash manager/install-manager.sh" from the home directory. Asked after the cd, it
# answered /root/wazuh-lab-install/manager/install-manager.sh, so the tuning step below found
# no tune-manager.sh beside it and skipped itself on every run, whatever had been copied over.
here="$(dirname "$(readlink -f "$0")")"
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

# The installer accepts every default, which is not the right size for this guest and leaves
# modules running that nothing here reads. Run the tuning if it was copied across; say so if it
# was not, rather than leaving an untuned manager looking finished.
tune="$here/tune-manager.sh"
if [[ -r $tune ]]; then
    echo 'Tuning for this profile:'
    bash "$tune"
else
    echo 'tune-manager.sh is not beside this script, so the indexer heap, the disabled modules'
    echo 'and the alert retention policy have not been applied. Copy it over and run it.'
fi

echo 'Run configure-manager.sh next.'
