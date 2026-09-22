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
: "${LAB_LINUX_HOST:=wazuh-linux}"
: "${LAB_WAZUH_PKG_VERSION:=4.14.7-1}"

[[ $(hostname -s) == "$LAB_LINUX_HOST" ]] || { echo "Run this on the $LAB_LINUX_HOST lab VM." >&2; exit 1; }
[[ $# == 2 ]] || { echo 'Usage: sudo bash install-agent.sh MANAGER_IPV4 AGENT_KEY_FILE' >&2; exit 1; }
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && $(dpkg --print-architecture) == amd64 ]] || {
    echo 'This setup targets Ubuntu 24.04 amd64.' >&2; exit 1;
}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
manager=$1
key_file=$(realpath -- "$2")
python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$manager"
[[ -s $key_file ]] || { echo 'The agent key file is missing.' >&2; exit 1; }
mkdir -p /var/log/wazuh-lab
log=/var/log/wazuh-lab/agent-setup.log
trap 'echo "Setup failed. Details: $log" >&2' ERR
export DEBIAN_FRONTEND=noninteractive
apt-get update >>"$log" 2>&1
apt-get install -y ca-certificates curl gnupg rsyslog auditd openssh-server sshpass cron >>"$log" 2>&1
curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /var/tmp/wazuh-lab-signing-key
gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh-lab.gpg /var/tmp/wazuh-lab-signing-key
chmod 644 /usr/share/keyrings/wazuh-lab.gpg
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/wazuh-lab.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh-lab.list
chmod 644 /etc/apt/sources.list.d/wazuh-lab.list
apt-get update >>"$log" 2>&1
apt-get install -y "wazuh-agent=$LAB_WAZUH_PKG_VERSION" >>"$log" 2>&1
apt-mark hold wazuh-agent >>"$log" 2>&1
systemctl stop wazuh-agent
# Ubuntu's packaged rsyslog configuration routes auth/authpriv to auth.log.
# Refuse a customized image lacking that route instead of silently duplicating it.
if ! grep -Eq '^[^#]*auth[^#]*/var/log/auth.log' /etc/rsyslog.d/50-default.conf; then
    echo 'Restore the Ubuntu auth.log route in rsyslog before continuing.' >&2; exit 1
fi
systemctl enable --now rsyslog auditd cron >>"$log" 2>&1
mkdir -p /var/spool/cron/crontabs
chmod 1730 /var/spool/cron/crontabs
chown root:crontab /var/spool/cron/crontabs
cat > /etc/audit/rules.d/wazuh-lab.rules <<'EOF'
-w /etc/passwd -p wa -k wazuh_lab_accounts
-w /etc/shadow -p wa -k wazuh_lab_accounts
-w /etc/crontab -p wa -k wazuh_lab_cron
-w /etc/cron.d/ -p wa -k wazuh_lab_cron
-w /etc/cron.hourly/ -p wa -k wazuh_lab_cron
-w /etc/cron.daily/ -p wa -k wazuh_lab_cron
-w /etc/cron.weekly/ -p wa -k wazuh_lab_cron
-w /etc/cron.monthly/ -p wa -k wazuh_lab_cron
-w /var/spool/cron/crontabs/ -p wa -k wazuh_lab_cron
EOF
augenrules --load >>"$log" 2>&1
python3 "$script_dir/configure_agent.py" --manager "$manager" --key-file "$key_file"
chown root:wazuh /var/ossec/etc/client.keys
/var/ossec/bin/wazuh-logcollector -t >>"$log" 2>&1
/var/ossec/bin/wazuh-syscheckd -t >>"$log" 2>&1
systemctl enable --now wazuh-agent >>"$log" 2>&1
echo 'Linux agent configured. Wait for the first FIM scan before testing cron changes.'
