#!/usr/bin/env bash
# Sizes the manager to the profile and turns off what this lab never uses.
#
# wazuh-install.sh -a accepts every default. Those defaults assume more memory than the lean
# profile hands the guest, and a deployment that queries things nothing here queries. Four
# changes, each reversible, each checked afterwards rather than assumed:
#
#   indexer heap             from the profile, instead of the shipped 1g
#   vulnerability detection  off, because it pulls a CTI feed this lab never reads
#   syscollector             1h to 12h, because these guests' package lists do not move
#   alert retention          an ISM policy, because Wazuh ships none and the disk fills
#
# Idempotent. Run it again after changing the profile and it will resize and say so.
#
# install-manager.sh runs this when it finds it alongside. Otherwise:
#
#     sudo bash tune-manager.sh
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }

lab_env=${LAB_ENV_FILE:-/etc/wazuh-lab/lab.env}
if [[ -r $lab_env ]]; then
    # shellcheck disable=SC1090
    . "$lab_env"
else
    echo "No $lab_env. Using the shipped defaults." >&2
fi
: "${LAB_INDEXER_HEAP_MB:=2048}"
# Not in lab.env. It is a retention decision rather than a machine one, and 90 days is what the
# project's own documentation claims; override it here or in the environment if that changes.
: "${LAB_ALERT_RETENTION_DAYS:=90}"

ossec=/var/ossec/etc/ossec.conf
certs=/etc/wazuh-indexer/certs
indexer=https://127.0.0.1:9200
[[ -f $ossec ]] || { echo "No $ossec. Run install-manager.sh first." >&2; exit 1; }

changed_manager=0

# ---- ossec.conf --------------------------------------------------------------------------------
#
# Both edits are restricted to the block they belong to. A bare substitution for
# <enabled>yes</enabled> would hit the indexer block four lines below it and take the manager
# off its own indexer.

cp -n "$ossec" "$ossec.lab-original" 2>/dev/null || true

if grep -q '<vulnerability-detection>' "$ossec"; then
    before=$(grep -c '<enabled>no</enabled>' "$ossec" || true)
    sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s|<enabled>yes</enabled>|<enabled>no</enabled>|' "$ossec"
    after=$(grep -c '<enabled>no</enabled>' "$ossec" || true)
    if [[ $after -gt $before ]]; then
        echo '  vulnerability detection off'
        changed_manager=1
    else
        echo '  vulnerability detection already off'
    fi
fi

if grep -q '<wodle name="syscollector">' "$ossec"; then
    if sed -n '/<wodle name="syscollector">/,/<\/wodle>/p' "$ossec" | grep -q '<interval>12h</interval>'; then
        echo '  syscollector already at 12h'
    else
        sed -i '/<wodle name="syscollector">/,/<\/wodle>/ s|<interval>[^<]*</interval>|<interval>12h</interval>|' "$ossec"
        echo '  syscollector interval 12h'
        changed_manager=1
    fi
fi

if [[ $changed_manager == 1 ]]; then
    systemctl restart wazuh-manager
    echo '  wazuh-manager restarted'
fi

# ---- indexer heap ------------------------------------------------------------------------------
#
# A drop-in rather than an edit to jvm.options. OpenSearch reads this directory after the shipped
# file, so these win, and a package upgrade does not quietly undo them.

dropin=/etc/wazuh-indexer/jvm.options.d/wazuh-lab.options
mkdir -p "$(dirname "$dropin")"
cat > "$dropin" <<OPTS
# Written by manager/tune-manager.sh from LAB_INDEXER_HEAP_MB in $lab_env.
# Delete this file and restart wazuh-indexer to go back to the shipped size.
-Xms${LAB_INDEXER_HEAP_MB}m
-Xmx${LAB_INDEXER_HEAP_MB}m
OPTS
chmod 0644 "$dropin"

if ps -eo args= | grep -F 'opensearch' | grep -q -- "-Xmx${LAB_INDEXER_HEAP_MB}m"; then
    echo "  indexer heap already ${LAB_INDEXER_HEAP_MB}m"
else
    systemctl restart wazuh-indexer
    # Checked from the running process rather than trusted. A drop-in the JVM never read is a
    # silent failure, and the symptom is an out-of-memory kill under load weeks later.
    running=0
    for _ in $(seq 1 45); do
        if ps -eo args= | grep -F 'opensearch' | grep -q -- "-Xmx${LAB_INDEXER_HEAP_MB}m"; then
            running=1
            break
        fi
        sleep 2
    done
    if [[ $running == 1 ]]; then
        echo "  indexer heap ${LAB_INDEXER_HEAP_MB}m"
    else
        echo "  WARNING: the indexer did not come back with -Xmx${LAB_INDEXER_HEAP_MB}m." >&2
        echo "  Check $dropin and 'journalctl -u wazuh-indexer'." >&2
    fi
fi

# ---- alert retention ---------------------------------------------------------------------------
#
# Authenticated with the indexer's admin certificate, the same way lab-dashboard-indexer is, so
# the admin password is neither read nor put on a command line.
#
# Deletion rather than rollover. Wazuh writes to date-named indices, wazuh-alerts-4.x-YYYY.MM.DD,
# not through a write alias, so a rollover action has nothing to roll. Age-based deletion is what
# actually keeps the disk from filling here.

curl_indexer() {
    curl -s --max-time 15 -k --cert "$certs/admin.pem" --key "$certs/admin-key.pem" "$@"
}

ready=0
for _ in $(seq 1 60); do
    if curl_indexer -o /dev/null -w '%{http_code}' "$indexer/_cluster/health" 2>/dev/null | grep -qE '^2'; then
        ready=1
        break
    fi
    sleep 2
done

if [[ $ready != 1 ]]; then
    echo '  WARNING: the indexer did not answer, so retention was not configured.' >&2
    echo "  Re-run this script once 'systemctl status wazuh-indexer' is green." >&2
    exit 0
fi

policy_id=wazuh-lab-retention
if curl_indexer -o /dev/null -w '%{http_code}' "$indexer/_plugins/_ism/policies/$policy_id" | grep -q '^200$'; then
    echo "  retention policy $policy_id already exists"
else
    body=$(cat <<JSON
{
  "policy": {
    "description": "Wazuh lab: delete alert indices after ${LAB_ALERT_RETENTION_DAYS} days.",
    "default_state": "hot",
    "states": [
      { "name": "hot",    "actions": [], "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "${LAB_ALERT_RETENTION_DAYS}d" } } ] },
      { "name": "delete", "actions": [ { "delete": {} } ], "transitions": [] }
    ],
    "ism_template": [ { "index_patterns": ["wazuh-alerts-*"], "priority": 100 } ]
  }
}
JSON
)
    response=$(curl_indexer -X PUT "$indexer/_plugins/_ism/policies/$policy_id" \
        -H 'Content-Type: application/json' -d "$body")
    if echo "$response" | grep -q '"_id"'; then
        echo "  retention policy $policy_id created, ${LAB_ALERT_RETENTION_DAYS} days"
    else
        echo "  WARNING: the indexer refused the retention policy: $response" >&2
    fi
fi

# ism_template only applies to indices created after the policy exists, so anything already here
# has to be attached by hand. A run on a fresh manager finds nothing to attach and says so.
attach=$(curl_indexer -X POST "$indexer/_plugins/_ism/add/wazuh-alerts-*" \
    -H 'Content-Type: application/json' -d "{\"policy_id\":\"$policy_id\"}")
attached=$(echo "$attach" | grep -o '"failures":false' || true)
if [[ -n $attached ]]; then
    echo '  policy attached to the alert indices that already exist'
else
    echo '  no existing alert index needed the policy'
fi

echo 'Tuning done.'
