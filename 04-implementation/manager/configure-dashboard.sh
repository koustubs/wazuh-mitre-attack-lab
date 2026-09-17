#!/usr/bin/env bash
# Creates the saved objects the dashboard needs in order to render alerts.
#
# Detection at the manager is not the same as an alert an analyst can see. Without an index
# pattern the Discover and Threat Hunting screens render nothing at all, and Wazuh does not
# create one during installation: it is created the first time somebody opens the web UI. A lab
# that is driven entirely over SSH therefore ends up with a working detection pipeline and a
# blank dashboard, which is why this runs as an explicit step.
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ $(hostname -s) == wazuh-manager ]] || { echo 'Run this on the wazuh-manager lab VM.' >&2; exit 1; }

mkdir -p /var/log/wazuh-lab
log=/var/log/wazuh-lab/dashboard-setup.log
pattern='wazuh-alerts-*'
time_field=timestamp
dash=https://127.0.0.1:443
# One working directory for everything, so the trap cleans up on any exit path. The session
# cookie and the login body both hold credentials and must not be left in /tmp.
work=$(mktemp -d)
cookie=$work/cookie
trap 'rm -rf -- "$work"' EXIT

password=$(grep -m1 'Password: ' /root/wazuh-lab-install/install.log | awk '{print $2}')
[[ -n $password ]] || { echo 'Could not read the dashboard admin password.' >&2; exit 1; }

echo "=== waiting for the dashboard ===" | tee -a "$log"
up=no
for _ in $(seq 1 36); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$dash/api/status" || true)
    # 401 still means the service is answering; it just wants credentials.
    if [[ $code == 200 || $code == 401 ]]; then up=yes; break; fi
    sleep 5
done
[[ $up == yes ]] || { echo 'The dashboard did not become ready.' >&2; exit 1; }

echo "=== authenticating ===" | tee -a "$log"
LAB_PW=$password python3 - > "$work/login.json" <<'PY'
import json, os
print(json.dumps({'username': 'admin', 'password': os.environ['LAB_PW']}))
PY
code=$(curl -sk -o /dev/null -w '%{http_code}' -c "$cookie" -X POST "$dash/auth/login" \
    -H 'Content-Type: application/json' -H 'osd-xsrf: true' -d @"$work/login.json")
[[ $code == 200 ]] || { echo "Dashboard login failed with HTTP $code." >&2; exit 1; }

# The field list is what lets Discover draw columns and lets a filter know a field is a
# keyword rather than text. The UI fetches it from this endpoint when a pattern is created
# by hand, so do the same rather than leaving the index pattern with no fields.
echo "=== resolving the field list for $pattern ===" | tee -a "$log"
curl -sk -b "$cookie" -H 'osd-xsrf: true' -G "$dash/api/index_patterns/_fields_for_wildcard" \
    --data-urlencode "pattern=$pattern" \
    --data-urlencode 'meta_fields=_source' --data-urlencode 'meta_fields=_id' \
    --data-urlencode 'meta_fields=_type' --data-urlencode 'meta_fields=_index' \
    --data-urlencode 'meta_fields=_score' > "$work/fields.json"

python3 - "$pattern" "$time_field" "$work" <<'PY'
import json, sys
pattern, time_field, work = sys.argv[1], sys.argv[2], sys.argv[3]
fields = json.load(open(f'{work}/fields.json'))['fields']
names = {f['name'] for f in fields}
if time_field not in names:
    sys.exit(f'The time field {time_field} is not present on {pattern}.')
body = {'attributes': {
    'title': pattern,
    'timeFieldName': time_field,
    'fields': json.dumps(fields),
}}
with open(f'{work}/pattern.json', 'w') as handle:
    json.dump(body, handle)
mitre = sorted(n for n in names if n.startswith('rule.mitre.'))
print(f'  {len(fields)} fields resolved, ATT&CK fields: {mitre}')
PY

echo "=== creating the index pattern ===" | tee -a "$log"
code=$(curl -sk -o "$work/created.json" -w '%{http_code}' -b "$cookie" -H 'osd-xsrf: true' \
    -H 'Content-Type: application/json' -X POST \
    "$dash/api/saved_objects/index-pattern/$pattern?overwrite=true" -d @"$work/pattern.json")
[[ $code == 200 ]] || { echo "Creating the index pattern failed with HTTP $code: $(head -c 300 "$work/created.json")" >&2; exit 1; }

echo "=== setting it as the default ===" | tee -a "$log"
code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$cookie" -H 'osd-xsrf: true' \
    -H 'Content-Type: application/json' -X POST "$dash/api/opensearch-dashboards/settings" \
    -d "{\"changes\":{\"defaultIndex\":\"$pattern\",\"timepicker:timeDefaults\":\"{\\\"from\\\":\\\"now-7d\\\",\\\"to\\\":\\\"now\\\"}\"}}")
[[ $code == 200 ]] || { echo "Setting the default index pattern failed with HTTP $code." >&2; exit 1; }

echo "=== verifying ===" | tee -a "$log"
curl -sk -b "$cookie" -H 'osd-xsrf: true' \
    "$dash/api/saved_objects/_find?type=index-pattern&fields=title&per_page=50" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if d.get('total', 0) < 1:
    sys.exit('No index pattern is visible to the dashboard after creation.')
for o in d['saved_objects']:
    print('  index pattern:', o['attributes']['title'], '(id ' + o['id'] + ')')
"
echo "Dashboard configured. Details: $log"
