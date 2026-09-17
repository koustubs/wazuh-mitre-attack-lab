#!/usr/bin/env bash
# Reports, for one test account, how many times each lab rule fired and on which agent.
# Used to read the result of a frequency rule edge case: the base rule 100110 counts the
# individual failures, and the composite rule 100111 is the one under test.
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: sudo bash query-frequency.sh <account>' >&2; exit 1; }
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ $(hostname -s) == wazuh-manager ]] || { echo 'Run this on the wazuh-manager lab VM.' >&2; exit 1; }
user=$1
password=$(grep -m1 'Password: ' /root/wazuh-lab-install/install.log | awk '{print $2}')
[[ -n $password ]] || { echo 'Could not read the indexer password.' >&2; exit 1; }

curl -sk -u "admin:$password" -H 'Content-Type: application/json' \
    "https://127.0.0.1:9200/wazuh-alerts-*/_search" -d "{
      \"size\": 0,
      \"query\": {\"bool\": {\"filter\": [
        {\"term\": {\"data.dstuser\": \"$user\"}},
        {\"range\": {\"rule.id\": {\"gte\": \"100110\", \"lte\": \"100111\"}}}]}},
      \"aggs\": {\"rule\": {\"terms\": {\"field\": \"rule.id\", \"order\": {\"_key\": \"asc\"}},
        \"aggs\": {\"agent\": {\"terms\": {\"field\": \"agent.id\"}},
                   \"first\": {\"min\": {\"field\": \"timestamp\"}},
                   \"last\": {\"max\": {\"field\": \"timestamp\"}}}}}}" \
| python3 -c "
import datetime as dt, json, sys
d = json.load(sys.stdin)
buckets = d['aggregations']['rule']['buckets']
if not buckets:
    print('  no lab alerts for this account yet')
for b in buckets:
    agents = ', '.join(f\"{a['key']}:{a['doc_count']}\" for a in b['agent']['buckets'])
    span = (b['last']['value'] - b['first']['value']) / 1000.0
    label = 'base failure' if b['key'] == '100110' else 'COMPOSITE'
    print(f\"  rule {b['key']} {label:<13} count={b['doc_count']:<3} agents[{agents}] span={span:.0f}s\")
"
