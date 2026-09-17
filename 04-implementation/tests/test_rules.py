"""Synthetic rule regression inputs. These are never counted as live evidence."""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import subprocess


def windows(event_id, user='wztest01', domain='WAZUH-WIN', **fields):
    return json.dumps({'win': {
        'system': {'providerName': 'Microsoft-Windows-Security-Auditing',
                   'eventID': str(event_id), 'channel': 'Security', 'computer': 'WAZUH-WIN',
                   'severityValue': 'AUDIT_FAILURE' if event_id == 4625 else 'AUDIT_SUCCESS'},
        'eventdata': {'targetUserName': user, 'targetDomainName': domain,
                     'subjectUserName': 'labadmin', **fields}}}, separators=(',', ':'))


def failed(user='wztest01', domain='WAZUH-WIN', sub_status='0xc000006a'):
    return windows(4625, user, domain, subStatus=sub_status, status='0xc000006d', logonType='3', ipAddress='-')


def ssh(user='wztest01', ip='127.0.0.1'):
    return f'Sep 11 10:00:00 wazuh-linux sshd[1000]: Failed password for {user} from {ip} port 44000 ssh2'


# A negative case only means something if the rules it must not fire are actually loaded.
# Each platform therefore has to reach its seed rule before its cases are trusted.
def controls():
    return {'windows': ([failed()], '100100'),
            'linux': ([ssh()], '100110')}


def cases():
    return [
        ('windows_single', [failed()], '100100', '100101'),
        ('windows_below_threshold', [failed()] * 5, '100100', '100101'),
        ('windows_threshold', [failed()] * 6, '100101', None),
        ('windows_different_users', [failed(user=f'wztest{i}') for i in range(6)], '100100', '100101'),
        ('windows_different_domains', [failed(domain=f'HOST{i}') for i in range(6)], '100100', '100101'),
        ('windows_locked_account', [failed(sub_status='0xc0000234')] * 6, None, '100101'),
        ('windows_account_created', [windows(4720)], '100102', None),
        ('windows_account_enabled', [windows(4722)], None, '100102'),
        ('windows_task_created', [windows(4698, taskName='\\WazuhLab-test', taskContent='<Task/>')], '100103', None),
        ('linux_single', [ssh()], '100110', '100111'),
        ('linux_below_threshold', [ssh()] * 5, '100110', '100111'),
        ('linux_threshold', [ssh()] * 6, '100111', None),
        ('linux_different_users', [ssh(user=f'wztest{i}') for i in range(6)], '100110', '100111'),
        ('linux_different_sources', [ssh(ip=f'192.0.2.{i+1}') for i in range(6)], '100110', '100111'),
        ('linux_account_created', ['Sep 11 10:00:00 wazuh-linux useradd[1001]: new user: name=wztest01, UID=1002, GID=1002, home=/home/wztest01, shell=/bin/bash'], '100112', None),
    ]


def run(command, events):
    proc = subprocess.run(command, input='\n'.join(events)+'\n', text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45)
    return proc, re.findall(r"\bid: '([0-9]+)'", proc.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--command', nargs=argparse.REMAINDER, default=['/var/ossec/bin/wazuh-logtest'])
    args = parser.parse_args()

    checks = {}
    for platform, (events, expected) in controls().items():
        proc, ids = run(args.command, events)
        ok = proc.returncode == 0 and len(ids) == len(events) and ids[-1] == expected
        checks[platform] = {'passed': ok, 'expectedRule': expected,
                            'matchedRules': ids, 'exitCode': proc.returncode}
        if not ok:
            checks[platform]['diagnostic'] = proc.stdout[-12000:]
        print(f'control {platform}: {"PASS" if ok else "FAIL"}')

    results = []
    for name, events, expected, forbidden in cases():
        platform = name.split('_', 1)[0]
        if not checks[platform]['passed']:
            results.append({'case': name, 'status': 'error', 'passed': False,
                            'reason': f'{platform} positive control failed: the lab rules were '
                                      'not reached, so this case proves nothing either way'})
            print(f'{name}: ERROR')
            continue
        proc, ids = run(args.command, events)
        passed = (proc.returncode == 0 and len(ids) == len(events)
                  and (expected is None or ids[-1] == expected)
                  and (forbidden is None or forbidden not in ids))
        results.append({'case': name, 'status': 'pass' if passed else 'fail', 'passed': passed,
                        'matchedRules': ids, 'exitCode': proc.returncode})
        if not passed:
            results[-1]['diagnostic'] = proc.stdout[-12000:]
        print(f'{name}: {"PASS" if passed else "FAIL"}')

    tally = {state: sum(1 for item in results if item['status'] == state)
             for state in ('pass', 'fail', 'error')}
    print(f'\n{tally["pass"]} passed, {tally["fail"]} failed, {tally["error"]} errored '
          f'of {len(results)}')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'recordedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
        'kind': 'synthetic_rule_checks', 'command': args.command,
        'positiveControls': checks, 'tally': tally,
        'limitations': ['Not endpoint or indexing evidence', 'FIM needs a live agent baseline and change test',
                        'Time-window expiry and cross-agent separation still need live checks'],
        'results': results}, indent=2)+'\n')
    return 0 if tally['pass'] == len(results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
