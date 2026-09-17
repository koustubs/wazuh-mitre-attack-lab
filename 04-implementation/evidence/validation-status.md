# Validation status

What has been verified, how, and what has not. Raw run output stays out of Git because it
carries account names and addresses; this file is the summary that can be committed.

Last updated 11 September 2026, against Wazuh 4.14.7 and OpenSearch Dashboards 2.19.5.

## 1. Rule checks, synthetic

`tests/test_rules.py` against a real `wazuh-analysisd`. Results in `rule-checks.json`.

The Windows rules and the Linux cron rule cannot be reached this way, because their decoders are
compiled into the engine and selected by where an event came from rather than what it contains.
Those four are marked as errors rather than passes and are verified on live agents instead. The
harness runs a positive control per platform first, so a negative case cannot pass merely because
no rules loaded.

## 2. Live detection, six cases

Every case run twice on real endpoints. All six detected with the ATT&CK mapping resolved from
the technique ID.

| Case | Rule | Level | ATT&CK |
| --- | --- | --- | --- |
| S1 Windows, repeated failed logons | 100101 | 10 | T1110.001 Password Guessing |
| S2 Windows, local account created | 100102 | 6 | T1136.001 Local Account |
| S3 Windows, scheduled task created | 100103 | 6 | T1053.005 Scheduled Task |
| S1 Linux, repeated SSH failures | 100111 | 10 | T1110.001 Password Guessing |
| S2 Linux, local account created | 100112 | 6 | T1136.001 Local Account |
| S3 Linux, cron path modified | 100113 | 6 | T1053.003 Cron |

Each S1 scenario also ran a benign single-failure comparison. Across all eight S1 accounts, four
attack runs alerted and four benign runs stayed silent.

## 3. Dashboard presentation path

Checked by authenticating to the dashboard as a real user and pulling data back through it,
rather than querying the indexer directly. Output in `dashboard-check.txt`, which is not
committed.

| Check | Result |
| --- | --- |
| Dashboard login and session | HTTP 200, session cookie issued |
| Dashboard status | green, no plugin below green |
| Default index pattern | `wazuh-alerts-*`, 724 fields, time field `timestamp` |
| Discover rows | lab alerts returned with description, level, agent and ATT&CK |
| MITRE ATT&CK aggregation | tactics and techniques resolve, including all six lab techniques |
| Wazuh app to manager API | HTTP 200 from the dashboard's own bridge on port 55000 |

This check found a real defect. Wazuh does not create an index pattern during installation; it is
created the first time somebody opens the web UI. The lab was built entirely over SSH, so no
index pattern existed and every dashboard screen would have rendered nothing, while detection at
the manager was working normally. `manager/configure-dashboard.sh` now creates it as an explicit
build step and is safe to re-run.

## 4. Frequency rule edge cases

Rule 100111 is frequency 6 within a 120 second window, keyed on the same account and the same
source. Two properties were untested until now. Both were tested with a control, so a silent
result cannot be mistaken for a rule that simply never fires.

**Control.** Six failures on one endpoint inside the window produced five base alerts and one
composite. The composite replaces the base alert on the triggering event, so six attempts show as
five plus one rather than six plus one.

**The window expires.** Ten failures against the same account from the same source produced no
composite alert, because they were split into two groups of five separated by 142 seconds and no
120 second window ever contained six. A single further failure 51 seconds after the second group
took that window to six and the composite fired immediately.

| Phase | Failures | Gap before it | Base alerts | Composite |
| --- | --- | --- | --- | --- |
| A | 5 | n/a | 5 | none |
| B | 5 | 142s | 10 | none |
| C | 1 | 51s | 10 | fires |

**Counting is per agent, not global.** The same account name was created on two machines and both
bursts ran against loopback, so the account and the source address were identical on both and the
agent was the only thing that differed. Three failures on one agent and three on the other, six
matching events inside a 70 second span, produced no composite. Three further failures on one of
those agents alone took that single agent to six and the composite fired, on that agent only.

| Step | Where | Failures | Events in window | Composite |
| --- | --- | --- | --- | --- |
| 1 | agent 000 | 3 | 3 | none |
| 2 | agent 002 | 3 | 6, split 3 and 3 | none |
| 3 | agent 002 | 3 | 6 on one agent | fires, agent 002 only |

This confirms the comment in `lab_rules.xml` that the same endpoint is implicit because
`global_frequency` is absent. It also means the rule will not correlate one campaign spread
thinly across several machines, which is a deliberate limit and worth stating rather than
leaving for someone to discover.

Reproduce with `tests/s1-burst.sh` on an endpoint and `tests/query-frequency.sh` on the manager.

## 5. Not verified

- The same two edge cases on the Windows rule 100101. The mechanism under test belongs to
  `wazuh-analysisd` and is shared by both rules, but rule 100101 keys on different fields and has
  not been exercised this way. The Windows endpoint is reachable only through Hyper-V PowerShell
  Direct, which needs an elevated host session.
- Behaviour when the manager is under sustained load. All timings were measured on an idle lab.
- Anything outside S1 to S3. The rule set covers three behaviours by design and coverage claims
  should stay limited to the table in section 2.
