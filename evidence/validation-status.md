# Validation status

What has been verified, how, and what has not. Raw run output stays out of Git because it
carries account names and addresses; this file is the summary that can be committed.

Sections 1 and 3 were verified on 11 September 2026, against Wazuh 4.14.7 and OpenSearch
Dashboards 2.19.5, and the date is the verification rather than the last edit. Sections 2 and 4
were run again on 23 September 2026, on the same versions, against the full profile as the
current scripts build it. Section 6 lists what has changed since and has not been re-run.

## 1. Rule checks, synthetic

`tests/test_rules.py` against a real `wazuh-analysisd`. Results in `rule-checks.json`.

The Windows rules and the Linux cron rule cannot be reached this way, because their decoders are
compiled into the engine and selected by where an event came from rather than what it contains.
Those four are marked as errors rather than passes and are verified on live agents instead. The
harness runs a positive control per platform first, so a negative case cannot pass merely because
no rules loaded.

## 2. Live detection, six cases

Run on 23 September 2026 from the dashboard, against the full profile. Every case ran twice as
an attack and at least once as its comparison, and all six detected on both attack runs, with
the ATT&CK mapping resolved from the technique ID.

| Case | Rule | Level | ATT&CK | Alert after the run started |
| --- | --- | --- | --- | --- |
| S1 Windows, repeated failed logons | 100101 | 10 | T1110.001 Password Guessing | 10.8 s, 13.6 s |
| S2 Windows, local account created | 100102 | 6 | T1136.001 Local Account | 4.3 s, 6.7 s |
| S3 Windows, scheduled task created | 100103 | 6 | T1053.005 Scheduled Task | 4.7 s, 6.6 s |
| S1 Linux, repeated SSH failures | 100111 | 10 | T1110.001 Password Guessing | 26.0 s, 20.0 s |
| S2 Linux, local account created | 100112 | 6 | T1136.001 Local Account | 2.0 s, 3.1 s |
| S3 Linux, cron path modified | 100113 | 6 | T1053.003 Cron | 2.4 s, 2.5 s |

The times run from the dashboard accepting the run to the alert's own timestamp, so they include
the scenario's work. For S1 that is six failures, one second apart on Windows and two to four on
Linux. The manager's clock was 1.4 seconds ahead of the host's, which the figures do not correct.

The run produced 59 alerts from the lab's rules in the manager's `alerts.json`, detections and
the base alerts under S1 together. All 59 were found in the indexer, and every detection carried
its ATT&CK technique, tactic and ID there.

**The comparisons.** S1's comparison is one failed logon instead of six. On both endpoints and on
both runs it produced the single base alert, 100100 or 100110 at level 3, and no composite:
across the eight S1 runs, the four attacks alerted at level 10 and the four comparisons did not.
S2's and S3's comparison is the same action recorded as approved. The approval is in the
scenario's own record and not in the event, so the rule cannot see it, and both comparisons
alerted exactly as the attacks did. That is the reason S2 and S3 report activity for an analyst
to judge rather than claim an attack.

On 11 September the same six cases ran twice each on the lab as it was then built, with the same
result: all six detected, and across eight S1 accounts four attacks alerted and four benign runs
stayed silent.

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

**The window expires on Windows too, 23 September 2026.** Rule 100101 is also frequency 6 within
120 seconds, keyed on the account and its domain. `tests/s1-burst.ps1` ran nine failures against
one new local account, in three groups of three. The first two groups were 142 seconds apart, so
no window held six and nothing fired. The third started 106 seconds after the second,
the window then held six, and 100101 fired on the sixth, replacing that event's base alert as
100111 does.

| Phase | Failures | Gap before it | Base alerts | Composite |
| --- | --- | --- | --- | --- |
| A | 3 | n/a | 3 | none |
| B | 3 | 142s | 6 | none |
| C | 3 | 106s | 8 | fires |

The stock ruleset constrains the spacing. Rules 60204 and 60205 are frequency 8 within 240
seconds on the logon's source address, and a local network logon records that address as "-",
so every failure on the endpoint shares it whatever the account. Once any 240 second span holds
eight, the event goes to 60204 instead of 100100 and 100101 never counts it. Groups A and C were
254 seconds apart, no 240 second span held more than six, and 60204 did not fire.

The per-agent test cannot be repeated on Windows. 100101 keys on the account's domain as well as
its name, and a local account's domain is the computer's name, so the same account name on two
endpoints is already two keys before per-agent counting applies. It needs a domain account, and
the lab has no domain.

## 5. Not verified

- Whether 100101 counts per agent. With local accounts the domain already separates endpoints,
  so this needs a domain account (section 4).
- Sustained load on the full profile. Load was measured once on the lean profile, in section 2
  of the architecture notes; the timings in section 2 here are from an otherwise idle lab.
- Anything outside S1 to S3. The rule set covers three behaviours by design and coverage claims
  should stay limited to the table in section 2.

## 6. Changed since these were verified

Sections 2 and 4 were re-run on 23 September against a lab built the current way, on a Linux
endpoint booted from the Ubuntu cloud image and a Windows endpoint reached over OpenSSH. What
follows has not been re-run or exercised since it changed.

- The VirtualBox backend has never built a lab. Every result here was measured on Hyper-V.
  Both backend modules define the same seventeen functions with the same parameter names and the
  same mandatory arguments, and both return the same fields from `Get-LabVmInfo` and
  `Get-LabNetworkInfo`. The read paths, `Test-LabBackendAvailable`, `Get-LabVmInfo`,
  `Get-LabNetworkInfo` and `Test-LabNetworkConflict`, have run against VirtualBox 7.2.6 on the
  build host and answer correctly. The write paths, which create the network and the VMs, have
  not been run.
- The lean profile gives the manager 4 GB, below Wazuh's published recommendation for an
  all-in-one deployment. It was measured separately, idle and under load, and the figures are in
  section 2 of the architecture notes. The detection cases in section 2 here ran on the full
  profile.
- The dashboard reads alerts from the indexer rather than from a log tail, and scores each
  endpoint against its own baseline. Section 3 covers the presentation path as it was.

## 7. Retention fix, 22 September 2026

The source now checks yellow cluster health and retries temporary failures on the public ISM
API. It distinguishes a missing policy from a failed lookup, checks attachment responses as
JSON, and reads back the policy on existing alert indices. Different or disabled policies are
reported for review. Tuning exits nonzero on failure; the installer reports incomplete tuning
without treating an already completed Wazuh installation as failed.

Sixteen local tests pass, covering recovery responses, exhausted retries, authentication
failure, malformed JSON, existing attachments, missing policies, partial attachment, and
readback that contradicts an apparent success. Both changed shell scripts pass Bash syntax
checks. These checks do not establish that the fix works on the running manager.

The fix was then applied to the running manager, and one run is recorded. It reported the heap,
the disabled modules, and `retention already attached; verified on 1 indices`. That is the
idempotent path: the policy was already there, matched what the script asks for, and read back
on the one alert index present. Creating a policy, attaching one to an unmanaged index, and
every failure path are covered by the tests above and have not run on the manager.

## 8. Full profile, 23 September 2026

The full profile was built and stood up end to end for the first time: three guests reachable
over SSH and three agents Active, the manager as 000, `wazuh-linux` as 001 and `wazuh-windows`
as 002.

An earlier version of this file said the Windows endpoint had not survived a save and restore.
That diagnosis was wrong. The UEFI boot failure on its console was the firmware falling back
after nobody pressed a key at the DVD's boot prompt, and it had no address because Windows had
never been installed. Three defects in the build were responsible, and none of them raised an
error.

- `New-WindowsSeed.ps1` cleared `$productKey` before testing `$ProductKey`. PowerShell variable
  names are not case sensitive, so the two are one variable and `-ProductKey` had never taken
  effect. Setup stopped on the product key page.
- Windows media waits about five seconds at "Press any key to boot from CD or DVD" and then
  hands back to the firmware. `setup/Start-WindowsInstall.ps1` now starts the VM and presses the
  key through the backend's `Send-LabVmKey`.
- The answer file set the locale only in the windowsPE pass, which covers the installer, so
  OOBE stopped at its region and keyboard pages. It is now set in oobeSystem as well. This build
  was taken past those two pages by hand, so that fix has not been through a build yet.

OpenSSH Server's capability install took five and a half minutes on Windows 11 25H2 and wrote
nothing until it returned. The first-logon log now says so before it starts.

The six detection cases, their comparisons and the Windows frequency edge case then ran on this
build. The results are in sections 2 and 4.
