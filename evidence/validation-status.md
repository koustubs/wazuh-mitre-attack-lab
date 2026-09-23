# Validation status

What has been verified, how, and what has not. Raw run output stays out of Git because it
carries account names and addresses; this file is the summary that can be committed.

The results in sections 1 to 4 were verified on 11 September 2026, against Wazuh 4.14.7 and OpenSearch
Dashboards 2.19.5, and the date is the verification rather than the last edit. The packaging
work since then changed how the lab is built and how the dashboard reads it; none of those
results have been re-run against a lab built the new way, and section 6 says what that leaves
open.

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
  not been exercised this way.
- Behaviour when the manager is under sustained load. All timings were measured on an idle lab.
- Anything outside S1 to S3. The rule set covers three behaviours by design and coverage claims
  should stay limited to the table in section 2.

## 6. Changed since these were verified

None of section 1 to 4 has been re-run against a lab built the way the current scripts build
one. The detections and the rules are untouched, so the results should hold, but "should" is
not "did" and this is the list of what a re-run would be covering.

- The Ubuntu guests now boot a cloud image and configure themselves from cloud-init. The
  previous guests were installed from an ISO. Same release, different image.
- The VirtualBox backend has never built a lab. Every result here was measured on Hyper-V.
  What has been checked is structural, and only that: both backend modules define the same
  seventeen functions with the same parameter names and the same mandatory arguments, both return
  the same fields from `Get-LabVmInfo` and `Get-LabNetworkInfo`, and `virtualbox.psm1` imports
  cleanly on a host with no VirtualBox installed. Nothing has run `VBoxManage`.
- The Windows endpoint is reached over OpenSSH rather than PowerShell Direct, which is what
  removed the obstacle to the two 100101 edge cases above. They are still not done.
- The manager is tuned after install: indexer heap sized to the profile, vulnerability
  detection off, syscollector lengthened. The five to seven second alert latency in section 2
  was measured before any of that.
- The lean profile gives the manager 4 GB, below Wazuh's published recommendation for an
  all-in-one deployment. Nothing here was measured on it.
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
