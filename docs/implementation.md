# 4. Implementation and Validation

**Status:** Complete. The lab is built, all six cases are detected on live endpoints with their
ATT&CK mappings, alerts render in the dashboard, delay is measured, retention is set, and the
frequency rule edge cases are characterised. R1 to R5 are met.

## Results

One Wazuh 4.14.7 manager and two enrolled agents, measured on Hyper-V. On VirtualBox only the lean
profile has been built, and its three Linux cases fired there as well; see section 10 of
`evidence/validation-status.md`. Every alert below came from a real endpoint action, not a
synthetic event.

| Case | Rule | Level | ATT&CK | Result |
| --- | --- | --- | --- | --- |
| S1 Windows, repeated failed logons | 100101 | 10 | T1110.001 Password Guessing | Detected |
| S2 Windows, local account created | 100102 | 6 | T1136.001 Local Account | Detected |
| S3 Windows, scheduled task created | 100103 | 6 | T1053.005 Scheduled Task | Detected |
| S1 Linux, repeated SSH failures | 100111 | 10 | T1110.001 Password Guessing | Detected |
| S2 Linux, local account created | 100112 | 6 | T1136.001 Local Account | Detected |
| S3 Linux, cron path modified | 100113 | 6 | T1053.003 Cron | Detected |

The tactic and technique names are not written into the rules. Wazuh resolves them from the
technique ID in the `<mitre>` block, so a correct ID is the whole mapping.

Windows alerts carry the initiating user, for example "account wzebbe02ffa4 created by labadmin"
and "scheduled task \WazuhLab-4268f11fbd created by labadmin". That is the context R3 asks for,
and it is what lets an analyst judge whether an account creation was routine administration.

## R4, telling the benign case apart

Each S1 scenario also ran in comparison mode, which makes a single failed logon instead of six.

| Platform | Account | Attempts | Threshold alert | Outcome |
| --- | --- | --- | --- | --- |
| Linux | wz6d0f61e0a2 | 1 | none | Correctly silent |
| Linux | wzf7356824a3 | 6 | 100111 | Correctly alerted |
| Windows | wz518d34d19c | 1 | none | Correctly silent |
| Windows | wzebbe02ffa4 | 6 | 100101 | Correctly alerted |

Wazuh fires the per-event rule for the first five failures and the composite rule on the sixth,
so six attempts show as five plus one rather than six plus one. Reading that as a shortfall is a
mistake I made once while checking these results.

All six cases were then run a second time. Both rounds produced the same result, and the
discrimination held across all eight S1 accounts: four attack runs alerted, four benign runs
stayed silent. That satisfies R2's requirement for two consecutive controlled runs.

Run records are in `evidence/live-runs/`.

## Faults found by running it for real

Four defects survived the synthetic checks and only appeared on live endpoints. All are fixed. A
fifth gap, in the dashboard rather than on the endpoints, is described under "Delivery through to
the dashboard" below.

**`ausearch` reads standard input when it is not a terminal.** `invoke-scenario.sh` called it
without `--input-logs`, so S3 reported "Cron audit context is missing" even though the events
were in the audit log. It would have worked by hand and failed in every automated run.

**The agent version guard rejected the correct version.** `ProductVersion` reports `v4.14.7`, and
the check compared against `4.14.7` without allowing the prefix, so a good install threw.

**`auditpol /get` does not take a wildcard subcategory.** The final line of `Install-Agent.ps1`
used `/get /subcategory:*`, which returns ERROR_INVALID_PARAMETER. `/get /category:*` is the
correct form. Everything before it had already succeeded, so the agent was configured and the
script still reported failure.

**The unattended Windows network command raced the adapter.** First logon ran before the
synthetic NIC reported Up, so the address was never applied and the endpoint sat on an APIPA
address. `New-WindowsSeed.ps1` now waits for the adapter.

## One environment constraint worth recording

Outbound port 80 is blocked on the network this lab was built on. Every plain-HTTP apt mirror
stalled at zero bytes while HTTPS hosts worked normally, which showed up as an apt download
running at 179 bytes per second. Ubuntu's default mirrors are HTTP only. Pointing apt at an
HTTPS mirror took the same fetch from 179 B/s to 4.2 MB/s. If this is rebuilt elsewhere, that
step may be unnecessary.

## Why the synthetic suite cannot cover every case

Two rule families are unreachable from `wazuh-logtest`. Both sit behind decoders compiled into
`wazuh-analysisd` rather than defined in XML, and both are selected by where the event came from
rather than what it contains.

| Rule family | Entry point | Decoder |
| --- | --- | --- |
| Windows 100100, 100102, 100103 | rule 60000 | `windows_eventchannel` |
| Linux cron 100113 | rules 550 and 554 | `syscheck_new_entry`, `syscheck_integrity_changed` |

I confirmed the second by sending a correctly shaped file integrity event to the running engine,
which returned "No decoder matched". These four rules are now verified on live agents instead,
which is the only way they can be.

The harness runs a positive control per platform before its cases. If the control cannot reach
that platform's seed rule, every case for the platform is marked an error rather than passed,
so a negative case cannot pass merely because no rules loaded.

## Two rule decisions worth noting

Rule 100110 hangs off 5760, not 5716. A "Failed password" event matches 5760, which is itself a
child of 5716, so a rule attached to 5716 never fires.

Rule 100111 duplicates built-in rule 5763 at first glance. 5763 is frequency 8 over 120 seconds
keyed on source IP alone and maps to parent technique T1110, so it also covers spraying across
many accounts. S1 is guessing against one account, so 100111 additionally requires `same_user`
and maps to T1110.001. Both are kept because they describe different behaviour.

## Building the lab

`setup.md` has the build order, host names and static addresses. The lab is created by
`setup/New-Lab.ps1`, on Hyper-V or VirtualBox, and every address and size it uses comes from
`lab.config.json`.

The Ubuntu guests boot the cloud image `setup/Get-LabImage.ps1` fetched and verified, and
configure themselves on first boot from the cloud-init seed `setup/New-LabSeeds.ps1` built. The
Windows endpoint is the one guest that still runs an installer, driven unattended by
`setup/New-WindowsSeed.ps1`.

That replaced an Ubuntu server ISO that had to be sourced by hand and an `autoinstall` directive
typed at the GRUB prompt through a framebuffer driver, which was about fifteen minutes of
installer per guest and the single most fragile step in the build.

## Delivery through to the indexer

Detection at the manager is not the same as an alert an analyst can find, so I checked the rest
of the path. The indexer reports green, and every lab alert is present and queryable with its
ATT&CK fields mapped rather than buried in a text blob.

| Check | Result |
| --- | --- |
| Indexer cluster health | green, 1 node, 23 active shards |
| Index | `wazuh-alerts-4.x-2026.09.11` |
| Lab rule documents indexed | 47, matching the manager's own counts exactly |
| Searchable ATT&CK fields | `rule.mitre.id`, `rule.mitre.tactic`, `rule.mitre.technique` |

The dashboard is reachable from the host only, because `configure-manager.sh` limits 443 to
172.29.70.1. That is deliberate.

## Delivery through to the dashboard

The port answering on 443 only proves the service is running. To check what an analyst would
actually see I authenticated to the dashboard as a real user and pulled the data back through it,
rather than querying the indexer directly.

| Check | Result |
| --- | --- |
| Dashboard login and session | HTTP 200, session cookie issued |
| Dashboard status | green, no plugin below green |
| Default index pattern | `wazuh-alerts-*`, 724 fields, time field `timestamp` |
| Discover rows | lab alerts with description, level, agent and ATT&CK |
| MITRE ATT&CK aggregation | tactics and techniques resolve, including all six lab techniques |
| Wazuh app to manager API | HTTP 200 through the dashboard's own bridge on port 55000 |

**This found a real gap, and it was the most misleading one in the project.** Wazuh does not
create an index pattern when it installs. One is created the first time somebody opens the web
UI. This lab was built entirely over SSH, so nobody ever had, and the saved object store held a
single configuration document and nothing else. Detection was working perfectly and every
dashboard screen would have rendered nothing at all. Anyone demonstrating this would have
concluded the detections had failed.

`manager/configure-dashboard.sh` now creates the index pattern and sets it as the default, as an
explicit build step. It resolves the field list the same way the UI does, so Discover can draw
columns and filters know which fields are keywords. It is safe to re-run.

## Frequency rule edge cases

Rule 100111 is frequency 6 within a 120 second window, keyed on the same account and the same
source. Two properties had never been tested. Both were tested with a control first, so that a
silent result could not be confused with a rule that never fires at all.

**The window expires.** Ten failures against one account from one source produced no composite
alert, because they came as two groups of five separated by 142 seconds and no 120 second window
ever held six. One further failure 51 seconds after the second group took that window to six and
the composite fired.

| Phase | Failures | Gap before it | Base alerts | Composite |
| --- | --- | --- | --- | --- |
| A | 5 | n/a | 5 | none |
| B | 5 | 142s | 10 | none |
| C | 1 | 51s | 10 | fires |

The base count stays at 10 after phase C because the composite replaced the base alert on the
event that triggered it, which is the same five plus one behaviour seen in the S1 runs.

**Counting is per agent, not global.** The same account name was created on two machines and both
bursts ran against loopback, so the account and the source address were identical on both and the
agent was the only variable. Six matching events inside 70 seconds, split three and three across
two agents, produced nothing. Three more on one of those agents alone took that single agent to
six and the composite fired, on that agent only.

| Step | Where | Failures | Events in window | Composite |
| --- | --- | --- | --- | --- |
| 1 | agent 000 | 3 | 3 | none |
| 2 | agent 002 | 3 | 6, split 3 and 3 | none |
| 3 | agent 002 | 3 | 6 on one agent | fires, agent 002 only |

That confirms the comment in `lab_rules.xml` that the same endpoint is implicit because
`global_frequency` is absent. It also sets a limit worth stating plainly: the rule will not
correlate one campaign spread thinly across several machines. For S1 as scoped in step 2, which
is guessing against a single account on a single host, that is the correct behaviour.

Reproduce with `tests/s1-burst.sh` on an endpoint and `tests/query-frequency.sh` on the manager.

## Alert delay, for R3

Measured by taking a timestamp on the endpoint immediately before the action, then polling the
indexer until the alert came back from a query.

| Case | Action to alert | Action to searchable |
| --- | --- | --- |
| S2 Linux, account created | 1s | 6s |
| S2 Windows, account created | 1s | 5s |
| S1 Windows, threshold reached | 6s | 15s |
| S1 Linux, threshold reached | 22s | 27s |

The S1 numbers are not detection latency. They start before the scenario does, so they include
generating six failures one second apart, and on Linux also generating a host key and starting a
throwaway sshd. The figure that matters is consistent across all four: roughly **one second from
the triggering event to the alert, and four to nine more seconds before a query returns it**.
That second gap is Filebeat's flush interval, not detection.

Proposed target for R3: **alerts searchable within 30 seconds of the triggering event.** Observed
worst case is 27 seconds including scenario setup, so this holds with margin while staying honest
about what was measured.

## Retention

Wazuh ships no retention policy, so `wazuh-alerts-*` would have grown until the disk filled. Step
3 costed the lab against a 90 day window but left the decision open, so I measured and then set
it.

- Average indexed alert: **5,093 bytes** (1,646 documents, 8.4 MB primary)
- Manager disk: 78 GB total, 45 GB free
- At a deliberately pessimistic 50,000 alerts per day, 90 days is roughly 22 GB

90 days therefore fits with room to spare, and matches the figure step 3 already used. An index
state management policy named `wazuh_lab_retention` now deletes `wazuh-alerts-*` indices at 90
days and is attached and enabled on the live index.

## Still outstanding

- The same two edge cases on the Windows rule 100101. The mechanism under test belongs to
  `wazuh-analysisd` and is shared by both rules, but 100101 keys on different fields and has not
  been exercised this way. The obstacle was that the Windows endpoint was reachable only through
  Hyper-V PowerShell Direct; it now runs OpenSSH like the Linux one, so this is outstanding work
  rather than a blocked path.
- All timings were measured on an idle lab. Behaviour under sustained load is unknown.
- The rule set covers three behaviours by design. Everything outside S1 to S3 is out of scope,
  and coverage claims should stay limited to what is in the results table above.
