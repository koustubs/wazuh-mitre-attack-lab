# Threat Detection Using Wazuh and MITRE ATT&CK

**Status:** Built and validated | **Updated:** 11 September 2026

I implemented selected endpoint detections on Windows and Linux using Wazuh, and used MITRE
ATT&CK to select the behaviours and describe the resulting alerts. The lab is running, all six
detection cases are proven on live endpoints, and alerts are searchable in the indexer.

## Project documents

| Step | Document | Status |
| --- | --- | --- |
| 1. Understand and analyse context | [Context analysis](01-context-analysis/context-analysis.md) and [system context diagram](01-context-analysis/system-context.png) | Complete |
| 2. Define scope and problem | [Problem statement and scope](02-scope-and-problem/problem-and-scope.md) | Complete |
| 3. Establish technical building blocks and stack | [Stack and approach](03-technical-design/README.md) | Complete |
| 4. Build the functionality | [Implementation and results](04-implementation/README.md) | Complete |

For the full picture including what was hit along the way and what comes next, read
[PROJECT-STATUS.md](PROJECT-STATUS.md). To rebuild the lab, start with the
[deployment guide](04-implementation/deployment-guide.md).

## What was built

One Wazuh 4.14.7 manager with indexer and dashboard, plus a Windows 11 and an Ubuntu 24.04
endpoint, each running an enrolled agent. All three VMs were provisioned unattended.

| Case | Rule | ATT&CK |
| --- | --- | --- |
| S1 repeated failed logons, Windows and Linux | 100101 / 100111 | T1110.001 Password Guessing |
| S2 local account creation, Windows and Linux | 100102 / 100112 | T1136.001 Local Account |
| S3 scheduled task or cron job, Windows and Linux | 100103 / 100113 | T1053.005 / T1053.003 |

Each case was demonstrated twice. Each S1 scenario also ran a benign single-failure comparison,
and in every case the benign run correctly stayed below the alert threshold while the six-attempt
run alerted. That discrimination is the result the project was built to produce.

Alerts reach the indexer in roughly five to seven seconds from the triggering event, with ATT&CK
technique, tactic and ID stored as searchable fields, and render in the dashboard with those
mappings resolved. A 90 day retention policy is in place.

The frequency rules were also tested at their edges. The 120 second window genuinely expires, and
counting is per agent rather than global, so the rule will not correlate one campaign spread
across several machines. Both results are recorded in
[validation status](04-implementation/evidence/validation-status.md).

## Scope

The rules cover three behaviours by design. Coverage claims are limited to the six cases above
and to the conditions they were tested under. S2 and S3 report observed activity for an analyst
to judge, because account creation and scheduled jobs are also normal administration.
