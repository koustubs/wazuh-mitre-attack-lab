# 2. Problem Statement and Scope

> Written before the build and left as submitted, so the requirements below are proposed rather
> than met. They were all met: see
> [docs/implementation.md](../implementation.md) for R1 to R5 against evidence,
> and [PROJECT-STATUS.md](../../PROJECT-STATUS.md) for what moved after this was written.
>
> One boundary below was later crossed on purpose. Machine learning is excluded from the first
> version, and [step 5](../../scoring/README.md) does it anyway, because the mentor
> raised it after this document was agreed. It sits outside the first version rather than
> inside it. Its result is narrower than "a model does not beat the rules": logistic
> regression does beat the best single rule, 0.251 average precision against 0.160, and it
> beats the tested sequence model on seven folds of eight. What does not hold up is the neural
> model. The portable version that can run on this lab scores 0.220, which is most of the
> full model rather than a fraction of it.

## Problem statement

The problem I want to address is how to turn Windows and Linux security events into useful, testable detections. Login attempts, account changes, and scheduled jobs appear in different logs, which can make suspicious activity difficult to recognise and investigate.

Following the three areas identified in step 1, I propose detecting repeated password-login failures, local account creation, and scheduled execution that could support persistence. I will use Wazuh to collect the events, map relevant alerts to MITRE ATT&CK, and retain supporting evidence. Controlled tests and legitimate comparisons will establish the demonstrated capabilities and limitations.

## Objective

My objective is a repeatable demonstration of three scenarios on both operating systems, supported by documented rules, ATT&CK mappings, and searchable alerts.

## Scope boundaries

I propose keeping the first version within the following boundaries:

| Included | Excluded from the initial release |
| --- | --- |
| One Windows endpoint, one Linux endpoint, and a central Wazuh deployment. | Production rollout, high availability, and enterprise-scale testing. |
| Required log collection and selected audit/file monitoring. | Broad network, cloud, or Active Directory monitoring. |
| Existing rules, justified custom rules, and ATT&CK mappings. | Full ATT&CK coverage, machine learning, and malware analysis. |
| Existing dashboard and evidence exports. | Custom frontend, separate application API, or replacement alert database. |
| Controlled demonstrations and benign comparison tests. | Automated blocking, isolation, and remediation. |

## Detection scenarios

Each scenario will have a Windows and Linux test, giving six cases. I will verify the required rules, audit settings, and event fields before implementation.

Event 4698 is not logged by default. It requires the "Audit Other Object Access Events" audit subcategory to be enabled, which I will configure as part of the Windows setup.

| ID | Behaviour and expected result | Windows evidence | Linux evidence | ATT&CK mapping |
| --- | --- | --- | --- | --- |
| S1 | Alert on repeated failed logons against one account within a defined threshold and time window. | Event ID 4625, using logon type, failure status codes and source address. | SSH failures in `/var/log/auth.log`, with account and source IP. | [T1110.001: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| S2 | Identify successful local account creation and the initiating user where available. | Event ID 4720. | `useradd` records in `/var/log/auth.log`, plus auditd context. | [T1136.001: Local Account](https://attack.mitre.org/techniques/T1136/001/) |
| S3 | Identify a new scheduled task or cron job for persistence review. | Event ID 4698, including the task definition XML. | Changes to `/etc/crontab`, `/etc/cron.*` and user crontabs, via file monitoring and auditd. | Windows: [T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/). Linux: [T1053.003: Cron](https://attack.mitre.org/techniques/T1053/003/). |

S1 addresses Credential Access; S2 and S3 focus on Persistence. Other uses of the scheduling techniques are outside these demonstrations.

For S2 and S3, I will report the observed action and context for review. These actions can be legitimate, and a generic file-change alert alone would not demonstrate either behaviour.

## Requirements and acceptance criteria

These are the checks I propose using to judge whether the first version is complete:

| ID | Requirement | Evidence of completion |
| --- | --- | --- |
| R1 | Collect the required evidence from both endpoints. | Received events contain the fields needed for S1 to S3. Missing telemetry is recorded as a gap. |
| R2 | Detect each behaviour with a justified ATT&CK mapping. | All six cases produce the expected rule result and mapping in two consecutive controlled runs. |
| R3 | Provide useful alert context. | Endpoint, timestamp, rule, severity, technique ID, and relevant account, source, task, or file details. |
| R4 | Evaluate legitimate activity and limitations. | Compare a mistyped password, approved account creation, and an approved scheduled job on each OS against the expected results below. |
| R5 | Make the demonstration reproducible. | Versioned configuration and rules, setup notes, and test records linking S1 to S3 with expected results and evidence. |

For R4, a single mistyped password below the S1 threshold should not trigger the repeated-failure alert. Approved account creation and scheduled jobs may correctly trigger S2 and S3 observation alerts. I will record them as legitimate activity; an alert alone will not be treated as proof of an attack.

I will test rules with sample events, then verify the complete path from live endpoint activity to searchable alerts.

I will measure alert delay and agree a timing target after establishing the lab baseline. Results will include missed cases and unwanted alerts, with conclusions limited to the tested conditions.

## Completion boundary and next step

I will consider the first version complete when R1 to R5 are demonstrated and limitations are documented. These requirements are proposed for review.
