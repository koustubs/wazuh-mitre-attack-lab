# 3. Prototype Technical Stack and Approach

**This stack is not confirmed for implementation. It needs further research, feasibility checks, and mentor review.** I have not deployed or tested the prototype yet.

> Left as submitted, which is why everything below is conditional. The stack was confirmed
> almost unchanged and built: see [docs/implementation.md](../implementation.md).
> Two things here did not survive contact, and both are marked where they appear.

## Proposed direction

To support the six cases and acceptance criteria in step 2, I propose a virtual lab with a central Wazuh deployment and separate Windows and Linux endpoints. I would use Wazuh's existing components and small scripts to make setup and testing repeatable.

The main alert path would be:

```text
Windows / Linux -> Agents -> Manager -> Filebeat -> Indexer
```

The manager, Filebeat, indexer, and dashboard would run together on the central Linux VM. Filebeat forwards generated alerts to the indexer, and the dashboard queries them for display.

I am targeting the 4.14.x branch, which is the current stable release. Wazuh 5.0 is still in beta and changes this path significantly: it removes Filebeat in favour of a built-in indexer connector and moves analysis out of the manager into the indexer. I am staying on 4.x for this project rather than building against a moving target.

## Candidate stack

| Area | Initial choice | Reason for considering it |
| --- | --- | --- |
| Lab environment | Hyper-V, three Gen 2 VMs, and an internal lab switch. | Separate the platform and endpoints, with checkpoints for endpoint resets. Hyper-V is already enabled on the host and is native to Windows 11 Pro. Its Gen 2 VMs supply TPM 2.0 and Secure Boot, which a Windows 11 guest requires. VirtualBox is ruled out, because it cannot run properly alongside an active Hyper-V hypervisor. |
| Central platform | Ubuntu Server 24.04 LTS and Wazuh `4.14.x` release, using an all-in-one installation. | Keep the manager, indexer, and dashboard together. |
| Windows endpoint | Windows 11, Wazuh agent, and selected Windows Security events. | Collect authentication, account-creation, and scheduled-task evidence with appropriate audit policies. |
| Linux endpoint | Ubuntu Server 24.04 LTS, Wazuh agent, authentication logs, Linux Audit, and targeted file monitoring. | Collect login, account-management, and cron evidence. Verify actual fields before writing rules. |
| Setup and testing | PowerShell, Bash, and Wazuh's rule-testing facility. | Make the Windows and Linux procedures repeatable. |
| Project records | Git, Markdown, PlantUML, and exported alert JSON; Python as an optional reporting helper. | Keep configuration, decisions, diagrams, and evidence together. |

Wazuh's Quickstart recommends 4 vCPU, 8 GiB RAM, and 50 GB storage for 1 to 25 agents and a 90-day alert-storage estimate. This is a reference for the central VM; endpoints, snapshots, and the host OS need additional resources. Retention still needs review. [This is the Wazuh Quickstart guidance on installation and resource requirements](https://documentation.wazuh.com/current/quickstart.html).

### Detection logic

Detection for S1 would use Wazuh's frequency options, with the ATT&CK mapping declared on the rule itself:

```xml
<rule id="100001" level="10" frequency="6" timeframe="120">
  <if_matched_sid>5716</if_matched_sid>
  <description>Repeated SSH authentication failures for the same account</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

Rule IDs, thresholds and the parent SID need confirming against my actual install.

> **Did not survive contact.** The parent SID above is wrong and the rule as written would
> never have fired. A `Failed password` line matches rule 5760, which is itself a child of
> 5716, so hanging a frequency rule off 5716 matches nothing. The built rule is 100111 with
> `<if_matched_sid>100110</if_matched_sid>`, where 100110 sits on 5760. Confirming the parent
> SID against a real install was the right instinct and it is why this was caught. See
> [lab_rules.xml](../../manager/lab_rules.xml).

## Working methods

I would combine three established approaches:

| Approach | How I would apply it |
| --- | --- |
| Iterative prototyping | Complete one scenario end to end, review it, and extend the setup to the remaining cases. |
| Threat-informed detection engineering | Start with an ATT&CK behaviour, identify observable events, define a detection, and test simulated and legitimate activity. |
| Detection as code | Keep rules, settings, sample events, and expected results in Git. Review changes and rerun affected cases. |

I would use short simulations of selected behaviours, drawing on [MITRE's approach to focused emulation plans](https://ctid.mitre.org/projects/micro-emulation-plans/).

Each rule and test record would link to its scenario and acceptance criteria from step 2.

## Proposed demonstration format

For each scenario, I would show Windows and Linux side by side: the action, source event, matched rule, ATT&CK mapping, alert, and legitimate comparison. Keeping the results before tuning would make improvements from configuration or rule changes visible.

A small Python script could assemble this report from exported alert JSON, checking the endpoint, time window, and expected rule result. Report automation is optional and needs review.

I would use `wazuh-logtest` for parsing and rule checks, followed by live endpoint tests to verify alert delivery. This would help distinguish missing telemetry from a rule that failed to match. [This is how Wazuh supports testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).

## Research and review before implementation

- Confirm host capacity, Windows VM requirements, and snapshot storage.
- Verify OS/Wazuh compatibility, audit settings, fields, and existing rules against actual events. Select the Windows login method and failure records for S1. Assess whether Windows needs additional process evidence from Sysmon.
- Review relevant Atomic Red Team tests, including prerequisites, actions, and cleanup. [This is the test library being considered](https://github.com/redcanaryco/atomic-red-team).
  > **Did not survive contact.** Atomic Red Team was not used. The three scenarios are small
  > enough to drive from purpose-written scripts that clean up after themselves
  > (`agents/linux/invoke-scenario.sh` and its Windows counterpart), and those also
  > run a benign comparison, which the library does not. Pulling in a dependency to execute
  > six commands would have added a supply chain to a lab that has none.
- Agree thresholds, retention, schedule, and report format. Define lab access controls, agent enrolment, and authenticated connections.