# Project status and handover

**Updated:** 11 September 2026
**State:** Steps 1 to 4 complete. Lab is built and running. All six detection cases proven on
live endpoints, alerts confirmed rendering in the dashboard, and the frequency rule edge cases
characterised. Next phase is optimisation and packaging for one-click deployment.

This file records where the project started, everything that happened, where it stands now, and
what someone picking it up needs to know. It is written so that a person who has never seen the
repository can get oriented without reading the whole history.

---

## 1. Where this started

The brief was to implement threat detection using Wazuh and MITRE ATT&CK, following a four step
method set by the project mentor:

1. Understand and analyse context
2. Define scope and problem
3. Establish technical building blocks and stack
4. Build the functionality

The work had to be backend focused, documented to a professional standard, and concise enough
for a busy reviewer. Windows and Linux both had to be demonstrable.

Steps 1 to 3 were written as documents and sent to the mentor as a single PDF. He acknowledged
them with "Captured what was set out", which settled the scope. Step 4 is the build, and that is
what most of this file covers.

---

## 2. What each step contains

| Step | Folder | State |
| --- | --- | --- |
| 1. Context analysis | `01-context-analysis/` | Complete. Includes a rendered PlantUML system context diagram. |
| 2. Problem and scope | `02-scope-and-problem/` | Complete. Defines S1 to S3 and acceptance criteria R1 to R5. |
| 3. Technical design | `03-technical-design/` | Complete. Stack pinned to Wazuh 4.14.x with the 5.0 beta transition acknowledged. |
| 4. Implementation | `04-implementation/` | Complete. See `04-implementation/README.md` for full results. |

The PDF sent to the mentor is at `docs/Wazuh-Threat-Detection-Proposal.pdf` and covers steps 1
to 3 only. It predates the build and has not been regenerated.

---

## 3. The three detection scenarios

| ID | Behaviour | Windows evidence | Linux evidence | ATT&CK |
| --- | --- | --- | --- | --- |
| S1 | Repeated failed logons against one account | Event ID 4625 | SSH failures in `/var/log/auth.log` | T1110.001 Password Guessing |
| S2 | Local account creation | Event ID 4720 | `useradd` plus auditd | T1136.001 Local Account |
| S3 | Scheduled task or cron job created | Event ID 4698 | `/etc/cron.d` via FIM and auditd | T1053.005 / T1053.003 |

Six cases in total, one per scenario per operating system.

---

## 4. The lab as it stands

Three Hyper-V VMs on an internal switch with NAT. Everything was provisioned unattended.

| VM | Guest hostname | Address | Role |
| --- | --- | --- | --- |
| WAZUH-MANAGER | `wazuh-manager` | 172.29.70.10 | Wazuh manager, indexer, dashboard, all 4.14.7 |
| WAZUH-WIN | `WAZUH-WIN` | 172.29.70.20 | Windows 11 Pro, agent 001 |
| WAZUH-LINUX | `wazuh-linux` | 172.29.70.30 | Ubuntu 24.04.5, agent 002 |

Host is the gateway at 172.29.70.1. There is no DHCP on the switch, so all addresses are static
and the guest hostnames must match exactly. Every script checks its hostname and refuses to run
on the wrong machine, so a mismatch fails loudly rather than silently doing the wrong thing.

**Access.** SSH to the two Ubuntu machines as `labadmin` using the key in
`04-implementation/host/.lab-secrets/lab_ed25519`. Windows has no SSH; use Hyper-V PowerShell
Direct from an elevated host session, which needs no network at all.

**Credentials** live in `04-implementation/host/.lab-secrets/`, which is gitignored. It holds the
SSH keypair, a random 20 character console password, and the three unattended install images.
The Wazuh dashboard admin password is not stored there; it is in
`/root/wazuh-lab-install/install.log` on the manager.

**Firewall.** `install-manager.sh` restricts the manager with ufw, before the platform is
started: SSH and 443 only from the
host, and 1514 only from the two endpoint addresses. The dashboard is deliberately not reachable
from anywhere except the host.

---

## 5. Results

All six cases detected on live endpoints, twice, with ATT&CK mappings resolved by Wazuh from the
technique ID alone.

| Case | Rule | Level | ATT&CK |
| --- | --- | --- | --- |
| S1 Windows | 100101 | 10 | T1110.001 Password Guessing |
| S2 Windows | 100102 | 6 | T1136.001 Local Account |
| S3 Windows | 100103 | 6 | T1053.005 Scheduled Task |
| S1 Linux | 100111 | 10 | T1110.001 Password Guessing |
| S2 Linux | 100112 | 6 | T1136.001 Local Account |
| S3 Linux | 100113 | 6 | T1053.003 Cron |

**The benign comparison worked on both platforms.** Each S1 scenario also ran with a single
failed logon instead of six. Across all eight S1 accounts, four attack runs alerted and four
benign runs stayed silent. That discrimination is the point of the whole project.

**Delivery to the indexer is proven.** Cluster green, 47 lab-rule documents indexed with counts
matching the manager exactly, ATT&CK fields mapped as queryable fields rather than free text.

**Alerts render in the dashboard.** Checked by authenticating as a real user and pulling the data
back through the dashboard rather than straight from the indexer: Discover returns lab alerts
with description, level, agent and ATT&CK, the MITRE ATT&CK aggregation resolves all six lab
techniques, and the Wazuh app's bridge to the manager API answers. This step found the most
misleading defect in the project, described in section 6.

**Frequency rule edge cases are characterised.** The 120 second window genuinely expires: ten
failures split either side of the boundary produced nothing, and one more inside the live window
fired immediately. Counting is per agent, not global: six matching events split across two agents,
with the account and source address identical on both, produced nothing, while six on one agent
alone fired. Both tests were run with controls so that silence could not be mistaken for a rule
that never fires.

**Delay measured.** Roughly one second from the triggering event to the alert, and another four
to nine seconds before an indexer query returns it. The second gap is Filebeat's flush interval,
not detection. Proposed R3 target is 30 seconds, which holds with margin.

**Retention set.** Wazuh ships no retention policy, so the indices would have grown until the
disk filled. Measured 5,093 bytes per alert against 45 GB free, then created an index state
management policy `wazuh_lab_retention` that deletes `wazuh-alerts-*` at 90 days. It is attached
and enabled.

Against step 2's criteria: **R1 to R5 are met.**

---

## 6. Problems hit, and what fixed them

This section exists because most of these will recur for anyone rebuilding the lab.

### Defects in the project's own scripts

Four bugs survived the synthetic test suite and only appeared on live endpoints. All are fixed in
source.

| Problem | Cause | Fix |
| --- | --- | --- |
| S3 always reported "Cron audit context is missing" | `ausearch` reads standard input when it is not a terminal, so over SSH it saw nothing | Added `--input-logs` |
| A correct agent install threw a version error | `ProductVersion` reports `v4.14.7`, compared against `4.14.7` | Strip the leading `v` before comparing |
| Installer failed after everything had succeeded | `auditpol /get` does not accept a wildcard subcategory | Use `/get /category:*` |
| Windows endpoint sat on an APIPA address | First logon ran before the synthetic NIC reported Up | Wait for the adapter before assigning |

Earlier in the build, two rule defects were also fixed: rule 100110 was attached to SID 5716 when
"Failed password" actually matches child rule 5760, and the test harness was passing cases
vacuously when no rules had loaded.

### The dashboard would have shown nothing

Worth its own heading, because it is the failure most likely to embarrass someone demonstrating
this. Wazuh does not create an index pattern when it installs. One is created the first time
somebody opens the web UI. This lab was built entirely over SSH, so nobody ever had, and the
saved object store held one configuration document and nothing else. Detection, enrichment,
indexing and retention were all working correctly, and every dashboard screen would have rendered
a blank page. The natural conclusion on seeing that is that the detections failed, which would
have been wrong.

`manager/configure-dashboard.sh` now creates the index pattern and sets it as the default as an
explicit build step, resolving the field list the way the UI does so Discover can draw columns.
It is safe to re-run.

### Environment constraints on this host

**Outbound port 80 is blocked on this network.** Every plain HTTP apt mirror stalled at zero
bytes while HTTPS worked normally. This showed up as an apt download running at 179 bytes per
second. Ubuntu's default mirrors are HTTP only. Repointing apt at an HTTPS mirror
(`ubuntu.mirror.constant.com`) took the same fetch from 179 B/s to 4.2 MB/s. Both Ubuntu VMs are
now configured this way. On a different network this step may be unnecessary.

**WSL DNS was broken** and is now pointed at 1.1.1.1 via `/etc/wsl.conf` with
`generateResolvConf = false`. Reversible by deleting that file and `/etc/resolv.conf`.

**Hyper-V automatic checkpoints are on by default** in Windows 11, which puts every new VM on a
differencing disk. This caused a confusing disk chain on the Windows VM early on. All three lab
VMs now have automatic checkpoints disabled.

### Two things worth knowing about the tooling

**Windows Setup has no safe key to press.** Both Enter and Escape activate Cancel and open a quit
dialog, and keystrokes buffer while firmware loads, so keys sent early all land at once when the
UI appears. Send exactly one key for the "press any key to boot" prompt and then stop. This is
recorded in `host/LabConsole.ps1`.

**Passing shell commands inline through PowerShell to ssh is unreliable.** Quotes and backslashes
get mangled. One mangled `sed` expression silently corrupted scripts on the manager by stripping
the trailing letter from every line that ended in "r", turning `wazuh-manager` into
`wazuh-manage`. Transfer a script file and run it instead of building commands inline, and verify
transfers with a checksum.

---

## 7. Repository layout

```
wazuh-threat-detection/
  Lab.cmd                       front door: opens the dashboard
  README.md                     project overview
  PROJECT-STATUS.md             this file
  SECURITY.md                   what is excluded, and the pre-publication checklist
  docs/
    fresh-clone.md              what a clone does not contain, and how to rebuild it
  01-context-analysis/          step 1, with system context diagram
  02-scope-and-problem/         step 2, scenarios and acceptance criteria
  03-technical-design/          step 3, stack and approach
  04-implementation/
    README.md                   step 4 results, the main technical record
    deployment-guide.md         build order, hostnames, addresses
    host/
      New-LabSecrets.ps1        creates the SSH keypair and console password
      New-Lab.ps1               creates switch, NAT and three VMs
      New-LabSeeds.ps1          cloud-init seed ISOs for the Ubuntu machines
      New-WindowsSeed.ps1       autounattend ISO for Windows
      LabConsole.ps1            headless VM console over WMI
      Get-LabHost.ps1           host capacity preflight
      .lab-secrets/             gitignored: keys, password, seed images
      lab-dashboard/
        Start-LabDashboard.ps1  the dashboard server, and the lab up and down sequences
        dashboard.html          the page
        Enable-LabDashboard.ps1 one-time grant so it can read alerts, agents and the indexer
    manager/
      install-manager.sh        manager, indexer and dashboard pinned to 4.14.7, and the firewall
      configure-manager.sh      lab rules and agent identities
      configure-dashboard.sh    index pattern the UI needs in order to render anything
      lab_rules.xml             the six detection rules
    linux/                      agent install and scenario driver
    windows/                    agent install and scenario driver
    tests/
      fetch-engine-package.sh   re-fetches the pinned manager package a clone does not have
      test_rules.py             offline rule checks against a real engine
      s1-burst.sh               controlled failure bursts for frequency edge cases
      query-frequency.sh        reads back which rule fired, on which agent
    evidence/
      validation-status.md      what is verified and what is not, committable
      rule-checks.json          synthetic rule check output
      live-runs/                live run records
```

---

## 8. Rebuilding from scratch

1. Run `host/New-LabSecrets.ps1` to create the SSH keypair and console password. A clone has
   none, and every step below depends on them.
2. Run `host/New-Lab.ps1` from an elevated PowerShell with both installation ISOs.
3. Run `host/New-LabSeeds.ps1` and `host/New-WindowsSeed.ps1` to build the unattended images.
4. Attach the seeds as second DVD drives, then boot each machine.
5. For the two Ubuntu machines only, add `autoinstall` to the GRUB kernel line. `LabConsole.ps1`
   can do this without opening a console window. Everything after that is unattended.
6. Once the Ubuntu machines power themselves off, eject the media, set the boot order to disk,
   and start them.
7. On the manager, run `manager/install-manager.sh`, then `manager/configure-manager.sh`, then
   `manager/configure-dashboard.sh`. Do not skip the third: without it the dashboard renders
   nothing, however well detection is working.
8. Transfer each agent key and run the matching agent installer on each endpoint.
9. Run the scenarios.

`deployment-guide.md` has the detail. The full sequence is still not a single command.

---

## 9. What is outstanding

**Not done:**

- The two frequency edge cases on the Windows rule 100101. They are done for the Linux rule
  100111, and the mechanism under test belongs to `wazuh-analysisd` and is shared by both, but
  100101 keys on different fields and has not been exercised this way. The Windows endpoint is
  reachable only through Hyper-V PowerShell Direct, which needs an elevated host session.
- All timings were measured on an idle lab. Behaviour under sustained load is unknown.
- The rule set covers three behaviours by design. Coverage claims should stay limited to the six
  cases in the results table.

**Done since, in the packaging phase:**

- The project is a Git repository, built to the standard a public one needs from the first
  commit. No credential has ever been committed. `SECURITY.md` carries the checklist to run
  before making it public, including reading the mentor PDF, whose text cannot be scanned
  automatically.
- `host/New-LabSecrets.ps1` creates the credentials. Nothing in the repository did, which meant a
  clone stopped at step 2 with a confusing error, and the gap was invisible on the machine where
  the files already existed.
- `Lab.cmd` opens the dashboard, which is now the front door: one button brings the lab up in the
  right order and another takes it down in the reverse order.
- The dashboard reads detection coverage, the alert pipeline and the manager log, and can trigger
  any of the three scenarios on either endpoint.

**Still open:**

- A single command from bare ISOs. The remaining manual steps are the GRUB edit for Ubuntu
  autoinstall and the key transfer between manager and endpoints.

**Housekeeping:**

- The PDF for the mentor covers steps 1 to 3 and predates the build. If he wants the results, it
  needs regenerating to include step 4.
- `lab-dashboard/Enable-LabDashboard.ps1` replaces the staged sudo password chore. It grants a
  narrow, visudo-checked rule once and stores nothing.
- `sshpass` was installed on the manager so it could act as a second endpoint for the cross-agent
  test. `tests/s1-burst.sh` needs it on whichever machine runs a burst.
- The two Ubuntu VMs still have an unmerged differencing disk from the automatic checkpoint that
  existed before it was disabled. Harmless, but worth merging during cleanup.
