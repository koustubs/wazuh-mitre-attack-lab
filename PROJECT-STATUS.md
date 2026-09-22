# Project status and handover

**Updated:** 21 September 2026
**State:** Steps 1 to 4 complete. Lab is built and running. All six detection cases proven on
live endpoints, alerts confirmed rendering in the dashboard, and the frequency rule edge cases
characterised. A fifth step beyond the brief, detection modelling, has been measured and
reported: a sequence model does not beat logistic regression on 2.6 million real alerts. A
portable version of the winning model now scores live alerts on the lab dashboard, and the
whole of step 5 is written up as a PDF. Remaining work is packaging and presentation.

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
| 5. Detection modelling | `05-detection-modelling/` | Beyond the brief. Measured and reported. See section 5b. |

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

## 5b. Detection modelling, and what it found

Beyond the brief. The mentor raised using PyTorch to find patterns. That was worth testing
properly rather than answering with an opinion, and testing it properly meant having data,
a baseline, and an evaluation that could not flatter whatever got built.

The data problem was the real one. The lab had nine recorded runs. Two routes were built:
`04-implementation/linux/run-campaign.sh` to generate a night of labelled episodes here, and
`05-detection-modelling/import-ait.py` to import the
[AIT Alert Data Set](https://zenodo.org/records/8263181), 2.6 million real Wazuh alerts from
eight simulated enterprise networks under CC-BY. The public route was taken first because it
was an afternoon rather than a night, and because eight independent networks is a stronger
test than one host.

Each network held out in turn, trained on the other seven:

| | f1 | average precision |
| --- | --- | --- |
| best single Wazuh rule | 0.245 (sd 0.134) | 0.161 (sd 0.092) |
| logistic on shape and severity, deployed | 0.192 (sd 0.107) | 0.177 (sd 0.080) |
| GRU over the alert sequence | 0.180 (sd 0.112) | 0.199 (sd 0.081) |
| logistic regression on counts and timing | **0.292** (sd 0.121) | **0.249** (sd 0.097) |
| random | | 0.021, the base rate |

**Logistic regression wins all eight folds. The GRU wins none, mean margin -0.049.** A sequence
model is not justified for this problem on this evidence.

Four things that should be read with it:

- **The winner cannot be deployed here, and the second row is what was.** The full feature set
  is one column per AIT rule id, and this lab shares two signatures with AIT out of thirty one,
  so on live lab alerts it would put everything in the unknown column. The deployed model drops
  every rule count and keeps eleven columns describing the shape and severity of a window. It
  holds 71% of the full model and still beats the best single rule. The 0.072 it gives up is the
  measured price of portability, and that the price is that high says most of the signal was in
  which rules fired rather than in the shape of the burst.
- **Nothing here is deployable as an alerting rule.** On its best fold, wheeler, 1,166 windows
  holding 16 attack windows, the winner keeps perfect precision down to recall 0.375: six caught
  and nothing false. Pushed to catch half, precision falls to 0.063, so eight real attacks arrive
  with 119 false positives. That is what a 2% base rate does, and it is the honest state of the
  art here rather than a failure of the modelling.
- **The synthetic results were measuring the generator.** On `make-synthetic.py` output every
  model scored near the ceiling, logistic at f1 1.000. The same model scores 0.249 average
  precision on real alerts. Synthetic numbers in this repo are evidence the code runs, nothing
  more, and the modelling README says so.
- **This does not test the lab's own rules.** No public dataset contains 100100 to 100113;
  5501 and 5502 are the entire overlap with AIT. Whether these six rules separate an attacker
  from an administrator in sequence is still open, and `run-campaign.sh` is what would answer
  it. That is now a specific question rather than a blocker, and the pipeline it would feed is
  built and proven.

The deployed model runs inside the dashboard's existing SSH poll, scoring the last twelve five
minute windows on every cycle at 4 ms for a full 800 record sample, with nothing installed on
the manager. `05-detection-modelling/export-model.py` writes the eight fold result into the
model file itself, and the panel prints it, because a weights file with no measurement attached
gets trusted more than it has earned. The panel also states permanently that the model has
never been measured on this lab.

All of step 5 is written up in [docs/Detection-Modelling-Report.pdf](docs/Detection-Modelling-Report.pdf),
seven pages, rebuilt by `05-detection-modelling/report/Build-Report.ps1`. Every figure in it is
read from a measurement artefact or produced by a run the build makes itself. Writing it caught
a real error: the operating point above had been quoted with two figures from different splits
in the same sentence.

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
    collecting-a-dataset.md     how to record a labelled campaign, and when it is worth it
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
      Sync-LabCampaign.ps1      pulls campaign records off the endpoint as they are written
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
    linux/                      agent install, scenario driver, and run-campaign.sh
    windows/                    agent install and scenario driver
    tests/
      fetch-engine-package.sh   re-fetches the pinned manager package a clone does not have
      test_rules.py             offline rule checks against a real engine
      test_dashboard_scoring.py runs the dashboard's manager script on fabricated alerts,
                                with no lab up, and checks the severity path end to end
      s1-burst.sh               controlled failure bursts for frequency edge cases
      query-frequency.sh        reads back which rule fired, on which agent
    evidence/
      validation-status.md      what is verified and what is not, committable
      rule-checks.json          synthetic rule check output
      live-runs/                live run records
      campaigns/                gitignored: records pulled off the endpoint by Sync-LabCampaign
  05-detection-modelling/
    README.md                   step 5, the measured answer on whether a model beats the rules
    alert_stream.py             the episode contract and the vocabulary a dataset carries
    import-ait.py               the AIT alert data set into episodes
    make-synthetic.py           stand-in alert stream, the only source with the lab's own rules
    features.py                 episodes into model input, the splits, the metrics
    baseline.py                 one rule, the degenerate classifier, logistic regression
    train.py                    embedding, GRU and linear head, in PyTorch
    evaluate.py                 leave one network out, across all eight
    export-model.py             fits the portable model, with its measurement inside the file
    scorer/                     score.py and model.json, the part that leaves this machine
    report/                     builds docs/Detection-Modelling-Report.pdf from the artefacts
    data/, models/              gitignored: rebuilt by the scripts above
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
- `Enable-LabDashboard.ps1` was run against the live lab on 21 September and completed. Both VMs
  report `labadmin` added to the `wazuh` group, `lab-dashboard-indexer`, `lab-dashboard-creds`
  and `lab-scenario` installed, and a validated sudoers file on each. Its own closing check
  answers yes to agent state, indexer summary and the alert log.

Alert sequence scoring went onto the dashboard on 21 September: the manager buckets its own
recent alerts into five minute windows and scores each with the portable model, inside the
SSH poll that was already happening. Verified offline against the substituted script, and in
all three states the panel can be in. It has not yet been watched against a live scenario run.

**Still open:**

- A single command from bare ISOs. The remaining manual steps are the GRUB edit for Ubuntu
  autoinstall and the key transfer between manager and endpoints.
- **The exporter.** `run-campaign.sh` records what it launched and when; nothing yet joins
  those runs to the alerts they caused in the indexer. Until it exists, a campaign produces
  labels without features and the lab's own rules stay untested in sequence. Alert retention
  is 90 days, so a campaign run now would still be exportable later.
- **The campaign itself.** Trialled for one hour on 17 September and correct: records landing
  on the host, varied failed-logon counts working on real hardware, staff rotation producing
  sessions. The full 14 hour run has not been made, and is now a specific question rather than
  a prerequisite for anything.
- `run-campaign.sh` is not in the dashboard's sudoers grant, so starting a campaign from the
  dashboard would prompt for a password. Everything else the dashboard needs is granted.
- **The scoring panel has not been watched live.** It is verified against fabricated alerts
  end to end, which is not the same as seeing the score move while an S1 burst runs. That is
  ten minutes with both VMs up and it is the screenshot worth having.

**From the external review, `docs/handoff-review-2026-09-21.md`.** An outside pass over the
repository and the session exports found five code issues that have not been fixed. They are
listed here rather than in that file alone so they are not lost, and none of them reverses the
headline result that logistic regression beats the sequence model on all eight folds.

- `05-detection-modelling/features.py` ranks equal scores by input order, so a binary
  single-rule score gets an order-dependent average precision. Grouping ties gives about
  0.1645 for the single-rule baseline against the stored 0.1608. Every figure derived from
  that column should be recomputed.
- `05-detection-modelling/evaluate.py` describes a whole-network validation holdout but takes
  an 85% row cut, which splits a network in all eight folds, and standardisation is fitted
  before that inner split. The outer test networks are still separate, so this is not label
  leakage into the test set, but the validation independence claim is wrong as written.
- `Start-LabDashboard.ps1` reads at most the last 400 KB and 800 records, so the oldest bucket
  can be truncated and still treated as complete, and the newest alert decides which bucket is
  partial, so a quiet completed window never closes until another alert arrives.
- `scorer/score.py` treats credential access and persistence anywhere in the same window as a
  chain, and the dashboard drops endpoint identity while bucketing, so unrelated activity on
  two different endpoints earns the same multiplier. Either describe it as co-occurrence or
  implement the temporal and identity relationship.
- `import-ait.py` anchors windows to the first capture event and keeps at most 256 events per
  window, while live scoring uses epoch boundaries and a global tail limit. Training and live
  features are therefore not sampled the same way.

Also from that review, and already fixed: the shareable session export carried an
administrator password on three pages because the redaction matched on the label immediately
preceding a value. Redaction is now by value, and `check-export.py` verifies the finished PDF
rather than the HTML it came from.

**Housekeeping:**

- The PDF for the mentor covers steps 1 to 3 and predates the build. If he wants the results, it
  needs regenerating to include step 4. `docs/Detection-Modelling-Report.pdf` covers step 5 and
  is generated from the measurements, so that one stays current on its own.
- `lab-dashboard/Enable-LabDashboard.ps1` replaces the staged sudo password chore. It grants a
  narrow, visudo-checked rule once and stores nothing.
- `sshpass` was installed on the manager so it could act as a second endpoint for the cross-agent
  test. `tests/s1-burst.sh` needs it on whichever machine runs a burst.
- The two Ubuntu VMs still have an unmerged differencing disk from the automatic checkpoint that
  existed before it was disabled. Harmless, but worth merging during cleanup.
