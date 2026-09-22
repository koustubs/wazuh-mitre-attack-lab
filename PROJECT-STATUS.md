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
| 1. Context analysis | `docs/design/` | Complete. Includes a rendered PlantUML system context diagram. |
| 2. Problem and scope | `docs/design/` | Complete. Defines S1 to S3 and acceptance criteria R1 to R5. |
| 3. Technical design | `docs/design/` | Complete. Stack pinned to Wazuh 4.14.x with the 5.0 beta transition acknowledged. |
| 4. Implementation | `setup/`, `manager/`, `agents/`, `dashboard/` | Complete. See `docs/implementation.md` for full results. |
| 5. Detection modelling | `scoring/` | Beyond the brief. Measured and reported. See section 5b. |

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

Two or three VMs on a private network with outbound NAT and no route in, depending on the
profile. Everything is provisioned unattended, on Hyper-V or on VirtualBox.

| VM | Guest hostname | Address | Role | Profile |
| --- | --- | --- | --- | --- |
| WAZUH-MANAGER | `wazuh-manager` | 172.29.70.10 | Wazuh manager, indexer, dashboard, all 4.14.7 | both |
| WAZUH-WIN | `WAZUH-WIN` | 172.29.70.20 | Windows 11, agent 001 | full |
| WAZUH-LINUX | `wazuh-linux` | 172.29.70.30 | Ubuntu 24.04 cloud image, agent 002 | both |

Every value in that table comes from `lab.config.json`, which is the one place the addresses,
names, memory, disk sizes, image URLs and the Wazuh version are written down. The running lab
was built on Hyper-V at the full profile.

Host is the gateway at 172.29.70.1. There is no DHCP on the switch, so all addresses are static
and the guest hostnames must match exactly. Every script checks its hostname and refuses to run
on the wrong machine, so a mismatch fails loudly rather than silently doing the wrong thing.

**Access.** SSH as `labadmin` using the key in `.lab-secrets/lab_ed25519`, to all three. The
Windows endpoint runs OpenSSH Server, installed by its unattend file and firewalled to the host
address, which replaced Hyper-V PowerShell Direct. That transport worked only on Hyper-V, and
one way in has to serve both backends.

**Credentials** live in `.lab-secrets/`, which is gitignored. It holds the
SSH keypair, a random 20 character console password, and the three unattended install images.
The Wazuh dashboard admin password is not stored there; it is in
`/root/wazuh-lab-install/install.log` on the manager.

**Firewall.** `install-manager.sh` restricts the manager with ufw, before the platform is
started: SSH and 443 only from the host, and 1514 only from the endpoint addresses in
`lab.config.json`. The Wazuh web interface is deliberately not reachable from anywhere except
the host.

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
`agents/linux/run-campaign.sh` to generate a night of labelled episodes here, and
`scoring/import-ait.py` to import the
[AIT Alert Data Set](https://zenodo.org/records/8263181), 2.6 million real Wazuh alerts from
eight simulated enterprise networks under CC-BY. The public route was taken first because it
was an afternoon rather than a night, and because eight independent networks is a stronger
test than one host.

Each network held out in turn, trained on the other seven:

| | f1 | average precision |
| --- | --- | --- |
| best single Wazuh rule | 0.235 (sd 0.148) | 0.160 (sd 0.098) |
| GRU over the alert sequence | 0.164 (sd 0.123) | 0.188 (sd 0.085) |
| logistic on shape and severity, deployed | 0.227 (sd 0.114) | 0.220 (sd 0.099) |
| logistic regression on counts and timing | **0.251** (sd 0.154) | **0.251** (sd 0.108) |
| random | | 0.021, the base rate |

**The GRU loses to logistic regression on seven of eight folds, mean margin 0.063 with a spread
of 0.048 on it.** A sequence model is not justified for this problem on this evidence, and that
is the one comparison here consistent enough to say so.

Four things that should be read with it:

- **The full feature set cannot be deployed here, and the deployed row is what runs.** It is
  one column per AIT rule id, and this lab shares two signatures with AIT out of thirty one, so
  on live lab alerts it would put everything in the unknown column. The deployed model drops
  every rule count and keeps eleven columns describing the shape and severity of a window. It
  holds 88% of the full model, beats the best single rule on all eight folds, and is ahead of
  the full model on three of them. The 0.031 it gives up has a 0.035 spread across folds, so
  the price of portability is smaller than the noise on it. That inverts what this section said
  before the sampling was corrected: rule identity was worth far less than the 256-alert cap
  made it look.
- **Nothing here is deployable as an alerting rule.** On its best fold, wheeler, 1,181 windows
  holding 15 attack windows, the winner keeps perfect precision down to recall 0.400: six caught
  and nothing false. Pushed to catch half, precision falls to 0.031, so eight real attacks arrive
  with 246 false positives. That is what a 2% base rate does, and it is the honest state of the
  art here rather than a failure of the modelling.
- **The synthetic results were measuring the generator.** On `make-synthetic.py` output every
  model scored near the ceiling, logistic at f1 1.000. The same model scores 0.251 average
  precision on real alerts. Synthetic numbers in this repo are evidence the code runs, nothing
  more, and the modelling README says so.
- **This does not test the lab's own rules.** No public dataset contains 100100 to 100113;
  5501 and 5502 are the entire overlap with AIT. Whether these six rules separate an attacker
  from an administrator in sequence is still open, and `run-campaign.sh` is what would answer
  it. That is now a specific question rather than a blocker, and the pipeline it would feed is
  built and proven.

The deployed model runs inside the dashboard's existing SSH poll, scoring the last twelve five
minute windows on every cycle. 8 ms for a full 5,000 document indexer search spread across
eighteen windows, in plain Python, with nothing installed on the manager. `scoring/export-model.py` writes the eight fold result into the
model file itself, and the panel prints it, because a weights file with no measurement attached
gets trusted more than it has earned. The panel also states permanently that the model has
never been measured on this lab.

All of step 5 is written up in [docs/Detection-Modelling-Report.pdf](docs/Detection-Modelling-Report.pdf),
seven pages, rebuilt by `scoring/report/Build-Report.ps1`. Every figure in it is
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
UI appears. Send exactly one key for the "press any key to boot" prompt and then stop. This was
learned from `LabConsole.ps1`, a framebuffer console driver that typed at VM consoles over the
Hyper-V WMI provider. It is gone: Ubuntu boots a cloud image and needs no console at all, and
nothing else in the repository types at one. The note is kept because the next person to reach
for that approach will hit the same thing.

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
  lab.config.json               the one place addresses, sizes and versions are written down
  README.md                     what this is, what it needs, and what it measured
  PROJECT-STATUS.md             this file
  SECURITY.md                   what is excluded, and the pre-publication checklist
  setup/
    Test-LabHost.ps1            run first: what this machine can and cannot do, and the fix
    New-LabSecrets.ps1          SSH keypair, console password and its crypt hash
    Get-LabImage.ps1            fetches and verifies the Ubuntu cloud image
    New-LabSeeds.ps1            cloud-init seeds for the Ubuntu guests
    New-WindowsSeed.ps1         autounattend seed for the Windows endpoint
    New-Lab.ps1                 the network and the profile's VMs, on either backend
    Install-LabAgents.ps1       collects each agent key and enrols the endpoint
    Remove-Lab.ps1              teardown; disks are kept unless asked for
    Write-GuestConfig.ps1       lab.config.json as shell, for the guests that cannot read it
    LabConfig.ps1               config reader, dot-sourced by the rest
    LabBackend.ps1              picks a backend module and checks it can run here
    LabPreflight.ps1            the host checks, shared by Test-LabHost and the dashboard
    LabIso.ps1                  ISO authoring over IMAPI2FS
    backends/
      hyperv.psm1               one contract, sixteen functions
      virtualbox.psm1           the same sixteen, against VBoxManage, never yet run
    .lab-secrets/               gitignored: keys, password, seed images
  manager/
    install-manager.sh          manager, indexer and dashboard pinned, and the firewall
    configure-firewall.sh       22 and 443 to the host, 1514 per endpoint, re-runnable
    tune-manager.sh             heap, disabled modules and index retention for the profile
    configure-manager.sh        lab rules and agent identities
    configure-dashboard.sh      index pattern the UI needs in order to render anything
    lab_rules.xml               the six detection rules
  agents/
    linux/                      agent install, scenario driver, campaign driver
    windows/                    agent install and scenario driver
  dashboard/
    Start-LabDashboard.ps1      the server, the up and down sequences, the scoring poll
    dashboard.html              the page
    Enable-LabDashboard.ps1     one-time grant: alerts, agents, the indexer and the baseline
    README.md                   what the page shows and what it needed permission for
  scoring/
    README.md                   the measured answer on whether a model beats the rules
    requirements.txt            NumPy and PyTorch, pinned
    alert_stream.py             the episode contract and the vocabulary a dataset carries
    import-ait.py               the AIT alert data set into episodes
    make-synthetic.py           stand-in alert stream, the only source with the lab's own rules
    features.py                 episodes into model input, the splits, the metrics
    baseline.py                 one rule, the degenerate classifier, logistic regression
    train.py                    embedding, GRU and linear head, in PyTorch
    evaluate.py                 leave one network out, across all eight
    evaluate_adaptive.py        the same eight folds against the per endpoint baseline layer
    window-sensitivity.py       whether the result is the models, the window width or the split
    export-model.py             fits the portable model, with its measurement inside the file
    Sync-LabCampaign.ps1        pulls campaign records off the endpoint as they are written
    scorer/                     score.py and model.json, the part that leaves this machine
    report/                     builds docs/Detection-Modelling-Report.pdf from the artefacts
    data/, models/              gitignored: rebuilt by the scripts above
  tests/
    fetch-engine-package.sh     re-fetches the pinned manager package a clone does not have
    prepare-engine-check.sh     stands the engine up offline for the rule suite
    test_rules.py               offline rule checks against a real engine
    test_dashboard_scoring.py   runs the dashboard's manager script on fabricated alerts,
                                with no lab up, and checks the severity path end to end
    test_adaptive_scoring.py    the baseline layer and the live baseline helper, offline
    s1-burst.sh                 controlled failure bursts for frequency edge cases
    query-frequency.sh          reads back which rule fired, on which agent
  evidence/
    validation-status.md        what is verified and what is not, committable
    README.md                   what lives here and why most of it does not
    live-runs/, campaigns/      gitignored: raw records from real runs
  docs/
    setup.md                    the build, step by step
    fresh-clone.md              what a clone does not contain, and how to rebuild it
    implementation.md           the main technical record
    collecting-a-dataset.md     how to record a labelled campaign, and when it is worth it
    design/                     the coursework the build started from, written before it
    architecture/               eleven Mermaid views and one page that renders them
    progress-update/            the update builder
    *.pdf                       the three deliverables
```

---

## 8. Rebuilding from scratch

1. `setup\Test-LabHost.ps1`. It changes nothing and names what is missing, including whether a
   hypervisor is installed at all. Installing one is yours to do.
2. `setup\New-LabSecrets.ps1`. A clone has no keys and every step below depends on them.
3. `setup\Get-LabImage.ps1`. Fetches and verifies the Ubuntu cloud image, once.
4. `setup\New-LabSeeds.ps1`, and `setup\New-WindowsSeed.ps1` on the full profile.
5. `setup\New-Lab.ps1`, elevated. The Ubuntu guests configure themselves on first boot.
6. Copy `manager/` to the manager and run `install-manager.sh`, `configure-manager.sh`, then
   `configure-dashboard.sh`. Do not skip the third: without it the dashboard renders nothing,
   however well detection is working.
7. `setup\Install-LabAgents.ps1`. It collects each key and enrols each endpoint.
8. `dashboard\Enable-LabDashboard.ps1`, once.
9. Run the scenarios.

`docs/setup.md` has the detail. The full sequence is still not a single command, deliberately:
each step is a script that does one job and reports what it did.

---

## 9. What is outstanding

**Not done:**

- The two frequency edge cases on the Windows rule 100101. They are done for the Linux rule
  100111, and the mechanism under test belongs to `wazuh-analysisd` and is shared by both, but
  100101 keys on different fields and has not been exercised this way. The obstacle used to be
  that the Windows endpoint was reachable only through Hyper-V PowerShell Direct; it now runs
  OpenSSH like the Linux one, so nothing is in the way except doing it.
- All timings were measured on an idle lab. Behaviour under sustained load is unknown.
- The rule set covers three behaviours by design. Coverage claims should stay limited to the six
  cases in the results table.

**Done since, in the packaging phase:**

- The project is a Git repository, built to the standard a public one needs from the first
  commit. No credential has ever been committed. `SECURITY.md` carries the checklist to run
  before making it public, including reading the mentor PDF, whose text cannot be scanned
  automatically.
- `setup/New-LabSecrets.ps1` creates the credentials. Nothing in the repository did, which meant a
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
all three states the panel can be in.

**Watched live on 22 September, and it found a bug first.** Against a running lab the page
reported the manager as unreachable. The status script is sent base64 encoded, and folding
the scorer into it took the payload to 34,644 characters, past the 32,767 a Windows command
line holds. `Start-Process` threw, `Invoke-LabSsh` caught it and returned `$null`, and
`Get-LabHealth` reported that as no answer over SSH. One round trip carries the whole health
payload, so coverage, recent alerts, the manager log and agent state were dead too, not just
the score. Offline testing never crosses a process boundary, so nothing caught it. The
payload now goes over standard input and the ceiling is gone.

With that fixed, S1 on WAZUH-LINUX: rule 100110 five times, then 100111 at level 10, and the
window climbed to 100 while the burst ran. It closed at 99.9, critical, with the chain
multiplier applied because 100112 created a local account in the same window. Base 76.84,
times 1.30. The 90 second window before it scored 54.2 on boot noise alone, which is a fair
illustration of what a 0.220 average precision model is and is not worth. Findings export
produced a three page PDF of both.

**Still open:**

- Windows still needs an ISO you supply. Ubuntu does not: `Get-LabImage.ps1` fetches the cloud
  image and checks it against the published SHA256, and cloud-init configures the guest on first
  boot, so there is nothing to type at a console. The agent key transfer is no longer manual
  either; `Install-LabAgents.ps1` reads each key off the manager and enrols the endpoint with it.
  What is left by design is the hypervisor, which you install yourself.
- **The exporter.** `run-campaign.sh` records what it launched and when; nothing yet joins
  those runs to the alerts they caused in the indexer. Until it exists, a campaign produces
  labels without features and the lab's own rules stay untested in sequence. Alert retention
  is 90 days, so a campaign run now would still be exportable later.
- **The campaign itself.** Trialled for one hour on 17 September and correct: records landing
  on the host, varied failed-logon counts working on real hardware, staff rotation producing
  sessions. The full 14 hour run has not been made, and is now a specific question rather than
  a prerequisite for anything.
**From an external review, 21 September 2026.** An outside pass over the repository found five
code issues. All five are fixed, and the numbers in section 5b were recomputed afterwards
rather than carried over. None of the fixes reversed the headline result that logistic
regression beats the sequence model.

- **Tied scores.** `scoring/features.py` ranked equal scores by input order, so a binary
  single-rule score got an average precision that depended on the order the rows arrived in.
  It now cuts the precision-recall curve only where the score changes, which is the standard
  definition and identical to the old arithmetic when nothing is tied. Every figure derived
  from that column was recomputed.
- **The validation claim.** `scoring/evaluate.py` described a whole-network validation holdout
  and took an 85% row cut, which, because the rows are sorted by source, was the back end of
  whichever network sorted last. It now holds out a whole network, rotated so each one
  validates exactly once, and standardisation, vocabulary and weights are all fitted on the
  inner split alone.
- **Truncation.** `Start-LabDashboard.ps1` read at most the last 400 KB and 800 records of the
  alert log, so a busy window lost its oldest records and was still treated as complete. It
  now reads the indexer over an explicit time range, keeps the log tail only as a fallback,
  and says which source it used.
- **The chain multiplier.** `scorer/score.py` treated credential access and persistence
  anywhere in the same window as a chain, and the dashboard dropped endpoint identity while
  bucketing, so activity on two unrelated endpoints earned the same multiplier. Alerts are now
  bucketed per endpoint and the chain is evaluated inside one.
- **Sampling.** `import-ait.py` anchored windows on the first capture event and kept 256 events
  per window, where live scoring uses epoch boundaries. Windows are now anchored on the epoch
  the same way, and the cap is 4096, which is where the live side runs out anyway. The old cap
  bound a fifth of the attack windows, so the count feature was saturating on exactly the
  windows whose size was the signal.

Fixing the last one surfaced a sixth defect the review did not find. `score.py` divided the
model probability by `2 * threshold`, and with the deployed threshold of 0.85 that divisor was
1.70. A probability cannot exceed 1, so the highest-weighted of the six components could never
reach more than 0.59 of its range: the model contributed at most 16 points of 100 however
certain it was. The divisor is now capped at 1.

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
