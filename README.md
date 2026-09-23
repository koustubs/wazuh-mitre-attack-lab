# Threat detection with Wazuh and MITRE ATT&CK

A small detection lab that runs on a single Windows machine. It stands up a Wazuh 4.14.7 manager
and one or two endpoints as virtual machines, deploys eight custom rules, six of them detections
for three attacker behaviours, and includes a local dashboard that runs the attacks, watches the
alerts arrive and scores them.

Every detection is driven by a real action. The Linux brute force case stands up a throwaway
`sshd` and drives real authentication at it; the Windows one calls `LogonUser` and asserts the
error code. Account creation is a real `useradd` or `New-LocalUser`, persistence a real
`/etc/cron.d` write or `Register-ScheduledTask`. Nothing is written into a log to make an alert
appear, and each scenario checks the OS-native event exists before it claims anything.

It runs on Hyper-V or VirtualBox, on a Windows host. The host has to be Windows: the dashboard,
the ISO authoring and the provisioning are PowerShell, and rewriting them for another OS is a
different project. The guests are Ubuntu and Windows.

## Requirements

| | lean | full |
| --- | --- | --- |
| Host RAM | 8 GB | 16 GB |
| Free disk | 60 GB | 180 GB |
| CPU | 4 to 8 cores with SVM or VT-x and SLAT | 8 or more, same features |
| Host OS | Windows 11, built and tested on 11 Pro 25H2 | same |
| Hypervisor | Hyper-V, or VirtualBox 7.0 or later | same |
| Guests | manager and Linux endpoint | plus the Windows endpoint |
| Detection cases | 3 of 6, Linux only | 6 of 6 |
| Images to supply | none | a Windows 11 ISO |

Host RAM is what the guests can grow to between them: the lean profile starts them at 5 GB and
caps them at 8, the full profile at 11.5 GB and 16. Idle, the lean guests were measured using
2.7 GB. Whatever else the host runs comes on top. The measurements are in
[section 2 of the architecture notes](docs/architecture/README.md#2-deployment-networks-and-trust-boundaries).

Hyper-V needs Windows Pro, Enterprise or Education. VirtualBox runs on Home as well, and on a
machine that already has it. Nothing here installs a hypervisor. Windows 10 has not been tried.

**The VirtualBox backend is written and has never built a lab.** Everything measured in this
repository was measured on Hyper-V. Both backends are held to the same seventeen function contract
and that contract is checked: the two modules define the same functions with the same parameter
names and the same mandatory arguments, and return the same fields. The read paths, which report
availability, VM state and the network, have run against VirtualBox 7.2 on the build host. The
write paths, which create the network and the VMs, have not been run. Hyper-V is the tested path
and VirtualBox is the one to expect to have to fix.

`setup\Test-LabHost.ps1` answers all of this about the host before anything is built. It
changes nothing, reports the virtualization setting under the name the CPU uses, and prints the
one command that fixes each failure.

## Getting it running

```
.\setup\Test-LabHost.ps1
```

```
.\setup\New-LabSecrets.ps1
.\setup\Get-LabImage.ps1
.\setup\New-LabSeeds.ps1
.\setup\New-Lab.ps1
```

```
.\Lab.cmd
```

Between the second block and the third the manager needs its packages installed, which is three
scripts run over SSH, and the endpoints need enrolling. [`docs/setup.md`](docs/setup.md) is the
whole thing: a preflight and eight numbered steps.

Everything reads [`lab.config.json`](lab.config.json): addresses, VM names, memory, disk, the
Ubuntu image and the Wazuh version. Change the subnet there and every script and both guest
images follow.

Nothing autostarts. VMs are created stopped, and the only autostart value any of this code can
write is off.

## What it detects

| Case | Rule | ATT&CK |
| --- | --- | --- |
| S1 repeated failed logons, Windows and Linux | 100101 / 100111 | T1110.001 Password Guessing |
| S2 local account creation, Windows and Linux | 100102 / 100112 | T1136.001 Local Account |
| S3 scheduled task or cron job, Windows and Linux | 100103 / 100113 | T1053.005 / T1053.003 |

The other two custom rules, 100100 and 100110, each match a single failed logon at level 3. The
S1 rules count them.

On 23 September 2026, on the full profile as the current scripts build it, every case was run
twice on live endpoints and all six detected both times, with the ATT&CK mapping resolved from
the technique ID. Each S1 case also ran a benign comparison of one failed logon instead of six:
across eight S1 runs, the four attacks alerted at level 10 and the four comparisons did not.

A single-event rule's alert is timestamped 2 to 8 seconds after its run starts. The S1 composites
take 10 to 26 seconds, which is the time the scenario spends generating six failures. Indexing
adds 3.4 to 7.5 seconds, median 5.1. Every detection reached the indexer with the ATT&CK
technique, tactic and ID stored as searchable fields. Retention is 90 days. The frequency rules
were tested at their edges: the 120 second window expires on both, and the Linux rule counts per
agent, so it will not correlate one campaign spread across several machines.

S2 and S3 report observed activity for an analyst to judge, because account creation and
scheduled jobs are also normal administration. Their comparison runs perform the same action and
record it as approved, and the rules alert on it exactly as on the attack, because nothing in the
event carries the approval. The rules cover three behaviours by design, and coverage claims stay
limited to these six cases. [Validation status](evidence/validation-status.md) is the record,
including what is still open.

## Does a model beat the rules?

Four of the six detection rules judge one event in isolation. The two S1 rules count repeated
failures in a window, which is the only correlation in the set. The question tested here is
whether a model reading the whole run of alerts in a window does better, and whether that model
needs to be a neural network.

Tested on the [AIT Alert Data Set](https://zenodo.org/records/8263181), 2.6 million real Wazuh
alerts from eight simulated enterprise networks, each with a labelled multi-step intrusion. Each
network is held out in turn and the models train on the other seven, with a second whole network
held back inside those for thresholds and early stopping.

| | f1 | average precision |
| --- | --- | --- |
| best single Wazuh rule | 0.235 | 0.160 |
| logistic on shape and severity only, **deployed** | **0.227** | **0.220** |
| GRU over the alert sequence, in PyTorch | 0.164 | 0.188 |
| logistic regression on counts and timing | 0.251 | 0.251 |
| random | | 0.021 |

**The GRU loses to logistic regression on 7 of the eight folds, by a mean margin of 0.063
average precision with a fold-to-fold spread of 0.048 on that margin.** It is the one comparison
here that is consistent rather than noisy, and it points the wrong way for the neural network.
On this evidence a sequence model is not justified for this problem: within a five minute
window, which rules fired and how bursty they were carries the signal, and the order of arrival
adds little on top of that.

**The deployed model is the portable one, at a small cost.** The full logistic has one column
per AIT rule id, and this lab shares two signatures out of thirty one, so on live alerts nearly
every one would land in the unknown column and its probability would mean nothing. The deployed row is the feature set that survives the move:
eleven columns describing the shape and severity of a window, with no rule identity in them. It
keeps 88% of the full model's average precision, beats the best single rule on all eight folds
and the base rate on all eight folds, and the 0.031 it gives up has a spread of 0.035 across
folds, so the gap is within the fold-to-fold noise. It is ahead on 3 of the eight folds.

Two caveats kept in the open. None of these is deployable as an alerting rule on its own: at the
operating points measured here, catching half the intrusions costs false positives in the
hundreds. And the public data contains none of rules 100100 to 100113, so this measures the
method rather than this lab's own detections. [The full write-up](scoring/README.md) covers both,
and [the report](docs/Detection-Modelling-Report.pdf) is the version with every figure read off a
measurement.

## Scoring that adjusts to the machine

A fixed threshold treats every endpoint the same, so an endpoint whose normal volume is high
scores permanently worse than a quiet one. The manager therefore keeps a baseline per endpoint: a robust centre and spread of its alert volume, which signatures it has
ever produced, and when in the day it usually produces them. Severity is then measured against
that endpoint rather than against a constant.

Two behaviours come out of it. A rule this endpoint has never produced counts for more than the
fifth occurrence of one it produces daily. And a rate sitting inside this endpoint's normal band
for this hour is discounted, which is what separates one person's daily mistake from the same
signature on a machine that has never seen it.

Until an endpoint has 24 completed windows behind it the fixed constants stand, and the panel
says which mode it is in.

It is measured, and on this data it does not pay for itself. On the same eight folds, each
network treated as one endpoint with one baseline warmed on its own first 24 windows, severity
against that baseline reaches 0.169 average precision on labelled intrusion windows against
0.173 for the fixed constants: -0.0036 mean, -0.0024 median, better on 3 of 8 folds. Both
severity arms sit below the raw model probability on the same windows, 0.221. Two things that measurement cannot
see: AIT alerts carry no ATT&CK tactic and none of this lab's rule ids, so the chain multiplier
is 1.0 on every window in it, and a network is not an endpoint, so its baseline is warmed on the
aggregate of a whole subnet rather than one machine's habits. The layer ships on the structural
argument for per-endpoint baselines, not on this measurement, which is a poor proxy for the case
it was built for.

## Where things are

| | |
| --- | --- |
| [`docs/setup.md`](docs/setup.md) | Build the lab: a preflight and eight steps. |
| [`lab.config.json`](lab.config.json) | Addresses, sizes, versions. The one place they are written down. |
| [`setup/`](setup/) | Preflight, secrets, image fetch, seeds, provisioning, enrolment, teardown. |
| [`manager/`](manager/) | Manager install, rules, tuning. Copied to the guest and run there. |
| [`agents/`](agents/) | Agent installers and the scenario drivers, per OS. |
| [`dashboard/`](dashboard/) | The local page and the manager-side helpers it is granted. |
| [`scoring/`](scoring/) | The dataset work, the models, and the scorer that ships. |
| [`tests/`](tests/) | Offline rule checks against a real engine, and the scoring tests. |
| [`docs/architecture/`](docs/architecture/) | Eleven diagrams of how it fits together. |
| [`docs/design/`](docs/design/) | The coursework this started from, kept as submitted. |
| [`PROJECT-STATUS.md`](PROJECT-STATUS.md) | What was built, what broke, what is still open. |
| [`docs/fresh-clone.md`](docs/fresh-clone.md) | What a clone does not contain, and how to rebuild it. |
| [`SECURITY.md`](SECURITY.md) | What is deliberately not in here. |

No credential, key or raw evidence has ever been committed. `.lab-secrets/` is generated on the
host by `New-LabSecrets.ps1` and is gitignored at any depth.
