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
| 5. Detection modelling | [Can a model read a run of alerts?](05-detection-modelling/README.md) | Measured, reported, and scoring live |
| | [Report (PDF)](docs/Detection-Modelling-Report.pdf) | Dataset, training process, every model tried, what won |

Step 5 is beyond the four step brief. It exists because the mentor raised using PyTorch to find
patterns, and that deserved a measured answer rather than an opinion.

For the full picture including what was hit along the way and what comes next, read
[PROJECT-STATUS.md](PROJECT-STATUS.md). To rebuild the lab, start with the
[deployment guide](04-implementation/deployment-guide.md). Cloning this rather than reading it,
start with [what a fresh clone does not contain](docs/fresh-clone.md).

## Running it

`Lab.cmd` is the front door. It opens a local dashboard that starts and stops the lab, shows what
each VM is costing, and answers the question the project exists to answer: are all six detections
alive, and when did each one last fire.

It checks the machine before it opens, so a host that cannot run the lab says why rather than
failing later: virtualization in firmware, the Hyper-V platform, the switch and NAT, the VMs,
and the credentials a fresh clone does not have. It also carries the logins for the Wazuh web
interface and all three guests.

One button brings the lab up in the right order, manager first so the agents have something to
connect to, and takes it down in the reverse order so the indexer closes cleanly. Nothing starts
by itself: every VM is created with `AutomaticStartAction Nothing`, and the dashboard has no code
path that can change that to anything else.

See [the dashboard notes](04-implementation/host/lab-dashboard/README.md).

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

## Does a model beat the rules?

Four of the six rules judge one event in isolation. The two S1 rules count repeated failures
inside a window, which is the only correlation in the ruleset. The obvious next question is
whether something reading a *run* of alerts does better, and whether that something needs to
be a neural network.

Tested on the [AIT Alert Data Set](https://zenodo.org/records/8263181): 2.6 million real Wazuh
alerts from eight simulated enterprise networks, each with a labelled multi-step intrusion. Each
network was held out in turn and the models trained on the other seven.

| | f1 | average precision |
| --- | --- | --- |
| best single Wazuh rule | 0.245 | 0.161 |
| logistic on shape and severity only, **deployed** | 0.192 | 0.177 |
| GRU over the alert sequence, in PyTorch | 0.180 | 0.199 |
| logistic regression on counts and timing | **0.292** | **0.249** |
| random | | 0.021 |

**Logistic regression wins all eight folds. The GRU wins none.** On this evidence a sequence
model is not justified for this problem: within a five minute window, which rules fired and how
bursty they were carries the signal, and the order adds little on top.

The winner is also the one model that cannot be deployed here. Its columns are one per AIT rule
id, and this lab shares two signatures out of thirty one, so pointed at live alerts it would put
every one of them in the unknown column and return a confident number about nothing. The row
marked deployed is the feature set that survives the move: eleven columns describing the shape
and severity of a window with no rule identity in them. It keeps 71% of the full model and beats the best
single rule, and the gap is the measured price of portability.

That one runs live. The [lab dashboard](04-implementation/host/lab-dashboard/README.md) scores
the last twelve five minute windows on every poll and prints the model's provenance and its
measured average precision on the panel, permanently, because it has never been measured on this
lab.

Two caveats kept in the open. None of these is deployable as an alerting rule: on the best fold
the winner holds perfect precision down to recall 0.375, and catching half the intrusions costs
119 false positives. And the public data contains none of rules 100100 to 100113, so this
measures the method rather than this lab's own detections.
[The full write-up](05-detection-modelling/README.md) covers both, and
[the report](docs/Detection-Modelling-Report.pdf) is the seven page version with every figure
read off a measurement.

## Scope

The rules cover three behaviours by design. Coverage claims are limited to the six cases above
and to the conditions they were tested under. S2 and S3 report observed activity for an analyst
to judge, because account creation and scheduled jobs are also normal administration.
