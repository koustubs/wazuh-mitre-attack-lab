# Detection modelling

Step 4 of the lab detects single events. Rule 100110 counts a failed SSH password, rule 100112
notices an account being created. Neither knows the other exists, and neither knows what an
ordinary Tuesday looks like on the endpoint.

This is the attempt to add the thing they cannot do: read a *run* of alerts and judge it.

The short answer, measured on 2.6 million real alerts across eight networks: **a sequence
model does not earn its place.** Plain logistic regression on rule counts and timing beats it
on seven held out networks out of eight, and ties it on the eighth. The detail is below,
including the numbers that say so and the reasons not to read too much into them.

A second answer sits under that one. The model that won cannot be deployed here at all, because
its features name AIT rule ids and this lab has different rules. What is actually running on the
dashboard is a portable version of it, fitted on eleven features that name no signature, and
what that costs is measured rather than waved at. See
[what is deployed](#what-is-deployed-and-why-it-is-not-the-winner).

The seven page version of all of this, for a reader who is not going to clone the repository, is
[docs/Detection-Modelling-Report.pdf](../docs/Detection-Modelling-Report.pdf).

## The order of work, and why

1. **Get data.** Either `import-ait.py` for the public set, or
   `agents/linux/run-campaign.sh` for the lab's own. See
   [docs/collecting-a-dataset.md](../docs/collecting-a-dataset.md) for what each can answer.
2. **Baseline.** `baseline.py`. Non-neural, and the number everything else has to beat.
3. **Model.** `train.py`. Last, and smallest.
4. **Compare properly.** `evaluate.py`. One split ranks nothing.

The model is last because it is the easy part. The hard part is having something to train on
and something to compare against.

## Files

| | |
| --- | --- |
| `alert_stream.py` | The episode contract, the lab rule ids, and the `Vocabulary` a dataset carries |
| `import-ait.py` | The AIT alert data set into episodes. Real alerts, eight networks |
| `make-synthetic.py` | A stand-in alert stream, kept because it is the only source with the lab's own rules in it |
| `features.py` | Windows into model input, the splits, and the metrics |
| `baseline.py` | One rule, the degenerate classifier, and logistic regression |
| `train.py` | An embedding, a GRU and a linear head, in PyTorch |
| `evaluate.py` | Leave one network out, across all eight |
| `evaluate_adaptive.py` | The same eight folds again, against the per endpoint baseline layer |
| `window-sensitivity.py` | Whether the result is the models or the window width and the split |
| `severity-ablation.py` | What the four severity columns are worth inside the deployed feature set |
| `export-model.py` | Fits the portable model and writes it out with its measurement attached |
| `scorer/` | The part that leaves this machine: `score.py` and `model.json`, read by the dashboard |
| `report/` | Builds [the report](../docs/Detection-Modelling-Report.pdf) from the artefacts |

## Running it

Download `ait_ads.zip` and `labels.csv` from [zenodo.org/records/8263181](https://zenodo.org/records/8263181)
into `data/ait/`, then:

```bash
python import-ait.py
python baseline.py --data data/ait/episodes.jsonl --split source
python evaluate.py --data data/ait/episodes.jsonl
python evaluate_adaptive.py
python window-sensitivity.py
python severity-ablation.py
python export-model.py
```

In that order: `export-model.py` reads the folds `evaluate.py` and `evaluate_adaptive.py` wrote,
and the report build reads all five artefacts. The import parses 2.8 GB
out of the archive once and caches what it needs, so re-running at a different `--window` is
seconds. `evaluate.py` is about fifty minutes on CPU and everything else is minutes.

Needs `torch`, `numpy`. No sklearn: the logistic regression, the average precision and the
metrics are about sixty lines of numpy between them, which is less than the cost of another
dependency in a repo meant to be cloned.

## The data

`import-ait.py` reads the [AIT Alert Data Set](https://zenodo.org/records/8263181), which is
2.6 million Wazuh alerts from eight simulated enterprise networks, each carrying a labelled
multi-step intrusion. CC-BY, published with the CSET 2024 paper. The alerts are in native
`alerts.json` form, the same records this lab's own manager writes.

It is not a test of our rules, and the README would be dishonest if it implied otherwise.
**None of 100100 to 100113 have a parent signature in it.** No sshd brute force in any of the
eight scenarios, no account creation, no FIM. Rules 5501 and 5502 are the entire overlap, and
AIT password cracking is offline hash cracking and WPScan rather than SSH. So this measures
the method. Only a campaign measures the lab.

An episode is a 300 second tumbling window, labelled attack if it overlaps a ground truth
phase. That gives 8,932 episodes, 188 of them attack, a base rate of 2.1%.

## Four things done deliberately

**Whole networks are held out, not the tail of a timeline.** Each scenario is a separate
network. A model that scores well on one it has never seen has generalised; a model that
scores well on the last hour of a network it trained on may only have learned that network's
noise floor.

**Average precision, not f1 at a fixed cutoff.** At a 2% base rate, f1 at 0.5 says more about
where a model happens to put its threshold than about whether it ranks attacks above
background. Logistic regression scores f1 0.162 at 0.5 and 0.317 at a threshold chosen on
validation, on identical predictions. Average precision cannot be flattered that way. Every
threshold quoted here was picked on a validation slice and never on the test set.

**Eight folds, not one split.** Any single fold here would have supported a different
conclusion. The logistic model beats the GRU by 0.137 average precision on harrison and loses to
it by 0.002 on fox, and it beats the deployed portable set by 0.088 on harrison and loses to it
on three other networks. Held-out network is worth more than model choice on this data, so a
result quoted from one split is a result about that split. Counting fold wins is the claim that
survives. Thresholds and early stopping come from a second whole network held back inside the
seven, rotated so each validates exactly once, and standardisation and the vocabulary are fitted
on the remaining six alone.

**Training windows are sampled the way live windows are.** Boundaries fall on the epoch, because
that is where the dashboard puts them and it has no capture start to anchor on. The per-window
alert cap is 4,096, set against the indexer's 5,000 document search ceiling rather than against
this data, so no training row can claim a count the panel could never produce. Both of those were
wrong at first: windows were anchored on the first alert of the capture and capped at 256, which
meant a burst the panel would split across two windows could arrive in training as one, and the
count feature saturated on a fifth of the attack windows. Neither defect was visible in any
score. The second one was also hiding a finding, which is in the width table below.

## Where it stands, measured

Leave one network out, eight folds, three seeds per fold for the GRU:

| | f1 | average precision |
| --- | --- | --- |
| best single rule | 0.235 (sd 0.148) | 0.160 (sd 0.098) |
| GRU over the sequence | 0.164 (sd 0.123) | 0.188 (sd 0.085) |
| logistic on shape and severity, the deployed one | 0.227 (sd 0.114) | 0.220 (sd 0.099) |
| logistic on counts and timing | **0.251** (sd 0.154) | **0.251** (sd 0.108) |
| random | | 0.021, the base rate |

**The GRU loses to logistic regression on seven of the eight folds, by a mean margin of 0.063
average precision with a spread of 0.048 on that margin.** It is the one comparison here that
is consistent rather than noisy, and it points away from the neural network. On this evidence
PyTorch is not justified for this problem.

Three things worth taking from that, and they are not all negative.

**Every model finds real signal.** 0.251 against a 0.021 base rate is twelve times better than
chance, the deployed portable set reaches ten times, and the single rule at 0.160 is seven and a
half. The signal is there; the argument is only about what is needed to extract it.

**None of them are deployable on their own.** Take the winning model on its best fold, wheeler,
which is 1,181 windows containing 15 attack windows. Ranked by score it holds perfect precision
down to recall 0.400, six attacks caught and nothing false. Push it to catch half of them,
recall 0.533, and precision is 0.031: eight real attacks arriving with 246 false positives
beside them. This is what alert triage actually looks like at a 2% base rate, and it is the
honest correction to the synthetic result below.

**The synthetic numbers were measuring the generator.** For comparison, on
`make-synthetic.py` output: rule 100111 alone f1 0.857, GRU f1 0.948 over five seeds, logistic
f1 **1.000**, GRU average precision 0.997. Everything near the ceiling. `make-synthetic.py` builds in exactly
two signals, that an attacker brute forces before persisting and moves between steps in
seconds, and both are linearly separable from counts and a burst measure. A good score there
was evidence the pipeline ran, not that anything had been detected. Real alerts cost every
model about 0.75 of its f1.

## How much of this is the window, and how much is the split

`window-sensitivity.py` re-imports the archive at each width and re-runs the same eight folds:

| window | average precision | sd |
| --- | --- | --- |
| 120s | 0.209 | 0.109 |
| 300s | 0.252 | 0.108 |
| 600s | 0.319 | 0.092 |

Average precision rises with the window, by half again across that range, so the width has to
be quoted with any number taken from here. An earlier version of this section reported a flat
curve and called the result stable. That was an artefact: the per-window alert cap was 256 at
the time, so the extra alerts a wider window collected were being thrown away before the
features saw them. Raising the cap to the live ceiling made the slope visible.

300 seconds is deployed anyway, because that is what the panel buckets at, and a training window
has to be the window the model will be shown. It is a stated trade, not the best score on the
table.

A time split rather than a network split scores 0.314 against the network split's 0.252, which
is the direction that should worry nobody: a time split shares every network between fitting and
test, so it is the easier problem and it comes out easier.

## What is deployed, and why it is not the winner

The model with the best mean cannot be run on this lab. Its feature vector is one column per
AIT rule id, and this lab and AIT share two signatures out of thirty one. Pointed at live lab
alerts, every one of them lands in the unknown column and the model returns a confident number
about nothing. Deploying it and calling it a detection would be the most dishonest thing in this
repository.

`shape_only()` in `features.py` is the feature set that survives the move. Eleven columns: how
many alerts arrived, over how long, how close together, how tightly the busiest minute was
packed, how many distinct signatures were involved, and how severe they were. No rule id appears
in it. Severity earns its place by being a property of the Wazuh ruleset rather than of one
capture, so it transfers where a rule id does not, and `severity-ablation.py` says what that is
worth rather than leaving it as an argument: dropping the four level columns costs 0.029 average
precision and hurts on seven of the eight folds, and the four on their own reach 0.189, which is
86% of what all eleven reach.

It keeps 88% of the full model, beats the best single rule on all eight folds, and beats the
base rate on all eight. The 0.031 average precision it gives up has a spread of 0.035 across
folds, which is to say the gap between the two feature sets is smaller than the noise on it, and
the portable set is ahead on three of the eight. That inverts what this section used to claim.
The earlier reading was that most of the signal lived in *which* rules fired, so portability was
expensive; the corrected sampling says the rule identity columns are worth almost nothing that
the shape and severity of the burst does not already carry.

`export-model.py` fits it on seven networks, picks its cutoff on the eighth, and writes
`scorer/model.json` with the eight fold result inside the file. A weights file carrying no
measurement gets trusted more than it has earned. The export refuses to write if `scorer/score.py`
and `features.py` disagree about what the features are, because that failure looks exactly like a
working dashboard.

The [lab dashboard](../dashboard/README.md) scores the last twelve windows on every poll,
inside the SSH round trip it was already making, in plain Python, with nothing installed on the
manager beyond the three root-owned helpers it is granted by exact path. Alerts come from an
authenticated indexer search over the manager's own admin certificate, with the alert log tail
as a fallback that says when it has hit its ceiling. The panel prints the model's provenance and
its measured average precision underneath itself, and says that it has never been measured on
this lab, which is what a campaign would fix.

## The report

[docs/Detection-Modelling-Report.pdf](../docs/Detection-Modelling-Report.pdf), seven pages,
rebuilt with `report/Build-Report.ps1`. Every figure in it is read from `data/ait/folds.jsonl`,
`scorer/model.json` or a run the build makes itself, and a missing artefact stops the build rather
than printing a zero. This README drifted from its own numbers once inside a week, which is why
the document that leaves the repository is generated rather than written.

## Not done yet

- **The lab's own rules are still untested in sequence.** Nothing public contains them. That
  is what `run-campaign.sh` is for, and it is now a specific question rather than a blocker.
- **Pattern of life, per account.** There is now a per-endpoint baseline on the manager, and
  `evaluate_adaptive.py` measures what it is worth. Per *account* is still open:
  `run-campaign.sh` creates three standing accounts with different shapes precisely so that a
  per-user baseline is possible, and nothing reads them apart yet.
- **The GRU has not been given every chance.** It is 5,458 parameters on 2.1% positives with
  no class-balanced sampling, no threshold tuned per fold during training, and no attention
  over the window. A fair reading of the result above is that a small recurrent model does not
  beat counting on this data, not that no sequence model ever could.
- **Windows scenarios.** Rules 100100 to 100103 are in the lab vocabulary and unreachable from
  a Linux campaign.
- **The deployed model has never been measured here.** Its 0.220 is what it scored on networks
  it had not seen. This lab is a ninth such network, so that is the honest expectation for it
  and not a result from it. The panel says so and will keep saying so until a campaign runs.
