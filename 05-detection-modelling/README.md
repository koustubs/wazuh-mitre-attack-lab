# Detection modelling

Step 4 of the lab detects single events. Rule 100110 counts a failed SSH password, rule 100112
notices an account being created. Neither knows the other exists, and neither knows what an
ordinary Tuesday looks like on the endpoint.

This is the attempt to add the thing they cannot do: read a *run* of alerts and judge it.

The short answer, measured on 2.6 million real alerts across eight networks: **a sequence
model does not earn its place.** Plain logistic regression on rule counts and timing beats it
on eight held out networks out of eight. The detail is below, including the numbers that say
so and the reasons not to read too much into them.

A second answer sits under that one. The model that won cannot be deployed here at all, because
its features name AIT rule ids and this lab has different rules. What is actually running on the
dashboard is a portable version of it, fitted on eleven features that name no signature, and
what that costs is measured rather than waved at. See
[what is deployed](#what-is-deployed-and-why-it-is-not-the-winner).

The seven page version of all of this, for a reader who is not going to clone the repository, is
[docs/Detection-Modelling-Report.pdf](../docs/Detection-Modelling-Report.pdf).

## The order of work, and why

1. **Get data.** Either `import-ait.py` for the public set, or
   `04-implementation/linux/run-campaign.sh` for the lab's own. See
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
python export-model.py
```

The import parses 2.8 GB out of the archive once and caches what it needs, so re-running at a
different `--window` is seconds. `evaluate.py` is about fifty minutes on CPU.

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
phase. That gives 8,915 episodes, 187 of them attack, a base rate of 2.1%.

## Three things done deliberately

**Whole networks are held out, not the tail of a timeline.** Each scenario is a separate
network. A model that scores well on one it has never seen has generalised; a model that
scores well on the last hour of a network it trained on may only have learned that network's
noise floor.

**Average precision, not f1 at a fixed cutoff.** At a 2% base rate, f1 at 0.5 says more about
where a model happens to put its threshold than about whether it ranks attacks above
background. Logistic regression scores f1 0.049 at 0.5 and 0.367 at a threshold chosen on
validation, on identical predictions. Average precision cannot be flattered that way. Every
threshold quoted here was picked on a validation slice and never on the test set.

**Eight folds, not one split.** On a single split the logistic model and the GRU finished
0.046 apart in average precision with forty attack episodes between them, which is well inside
what a different pair of held out networks would move. Counting fold wins is the claim that
survives.

## Where it stands, measured

Leave one network out, eight folds, three seeds per fold for the GRU:

| | f1 | average precision |
| --- | --- | --- |
| best single rule | 0.245 (sd 0.134) | 0.161 (sd 0.092) |
| logistic on shape and severity, the deployed one | 0.192 (sd 0.107) | 0.177 (sd 0.080) |
| GRU over the sequence | 0.180 (sd 0.112) | 0.199 (sd 0.081) |
| logistic on counts and timing | **0.292** (sd 0.121) | **0.249** (sd 0.097) |
| random | | 0.021, the base rate |

**Logistic regression wins all eight folds. The GRU beats it on none of them, by a mean margin
of 0.049 average precision.** On this evidence PyTorch is not justified for this problem.

Three things worth taking from that, and they are not all negative.

**All three models find real signal.** 0.249 against a 0.021 base rate is twelve times better
than chance, and the single rule at 0.161 is not far behind. The signal is there; the argument
is only about what is needed to extract it.

**None of them are deployable.** Take the winning model on its best fold, wheeler, which is
1,166 windows containing 16 attack windows. Ranked by score it holds perfect precision down to
recall 0.375, six attacks caught and nothing false. Push it to catch half of them, recall
0.500, and precision is 0.063: eight real attacks arriving with 119 false positives beside
them. This is what alert triage actually looks like at a 2% base rate, and it is the honest
correction to the synthetic result below.

**The synthetic numbers were measuring the generator.** For comparison, on
`make-synthetic.py` output: rule 100111 alone f1 0.857, GRU f1 0.948 over five seeds, logistic
f1 **1.000**, GRU average precision 0.997. Everything near the ceiling. `make-synthetic.py` builds in exactly
two signals, that an attacker brute forces before persisting and moves between steps in
seconds, and both are linearly separable from counts and a burst measure. A good score there
was evidence the pipeline ran, not that anything had been detected. Real alerts cost every
model about 0.75 of its f1.

The result is stable in the ways that were checked. Window width barely moves it: logistic
average precision is 0.296, 0.303 and 0.289 at 120, 300 and 600 second windows. A time split
rather than a network split gives 0.273, the same picture.

## What is deployed, and why it is not the winner

The model that wins every fold cannot be run on this lab. Its feature vector is one column per
AIT rule id, and this lab and AIT share two signatures out of thirty one. Pointed at live lab
alerts, every one of them lands in the unknown column and the model returns a confident number
about nothing. Deploying it and calling it a detection would be the most dishonest thing in this
repository.

`shape_only()` in `features.py` is the feature set that survives the move. Eleven columns: how
many alerts arrived, over how long, how close together, how tightly the busiest minute was
packed, how many distinct signatures were involved, and how severe they were. No rule id appears
in it. Severity earns its place by being a property of the Wazuh ruleset rather than of one
capture, so it transfers where a rule id does not, and on three folds it roughly doubled average
precision on its own.

It keeps 71% of the full model, beats the best single rule, and beats the base rate on all eight
folds. The 0.072 average precision it gives up is the measured price of portability, and the
reason it is that large is itself a finding: most of the signal was in *which* rules fired, not
in the shape of the burst. That is an argument for the rule based approach this lab already has.

`export-model.py` fits it on seven networks, picks its cutoff on the eighth, and writes
`scorer/model.json` with the eight fold result inside the file. A weights file carrying no
measurement gets trusted more than it has earned. The export refuses to write if `scorer/score.py`
and `features.py` disagree about what the features are, because that failure looks exactly like a
working dashboard.

The [lab dashboard](../04-implementation/host/lab-dashboard/README.md) scores the last twelve
windows on every poll, inside the SSH round trip it was already making. 4 ms for the manager's
full 800 record sample, in plain Python, with nothing installed on the manager. The panel prints
the model's provenance and its measured average precision underneath itself and says that it has
never been measured on this lab, which is what a campaign would fix.

## The report

[docs/Detection-Modelling-Report.pdf](../docs/Detection-Modelling-Report.pdf), seven pages,
rebuilt with `report/Build-Report.ps1`. Every figure in it is read from `data/ait/folds.jsonl`,
`scorer/model.json` or a run the build makes itself, and a missing artefact stops the build rather
than printing a zero. This README drifted from its own numbers once inside a week, which is why
the document that leaves the repository is generated rather than written.

## Not done yet

- **The lab's own rules are still untested in sequence.** Nothing public contains them. That
  is what `run-campaign.sh` is for, and it is now a specific question rather than a blocker.
- **Pattern of life.** `run-campaign.sh` creates three standing accounts with different shapes
  precisely so a per-user baseline is possible. Nothing here uses them.
- **The GRU has not been given every chance.** It is 5,458 parameters on 2.1% positives with
  no class-balanced sampling, no threshold tuned per fold during training, and no attention
  over the window. A fair reading of the result above is that a small recurrent model does not
  beat counting on this data, not that no sequence model ever could.
- **Windows scenarios.** Rules 100100 to 100103 are in the lab vocabulary and unreachable from
  a Linux campaign.
- **The deployed model has never been measured here.** Its 0.177 is what it scored on networks
  it had not seen. This lab is a ninth such network, so that is the honest expectation for it
  and not a result from it. The panel says so and will keep saying so until a campaign runs.
