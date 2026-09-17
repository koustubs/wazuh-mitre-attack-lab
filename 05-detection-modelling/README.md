# Detection modelling

Step 4 of the lab detects single events. Rule 100110 counts a failed SSH password, rule 100112
notices an account being created. Neither knows the other exists, and neither knows what an
ordinary Tuesday looks like on the endpoint.

This is the attempt to add the thing they cannot do: read a *run* of alerts and judge it.

## The order of work, and why

1. **Collect.** `04-implementation/linux/run-campaign.sh`. See
   [docs/collecting-a-dataset.md](../docs/collecting-a-dataset.md).
2. **Export.** Join each recorded run to the alerts it actually caused. Not built yet.
3. **Baseline.** `baseline.py`. Non-neural, and the number everything else has to beat.
4. **Model.** `train.py`. Last, and smallest.

The model is last because it is the easy part. The hard part is having something to train on
and something to compare against.

## Files

| | |
| --- | --- |
| `alert_stream.py` | The rule vocabulary and the episode contract both producers must agree on |
| `make-synthetic.py` | A stand-in alert stream, so the pipeline can be built before a real campaign exists |
| `features.py` | Windows into model input, and the time-ordered split |
| `baseline.py` | Rule 100111 alone, the degenerate classifier, and logistic regression |
| `train.py` | An embedding, a GRU and a linear head, in PyTorch |

## Running it

```bash
python make-synthetic.py --hours 14 --seed 1
python baseline.py --data data/synthetic/episodes.jsonl
python train.py    --data data/synthetic/episodes.jsonl
```

Needs `torch`, `numpy`. No sklearn: the logistic regression is about twenty lines of numpy,
which is less than the cost of another dependency in a repo meant to be cloned.

## Two things done deliberately

**The split is by time, never shuffled.** Episodes come from one continuous campaign. Shuffling
before splitting would put test episodes between training examples recorded minutes either
side, and the score would improve for reasons that have nothing to do with detection.

**Results are reported across five seeds.** The test set is about fifty episodes. One seed on
fifty samples is a sample, not a result, and the spread below is not small enough to ignore.

## Where it stands, measured

On **synthetic** data: 167 episodes, 51 held out, 39% attack.

| | f1 |
| --- | --- |
| rule 100111 alone | 0.857 |
| GRU over the sequence | 0.947 mean, 0.046 sd, 0.857 worst |
| logistic regression on counts and timing | **1.000** |

Read that honestly. **The GRU loses to logistic regression, and one seed in five collapses to
exactly the rule baseline.** On this data, PyTorch is not justified.

Two reasons, and they point in different directions:

The synthetic data is too clean. `make-synthetic.py` builds in exactly two signals, that an
attacker brute forces before persisting and moves between steps in seconds, and both are
linearly separable from rule counts and a burst measure. A linear model is the right size for
that problem, so it wins. Real alerts will be messier and every number here will fall.

And 98 training episodes is not enough for a recurrent model to be stable. The seed spread says
so directly. More data may fix that. A night of collection is the experiment that finds out.

What is worth keeping from this either way: rule 100111 alone has **recall 0.75**, and every
one of its misses is the same case, an attack that never brute forced. Both models find those.
That is the concrete gap in the current detection, and it does not need a neural network to
close.

## Not done yet

- **The exporter.** Everything above runs on synthetic alerts. Until step 2 exists, no result
  here describes the lab.
- **Pattern of life.** `run-campaign.sh` creates three standing accounts with different shapes
  precisely so a per-user baseline is possible. Nothing here uses them yet.
- **Windows scenarios.** Rules 100100 to 100103 are in the vocabulary and unreachable from a
  Linux campaign.
