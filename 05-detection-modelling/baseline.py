"""The numbers a model has to beat before it is worth having.

Three of them, in increasing order of effort:

  rule 100111        Did the composite brute force rule fire in this window? This is the
                     detection the lab already ships. If a model does not beat this, the model
                     is not adding anything and should be said so plainly.
  always attack      The degenerate classifier. Catches everything, cries wolf constantly. It
                     exists to show what recall alone is worth.
  logistic           Rule counts plus the shape of the timing, fitted with plain gradient
                     descent. No neural network, no sklearn.

Run after make-synthetic.py or export-campaign.py:

    python baseline.py --data data/synthetic/episodes.jsonl
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from alert_stream import COMPOSITE_RULE, LABEL_TO_IX
from features import (TABULAR_COLUMNS, load_split, report, scores, standardise, tabular)

ATTACK = LABEL_TO_IX["attack"]


def rule_only(episodes):
    """Exactly what rule 100111 does: fire if six failed SSH passwords landed in two minutes."""
    return np.array([
        int(any(a["ruleId"] == COMPOSITE_RULE for a in ep["alerts"])) for ep in episodes
    ], dtype=np.int64)


def fit_logistic(X, y, epochs=3000, lr=0.15, l2=1e-3, seed=0):
    """Plain batch gradient descent on the log loss. Small data, so nothing fancier is needed."""
    rng = np.random.default_rng(seed)
    n, d = X.shape
    w = rng.normal(0, 0.01, d)
    b = 0.0
    # Weight the rarer class up, or the model can score well by rarely saying attack.
    pos = max(float(y.sum()), 1.0)
    neg = max(float(len(y) - y.sum()), 1.0)
    wpos, wneg = neg / pos, 1.0
    sample_w = np.where(y == 1, wpos, wneg)
    sample_w = sample_w / sample_w.mean()

    for _ in range(epochs):
        z = X @ w + b
        p = 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))
        err = (p - y) * sample_w
        w -= lr * ((X.T @ err) / n + l2 * w)
        b -= lr * err.mean()
    return w, b


def predict_logistic(X, w, b):
    z = X @ w + b
    return (1.0 / (1.0 + np.exp(-np.clip(z, -30, 30))) >= 0.5).astype(np.int64)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default="data/synthetic/episodes.jsonl")
    p.add_argument("--train-frac", type=float, default=0.7)
    a = p.parse_args()

    train, test = load_split(a.data, a.train_frac)
    Xtr, ytr = tabular(train)
    Xte, yte = tabular(test)
    Xtr_s, Xte_s = standardise(Xtr, Xte)

    print("%s" % a.data)
    print("  train %d episodes (%d attack)   test %d episodes (%d attack)   split by time"
          % (len(train), int(ytr.sum()), len(test), int(yte.sum())))
    print()
    print("Held out results:")

    report("rule 100111 only", scores(yte, rule_only(test)))
    report("always attack", scores(yte, np.ones_like(yte)))

    w, b = fit_logistic(Xtr_s, ytr)
    report("logistic, counts + timing", scores(yte, predict_logistic(Xte_s, w, b)))

    print()
    print("Largest logistic weights (positive pushes towards attack):")
    for i in np.argsort(-np.abs(w))[:8]:
        print("  %-16s %+.3f" % (TABULAR_COLUMNS[i], w[i]))


if __name__ == "__main__":
    main()
