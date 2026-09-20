"""The numbers a model has to beat before it is worth having.

Three of them, in increasing order of effort:

  one rule           Did a single signature fire in this window? On the lab campaign that is
                     100111, the composite brute force rule the lab already ships. On another
                     dataset it is the strongest single signature found on training data, so
                     the comparison is against the best version of "just alert on the rule"
                     rather than a strawman. A model that cannot beat this is not adding
                     anything, and saying so plainly is the point of this file.
  always attack      The degenerate classifier. Catches everything, cries wolf constantly. It
                     exists to show what recall alone is worth.
  logistic           Rule counts plus the shape of the timing, fitted with plain gradient
                     descent. No neural network, no sklearn.

Everything is reported twice over, because one number is not enough when positives are rare.
f1 at a chosen operating point says what an analyst would see; average precision says how well
the thing ranks, and cannot be flattered by moving the threshold. Where a threshold is needed
it is picked on a slice held back from training, never on the test set.

Run after make-synthetic.py or import-ait.py:

    python baseline.py --data data/synthetic/episodes.jsonl
    python baseline.py --data data/ait/episodes.jsonl --split source
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from alert_stream import COMPOSITE_RULE, LABEL_TO_IX
from features import (average_precision, build_vocab, load_split, pick_threshold, report,
                      scores, sources_of, standardise, tabular, tabular_columns)

ATTACK = LABEL_TO_IX["attack"]


def rule_only(episodes, rule=COMPOSITE_RULE):
    """Exactly what one composite rule does: fire if it appeared anywhere in the window.

    On the lab campaign that is 100111, six failed SSH passwords inside two minutes. On a
    public dataset the equivalent is whichever single signature the operator would have
    alerted on, passed in with --rule. The point of the comparison does not change: a model
    that cannot beat one rule is not worth deploying over that rule.
    """
    return np.array([
        int(any(a["ruleId"] == rule for a in ep["alerts"])) for ep in episodes
    ], dtype=np.int64)


def best_single_rule(train, ytr, vocab):
    """The single most useful signature by f1 on training data.

    Chosen on training only, then reported on the held out set like everything else. This is
    the fairest version of the rule baseline when the dataset is not ours and there is no
    obvious candidate to nominate by hand.
    """
    best, best_f1 = None, -1.0
    for r in vocab.rule_ids:
        f1 = scores(ytr, rule_only(train, r))["f1"]
        if f1 > best_f1:
            best, best_f1 = r, f1
    return best, best_f1


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


def score_logistic(X, w, b):
    return 1.0 / (1.0 + np.exp(-np.clip(X @ w + b, -30, 30)))


def predict_logistic(X, w, b, threshold=0.5):
    return (score_logistic(X, w, b) >= threshold).astype(np.int64)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default="data/synthetic/episodes.jsonl")
    p.add_argument("--train-frac", type=float, default=0.7)
    p.add_argument("--split", choices=("time", "source"), default="time",
                   help="time holds out the tail of the timeline; source holds out whole "
                        "capture sources, which is the harder test where it is possible")
    p.add_argument("--rule", type=int, default=None,
                   help="the single signature to compare against (default 100111 on lab data, "
                        "or the best one found on training data elsewhere)")
    a = p.parse_args()

    train, test = load_split(a.data, a.train_frac, a.split)
    vocab = build_vocab(train, a.data)
    cols = tabular_columns(vocab)

    Xtr, ytr = tabular(train, vocab)
    Xte, yte = tabular(test, vocab)
    Xtr_s, Xte_s = standardise(Xtr, Xte)

    print("%s" % a.data)
    print("  train %d episodes (%d attack, %.1f%%)   test %d episodes (%d attack, %.1f%%)"
          % (len(train), int(ytr.sum()), 100.0 * ytr.mean(),
             len(test), int(yte.sum()), 100.0 * yte.mean()))
    print("  split by %s   %d signatures in the training vocabulary" % (a.split, len(vocab.rule_ids)))
    if a.split == "source":
        print("  train sources: %s" % ", ".join(sources_of(train)))
        print("  held out:      %s" % ", ".join(sources_of(test)))
    print()

    # Which single rule to hold the models against. The lab answer is 100111 and is not up for
    # debate; on any other dataset, nominating one by hand would be picking a weak opponent, so
    # the strongest single signature on training data is used instead.
    rule = a.rule
    picked_note = ""
    if rule is None:
        if COMPOSITE_RULE in vocab.rule_ids:
            rule = COMPOSITE_RULE
        else:
            rule, tr_f1 = best_single_rule(train, ytr, vocab)
            picked_note = " (best of %d on training, f1 %.3f there)" % (len(vocab.rule_ids), tr_f1)

    print("Held out results:")
    if rule is not None:
        label = "rule %d only" % rule
        desc = vocab.describe(rule)
        report(label, scores(yte, rule_only(test, rule)))
        if desc:
            print("  %-28s %s%s" % ("", desc, picked_note))
    report("always attack", scores(yte, np.ones_like(yte)))

    # The threshold is chosen on the tail of training, never on the test set. Comparing a rule
    # (which has no threshold) against a model left at 0.5 is not a comparison, and at a 2%
    # base rate the cut moves f1 further than anything else in this file.
    cut = int(len(Xtr_s) * 0.85)
    w, b = fit_logistic(Xtr_s[:cut], ytr[:cut])
    thr, thr_f1 = pick_threshold(ytr[cut:], score_logistic(Xtr_s[cut:], w, b))
    ste = score_logistic(Xte_s, w, b)

    report("logistic @0.5", scores(yte, (ste >= 0.5).astype(np.int64)))
    report("logistic @%.3f" % thr, scores(yte, (ste >= thr).astype(np.int64)))
    print("  %-28s threshold picked on held back training slice, f1 %.3f there"
          % ("", thr_f1))

    print()
    print("Ranking quality, which no threshold can flatter:")
    print("  %-28s average precision %.3f   (random would score %.3f, the base rate)"
          % ("logistic", average_precision(yte, ste), float(yte.mean())))
    if rule is not None:
        print("  %-28s average precision %.3f"
              % ("rule %d only" % rule, average_precision(yte, rule_only(test, rule))))

    print()
    print("Largest logistic weights (positive pushes towards attack):")
    for i in np.argsort(-np.abs(w))[:10]:
        name = cols[i]
        desc = ""
        if name.startswith("count_") and name[6:].isdigit():
            desc = vocab.describe(int(name[6:]))
        print("  %-16s %+.3f  %s" % (name, w[i], desc))


if __name__ == "__main__":
    main()
