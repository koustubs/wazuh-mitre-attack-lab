"""Turn episodes into model input, and split them the way a time series has to be split.

The split is by time, not at random. Episodes come from one continuous campaign, so shuffling
before splitting lets the model see the future: the test set would sit between training
examples drawn minutes either side of it, and the score would be optimistic for a reason that
has nothing to do with detection.
"""
from __future__ import annotations

import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from alert_stream import LABEL_TO_IX, PAD, RULE_IDS, RULE_TO_IX, read_episodes

# Names in the same order tabular() builds its columns, so a coefficient can be read back.
TABULAR_COLUMNS = (
    [("count_%d" % r) for r in RULE_IDS]
    + ["n_alerts", "duration_s", "min_gap_s", "median_gap_s", "max_gap_s", "busiest_60s"]
)


def load_split(path, train_frac=0.7):
    """Oldest train_frac of episodes for training, the rest held out."""
    episodes = read_episodes(path)
    episodes.sort(key=lambda e: e["startedAt"])
    if not episodes:
        raise SystemExit("No episodes in %s" % path)
    cut = int(len(episodes) * train_frac)
    if cut == 0 or cut == len(episodes):
        raise SystemExit("Not enough episodes to split: %d" % len(episodes))
    return episodes[:cut], episodes[cut:]


def _times_and_rules(ep):
    alerts = sorted(ep["alerts"], key=lambda a: a["at"])
    return [a["at"] for a in alerts], [a["ruleId"] for a in alerts]


def tabular(episodes):
    """Counts per rule plus the shape of the timing. What a non-neural model gets to see."""
    X = np.zeros((len(episodes), len(TABULAR_COLUMNS)), dtype=np.float64)
    y = np.zeros(len(episodes), dtype=np.int64)
    for i, ep in enumerate(episodes):
        times, rules = _times_and_rules(ep)
        row = []
        for r in RULE_IDS:
            row.append(float(rules.count(r)))
        gaps = np.diff(times) if len(times) > 1 else np.array([0.0])
        # busiest_60s is the timing signal the episode grammar actually builds in: an attacker
        # moves between steps in seconds where an administrator takes minutes.
        busiest = 0
        for t in times:
            busiest = max(busiest, sum(1 for u in times if t <= u < t + 60.0))
        row += [
            float(len(times)),
            float(times[-1] - times[0]) if len(times) > 1 else 0.0,
            float(gaps.min()), float(np.median(gaps)), float(gaps.max()),
            float(busiest),
        ]
        X[i] = row
        y[i] = LABEL_TO_IX[ep["label"]]
    return X, y


def sequences(episodes, max_len=64):
    """Rule ids as tokens plus the gap before each one, left padded to max_len.

    The gap is log1p'd because inter-arrival times here span three orders of magnitude, from
    0.05 seconds between a failed password and the composite rule it triggers, to five minutes
    between an administrator's two steps.
    """
    n = len(episodes)
    ids = np.full((n, max_len), PAD, dtype=np.int64)
    gaps = np.zeros((n, max_len), dtype=np.float32)
    lengths = np.zeros(n, dtype=np.int64)
    y = np.zeros(n, dtype=np.int64)
    for i, ep in enumerate(episodes):
        times, rules = _times_and_rules(ep)
        # Keep the most recent max_len alerts: the tail of a window is where persistence lands.
        times, rules = times[-max_len:], rules[-max_len:]
        L = len(rules)
        lengths[i] = L
        for j, (t, r) in enumerate(zip(times, rules)):
            pos = max_len - L + j
            ids[i, pos] = RULE_TO_IX[r]
            gaps[i, pos] = np.log1p(max(0.0, t - times[j - 1]) if j else 0.0)
        y[i] = LABEL_TO_IX[ep["label"]]
    return ids, gaps, lengths, y


def standardise(train, *others):
    """Scale using the training set's own statistics only. Using the test set's would leak."""
    mu = train.mean(axis=0)
    sd = train.std(axis=0)
    sd[sd == 0] = 1.0
    return ((train - mu) / sd,) + tuple((o - mu) / sd for o in others)


def scores(y_true, y_pred, positive=1):
    """Accuracy plus the numbers that matter when the classes are not balanced."""
    tp = int(np.sum((y_pred == positive) & (y_true == positive)))
    fp = int(np.sum((y_pred == positive) & (y_true != positive)))
    fn = int(np.sum((y_pred != positive) & (y_true == positive)))
    tn = int(np.sum((y_pred != positive) & (y_true != positive)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"accuracy": (tp + tn) / max(len(y_true), 1), "precision": precision,
            "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def report(name, s):
    print("  %-28s acc %.3f   precision %.3f   recall %.3f   f1 %.3f   "
          "(tp %d fp %d fn %d tn %d)"
          % (name, s["accuracy"], s["precision"], s["recall"], s["f1"],
             s["tp"], s["fp"], s["fn"], s["tn"]))
