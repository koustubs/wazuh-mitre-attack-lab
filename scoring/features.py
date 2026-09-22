"""Turn episodes into model input, and split them the way this data has to be split.

Never at random. Episodes from one campaign are a time series, so shuffling before splitting
lets the model see the future: the test set would sit between training examples drawn minutes
either side of it, and the score would improve for a reason that has nothing to do with
detection. Two honest splits are offered instead.

  time     The oldest train_frac of episodes trains, the rest is held out. Right when every
           episode comes from one continuous capture, which is what a lab campaign produces.

  source   Whole sources are held out. Right when the data has several independent origins,
           as the AIT scenarios do, because scoring well on a network never seen during
           training is generalisation rather than a learned noise floor. Strictly the harder
           of the two, and the one to quote when it is available.
"""
from __future__ import annotations

import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from alert_stream import LAB_VOCAB, LABEL_TO_IX, PAD, Vocabulary, read_episodes


def tabular_columns(vocab=LAB_VOCAB):
    """Names in the order tabular() builds its columns, so a coefficient can be read back."""
    return ([("count_%d" % r) for r in vocab.rule_ids]
            + ["count_unknown", "n_alerts", "duration_s", "min_gap_s", "median_gap_s",
               "max_gap_s", "busiest_60s"])


# Kept for the lab vocabulary so existing callers still import a constant.
TABULAR_COLUMNS = tabular_columns()


def build_vocab(train_episodes, path=None):
    """The vocabulary a model is allowed to know, built from the training episodes only.

    Building it from the whole file would leak: the held out sources would be contributing the
    fact that a signature exists. Anything they bring that training never saw falls through to
    the unknown index, which is the correct thing for it to do. A vocab.json written beside the
    data supplies the human readable descriptions and nothing that affects indexing.
    """
    v = Vocabulary.from_episodes(train_episodes)
    if path is not None:
        side = pathlib.Path(path).with_name("vocab.json")
        if side.exists():
            v.names = Vocabulary.load(side).names
    return v


def load_split(path, train_frac=0.7, by="time"):
    """Split into train and held out. See the module docstring for the two modes."""
    episodes = read_episodes(path)
    if not episodes:
        raise SystemExit("No episodes in %s" % path)

    if by == "source":
        if not all("source" in e for e in episodes):
            raise SystemExit(
                "--split source needs a 'source' on every episode; this file has none. "
                "Use --split time.")
        groups = {}
        for e in episodes:
            groups.setdefault(e["source"], []).append(e)
        if len(groups) < 2:
            raise SystemExit("--split source needs at least two sources, found %d"
                             % len(groups))
        # Sorted by name so the split is reproducible, then filled greedily until training has
        # its share. Whichever sources are left over are the test set, whole.
        want = len(episodes) * train_frac
        train, test, running = [], [], 0
        for name in sorted(groups):
            bucket = groups[name]
            # The last source always goes to test, or a large final source could absorb
            # everything and leave nothing held out.
            if running < want and name != sorted(groups)[-1]:
                train.extend(bucket)
                running += len(bucket)
            else:
                test.extend(bucket)
        train.sort(key=lambda e: (e["source"], e["startedAt"]))
        test.sort(key=lambda e: (e["source"], e["startedAt"]))
        if not train or not test:
            raise SystemExit("Source split left one side empty")
        return train, test

    episodes.sort(key=lambda e: e["startedAt"])
    cut = int(len(episodes) * train_frac)
    if cut == 0 or cut == len(episodes):
        raise SystemExit("Not enough episodes to split: %d" % len(episodes))
    return episodes[:cut], episodes[cut:]


def sources_of(episodes):
    return sorted({e.get("source", "-") for e in episodes})


def _times_and_rules(ep):
    alerts = sorted(ep["alerts"], key=lambda a: a["at"])
    return [a["at"] for a in alerts], [a["ruleId"] for a in alerts]


def _timing_row(times):
    """The six timing features, in the order tabular_columns names them.

    Shared by tabular() and shape_only() so the two cannot drift apart. A model exported from
    one and fed by the other would be wrong in a way no test here would notice.

    busiest_60s is the timing signal the episode grammar actually builds in: an attacker moves
    between steps in seconds where an administrator takes minutes.

    A sliding window rather than the obvious pair of nested loops. times is sorted, so the
    right hand edge only ever moves forward and the whole thing is one pass. The nested
    version was quadratic in the alerts per episode, which nobody noticed at nine alerts a run
    and which dominated the runtime at two hundred and fifty.
    """
    gaps = np.diff(times) if len(times) > 1 else np.array([0.0])
    busiest = 0
    right = 0
    for left, t in enumerate(times):
        while right < len(times) and times[right] < t + 60.0:
            right += 1
        busiest = max(busiest, right - left)
    return [
        float(len(times)),
        float(times[-1] - times[0]) if len(times) > 1 else 0.0,
        float(gaps.min()), float(np.median(gaps)), float(gaps.max()),
        float(busiest),
    ]


def tabular(episodes, vocab=LAB_VOCAB):
    """Counts per rule plus the shape of the timing. What a non-neural model gets to see."""
    cols = tabular_columns(vocab)
    known = set(vocab.rule_ids)
    X = np.zeros((len(episodes), len(cols)), dtype=np.float64)
    y = np.zeros(len(episodes), dtype=np.int64)
    for i, ep in enumerate(episodes):
        times, rules = _times_and_rules(ep)
        row = []
        for r in vocab.rule_ids:
            row.append(float(rules.count(r)))
        row.append(float(sum(1 for r in rules if r not in known)))
        row += _timing_row(times)
        X[i] = row
        y[i] = LABEL_TO_IX[ep["label"]]
    return X, y


# The features that do not name a signature, and therefore mean the same thing on a network
# whose rule set nobody here has seen. Severity is in here and rule identity is not, which is
# the whole distinction: level 10 means the same thing in every Wazuh install, and rule 52507
# means nothing outside the capture it came from.
SHAPE_COLUMNS = ["n_alerts", "duration_s", "min_gap_s", "median_gap_s", "max_gap_s",
                 "busiest_60s", "n_distinct_rules", "max_level", "mean_level",
                 "n_level_ge_7", "n_level_ge_10"]


def shape_only(episodes):
    """The shape and severity of a burst, with every per-rule count removed.

    tabular() is the stronger feature set and it is the one to quote, but it cannot leave the
    dataset it was fitted on. Its columns are one per rule id, and the AIT rule ids and this
    lab's rule ids have two values in common out of thirty one. Scoring lab alerts with a
    model fitted on AIT counts would put every alert in the unknown column and return a number
    that looks like a probability and means nothing. This is the feature set that survives the
    move, and it is what gets exported and deployed.

    Eleven columns: how many alerts arrived, over how long, how close together, how tightly
    the busiest minute was packed, how many distinct signatures were involved, and how severe
    they were. Severity earns its place by being a property of the Wazuh ruleset rather than
    of any one capture, so it transfers where a rule id does not. severity-ablation.py is
    what that is worth rather than what it sounds like: dropping the four level columns costs
    0.029 average precision and hurts on seven of the eight folds, and the four on their own
    reach 86% of what all eleven reach.

    What the whole set costs against tabular() is measurable, and evaluate.py measures it. It
    is 0.031 average precision, against a 0.035 spread on that difference across folds, so the
    price of portability is smaller than the fold to fold noise on it.

    No vocabulary argument, deliberately. There is nothing here for a vocabulary to index, and
    accepting one would imply otherwise.
    """
    X = np.zeros((len(episodes), len(SHAPE_COLUMNS)), dtype=np.float64)
    y = np.zeros(len(episodes), dtype=np.int64)
    for i, ep in enumerate(episodes):
        times, rules = _times_and_rules(ep)
        # Missing level reads as 0, which is below every real Wazuh level and so cannot be
        # mistaken for a quiet alert. An episode file written before levels were carried will
        # score as though nothing was severe rather than failing here.
        levels = [float(a.get("level", 0) or 0)
                  for a in sorted(ep["alerts"], key=lambda a: a["at"])]
        X[i] = _timing_row(times) + [
            float(len(set(rules))),
            max(levels) if levels else 0.0,
            float(np.mean(levels)) if levels else 0.0,
            float(sum(1 for v in levels if v >= 7)),
            float(sum(1 for v in levels if v >= 10)),
        ]
        y[i] = LABEL_TO_IX[ep["label"]]
    return X, y


def sequences(episodes, max_len=64, vocab=LAB_VOCAB):
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
            ids[i, pos] = vocab.index(r)
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


def average_precision(y_true, score, positive=1):
    """Area under the precision-recall curve, computed without choosing a threshold.

    Necessary once the positive class is rare. At a 2% base rate, f1 at a fixed cutoff says
    more about where a model happens to put its 0.5 than about whether it ranks attacks above
    background, and two models can be compared on the wrong thing entirely. This ranks every
    episode by score and asks how much of the ranking above each true positive is also true.

    Read it against the positive rate, which is what a coin weighted to the base rate scores.

    Episodes that score identically are one rank, not an ordered run. The first version of this
    walked the sorted array one row at a time, so a tied block was credited in whatever order
    the rows happened to arrive in, and a model that emits only two distinct scores, which is
    what a single-rule detector does, got an average precision that moved when the input was
    reordered. Cutting the curve only where the score actually changes removes that: every
    episode in a tied block is measured at the same precision, the one you would get by taking
    the whole block. On data with no ties this is the same arithmetic as before.
    """
    s = np.asarray(score, dtype=np.float64)
    order = np.argsort(-s, kind="stable")
    s = s[order]
    hit = (np.asarray(y_true)[order] == positive).astype(np.float64)
    total = hit.sum()
    if total == 0:
        return 0.0
    cuts = np.r_[np.flatnonzero(np.diff(s)), len(s) - 1]
    found = np.cumsum(hit)[cuts]
    precision = found / (cuts + 1.0)
    recall = found / total
    return float((np.diff(np.r_[0.0, recall]) * precision).sum())


def pick_threshold(y_true, score, positive=1):
    """The cutoff with the best f1 on the data given.

    Call this on validation and apply the result to test. Calling it on test would be choosing
    the operating point after seeing the answer, which flatters every model that tries it.
    """
    s = np.asarray(score, dtype=np.float64)
    best_t, best_f1 = 0.5, -1.0
    for t in np.unique(s):
        f1 = scores(y_true, (s >= t).astype(np.int64), positive)["f1"]
        if f1 > best_f1:
            best_f1, best_t = f1, float(t)
    return best_t, best_f1


def report(name, s):
    print("  %-28s acc %.3f   precision %.3f   recall %.3f   f1 %.3f   "
          "(tp %d fp %d fn %d tn %d)"
          % (name, s["accuracy"], s["precision"], s["recall"], s["f1"],
             s["tp"], s["fp"], s["fn"], s["tn"]))
