"""What are the four severity columns worth inside the deployed feature set?

`shape_only()` has eleven columns and four of them describe how severe a window was:
`max_level`, `mean_level`, `n_level_ge_7` and `n_level_ge_10`. They are there on an argument
rather than a measurement. A Wazuh level is a property of the ruleset, so it means the same
thing on a network the model has never seen, where a rule id does not. That argument is worth
nothing if the columns turn out not to carry anything, and the README said they roughly doubled
average precision on three folds, which was written before the sampling was corrected and was
never traced to a run. This is the run.

Three fits per fold on the same rotated whole-network splits `evaluate.py` uses: the whole
eleven, the seven without severity, and the four severity columns alone. Fast enough to be
worth re-running whenever the import changes, because it reads the episodes and fits a logistic
eight times and nothing else.

    python severity-ablation.py

The result is written to `data/ait/severity.json`, which the report build reads rather than
re-running this.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from alert_stream import read_episodes
from baseline import fit_logistic, score_logistic
from features import SHAPE_COLUMNS, average_precision, shape_only, sources_of, standardise

SEVERITY = ("max_level", "mean_level", "n_level_ge_7", "n_level_ge_10")


def ablate(path):
    sev = [SHAPE_COLUMNS.index(c) for c in SEVERITY]
    rest = [i for i in range(len(SHAPE_COLUMNS)) if i not in sev]

    episodes = read_episodes(path)
    names = sources_of(episodes)
    arms = {"full": [], "withoutSeverity": [], "severityOnly": []}
    per_fold = []
    for i, held in enumerate(names):
        val_name = names[(i + 1) % len(names)]
        inner = [e for e in episodes if e["source"] not in (held, val_name)]
        test = [e for e in episodes if e["source"] == held]
        Xin, yin = shape_only(inner)
        Xte, yte = shape_only(test)
        row = {"held": held, "validatedOn": val_name}
        for arm, cols in (("full", slice(None)), ("withoutSeverity", rest),
                          ("severityOnly", sev)):
            a, b = standardise(Xin[:, cols], Xte[:, cols])
            w, b0 = fit_logistic(a, yin)
            ap = float(average_precision(yte, score_logistic(b, w, b0)))
            arms[arm].append(ap)
            row[arm] = ap
        per_fold.append(row)
        print("  %-16s  all eleven %.3f   without severity %.3f   severity alone %.3f"
              % (held, row["full"], row["withoutSeverity"], row["severityOnly"]))
    return {k: np.asarray(v, dtype=np.float64) for k, v in arms.items()}, per_fold


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default="data/ait/episodes.jsonl")
    p.add_argument("--out", default="data/ait/severity.json",
                   help="where the report build reads this from")
    a = p.parse_args()

    data = pathlib.Path(a.data)
    if not data.is_absolute():
        data = HERE / data

    print("The deployed feature set, with and without its four severity columns.")
    print("Leave one network out, the same folds evaluate.py uses.")
    print()
    arms, per_fold = ablate(data)
    print()

    full, without, alone = arms["full"], arms["withoutSeverity"], arms["severityOnly"]
    delta = without - full
    print("  all eleven        average precision %.4f (sd %.4f)" % (full.mean(), full.std()))
    print("  without severity  average precision %.4f (sd %.4f)"
          % (without.mean(), without.std()))
    print("  severity alone    average precision %.4f (sd %.4f)" % (alone.mean(), alone.std()))
    print()
    print("  Removing them costs %+.4f mean and %+.4f median, and hurts on %d of %d folds."
          % (delta.mean(), float(np.median(delta)), int((delta < 0).sum()), len(full)))
    print("  The four on their own reach %.0f%% of what all eleven reach, which says the"
          % (100.0 * alone.mean() / full.mean()))
    print("  severity columns and the shape columns are largely measuring the same bursts.")
    print()

    out = pathlib.Path(a.out)
    if not out.is_absolute():
        out = HERE / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "columns": list(SEVERITY),
        "folds": per_fold,
        "full": {"mean": float(full.mean()), "sd": float(full.std())},
        "withoutSeverity": {"mean": float(without.mean()), "sd": float(without.std())},
        "severityOnly": {"mean": float(alone.mean()), "sd": float(alone.std())},
        "delta": float(delta.mean()),
        "deltaMedian": float(np.median(delta)),
        "foldsHurt": int((delta < 0).sum()),
    }, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print("wrote %s, which the report build reads rather than re-running this." % out)


if __name__ == "__main__":
    main()
