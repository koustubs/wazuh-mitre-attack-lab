"""Fit the portable model and write the file the dashboard scores with.

Two things have to be true of anything deployed here, and this script exists to make both of
them checkable rather than asserted.

It has to be the feature set that can move. The full model wins every fold and cannot leave
this dataset: its columns are one per AIT rule id, and this lab shares two of those thirty
one. Scoring lab alerts with it would put everything in the unknown column and return a
confident number about nothing. shape_only() in features.py is the set that survives the move,
and it is what gets fitted here.

It has to carry what it scored. A weights file with no measurement attached will be trusted
more than it has earned, so the eight fold result goes into the file itself, read out of
folds.jsonl rather than typed, along with what beat it and by how much. The dashboard prints
it on the panel.

    python evaluate.py --data data/ait/episodes.jsonl      # writes folds.jsonl
    python export-model.py                                 # writes scorer/model.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scorer"))

from alert_stream import read_episodes
from baseline import fit_logistic, score_logistic
from features import SHAPE_COLUMNS, pick_threshold, scores, shape_only

import score as pure


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default="data/ait/episodes.jsonl")
    p.add_argument("--folds", default="data/ait/folds.jsonl")
    p.add_argument("--out", default="scorer/model.json")
    p.add_argument("--window", type=float, default=300.0,
                   help="the episode width the model was fitted at; the dashboard has to "
                        "window live alerts the same way or the features mean something else")
    p.add_argument("--train-frac", type=float, default=0.85)
    a = p.parse_args()

    episodes = read_episodes(a.data)
    if not episodes:
        raise SystemExit("No episodes in %s" % a.data)

    # Sorted by source then time, so the validation tail is the last networks alphabetically
    # rather than a slice cut through the middle of every one of them. The threshold is then
    # chosen on networks the fit never saw, which is the same discipline as the fold harness.
    episodes.sort(key=lambda e: (e.get("source", ""), e["startedAt"]))
    cut = int(len(episodes) * a.train_frac)
    # Then pushed forward to the next network boundary. Cutting on the raw fraction lands in
    # the middle of a network, and the threshold is then partly chosen on the same network the
    # fit was trained on, which is the quiet version of the mistake this whole file is
    # arranged to avoid.
    while cut < len(episodes) and episodes[cut].get("source") == episodes[cut - 1].get("source"):
        cut += 1
    train, valid = episodes[:cut], episodes[cut:]
    if not valid:
        raise SystemExit("Nothing left to choose a threshold on")

    Xtr, ytr = shape_only(train)
    Xva, yva = shape_only(valid)

    mu = Xtr.mean(axis=0)
    sd = Xtr.std(axis=0)
    sd[sd == 0] = 1.0
    w, b = fit_logistic((Xtr - mu) / sd, ytr)

    sva = score_logistic((Xva - mu) / sd, w, b)
    thr, thr_f1 = pick_threshold(yva, sva)
    va = scores(yva, (sva >= thr).astype(np.int64))

    folds = [json.loads(l) for l in open(a.folds, encoding="utf-8-sig") if l.strip()]
    if not folds:
        raise SystemExit("No folds in %s; run evaluate.py first" % a.folds)
    sap = np.array([f["shape_ap"] for f in folds])
    lap = np.array([f["log_ap"] for f in folds])
    gap = np.array([f["gru_ap"] for f in folds])
    rap = np.array([f["rule_ap"] for f in folds])
    base = np.array([f["base"] for f in folds])

    model = {
        "columns": SHAPE_COLUMNS,
        "weights": [round(float(v), 8) for v in w],
        "bias": round(float(b), 8),
        "mean": [round(float(v), 8) for v in mu],
        "sd": [round(float(v), 8) for v in sd],
        "threshold": round(float(thr), 6),
        "windowSeconds": a.window,
        "model": "logistic regression, portable feature set",
        "trainedOn": {
            "dataset": "AIT Alert Data Set",
            "source": "https://zenodo.org/records/8263181",
            "licence": "CC-BY-4.0",
            "episodes": len(train),
            "attackEpisodes": int(ytr.sum()),
            "baseRate": round(float(ytr.mean()), 4),
            "networks": sorted({e.get("source", "") for e in train}),
        },
        "thresholdChosenOn": {
            "episodes": len(valid),
            "attackEpisodes": int(yva.sum()),
            "networks": sorted({e.get("source", "") for e in valid}),
            "f1": round(float(thr_f1), 4),
            "precision": round(float(va["precision"]), 4),
            "recall": round(float(va["recall"]), 4),
        },
        # The generalisation estimate, and the only number worth quoting. Each fold trains on
        # seven networks and is scored on a network it has never seen. This lab is an unseen
        # network, so this is the honest expectation for it, not the validation figures above.
        "measured": {
            "protocol": "leave one network out, %d folds" % len(folds),
            "averagePrecision": round(float(sap.mean()), 4),
            "averagePrecisionSd": round(float(sap.std()), 4),
            "baseRate": round(float(base.mean()), 4),
            "foldsAboveBaseRate": int((sap > base).sum()),
            "beatenBy": {"full feature set, which cannot be deployed here":
                         round(float(lap.mean()), 4),
                         "GRU over the sequence": round(float(gap.mean()), 4)},
            "beats": {"best single rule": round(float(rap.mean()), 4)},
        },
        "caveat": ("Fitted on eight public networks and never measured on this lab, whose own "
                   "rules appear in no public dataset. Treat the score as triage ordering, "
                   "not as a detection. A campaign is what would replace this sentence with a "
                   "number."),
        "generated": datetime.date.today().isoformat(),
        "generatedBy": "scoring/export-model.py",
    }

    out = pathlib.Path(a.out)
    if not out.is_absolute():
        out = HERE / out
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(model, fh, indent=1, sort_keys=True)
        fh.write("\n")

    # The check that matters. score.py computes the features again in plain Python for the
    # manager, and a disagreement between the two means the deployed model is being fed
    # something other than what it was fitted on. That failure looks exactly like a working
    # dashboard, so it is caught here rather than noticed later.
    loaded = pure.load(str(out))
    worst_f, worst_p = 0.0, 0.0
    for ep, want in zip(valid, sva):
        got_f = pure.features(ep["alerts"])
        ref_f = shape_only([ep])[0][0]
        worst_f = max(worst_f, float(np.abs(np.array(got_f) - ref_f).max()))
        worst_p = max(worst_p, abs(pure.score(loaded, got_f) - float(want)))

    print("wrote %s" % out)
    print("  %d features, fitted on %d episodes from %d networks"
          % (len(SHAPE_COLUMNS), len(train), len(model["trainedOn"]["networks"])))
    print("  threshold %.4f, chosen on %d held out episodes (f1 %.3f)"
          % (thr, len(valid), thr_f1))
    print("  leave one network out: average precision %.3f (sd %.3f) against a %.3f base rate"
          % (sap.mean(), sap.std(), base.mean()))
    print()
    # Features have to match exactly: they are the same arithmetic on the same inputs and any
    # difference at all is a bug. Probabilities are allowed a little room, because the file
    # rounds its coefficients to eight decimal places and the manager therefore scores with
    # marginally different numbers than the fit did. That shows up around 1e-9. A real fault,
    # a column out of order or a standardisation applied the wrong way round, moves the
    # probability by tenths, so 1e-6 still catches everything worth catching.
    print("score.py agreement on the held out slice:")
    print("  worst feature difference     %.2e" % worst_f)
    print("  worst probability difference %.2e  (coefficients are stored to 8dp)" % worst_p)
    if worst_f > 0.0 or worst_p > 1e-6:
        raise SystemExit("score.py and features.py disagree; the deployed model would be "
                         "reading different numbers from the same alerts.")
    print("  agreed, so the manager scores what was fitted here.")


if __name__ == "__main__":
    main()
