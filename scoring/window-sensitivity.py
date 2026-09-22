"""How much of the result is the window width, and how much is the split?

Everything else here rests on a five minute window and a leave-one-network-out split. Both are
choices rather than measurements, and a finding that only holds at one width, or only when the
held out data is a different network rather than a later hour, is a finding about the setup.
This is what says which.

The width answer is not the reassuring one. Average precision rises with the window: wider
windows carry more of an attack phase and rank it better, and the gap between two minutes and
ten is large enough that the width has to be quoted with any number taken from here. An earlier
version of this measurement reported a flat curve, which was an artefact: the per-window alert
cap was 256 at the time, so the extra alerts a wider window collected were being thrown away
before the features saw them. Raising the cap to the live ceiling made the slope visible.

The deployed width stays 300 seconds regardless, because that is what the panel buckets at and
a training window has to be the window the model will be shown. The measurement is here so that
is a stated trade rather than an unexamined default.

Only the full logistic model runs, and only average precision is reported. The GRU is left out
on purpose: it is fifty minutes of the hour `evaluate.py` takes, and the question is whether
the shape of the result survives, not what every model scores at every width. The folds are the
same ones `evaluate.py` uses, including the rotated whole-network validation holdout, so the
300 second row is comparable with the `log_ap` column there.

    python window-sensitivity.py                      # 120, 300 and 600, then the time split
    python window-sensitivity.py --widths 60 900      # or whichever widths

Re-importing at a new width is quick because `import-ait.py` caches the parsed archive; the
first run of all is not, because it has 2.8 GB of JSON to read. The result is written to
`data/ait/sensitivity.json`, which the report build reads rather than re-running this.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from alert_stream import read_episodes
from baseline import fit_logistic, score_logistic
from features import average_precision, build_vocab, sources_of, standardise, tabular


def build(width, cache, out):
    """Re-window the cached archive at `width` seconds."""
    cmd = [sys.executable, str(HERE / "import-ait.py"),
           "--window", str(float(width)), "--cache", str(cache), "--out", str(out)]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(HERE))
    if r.returncode != 0:
        raise SystemExit("import at %ds failed:\n%s" % (width, r.stderr[-2000:]))
    return r.stdout.strip().splitlines()[-3:]


def average(path):
    """Mean average precision of the full logistic across every fold."""
    episodes = read_episodes(path)
    names = sources_of(episodes)
    scored = []
    for i, held in enumerate(names):
        val_name = names[(i + 1) % len(names)]
        inner = [e for e in episodes if e["source"] not in (held, val_name)]
        test = [e for e in episodes if e["source"] == held]
        vocab = build_vocab(inner, path)
        Xin, yin = tabular(inner, vocab)
        Xte, yte = tabular(test, vocab)
        Xin_s, Xte_s = standardise(Xin, Xte)
        w, b = fit_logistic(Xin_s, yin)
        scored.append(average_precision(yte, score_logistic(Xte_s, w, b)))
    return np.asarray(scored, dtype=np.float64)


def time_split(path, train_frac=0.7):
    """The same model, held out by time instead of by network.

    Weaker than the network split and kept for exactly that reason: if a time split scored
    far higher, the thing being measured would be how much of a network's noise floor a model
    can memorise rather than whether it generalises.
    """
    from features import load_split

    train, test = load_split(path, train_frac=train_frac, by="time")
    cut = int(len(train) * 0.85)
    inner, _val = train[:cut], train[cut:]
    vocab = build_vocab(inner, path)
    Xin, yin = tabular(inner, vocab)
    Xte, yte = tabular(test, vocab)
    Xin_s, Xte_s = standardise(Xin, Xte)
    w, b = fit_logistic(Xin_s, yin)
    return average_precision(yte, score_logistic(Xte_s, w, b))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--widths", type=int, nargs="+", default=[120, 300, 600])
    p.add_argument("--cache", default="data/ait/cache")
    p.add_argument("--data", default="data/ait/episodes.jsonl",
                   help="the committed import, used for the time split")
    p.add_argument("--time-split", type=int, default=300,
                   help="window width the --data file was built at; 0 skips the time split")
    p.add_argument("--out", default="data/ait/sensitivity.json",
                   help="where the report build reads these from")
    a = p.parse_args()

    saved = {"widths": {}, "timeSplit": None, "deployedWidth": a.time_split or None}

    print("Full logistic, leave one network out, average precision by window width.")
    print()
    with tempfile.TemporaryDirectory() as work:
        for width in a.widths:
            out = pathlib.Path(work) / ("episodes-%d.jsonl" % width)
            for line in build(width, a.cache, out):
                print("  " + line)
            ap = average(out)
            print("  %4ds  AP %.4f mean, %.4f sd, per fold %s"
                  % (width, ap.mean(), ap.std(),
                     " ".join("%.3f" % v for v in ap)))
            print()
            saved["widths"][str(width)] = {
                "mean": float(ap.mean()), "sd": float(ap.std()),
                "values": [float(v) for v in ap]}

    if a.time_split:
        print("The same model on a time split rather than a network split, at %ds."
              % a.time_split)
        print()
        ap = float(time_split(pathlib.Path(a.data)))
        saved["timeSplit"] = ap
        print("  %.4f" % ap)
        print()
        print("  Not comparable with the folds above as a like-for-like number: it is one")
        print("  split rather than eight, and its test set is the back end of every network")
        print("  at once rather than a network nobody trained on. It is here to say whether")
        print("  the picture changes when the held out data is later rather than elsewhere.")
        print()

    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(saved, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print("wrote %s, which the report build reads rather than re-running this." % out)


if __name__ == "__main__":
    main()
