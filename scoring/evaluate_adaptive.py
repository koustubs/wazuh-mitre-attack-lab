"""Does dividing by an endpoint's own history separate attacks better than fixed constants?

score.py grew a baseline layer: four of its six denominators are derived from the endpoint
being scored, a signature that endpoint has barely produced is worth more, and one it produces
at its usual rate for this hour of the day is worth less. All of that is reasonable. None of it
is evidence, and a scoring change that sounds reasonable and was never measured is exactly the
kind of thing this repository has already had to walk back once.

So it gets the same treatment the model got. Eight folds, one per AIT network, each network
treated as one endpoint with one baseline. The portable model is refitted per fold on the other
seven networks, so the probability the severity reads is honest for the network it is scoring.
Then that network's windows are walked in time order, twice over the same windows:

    fixed      severity(window, probability, threshold)
    adaptive   severity(window, probability, threshold, baseline, hour)

The baseline is folded one completed window at a time, and a window is scored before it is
folded, so no window is ever baselined against itself. That is the same contract the live
helper has, and the folding is literally the live helper's code: this script lifts blank() and
fold() out of Enable-LabDashboard.ps1 rather than reimplementing them, because a measurement of
a second implementation measures the wrong thing.

Both arms are scored only from the warm-up point onward. Before that the adaptive arm is the
fixed arm by construction, and including those windows would dilute the comparison with rows
where the two are identical.

What this cannot measure, stated plainly:

  - The chain multiplier. It fires on credential access plus persistence, read from ATT&CK
    tactics or from this lab's own rule ids. AIT alerts carry neither, so `chain` is 1.0 on
    every window here and the pairing this lab was built around is untested by this script.
  - Coverage, for the same reason.
  - Anything about this lab. AIT is eight public enterprise networks; the transfer caveat on
    model.json applies here word for word.

What it does measure is the part that was actually changed: the four measured denominators,
novelty, and routine suppression, against labelled intrusion windows on networks the model was
not fitted on.

    python evaluate.py --data data/ait/episodes.jsonl        # writes folds.jsonl
    python evaluate_adaptive.py                              # writes adaptive.jsonl
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import re
import sys

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scorer"))

from alert_stream import read_episodes
from baseline import fit_logistic, score_logistic
from features import average_precision, pick_threshold, shape_only, sources_of, standardise

import score as pure


# Where the live baseline helper lives. It is a heredoc inside the enabler rather than a file
# of its own, because it is installed on the manager and nothing on the host ever runs it.
HELPER = HERE.parent / "dashboard" / "Enable-LabDashboard.ps1"
# The line the helper's module level driver starts on. Everything above it is definitions and
# is safe to exec; everything below reads stdin and exits. Asserted rather than assumed, so
# that editing the helper breaks this loudly instead of quietly measuring a stale copy.
DRIVER = "state = read_state()"


def load_helper(path=HELPER):
    """blank() and fold() from the deployed baseline helper, with no side effects."""
    src = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    found = re.search(r"<<'BASELINE'\r?\n(.*?)\r?\nBASELINE\r?\n", src, re.S)
    if not found:
        raise SystemExit("No BASELINE helper found in %s" % path)
    body = found.group(1).replace("\r\n", "\n")
    head, sep, _ = body.partition("\n" + DRIVER)
    if not sep:
        raise SystemExit("The baseline helper no longer starts its driver with %r; this "
                         "script splits on that line and would otherwise run it." % DRIVER)
    ns = {"__name__": "lab_baseline"}
    exec(compile(head, str(path) + ":BASELINE", "exec"), ns)
    for name in ("blank", "fold"):
        if name not in ns:
            raise SystemExit("The baseline helper no longer defines %s()" % name)
    return ns["blank"], ns["fold"]


def observation(name, episode, probability):
    """One window in the shape the baseline folds, matching Start-LabDashboard's _observation.

    The five readings are recomputed here from the same alerts the severity reads, which is
    what that function does on the host. They are five lines of arithmetic; sharing them
    across a PowerShell here-string and a Python script is not worth the indirection, and the
    test suite checks the two agree.
    """
    share = episode["alerts"]
    lo = float(episode["startedAt"])
    levels = [float(x.get("level") or 0) for x in share]
    times = sorted(float(x.get("at") or 0.0) for x in share)
    burst, right = 0, 0
    for left, t in enumerate(times):
        while right < len(times) and times[right] < t + 60.0:
            right += 1
        burst = max(burst, right - left)
    rules = {}
    for x in share:
        rid = str(x.get("ruleId"))
        rules[rid] = rules.get(rid, 0) + 1
    stamp = datetime.datetime.fromtimestamp(lo, datetime.timezone.utc)
    return {
        "agent": name, "epoch": int(lo), "hour": stamp.hour,
        "at": stamp.strftime("%Y-%m-%dT%H:%M:%S"),
        "count": len(share),
        "peak": max(levels) if levels else 0.0,
        "mass": sum(2.0 ** ((L - 7.0) / 2.0) for L in levels if L >= 7.0),
        "burst": burst,
        "distinct": len(set(x.get("ruleId") for x in share)),
        "prob": round(float(probability), 4),
        "rules": rules,
    }


def probabilities(episodes, held, names):
    """The portable model's probability for every window of `held`, fitted without it.

    The same discipline as evaluate.py: the test network is out, one more whole network is
    held back inside training to choose the threshold, and standardisation is fitted on what
    is left. A severity term that reads a probability fitted on the network it is scoring
    would flatter both arms equally, but it would also make the numbers unquotable.
    """
    train = [e for e in episodes if e["source"] != held]
    test = [e for e in episodes if e["source"] == held]
    test.sort(key=lambda e: e["startedAt"])

    val_name = names[(names.index(held) + 1) % len(names)]
    inner = [e for e in train if e["source"] != val_name]
    val = [e for e in train if e["source"] == val_name]

    Xin, yin = shape_only(inner)
    Xva, yva = shape_only(val)
    Xte, yte = shape_only(test)
    Xin_s, Xva_s, Xte_s = standardise(Xin, Xva, Xte)
    w, b = fit_logistic(Xin_s, yin)
    thr, _ = pick_threshold(yva, score_logistic(Xva_s, w, b))
    return test, score_logistic(Xte_s, w, b), yte, float(thr)


def fold_network(episodes, held, names, warm):
    """One network, walked in time order, scored both ways."""
    blank, fold_in = load_helper()
    test, probs, y, thr = probabilities(episodes, held, names)

    state = blank()
    fixed, adaptive, labels, modes = [], [], [], []
    for i, (ep, p) in enumerate(zip(test, probs)):
        hour = datetime.datetime.fromtimestamp(float(ep["startedAt"]), datetime.timezone.utc).hour
        # Scored against the baseline as it stands before this window is in it.
        f = pure.severity(ep["alerts"], float(p), thr)
        a = pure.severity(ep["alerts"], float(p), thr, state, hour)
        if i >= warm:
            fixed.append(f["score"])
            adaptive.append(a["score"])
            labels.append(int(y[i]))
            modes.append(a["baselineMode"])
        fold_in(state, observation(held, ep, p))

    labels = np.asarray(labels, dtype=np.int64)
    fixed = np.asarray(fixed, dtype=np.float64)
    adaptive = np.asarray(adaptive, dtype=np.float64)
    keep = probs[warm:]
    return {
        "held": held,
        "n": int(len(labels)),
        "attack": int(labels.sum()),
        "base": float(labels.mean()) if len(labels) else 0.0,
        "threshold": round(thr, 6),
        "windows": int(state.get("windows") or 0),
        "rulesSeen": len(state.get("rules") or {}),
        "warmFraction": round(float(modes.count("baseline")) / len(modes), 4) if modes else 0.0,
        "model_ap": average_precision(labels, np.asarray(keep, dtype=np.float64)),
        "fixed_ap": average_precision(labels, fixed),
        "adaptive_ap": average_precision(labels, adaptive),
        "moved": int(np.sum(np.abs(adaptive - fixed) > 0.05)),
        "meanShift": round(float(np.mean(adaptive - fixed)), 3) if len(labels) else 0.0,
        "attackShift": (round(float(np.mean((adaptive - fixed)[labels == 1])), 3)
                        if labels.sum() else 0.0),
        "benignShift": (round(float(np.mean((adaptive - fixed)[labels == 0])), 3)
                        if (labels == 0).sum() else 0.0),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default="data/ait/episodes.jsonl")
    p.add_argument("--results", default="data/ait/adaptive.jsonl")
    p.add_argument("--warmup", type=int, default=pure.WARMUP_WINDOWS,
                   help="windows folded before scoring starts (default: score.py's own)")
    a = p.parse_args()

    episodes = read_episodes(a.data)
    if not episodes:
        raise SystemExit("No episodes in %s" % a.data)
    names = sources_of(episodes)
    if len(names) < 3:
        raise SystemExit("Leave one out needs at least three sources, found %d" % len(names))

    print("%s   %d episodes across %d networks" % (a.data, len(episodes), len(names)))
    print("Each network is one endpoint with one baseline, warmed on its own first %d windows."
          % a.warmup)
    print()
    print("  %-16s %5s %4s  | %8s %8s %8s  | %7s %7s %6s"
          % ("held out", "eps", "atk", "model AP", "fixed AP", "adapt AP",
             "atk", "benign", "moved"))

    rows = []
    for held in names:
        r = fold_network(episodes, held, names, a.warmup)
        rows.append(r)
        print("  %-16s %5d %4d  | %8.3f %8.3f %8.3f  | %+7.1f %+7.1f %6d"
              % (r["held"], r["n"], r["attack"], r["model_ap"], r["fixed_ap"],
                 r["adaptive_ap"], r["attackShift"], r["benignShift"], r["moved"]))
        sys.stdout.flush()

    res = pathlib.Path(a.results)
    if not res.is_absolute():
        res = HERE / res
    res.parent.mkdir(parents=True, exist_ok=True)
    with open(res, "w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")

    fx = np.array([r["fixed_ap"] for r in rows])
    ad = np.array([r["adaptive_ap"] for r in rows])
    md = np.array([r["model_ap"] for r in rows])
    base = np.array([r["base"] for r in rows])
    print()
    print("Across %d folds (mean, sd):" % len(rows))
    print("  %-22s average precision %.4f (sd %.4f)" % ("model probability", md.mean(), md.std()))
    print("  %-22s average precision %.4f (sd %.4f)" % ("fixed severity", fx.mean(), fx.std()))
    print("  %-22s average precision %.4f (sd %.4f)" % ("adaptive severity",
                                                        ad.mean(), ad.std()))
    print("  %-22s average precision %.4f, the base rate" % ("random", base.mean()))
    print()
    delta = ad - fx
    wins = int((delta > 0).sum())
    # A mean over eight folds can be carried by one of them, so the count is reported beside
    # it. Eight is few enough that six wins and two losses is a tendency, not a result.
    print("  adaptive minus fixed: %+.4f mean, %+.4f median, better on %d of %d folds"
          % (delta.mean(), float(np.median(delta)), wins, len(rows)))
    print("  per fold: %s" % ", ".join("%s %+.4f" % (r["held"], d) for r, d in zip(rows, delta)))
    print()
    print("  Neither arm sees a chain on this dataset: AIT alerts carry no ATT&CK tactic and")
    print("  none of this lab's rule ids, so the chain multiplier is 1.0 on every window here.")
    print("  What moved is the four measured denominators, novelty and routine suppression.")
    print("wrote %s" % res)


if __name__ == "__main__":
    main()
