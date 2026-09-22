"""Leave one network out, across every network, so the comparison survives contact.

baseline.py and train.py each hold out one fixed slice. That is enough to see whether a thing
works at all and not enough to rank two things that finish close together. Any single network
here would have supported a different conclusion: the logistic model beats the GRU by 0.137
average precision on harrison and loses to it by 0.002 on fox, and beats the deployed portable
feature set by 0.088 on harrison while losing to it on three other networks. Which network was
held out moves the answer further than which model was fitted.

This runs the whole comparison once per network: train on the other seven, test on that one,
and report the spread across all eight folds. A model that is genuinely better is better on
most folds, not on the one that happened to be chosen.

Expensive by design, at roughly fifty minutes on CPU. It is the difference between a number
and a finding.

    python evaluate.py --data data/ait/episodes.jsonl
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

import numpy as np
import torch
import torch.nn as nn

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from alert_stream import read_episodes
from baseline import best_single_rule, fit_logistic, rule_only, score_logistic
from features import (average_precision, build_vocab, pick_threshold, scores, shape_only,
                      sources_of, standardise, tabular)
from train import AlertGRU, to_tensors


# Every column a finished fold is expected to carry. A cached row missing one of these is
# recomputed for that model alone, which is what makes adding a column cost two minutes rather
# than re-running fifty minutes of GRU that was already measured.
COLUMNS = ("rule_f1", "rule_ap", "log_f1", "log_ap", "shape_f1", "shape_ap", "gru_f1", "gru_ap")


def fold(episodes, held, args, have=None):
    """One fold: everything except `held` trains, `held` is the test set.

    `have` is a previously saved row for this network. Anything already in it is kept and not
    recomputed, so the expensive model is not refitted to fill in a cheap column.
    """
    have = dict(have or {})
    names = sources_of(episodes)
    train = [e for e in episodes if e["source"] != held]
    test = [e for e in episodes if e["source"] == held]
    train.sort(key=lambda e: (e["source"], e["startedAt"]))
    test.sort(key=lambda e: e["startedAt"])

    # Thresholds and early stopping are chosen on a whole network held back from training and
    # nowhere else. The first version of this took the last 15% of the training rows and
    # described them as a network, which they were not: the rows are sorted by source, so the
    # tail was the back end of whichever network sorted last, cut partway through, and the
    # operating point was chosen against a fragment of one network rather than a network.
    # Rotating by one keeps the choice deterministic and lets each network validate exactly
    # once across the eight folds, so no single network sets the operating point for all of
    # them. The outer test network was never in either slice, then or now.
    val_name = names[(names.index(held) + 1) % len(names)]
    inner = [e for e in train if e["source"] != val_name]
    val = [e for e in train if e["source"] == val_name]

    # Everything a model learns comes from `inner`. Standardisation used to be fitted across
    # the whole of training before the validation slice was cut out of it, so the validation
    # network moved the column means that its own threshold was then chosen against.
    vocab = build_vocab(inner, args.data)
    Xin, yin = tabular(inner, vocab)
    Xva, yva = tabular(val, vocab)
    Xte, yte = tabular(test, vocab)
    Xin_s, Xva_s, Xte_s = standardise(Xin, Xva, Xte)

    out = dict(have)
    out.update({"held": held, "n": len(test), "attack": int(yte.sum()),
                "base": float(yte.mean()), "validatedOn": val_name})

    if "rule_ap" not in out:
        # The one rule baseline picks on all of training, validation network included. It has
        # no operating point to choose, so there is nothing for that slice to leak into, and
        # the comparison should not be won by starving the thing being compared against.
        _, ytr = tabular(train, vocab)
        rule, _ = best_single_rule(train, ytr, vocab)
        out["rule"] = rule
        out["rule_f1"] = scores(yte, rule_only(test, rule))["f1"]
        out["rule_ap"] = average_precision(yte, rule_only(test, rule))

    if "log_ap" not in out:
        w, b = fit_logistic(Xin_s, yin)
        thr, _ = pick_threshold(yva, score_logistic(Xva_s, w, b))
        ste = score_logistic(Xte_s, w, b)
        out["log_f1"] = scores(yte, (ste >= thr).astype(np.int64))["f1"]
        out["log_ap"] = average_precision(yte, ste)

    # The portable feature set, fitted and thresholded exactly as the full one is, so the gap
    # between the two rows is the feature set and nothing else. This is the model that gets
    # exported, because it is the only one whose columns still mean something on this lab.
    if "shape_ap" not in out:
        Sin, _ = shape_only(inner)
        Sva, _ = shape_only(val)
        Ste, _ = shape_only(test)
        Sin_s, Sva_s, Ste_s = standardise(Sin, Sva, Ste)
        w, b = fit_logistic(Sin_s, yin)
        thr, _ = pick_threshold(yva, score_logistic(Sva_s, w, b))
        sh = score_logistic(Ste_s, w, b)
        out["shape_f1"] = scores(yte, (sh >= thr).astype(np.int64))["f1"]
        out["shape_ap"] = average_precision(yte, sh)

    if "gru_ap" in out:
        return out

    tr = to_tensors(inner, args.max_len, vocab)
    va = to_tensors(val, args.max_len, vocab)
    te = to_tensors(test, args.max_len, vocab)
    yv = va[3].numpy()

    f1s, aps = [], []
    for run in range(args.repeats):
        seed = run
        torch.manual_seed(seed)
        np.random.seed(seed)
        model = AlertGRU(vocab.size)
        counts = torch.bincount(tr[3], minlength=2).float().clamp(min=1.0)
        loss_fn = nn.CrossEntropyLoss(weight=counts.sum() / (2.0 * counts))
        opt = torch.optim.Adam(model.parameters(), lr=args.lr)

        n_train = tr[0].shape[0]
        bs = min(args.batch_size, n_train) if args.batch_size > 0 else n_train
        g = torch.Generator().manual_seed(seed)

        best_f1, best_state = -1.0, None
        for epoch in range(1, args.epochs + 1):
            model.train()
            order = (torch.arange(n_train) if bs == n_train
                     else torch.randperm(n_train, generator=g))
            for s in range(0, n_train, bs):
                sl = order[s:s + bs]
                opt.zero_grad()
                loss_fn(model(tr[0][sl], tr[1][sl], tr[2][sl]), tr[3][sl]).backward()
                opt.step()
            if epoch % 5 == 0 or epoch == args.epochs:
                model.eval()
                with torch.no_grad():
                    f1 = scores(yv, model(va[0], va[1], va[2]).argmax(1).numpy())["f1"]
                if f1 > best_f1:
                    best_f1 = f1
                    best_state = {k: v.clone() for k, v in model.state_dict().items()}
        if best_state is not None:
            model.load_state_dict(best_state)
        model.eval()
        with torch.no_grad():
            pv = torch.softmax(model(va[0], va[1], va[2]), dim=1)[:, 1].numpy()
            pt = torch.softmax(model(te[0], te[1], te[2]), dim=1)[:, 1].numpy()
        t2, _ = pick_threshold(yv, pv)
        f1s.append(scores(yte, (pt >= t2).astype(np.int64))["f1"])
        aps.append(average_precision(yte, pt))

    out["gru_f1"] = float(np.mean(f1s))
    out["gru_ap"] = float(np.mean(aps))
    out["gru_ap_sd"] = float(np.std(aps))
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default="data/ait/episodes.jsonl")
    p.add_argument("--max-len", type=int, default=128)
    p.add_argument("--epochs", type=int, default=60)
    p.add_argument("--lr", type=float, default=3e-3)
    p.add_argument("--batch-size", type=int, default=256)
    # Three rather than five, because eight folds already give the spread that repeats were
    # standing in for when there was only one split.
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--results", default="data/ait/folds.jsonl",
                   help="each fold is appended here as it finishes, and a rerun skips the "
                        "folds already in it")
    p.add_argument("--fresh", action="store_true", help="ignore and overwrite any saved folds")
    a = p.parse_args()

    episodes = read_episodes(a.data)
    if not episodes:
        raise SystemExit("No episodes in %s" % a.data)
    names = sources_of(episodes)
    if len(names) < 3:
        raise SystemExit("Leave one out needs at least three sources, found %d" % len(names))

    # Half an hour of folds is long enough that something will eventually interrupt one, and
    # losing seven finished folds to the eighth being killed is avoidable. Each is written as
    # it completes and a rerun starts from where it stopped.
    res = pathlib.Path(a.results)
    res.parent.mkdir(parents=True, exist_ok=True)
    if a.fresh and res.exists():
        res.unlink()
    saved = {}
    for r in (read_episodes(res) if res.exists() else []):
        if "held" in r:
            saved[r["held"]] = r
    done = {h for h, r in saved.items() if all(k in r for k in COLUMNS)}
    partial = sorted(set(saved) - done)
    rows = []

    print("%s   %d episodes across %d networks" % (a.data, len(episodes), len(names)))
    print("Each row trains on the other %d and tests on the one named." % (len(names) - 1))
    if done:
        print("Resuming: %d fold(s) already complete in %s" % (len(done), res))
    if partial:
        print("Filling in missing columns for: %s" % ", ".join(partial))
    print()
    print("  %-16s %5s %5s  | %-6s %6s %6s  | %6s %6s  | %6s %6s  | %6s %6s"
          % ("held out", "eps", "atk", "rule", "f1", "AP", "log f1", "log AP",
             "shp f1", "shp AP", "GRU f1", "GRU AP"))

    for held in names:
        r = saved.get(held)
        if held not in done:
            r = fold(episodes, held, a, saved.get(held))
            saved[held] = r
            # Rewritten rather than appended, because a row can now be completed in place and
            # appending would leave two rows for one network carrying different columns.
            with open(res, "w", encoding="utf-8", newline="\n") as fh:
                for h in sorted(saved):
                    fh.write(json.dumps(saved[h], sort_keys=True) + "\n")
        rows.append(r)
        print("  %-16s %5d %5d  | %-6d %6.3f %6.3f  | %6.3f %6.3f  | %6.3f %6.3f  | %6.3f %6.3f"
              % (r["held"], r["n"], r["attack"], r["rule"], r["rule_f1"], r["rule_ap"],
                 r["log_f1"], r["log_ap"], r["shape_f1"], r["shape_ap"],
                 r["gru_f1"], r["gru_ap"]))
        sys.stdout.flush()

    rows = [r for r in rows if r["held"] in set(names)]
    print()
    print("Across %d folds (mean, sd):" % len(rows))
    for key, label in (("rule", "one rule"), ("log", "logistic"),
                       ("shape", "portable"), ("gru", "GRU")):
        f1 = np.array([r["%s_f1" % key] for r in rows])
        ap = np.array([r["%s_ap" % key] for r in rows])
        print("  %-12s f1 %.3f (sd %.3f)   average precision %.3f (sd %.3f)"
              % (label, f1.mean(), f1.std(), ap.mean(), ap.std()))
    base = np.array([r["base"] for r in rows])
    print("  %-12s average precision %.3f, the base rate" % ("random", base.mean()))

    print()
    # A mean over eight folds can be carried by one of them. Counting wins says whether the
    # ordering is consistent, which is the claim actually being made.
    lap = np.array([r["log_ap"] for r in rows])
    gap = np.array([r["gru_ap"] for r in rows])
    rap = np.array([r["rule_ap"] for r in rows])
    print("Folds won on average precision: logistic %d, GRU %d, one rule %d, of %d"
          % (int(((lap > gap) & (lap > rap)).sum()), int(((gap > lap) & (gap > rap)).sum()),
             int(((rap > lap) & (rap > gap)).sum()), len(rows)))
    print("GRU beats logistic on %d of %d folds (mean margin %+.3f AP)"
          % (int((gap > lap).sum()), len(rows), float((gap - lap).mean())))

    # What dropping the rule counts costs. This is the number that decides whether anything
    # can be put in front of live lab alerts at all, because the full feature set cannot be.
    sap = np.array([r["shape_ap"] for r in rows])
    print("Portable set keeps %.0f%% of the full model's AP (%.3f against %.3f) and beats the "
          "base rate on %d of %d folds"
          % (100.0 * sap.mean() / max(lap.mean(), 1e-9), sap.mean(), lap.mean(),
             int((sap > base).sum()), len(rows)))


if __name__ == "__main__":
    main()
