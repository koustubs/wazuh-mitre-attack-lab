"""Build the modelling report from the measurements, not from memory.

Every figure in the output is read from an artefact or produced by a run this script makes
itself. Nothing is typed in. That is the entire reason this file exists rather than a Markdown
document: the README of this project has already drifted from its own numbers once, inside a
week, and a report that goes to somebody else is a worse place for that to happen.

  folds.jsonl        the eight fold comparison, written by evaluate.py
  scorer/model.json  the deployed model and its provenance, written by export-model.py
  episodes.jsonl     the dataset, for the shape of it
  cache/*.npz        the raw alert counts per scenario, for what was read out of the archive
  baseline.py        re-run here, on the synthetic data, for the numbers that were discarded
  train.py           likewise

A missing artefact or a summary line that has changed shape stops the build. A report that
quietly omits a number is worse than no report.

    python build-report.py            # writes report.html
    .\\Build-Report.ps1                # that, then prints it to docs/ as a PDF
"""
from __future__ import annotations

import datetime
import html
import io
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
STEP = HERE.parent
sys.path.insert(0, str(STEP))

import numpy as np

from alert_stream import read_episodes


def need(path):
    p = pathlib.Path(path)
    if not p.exists():
        raise SystemExit("Missing %s. Run the step that produces it first; see the docstring."
                         % p)
    return p


def grab(pattern, text, what):
    """One number out of a script's own output, or a loud failure.

    Parsing stdout is fragile and that is handled by refusing to continue rather than by
    printing a zero. If one of these stops matching, the script it came from has changed and
    the report needs looking at, which is exactly the moment to be interrupted.
    """
    m = re.search(pattern, text)
    if not m:
        raise SystemExit("Could not read %s out of the run. The output format has changed:\n%s"
                         % (what, text[-1500:]))
    return m.groups()


def run(script, *args):
    cmd = [sys.executable, str(STEP / script)] + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(STEP))
    if r.returncode != 0:
        raise SystemExit("%s failed:\n%s" % (script, r.stderr[-2000:]))
    return r.stdout


def operating_points(folds):
    """Refit the winning model on its best fold and walk its precision-recall curve.

    Two points are worth quoting and neither is the f1 optimum. The first is how much recall
    survives at perfect precision, which is the version an analyst would actually switch on.
    The second is what it costs to catch half the intrusions, which is the version somebody
    asks for after seeing the first. The distance between them is the whole argument about
    whether this is deployable.
    """
    from baseline import fit_logistic, score_logistic
    from features import build_vocab, sources_of, standardise, tabular

    best = max(folds, key=lambda f: f["log_ap"])
    eps = read_episodes(STEP / "data/ait/episodes.jsonl")
    train = sorted((e for e in eps if e["source"] != best["held"]),
                   key=lambda e: (e["source"], e["startedAt"]))
    test = sorted((e for e in eps if e["source"] == best["held"]), key=lambda e: e["startedAt"])

    # Fitted the way evaluate.py fits that fold, or the curve below belongs to a different
    # model than the average precision quoted beside it. That means the same rotated
    # whole-network validation holdout, excluded from fitting. This used to take the first 85%
    # of the training rows instead, which, because they are sorted by source, silently dropped
    # the back end of whichever network sorted last.
    names = sources_of(eps)
    val_name = best.get("validatedOn") or names[(names.index(best["held"]) + 1) % len(names)]
    inner = [e for e in train if e["source"] != val_name]

    vocab = build_vocab(inner, STEP / "data/ait/episodes.jsonl")
    Xin, yin = tabular(inner, vocab)
    Xte, yte = tabular(test, vocab)
    Xin_s, Xte_s = standardise(Xin, Xte)
    w, b = fit_logistic(Xin_s, yin)
    s = score_logistic(Xte_s, w, b)

    order = np.argsort(-s, kind="stable")
    hit = (yte[order] == 1)
    tp = np.cumsum(hit)
    fp = np.cumsum(~hit)
    prec = tp / np.arange(1, len(hit) + 1)
    rec = tp / max(int(yte.sum()), 1)

    clean = np.where(prec >= 1.0)[0]
    k = int(clean[-1]) if len(clean) else 0
    half = np.where(rec >= 0.5)[0]
    j = int(half[0]) if len(half) else len(hit) - 1

    return {
        "held": best["held"], "validatedOn": val_name, "n": len(test),
        "attack": int(yte.sum()), "ap": best["log_ap"],
        "perfect": {"recall": float(rec[k]), "tp": int(tp[k]), "fp": int(fp[k])},
        "half": {"recall": float(rec[j]), "precision": float(prec[j]),
                 "tp": int(tp[j]), "fp": int(fp[j])},
    }


# --------------------------------------------------------------------------- the measurements

def collect():
    data = {}

    folds = [json.loads(l) for l in io.open(need(STEP / "data/ait/folds.jsonl"),
                                            encoding="utf-8-sig") if l.strip()]
    folds.sort(key=lambda f: f["held"])
    data["folds"] = folds

    def col(k):
        a = np.array([f[k] for f in folds])
        return {"mean": float(a.mean()), "sd": float(a.std()), "values": [float(v) for v in a]}

    data["summary"] = {k: col(k) for k in
                       ("rule_f1", "rule_ap", "log_f1", "log_ap", "shape_f1", "shape_ap",
                        "gru_f1", "gru_ap", "base")}

    lap = np.array([f["log_ap"] for f in folds])
    gap = np.array([f["gru_ap"] for f in folds])
    rap = np.array([f["rule_ap"] for f in folds])
    sap = np.array([f["shape_ap"] for f in folds])
    base = np.array([f["base"] for f in folds])
    data["wins"] = {
        "logistic": int(((lap > gap) & (lap > rap) & (lap > sap)).sum()),
        "gru": int(((gap > lap) & (gap > rap) & (gap > sap)).sum()),
        "rule": int(((rap > lap) & (rap > gap) & (rap > sap)).sum()),
        "portable": int(((sap > lap) & (sap > gap) & (sap > rap)).sum()),
        "gru_over_log": int((gap > lap).sum()),
        "log_over_gru": int((lap > gap).sum()),
        "gru_margin": float((gap - lap).mean()),
        "gru_margin_sd": float((lap - gap).std()),
        "portable_over_rule": int((sap > rap).sum()),
        "portable_over_base": int((sap > base).sum()),
        "portable_over_full": int((sap > lap).sum()),
        # The spread on the paired difference, not on either column. It is the number that
        # says whether the gap between the two feature sets is a result or a coin flip.
        "portable_gap_sd": float((lap - sap).std()),
        "portable_retained": float(sap.mean() / lap.mean()),
        "n": len(folds),
    }

    data["model"] = json.loads(io.open(need(STEP / "scorer/model.json"),
                                       encoding="utf-8-sig").read())

    eps = read_episodes(need(STEP / "data/ait/episodes.jsonl"))
    lens = sorted(len(e["alerts"]) for e in eps)
    sigs = {al["ruleId"] for e in eps for al in e["alerts"]}
    atk = sum(1 for e in eps if e["label"] == "attack")
    by_source = {}
    for e in eps:
        b = by_source.setdefault(e["source"], [0, 0])
        b[0] += 1
        b[1] += 1 if e["label"] == "attack" else 0
    data["dataset"] = {
        "episodes": len(eps), "attack": atk, "base": atk / len(eps),
        "signatures": len(sigs), "median": lens[len(lens) // 2],
        "p90": lens[int(len(lens) * 0.9)], "max": lens[-1],
        "bySource": {k: {"episodes": v[0], "attack": v[1]} for k, v in sorted(by_source.items())},
    }

    # What the import actually read out of the archive, counted rather than quoted from the
    # paper. The cache holds one array per scenario and its length is the alert count.
    total = 0
    per = {}
    for npz in sorted((STEP / "data/ait/cache").glob("*.npz")):
        n = int(np.load(npz)["times"].shape[0])
        per[npz.stem] = n
        total += n
    data["alerts"] = {"total": total, "bySource": per}

    # What moving the cutoff does to f1 on identical predictions, which is the argument for
    # quoting average precision at all. Re-run on the real data rather than typed into the
    # template, because it was typed in once and was 0.049 and 0.367 for a year after the
    # import that produced it had changed. Under a minute.
    ait_b = run("baseline.py", "--data", "data/ait/episodes.jsonl")
    f1_half, = grab(r"logistic @0\.5\s+acc [\d.]+\s+precision [\d.]+\s+recall [\d.]+\s+f1 ([\d.]+)",
                    ait_b, "the AIT logistic f1 at 0.5")
    f1_tuned, = grab(
        r"logistic @(?!0\.5\s)[\d.]+\s+acc [\d.]+\s+precision [\d.]+\s+recall [\d.]+\s+f1 ([\d.]+)",
        ait_b, "the AIT logistic f1 at a chosen threshold")
    data["cutoff"] = {"atHalf": float(f1_half), "atChosen": float(f1_tuned)}

    # The synthetic comparison, re-run rather than remembered. It is eight seconds.
    syn_b = run("baseline.py", "--data", "data/synthetic/episodes.jsonl")
    syn_t = run("train.py", "--data", "data/synthetic/episodes.jsonl")
    log_f1, = grab(r"logistic @[\d.]+\s+acc [\d.]+\s+precision [\d.]+\s+recall [\d.]+\s+f1 ([\d.]+)",
                   syn_b, "the synthetic logistic f1")
    log_ap, syn_base = grab(r"logistic\s+average precision ([\d.]+)\s+\(random would score ([\d.]+)",
                            syn_b, "the synthetic logistic average precision")
    rule_f1, = grab(r"rule 100111 only\s+acc [\d.]+\s+precision [\d.]+\s+recall [\d.]+\s+f1 ([\d.]+)",
                    syn_t, "the synthetic rule f1")
    gru_f1, gru_sd = grab(r"GRU over the sequence\s+f1 ([\d.]+) mean, ([\d.]+) sd", syn_t,
                          "the synthetic GRU f1")
    gru_ap, = grab(r"average precision ([\d.]+) mean", syn_t, "the synthetic GRU average precision")
    syn_eps = read_episodes(need(STEP / "data/synthetic/episodes.jsonl"))
    data["synthetic"] = {
        "episodes": len(syn_eps),
        "attack": sum(1 for e in syn_eps if e["label"] == "attack"),
        "base": float(syn_base), "rule_f1": float(rule_f1), "log_f1": float(log_f1),
        "log_ap": float(log_ap), "gru_f1": float(gru_f1), "gru_sd": float(gru_sd),
        "gru_ap": float(gru_ap),
    }

    # Window width and split sensitivity, read rather than re-run: window-sensitivity.py
    # re-imports the archive at each width and that is ten minutes, which does not belong in a
    # document build. It is a required artefact for the same reason folds.jsonl is, so the
    # report cannot quote a width figure that nothing produced.
    data["sensitivity"] = json.loads(
        io.open(need(STEP / "data/ait/sensitivity.json"), encoding="utf-8-sig").read())

    # What the four severity columns are worth inside the deployed set. Required for the same
    # reason: the document claims severity transfers where a rule id does not, and that claim
    # used to be an argument with a figure attached to it that no run had produced.
    data["ablation"] = json.loads(
        io.open(need(STEP / "data/ait/severity.json"), encoding="utf-8-sig").read())

    # The operating points that say why none of this is an alerting rule.
    #
    # Refitted here rather than read off folds.jsonl, because a fold row stores one threshold
    # and the point being made needs two: what perfect precision costs in recall, and what
    # catching half the intrusions costs in false alarms. Both are taken from the strongest
    # model on its best fold, which is the most favourable honest reading available.
    data["operating"] = operating_points(folds)

    # The severity composite, measured the same way as everything else: by running it. Three
    # windows built to be obviously different, so the number in the report is the one the code
    # produces rather than the one the prose would like it to produce.
    sys.path.insert(0, str(STEP / "scorer"))
    import score as pure
    thr = data["model"]["threshold"]
    quiet = [{"at": i * 15, "ruleId": 5501, "level": 3} for i in range(20)]
    brute = [{"at": i * 2, "ruleId": 100110, "level": 3} for i in range(40)] +             [{"at": 40 + i * 5, "ruleId": 100111, "level": 10} for i in range(4)]
    chain = brute + [{"at": 100, "ruleId": 100112, "level": 6}]
    data["severity"] = {
        "weights": [{"key": k, "weight": w, "label": l} for k, w, l in pure.SEVERITY_WEIGHTS],
        "chainBonus": pure.CHAIN_BONUS,
        "quiet": pure.severity(quiet, 0.51, thr)["score"],
        "brute": pure.severity(brute, 0.55, thr)["score"],
        "chained": pure.severity(chain, 0.58, thr)["score"],
    }

    data["generated"] = datetime.date.today().isoformat()
    return data


# --------------------------------------------------------------------------- the page

def e(x):
    return html.escape(str(x))


def n(x):
    return "{:,}".format(int(x))


def page(d):
    s, m, w, ds = d["summary"], d["model"], d["wins"], d["dataset"]
    syn, op = d["synthetic"], d["operating"]

    def row(label, f1k, apk, strong=False):
        b0, b1 = ("<strong>", "</strong>") if strong else ("", "")
        return ("<tr%s><td>%s%s%s</td><td class=n>%s%.3f%s</td><td class=n>%.3f</td>"
                "<td class=n>%s%.3f%s</td><td class=n>%.3f</td></tr>"
                % (" class=win" if strong else "", b0, label, b1,
                   b0, s[f1k]["mean"], b1, s[f1k]["sd"], b0, s[apk]["mean"], b1, s[apk]["sd"]))

    folds_rows = "".join(
        "<tr><td>%s</td><td class=n>%s</td><td class=n>%d</td><td class=n>%.3f</td>"
        "<td class=n>%.3f</td><td class=n>%.3f</td><td class=n>%.3f</td></tr>"
        % (e(f["held"]), n(f["n"]), f["attack"], f["rule_ap"], f["gru_ap"], f["shape_ap"],
           f["log_ap"])
        for f in d["folds"])

    source_rows = "".join(
        "<tr><td>%s</td><td class=n>%s</td><td class=n>%s</td><td class=n>%d</td>"
        "<td class=n>%.1f%%</td></tr>"
        % (e(k), n(d["alerts"]["bySource"].get(k, 0)), n(v["episodes"]), v["attack"],
           100.0 * v["attack"] / max(v["episodes"], 1))
        for k, v in ds["bySource"].items())

    feat_rows = "".join(
        "<tr><td class=mono>%s</td><td class=n>%+.3f</td></tr>" % (e(c), wt)
        for c, wt in sorted(zip(m["columns"], m["weights"]), key=lambda p: -abs(p[1])))

    return TEMPLATE % {
        "generated": e(d["generated"]),
        "alerts_total": n(d["alerts"]["total"]),
        "episodes": n(ds["episodes"]),
        "attack": n(ds["attack"]),
        "base_pct": "%.1f" % (100.0 * ds["base"]),
        "signatures": ds["signatures"],
        "median": ds["median"], "p90": ds["p90"], "maxlen": ds["max"],
        "source_rows": source_rows,
        "folds_rows": folds_rows,
        "n_folds": w["n"],
        "row_rule": row("Best single rule", "rule_f1", "rule_ap"),
        "row_gru": row("GRU over the sequence (3 seeds a fold)", "gru_f1", "gru_ap"),
        "row_portable": row("Logistic, portable features (deployed)", "shape_f1", "shape_ap"),
        "row_log": row("Logistic, full features", "log_f1", "log_ap", strong=True),
        "base_ap": "%.3f" % s["base"]["mean"],
        "log_ap": "%.3f" % s["log_ap"]["mean"],
        "gru_ap": "%.3f" % s["gru_ap"]["mean"],
        "rule_ap": "%.3f" % s["rule_ap"]["mean"],
        "shape_ap": "%.3f" % s["shape_ap"]["mean"],
        "shape_sd": "%.3f" % s["shape_ap"]["sd"],
        "wins_log": w["logistic"], "wins_gru": w["gru"],
        "cut_half": "%.3f" % d["cutoff"]["atHalf"],
        "cut_chosen": "%.3f" % d["cutoff"]["atChosen"],
        # The two folds that would each have produced a different headline on their own.
        "swing_gru": "%.3f" % max(f["log_ap"] - f["gru_ap"] for f in d["folds"]),
        "swing_gru_lo": "%.3f" % abs(min(f["log_ap"] - f["gru_ap"] for f in d["folds"])),
        "swing_shape": "%.3f" % max(f["log_ap"] - f["shape_ap"] for f in d["folds"]),
        "gru_margin": "%+.3f" % w["gru_margin"],
        "portable_gap_gru": "%.3f" % abs(w["gru_margin"]),
        "portable_gap_gru_sd": "%.3f" % w["gru_margin_sd"],
        "log_over_gru": w["log_over_gru"],
        "portable_pct": "%.0f" % (100.0 * w["portable_retained"]),
        "portable_gap": "%.3f" % (s["log_ap"]["mean"] - s["shape_ap"]["mean"]),
        "portable_gap_sd": "%.3f" % w["portable_gap_sd"],
        "portable_over_rule": w["portable_over_rule"],
        "portable_over_base": w["portable_over_base"],
        "portable_over_full": w["portable_over_full"],
        "portable_times": "%.0f" % (s["shape_ap"]["mean"] / s["base"]["mean"]),
        "sev_full": "%.3f" % d["ablation"]["full"]["mean"],
        "sev_without": "%.3f" % d["ablation"]["withoutSeverity"]["mean"],
        "sev_alone": "%.3f" % d["ablation"]["severityOnly"]["mean"],
        "sev_cost": "%.3f" % abs(d["ablation"]["delta"]),
        "sev_hurt": d["ablation"]["foldsHurt"],
        "sev_pct": "%.0f" % (100.0 * d["ablation"]["severityOnly"]["mean"]
                             / d["ablation"]["full"]["mean"]),
        "syn_episodes": syn["episodes"], "syn_attack": syn["attack"],
        "syn_base": "%.3f" % syn["base"],
        "syn_rule_f1": "%.3f" % syn["rule_f1"], "syn_log_f1": "%.3f" % syn["log_f1"],
        "syn_log_ap": "%.3f" % syn["log_ap"], "syn_gru_f1": "%.3f" % syn["gru_f1"],
        "syn_gru_sd": "%.3f" % syn["gru_sd"], "syn_gru_ap": "%.3f" % syn["gru_ap"],
        "syn_drop": "%.3f" % (syn["gru_f1"] - s["gru_f1"]["mean"]),
        "op_held": e(op["held"]), "op_n": n(op["n"]), "op_attack": op["attack"],
        "op_ap": "%.3f" % op["ap"],
        "op_perfect_rec": "%.3f" % op["perfect"]["recall"],
        "op_perfect_tp": op["perfect"]["tp"],
        "op_half_rec": "%.3f" % op["half"]["recall"],
        "op_half_prec": "%.3f" % op["half"]["precision"],
        "op_half_tp": op["half"]["tp"], "op_half_fp": n(op["half"]["fp"]),
        "m_train_eps": n(m["trainedOn"]["episodes"]),
        "m_train_nets": len(m["trainedOn"]["networks"]),
        "m_thr": "%.3f" % m["threshold"],
        "m_thr_eps": n(m["thresholdChosenOn"]["episodes"]),
        "m_thr_nets": ", ".join(e(x) for x in m["thresholdChosenOn"]["networks"]),
        "m_thr_prec": "%.3f" % m["thresholdChosenOn"]["precision"],
        "m_thr_rec": "%.3f" % m["thresholdChosenOn"]["recall"],
        "feat_rows": feat_rows,
        "window": int(m["windowSeconds"]),
        "sev_rows": "".join(
            "<tr><td class=mono>%s</td><td>%s</td><td class=n>%.2f</td></tr>"
            % (e(c["key"]), e(c["label"]), c["weight"]) for c in d["severity"]["weights"]),
        "w_model": "%.2f" % next(c["weight"] for c in d["severity"]["weights"]
                                 if c["key"] == "model"),
        "chain_max": "%.2f" % (1.0 + d["severity"]["chainBonus"]),
        "sev_quiet": "%.0f" % d["severity"]["quiet"],
        "sev_brute": "%.0f" % d["severity"]["brute"],
        "sev_chain": "%.0f" % d["severity"]["chained"],
        "sens_rows": "".join(
            "<tr><td class=n>%s</td><td class=n>%.3f</td><td class=n>%.3f</td></tr>"
            % (e(w), v["mean"], v["sd"])
            for w, v in sorted(d["sensitivity"]["widths"].items(), key=lambda kv: int(kv[0]))),
        "sens_low": "%.3f" % min(v["mean"] for v in d["sensitivity"]["widths"].values()),
        "sens_high": "%.3f" % max(v["mean"] for v in d["sensitivity"]["widths"].values()),
        "sens_time": "%.3f" % d["sensitivity"]["timeSplit"],
    }


TEMPLATE = open(HERE / "report.template.html", encoding="utf-8").read() \
    if (HERE / "report.template.html").exists() else None


def main():
    if TEMPLATE is None:
        raise SystemExit("Missing report.template.html beside this script.")
    d = collect()
    out = HERE / "report.html"
    io.open(out, "w", encoding="utf-8", newline="\n").write(page(d))
    io.open(HERE / "figures.json", "w", encoding="utf-8", newline="\n").write(
        json.dumps(d, indent=1, sort_keys=True, default=float) + "\n")
    print("wrote %s" % out)
    print("      %s" % (HERE / "figures.json"))
    print("%s alerts, %s episodes, %s attack, %d folds, deployed AP %.3f"
          % (n(d["alerts"]["total"]), n(d["dataset"]["episodes"]), n(d["dataset"]["attack"]),
             d["wins"]["n"], d["summary"]["shape_ap"]["mean"]))


if __name__ == "__main__":
    main()
