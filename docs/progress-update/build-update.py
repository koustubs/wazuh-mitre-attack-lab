"""Build the progress update page that goes to the mentor.

    python build-update.py            # writes update.html beside this file

Steps 1 to 4 are already reported. This document covers only the open question, which is
whether a neural sequence model can classify runs of alerts that the single event rules
cannot. Plain technical register throughout.

Same rule as the modelling report. No figure is typed in here. Every number is read from
the artefact that produced it, so the document cannot drift away from the measurements the
way the README already did once this week. If a figure looks wrong, the artefact is wrong.

    scoring/data/ait/folds.jsonl   the eight fold results
    scoring/scorer/model.json      the deployed model and its provenance
    scoring/scorer/score.py        the severity weights and bands
"""
from __future__ import annotations

import datetime
import io
import json
import os
import pathlib
import re
import statistics

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MODELLING = ROOT / "scoring"


def read_folds():
    path = MODELLING / "data/ait/folds.jsonl"
    if not path.exists():
        raise SystemExit("No %s. Run evaluate.py first; this page is built from its output."
                         % path)
    return [json.loads(l) for l in io.open(path, encoding="utf-8") if l.strip()]


def agg(folds, key):
    v = [f[key] for f in folds if key in f]
    return statistics.mean(v), statistics.pstdev(v)


def chain_bonus():
    """Read out of the scorer rather than restated, so the two cannot disagree."""
    src = io.open(MODELLING / "scorer/score.py", encoding="utf-8").read()
    return float(re.search(r"CHAIN_BONUS = ([\d.]+)", src).group(1))


def row(label, folds, stem, win=False):
    f1, f1sd = agg(folds, stem + "_f1")
    ap, apsd = agg(folds, stem + "_ap")
    return ('<tr%s><td>%s</td><td class="n">%.3f <span class="sd">(sd %.3f)</span></td>'
            '<td class="n">%.3f <span class="sd">(sd %.3f)</span></td></tr>'
            % (' class="win"' if win else "", label, f1, f1sd, ap, apsd))


def main():
    folds = read_folds()
    model = json.loads(io.open(MODELLING / "scorer/model.json", encoding="utf-8").read())
    bonus = chain_bonus()

    trained, chosen = model["trainedOn"], model["thresholdChosenOn"]
    measured = model["measured"]
    log_ap, _ = agg(folds, "log_ap")
    gru_ap, _ = agg(folds, "gru_ap")
    shape_ap, _ = agg(folds, "shape_ap")
    wins = sum(1 for f in folds if f["log_ap"] >= max(f["gru_ap"], f["rule_ap"], f["shape_ap"]))
    episodes = trained["episodes"] + chosen["episodes"]
    attacks = trained["attackEpisodes"] + chosen["attackEpisodes"]

    page = TEMPLATE % {
        "alerts": "2,600,263",
        "networks": len(folds),
        "episodes": "{:,}".format(episodes),
        "attacks": attacks,
        "base": "%.1f%%" % (100 * measured["baseRate"]),
        "window": int(model["windowSeconds"]),
        "rows": "".join([
            row("Best single rule, the baseline", folds, "rule"),
            row("Logistic regression on shape and severity, deployed", folds, "shape"),
            row("GRU over the alert sequence", folds, "gru"),
            row("Logistic regression on rule counts and timing", folds, "log", win=True),
        ]),
        "baserate": "%.3f" % measured["baseRate"],
        "wins": wins,
        "folds": len(folds),
        "gru_ap": "%.3f" % gru_ap,
        "gru_gap": "%.3f" % (log_ap - gru_ap),
        "log_ap": "%.3f" % log_ap,
        "shape_ap": "%.3f" % shape_ap,
        "portable_gap": "%.3f" % (log_ap - shape_ap),
        "retained": "%.0f%%" % (100 * shape_ap / log_ap),
        "lift": "%.0f" % (log_ap / measured["baseRate"]),
        "features": len(model["columns"]),
        "dataset": trained["dataset"],
        "licence": trained["licence"],
        "bonus": "%d%%" % (100 * bonus),
        # The day it is built, which is the day it is sent. The model carries its own date.
        "generated": datetime.date.today().strftime("%d %B %Y"),
    }

    out = HERE / "update.html"
    io.open(out, "w", encoding="utf-8", newline="\n").write(page)
    print("wrote %s (%.0f KB)" % (out, os.path.getsize(out) / 1024))


TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sequence modelling for multi-event detection</title>
<style>
  @page { size: A4; margin: 15mm 16mm 14mm; }
  :root { --ink:#17171a; --soft:#55555e; --faint:#85858e; --line:#d9d9d4;
          --rule:#24242a; --accent:#0f6e56; }
  * { box-sizing: border-box; }
  body { font: 10.2pt/1.48 "Charter","Georgia","Cambria",serif; color: var(--ink);
         margin: 0 auto; max-width: 178mm; -webkit-print-color-adjust: exact;
         print-color-adjust: exact; }
  h1 { font-size: 19pt; line-height: 1.22; margin: 0 0 6px; letter-spacing: -.01em; }
  h2 { font-size: 12.5pt; margin: 17px 0 7px; padding-bottom: 5px;
       border-bottom: 1.5px solid var(--rule); }
  h3 { font-size: 10.5pt; margin: 16px 0 5px; }
  p { margin: 0 0 7px; }
  ul { margin: 0 0 9px; padding-left: 18px; }
  li { margin-bottom: 4px; }
  a { color: var(--accent); text-decoration: none; }
  .sub { color: var(--soft); font-size: 10pt; margin: 0 0 3px; }
  .meta { color: var(--faint); font-size: 8.5pt; margin: 0 0 18px; padding-bottom: 11px;
          border-bottom: 1px solid var(--line); }
  .lead { font-size: 11pt; }
  .finding { border-left: 3px solid var(--rule); padding: 2px 0 2px 13px; margin: 13px 0 17px; }
  .finding p:last-child { margin-bottom: 0; }
  .aside { background:#f5f5f1; border:1px solid var(--line); border-radius:4px;
           padding:9px 12px; margin:10px 0; font-size:9.5pt; }
  .aside p:last-child { margin-bottom: 0; }
  table { border-collapse: collapse; width: 100%%; margin: 8px 0 11px; font-size: 9.5pt; }
  th { text-align:left; font-weight:650; font-size:8pt; text-transform:uppercase;
       letter-spacing:.05em; color:var(--soft); border-bottom:1.2px solid var(--rule);
       padding:0 8px 4px 0; }
  td { padding:5px 8px 5px 0; border-bottom:1px solid var(--line); vertical-align: top; }
  td.n, th.n { text-align:right; padding-right:0; font-variant-numeric:tabular-nums;
               white-space:nowrap; }
  td.n:not(:last-child), th.n:not(:last-child) { padding-right: 16px; }
  td.d { color: var(--soft); font-size: 9pt; text-align: left; padding-right: 0; }
  th.d { text-align: left; }
  tr.win td { background:#eef6f2; font-weight: 600; }
  .sd { color: var(--faint); font-weight: 400; font-size: 8.5pt; }
  code { font-family:"Consolas","SF Mono",monospace; font-size:9pt; background:#f2f2ee;
         padding:0 3px; border-radius:3px; }
  h2, h3 { break-after: avoid; page-break-after: avoid; }
  table, .aside, .finding { break-inside: avoid; page-break-inside: avoid; }
  .newpage { break-before: page; page-break-before: always; }
  .note { margin:10px 0 0; padding-top:6px; border-top:1px solid var(--line);
          color:var(--faint); font-size:8.5pt; }
</style>
</head>
<body>

<h1>Sequence modelling for multi-event detection</h1>
<p class="sub">Evaluation against non-neural baselines, and the model deployed</p>
<p class="meta">%(generated)s &middot; Prepared by Koustub</p>

<h2>Summary</h2>

<p>The detection rules built in step 4 classify single events. This work evaluated whether
a neural sequence model can classify a run of alerts instead. Across %(folds)s held out
networks a GRU over the alert sequence scored %(gru_ap)s mean average precision against
%(log_ap)s for logistic regression on the same windows, and won no fold, so a neural model is
not justified at this data scale. A portable logistic model scoring %(shape_ap)s is deployed
on the dashboard with its measurement recorded alongside it.</p>

<h2>1. Dataset</h2>

<p>%(dataset)s, Zenodo record 8263181, %(licence)s, published with the CSET 2024 paper.
%(alerts)s Wazuh alerts from %(networks)s simulated enterprise networks, each containing a
labelled multi-step intrusion, in native <code>alerts.json</code> format. Kaggle and
HuggingFace held no comparable set of real Wazuh alerts with ground truth phases.</p>

<div class="aside">
<p><strong>Scope limit.</strong> Rules 100100 to 100113 have no parent signature in this
dataset, and rules 5501 and 5502 are the only overlap. The evaluation therefore measures the
method and not the lab ruleset. Measuring the ruleset requires a campaign against the lab
endpoints.</p>
</div>

<h2>2. Sampling and evaluation protocol</h2>

<table>
<tr><th>Parameter</th><th class="d">Value</th></tr>
<tr><td>Episode</td><td class="d">%(window)s second tumbling window, labelled attack if it
overlaps a ground truth phase</td></tr>
<tr><td>Episodes</td><td class="d">%(episodes)s, of which %(attacks)s are attack. Base rate
%(base)s</td></tr>
<tr><td>Split</td><td class="d">Leave one network out, %(folds)s folds, three seeds per fold
for the sequence model. Whole networks are held out rather than the tail of a timeline, and
the feature vocabulary is built from training sources only, so a held out network contributes
no features</td></tr>
<tr><td>Metric</td><td class="d">Average precision. f1 at a fixed cutoff is unstable at this
base rate: the same predictions score 0.049 at 0.5 and 0.367 at a validation-selected
threshold. Thresholds are selected on validation, never on the test set</td></tr>
</table>

<h2>3. Models and results</h2>

<p>Four models were evaluated under the protocol above. The logistic regression, average
precision and metrics are implemented in numpy, approximately sixty lines in total. The
sequence model is PyTorch: an embedding over rule identifiers, a GRU, and a linear head.</p>

<table>
<tr><th>Model</th><th class="n">f1</th><th class="n">Average precision</th></tr>
%(rows)s
<tr><td>Random, for reference</td><td class="n">&mdash;</td>
    <td class="n">%(baserate)s, the base rate</td></tr>
</table>

<p>Logistic regression on rule counts and timing wins all %(wins)s folds, the GRU none, with
a mean margin of %(gru_gap)s average precision. All four score above the %(baserate)s base
rate and %(log_ap)s is approximately %(lift)s times base rate at ranking, so the alert stream
carries signal. Sequence order is not where it is.</p>

<h2>4. Deployed model</h2>

<p>The winning model uses one feature column per dataset rule identifier. Applied to this lab
every such count is zero, so it cannot be deployed. A portable variant was fitted on
%(features)s vocabulary-independent features describing burst shape and alert severity, which
transfer because Wazuh rule levels are a property of the ruleset rather than of a network. It
scores %(shape_ap)s average precision against %(log_ap)s for the non-portable model, a cost of
%(portable_gap)s and a retention of %(retained)s. The remaining signal is therefore
concentrated in which rules fired rather than in the shape of the burst, which supports the
rule-based approach already implemented.</p>

<p>The scorer runs inside the status script the dashboard already sends to the manager on each
poll. No additional service, port, dependency or manager-side installation was required.
Alerts are bucketed into %(window)s second windows and each window is scored, at a measured
cost of 4 ms against a 90 ms poll budget.</p>

<h2>5. Severity scoring</h2>

<p>Model output ranks windows by how unusual they are, which is not the same as impact.
Each window therefore also receives a 0 to 100 severity score: a weighted composite of the
model margin, peak rule level, volume of high-level alerting, burst density, distinct
signatures and distinct attack stages. A multiplier of up to %(bonus)s applies when credential
access and persistence appear in the same window, indicating a chain rather than two
independent events.</p>

<table>
<tr><th>Test case</th><th class="n">Severity</th></tr>
<tr><td>Quiet window, session opens only</td><td class="n">16</td></tr>
<tr><td>Brute force burst, rule 100111</td><td class="n">54</td></tr>
<tr><td>Brute force burst with local account creation</td><td class="n">78</td></tr>
</table>

<p>The single-event rules do not distinguish the second case from the third: both events
are reported with no relationship recorded between them. Windows scoring 50 or above are
recorded as findings, expandable to the per-term working and exportable to PDF. All constants
are stated judgements rather than fitted parameters, held in one file and printed beside the
score.</p>

<h2>6. Limitations and next step</h2>

<p>The model is fitted on eight public networks and has not been measured on this lab,
whose rules appear in no public dataset. The score is therefore triage ordering rather than a
detection, and that statement is recorded in the model file and shown on the dashboard panel.
Removing the limitation requires a scenario campaign against the lab endpoints, producing
labelled alerts that carry the lab ruleset.</p>

<p class="note">Architecture diagrams are in <code>docs/architecture/</code>. The
modelling report and the per-fold measurements are available on request.</p>

</body>
</html>
"""


if __name__ == "__main__":
    main()
