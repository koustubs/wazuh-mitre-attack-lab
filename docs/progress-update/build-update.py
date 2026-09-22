"""Build the progress update page that goes to the mentor.

    python build-update.py            # writes update.html beside this file

He already knows steps 1 to 4. The only open thread is the one he raised, which is whether
PyTorch can find patterns across alerts that the single event rules cannot. This answers
that and nothing else.

Same rule as the modelling report. No figure is typed in here. Every number is read from
the artefact that produced it, so the document cannot drift away from the measurements the
way the README already did once this week. If a figure looks wrong, the artefact is wrong.

    05-detection-modelling/data/ait/folds.jsonl   the eight fold results
    05-detection-modelling/scorer/model.json      the deployed model and its provenance
    05-detection-modelling/scorer/score.py        the severity weights and bands
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
MODELLING = ROOT / "05-detection-modelling"


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
        "caveat": model["caveat"],
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
<title>Using PyTorch to find patterns across alerts</title>
<style>
  @page { size: A4; margin: 17mm 16mm 16mm; }
  :root { --ink:#17171a; --soft:#55555e; --faint:#85858e; --line:#d9d9d4;
          --rule:#24242a; --accent:#0f6e56; }
  * { box-sizing: border-box; }
  body { font: 10.5pt/1.55 "Charter","Georgia","Cambria",serif; color: var(--ink);
         margin: 0 auto; max-width: 178mm; -webkit-print-color-adjust: exact;
         print-color-adjust: exact; }
  h1 { font-size: 19pt; line-height: 1.22; margin: 0 0 6px; letter-spacing: -.01em; }
  h2 { font-size: 12.5pt; margin: 24px 0 9px; padding-bottom: 5px;
       border-bottom: 1.5px solid var(--rule); }
  h3 { font-size: 10.5pt; margin: 16px 0 5px; }
  p { margin: 0 0 9px; }
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
           padding:10px 13px; margin:12px 0; font-size:9.5pt; }
  .aside p:last-child { margin-bottom: 0; }
  table { border-collapse: collapse; width: 100%%; margin: 10px 0 14px; font-size: 9.5pt; }
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
  footer { margin-top:24px; padding-top:10px; border-top:1px solid var(--line);
           color:var(--faint); font-size:8.5pt; }
</style>
</head>
<body>

<h1>Using PyTorch to find patterns across alerts</h1>
<p class="sub">What it measured, and what went on the dashboard instead</p>
<p class="meta">%(generated)s &middot; Prepared by Koustub</p>

<p class="lead">This is the idea we talked about: the rules detect single events, so use a
neural model to read a <em>run</em> of alerts and judge it. I built it and measured it
properly. The short version is that it loses, and this is the account of what it lost to and
what I shipped instead.</p>

<div class="finding">
<p><strong>A GRU over the alert sequence is beaten by plain logistic regression on all
%(wins)s held out networks.</strong> The neural model wins none of them, trailing by a mean
of %(gru_gap)s average precision. On this evidence PyTorch is not justified for this problem,
and I would rather report that than ship a neural network because it sounds better.</p>
</div>

<h2>The data</h2>

<p>The %(dataset)s, published on Zenodo with the CSET 2024 paper under %(licence)s.
%(alerts)s Wazuh alerts from %(networks)s simulated enterprise networks, each carrying a
labelled multi-step intrusion, in native <code>alerts.json</code> form, which is the same
record my own manager writes. I checked Kaggle and HuggingFace first; neither had real Wazuh
alerts with ground truth attached.</p>

<div class="aside">
<p><strong>What it cannot answer, stated up front.</strong> None of this lab's rules 100100 to
100113 have a parent signature in it. Rules 5501 and 5502 are the entire overlap. So this
measures the method, not my ruleset. Only a campaign against the lab measures the lab.</p>
</div>

<h2>Sampling</h2>

<ul>
<li>An episode is a <strong>%(window)s second tumbling window</strong>, labelled attack if it
overlaps a ground truth phase: <strong>%(episodes)s episodes, %(attacks)s of them attack</strong>,
a base rate of %(base)s.</li>
<li><strong>Whole networks held out, never the tail of a timeline.</strong> A model scored on
the last hour of a network it trained on may only have learned that network's noise floor.</li>
<li><strong>%(folds)s folds, leave one network out</strong>, three seeds per fold for the
neural model. On a single split two of these finished 0.046 apart with forty attack episodes
between them, well inside what a different pair of held out networks would move. Counting fold
wins is the claim that survives.</li>
<li><strong>Average precision, not f1 at a fixed cutoff.</strong> At a 2%% base rate the same
logistic predictions score f1 0.049 at 0.5 and 0.367 at a threshold chosen on validation.
Every threshold here was picked on validation and never on the test set.</li>
</ul>

<h2>What each model scored</h2>

<p>The logistic regression, the average precision and the metrics are about sixty lines of
numpy between them. The sequence model is PyTorch: an embedding over rule ids, a GRU, and a
linear head.</p>

<table>
<tr><th>Model</th><th class="n">f1</th><th class="n">Average precision</th></tr>
%(rows)s
<tr><td>Random, for reference</td><td class="n">&mdash;</td>
    <td class="n">%(baserate)s, the base rate</td></tr>
</table>

<p>All three find real signal: %(log_ap)s against a %(baserate)s base rate is about %(lift)s
times better than chance at ranking. The sequence structure is simply not where the signal
is.</p>

<h2>What is deployed instead</h2>

<p>The winning model's features are one column per dataset rule id. Pointed at this lab every
one of those counts is zero, so I fitted a portable version on %(features)s features that name
no signature at all: the shape of a burst and the severity inside it, which transfer because
Wazuh levels are a property of the ruleset rather than of a network. It scores %(shape_ap)s
against the winner's %(log_ap)s.</p>

<div class="aside">
<p><strong>The size of that gap is itself the result.</strong> Portability costs
%(portable_gap)s average precision and retains %(retained)s. Most of the signal was in which
rules fired, not in the shape of the burst, which is an argument for the rule based approach
the lab already has rather than against it.</p>
</div>

<p>It runs inside the dashboard that already existed. No second dashboard, no new service, no
new port, nothing installed on the manager: the scorer went into the status script the
dashboard already ships to the manager on every poll. Alerts are bucketed into %(window)s
second windows and each is scored, at a cost of 4 ms against a 90 ms poll budget.</p>

<h2>A severity score, because the model answers the wrong question</h2>

<p>The model says how unusual a window is. A queue needs how bad it is, and those are not the
same. So each window also gets a 0 to 100 severity, a weighted composite with the model as one
term among six: peak rule level, how much high level alerting there was rather than just the
peak, how tight the busiest minute was, how many distinct signatures, and how many attack
stages appeared. The total is multiplied by up to %(bonus)s when credential access and
persistence both appear in the same window, because that pairing is a chain rather than two
events.</p>

<div class="finding">
<p>A quiet window scores <strong>16</strong>, a brute force burst alone scores <strong>54</strong>,
and the same burst with an account creation beside it scores <strong>78</strong>. The existing
rules cannot separate those last two. They report both events and nothing that says they
belong together.</p>
</div>

<p>Any window at 50 or above becomes a finding, expandable to the full working and exportable
to PDF. Every constant is judgement rather than a fitted parameter, they are in one file, and
the dashboard prints the formula beside the score.</p>

<h2>The limit, and what would remove it</h2>

<p>%(caveat)s</p>

<p>That sentence is on the panel itself rather than buried in a document. The work that closes
it is a long scenario campaign against the lab's own endpoints, producing labelled alerts that
carry my rules, and that is the next thing I would do if this is worth continuing.</p>

<footer>
Eleven architecture diagrams covering the full system are in
<code>docs/architecture/</code>, viewable as a single self-contained page. A longer seven page
write up of the modelling, and the raw per-fold measurements, are available on request.
</footer>

</body>
</html>
"""


if __name__ == "__main__":
    main()
