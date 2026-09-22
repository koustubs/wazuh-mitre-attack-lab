"""Run the dashboard's manager-side script against fabricated alerts, with no lab running.

The scoring path is the longest thing in this project between a change and its consequence. A
Python block lives inside a PowerShell here-string, has two files substituted into it, is base64
encoded, travels over SSH, runs on the manager and comes back as JSON that a browser renders. A
mistake anywhere in that chain looks the same from the dashboard: a panel that is quietly wrong.

So it is assembled and run here exactly as Start-LabDashboard.ps1 assembles it, against alerts
written to make the answers knowable in advance. This needs no VM, no SSH and no manager. It
takes about a second and it is the check to run before touching any of:

    dashboard/Start-LabDashboard.ps1   the remote script
    scoring/scorer/score.py                        features and severity
    scoring/scorer/model.json                      the fitted model

    python test_dashboard_scoring.py
    python test_dashboard_scoring.py --payload out.json   # also dump what the manager returns

The dumped payload is what the page is handed as `health.scoring`, which makes it the input to
use when eyeballing the panel itself in a browser.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
DASHBOARD = ROOT / "dashboard/Start-LabDashboard.ps1"
SCORER = ROOT / "scoring/scorer"

# The lab's own rules, with the ATT&CK metadata Wazuh attaches from lab_rules.xml.
MITRE = {
    100110: {"id": ["T1110.001"], "tactic": ["Credential Access"], "technique": ["Password Guessing"]},
    100111: {"id": ["T1110.001"], "tactic": ["Credential Access"], "technique": ["Password Guessing"]},
    100112: {"id": ["T1136.001"], "tactic": ["Persistence"], "technique": ["Local Account"]},
    100113: {"id": ["T1053.003"], "tactic": ["Persistence"], "technique": ["Cron"]},
}

FAILURES = 0


def check(name, ok, detail=""):
    global FAILURES
    print("  %-52s %s%s" % (name, "ok" if ok else "FAILED", ("  " + detail) if detail else ""))
    if not ok:
        FAILURES += 1


def build_script(with_model=True):
    """Assemble the manager script the way Start-LabDashboard.ps1 does, substitutions and all."""
    ps = io.open(DASHBOARD, encoding="utf-8-sig", newline="").read()
    m = re.search(r"\$RemoteStatusScript = @'\r?\n(.*?)\r?\n'@", ps, re.S)
    if not m:
        raise SystemExit("Could not find $RemoteStatusScript in %s. The here-string that carries "
                         "the manager script has moved or changed shape." % DASHBOARD)
    script = m.group(1)
    if not with_model:
        # The markers are left alone, which is what happens on a clone that never ran the
        # modelling step, and the panel is supposed to say so rather than fail.
        return script
    code = io.open(SCORER / "score.py", encoding="utf-8").read().replace("\r\n", "\n")
    model = io.open(SCORER / "model.json", encoding="utf-8").read()
    script = script.replace("# __SCORER_MODULE__", code)
    return script.replace("__SCORER_MODEL_B64__",
                          base64.b64encode(model.encode("utf-8")).decode("ascii"))


def alerts():
    """Four windows whose relative severities are known before anything is run.

    10:00  twenty session opens, slowly              quiet
    10:05  a brute force burst tripping 100111       credential access only
    10:10  the same burst plus an account creation   a chain, and the worst of the four
    10:15  a handful of session opens                still filling when the sample is taken
    """
    base = datetime.datetime(2026, 9, 21, 10, 0, 0)
    out = []

    def add(off, rid, level, desc):
        t = base + datetime.timedelta(seconds=off)
        out.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
            "agent": {"name": "wazuh-linux"},
            "rule": {"id": str(rid), "level": level, "description": desc,
                     "mitre": MITRE.get(rid, {})},
        })

    for i in range(20):
        add(i * 15, 5501, 3, "PAM: login session opened")

    for i in range(40):
        add(300 + i * 2, 100110, 3, "Linux: incorrect SSH password")
    for i in range(4):
        add(340 + i * 5, 100111, 10, "Linux: repeated incorrect SSH passwords")

    for i in range(40):
        add(600 + i * 2, 100110, 3, "Linux: incorrect SSH password")
    for i in range(4):
        add(640 + i * 5, 100111, 10, "Linux: repeated incorrect SSH passwords")
    add(700, 100112, 6, "Linux: local account created")

    for i in range(6):
        add(900 + i * 40, 5501, 3, "PAM: login session opened")

    return out


def run(script, records, tmp, indexer=None, baseline=None):
    """Run the assembled script with its alert log, and optionally its two manager side
    helpers, pointed at things we control.

    The helpers are the part of this path a workstation cannot reach: there is no sudo, no
    indexer and no /var/lib/wazuh-lab. Substituting a stub for each is what makes the three
    states a real manager can be in reachable here, and they behave differently enough to
    matter: one with the current helpers, one still carrying the older ones, and one with
    neither. Passing no stub is the third of those.
    """
    path = tmp / "alerts.json"
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    # Everything else the script reads (systemctl, sudo, ossec.log) is absent here and is
    # reported as a missing capability rather than raising, which is itself worth exercising.
    script = script.replace("/var/ossec/logs/alerts/alerts.json", str(path).replace("\\", "/"))
    for helper, stub in (("indexer", indexer), ("baseline", baseline)):
        if stub is None:
            continue
        script = script.replace("'sudo', '-n', '/usr/local/bin/lab-dashboard-%s'" % helper,
                                "%r, %r" % (sys.executable, str(stub)))
    runner = tmp / "remote.py"
    io.open(runner, "w", encoding="utf-8", newline="\n").write(script)
    p = subprocess.run([sys.executable, str(runner)], capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit("The manager script failed:\n%s" % p.stderr[-2500:])
    return json.loads(p.stdout)


def stub(tmp, name, prints, records_stdin_to=None):
    """A stand-in helper that prints a fixed document, and optionally keeps what it was sent."""
    body = ["import io, sys",
            "sys.stdout.write(%r)" % json.dumps(prints)]
    if records_stdin_to is not None:
        body.append("io.open(%r, 'w', encoding='utf-8').write(sys.stdin.read())"
                    % str(records_stdin_to))
    p = tmp / (name + "_stub.py")
    io.open(p, "w", encoding="utf-8", newline="\n").write("\n".join(body) + "\n")
    return p


def warm_baseline(agent, windows=200):
    """An endpoint with enough history to be past warm-up, in the helper's own state shape."""
    hours = [windows // 24 + 1] * 24
    return {"version": 1, "agents": {agent: {
        "windows": windows, "lastWindow": 0, "hours": hours,
        "samples": {k: [v + (0.5 if i % 2 else -0.5) for i in range(60)] for k, v in
                    (("count", 20.0), ("peak", 3.0), ("mass", 1.0), ("burst", 8.0),
                     ("distinct", 2.0), ("prob", 0.5))},
        "rules": {"5501": {"count": 5000, "first": "", "last": "",
                           "hours": [200] * 24}}}}}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--payload", help="write the manager's JSON here as well")
    a = ap.parse_args()

    tmp = pathlib.Path(tempfile.mkdtemp())
    records = alerts()

    print("Assembling the manager script and running it on %d fabricated alerts." % len(records))
    out = run(build_script(), records, tmp)
    sc = out.get("scoring")

    print()
    print("Windows returned:")
    for w in (sc or {}).get("windows", []):
        print("  %s  severity %5.1f %-14s model %.3f  %3d alerts%s"
              % (w["at"], w["severity"], w["band"], w["score"], w["alerts"],
                 "  (still filling)" if w["partial"] else ""))

    print()
    print("Checks:")
    check("the script returns a scoring block", bool(sc))
    if not sc:
        raise SystemExit("Nothing else can be checked. Keys returned: %s" % sorted(out))

    wins = sc["windows"]
    check("one window per five minutes of alerts", len(wins) == 4, "got %d" % len(wins))
    check("windows are in time order", [w["at"] for w in wins] == sorted(w["at"] for w in wins))
    check("only the newest window is still filling",
          [w["partial"] for w in wins] == [False, False, False, True])

    quiet, brute, chained, filling = wins
    check("quiet window is informational", quiet["band"] == "informational",
          "%.1f %s" % (quiet["severity"], quiet["band"]))
    check("a brute force burst outscores a quiet window",
          brute["severity"] > quiet["severity"],
          "%.1f against %.1f" % (brute["severity"], quiet["severity"]))
    # The finding the whole project is about: the rules in step 4 report a brute force alert and
    # an account creation alert and nothing that says they belong together.
    check("brute force plus persistence outscores brute force alone",
          chained["severity"] > brute["severity"],
          "%.1f against %.1f" % (chained["severity"], brute["severity"]))
    check("only the chained window earns the multiplier",
          chained["working"]["chained"] and not brute["working"]["chained"])
    check("the multiplier actually multiplies", chained["working"]["chain"] > 1.0,
          "x%.4f" % chained["working"]["chain"])
    check("both stages are recognised",
          set(chained["working"]["stages"]) == {"credential access", "persistence"},
          str(chained["working"]["stages"]))

    weights = sum(c["weight"] for c in chained["working"]["components"])
    check("the weights sum to one", abs(weights - 1.0) < 1e-9, "%.6f" % weights)
    points = sum(c["contribution"] for c in chained["working"]["components"])
    check("the components account for the base score",
          abs(points - chained["working"]["base"]) < 0.05,
          "%.2f against %.2f" % (points, chained["working"]["base"]))
    check("severity is base times chain",
          abs(chained["working"]["base"] * chained["working"]["chain"]
              - chained["severity"]) < 0.06)

    findings = sc["findings"]
    check("findings are completed windows at elevated or above",
          all(f["severity"] >= 50 and not f["partial"] for f in findings),
          "%d finding(s)" % len(findings))
    check("findings are ordered worst first",
          [f["severity"] for f in findings] == sorted((f["severity"] for f in findings),
                                                      reverse=True))
    check("the worst window is reported as the top one",
          sc["top"]["epoch"] == max(w["epoch"] for w in wins if not w["partial"]
                                    and w["severity"] == max(x["severity"] for x in wins
                                                             if not x["partial"])))
    check("every finding carries the rules that produced it",
          all(f.get("rules") for f in findings))
    check("the explainer is sent the weights it must print",
          len(sc.get("severityWeights", [])) == len(chained["working"]["components"]))
    check("the model's own measurement travels with it",
          bool(sc["model"]["ap"]) and bool(sc["model"]["caveat"]))

    # A stage read from a rule id must count the same as one ATT&CK named, or the score depends
    # on whether a rule author filled in a field. This is the fault that produced a chain
    # multiplier of exactly 1.0 while the page reported a chain had been found.
    bare = [dict(r, rule=dict(r["rule"], mitre={})) for r in records]
    out2 = run(build_script(), bare, tmp)
    bare_chained = out2["scoring"]["windows"][2]
    check("stripping ATT&CK metadata does not change the score",
          abs(bare_chained["severity"] - chained["severity"]) < 1e-9,
          "%.1f against %.1f" % (bare_chained["severity"], chained["severity"]))

    # A clone that never ran the modelling step gets a working dashboard and an honest panel.
    out3 = run(build_script(with_model=False), records, tmp)
    check("no model file is reported rather than failing",
          (out3.get("scoring") or {}).get("note") == "no-model",
          str(out3.get("scoring")))
    out4 = run(build_script(), [], tmp)
    check("no alerts is reported rather than failing",
          (out4.get("scoring") or {}).get("note") == "no-alerts",
          str(out4.get("scoring")))

    print()
    print("Where the alerts came from:")
    check("with no helper at all, the log tail answers and says it has a ceiling",
          (out.get("alertSource") or {}).get("from") == "log-tail"
          and "truncated" in (out.get("alertSource") or {}),
          str(out.get("alertSource")))

    # A manager still carrying the older helper. It ignores the subcommand, prints its cluster
    # summary and exits 0, so an exit code alone would read that as a search that found
    # nothing and the panel would go blank on every lab that has not been re-enabled.
    old = run(build_script(), records, tmp,
              indexer=stub(tmp, "old_indexer", {"status": "green", "nodes": 1}))
    check("an older helper's answer is recognised and not mistaken for an empty search",
          (old.get("alertSource") or {}).get("from") == "log-tail"
          and len(old["scoring"]["windows"]) == 4,
          str(old.get("alertSource")))

    fresh = stub(tmp, "new_indexer", {
        "records": records, "total": len(records), "returned": len(records),
        "truncated": False, "spanMinutes": 90,
        "hourly": [], "coverage": {"5501": {"count": 26, "timestamp": records[0]["timestamp"],
                                            "level": 3}},
        "attack": [{"tech": "Password Guessing", "count": 8}]})
    viaindex = run(build_script(), [], tmp, indexer=fresh)
    check("the indexer answers, with an empty alert log beside it",
          (viaindex.get("alertSource") or {}).get("from") == "indexer"
          and len(viaindex["scoring"]["windows"]) == 4,
          str((viaindex.get("alertSource") or {}).get("from")))
    check("the rule tallies come from the aggregation rather than the documents",
          viaindex["coverage"].get("5501", {}).get("count") == 26,
          str(viaindex["coverage"].get("5501")))

    cut = stub(tmp, "cut_indexer", {
        "records": records, "total": 9999, "returned": len(records), "truncated": True,
        "spanMinutes": 90})
    short = run(build_script(), [], tmp, indexer=cut)
    check("a fetch that hit its ceiling says so instead of looking like a quiet hour",
          (short["scoring"]["source"] or {}).get("truncated") is True
          and short["scoring"]["source"]["total"] == 9999)

    print()
    print("The baseline, through the assembled script:")
    seen = tmp / "folded.json"
    warm = stub(tmp, "baseline", warm_baseline("wazuh-linux"), records_stdin_to=seen)
    adapted = run(build_script(), records, tmp, baseline=warm)
    worst = adapted["scoring"]["top"]["working"]
    check("a warm endpoint is scored against its own baseline",
          worst["baselineMode"] == "baseline" and worst["baselineWindows"] == 200,
          "%s, %d windows" % (worst["baselineMode"], worst["baselineWindows"]))
    check("the denominators travel with the score",
          all("denominator" in c and "source" in c for c in worst["components"])
          and any(c["source"] == "measured" for c in worst["components"]))
    check("the explainer is sent the constants behind them",
          bool(adapted["scoring"].get("adaptive", {}).get("fixed")))
    check("the endpoint the severity belongs to is named",
          adapted["scoring"]["top"]["agent"] == "wazuh-linux")
    check("four windows is fewer than one screen, so nothing is folded yet",
          json.loads(io.open(seen, encoding="utf-8").read())["observations"] == []
          and adapted["scoring"]["baseline"]["folded"] == 0)

    # Sixteen windows of quiet traffic, so four of them have scrolled off the chart.
    long_run = []
    stamp = datetime.datetime(2026, 9, 21, 6, 0, 0)
    for w in range(16):
        for i in range(5):
            t = stamp + datetime.timedelta(seconds=w * 300 + i * 20)
            long_run.append({
                "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
                "agent": {"name": "wazuh-linux"},
                "rule": {"id": "5501", "level": 3, "description": "PAM: login session opened",
                         "mitre": {}}})
    rolled = run(build_script(), long_run, tmp, baseline=warm)
    folded = json.loads(io.open(seen, encoding="utf-8").read())["observations"]
    check("only windows that have scrolled off the chart are folded",
          len(folded) == 4 and rolled["scoring"]["baseline"]["folded"] == 4,
          "%d of 16 windows" % len(folded))
    check("a folded observation carries the endpoint, the hour and its rule counts",
          all(o["agent"] == "wazuh-linux" and o["rules"] == {"5501": 5}
              and 0 <= o["hour"] <= 23 for o in folded))
    check("no window still on the chart was folded",
          max(o["epoch"] for o in folded)
          < min(w["epoch"] for w in rolled["scoring"]["windows"]))

    if a.payload:
        dest = pathlib.Path(a.payload)
        out["reachable"] = True
        io.open(dest, "w", encoding="utf-8", newline="\n").write(json.dumps(out, indent=1))
        print()
        print("wrote %s" % dest)

    print()
    if FAILURES:
        raise SystemExit("%d check(s) failed." % FAILURES)
    print("All checks passed.")


if __name__ == "__main__":
    main()
