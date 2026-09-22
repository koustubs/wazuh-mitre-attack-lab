"""The per endpoint parts of the scoring, checked without a lab.

test_dashboard_scoring.py assembles the whole manager script and runs it, which is the right
check for the plumbing and the wrong one for this: on a workstation there is no indexer and no
lab-dashboard-baseline, so that test only ever exercises the path where both are absent. That
path is supposed to score exactly the way this project scored before any of the adaptive work,
and it does, which is why every number in it is unchanged.

What that leaves unchecked is everything the baseline actually does. So this file imports
score.py directly, hands it baselines it constructs, and asserts the four behaviours the
adaptive layer was added for:

    a denominator moves with the endpoint it is scoring, and not outside its bounds
    a signature the endpoint produces daily is discounted, and the same one elsewhere is not
    a signature the endpoint has never produced is not discounted, and counts for more
    a chain needs both halves on one endpoint

It also runs lab-dashboard-baseline itself, lifted out of Enable-LabDashboard.ps1, because the
folding is the part that has to be idempotent across polls and there is nowhere else that gets
checked.

    python test_adaptive_scoring.py
"""
from __future__ import annotations

import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "scoring" / "scorer"))

import score as S  # noqa: E402

FAILURES = 0


def check(name, ok, detail=""):
    global FAILURES
    print("  %-56s %s%s" % (name, "ok" if ok else "FAILED", ("  " + detail) if detail else ""))
    if not ok:
        FAILURES += 1


# A model is needed only for its threshold here. The fitted one is used rather than a made up
# number so that the model term is divided by the same thing the dashboard divides by.
MODEL = json.loads(io.open(ROOT / "scoring/scorer/model.json", encoding="utf-8-sig").read())
THRESHOLD = MODEL["threshold"]


def window(rule_id, level, n, agent="wazuh-linux", start=0.0, step=2.0, tactics=None):
    """n alerts of one rule, evenly spaced, as the scorer's episode contract wants them."""
    return [{"at": start + i * step, "ruleId": rule_id, "level": level,
             "agent": agent, "tactics": tactics or []} for i in range(n)]


def baseline_for(rule_id, seen, per_window, hour, windows=120, peak=3.0, burst=6.0,
                 distinct=1.0, mass=0.0, prob=0.35):
    """An endpoint that has produced `rule_id` `per_window` times an hour, for a long time.

    The sample rings carry a small alternating jitter rather than being flat. A flat ring has
    a median absolute deviation of zero, which collapses every derived denominator onto the
    fixed value and would make this fixture agree with the fixed path for the wrong reason.
    """
    def ring(centre, wobble):
        return [round(centre + (wobble if i % 2 else -wobble), 4) for i in range(60)]

    hours = [0] * 24
    hours[hour] = windows
    rule_hours = [0] * 24
    rule_hours[hour] = per_window * windows
    return {
        "windows": windows,
        "lastWindow": 0,
        "hours": hours,
        "samples": {"count": ring(float(per_window), 1.0), "peak": ring(peak, 0.5),
                    "mass": ring(mass, 0.5), "burst": ring(burst, 1.0),
                    "distinct": ring(distinct, 0.5), "prob": ring(prob, 0.05)},
        "rules": {str(rule_id): {"count": seen, "first": "", "last": "", "hours": rule_hours}},
    }


def main():
    print("Scoring against constructed baselines, with no lab and no manager.")
    print()
    print("Denominators:")

    fixed, meta = S.denominators(None, THRESHOLD)
    check("no baseline leaves every denominator at its fixed value",
          fixed == S.FIXED_DENOMINATORS and meta["mode"] == "fixed")

    thin = baseline_for(5501, seen=400, per_window=4, hour=10, windows=S.WARMUP_WINDOWS - 1)
    values, meta = S.denominators(thin, THRESHOLD)
    check("a baseline under the warm-up count is not used yet",
          values == S.FIXED_DENOMINATORS and meta["mode"] == "warming",
          "%d of %d windows" % (meta["windows"], meta["need"]))

    warm = baseline_for(5501, seen=400, per_window=4, hour=10)
    values, meta = S.denominators(warm, THRESHOLD)
    check("a warm baseline is used", meta["mode"] == "baseline")
    check("every measured denominator stays inside its bounds",
          all(S.DENOMINATOR_BOUNDS[k][0] <= values[k] <= S.DENOMINATOR_BOUNDS[k][1]
              for k in S.DENOMINATOR_BOUNDS),
          ", ".join("%s %.2f" % (k, values[k]) for k in sorted(S.DENOMINATOR_BOUNDS)))
    check("peak and coverage take no measurement",
          all(values[k] == S.FIXED_DENOMINATORS[k] and meta["source"][k] == "fixed"
              for k in ("peak", "coverage")))
    # The rule that cost a rewrite: a quiet endpoint must not end up with an easier bar than
    # the fixed one, or its most ordinary window saturates a component and outscores a busy
    # window on a busy host.
    check("a measured denominator never drops below its fixed value",
          all(values[k] >= S.FIXED_DENOMINATORS[k] for k in S.FIXED_DENOMINATORS),
          ", ".join("%s %.2f" % (k, values[k]) for k in sorted(S.DENOMINATOR_BOUNDS)))

    # A busy endpoint should have a larger denominator than a quiet one on the same metric,
    # because a larger reading is what is ordinary for it.
    busy = baseline_for(5501, seen=9000, per_window=90, hour=10, peak=10.0, burst=70.0,
                        distinct=6.0, mass=9.0)
    busy_values, _ = S.denominators(busy, THRESHOLD)
    check("a busier endpoint saturates later than a quiet one",
          busy_values["breadth"] > values["breadth"]
          and busy_values["velocity"] > values["velocity"],
          "breadth %.2f against %.2f, velocity %.2f against %.2f"
          % (busy_values["breadth"], values["breadth"],
             busy_values["velocity"], values["velocity"]))

    print()
    print("The model term, against the threshold it is measured from:")

    # The divisor is a multiple of the threshold, and a probability cannot exceed 1. The
    # deployed threshold is 0.85, which put the top of the highest weighted component out of
    # reach entirely: the model could contribute at most 16 of the 100 points however certain
    # it was. Measured on AIT, capping the divisor lifted average precision on both arms.
    def model_term(probability, threshold):
        got = S.severity(window(5501, 3, 4), probability, threshold)
        return [c for c in got["components"] if c["key"] == "model"][0]["value"]

    check("a certain window saturates the model term at a high threshold",
          model_term(1.0, 0.85) == 1.0, "value %.4f" % model_term(1.0, 0.85))
    check("a low threshold still saturates at twice it",
          abs(model_term(0.2, 0.1) - 1.0) < 1e-9, "p 0.20 against threshold 0.10")
    check("and is proportional below that",
          abs(model_term(0.1, 0.1) - 0.5) < 1e-9, "value %.4f" % model_term(0.1, 0.1))

    print()
    print("Routine and novelty:")

    # Four occurrences of a rule this endpoint produces four times an hour, at that hour.
    routine_alerts = window(5501, 3, 4)
    on_warm = S.severity(routine_alerts, 0.4, THRESHOLD, warm, hour=10)
    on_cold = S.severity(routine_alerts, 0.4, THRESHOLD, None, hour=10)
    check("the endpoint's own daily signature is recognised as routine",
          on_warm["routineShare"] == 1.0 and on_warm["routine"] < 1.0,
          "x%.4f on %d%% of the window" % (on_warm["routine"], 100 * on_warm["routineShare"]))
    check("and scores lower than the same window with no history",
          on_warm["score"] < on_cold["score"],
          "%.1f against %.1f" % (on_warm["score"], on_cold["score"]))

    # The same four alerts at three in the morning, when this endpoint has never produced them.
    off_hour = S.severity(routine_alerts, 0.4, THRESHOLD, warm, hour=3)
    check("the same signature outside its usual hour is not discounted",
          off_hour["routine"] == 1.0 and off_hour["score"] > on_warm["score"],
          "%.1f against %.1f" % (off_hour["score"], on_warm["score"]))

    # Twenty of them, where four is normal, is five times the rate and past the band.
    burst_alerts = window(5501, 3, 20)
    on_burst = S.severity(burst_alerts, 0.4, THRESHOLD, warm, hour=10)
    check("a burst of the routine signature is not called routine",
          on_burst["routineShare"] == 0.0 and on_burst["routine"] == 1.0)

    # A rule the endpoint has never produced.
    novel_alerts = window(100199, 3, 4)
    on_novel = S.severity(novel_alerts, 0.4, THRESHOLD, warm, hour=10)
    check("a signature this endpoint has never produced counts for more",
          on_novel["novelty"] > 1.0 and on_novel["novelShare"] == 1.0,
          "x%.4f" % on_novel["novelty"])
    check("and outscores the endpoint's own daily traffic",
          on_novel["score"] > on_warm["score"],
          "%.1f against %.1f" % (on_novel["score"], on_warm["score"]))
    check("neither multiplier fires during warm-up",
          S.severity(novel_alerts, 0.4, THRESHOLD, thin, hour=10)["novelty"] == 1.0
          and S.severity(routine_alerts, 0.4, THRESHOLD, thin, hour=10)["routine"] == 1.0)

    print()
    print("Chains, per endpoint:")

    together = window(100110, 3, 20, agent="a") + window(100112, 6, 1, agent="a", start=100.0)
    apart = window(100110, 3, 20, agent="a") + window(100112, 6, 1, agent="b", start=100.0)
    one_box = S.severity_by_agent(together, 0.5, THRESHOLD)
    two_boxes = S.severity_by_agent(apart, 0.5, THRESHOLD)
    check("credential access and persistence on one endpoint is a chain",
          one_box["chained"] and one_box["chain"] > 1.0, "x%.4f" % one_box["chain"])
    check("the same two on different endpoints is not",
          not two_boxes["chained"] and two_boxes["chain"] == 1.0)
    check("and therefore scores lower",
          two_boxes["score"] < one_box["score"],
          "%.1f against %.1f" % (two_boxes["score"], one_box["score"]))
    check("both endpoints are still reported",
          [p["agent"] for p in sorted(two_boxes["perAgent"], key=lambda p: p["agent"])]
          == ["a", "b"])
    check("a window with no agent names scores as one slice",
          S.severity_by_agent(window(100110, 3, 20, agent=""), 0.5, THRESHOLD)["score"]
          == S.severity(window(100110, 3, 20, agent=""), 0.5, THRESHOLD)["score"])
    check("a routine chain keeps its multiplier and loses the discount",
          S.severity(together, 0.5, THRESHOLD,
                     baseline_for(100110, seen=9000, per_window=20, hour=10),
                     hour=10)["routine"] == 1.0)

    print()
    print("lab-dashboard-baseline, lifted out of Enable-LabDashboard.ps1:")
    helper = extract_baseline()
    if helper is None:
        check("the helper was found in Enable-LabDashboard.ps1", False)
    else:
        run_baseline_checks(helper)

    print()
    if FAILURES:
        print("%d check(s) FAILED." % FAILURES)
        return 1
    print("All checks passed.")
    return 0


def extract_baseline():
    """The helper's source, with its state file pointed somewhere this test owns."""
    src = io.open(ROOT / "dashboard/Enable-LabDashboard.ps1", encoding="utf-8-sig").read()
    m = re.search(r"<<'BASELINE'\r?\n(.*?)\r?\nBASELINE\r?\n", src, re.S)
    return m.group(1) if m else None


def call_baseline(script, state_path, observations):
    """Run it the way the manager script does: observations in, the previous state out."""
    body = script.replace("STATE = '/var/lib/wazuh-lab/baseline.json'",
                          "STATE = %r" % str(state_path))
    runner = state_path.parent / "baseline.py"
    io.open(runner, "w", encoding="utf-8", newline="\n").write(body)
    p = subprocess.run([sys.executable, str(runner)], input=json.dumps(
        {"observations": observations}), capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit("lab-dashboard-baseline failed:\n%s" % p.stderr[-2000:])
    return json.loads(p.stdout)


def observation(agent, epoch, hour, rules, count=None):
    return {"agent": agent, "epoch": epoch, "hour": hour, "at": "2026-09-22T%02d:00:00" % hour,
            "count": count if count is not None else sum(rules.values()),
            "peak": 3.0, "mass": 0.0, "burst": 4, "distinct": len(rules), "prob": 0.3,
            "rules": rules}


def run_baseline_checks(script):
    tmp = pathlib.Path(tempfile.mkdtemp())
    state = tmp / "baseline.json"

    first = call_baseline(script, state, [observation("wazuh-linux", 1000, 10, {"5501": 4})])
    check("the first call prints an empty baseline", first.get("agents") == {})

    second = call_baseline(script, state, [observation("wazuh-linux", 1300, 10, {"5501": 4})])
    agent = second["agents"]["wazuh-linux"]
    check("what it printed second is what it folded first",
          agent["windows"] == 1 and agent["rules"]["5501"]["count"] == 4)
    check("the state it prints is the state before this call's observations",
          agent["lastWindow"] == 1000)

    # The same two windows again, which is what every subsequent poll sends.
    third = call_baseline(script, state, [observation("wazuh-linux", 1000, 10, {"5501": 4}),
                                          observation("wazuh-linux", 1300, 10, {"5501": 4})])
    check("re-sending a folded window changes nothing",
          third["agents"]["wazuh-linux"]["windows"] == 2
          and third["agents"]["wazuh-linux"]["rules"]["5501"]["count"] == 8)

    fourth = call_baseline(script, state, [])
    check("an empty observation list folds nothing",
          fourth["agents"]["wazuh-linux"]["windows"] == 2)

    # Past the ring, to check it is a ring and not a list that grows for as long as the lab
    # runs. One poll's worth of observations at a time, as the manager sends them.
    batch = [observation("wazuh-linux", 2000 + i * 300, 10, {"5501": 4})
             for i in range(S.WARMUP_WINDOWS * 20)]
    call_baseline(script, state, batch)
    final = call_baseline(script, state, [])["agents"]["wazuh-linux"]
    check("the sample ring is bounded",
          all(len(v) <= 288 for v in final["samples"].values()),
          "count ring holds %d" % len(final["samples"]["count"]))
    check("the window count is not",
          final["windows"] == 2 + len(batch), "%d windows" % final["windows"])

    check("two endpoints are kept apart",
          "wazuh-win" not in call_baseline(
              script, state, [observation("wazuh-win", 9000, 10, {"100101": 2})])["agents"]
          and "wazuh-win" in call_baseline(script, state, [])["agents"])

    # And the whole point: that folded history makes the scoring treat the two differently.
    built = call_baseline(script, state, [])["agents"]["wazuh-linux"]
    quiet = S.severity(window(5501, 3, 4), 0.4, THRESHOLD, built, hour=10)
    check("a baseline this helper built discounts the traffic it was built from",
          quiet["routine"] < 1.0, "x%.4f" % quiet["routine"])


if __name__ == "__main__":
    raise SystemExit(main())
