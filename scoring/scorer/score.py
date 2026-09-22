"""The deployed scorer. Standard library only, and deliberately so.

This is the one piece of the modelling step that leaves the workstation. It runs on the Wazuh
manager, inside the status script the dashboard already ships there on every poll, and the
manager has python3 and nothing else. No numpy, no torch, no pip install on a box whose job is
to receive alerts.

That is affordable because the model that won is logistic regression over eleven features. The
whole of inference is a dot product and one exponential. Shipping PyTorch to evaluate 5,458
parameters that lost on all eight folds would have been the wrong trade twice over.

The same file is used by export-model.py to check itself. features() here and shape_only() in
features.py have to agree to the last decimal or the model is being fed something other than
what it was fitted on, and that is the failure that looks like a working dashboard.

    from score import features, score, load
    model = load("model.json")
    p = score(model, features(alerts))

`alerts` is a list of dicts with `at` in seconds from the start of the window, `ruleId`, and
`level`. That is the episode contract from alert_stream.py, and it is also what one line of
/var/ossec/logs/alerts/alerts.json reduces to.
"""
import json
import math

# The order the model's weights are in. Changing it silently mis-scores everything, so the
# exported file carries this list too and load() refuses a file that disagrees.
COLUMNS = ["n_alerts", "duration_s", "min_gap_s", "median_gap_s", "max_gap_s",
           "busiest_60s", "n_distinct_rules", "max_level", "mean_level",
           "n_level_ge_7", "n_level_ge_10"]


def _median(xs):
    """numpy's median, which averages the middle pair on an even count. Matching it matters."""
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return float(s[mid]) if n % 2 else (float(s[mid - 1]) + float(s[mid])) / 2.0


def features(alerts):
    """Eleven numbers describing a window of alerts. No rule id appears in the result.

    That is the point of this feature set rather than an oversight: see shape_only() in
    features.py for why a model over rule counts cannot be moved to a network with a different
    rule set, which this lab is.
    """
    a = sorted(alerts, key=lambda x: x.get("at", 0.0))
    times = [float(x.get("at", 0.0)) for x in a]
    rules = [x.get("ruleId") for x in a]
    levels = [float(x.get("level") or 0) for x in a]

    gaps = [times[i] - times[i - 1] for i in range(1, len(times))] or [0.0]

    # One pass, not the obvious nested pair. times is sorted so the right edge only moves
    # forward. The quadratic version is invisible at nine alerts a window and dominates at
    # two hundred and fifty, which is where the busy scenarios actually sit.
    busiest = 0
    right = 0
    for left, t in enumerate(times):
        while right < len(times) and times[right] < t + 60.0:
            right += 1
        busiest = max(busiest, right - left)

    return [
        float(len(times)),
        float(times[-1] - times[0]) if len(times) > 1 else 0.0,
        float(min(gaps)),
        _median(gaps),
        float(max(gaps)),
        float(busiest),
        float(len(set(rules))),
        max(levels) if levels else 0.0,
        (sum(levels) / len(levels)) if levels else 0.0,
        float(sum(1 for v in levels if v >= 7)),
        float(sum(1 for v in levels if v >= 10)),
    ]


def score(model, feats):
    """The probability this window is an attack, on the model's own scale.

    Standardise with the training set's mean and sd, then the logistic. The clamp is the same
    one the training code uses; without it a far out window overflows exp() and raises rather
    than saturating, which on a live dashboard would be a panel that vanishes when something
    interesting happens.
    """
    mu, sd, w = model["mean"], model["sd"], model["weights"]
    z = float(model["bias"])
    for i in range(len(w)):
        z += w[i] * ((feats[i] - mu[i]) / (sd[i] if sd[i] else 1.0))
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def load(path_or_text):
    """A model file, checked against this file's idea of the column order."""
    if isinstance(path_or_text, str) and path_or_text.lstrip().startswith("{"):
        m = json.loads(path_or_text)
    else:
        with open(path_or_text, encoding="utf-8-sig") as fh:
            m = json.load(fh)
    if m.get("columns") != COLUMNS:
        raise ValueError("model column order does not match score.py")
    for k in ("weights", "mean", "sd", "bias", "threshold"):
        if k not in m:
            raise ValueError("model file is missing %s" % k)
    if not (len(m["weights"]) == len(m["mean"]) == len(m["sd"]) == len(COLUMNS)):
        raise ValueError("model file has the wrong number of coefficients")
    return m


# --------------------------------------------------------------------------- severity

# The model answers one question: how unusual is this window. That is not the same as how bad
# it is, and an analyst working a queue needs the second. A window of forty level 3 alerts and
# a window holding one level 10 plus an account creation can score alike on the model and are
# not alike.
#
# So the number shown beside a flagged window is a composite, and the model is one term in it.
# Six components, each normalised to 0..1, weighted, then multiplied by an escalation term for
# the one pattern this whole lab was built around: credential access followed by persistence.
#
# The weights below are judgements and are in one place so that disagreeing with them is an
# edit rather than an argument. The denominators they divide by are no longer judgements:
# where an endpoint has enough history, four of the six are derived from that endpoint's own
# traffic. The baseline section further down is where that happens.
SEVERITY_WEIGHTS = (
    ("model",     0.28, "How far past its cutoff the model put this window"),
    ("peak",      0.18, "The highest Wazuh rule level in the window"),
    ("mass",      0.16, "How much high level alerting there was, not just the peak"),
    ("velocity",  0.12, "How tightly the busiest minute was packed"),
    ("breadth",   0.10, "How many distinct signatures were involved"),
    ("coverage",  0.16, "How many distinct attack stages appeared"),
)

# Escalation. A window that shows credential access and persistence together is worth more than
# the sum of the two, because that pairing is a chain rather than two events, and a chain is
# what the rules in step 4 individually cannot see.
#
# Half the bonus is for the pairing existing at all and half is scaled by how much of the chain
# is visible. An earlier version scaled the whole bonus by coverage, which meant a chain read
# from rule identity alone, on alerts carrying no ATT&CK metadata, produced a multiplier of
# exactly 1.0 while the page reported a chain had been found. A multiplier that does nothing is
# worse than no multiplier, because it looks like a reason.
CHAIN_BONUS = 0.30

# The lab's own rules for each stage, so a chain is still recognised when the alerts carry no
# ATT&CK metadata. Wazuh attaches a tactic only where the rule author declared one, and plenty
# of built-in rules did not.
PERSISTENCE_RULES = (100102, 100103, 100112, 100113)
CREDENTIAL_RULES = (100100, 100101, 100110, 100111)

BANDS = ((85, "critical"), (70, "high"), (50, "elevated"), (25, "low"), (0, "informational"))


# --------------------------------------------------------------------------- baseline

# A fixed denominator is the same judgement on every machine, which is the wrong property for
# what this is trying to do. Six failed logins in five minutes is a rounding error on a jump
# host that sees four hundred a day, and the most interesting thing that has happened this
# month on an appliance that has never seen one. Scoring them alike is how a queue fills with
# one person's daily mistake while the same signature on a quiet host sits below the fold.
#
# So each denominator is derived from the endpoint it is scoring, where that endpoint has
# enough history to derive one from, and stays at its fixed value where it does not. The
# history lives on the manager in /var/lib/wazuh-lab/baseline.json, is folded one completed
# window at a time by lab-dashboard-baseline, and arrives here as a plain dict. Nothing in this
# file reads it from disk or writes it back.
#
# The shape, per agent:
#
#     windows   how many completed windows have been folded in
#     samples   the last few hundred readings of each metric, oldest first
#     hours     how many of those windows fell in each hour of the day, 24 slots
#     rules     per rule id: count, first, last, and that rule's alert total per hour slot
#
# Absent, or too thin to trust, and every fixed constant stands unchanged. That is the whole of
# the warm-up rule. A baseline built from ten minutes of data is worse than no baseline, and
# the panel reports which mode it is in rather than quietly using one.
WARMUP_WINDOWS = 24

# How far above an endpoint's own normal saturates a component: three robust standard
# deviations, with the median absolute deviation scaled the usual way. Median and MAD rather
# than mean and sd so that the one afternoon somebody ran a scan does not move the reading.
ROBUST_SPREAD = 3.0
MAD_TO_SD = 1.4826

# The fixed denominators, and how far a measured one may move from each.
#
# A measured denominator may only raise the bar, never lower it, and the floor of every band
# is the fixed value for that reason. The first draft let them move both ways and it inverted
# the thing this is for: an endpoint whose ordinary traffic peaks at level 3 got a peak
# denominator of 3, so its most ordinary window sat at the top of that component's scale and
# outscored a genuinely busy window on a busy host. A baseline is entitled to say "on this
# machine that is background". It is not entitled to say "on this machine a routine level 3 is
# as bad as it gets", because what counts as serious in absolute terms is the whole reason the
# fixed constants were chosen. Quiet endpoints are handled by novelty and by routine
# suppression instead, which is the direction that reading belongs in.
#
# The ceilings are the winsorising: an endpoint whose history is thin or strange cannot drive
# a denominator somewhere absurd, so the worst a bad baseline can do is make a component two
# or three times harder to saturate.
FIXED_DENOMINATORS = {
    "model": 2.0, "peak": 15.0, "mass": 12.0, "velocity": 8.0, "breadth": 5.0, "coverage": 3.0,
}
DENOMINATOR_BOUNDS = {
    "model":    (2.0, 4.0),
    "mass":     (12.0, 36.0),
    "velocity": (8.0, 24.0),
    "breadth":  (5.0, 15.0),
}
# Peak and coverage take no measurement. Peak's denominator is already 15, the top of the
# Wazuh scale, so there is no room above it and the rule above forbids going below. Coverage
# counts stages, and only two of them are reachable from this lab's own rules, so a per
# endpoint denominator there would be fitted to the two values it can take rather than to
# anything about the endpoint.
MEASURED = (("mass", "mass"), ("velocity", "burst"), ("breadth", "distinct"))

# Novelty and routine, which are the two things a fixed constant cannot express at all. A rule
# this endpoint has barely seen counts for more than one it produces daily; a rule it produces
# daily, at about the rate it produces it at this hour, counts for less.
NOVELTY_SEEN = 3
ROUTINE_SEEN = 20
NOVELTY_BONUS = 0.25
ROUTINE_DISCOUNT = 0.35
# Under this many windows of history for an hour of the day there is no normal rate for that
# hour, so nothing in it is called routine.
ROUTINE_MIN_HOURS = 3


def _clamp(x):
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else float(x))


def _mad(values, centre):
    """Median absolute deviation. Zero for a series with no spread, which callers handle."""
    return _median([abs(v - centre) for v in values]) if values else 0.0


def _bounded(value, key):
    low, high = DENOMINATOR_BOUNDS[key]
    return low if value < low else (high if value > high else value)


def _saturation(samples, key):
    """Where an endpoint's own history puts the top of a component's scale.

    Its centre plus three robust standard deviations, held inside the band around the fixed
    constant. A series with no spread at all, which is what a run of identical quiet windows
    looks like, would otherwise return its own median and put every slightly busier window
    straight at 1.0.
    """
    if not samples:
        return FIXED_DENOMINATORS[key]
    centre = _median(samples)
    spread = _mad(samples, centre) * MAD_TO_SD
    return _bounded(centre + ROBUST_SPREAD * spread, key)


def denominators(baseline=None, threshold=None):
    """The six divisors for one endpoint, and where each of them came from.

    Returns (values, meta). meta carries the mode, the window count behind it and, per key,
    whether that number was measured on this endpoint or taken from the table above. The
    explainer prints all of it, for the same reason the weights are printed beside the score:
    a denominator with no provenance is a denominator nobody can argue with.
    """
    values = dict(FIXED_DENOMINATORS)
    source = dict((k, "fixed") for k in values)
    windows = int((baseline or {}).get("windows") or 0)
    if not baseline or windows < WARMUP_WINDOWS:
        return values, {"mode": "warming" if baseline else "fixed", "windows": windows,
                        "need": WARMUP_WINDOWS, "source": source}

    samples = baseline.get("samples") or {}
    for key, metric in MEASURED:
        got = [float(v) for v in (samples.get(metric) or [])]
        if got:
            values[key] = _saturation(got, key)
            source[key] = "measured"

    # The model term is the odd one out. Its denominator is a multiple of the model's own
    # threshold rather than a reading in the window's units, so what gets derived is the
    # multiple. An endpoint whose ordinary windows already sit near the threshold needs a
    # higher bar before the term saturates than one that never goes near it.
    probabilities = [float(v) for v in (samples.get("prob") or [])]
    if probabilities and threshold:
        centre = _median(probabilities)
        spread = _mad(probabilities, centre) * MAD_TO_SD
        values["model"] = _bounded((centre + ROBUST_SPREAD * spread) / float(threshold), "model")
        source["model"] = "measured"

    return values, {"mode": "baseline", "windows": windows, "need": WARMUP_WINDOWS,
                    "source": source}


def _rule_profile(alerts, baseline, hour):
    """Which of a window's alerts are new to the endpoint, and which are its daily traffic.

    Returns the two fractions and the rule ids behind each, so the panel can name them rather
    than assert them. Both are zero without a baseline, which is what leaves the two terms
    inert during warm-up instead of guessing.
    """
    total = len(alerts)
    if not total or not baseline:
        return 0.0, 0.0, [], []
    rules = baseline.get("rules") or {}
    hours = baseline.get("hours") or []
    this_hour = float(hours[hour]) if 0 <= hour < len(hours) else 0.0

    counts = {}
    for a in alerts:
        rid = str(a.get("ruleId"))
        counts[rid] = counts.get(rid, 0) + 1

    novel, routine = 0, 0
    novel_ids, routine_ids = [], []
    for rid, occurrences in counts.items():
        entry = rules.get(rid)
        seen = int((entry or {}).get("count") or 0)
        if entry is None or seen <= NOVELTY_SEEN:
            novel += occurrences
            novel_ids.append(rid)
            continue
        if seen < ROUTINE_SEEN or this_hour < ROUTINE_MIN_HOURS:
            continue
        by_hour = entry.get("hours") or []
        usual = (float(by_hour[hour]) / this_hour) if 0 <= hour < len(by_hour) else 0.0
        # Twice the endpoint's usual rate for this hour of the day, plus one, so a rule that
        # normally fires once is not called unusual for firing twice.
        if occurrences <= 2.0 * usual + 1.0:
            routine += occurrences
            routine_ids.append(rid)
    return (novel / float(total), routine / float(total),
            sorted(novel_ids), sorted(routine_ids))


def severity(alerts, probability, threshold, baseline=None, hour=None):
    """A 0 to 100 severity for one endpoint's share of one window, with all of its working.

    Returns the score, its band, and every term it was built from: each component's raw
    reading, the denominator it was divided by and where that denominator came from, its weight
    and what it contributed, then the three multipliers. The panel renders that working in the
    explainer and the findings export prints it, because a severity number with no derivation
    attached is a number nobody can argue with, which is the wrong property.

    baseline is this endpoint's entry from lab-dashboard-baseline, or None. None is not a
    degraded mode, it is the documented one: the fixed constants stand and the two baseline
    only multipliers are exactly 1.0, so a lab on its first afternoon scores the way this file
    scored before any of it existed.

    hour is the hour of the day, 0 to 23, that the window starts in. Only routine suppression
    uses it, and only to ask what this endpoint normally does at this time of day.
    """
    a = sorted(alerts, key=lambda x: x.get("at", 0.0))
    n = len(a)
    levels = [float(x.get("level") or 0) for x in a]
    peak = max(levels) if levels else 0.0

    # Severity mass, doubling every two levels above 7. A single level 12 outweighs a dozen
    # level 7s, which is the ordering a human would give them.
    mass = sum(2.0 ** ((L - 7.0) / 2.0) for L in levels if L >= 7.0)

    times = [float(x.get("at", 0.0)) for x in a]
    burst, right = 0, 0
    for left, t in enumerate(times):
        while right < len(times) and times[right] < t + 60.0:
            right += 1
        burst = max(burst, right - left)

    distinct = len({x.get("ruleId") for x in a})

    tactics = set()
    for x in a:
        for t in (x.get("tactics") or []):
            if t:
                tactics.add(str(t).strip().lower())

    persistent = any("persistence" in t for t in tactics) or \
        any(int(x.get("ruleId") or 0) in PERSISTENCE_RULES for x in a)
    credential = any("credential" in t for t in tactics) or \
        any(int(x.get("ruleId") or 0) in CREDENTIAL_RULES for x in a)

    # Coverage counts stages, not ATT&CK strings. A window whose alerts carry no tactic but
    # whose rule ids say credential access and persistence has covered two stages, and counting
    # zero there would state the opposite of what the two lines above just concluded.
    stages = set(tactics)
    if credential:
        stages.add("credential access")
    if persistent:
        stages.add("persistence")

    raw = {
        "model": probability,
        "peak": peak,
        "mass": mass,
        "velocity": float(burst),
        "breadth": float(distinct),
        "coverage": float(len(stages)),
    }
    # A denominator is the point at which a component counts as saturated, and four of the six
    # are this endpoint's own numbers once it has been watched long enough. Velocity keeps its
    # second term as well, scaling with the window's own volume so that a busy interval does
    # not sit permanently at 1.0 whatever the baseline says.
    den, meta = denominators(baseline, threshold)
    norm = {
        "model": _clamp(probability / (den["model"] * threshold)) if threshold > 0 else 0.0,
        "peak": _clamp((peak / den["peak"]) ** 1.2),
        "mass": _clamp(mass / den["mass"]),
        "velocity": _clamp(burst / max(den["velocity"], 0.5 * n)) if n else 0.0,
        "breadth": _clamp((distinct - 1) / den["breadth"]),
        "coverage": _clamp(len(stages) / den["coverage"]),
    }

    base = 100.0 * sum(w * norm[k] for k, w, _ in SEVERITY_WEIGHTS)
    chained = persistent and credential
    chain = 1.0 + CHAIN_BONUS * (0.5 + 0.5 * norm["coverage"]) if chained else 1.0

    # Only once the baseline is warm. Novelty and routine both read the endpoint's rule
    # history, and a rule history twenty windows deep says a rule is new to the endpoint when
    # what it means is that nobody has been watching for long. Warm-up has to gate the whole
    # adaptive layer or it gates none of it.
    novel_share, routine_share, novel_ids, routine_ids = _rule_profile(
        a, baseline if meta["mode"] == "baseline" else None,
        hour if hour is not None else -1)
    novelty = 1.0 + NOVELTY_BONUS * novel_share
    # A chain is never routine. Both halves of a credential access and persistence pair can be
    # signatures the endpoint produces every day while the pair is not, so the discount is
    # withheld from precisely the thing this lab exists to catch rather than applied to it.
    routine = 1.0 if chained else 1.0 - ROUTINE_DISCOUNT * routine_share
    total = min(100.0, base * chain * novelty * routine)

    band = "informational"
    for floor, name in BANDS:
        if total >= floor:
            band = name
            break

    return {
        "score": round(total, 1),
        "band": band,
        "base": round(base, 2),
        "chain": round(chain, 4),
        "chained": bool(chained),
        "novelty": round(novelty, 4),
        "routine": round(routine, 4),
        "novelShare": round(novel_share, 4),
        "routineShare": round(routine_share, 4),
        "novelRules": novel_ids,
        "routineRules": routine_ids,
        "baselineMode": meta["mode"],
        "baselineWindows": meta["windows"],
        "baselineNeeds": meta["need"],
        "persistence": bool(persistent),
        "credentialAccess": bool(credential),
        "tactics": sorted(tactics),
        "stages": sorted(stages),
        "components": [
            {"key": k, "weight": w, "label": label,
             "raw": round(raw[k], 4), "value": round(norm[k], 4),
             "denominator": round(den[k], 4), "source": meta["source"][k],
             "contribution": round(100.0 * w * norm[k], 2)}
            for k, w, label in SEVERITY_WEIGHTS
        ],
    }


def severity_by_agent(alerts, probability, threshold, baselines=None, hour=None, model=None):
    """The worst any one endpoint in a window looks, with the working for each of them.

    A window is a slice of time, not a slice of one machine, and it used to be scored as though
    it were one machine. Credential access on the jump host and a new account on the file
    server earned the same chain multiplier as both happening on the same box, which is the one
    reading that multiplier is not entitled to make.

    Splitting first is also what gives each endpoint its own baseline, which is the point of
    having one. A window whose alerts carry no agent name, which is what a fabricated test case
    and an older manager both produce, is a single slice under the empty name and scores
    exactly as it did before any of this.

    model, when given, is used to score each slice on its own rather than handing every slice
    the window's probability. That matters because the model denominator is derived from the
    probabilities the baseline holds, and those are per endpoint: comparing a window level
    probability against a per endpoint scale would be comparing two different things. Without
    it the passed probability stands for every slice, which is what the no-model path needs.
    """
    groups = {}
    for a in alerts:
        groups.setdefault(str(a.get("agent") or ""), []).append(a)
    if not groups:
        groups[""] = []

    scored = []
    for name in sorted(groups):
        share = groups[name]
        p = score(model, features(share)) if (model and share) else probability
        one = severity(share, p, threshold, (baselines or {}).get(name), hour)
        one["agent"] = name
        one["probability"] = round(p, 4)
        scored.append(one)

    worst = dict(max(scored, key=lambda s: s["score"]))
    worst["perAgent"] = [
        {"agent": s["agent"], "score": s["score"], "band": s["band"],
         "probability": s["probability"], "alerts": len(groups[s["agent"]]),
         "chained": s["chained"], "mode": s["baselineMode"]}
        for s in sorted(scored, key=lambda s: -s["score"])
    ]
    return worst
