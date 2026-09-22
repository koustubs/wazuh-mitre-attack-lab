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
# Every constant here is a judgement rather than a fitted parameter, and the panel says so.
# They are in one place so that disagreeing with them is an edit rather than an argument.
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


def _clamp(x):
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else float(x))


def severity(alerts, probability, threshold):
    """A 0 to 100 severity for one window, with every term it was built from.

    Returns the score, its band, and the full working: each component's raw reading, its
    normalised value, its weight and what it contributed. The panel renders that working in
    the explainer, and the findings export prints it, because a severity number with no
    derivation attached is a number nobody can argue with, which is the wrong property.
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
    # Denominators are the point at which a component is considered saturated. Velocity scales
    # with the window's own volume so that a busy network does not sit permanently at 1.0.
    norm = {
        "model": _clamp(probability / (2.0 * threshold)) if threshold > 0 else 0.0,
        "peak": _clamp((peak / 15.0) ** 1.2),
        "mass": _clamp(mass / 12.0),
        "velocity": _clamp(burst / max(8.0, 0.5 * n)) if n else 0.0,
        "breadth": _clamp((distinct - 1) / 5.0),
        "coverage": _clamp(len(stages) / 3.0),
    }

    base = 100.0 * sum(w * norm[k] for k, w, _ in SEVERITY_WEIGHTS)
    chained = persistent and credential
    chain = 1.0 + CHAIN_BONUS * (0.5 + 0.5 * norm["coverage"]) if chained else 1.0
    total = min(100.0, base * chain)

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
        "persistence": bool(persistent),
        "credentialAccess": bool(credential),
        "tactics": sorted(tactics),
        "stages": sorted(stages),
        "components": [
            {"key": k, "weight": w, "label": label,
             "raw": round(raw[k], 4), "value": round(norm[k], 4),
             "contribution": round(100.0 * w * norm[k], 2)}
            for k, w, label in SEVERITY_WEIGHTS
        ],
    }
