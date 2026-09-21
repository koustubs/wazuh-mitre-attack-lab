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
