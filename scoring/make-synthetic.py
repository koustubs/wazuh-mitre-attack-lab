"""Generate a synthetic alert stream shaped like a real campaign.

This exists so the pipeline can be built and measured before a night of collection has happened,
not as a substitute for one. It mirrors run-campaign.sh's episode grammar and turns each
scenario into the alerts the lab rules would actually raise, then windows the stream the same
way export-campaign.py will window the real thing.

Numbers produced from this data say whether the code works. They say nothing about whether a
model would catch an intruder. Replace it with a real campaign before quoting any result.

    python make-synthetic.py --hours 14 --seed 1 --out data/synthetic/episodes.jsonl
"""
from __future__ import annotations

import argparse
import pathlib
import random
import secrets
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from alert_stream import (Alert, COMPOSITE_RULE, COMPOSITE_THRESHOLD, Episode, EPISODE_KINDS,
                          write_episodes)

MIN_S1_GAP = 330          # matches run-campaign.sh
STAFF = [("labstaff1", 60, 0, 48), ("labstaff2", 30, 0, 7), ("labstaff3", 10, 0, 48)]

# The same weights run-campaign.sh's pick_episode uses.
KIND_WEIGHTS = [
    ("admin-failed-login", 22), ("admin-new-account", 14), ("admin-new-cronjob", 14),
    ("admin-provision", 12), ("bruteforce", 18), ("bruteforce-persist", 12),
    ("quiet-persist", 8),
]


def plan_episode(kind, rnd):
    """One (scenario, logons, gap-to-next-step) per step. Mirrors plan_episode in the shell."""
    if kind == "admin-failed-login":
        return [("S1", rnd.randint(1, 5), 0)]
    if kind == "admin-new-account":
        return [("S2", None, 0)]
    if kind == "admin-new-cronjob":
        return [("S3", None, 0)]
    if kind == "admin-provision":
        return [("S2", None, rnd.randint(60, 300)), ("S3", None, 0)]
    if kind == "bruteforce":
        return [("S1", rnd.randint(6, 14), 0)]
    if kind == "bruteforce-persist":
        return [("S1", rnd.randint(6, 14), rnd.randint(15, 75)),
                ("S2", None, rnd.randint(15, 75)), ("S3", None, 0)]
    if kind == "quiet-persist":
        return [("S2", None, rnd.randint(10, 45)), ("S3", None, 0)]
    raise ValueError(kind)


def scenario_alerts(scenario, logons, t0, rnd):
    """The alerts one scenario run actually raises, and when the run finishes.

    S1's measured wall time was 7.5s for one failed logon and 24.3s for six, so roughly six
    seconds of setup and three per attempt. S2 measured 3.8s and S3 measured 18.2s, most of
    which is the script waiting for the audit record.
    """
    out = []
    if scenario == "S1":
        t = t0 + rnd.uniform(4.0, 7.0)
        for i in range(logons):
            out.append(Alert(t, 100110))
            # The composite fires on the attempt that crosses the threshold, not at the end.
            if i + 1 == COMPOSITE_THRESHOLD:
                out.append(Alert(t + rnd.uniform(0.05, 0.4), COMPOSITE_RULE))
            t += rnd.uniform(2.0, 3.6)
        return out, t + rnd.uniform(2.5, 3.5)
    if scenario == "S2":
        t = t0 + rnd.uniform(0.3, 1.2)
        out.append(Alert(t, 100112))
        return out, t0 + rnd.uniform(3.4, 4.4)
    if scenario == "S3":
        t = t0 + rnd.uniform(0.3, 1.5)
        out.append(Alert(t, 100113))
        return out, t0 + rnd.uniform(17.5, 19.5)
    raise ValueError(scenario)


def build(hours, seed):
    rnd = random.Random(seed)
    total = hours * 3600
    background = []
    episodes = []

    # Background first, across the whole run, so episodes land in traffic rather than silence.
    t = rnd.uniform(20, 60)
    while t < total:
        hour = int(t // 3600)
        eligible = [(n, w) for n, w, lo, hi in STAFF if lo <= hour < hi]
        if eligible:
            names = [n for n, _ in eligible]
            weights = [w for _, w in eligible]
            rnd.choices(names, weights=weights, k=1)
            background.append(Alert(t, 5501))
            background.append(Alert(t + rnd.uniform(0.2, 2.5), 5502))
        t += rnd.uniform(20, 60)

    kinds = [k for k, _ in KIND_WEIGHTS]
    weights = [w for _, w in KIND_WEIGHTS]

    t = rnd.uniform(30, 120)
    last_s1_end = -10 ** 9
    while t < total:
        kind = rnd.choices(kinds, weights=weights, k=1)[0]
        ep = Episode(secrets.token_hex(5), kind, EPISODE_KINDS[kind], t)
        cursor = t
        for scenario, logons, gap in plan_episode(kind, rnd):
            if scenario == "S1" and cursor - last_s1_end < MIN_S1_GAP:
                cursor = last_s1_end + MIN_S1_GAP
            alerts, end = scenario_alerts(scenario, logons, cursor, rnd)
            ep.alerts.extend(alerts)
            if scenario == "S1":
                last_s1_end = end
            cursor = end + gap
        ep.ended_at = cursor
        episodes.append(ep)
        t = cursor + rnd.uniform(150, 330)

    # Window each episode over the whole stream, so the background traffic that happens to fall
    # inside is part of the sample. Without this the task is trivial: every alert in the window
    # would belong to the episode itself.
    background.sort(key=lambda a: a.at)
    bg_times = [a.at for a in background]
    import bisect
    for ep in episodes:
        lo = ep.started_at - 10.0
        hi = getattr(ep, "ended_at", ep.started_at) + 60.0
        i = bisect.bisect_left(bg_times, lo)
        j = bisect.bisect_right(bg_times, hi)
        ep.alerts.extend(background[i:j])

    return episodes


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hours", type=int, default=14)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--out", default="data/synthetic/episodes.jsonl")
    a = p.parse_args()

    episodes = build(a.hours, a.seed)
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_episodes(out, episodes)

    n_alerts = sum(len(e.alerts) for e in episodes)
    attack = sum(1 for e in episodes if e.label == "attack")
    print("synthetic, seed %d, %d hours" % (a.seed, a.hours))
    print("  episodes %d  (%d attack, %d benign)" % (len(episodes), attack, len(episodes) - attack))
    print("  alerts   %d  (%.1f per episode)" % (n_alerts, n_alerts / max(len(episodes), 1)))
    print("  written  %s" % out)
    print("\nThis is synthetic. Any score measured on it describes the code, not the detection.")


if __name__ == "__main__":
    main()
