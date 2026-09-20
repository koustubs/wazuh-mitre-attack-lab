"""Turn the AIT Alert Data Set into episodes this pipeline can read.

The lab campaign answers whether rules 100100-100113 distinguish an attacker from an
administrator. It cannot answer the prior question, which is whether reading a *sequence* of
alerts beats counting them, because a night of collection produces a few hundred episodes and
the seed spread on that is wider than the effect being measured.

AIT-ADS answers that one. It is 2.29 million real Wazuh alerts from eight simulated enterprise
networks, each with a labelled multi-step attack, published under CC-BY alongside the CSET 2024
paper. The alerts are in native alerts.json form, the same records our own manager writes, so
nothing here has to invent a format.

    https://zenodo.org/records/8263181

What it is not: a test of our rules. None of 100100-100113 have a parent signature in this
data. There is no sshd brute force in any of the eight scenarios, no account creation, and no
FIM. The overlap with our vocabulary is 5501 and 5502 alone, and AIT password cracking is
offline hash cracking and WPScan rather than SSH. So this measures the method, not the lab.

Two choices below are worth knowing about.

An episode here is a fixed window of wall clock time, not a scripted run. The campaign knows
what it launched and when; AIT gives ground truth only as intervals, so the honest unit is a
tumbling window labelled by whether it overlaps one. Windows holding no alerts are not
episodes and are dropped.

The split holds out whole scenarios rather than the tail of a timeline. Each scenario is a
separate network, so a model that scores well on an unseen one has generalised rather than
learned that network noise floor. That is a harder test than the time split used on the
synthetic data, and the right one when the sources really are independent.

    python import-ait.py --zip data/ait/ait_ads.zip --labels data/ait/labels.csv
"""
from __future__ import annotations

import argparse
import bisect
import collections
import csv
import io
import json
import pathlib
import sys
import zipfile
from datetime import datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from alert_stream import Vocabulary, write_episodes

SCENARIOS = ("fox", "harrison", "russellmitchell", "santos",
             "shaw", "wardbeck", "wheeler", "wilson")


def parse_labels(path):
    """Ground truth as {scenario: [(attack, start, end), ...]}, sorted by start."""
    by = collections.defaultdict(list)
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            by[row["scenario"]].append(
                (row["attack"], float(row["start"]), float(row["end"])))
    for s in by:
        by[s].sort(key=lambda p: p[1])
    return by


class ShortRead(Exception):
    """A member ended before the central directory said it should."""


def stream_alerts(zf, scenario):
    """Yields (epoch_seconds, rule_id, level, description) for one scenario.

    Read straight out of the archive. Extracted, the eight files are 2.8 GB, and none of that
    is wanted on disk once the timestamps and rule ids are out of it.

    The byte count at the end is not paranoia. Reading these members has been seen to stop
    early with an EOFError on an archive that unzip -t passes, and a short read here would
    quietly produce a smaller dataset rather than an error. Every model downstream would then
    be measured on data nobody knew was incomplete. Counting bytes makes that loud.
    """
    info = zf.getinfo("%s_wazuh.json" % scenario)
    seen = 0
    with zf.open(info) as raw:
        for line in io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline=""):
            seen += len(line.encode("utf-8", "replace"))
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
                rule = a["rule"]
                # Stored as 2022-01-21T00:02:27.000000Z. fromisoformat takes the Z directly on
                # 3.11 and later and is far quicker than strptime at this volume.
                at = datetime.fromisoformat(a["@timestamp"]).timestamp()
                rid = int(rule["id"])
            except (ValueError, TypeError, KeyError):
                continue
            yield at, rid, int(rule.get("level", 0)), rule.get("description", "")
    if seen < info.file_size:
        raise ShortRead("%s: read %d of %d bytes" % (info.filename, seen, info.file_size))


def extract(zip_path, cache_dir, scenarios):
    """Pulls (time, rule) out of the archive once and caches it.

    Re-windowing at a different width is then instant, where re-parsing 2.8 GB of JSON is a
    few minutes every time.
    """
    import numpy as np

    cache_dir.mkdir(parents=True, exist_ok=True)
    names = {}
    for s in scenarios:
        out = cache_dir / ("%s.npz" % s)
        meta = cache_dir / ("%s.names.json" % s)
        if out.exists() and meta.exists():
            names.update({int(k): tuple(v)
                          for k, v in json.loads(meta.read_text()).items()})
            continue
        # One retry, because the short read that motivated the check has not been reproducible
        # and re-reading one member is cheaper than failing the whole import.
        for attempt in (1, 2):
            times, rules, local = [], [], {}
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    for at, rid, level, desc in stream_alerts(zf, s):
                        times.append(at)
                        rules.append(rid)
                        if rid not in local:
                            local[rid] = (desc, level)
                break
            except (ShortRead, EOFError) as exc:
                if attempt == 2:
                    raise SystemExit(
                        "%s could not be read completely: %s\nNothing was cached for it, so "
                        "re-run once the archive is sound." % (s, exc))
                print("  %-16s short read, retrying: %s" % (s, exc))
        t = np.asarray(times, dtype=np.float64)
        r = np.asarray(rules, dtype=np.int32)
        order = np.argsort(t, kind="stable")
        np.savez_compressed(out, times=t[order], rules=r[order])
        meta.write_text(json.dumps({str(k): list(v) for k, v in local.items()}))
        names.update(local)
        print("  %-16s %8d alerts, %3d signatures" % (s, len(times), len(local)))
    return names


def windows(times, rules, phases, scenario, width, max_alerts):
    """Tumbling windows of `width` seconds, labelled by overlap with a ground truth phase."""
    if len(times) == 0:
        return []
    # Anchored on the first alert rather than the epoch, so a boundary means something
    # relative to the capture rather than to 1970.
    origin = float(times[0])
    out = []
    n = len(times)
    i = idx = 0
    while i < n:
        lo = origin + width * ((float(times[i]) - origin) // width)
        hi = lo + width
        j = bisect.bisect_left(times, hi, i)
        chunk_t, chunk_r = times[i:j], rules[i:j]

        hit = [p for p in phases if p[1] < hi and p[2] > lo]

        # The tail is kept rather than the head, because persistence lands at the end of a
        # window and sequences() truncates the same way.
        if len(chunk_t) > max_alerts:
            chunk_t, chunk_r = chunk_t[-max_alerts:], chunk_r[-max_alerts:]

        out.append({
            "episodeId": "%s-%06d" % (scenario, idx),
            "episodeKind": hit[0][0] if hit else "background",
            "label": "attack" if hit else "benign",
            "source": scenario,
            "startedAt": round(lo, 3),
            "alerts": [{"at": round(float(t) - lo, 3), "ruleId": int(r)}
                       for t, r in zip(chunk_t, chunk_r)],
        })
        idx += 1
        i = j
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--zip", default="data/ait/ait_ads.zip")
    p.add_argument("--labels", default="data/ait/labels.csv")
    p.add_argument("--out", default="data/ait/episodes.jsonl")
    p.add_argument("--cache", default="data/ait/cache")
    p.add_argument("--window", type=float, default=300.0,
                   help="episode width in seconds (default 300, the lab episode scale)")
    p.add_argument("--max-alerts", type=int, default=256,
                   help="cap per episode; the busiest scenarios run thousands a minute")
    p.add_argument("--scenarios", nargs="*", default=list(SCENARIOS))
    a = p.parse_args()

    import numpy as np

    zip_path = pathlib.Path(a.zip)
    if not zip_path.exists():
        raise SystemExit(
            "Missing %s.\nDownload ait_ads.zip and labels.csv from "
            "https://zenodo.org/records/8263181 into %s" % (zip_path, zip_path.parent))

    print("Extracting (once; cached in %s)" % a.cache)
    names = extract(zip_path, pathlib.Path(a.cache), a.scenarios)
    phases = parse_labels(a.labels)

    episodes = []
    for s in a.scenarios:
        d = np.load(pathlib.Path(a.cache) / ("%s.npz" % s))
        eps = windows(d["times"], d["rules"], phases.get(s, []), s, a.window, a.max_alerts)
        episodes.extend(eps)
        atk = sum(1 for e in eps if e["label"] == "attack")
        print("  %-16s %6d episodes, %4d attack (%4.1f%%)"
              % (s, len(eps), atk, 100.0 * atk / max(len(eps), 1)))

    episodes.sort(key=lambda e: (e["source"], e["startedAt"]))

    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_episodes(out, episodes)

    # The vocabulary is written beside the data rather than hardcoded, because it belongs to
    # the dataset. features.py picks it up automatically.
    seen = sorted({al["ruleId"] for e in episodes for al in e["alerts"]})
    Vocabulary(seen, {r: names.get(r, ("", 0)) for r in seen}).save(out.with_name("vocab.json"))

    total = len(episodes)
    atk = sum(1 for e in episodes if e["label"] == "attack")
    lens = sorted(len(e["alerts"]) for e in episodes)
    print()
    print("%d episodes, %d attack (%.1f%%), %d signatures, %ds windows"
          % (total, atk, 100.0 * atk / max(total, 1), len(seen), int(a.window)))
    print("alerts per episode: median %d, p90 %d, max %d"
          % (lens[len(lens) // 2], lens[int(len(lens) * 0.9)], lens[-1]))
    print("wrote %s and %s" % (out, out.with_name("vocab.json")))


if __name__ == "__main__":
    main()
