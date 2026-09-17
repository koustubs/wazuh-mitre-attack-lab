"""Shared vocabulary and the episode grammar, in one place.

Both the synthetic generator and the real exporter have to agree on what an episode looks like
once it has become alerts, or the model trained on one will not read the other. That contract
lives here rather than being written twice.

The rule ids are the lab's own, from 04-implementation/manager/lab_rules.xml, plus the two
built-in PAM rules the standing accounts trip when they open and close a session.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- the rules

# Lab rules. 100100-100103 are the Windows side and are not reachable from a Linux campaign,
# but they stay in the vocabulary so a model trained now does not have to be re-indexed when
# Windows scenarios are added.
RULES = {
    100100: ("Windows: incorrect password", 3),
    100101: ("Windows: repeated incorrect passwords", 10),
    100102: ("Windows: account created", 6),
    100103: ("Windows: scheduled task created", 6),
    100110: ("Linux: incorrect SSH password", 3),
    100111: ("Linux: repeated incorrect SSH passwords", 10),
    100112: ("Linux: local account created", 6),
    100113: ("Linux: cron path added or modified", 6),
    5501:   ("PAM: login session opened", 3),
    5502:   ("PAM: login session closed", 3),
}

# Index 0 is reserved for padding, so every real rule is 1 or above.
PAD = 0
RULE_IDS = sorted(RULES)
RULE_TO_IX = {r: i + 1 for i, r in enumerate(RULE_IDS)}
IX_TO_RULE = {i + 1: r for i, r in enumerate(RULE_IDS)}
VOCAB = len(RULE_IDS) + 1

# The frequency rule that the whole labelling scheme is built around. Rule 100111 is
# frequency="6" timeframe="120", so six failed SSH passwords inside two minutes produce one of
# these on top of the six level 3 alerts.
COMPOSITE_RULE = 100111
COMPOSITE_THRESHOLD = 6
COMPOSITE_WINDOW = 120

LABELS = ("benign", "attack")
LABEL_TO_IX = {l: i for i, l in enumerate(LABELS)}

# Episode kinds as run-campaign.sh defines them. Kept here so a dataset can be checked against
# the generator that produced it.
EPISODE_KINDS = {
    "admin-failed-login": "benign",
    "admin-new-account": "benign",
    "admin-new-cronjob": "benign",
    "admin-provision": "benign",
    "bruteforce": "attack",
    "bruteforce-persist": "attack",
    "quiet-persist": "attack",
}


@dataclass
class Alert:
    at: float          # seconds since the campaign started
    rule_id: int

    def as_dict(self) -> dict:
        return {"at": round(self.at, 3), "ruleId": self.rule_id, "level": RULES[self.rule_id][1]}


@dataclass
class Episode:
    episode_id: str
    kind: str
    label: str
    started_at: float
    alerts: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "episodeId": self.episode_id,
            "episodeKind": self.kind,
            "label": self.label,
            "startedAt": round(self.started_at, 3),
            "alerts": [a.as_dict() for a in sorted(self.alerts, key=lambda a: a.at)],
        }


def read_episodes(path):
    """Reads an episodes.jsonl, skipping any line a power cut left half written."""
    out = []
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def write_episodes(path, episodes):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for e in episodes:
            fh.write(json.dumps(e.as_dict() if isinstance(e, Episode) else e, sort_keys=True) + "\n")
