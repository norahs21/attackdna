"""What the attacker will likely do next.

Given the ATT&CK techniques seen so far in an incident, find the known attacks
that behaved most like it and report what they went on to do.

"Known attacks" are two pools:

  * MITRE ATT&CK's profiles of ~930 threat groups, malware families, tools and
    campaigns, each a list of the techniques they use;
  * the incidents in shared memory, contributed by member organisations (their
    identity is never used here, only their techniques).

How it works:

  1. The furthest kill-chain stage the incident has reached is found.
  2. The 50 most similar known attacks are found. Similarity weights each shared
     technique by how distinctive it is: sharing a rare technique says more than
     sharing PowerShell.
  3. Every technique at a LATER stage is scored by the share of those 50 attacks
     (weighted by similarity) that used it.
  4. The ten techniques almost every attack uses (command and control, tool
     transfer, obfuscation...) are left out: predicting them tells a defender
     nothing they did not already know.

If the incident already reaches the last stage (impact), there is no "next";
the same scoring then lists what similar attacks did that the report does not
mention, as steps worth hunting for.

Settings (50 neighbours, distinctiveness weighting, no popularity penalty) were
chosen on a development split of the ATT&CK profiles; the result is measured on
profiles of attackers never used in tuning (scripts/evaluate_next_step.py).
"""
from __future__ import annotations

import ast
import math
from collections import Counter
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from app.services import knowledge_base as kb

NEIGHBOURS = 50
PREDICTIONS = 3
UNIVERSAL = 10          # the most common techniques, never predicted
MIN_TECHNIQUES = 4      # profiles smaller than this say too little to compare


def family(technique_id: str) -> str:
    return technique_id.split(".")[0]


def _as_list(value) -> list:
    if isinstance(value, str):
        try:
            value = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return []
    return list(value or [])


@lru_cache(maxsize=4096)
def stages(technique_id: str) -> Tuple[int, ...]:
    """Kill-chain positions of a technique's tactics."""
    index = kb.technique_index()
    record = index.get(technique_id) or index.get(family(technique_id))
    if not record:
        return ()
    return tuple(sorted(kb.TACTIC_ORDER.index(t) for t in _as_list(record.get("tactics"))
                  if t in kb.TACTIC_ORDER))


def first_stage(technique_id: str) -> Optional[int]:
    found = stages(technique_id)
    return found[0] if found else None


def last_stage(technique_id: str) -> Optional[int]:
    found = stages(technique_id)
    return found[-1] if found else None


def techniques_of(record: dict) -> Set[str]:
    return {family(t) for t in _as_list(record.get("techniques"))
            if first_stage(t) is not None}


@lru_cache(maxsize=1)
def attack_profiles() -> Dict[str, Set[str]]:
    """ATT&CK group, software and campaign id -> its technique families."""
    profiles = {}
    for record in kb.load_groups() + kb.load_software() + kb.load_campaigns():
        found = techniques_of(record)
        if len(found) >= MIN_TECHNIQUES:
            profiles[record["id"]] = found
    return profiles


class NextStepModel:
    """Similar-attack voting over a pool of technique sets."""

    def __init__(self, pool: Sequence[Set[str]], labels: Optional[Sequence[str]] = None):
        self.pool = [set(p) for p in pool]
        self.labels = list(labels) if labels is not None else ["attack"] * len(self.pool)
        counts = Counter(t for p in self.pool for t in p)
        self.frequency = counts
        size = max(1, len(self.pool))
        self.weight = {t: (math.log(size / (1 + c)) + 1) ** 2 for t, c in counts.items()}
        self.universal = {t for t, _ in counts.most_common(UNIVERSAL)}

    def _similarity(self, observed: Set[str], profile: Set[str]) -> float:
        shared = observed & profile
        if not shared:
            return 0.0
        w = self.weight
        return (sum(w.get(t, 1.0) for t in shared)
                / math.sqrt(sum(w.get(t, 1.0) for t in observed)
                            * sum(w.get(t, 1.0) for t in profile)))

    def neighbours(self, observed: Set[str]) -> List[Tuple[float, int]]:
        scored = [(self._similarity(observed, p), i) for i, p in enumerate(self.pool)]
        scored = [s for s in scored if s[0] > 0]
        scored.sort(key=lambda s: (-s[0], s[1]))
        return scored[:NEIGHBOURS]

    def rank(self, observed: Iterable[str], after_stage: Optional[int],
             limit: int = PREDICTIONS) -> List[dict]:
        """Techniques the similar attacks used, best first.

        after_stage: only techniques that can occur after this kill-chain
        position; None means any stage (the "not in the report" mode).
        """
        observed = {family(t) for t in observed if first_stage(t) is not None}
        if not observed:
            return []
        near = self.neighbours(observed)
        total = sum(score for score, _ in near)
        if not total:
            return []
        votes: Dict[str, float] = {}
        support: Dict[str, Counter] = {}
        for score, i in near:
            for technique in self.pool[i] - observed:
                if technique in self.universal:
                    continue
                end = last_stage(technique)
                if end is None or (after_stage is not None and end <= after_stage):
                    continue
                votes[technique] = votes.get(technique, 0.0) + score
                support.setdefault(technique, Counter())[self.labels[i]] += 1
        ranked = sorted(votes, key=lambda t: (-votes[t], t))[:limit]
        return [{"technique_id": t, "likelihood": round(votes[t] / total, 3),
                 "similar_attacks": len(near), "support": dict(support[t])}
                for t in ranked]


def furthest_stage(technique_ids: Iterable[str]) -> Optional[int]:
    found = [first_stage(t) for t in technique_ids]
    found = [s for s in found if s is not None]
    return max(found) if found else None


def _memory_profiles(session) -> List[Set[str]]:
    if session is None:
        return []
    from app.db.database import IncidentDB  # local import: keeps this module light
    profiles = []
    for incident in session.query(IncidentDB).all():
        found = {family(t) for t in incident.technique_ids() if first_stage(t) is not None}
        if len(found) >= 2:
            profiles.append(found)
    return profiles


def _stop_with(technique_id: str) -> Optional[dict]:
    """The official ATT&CK mitigation that best addresses this technique.

    Mitigations are often listed against sub-techniques (T1547.001) rather than
    the parent (T1547), so the one covering the most of the family is chosen.
    """
    target = family(technique_id)
    best, best_cover = None, 0
    for mitigation in kb.load_mitigations().values():
        cover = sum(1 for t in mitigation.get("techniques", []) if family(t) == target)
        if cover > best_cover or (cover == best_cover and cover and mitigation["id"] < best["id"]):
            best, best_cover = mitigation, cover
    return {"id": best["id"], "name": best["name"]} if best else None


def predict_next_steps(technique_ids: Sequence[str], session=None,
                       limit: int = PREDICTIONS) -> dict:
    """The likely next steps for an incident, ready for the interface.

    Returns {"mode": "next" | "unreported" | "none", "after": <tactic label>,
             "steps": [...], "similar_attacks": n, "from_memory": n}.
    """
    profiles = attack_profiles()
    memory = _memory_profiles(session)
    pool = list(profiles.values()) + memory
    labels = ["attck"] * len(profiles) + ["memory"] * len(memory)
    if not pool:
        return {"mode": "none", "steps": [], "similar_attacks": 0, "from_memory": 0}
    model = NextStepModel(pool, labels)

    stage = furthest_stage(technique_ids)
    if stage is None:
        return {"mode": "none", "steps": [], "similar_attacks": 0, "from_memory": 0}
    mode = "next"
    ranked = model.rank(technique_ids, after_stage=stage, limit=limit)
    if not ranked:
        mode = "unreported"
        ranked = model.rank(technique_ids, after_stage=None, limit=limit)

    steps = []
    for item in ranked:
        described = kb.describe_technique(item["technique_id"])
        tactic = next((t for t in kb.sort_tactics(described["tactics"])
                       if kb.TACTIC_ORDER.index(t) > stage), None) if mode == "next" else None
        tactic = tactic or (kb.sort_tactics(described["tactics"]) or [""])[0]
        steps.append({
            "technique_id": item["technique_id"],
            "name": described["name"],
            "tactic": tactic,
            "tactic_label": kb.TACTIC_LABELS.get(tactic, tactic.replace("-", " ").title()),
            "likelihood": item["likelihood"],
            "seen_in_memory": item["support"].get("memory", 0),
            "stop_with": _stop_with(item["technique_id"]),
        })
    near = model.neighbours({family(t) for t in technique_ids if first_stage(t) is not None})
    return {
        "mode": mode if steps else "none",
        "after": kb.TACTIC_LABELS.get(kb.TACTIC_ORDER[stage], ""),
        "steps": steps,
        "similar_attacks": len(near),
        "from_memory": sum(1 for _, i in near if labels[i] == "memory"),
    }
