"""Guidance for a team in the middle of an incident: "Ask the memory".

The team describes what has happened so far. That description goes through the
same pipeline as a report (privacy layer, Attack DNA, similar incidents,
mitigation memory), and this module turns the result into three answers, all
taken from what memory holds:

    what_worked   response actions that worked in similar past incidents
    same_entry    past attackers who got in the same way, and what they did
    next_steps    what attackers did next in those incidents, after the
                  furthest point this attack has reached so far

`next_steps` is a record of what happened in similar past incidents, not a
prediction: it says how many of them went on to each later stage, and nothing
more. That keeps it in line with the rest of the system (resemblance, never
attribution) and means every line on screen can be traced to an incident.

Pure functions over plain dicts: no database, no model, easy to test.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List

from app.services.knowledge_base import TACTIC_LABELS, TACTIC_ORDER

UNKNOWN_VECTORS = {None, "", "unknown"}


def _rank(tactic: str) -> int:
    return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else -1


def _label(tactic: str) -> str:
    return TACTIC_LABELS.get(tactic, tactic.replace("-", " ").title())


def _chain(tactics: List[str]) -> List[str]:
    """Tactics in kill-chain order, labelled, unknown ones dropped."""
    return [_label(t) for t in sorted({t for t in tactics if _rank(t) >= 0}, key=_rank)]


def what_worked(mitigations: dict, limit: int = 5) -> List[dict]:
    """Actions recalled from past incidents, best first. Baseline controls only
    when memory has nothing recalled to offer."""
    recommended = mitigations.get("recommended") or []
    recalled = [a for a in recommended if a.get("origin") == "recalled"]
    chosen = recalled or [a for a in recommended if a.get("origin") == "suggested"]
    return [{
        "action": a["action"],
        "origin": a.get("origin"),
        "times_used": a.get("times_used", 0),
        "avg_effectiveness": a.get("avg_effectiveness"),
        "sources": [s.get("title") for s in a.get("sources", [])][:3],
    } for a in chosen[:limit]]


def same_entry(dna: dict, similar: List[dict], limit: int = 3) -> List[dict]:
    """Similar past incidents whose attacker got in the same way as this one."""
    vector = dna.get("initial_vector")
    if vector in UNKNOWN_VECTORS:
        return []
    matches = [m for m in similar if m.get("initial_vector") == vector][:limit]
    return [{
        "title": m["title"],
        "similarity": m["similarity"],
        "provenance": m.get("provenance"),
        "from_your_organisation": m.get("from_your_organisation", False),
        "attack_type": m.get("attack_type"),
        "chain": _chain(m.get("tactics", [])),
        "techniques": [t["name"] for t in m.get("techniques", []) if t.get("name")][:6],
        "worked": [{"action": x["action"], "effectiveness": x.get("effectiveness")}
                   for x in sorted(m.get("mitigations", []),
                                   key=lambda x: -(x.get("effectiveness") or 0))][:3],
    } for m in matches]


def next_steps(dna: dict, similar: List[dict], limit: int = 4) -> dict:
    """What attackers did after this point in similar past incidents.

    "This point" is the furthest kill-chain stage the description reaches.
    Each later stage is counted once per incident that reached it.
    """
    reached = [_rank(t) for t in dna.get("tactics", []) if _rank(t) >= 0]
    furthest = max(reached) if reached else -1
    counts: Counter = Counter()
    examples: Dict[str, List[str]] = {}
    for match in similar:
        later = {t for t in match.get("tactics", []) if _rank(t) > furthest}
        counts.update(later)
        for technique in match.get("techniques", []):
            for tactic in technique.get("tactics", []):
                if tactic in later and technique.get("name"):
                    names = examples.setdefault(tactic, [])
                    if technique["name"] not in names:
                        names.append(technique["name"])
    steps = sorted(counts.items(), key=lambda item: (-item[1], _rank(item[0])))[:limit]
    return {
        "reached": _label(TACTIC_ORDER[furthest]) if furthest >= 0 else None,
        "out_of": len(similar),
        "steps": [{"tactic": _label(tactic), "incidents": count,
                   "examples": examples.get(tactic, [])[:3]}
                  for tactic, count in sorted(steps, key=lambda item: _rank(item[0]))],
    }


def build(result: dict) -> dict:
    """All three answers from one analysis result."""
    dna, similar = result["dna"], result["similar_incidents"]
    return {
        "what_worked": what_worked(result["mitigations"]),
        "same_entry": same_entry(dna, similar),
        "next_steps": next_steps(dna, similar),
    }
