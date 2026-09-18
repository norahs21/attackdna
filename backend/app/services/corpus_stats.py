"""What the memory holds, in aggregate.

Every other service answers a question about *one* incident. This one answers
the question a room full of people actually asks first — "what does this system
know?" — and it is the only place that reads the corpus as a whole.

It lives in `services/` rather than in the dashboard because the same numbers
are served by `/stats`: the API and the UI must never be able to disagree about
how many incidents are in memory, and the only way to guarantee that is for
there to be one implementation.

Counts come back as ordered lists of `{label, count}` rather than dicts, because
every consumer needs them sorted and Python dict ordering is an accident of
insertion, not a promise about magnitude.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app.db.database import IncidentDB
from app.services.knowledge_base import TACTIC_LABELS

# Severity is ordinal, so it is never sorted by count — a chart that puts
# "critical" between "low" and "medium" because of how many there are is
# unreadable. The kill chain has the same property, handled by TACTIC_ORDER.
SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _ranked(counter: Counter, limit: Optional[int] = None) -> List[Dict]:
    """Counts as an ordered list, largest first, ties broken alphabetically."""
    rows = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    if limit is not None:
        rows = rows[:limit]
    return [{"label": label, "count": count} for label, count in rows]


def _in_order(counter: Counter, order: Iterable[str]) -> List[Dict]:
    """Counts in a fixed order, including zeroes so the scale stays stable."""
    return [{"label": label, "count": counter.get(label, 0)} for label in order]


def _pretty(value: Optional[str]) -> str:
    return (value or "unknown").replace("_", " ")


def overview(session: Session) -> dict:
    """Everything the dashboard and /stats need, in one pass over the corpus."""
    incidents = session.query(IncidentDB).all()

    attack_types: Counter = Counter()
    initial_vectors: Counter = Counter()
    sectors: Counter = Counter()
    severities: Counter = Counter()
    provenance: Counter = Counter()
    years: Counter = Counter()
    technique_counts: Counter = Counter()
    technique_names: Dict[str, str] = {}
    tactic_counts: Counter = Counter()
    cve_counts: Counter = Counter()

    # Effectiveness is reported per incident, so an action's real track record
    # is the mean across every incident that used it — which needs both the
    # running total and the number of reports behind it.
    action_scores: Dict[str, List[float]] = defaultdict(list)
    action_uses: Counter = Counter()

    for incident in incidents:
        attack_types[_pretty(incident.attack_type)] += 1
        initial_vectors[_pretty(incident.initial_vector)] += 1
        sectors[_pretty(incident.sector)] += 1
        if incident.severity:
            severities[incident.severity] += 1
        provenance[incident.provenance or "internal"] += 1
        if incident.occurred_at:
            years[str(incident.occurred_at.year)] += 1

        for technique in incident.get_json("techniques", []):
            if not isinstance(technique, dict) or not technique.get("id"):
                continue
            technique_counts[technique["id"]] += 1
            technique_names.setdefault(technique["id"], technique.get("name", ""))

        tactic_counts.update(incident.get_json("tactics", []))
        cve_counts.update(incident.get_json("cves", []))

        for mitigation in incident.mitigations:
            action = (mitigation.action or "").strip()
            if not action:
                continue
            action_uses[action] += 1
            if mitigation.effectiveness is not None:
                action_scores[action].append(mitigation.effectiveness)

    proven_actions = [
        {
            "action": action,
            "effectiveness": sum(scores) / len(scores),
            "times_used": action_uses[action],
        }
        for action, scores in action_scores.items()
    ]
    # Effectiveness first, then evidence: an action that worked once is ranked
    # below one that worked as well twice.
    proven_actions.sort(key=lambda row: (-row["effectiveness"], -row["times_used"],
                                         row["action"]))

    return {
        "incidents": len(incidents),
        "distinct_techniques": len(technique_counts),
        "total_redactions": sum(i.redaction_count or 0 for i in incidents),
        "mitigations_recorded": sum(len(i.mitigations) for i in incidents),
        "by_provenance": _ranked(provenance),
        "by_attack_type": _ranked(attack_types),
        "by_initial_vector": _ranked(initial_vectors),
        "by_sector": _ranked(sectors),
        "by_severity": _in_order(severities, SEVERITY_ORDER),
        "by_year": sorted(
            ({"label": year, "count": count} for year, count in years.items()),
            key=lambda row: row["label"],
        ),
        "top_techniques": [
            {"label": technique_id, "name": technique_names.get(technique_id, ""),
             "count": count}
            for technique_id, count in technique_counts.most_common(10)
        ],
        "by_tactic": [
            {"label": TACTIC_LABELS.get(tactic, tactic.replace("-", " ").title()),
             "id": tactic, "count": count}
            for tactic, count in tactic_counts.most_common(12)
        ],
        "top_cves": _ranked(cve_counts, limit=10),
        "proven_actions": proven_actions[:8],
    }
