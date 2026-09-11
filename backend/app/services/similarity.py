"""Similar-incident retrieval with explainable scoring.

Raw embedding distance alone is a poor answer to "have we seen this before?".
Two incidents described in similar prose can score 0.9 while sharing no actual
behaviour, and an analyst has no way to check the machine's work.

So retrieval happens in two stages:

    1. **Recall** — vector memory returns semantically nearby Attack DNA.
    2. **Re-rank** — each candidate is re-scored on *structural* overlap:
       shared ATT&CK techniques, shared tactics, same attack type, same
       initial vector, same sector, shared CVEs.

The final score is a blend of the two, and every match carries the human-
readable reasons that produced it. An analyst can disagree with a match on the
evidence shown, which is the difference between a tool and an oracle.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.config import SIMILARITY_THRESHOLD, SIMILARITY_TOP_K
from app.db.database import IncidentDB
from app.services import vector_memory

# Blend weights. Structure is weighted slightly higher than prose similarity
# because shared techniques are the claim we actually want to make.
SEMANTIC_WEIGHT = 0.45
STRUCTURAL_WEIGHT = 0.55

# Contribution of each structural signal to the structural sub-score.
STRUCTURE_WEIGHTS = {
    "techniques": 0.40,
    "tactics": 0.20,
    "attack_type": 0.18,
    "initial_vector": 0.10,
    "cves": 0.07,
    "sector": 0.05,
}


def _jaccard(left: set, right: set) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _structural_score(current: dict, candidate: dict) -> tuple:
    """Structural overlap in [0, 1], plus the reasons behind it."""
    reasons: List[str] = []
    score = 0.0

    current_techniques = {t["id"] for t in current.get("techniques", []) if isinstance(t, dict)}
    candidate_techniques = set(candidate.get("technique_ids", []))
    shared_techniques = sorted(current_techniques & candidate_techniques)
    technique_overlap = _jaccard(current_techniques, candidate_techniques)
    score += STRUCTURE_WEIGHTS["techniques"] * technique_overlap
    if shared_techniques:
        preview = ", ".join(shared_techniques[:4])
        more = f" (+{len(shared_techniques) - 4} more)" if len(shared_techniques) > 4 else ""
        reasons.append(f"{len(shared_techniques)} shared ATT&CK technique(s): {preview}{more}")

    current_tactics = set(current.get("tactics", []))
    candidate_tactics = set(candidate.get("tactics", []))
    shared_tactics = sorted(current_tactics & candidate_tactics)
    score += STRUCTURE_WEIGHTS["tactics"] * _jaccard(current_tactics, candidate_tactics)
    if len(shared_tactics) >= 2:
        reasons.append(f"Overlapping kill-chain phases: {', '.join(shared_tactics[:4])}")

    if current.get("attack_type") and current["attack_type"] == candidate.get("attack_type"):
        score += STRUCTURE_WEIGHTS["attack_type"]
        reasons.append(f"Same attack type: {current['attack_type'].replace('_', ' ')}")

    if (current.get("initial_vector") not in (None, "unknown")
            and current.get("initial_vector") == candidate.get("initial_vector")):
        score += STRUCTURE_WEIGHTS["initial_vector"]
        reasons.append(f"Same initial vector: {current['initial_vector'].replace('_', ' ')}")

    shared_cves = sorted(set(current.get("cves", [])) & set(candidate.get("cves", [])))
    if shared_cves:
        score += STRUCTURE_WEIGHTS["cves"]
        reasons.append(f"Same vulnerability exploited: {', '.join(shared_cves[:3])}")

    if (current.get("sector") not in (None, "unknown")
            and current.get("sector") == candidate.get("sector")):
        score += STRUCTURE_WEIGHTS["sector"]
        reasons.append(f"Same sector: {current['sector']}")

    return min(1.0, score), reasons, shared_techniques, shared_tactics


def _candidate_from_incident(incident: IncidentDB) -> dict:
    return {
        "attack_type": incident.attack_type,
        "initial_vector": incident.initial_vector,
        "sector": incident.sector,
        "tactics": incident.get_json("tactics", []),
        "technique_ids": incident.technique_ids(),
        "cves": incident.get_json("cves", []),
    }


def find_similar_incidents(
    session: Session,
    dna: dict,
    top_k: int = SIMILARITY_TOP_K,
    exclude_id: Optional[str] = None,
    threshold: float = SIMILARITY_THRESHOLD,
) -> List[Dict]:
    """Return past incidents that resemble this Attack DNA, best match first."""
    # Recall stage: over-fetch so re-ranking has real choices to make.
    candidates = vector_memory.find_similar(
        dna["embedding_text"],
        top_k=max(top_k * 3, 10),
        exclude_id=exclude_id,
        threshold=0.0,
    )
    if not candidates:
        return []

    incident_ids = [c["incident_id"] for c in candidates]
    incidents = {
        incident.id: incident
        for incident in session.query(IncidentDB).filter(IncidentDB.id.in_(incident_ids)).all()
    }

    results: List[Dict] = []
    for candidate in candidates:
        incident = incidents.get(candidate["incident_id"])
        if incident is None:
            # In memory but not in the database — a stale vector entry.
            continue

        structural, reasons, shared_techniques, shared_tactics = _structural_score(
            dna, _candidate_from_incident(incident)
        )
        semantic = candidate["similarity"]
        combined = SEMANTIC_WEIGHT * semantic + STRUCTURAL_WEIGHT * structural

        results.append({
            "incident_id": incident.id,
            "title": incident.title,
            "provenance": incident.provenance,
            "source_name": incident.source_name,
            "source_url": incident.source_url,
            "why_it_matters": incident.why_it_matters,
            "occurred_at": incident.occurred_at.isoformat() if incident.occurred_at else None,
            "similarity": round(combined, 4),
            "semantic_similarity": round(semantic, 4),
            "structural_similarity": round(structural, 4),
            "match_reasons": reasons or ["Similar behavioural description"],
            "shared_techniques": shared_techniques,
            "shared_tactics": shared_tactics,
            "attack_type": incident.attack_type,
            "initial_vector": incident.initial_vector,
            "sector": incident.sector,
            "severity": incident.severity,
            "signature": incident.signature,
            "summary": incident.summary,
            "root_cause": incident.root_cause,
            "cves": incident.get_json("cves", []),
            "mitigations": [m.to_dict() for m in incident.mitigations],
        })

    results.sort(key=lambda r: -r["similarity"])
    return [r for r in results if r["similarity"] >= threshold][:top_k]
