"""Aggregate statistics — the numbers a dashboard or a demo slide needs."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.config import LLM_MODEL
from app.db.database import IncidentDB, get_session
from app.services import llm_client, vector_memory
from app.services.knowledge_base import load_kev, load_techniques

router = APIRouter(tags=["stats"])


@router.get("/stats", summary="Corpus and knowledge-base statistics")
def stats(session: Session = Depends(get_session)):
    incidents = session.query(IncidentDB).all()

    technique_counter: Counter = Counter()
    tactic_counter: Counter = Counter()
    cve_counter: Counter = Counter()
    for incident in incidents:
        technique_counter.update(incident.technique_ids())
        tactic_counter.update(incident.get_json("tactics", []))
        cve_counter.update(incident.get_json("cves", []))

    try:
        kb = {"techniques": len(load_techniques()), "known_exploited_cves": len(load_kev())}
    except FileNotFoundError as exc:
        kb = {"error": str(exc)}

    return {
        "incidents": len(incidents),
        "total_redactions": sum(i.redaction_count or 0 for i in incidents),
        "mitigations_recorded": sum(len(i.mitigations) for i in incidents),
        "by_attack_type": dict(Counter(i.attack_type for i in incidents if i.attack_type)),
        "by_sector": dict(Counter(i.sector for i in incidents if i.sector)),
        "by_severity": dict(Counter(i.severity for i in incidents if i.severity)),
        "top_techniques": technique_counter.most_common(10),
        "top_tactics": tactic_counter.most_common(10),
        "top_cves": cve_counter.most_common(10),
        "knowledge_base": kb,
        "memory": vector_memory.memory_stats(),
        "llm": {
            "available": llm_client.is_available(),
            "model": LLM_MODEL if llm_client.is_available() else None,
            "mode": "hybrid (rules + LLM)" if llm_client.is_available() else "rule-based",
        },
    }
