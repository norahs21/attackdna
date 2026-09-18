"""Aggregate statistics — the numbers a dashboard or a demo slide needs."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.database import get_session
from app.services import corpus_stats, llm_client, vector_memory
from app.services.knowledge_base import (
    cti_available, load_campaigns, load_groups, load_kev, load_mitigations,
    load_software, load_techniques,
)

router = APIRouter(tags=["stats"])


@router.get("/stats", summary="Corpus and knowledge-base statistics")
def stats(session: Session = Depends(get_session)):
    """The corpus figures, plus what the system was loaded with.

    The corpus half comes from `corpus_stats.overview`, which is the same code
    the dashboard renders — so the API and the screen can never disagree about
    how many incidents are in memory.
    """
    try:
        knowledge_base = {
            "techniques": len(load_techniques()),
            "known_exploited_cves": len(load_kev()),
            "attack_mitigations": len(load_mitigations()),
            "threat_groups": len(load_groups()),
            "software": len(load_software()),
            "campaigns": len(load_campaigns()),
            "cti_available": cti_available(),
        }
    except FileNotFoundError as exc:
        knowledge_base = {"error": str(exc)}

    return {
        **corpus_stats.overview(session),
        "knowledge_base": knowledge_base,
        "memory": vector_memory.memory_stats(),
        "llm": {
            "available": llm_client.is_available(),
            "provider": llm_client.provider_name(),
            "model": llm_client.active_model() if llm_client.is_available() else None,
            "mode": "hybrid (rules + LLM)" if llm_client.is_available() else "rule-based",
        },
    }
