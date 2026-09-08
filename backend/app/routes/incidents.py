"""Incident endpoints: analyze, ingest, browse."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.database import IncidentDB, MitigationDB, get_session
from app.models.schemas import (
    AnalyzeRequest, IngestRequest, MitigationAppendRequest, SanitizeRequest,
)
from app.pipelines.analyze import analyze, ingest, reindex_memory
from app.services import vector_memory
from app.services.sanitizer import sanitize, verify_clean

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.post("/sanitize", summary="Privacy Layer only")
def sanitize_only(request: SanitizeRequest):
    """Redact an incident report without analysing or storing it.

    Exposed on its own so the privacy claim can be demonstrated in isolation.
    """
    result = sanitize(request.text)
    leaks = verify_clean(result.sanitized_text)
    return {
        "sanitized_text": result.sanitized_text,
        "redactions_by_type": result.counts,
        "total_redactions": result.total_redactions,
        "audit": result.audit_rows(),
        "verified_clean": not leaks,
        "residual_findings": leaks,
    }


@router.post("/analyze", summary="Run the full pipeline without storing anything")
def analyze_incident(request: AnalyzeRequest, session: Session = Depends(get_session)):
    return analyze(
        session,
        request.text,
        top_k=request.top_k,
        use_llm=request.use_llm,
        include_simulation=request.include_simulation,
    )


@router.post("/", status_code=201, summary="Analyze and commit an incident to memory")
def create_incident(request: IngestRequest, session: Session = Depends(get_session)):
    return ingest(
        session,
        request.text,
        title=request.title,
        source=request.source,
        occurred_at=request.occurred_at,
        mitigations=[m.model_dump() for m in request.mitigations],
        store_raw=request.store_raw,
        use_llm=request.use_llm,
        top_k=request.top_k,
    )


@router.get("/", summary="List stored incidents")
def list_incidents(
    session: Session = Depends(get_session),
    attack_type: Optional[str] = None,
    sector: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = session.query(IncidentDB)
    if attack_type:
        query = query.filter(IncidentDB.attack_type == attack_type)
    if sector:
        query = query.filter(IncidentDB.sector == sector)
    if severity:
        query = query.filter(IncidentDB.severity == severity)

    total = query.count()
    rows = (
        query.order_by(IncidentDB.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "incidents": [incident.to_dict() for incident in rows],
    }


@router.get("/{incident_id}", summary="Fetch one incident")
def get_incident(incident_id: str, session: Session = Depends(get_session)):
    incident = session.get(IncidentDB, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident.to_dict()


@router.post("/{incident_id}/mitigations", status_code=201,
             summary="Record what was done about an incident")
def add_mitigations(
    incident_id: str,
    request: MitigationAppendRequest,
    session: Session = Depends(get_session),
):
    """Close the learning loop: today's response becomes tomorrow's recall."""
    incident = session.get(IncidentDB, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    start = len(incident.mitigations)
    for offset, mitigation in enumerate(request.mitigations):
        incident.mitigations.append(MitigationDB(
            action=mitigation.action,
            category=mitigation.category,
            effectiveness=mitigation.effectiveness,
            notes=mitigation.notes,
            position=start + offset,
        ))
    session.commit()
    return incident.to_dict()


@router.delete("/{incident_id}", summary="Delete an incident and forget it")
def delete_incident(incident_id: str, session: Session = Depends(get_session)):
    incident = session.get(IncidentDB, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    session.delete(incident)
    session.commit()
    vector_memory.forget(incident_id)
    return {"deleted": incident_id}


@router.post("/reindex", summary="Rebuild vector memory from the database")
def reindex(session: Session = Depends(get_session)):
    return reindex_memory(session)
