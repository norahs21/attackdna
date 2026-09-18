"""Memory search and simulation endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import IncidentDB, get_session
from app.models.schemas import AskRequest, SearchRequest, SimulateRequest
from app.services import rag_qa
from app.services.dna_extractor import extract_dna
from app.services.mitigation_memory import recall_mitigations
from app.services.sanitizer import sanitize
from app.services.similarity import find_similar_incidents
from app.services.simulator import build_simulation

router = APIRouter(tags=["memory"])


@router.post("/search", summary="Have we seen this attack pattern before?")
def search_memory(request: SearchRequest, session: Session = Depends(get_session)):
    """Answer the SOC's real question: is this familiar, and what worked?"""
    sanitized = sanitize(request.text)
    dna = extract_dna(sanitized.sanitized_text, sanitized.counts, use_llm=request.use_llm)
    similar = find_similar_incidents(session, dna, top_k=request.top_k)
    mitigations = recall_mitigations(similar, [t["id"] for t in dna["techniques"]])

    return {
        "query_dna": {
            "attack_type": dna["attack_type"],
            "initial_vector": dna.get("initial_vector"),
            "sector": dna["sector"],
            "severity": dna["severity"],
            "signature": dna["signature"],
            "techniques": dna["techniques"],
            "tactics": dna["tactics"],
        },
        "matches_found": len(similar),
        "similar_incidents": similar,
        "mitigations": mitigations,
    }


@router.post("/ask", summary="Ask the incident corpus a question (RAG)")
def ask_memory(request: AskRequest, session: Session = Depends(get_session)):
    """Retrieval-augmented answer over the organisation's own incidents.

    The answer is built only from retrieved incidents, every citation is
    verified against what was actually retrieved, and with no API key the same
    retrieval returns a structured digest instead.
    """
    return rag_qa.ask(session, request.question, top_k=request.top_k,
                      use_llm=request.use_llm)


@router.get("/ask/suggestions", summary="Starter questions for the memory")
def ask_suggestions():
    return {"questions": rag_qa.suggested_questions()}


@router.post("/simulate", summary="Generate a safe defensive tabletop exercise")
def simulate(request: SimulateRequest, session: Session = Depends(get_session)):
    """Build a tabletop from free text or from a stored incident's DNA."""
    if not request.text and not request.incident_id:
        raise HTTPException(status_code=400, detail="Provide either 'text' or 'incident_id'")

    if request.incident_id:
        incident = session.get(IncidentDB, request.incident_id)
        if incident is None:
            raise HTTPException(
                status_code=404, detail=f"Incident {request.incident_id} not found"
            )
        # Rebuild the minimal DNA shape the simulator needs from stored fields.
        dna = {
            "attack_type": incident.attack_type,
            "initial_vector": incident.initial_vector,
            "sector": incident.sector,
            "severity": incident.severity,
            "signature": incident.signature,
            "summary": incident.summary,
            "techniques": incident.get_json("techniques", []),
            "tactics": incident.get_json("tactics", []),
            "impacts": incident.get_json("impacts", []),
            "kev": {
                "known_exploited": [
                    c["cve"] for c in incident.get_json("cve_details", [])
                    if c.get("known_exploited")
                ],
            },
        }
        dna["kev"]["known_exploited_count"] = len(dna["kev"]["known_exploited"])
    else:
        sanitized = sanitize(request.text)
        dna = extract_dna(sanitized.sanitized_text, sanitized.counts, use_llm=request.use_llm)

    return {
        "source_incident_id": request.incident_id,
        "simulation": build_simulation(dna, use_llm=request.use_llm),
    }
