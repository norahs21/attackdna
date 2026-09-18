"""The ATTACKDNA pipeline.

    Incident Report
         ↓  1. Privacy Layer          sanitizer.sanitize
    Sanitized Incident
         ↓  2. Attack DNA             dna_extractor.extract_dna
    Attack DNA  ──→ MITRE ATT&CK  ──→ CISA KEV
         ↓  3. Vector Memory          vector_memory / similarity
    Similar Incidents
         ↓  4. Mitigation Memory      mitigation_memory.recall_mitigations
    Recommended Response
         ↓  5. Safe Simulation        simulator.build_simulation
    Tabletop Exercise

Two entry points:
  * `analyze` — read-only. Runs the whole chain and returns the result without
    writing anything, so a user can see what would be stored before storing it.
  * `ingest`  — persists the sanitized incident plus its DNA and adds it to
    memory, so the next incident can learn from this one.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from app.config import SIMILARITY_TOP_K
from app.db.database import IncidentDB, MitigationDB
from app.services import llm_client, vector_memory
from app.services.dna_extractor import extract_dna
from app.services.mitigation_memory import recall_mitigations
from app.services.sanitizer import sanitize, verify_clean
from app.services.similarity import find_similar_incidents
from app.services.simulator import build_simulation


def analyze(
    session: Session,
    raw_text: str,
    top_k: int = SIMILARITY_TOP_K,
    use_llm: bool = True,
    include_simulation: bool = True,
) -> dict:
    """Run the full pipeline without persisting anything."""
    # --- Stage 1: Privacy Layer ---
    sanitized = sanitize(raw_text)
    leaks = verify_clean(sanitized.sanitized_text)

    privacy = {
        "sanitized_text": sanitized.sanitized_text,
        "redactions_by_type": sanitized.counts,
        "total_redactions": sanitized.total_redactions,
        "audit": sanitized.audit_rows(),
        "verified_clean": not leaks,
        "residual_findings": leaks,
    }

    # --- Stage 2: Attack DNA (+ MITRE ATT&CK, + CISA KEV) ---
    dna = extract_dna(sanitized.sanitized_text, sanitized.counts, use_llm=use_llm)

    # --- Stage 3: Vector Memory ---
    similar = find_similar_incidents(session, dna, top_k=top_k)

    # --- Stage 4: Mitigation Memory ---
    mitigations = recall_mitigations(similar, [t["id"] for t in dna["techniques"]])

    # --- Stage 5: Safe Simulation ---
    simulation = build_simulation(dna, use_llm=use_llm) if include_simulation else None

    return {
        "privacy": privacy,
        "dna": dna,
        "similar_incidents": similar,
        "mitigations": mitigations,
        "simulation": simulation,
        "meta": {
            "llm_available": llm_client.is_available(),
            "extraction_mode": dna.get("extraction_mode", "rule-based"),
            "memory": vector_memory.memory_stats(),
        },
    }


def ingest(
    session: Session,
    raw_text: str,
    title: Optional[str] = None,
    source: str = "upload",
    occurred_at: Optional[datetime] = None,
    mitigations: Optional[List[dict]] = None,
    store_raw: bool = False,
    use_llm: bool = True,
    top_k: int = SIMILARITY_TOP_K,
    provenance: str = "internal",
    source_name: Optional[str] = None,
    source_url: Optional[str] = None,
    why_it_matters: Optional[str] = None,
) -> dict:
    """Analyze an incident, persist it, and commit it to vector memory.

    `store_raw` defaults to False: the original report is discarded once the
    sanitized version and the DNA have been derived from it.
    """
    result = analyze(session, raw_text, top_k=top_k, use_llm=use_llm)
    dna = result["dna"]

    incident = IncidentDB(
        title=title or _derive_title(dna),
        source=source,
        provenance=provenance,
        source_name=source_name,
        source_url=source_url,
        why_it_matters=why_it_matters,
        occurred_at=occurred_at,
        raw_text=raw_text if store_raw else None,
        sanitized_text=result["privacy"]["sanitized_text"],
        attack_type=dna["attack_type"],
        initial_vector=dna.get("initial_vector"),
        sector=dna["sector"],
        severity=dna["severity"],
        signature=dna["signature"],
        summary=dna["summary"],
        root_cause=dna.get("root_cause") or None,
        extraction_mode=dna.get("extraction_mode", "rule-based"),
        redaction_count=result["privacy"]["total_redactions"],
        embedding_text=dna["embedding_text"],
    )
    incident.set_json("tactics", dna["tactics"])
    incident.set_json("techniques", dna["techniques"])
    incident.set_json("cves", dna["cves"])
    incident.set_json("cve_details", dna["cve_details"])
    incident.set_json("impacts", dna["impacts"])
    incident.set_json("ioc_classes", dna["ioc_classes"])
    incident.set_json("iocs", dna.get("iocs", {}))
    incident.set_json("attribution", dna.get("attribution", {}))

    for position, mitigation in enumerate(mitigations or []):
        incident.mitigations.append(MitigationDB(
            action=mitigation["action"],
            category=mitigation.get("category", "contain"),
            effectiveness=mitigation.get("effectiveness"),
            notes=mitigation.get("notes"),
            position=position,
        ))

    session.add(incident)
    session.commit()

    # Memory is written only after the database commit succeeds, so the two
    # stores cannot disagree about which incidents exist.
    vector_memory.remember(
        incident.id,
        dna["embedding_text"],
        {
            "attack_type": incident.attack_type,
            "initial_vector": incident.initial_vector or "unknown",
            "sector": incident.sector,
            "severity": incident.severity,
            "techniques": [t["id"] for t in dna["techniques"]],
            "signature": incident.signature,
        },
    )

    result["incident"] = incident.to_dict()
    result["incident_id"] = incident.id
    return result


def _derive_title(dna: dict) -> str:
    attack = dna["attack_type"].replace("_", " ").title()
    sector = dna["sector"]
    where = f" — {sector.title()}" if sector != "unknown" else ""
    return f"{attack}{where} ({datetime.utcnow():%Y-%m-%d})"


def reindex_memory(session: Session) -> dict:
    """Rebuild vector memory from the database.

    Needed after switching embedding backend or restoring a database, and it
    also proves the database is the system of record — memory is derived state.
    """
    vector_memory.reset_memory()
    count = 0
    for incident in session.query(IncidentDB).all():
        if not incident.embedding_text:
            continue
        vector_memory.remember(
            incident.id,
            incident.embedding_text,
            {
                "attack_type": incident.attack_type,
                "initial_vector": incident.initial_vector or "unknown",
                "sector": incident.sector,
                "severity": incident.severity,
                "techniques": incident.technique_ids(),
                "signature": incident.signature,
            },
        )
        count += 1
    return {"reindexed": count, **vector_memory.memory_stats()}
