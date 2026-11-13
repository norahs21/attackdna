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

Three entry points:
  * `analyze`    — read-only. Runs the whole chain and returns the result
    without writing anything, so a user can see what would be stored before
    storing it.
  * `contribute` — the security team's consent step. Stores an incident that
    has already been analysed, from its sanitized text and DNA alone, in the
    shared memory other organisations recall from. The raw report is not an
    input, so it cannot be stored by mistake.
  * `ingest`     — analyze + persist in one call, used for loading corpora.

The privacy check is a gate, not a label. If the self-check still finds an
identifier, the text is not sent to the optional LLM and it cannot be
contributed to shared memory.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from app.config import SIMILARITY_TOP_K
from app.db.database import IncidentDB, MitigationDB
from app.services import llm_client, vector_memory
from app.services.contributors import pseudonym
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
    viewer_ref: Optional[str] = None,
) -> dict:
    """Run the full pipeline without persisting anything.

    `viewer_ref` is the analysing organisation's pseudonym, used only to mark
    which recalled incidents are its own.
    """
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

    # --- Privacy gate ---
    # Text that failed the check never leaves the machine. The rule-based path
    # still runs, so the analyst gets an answer either way.
    llm_blocked = bool(use_llm and leaks)
    use_llm = use_llm and not leaks

    # --- Stage 2: Attack DNA (+ MITRE ATT&CK, + CISA KEV) ---
    dna = extract_dna(sanitized.sanitized_text, sanitized.counts, use_llm=use_llm)

    # --- Stage 3: Vector Memory ---
    similar = find_similar_incidents(session, dna, top_k=top_k, viewer_ref=viewer_ref)

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
            "llm_blocked_by_privacy_gate": llm_blocked,
            "shareable": not leaks,
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
    incident = _persist(
        session, result,
        title=title, source=source, provenance=provenance, occurred_at=occurred_at,
        mitigations=mitigations, raw_text=raw_text if store_raw else None,
        source_name=source_name, source_url=source_url, why_it_matters=why_it_matters,
    )
    result["incident"] = incident.to_dict()
    result["incident_id"] = incident.id
    return result


class PrivacyGateError(ValueError):
    """Raised when an incident that failed the privacy check is offered for sharing."""


def contribute(
    session: Session,
    result: dict,
    organisation: Optional[str] = None,
    mitigations: Optional[List[dict]] = None,
) -> dict:
    """Add an analysed incident to shared memory, with the team's approval.

    Takes the output of `analyze`, never the raw report. What is stored is the
    sanitized text, the Attack DNA and the actions the team chose to share;
    the organisation is kept only as a keyed pseudonym (see contributors.py).

    The privacy check is run again here rather than trusted from `result`, so
    a result edited between analysis and approval cannot slip through.
    Free-text mitigation fields are sanitized too: they are written by the
    same people who wrote the report, and can name the same things.
    """
    sanitized_text = result["privacy"]["sanitized_text"]
    residual = verify_clean(sanitized_text)
    if residual:
        raise PrivacyGateError(
            "This incident cannot be shared: the privacy check still finds "
            f"{len(residual)} identifying value(s) in the sanitized text."
        )

    cleaned_mitigations = []
    for mitigation in mitigations or []:
        action = sanitize(str(mitigation.get("action", ""))).sanitized_text.strip()
        if not action:
            continue
        notes = mitigation.get("notes")
        cleaned_mitigations.append({
            "action": action,
            "category": mitigation.get("category") or "contain",
            "effectiveness": mitigation.get("effectiveness"),
            "notes": sanitize(str(notes)).sanitized_text.strip() if notes else None,
        })

    # Sharing the same incident twice would make it count twice in every
    # recall ranking and in every "used in N past incidents" tally.
    contributor_ref = pseudonym(organisation)
    duplicate = (session.query(IncidentDB)
                 .filter(IncidentDB.provenance == "shared",
                         IncidentDB.embedding_text == result["dna"]["embedding_text"],
                         IncidentDB.sanitized_text == sanitized_text)
                 .all())
    for existing in duplicate:
        if existing.contributor_ref == contributor_ref:
            return {"incident_id": existing.id, "title": existing.title,
                    "already_shared": True,
                    "shared": {"sanitized_text": True, "attack_dna": True,
                               "mitigations": len(existing.mitigations)},
                    "withheld": ["original report", "organisation name",
                                 "removed identifiers", "date of the incident"]}

    # Timing can identify a victim as surely as a name ("the hospital hit last
    # Tuesday"), so shared records carry the month they were shared, not the
    # moment, and their title carries no date at all.
    month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    incident = _persist(
        session, result,
        title=_shared_title(result["dna"]), source="shared", provenance="shared",
        occurred_at=None, mitigations=cleaned_mitigations, raw_text=None,
        contributor_ref=contributor_ref, shared_at=month, created_at=month,
    )
    return {
        "incident_id": incident.id,
        "title": incident.title,
        "already_shared": False,
        "shared": {
            "sanitized_text": True,
            "attack_dna": True,
            "mitigations": len(cleaned_mitigations),
        },
        "withheld": ["original report", "organisation name", "removed identifiers",
                     "date of the incident"],
    }


def _persist(
    session: Session,
    result: dict,
    *,
    title: Optional[str],
    source: str,
    provenance: str,
    occurred_at: Optional[datetime],
    mitigations: Optional[List[dict]],
    raw_text: Optional[str],
    source_name: Optional[str] = None,
    source_url: Optional[str] = None,
    why_it_matters: Optional[str] = None,
    contributor_ref: Optional[str] = None,
    shared_at: Optional[datetime] = None,
    created_at: Optional[datetime] = None,
) -> IncidentDB:
    """Write one analysed incident to the database, then to vector memory."""
    dna = result["dna"]
    incident = IncidentDB(
        title=title or _derive_title(dna),
        source=source,
        provenance=provenance,
        source_name=source_name,
        source_url=source_url,
        why_it_matters=why_it_matters,
        contributor_ref=contributor_ref,
        shared_at=shared_at,
        occurred_at=occurred_at,
        raw_text=raw_text,
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
    if created_at is not None:
        incident.created_at = created_at
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
    return incident


def _shared_title(dna: dict) -> str:
    attack = dna["attack_type"].replace("_", " ").title()
    vector = (dna.get("initial_vector") or "unknown")
    via = (f" via {vector.replace('_', ' ')}"
           if vector not in ("unknown", dna["attack_type"]) else "")
    sector = dna["sector"]
    where = f" — {sector.title()} sector" if sector != "unknown" else ""
    return f"{attack}{via}{where}"


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
