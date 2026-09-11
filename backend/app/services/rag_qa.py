"""Ask the memory — retrieval-augmented question answering over the corpus.

This is the generation half of ATTACKDNA's RAG loop. The retrieval half already
exists (`vector_memory` + `similarity`); this module lets an analyst ask the
corpus a question in plain language and get an answer built from the incidents
that were actually retrieved.

    "Have we seen double extortion in healthcare?"
    "What worked against ransomware that disabled EDR?"
    "Which sector gets hit by phishing most often?"

Three properties make the answer trustworthy rather than merely fluent:

1. **Grounded.** The model sees only the retrieved incidents and is told to
   answer from them alone. No corpus, no answer — it says so instead of
   guessing.
2. **Cited, and the citations are verified.** The model returns incident ids
   alongside its answer; ids that were not in the retrieved set are stripped
   before display and counted. A model that invents a source is caught by code,
   not by the reader.
3. **Degrades instead of failing.** With no API key the same retrieval runs and
   returns a structured digest of the matching incidents. Less fluent, equally
   true, and it works offline.

Everything the model sees is sanitized text and DNA fields, so the privacy
guarantee holds here exactly as it does everywhere else.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.db.database import IncidentDB
from app.services import llm_client, vector_memory
from app.services.knowledge_base import TACTIC_LABELS

ARABIC_RE = re.compile(r"[؀-ۿ]")

# Relevance floor for the retrieval-only path.
#
# MiniLM cosine similarity has a high floor on same-domain text: on this corpus
# a genuinely relevant incident scores 0.75-0.80 while an unrelated one still
# scores 0.66-0.70. Without a cut-off the offline path answers "have we seen a
# satellite uplink attack?" with four ransomware incidents and calls that a hit.
#
# In LLM mode no floor is applied — the model reads the incidents and says when
# they do not answer the question, which is better judgement than a threshold.
# The floor exists precisely because the offline path has no such judgement.
RELEVANCE_FLOOR = 0.73

# The embedding model is English-only, so an Arabic question retrieves poorly
# against an English corpus. When a model is available we translate the question
# into an English retrieval query first — standard RAG query rewriting, and the
# cheapest way to make the system usable in Arabic.
REWRITE_SYSTEM = """You turn a security analyst's question into an English search query.

Return ONLY JSON: {"query": "<english search query>", "language": "<ar|en>"}

The query is matched against incident records describing attack type, sector,
MITRE ATT&CK techniques, impacts and response actions. Use the vocabulary those
records would use. Do not answer the question — only rewrite it as a query."""

ANSWER_SYSTEM = """You answer questions about an organisation's past security incidents.

You are given RETRIEVED INCIDENTS from the organisation's own memory. They are
already sanitized: identifying values were replaced with tokens like
[ORG_REDACTED]. Never speculate about what a token originally was.

STRICT RULES:
- Answer ONLY from the retrieved incidents. They are your entire world.
- If they do not contain the answer, say so plainly. Do not fill the gap from
  general knowledge, and do not guess.
- Cite every claim by incident id.
- Be concrete: name techniques, effectiveness figures and outcomes where the
  incidents give them.
- Answer in the same language the question was asked in.
- Never invent an incident id. Only ids listed below exist.

Return ONLY JSON:
{
  "answer": "<your answer, 2-5 sentences, in the question's language>",
  "cited_incident_ids": ["inc_...", "..."],
  "answered_from_corpus": true|false,
  "confidence": "high"|"medium"|"low"
}

Set "answered_from_corpus" to false when the retrieved incidents do not support
an answer; then say that in "answer" and leave the citations empty."""


def _is_arabic(text: str) -> bool:
    return bool(ARABIC_RE.search(text or ""))


def _rewrite_query(question: str) -> Dict[str, str]:
    """Turn a question into an English retrieval query when we can."""
    default = {"query": question, "language": "ar" if _is_arabic(question) else "en"}

    # English questions already match the corpus vocabulary; skip the round trip.
    if not _is_arabic(question) or not llm_client.is_available():
        return default

    result = llm_client.complete_json(REWRITE_SYSTEM, question, max_tokens=300, effort="low")
    if not result or not isinstance(result.get("query"), str) or not result["query"].strip():
        return default
    return {"query": result["query"].strip(), "language": "ar"}


def _incident_context(incident: IncidentDB, similarity: float) -> str:
    """One incident rendered for the model, as compactly as stays useful."""
    techniques = ", ".join(
        f"{t['id']} {t.get('name', '')}".strip()
        for t in incident.get_json("techniques", [])[:8]
    ) or "none recorded"

    tactics = ", ".join(
        TACTIC_LABELS.get(t, t) for t in incident.get_json("tactics", [])
    ) or "none recorded"

    mitigations = incident.mitigations
    if mitigations:
        actions = "\n".join(
            f"    - [{m.category}] {m.action}"
            + (f" (effectiveness {m.effectiveness:.0%})" if m.effectiveness is not None else "")
            + (f" — {m.notes}" if m.notes else "")
            for m in mitigations[:8]
        )
    else:
        actions = "    - none recorded"

    occurred = incident.occurred_at.date().isoformat() if incident.occurred_at else "undated"
    cves = ", ".join(incident.get_json("cves", [])) or "none"

    return (
        f"INCIDENT {incident.id}\n"
        f"  Title: {incident.title}\n"
        f"  Date: {occurred} | Retrieval score: {similarity:.0%}\n"
        f"  Type: {incident.attack_type} | Entry vector: {incident.initial_vector} | "
        f"Sector: {incident.sector} | Severity: {incident.severity}\n"
        f"  Summary: {incident.summary}\n"
        f"  Kill chain: {tactics}\n"
        f"  Techniques: {techniques}\n"
        f"  Vulnerabilities: {cves}\n"
        f"  Response actions taken:\n{actions}\n"
    )


def _retrieve(session: Session, query: str, top_k: int) -> List[Dict]:
    """Vector recall, resolved against the database."""
    # Threshold 0.0: for open questions we want recall, and the model decides
    # what is relevant. Filtering here would hide evidence from it.
    matches = vector_memory.find_similar(query, top_k=top_k, threshold=0.0)
    if not matches:
        return []

    ids = [m["incident_id"] for m in matches]
    incidents = {
        incident.id: incident
        for incident in session.query(IncidentDB).filter(IncidentDB.id.in_(ids)).all()
    }

    retrieved = []
    for match in matches:
        incident = incidents.get(match["incident_id"])
        if incident is not None:
            retrieved.append({"incident": incident, "similarity": match["similarity"]})
    return retrieved


def _sources(retrieved: List[Dict]) -> List[Dict]:
    return [
        {
            "incident_id": entry["incident"].id,
            "title": entry["incident"].title,
            "attack_type": entry["incident"].attack_type,
            "sector": entry["incident"].sector,
            "severity": entry["incident"].severity,
            "occurred_at": (entry["incident"].occurred_at.date().isoformat()
                            if entry["incident"].occurred_at else None),
            "similarity": entry["similarity"],
            "summary": entry["incident"].summary,
        }
        for entry in retrieved
    ]


def _fallback_answer(question: str, relevant: List[Dict]) -> str:
    """A true, useful answer with no model involved.

    Not a placeholder: it reports exactly what retrieval found, which is the
    honest answer to "what does memory hold about this?".
    """
    if not relevant:
        return (
            "No incident in memory is a close enough match to answer this. "
            "Either the corpus does not cover it yet, or the question needs rewording. "
            "Saying so is the correct answer — the alternative is presenting "
            "loosely-related incidents as if they answered the question."
        )

    lines = [
        f"Retrieval found {len(relevant)} relevant incident(s) in memory. "
        "No language model is configured, so here is what those incidents record:",
        "",
    ]
    for entry in relevant:
        incident = entry["incident"]
        lines.append(
            f"• {incident.title} ({entry['similarity']:.0%} match) — "
            f"{incident.attack_type} via {incident.initial_vector}, "
            f"{incident.sector}, severity {incident.severity}."
        )
        top = sorted(
            incident.mitigations,
            key=lambda m: -(m.effectiveness or 0),
        )[:2]
        for mitigation in top:
            score = (f" ({mitigation.effectiveness:.0%} effective)"
                     if mitigation.effectiveness is not None else "")
            lines.append(f"    ↳ {mitigation.action}{score}")
    return "\n".join(lines)


def ask(session: Session, question: str, top_k: int = 6,
        use_llm: bool = True) -> dict:
    """Answer a question from the incident corpus, with verified citations."""
    question = (question or "").strip()
    if not question:
        return {
            "question": question,
            "answer": "Ask a question about the incidents in memory.",
            "sources": [], "citations": [], "mode": "empty",
            "answered_from_corpus": False, "unverified_citations": [],
        }

    rewritten = _rewrite_query(question) if use_llm else {
        "query": question, "language": "ar" if _is_arabic(question) else "en",
    }
    retrieved = _retrieve(session, rewritten["query"], top_k)

    base = {
        "question": question,
        "search_query": rewritten["query"],
        "language": rewritten["language"],
        "sources": _sources(retrieved),
        "retrieved_count": len(retrieved),
        "unverified_citations": [],
    }

    # --- Retrieval-only path: no key, no network, or nothing retrieved ---
    if not use_llm or not llm_client.is_available() or not retrieved:
        # Without a model to judge relevance, apply the floor (see RELEVANCE_FLOOR).
        relevant = [e for e in retrieved if e["similarity"] >= RELEVANCE_FLOOR]
        return {
            **base,
            "answer": _fallback_answer(question, relevant),
            "citations": [e["incident"].id for e in relevant],
            "sources": _sources(relevant),
            "retrieved_count": len(relevant),
            "mode": "retrieval-only",
            "answered_from_corpus": bool(relevant),
            "confidence": "medium" if relevant else "low",
        }

    # --- Grounded generation ---
    context = "\n".join(_incident_context(e["incident"], e["similarity"]) for e in retrieved)
    valid_ids = {e["incident"].id for e in retrieved}

    prompt = (
        f"RETRIEVED INCIDENTS ({len(retrieved)}):\n\n{context}\n"
        f"Valid incident ids: {', '.join(sorted(valid_ids))}\n\n"
        f"QUESTION: {question}"
    )

    result = llm_client.complete_json(ANSWER_SYSTEM, prompt, max_tokens=1500, effort="medium")

    if not result or not isinstance(result.get("answer"), str):
        return {
            **base,
            "answer": _fallback_answer(question, retrieved),
            "citations": [s["incident_id"] for s in base["sources"]],
            "mode": "retrieval-only",
            "answered_from_corpus": bool(retrieved),
            "confidence": "medium",
        }

    # Verify every citation against what was actually retrieved. An id the model
    # invented never reaches the reader.
    claimed = [c for c in result.get("cited_incident_ids", []) if isinstance(c, str)]
    citations = [c for c in claimed if c in valid_ids]
    unverified = [c for c in claimed if c not in valid_ids]

    return {
        **base,
        "answer": result["answer"].strip(),
        "citations": citations,
        "unverified_citations": unverified,
        "mode": "llm-grounded",
        "answered_from_corpus": bool(result.get("answered_from_corpus", True)),
        "confidence": result.get("confidence", "medium"),
    }


def suggested_questions() -> List[str]:
    """Starter questions for the UI, each exercising a different retrieval path."""
    return [
        "Have we seen ransomware that disabled the EDR agent before?",
        "What worked best against phishing that led to credential theft?",
        "Which incidents involved data exfiltration to cloud storage?",
        "Have we had a supply chain compromise, and how did we respond?",
        "What is our track record on restoring from backup?",
        "هل تعرضنا لهجوم فدية في القطاع المالي من قبل؟",
    ]
