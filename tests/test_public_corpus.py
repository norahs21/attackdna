"""Tests for the real, publicly documented incident corpus.

This corpus exists to answer the first question anyone asks about a memory
system: where does the memory come from? So these tests protect the properties
that make that answer credible — every entry cites a source, every entry is
classified correctly by the real extractor, and provenance is never lost
between ingestion and display.
"""
import json

import pytest

from app.config import DATA_DIR
from app.db.database import IncidentDB
from app.pipelines.analyze import ingest
from app.services.dna_extractor import extract_dna
from app.services.sanitizer import sanitize, verify_clean
from app.services.similarity import find_similar_incidents

PUBLIC_PATH = DATA_DIR / "seed" / "public_incidents.json"


@pytest.fixture(scope="module")
def public_incidents():
    if not PUBLIC_PATH.exists():
        pytest.skip("public corpus not present")
    with open(PUBLIC_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)["incidents"]


# --- The corpus itself ----------------------------------------------------
def test_the_corpus_is_substantial(public_incidents):
    assert len(public_incidents) >= 8


def test_every_incident_cites_a_source(public_incidents):
    """An uncited 'real' incident is worth less than an honest synthetic one."""
    for incident in public_incidents:
        assert incident.get("source_name"), f"{incident['title']} has no source name"
        assert incident.get("source_url", "").startswith("http"), \
            f"{incident['title']} has no source URL"


def test_every_incident_records_what_was_done(public_incidents):
    for incident in public_incidents:
        mitigations = incident.get("mitigations", [])
        assert len(mitigations) >= 3, f"{incident['title']} records too few actions"
        for mitigation in mitigations:
            assert mitigation["action"]
            assert mitigation["category"] in {
                "detect", "contain", "eradicate", "recover", "harden"
            }


def test_the_corpus_covers_several_sectors_and_attack_types(public_incidents):
    """Breadth is what makes retrieval meaningful rather than a lookup table."""
    dnas = [extract_dna(sanitize(i["text"]).sanitized_text, use_llm=False)
            for i in public_incidents]
    assert len({d["sector"] for d in dnas}) >= 5
    assert len({d["attack_type"] for d in dnas}) >= 3


def test_no_public_incident_is_left_unclassified(public_incidents):
    """A real report the extractor cannot read is a bug, not a data problem."""
    for incident in public_incidents:
        dna = extract_dna(sanitize(incident["text"]).sanitized_text, use_llm=False)
        assert dna["attack_type"] != "unknown", f"{incident['title']} has no attack type"
        assert dna["sector"] != "unknown", f"{incident['title']} has no sector"
        assert dna["techniques"], f"{incident['title']} mapped to no ATT&CK techniques"
        assert dna["validation"]["valid"], dna["validation"]["problems"]


def test_public_reports_still_pass_the_privacy_check(public_incidents):
    """Public does not mean exempt: the body goes through the same redaction."""
    for incident in public_incidents:
        residual = verify_clean(sanitize(incident["text"]).sanitized_text)
        assert residual == [], f"{incident['title']} leaked: {residual}"


# --- Ingestion and provenance ---------------------------------------------
def test_provenance_survives_ingestion(clean_memory, public_incidents):
    session = clean_memory
    incident = public_incidents[0]

    result = ingest(
        session, incident["text"], title=incident["title"], use_llm=False,
        provenance="public", source_name=incident["source_name"],
        source_url=incident["source_url"], why_it_matters=incident.get("why_it_matters"),
    )
    stored = session.get(IncidentDB, result["incident_id"])

    assert stored.provenance == "public"
    assert stored.source_url == incident["source_url"]
    assert stored.to_dict()["provenance"] == "public"


def test_provenance_reaches_the_similarity_results(clean_memory, public_incidents):
    """A recalled action must always be traceable to the kind of source it came from."""
    session = clean_memory
    incident = next(i for i in public_incidents if "Norsk" in i["title"])
    ingest(session, incident["text"], title=incident["title"], use_llm=False,
           provenance="public", source_name=incident["source_name"],
           source_url=incident["source_url"], mitigations=incident["mitigations"])

    query = ("Ransomware spread across our estate and encrypted files on thousands of "
             "computers. Production lines lost IT control.")
    dna = extract_dna(sanitize(query).sanitized_text, use_llm=False)
    matches = find_similar_incidents(session, dna, top_k=3)

    assert matches, "the public incident should be retrievable"
    assert matches[0]["provenance"] == "public"
    assert matches[0]["source_url"]


def test_recalled_mitigations_carry_their_provenance(clean_memory, public_incidents):
    from app.services.mitigation_memory import recall_mitigations

    session = clean_memory
    incident = next(i for i in public_incidents if "Norsk" in i["title"])
    ingest(session, incident["text"], title=incident["title"], use_llm=False,
           provenance="public", source_name=incident["source_name"],
           source_url=incident["source_url"], mitigations=incident["mitigations"])

    query = "Ransomware encrypted files across the estate and production lines went down."
    dna = extract_dna(sanitize(query).sanitized_text, use_llm=False)
    matches = find_similar_incidents(session, dna, top_k=3)
    recalled = [m for m in recall_mitigations(matches, [t["id"] for t in dna["techniques"]])
                ["recommended"] if m["origin"] == "recalled"]

    assert recalled
    assert all(source["provenance"] == "public"
               for item in recalled for source in item["sources"])


def test_defaults_to_internal_provenance(clean_memory):
    """An incident a user uploads is theirs, not public and not synthetic."""
    session = clean_memory
    result = ingest(session, "A phishing email led to credential theft in the finance team. "
                            "The account was disabled and passwords reset.", use_llm=False)
    assert session.get(IncidentDB, result["incident_id"]).provenance == "internal"


# --- The thing this corpus is for -----------------------------------------
def test_a_new_incident_recalls_a_real_documented_breach(clean_memory, public_incidents):
    """The whole point: today's incident reaching a real past one for its lesson."""
    session = clean_memory
    for incident in public_incidents:
        ingest(session, incident["text"], title=incident["title"], use_llm=False,
               provenance="public", source_name=incident["source_name"],
               source_url=incident["source_url"], mitigations=incident["mitigations"])

    query = (
        "An attacker signed in to our remote access portal using stolen credentials. "
        "The portal did not have multi-factor authentication enabled. They moved "
        "laterally, exfiltrated data and deployed ransomware."
    )
    dna = extract_dna(sanitize(query).sanitized_text, use_llm=False)
    matches = find_similar_incidents(session, dna, top_k=5)

    assert matches, "expected recall from the public corpus"
    titles = " ".join(m["title"] for m in matches)
    # Colonial Pipeline and Change Healthcare are both MFA-gap intrusions.
    assert "Colonial" in titles or "Change Healthcare" in titles
    assert all(m["source_url"] for m in matches)
