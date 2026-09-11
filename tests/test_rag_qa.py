"""RAG question-answering tests.

The behaviours worth protecting here are the trust properties, not the prose:
answers must stay inside the corpus, citations must be verifiable, an off-topic
question must be refused rather than answered with loosely-related incidents,
and the whole thing must work with no API key and no network.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.pipelines.analyze import ingest
from app.services import rag_qa

RANSOMWARE = (
    "Falcon Bank reported ransomware in the finance department. A spearphishing link "
    "harvested credentials from an employee. The attacker ran encoded PowerShell, disabled "
    "the EDR agent, moved laterally over SMB shares, deleted shadow copies and files were "
    "encrypted. Customer data was exfiltrated to cloud storage."
)

DDOS = (
    "A telecom operator experienced a distributed denial of service attack. A traffic flood "
    "targeted the subscriber portal causing an outage for five hours. No intrusion, malware "
    "or data exfiltration was identified."
)


@pytest.fixture
def corpus(clean_memory):
    """Two clearly different incidents, each with recorded mitigations."""
    session = clean_memory
    ingest(session, RANSOMWARE, title="Ransomware — finance", use_llm=False, mitigations=[
        {"action": "Isolate affected endpoints from the network immediately",
         "category": "contain", "effectiveness": 0.95},
        {"action": "Enable tamper protection on all endpoint security agents",
         "category": "harden", "effectiveness": 1.0, "notes": "Root cause fix"},
    ])
    ingest(session, DDOS, title="DDoS — telecom", use_llm=False, mitigations=[
        {"action": "Enable upstream scrubbing with the ISP", "category": "contain",
         "effectiveness": 0.9},
    ])
    return session


# --- Retrieval and grounding ----------------------------------------------
def test_a_relevant_question_retrieves_the_right_incident(corpus):
    result = rag_qa.ask(corpus, "Have we seen ransomware that disabled the EDR agent?",
                        use_llm=False)

    assert result["answered_from_corpus"] is True
    assert result["sources"]
    assert result["sources"][0]["title"] == "Ransomware — finance"


def test_an_off_topic_question_is_refused_rather_than_answered(corpus):
    """The failure mode that matters: loosely-related hits passed off as an answer."""
    result = rag_qa.ask(corpus, "Have we ever been hit by a satellite uplink attack?",
                        use_llm=False)

    assert result["answered_from_corpus"] is False
    assert result["sources"] == []
    assert result["citations"] == []
    assert "close enough match" in result["answer"]


def test_every_returned_source_clears_the_relevance_floor(corpus):
    result = rag_qa.ask(corpus, "What did we do about ransomware?", use_llm=False)
    for source in result["sources"]:
        assert source["similarity"] >= rag_qa.RELEVANCE_FLOOR


def test_citations_only_ever_reference_retrieved_incidents(corpus):
    result = rag_qa.ask(corpus, "What worked against ransomware?", use_llm=False)
    retrieved_ids = {s["incident_id"] for s in result["sources"]}
    assert set(result["citations"]) <= retrieved_ids
    assert result["unverified_citations"] == []


def test_an_empty_corpus_answers_honestly(clean_memory):
    result = rag_qa.ask(clean_memory, "Have we seen ransomware before?", use_llm=False)
    assert result["answered_from_corpus"] is False
    assert result["sources"] == []


def test_a_blank_question_is_handled(corpus):
    result = rag_qa.ask(corpus, "   ", use_llm=False)
    assert result["mode"] == "empty"
    assert result["sources"] == []


# --- The offline path -----------------------------------------------------
def test_the_fallback_answer_reports_real_mitigations(corpus):
    """With no model, the answer must still carry the recorded response actions."""
    result = rag_qa.ask(corpus, "What did we do about ransomware in finance?", use_llm=False)

    assert result["mode"] == "retrieval-only"
    assert "Isolate affected endpoints" in result["answer"]
    assert "%" in result["answer"], "effectiveness figures should be shown"


def test_question_answering_works_with_no_network(corpus, monkeypatch):
    import socket

    def _blocked(*args, **kwargs):
        raise OSError("network disabled for this test")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)

    result = rag_qa.ask(corpus, "Have we seen ransomware before?", use_llm=False)
    assert result["answered_from_corpus"] is True
    assert result["mode"] == "retrieval-only"


def test_arabic_is_detected_and_handled_without_a_model(corpus):
    """No key means no query rewriting — it must degrade, not crash."""
    result = rag_qa.ask(corpus, "هل تعرضنا لهجوم فدية من قبل؟", use_llm=False)
    assert result["language"] == "ar"
    assert "answer" in result


# --- Privacy --------------------------------------------------------------
def test_the_model_context_contains_no_identifiers(corpus):
    """Whatever would be sent to the LLM must already be sanitized."""
    from app.db.database import IncidentDB

    incident = corpus.query(IncidentDB).filter(
        IncidentDB.title == "Ransomware — finance"
    ).one()
    context = rag_qa._incident_context(incident, 0.9)

    assert "@" not in context.replace("—", "")
    assert "Falcon Bank" not in context


def test_suggested_questions_are_offered_in_both_languages():
    questions = rag_qa.suggested_questions()
    assert len(questions) >= 5
    assert any(rag_qa._is_arabic(q) for q in questions)


# --- API ------------------------------------------------------------------
@pytest.fixture
def client(corpus):
    with TestClient(app) as test_client:
        yield test_client


def test_ask_endpoint_returns_an_answer_with_sources(client):
    response = client.post("/ask", json={
        "question": "Have we seen ransomware that disabled the EDR agent?",
        "use_llm": False,
    })
    body = response.json()

    assert response.status_code == 200
    assert body["answered_from_corpus"] is True
    assert body["sources"]
    assert body["unverified_citations"] == []


def test_ask_endpoint_refuses_an_off_topic_question(client):
    body = client.post("/ask", json={
        "question": "Have we ever been hit by a satellite uplink attack?",
        "use_llm": False,
    }).json()
    assert body["answered_from_corpus"] is False


def test_ask_endpoint_rejects_an_empty_question(client):
    assert client.post("/ask", json={"question": ""}).status_code == 422


def test_suggestions_endpoint(client):
    body = client.get("/ask/suggestions").json()
    assert len(body["questions"]) >= 5
