"""API contract tests."""
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client(clean_memory):
    with TestClient(app) as test_client:
        yield test_client


REPORT = (
    "Falcon Bank reported ransomware in the finance department. A spearphishing link was "
    "emailed to sara@falconbank.sa; encoded PowerShell ran from 91.240.118.22, the EDR agent "
    "was disabled, and files were encrypted. Exploited CVE-2024-21412."
)


def test_health(client):
    assert client.get("/").json()["status"] == "ok"


def test_sanitize_endpoint_removes_identifiers_and_verifies_itself(client):
    response = client.post("/incidents/sanitize", json={"text": REPORT})
    body = response.json()

    assert response.status_code == 200
    assert "sara@falconbank.sa" not in body["sanitized_text"]
    assert body["verified_clean"] is True
    assert body["total_redactions"] > 0
    assert "CVE-2024-21412" in body["sanitized_text"]


def test_analyze_endpoint_returns_the_full_pipeline(client):
    response = client.post("/incidents/analyze",
                           json={"text": REPORT, "use_llm": False})
    body = response.json()

    assert response.status_code == 200
    assert body["dna"]["attack_type"] == "ransomware"
    assert body["simulation"]["injects"]


def test_create_list_and_fetch_incident(client):
    created = client.post("/incidents/",
                          json={"text": REPORT, "title": "API test", "use_llm": False})
    assert created.status_code == 201
    incident_id = created.json()["incident_id"]

    listing = client.get("/incidents/").json()
    assert listing["total"] == 1

    fetched = client.get(f"/incidents/{incident_id}").json()
    assert fetched["title"] == "API test"
    assert fetched["attack_type"] == "ransomware"


def test_search_endpoint_finds_a_stored_incident(client):
    client.post("/incidents/", json={"text": REPORT, "title": "Stored", "use_llm": False})

    body = client.post("/search", json={
        "text": "Our finance team was hit by ransomware after a phishing link; "
                "PowerShell ran and files were encrypted.",
        "use_llm": False,
    }).json()

    assert body["matches_found"] >= 1
    assert body["similar_incidents"][0]["title"] == "Stored"
    assert body["query_dna"]["attack_type"] == "ransomware"


def test_mitigations_can_be_appended_after_the_fact(client):
    incident_id = client.post(
        "/incidents/", json={"text": REPORT, "use_llm": False}
    ).json()["incident_id"]

    response = client.post(f"/incidents/{incident_id}/mitigations", json={
        "mitigations": [{"action": "Isolated the endpoint", "category": "contain",
                         "effectiveness": 0.9}],
    })
    assert response.status_code == 201
    assert len(response.json()["mitigations"]) == 1


def test_simulate_from_a_stored_incident(client):
    incident_id = client.post(
        "/incidents/", json={"text": REPORT, "use_llm": False}
    ).json()["incident_id"]

    body = client.post("/simulate",
                       json={"incident_id": incident_id, "use_llm": False}).json()
    assert body["simulation"]["injects"]
    assert body["simulation"]["safety_notice"]


def test_simulate_requires_text_or_incident_id(client):
    assert client.post("/simulate", json={"use_llm": False}).status_code == 400


def test_missing_incident_returns_404(client):
    assert client.get("/incidents/inc_doesnotexist").status_code == 404


def test_delete_removes_the_incident(client):
    incident_id = client.post(
        "/incidents/", json={"text": REPORT, "use_llm": False}
    ).json()["incident_id"]

    assert client.delete(f"/incidents/{incident_id}").status_code == 200
    assert client.get(f"/incidents/{incident_id}").status_code == 404


def test_stats_reports_corpus_and_knowledge_base(client):
    client.post("/incidents/", json={"text": REPORT, "use_llm": False})
    body = client.get("/stats").json()

    assert body["incidents"] == 1
    assert body["knowledge_base"]["techniques"] > 500
    assert body["knowledge_base"]["known_exploited_cves"] > 1000
    assert body["memory"]["incidents_in_memory"] == 1


def test_short_input_is_rejected(client):
    assert client.post("/incidents/analyze", json={"text": "too short"}).status_code == 422
