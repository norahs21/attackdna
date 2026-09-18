"""Corpus-wide aggregation tests.

These numbers are read off a screen in front of an audience and served by the
API at the same time, so what matters is that they are true, that ordinal
things stay in their own order rather than being sorted by popularity, and that
an empty corpus produces an empty dashboard rather than a traceback.
"""
import pytest

from app.pipelines.analyze import ingest
from app.services import corpus_stats

RANSOMWARE = (
    "Falcon Bank reported ransomware in the finance department. A spearphishing link "
    "harvested credentials. The attacker ran encoded PowerShell, disabled the EDR agent, "
    "moved laterally over SMB shares and files were encrypted."
)

DDOS = (
    "A telecom operator experienced a distributed denial of service attack. A traffic flood "
    "targeted the subscriber portal causing an outage for five hours."
)

PHISHING = (
    "A retail chain reported a phishing campaign. Staff received a fraudulent login page "
    "and several accounts were taken over before the campaign was blocked."
)


@pytest.fixture
def corpus(clean_memory):
    session = clean_memory
    ingest(session, RANSOMWARE, title="Ransomware — finance", use_llm=False, mitigations=[
        {"action": "Isolate affected endpoints", "category": "contain", "effectiveness": 0.9},
        {"action": "Restore from offline backup", "category": "recover", "effectiveness": 0.6},
    ])
    ingest(session, DDOS, title="DDoS — telecom", use_llm=False, mitigations=[
        {"action": "Isolate affected endpoints", "category": "contain", "effectiveness": 1.0},
    ])
    ingest(session, PHISHING, title="Phishing — retail", use_llm=False, mitigations=[
        {"action": "Reset credentials for affected accounts", "category": "eradicate"},
    ])
    return session


def test_the_headline_counts_are_the_corpus(corpus):
    overview = corpus_stats.overview(corpus)

    assert overview["incidents"] == 3
    assert overview["mitigations_recorded"] == 4
    assert overview["distinct_techniques"] > 0


def test_counts_come_back_ranked_largest_first(corpus):
    sectors = corpus_stats.overview(corpus)["by_sector"]
    counts = [row["count"] for row in sectors]

    assert counts == sorted(counts, reverse=True)
    assert sum(counts) == 3


def test_severity_keeps_its_own_order_rather_than_being_ranked(corpus):
    """A chart that puts 'critical' between 'low' and 'medium' is unreadable."""
    labels = [row["label"] for row in corpus_stats.overview(corpus)["by_severity"]]
    assert labels == corpus_stats.SEVERITY_ORDER


def test_every_severity_band_is_present_even_at_zero(corpus):
    """A band that vanishes when empty makes the axis jump between runs."""
    severities = corpus_stats.overview(corpus)["by_severity"]
    assert len(severities) == len(corpus_stats.SEVERITY_ORDER)
    assert sum(row["count"] for row in severities) == 3


def test_an_action_is_scored_by_its_mean_across_incidents(corpus):
    """One action, two incidents, two different results — the average is the record."""
    actions = corpus_stats.overview(corpus)["proven_actions"]
    isolate = next(a for a in actions if a["action"] == "Isolate affected endpoints")

    assert isolate["times_used"] == 2
    assert isolate["effectiveness"] == pytest.approx(0.95)


def test_an_action_with_no_reported_effectiveness_is_not_ranked(corpus):
    """Unscored is not the same as zero, and must not be presented as a record."""
    actions = corpus_stats.overview(corpus)["proven_actions"]
    assert all(a["action"] != "Reset credentials for affected accounts" for a in actions)


def test_techniques_carry_their_names(corpus):
    techniques = corpus_stats.overview(corpus)["top_techniques"]

    assert techniques, "the corpus maps techniques, so some should be counted"
    assert all(row["label"].startswith("T") for row in techniques)
    assert any(row["name"] for row in techniques), "an ID alone is unreadable on a chart"


def test_provenance_is_reported_for_every_incident(corpus):
    provenance = corpus_stats.overview(corpus)["by_provenance"]
    assert sum(row["count"] for row in provenance) == 3


def test_an_empty_corpus_produces_an_empty_dashboard_not_a_crash(clean_memory):
    overview = corpus_stats.overview(clean_memory)

    assert overview["incidents"] == 0
    assert overview["top_techniques"] == []
    assert overview["proven_actions"] == []
    # The ordinal axis still exists, so an empty dashboard keeps its shape.
    assert [row["count"] for row in overview["by_severity"]] == [0, 0, 0, 0]


def test_the_api_serves_the_same_numbers_as_the_dashboard(corpus):
    """One implementation, so the screen and the API cannot drift apart."""
    from fastapi.testclient import TestClient

    from app.main import app

    overview = corpus_stats.overview(corpus)
    with TestClient(app) as client:
        body = client.get("/stats").json()

    assert body["incidents"] == overview["incidents"]
    assert body["by_sector"] == overview["by_sector"]
    assert body["by_severity"] == overview["by_severity"]
    assert "knowledge_base" in body and "memory" in body
