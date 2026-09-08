"""Demo-readiness checks — Phase 11 (performance) and Phase 12 (demo prep).

These are the tests that answer "will this hold up on stage?": the pipeline must
be fast enough to run live, must work with the network unplugged, and must give
the same answer every time it is run.
"""
import json
import time

import pytest

from app.config import DEMO_SCENARIOS_PATH, EVALUATION_SET_PATH
from app.pipelines.analyze import analyze, ingest
from app.services.sanitizer import sanitize, verify_clean

# Budget for one full in-process pipeline run. Generous enough not to be flaky
# on a loaded laptop, tight enough that a real regression trips it.
LATENCY_BUDGET_SECONDS = 5.0


@pytest.fixture(scope="module")
def scenarios():
    if not DEMO_SCENARIOS_PATH.exists():
        pytest.skip("demo scenarios not present")
    with open(DEMO_SCENARIOS_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)["scenarios"]


# --- Demo scenarios -------------------------------------------------------
def test_every_scenario_has_presenter_material(scenarios):
    assert len(scenarios) >= 3, "the plan calls for finance, healthcare and vulnerability scenarios"
    for scenario in scenarios:
        assert scenario["text"].strip()
        assert scenario["highlight"].strip()
        assert scenario["watch_for"], f"{scenario['id']} has no presenter notes"


def test_the_planned_scenario_types_are_present(scenarios):
    ids = {s["id"] for s in scenarios}
    assert {"financial_services", "healthcare", "vulnerability"} <= ids


def test_every_scenario_runs_end_to_end(clean_memory, scenarios):
    session = clean_memory
    for scenario in scenarios:
        result = analyze(session, scenario["text"], use_llm=False)
        assert result["dna"]["validation"]["valid"], scenario["id"]
        assert result["privacy"]["verified_clean"], scenario["id"]
        assert result["simulation"]["injects"], scenario["id"]


def test_every_scenario_is_fully_sanitized(scenarios):
    """No scenario may leak an identifier on stage."""
    for scenario in scenarios:
        residual = verify_clean(sanitize(scenario["text"]).sanitized_text)
        assert residual == [], f"{scenario['id']} leaked: {residual}"


def test_the_vulnerability_scenario_actually_hits_the_kev_catalog(clean_memory, scenarios):
    scenario = next(s for s in scenarios if s["id"] == "vulnerability")
    dna = analyze(clean_memory, scenario["text"], use_llm=False)["dna"]
    assert dna["kev"]["known_exploited_count"] >= 1
    assert dna["severity"] == "critical"


def test_the_healthcare_scenario_separates_vector_from_outcome(clean_memory, scenarios):
    scenario = next(s for s in scenarios if s["id"] == "healthcare")
    dna = analyze(clean_memory, scenario["text"], use_llm=False)["dna"]
    assert dna["attack_type"] == "ransomware"
    assert dna["initial_vector"] == "supply_chain"
    assert dna["sector"] == "healthcare"


# --- Determinism ----------------------------------------------------------
def test_the_rule_based_pipeline_is_deterministic(clean_memory, scenarios):
    """Same input, same output — the demo cannot surprise the presenter."""
    session = clean_memory
    text = scenarios[0]["text"]

    first = analyze(session, text, use_llm=False)["dna"]
    second = analyze(session, text, use_llm=False)["dna"]

    assert first["signature"] == second["signature"]
    assert first["severity"] == second["severity"]
    assert [t["id"] for t in first["techniques"]] == [t["id"] for t in second["techniques"]]


def test_repeated_runs_do_not_drift_after_ingestion(clean_memory, scenarios):
    """Running the demo several times in a row must stay stable."""
    session = clean_memory
    text = scenarios[0]["text"]
    ingest(session, text, title="Run 1", use_llm=False)

    signatures = {analyze(session, text, use_llm=False)["dna"]["signature"] for _ in range(3)}
    assert len(signatures) == 1


# --- Performance ----------------------------------------------------------
def test_a_full_pipeline_run_is_fast_enough_to_demo(clean_memory, scenarios):
    session = clean_memory
    for scenario in scenarios:
        started = time.perf_counter()
        analyze(session, scenario["text"], use_llm=False)
        elapsed = time.perf_counter() - started
        assert elapsed < LATENCY_BUDGET_SECONDS, (
            f"{scenario['id']} took {elapsed:.2f}s, budget is {LATENCY_BUDGET_SECONDS}s"
        )


def test_sanitization_alone_is_effectively_instant(scenarios):
    started = time.perf_counter()
    for scenario in scenarios:
        sanitize(scenario["text"])
    assert (time.perf_counter() - started) < 1.0


# --- Offline operation ----------------------------------------------------
def test_the_pipeline_runs_with_no_network(clean_memory, scenarios, monkeypatch):
    """Unplug the network and the demo must still work.

    Every outbound socket is blocked for the duration of this test. If any stage
    quietly depends on a network call, this fails.
    """
    import socket

    def _blocked(*args, **kwargs):
        raise OSError("network disabled for this test")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)

    result = analyze(clean_memory, scenarios[0]["text"], use_llm=False)

    assert result["privacy"]["verified_clean"]
    assert result["dna"]["techniques"]
    assert result["simulation"]["injects"]
    assert result["meta"]["extraction_mode"] == "rule-based"


# --- The labelled evaluation set --------------------------------------------
def test_the_evaluation_set_is_well_formed():
    if not EVALUATION_SET_PATH.exists():
        pytest.skip("evaluation set not present")
    with open(EVALUATION_SET_PATH, "r", encoding="utf-8") as handle:
        cases = json.load(handle)["cases"]

    assert len(cases) >= 5
    for case in cases:
        expected = case["expected"]
        assert expected["attack_type"] and expected["sector"]
        assert expected["techniques"], f"{case['id']} has no expected techniques"
        assert case["expected_similar_to"], f"{case['id']} has no retrieval target"
