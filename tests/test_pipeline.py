"""End-to-end pipeline, memory and simulation tests."""
import pytest

from app.db.database import IncidentDB
from app.pipelines.analyze import analyze, ingest, reindex_memory
from app.services import vector_memory
from app.services.simulator import build_simulation

RANSOMWARE_A = (
    "Falcon Bank reported ransomware on WKSTN-FIN-204 in the finance department. "
    "A spearphishing link was emailed to sara@falconbank.sa; the user entered credentials "
    "on a fake login page. The attacker ran encoded PowerShell from 91.240.118.22, disabled "
    "the EDR agent, moved laterally over SMB shares, deleted shadow copies and files were "
    "encrypted. Customer data was exfiltrated to cloud storage. Exploited CVE-2024-21412."
)

RANSOMWARE_B = (
    "Nile Trading Bank detected ransomware in its finance team. Initial access was a "
    "phishing link that harvested credentials. Encoded PowerShell ran on the host, the EDR "
    "agent was disabled, the attacker moved laterally over SMB shares, shadow copies were "
    "deleted and files were encrypted. Data was exfiltrated before encryption."
)

DDOS = (
    "A telecom operator experienced a distributed denial of service attack. A traffic flood "
    "targeted the subscriber portal causing an outage for five hours. No intrusion, malware "
    "or data exfiltration was identified."
)


def test_analyze_returns_every_pipeline_stage(session):
    result = analyze(session, RANSOMWARE_A, use_llm=False)
    for stage in ("privacy", "dna", "similar_incidents", "mitigations", "simulation", "meta"):
        assert stage in result


def test_analyze_does_not_persist_anything(clean_memory):
    session = clean_memory
    analyze(session, RANSOMWARE_A, use_llm=False)
    assert session.query(IncidentDB).count() == 0
    assert vector_memory.memory_stats()["incidents_in_memory"] == 0


def test_ingest_persists_the_incident_and_its_memory_entry(clean_memory):
    session = clean_memory
    result = ingest(session, RANSOMWARE_A, title="Test incident", use_llm=False)

    incident = session.get(IncidentDB, result["incident_id"])
    assert incident is not None
    assert incident.attack_type == "ransomware"
    assert incident.technique_ids()
    assert vector_memory.memory_stats()["incidents_in_memory"] == 1


def test_raw_text_is_not_stored_by_default(clean_memory):
    """The privacy promise is enforced by the schema, not by convention."""
    session = clean_memory
    result = ingest(session, RANSOMWARE_A, use_llm=False)
    incident = session.get(IncidentDB, result["incident_id"])

    assert incident.raw_text is None
    assert "sara@falconbank.sa" not in incident.sanitized_text
    assert "91.240.118.22" not in incident.sanitized_text
    assert "sara@falconbank.sa" not in (incident.embedding_text or "")


def test_raw_text_is_stored_only_on_explicit_opt_in(clean_memory):
    session = clean_memory
    result = ingest(session, RANSOMWARE_A, store_raw=True, use_llm=False)
    incident = session.get(IncidentDB, result["incident_id"])
    assert incident.raw_text == RANSOMWARE_A


def test_memory_recalls_a_similar_incident_and_explains_why(clean_memory):
    session = clean_memory
    ingest(session, RANSOMWARE_A, title="Ransomware A", use_llm=False, mitigations=[
        {"action": "Isolate affected endpoints from the network immediately",
         "category": "contain", "effectiveness": 0.95},
    ])

    result = analyze(session, RANSOMWARE_B, use_llm=False)
    assert len(result["similar_incidents"]) == 1

    match = result["similar_incidents"][0]
    assert match["title"] == "Ransomware A"
    assert match["similarity"] > 0.5
    assert match["shared_techniques"]
    assert any("shared ATT&CK technique" in r for r in match["match_reasons"])


def test_an_unrelated_incident_ranks_below_a_related_one(clean_memory):
    session = clean_memory
    ingest(session, RANSOMWARE_A, title="Ransomware A", use_llm=False)
    ingest(session, DDOS, title="DDoS", use_llm=False)

    matches = analyze(session, RANSOMWARE_B, use_llm=False)["similar_incidents"]
    assert matches[0]["title"] == "Ransomware A"
    if len(matches) > 1:
        assert matches[0]["similarity"] > matches[1]["similarity"]


def test_mitigations_are_recalled_from_past_incidents_with_citations(clean_memory):
    session = clean_memory
    ingest(session, RANSOMWARE_A, title="Ransomware A", use_llm=False, mitigations=[
        {"action": "Isolate affected endpoints from the network immediately",
         "category": "contain", "effectiveness": 0.95},
        {"action": "Restore from the most recent verified-clean offline backup",
         "category": "recover", "effectiveness": 0.8},
    ])

    result = analyze(session, RANSOMWARE_B, use_llm=False)
    recalled = [m for m in result["mitigations"]["recommended"] if m["origin"] == "recalled"]

    assert recalled, "expected at least one recalled mitigation"
    assert all(m["sources"] for m in recalled), "every recalled action must cite its source"
    assert any("Isolate affected endpoints" in m["action"] for m in recalled)


def test_baseline_controls_fill_the_gap_when_memory_is_empty(clean_memory):
    result = analyze(clean_memory, RANSOMWARE_A, use_llm=False)
    recommended = result["mitigations"]["recommended"]

    assert recommended
    assert all(m["origin"] == "suggested" for m in recommended)
    assert result["mitigations"]["recalled_count"] == 0


def test_deleting_an_incident_also_forgets_it(clean_memory):
    session = clean_memory
    result = ingest(session, RANSOMWARE_A, use_llm=False)
    incident_id = result["incident_id"]

    session.delete(session.get(IncidentDB, incident_id))
    session.commit()
    vector_memory.forget(incident_id)

    assert vector_memory.memory_stats()["incidents_in_memory"] == 0


def test_reindex_rebuilds_memory_from_the_database(clean_memory):
    session = clean_memory
    ingest(session, RANSOMWARE_A, use_llm=False)
    ingest(session, DDOS, use_llm=False)

    vector_memory.reset_memory()
    assert vector_memory.memory_stats()["incidents_in_memory"] == 0

    assert reindex_memory(session)["reindexed"] == 2
    assert vector_memory.memory_stats()["incidents_in_memory"] == 2


# --- Safe Simulation ------------------------------------------------------
FORBIDDEN_OPERATIONAL_MARKERS = [
    "powershell -e", "invoke-expression", "iex(", "certutil -urlcache", "vssadmin delete",
    "rm -rf", "curl http", "wget http", "base64 -d", "msfvenom", "nc -e", "/bin/sh",
    "cmd.exe /c", "python -c", "#!/",
]


def _all_text(node) -> str:
    if isinstance(node, str):
        return node + " "
    if isinstance(node, dict):
        return "".join(_all_text(v) for v in node.values())
    if isinstance(node, (list, tuple)):
        return "".join(_all_text(v) for v in node)
    return ""


def test_simulation_covers_the_observed_kill_chain():
    from app.services.dna_extractor import extract_dna

    dna = extract_dna(RANSOMWARE_A, use_llm=False)
    simulation = build_simulation(dna, use_llm=False)

    assert simulation["injects"]
    assert simulation["success_criteria"]
    assert simulation["headline"]["technique"].startswith("T")
    assert simulation["headline"]["recommended_controls"]

    observed = {t for t in dna["tactics"]}
    covered = {i["phase"] for i in simulation["injects"]}
    assert covered <= observed


@pytest.mark.parametrize("report", [RANSOMWARE_A, DDOS])
def test_simulation_contains_no_executable_attacker_content(report):
    """The safety boundary: defensive material only, never something runnable."""
    from app.services.dna_extractor import extract_dna

    simulation = build_simulation(extract_dna(report, use_llm=False), use_llm=False)
    text = _all_text(simulation).lower()

    for marker in FORBIDDEN_OPERATIONAL_MARKERS:
        assert marker not in text, f"simulation leaked operational content: {marker!r}"
    assert simulation["safety_notice"]


def test_simulation_is_produced_even_with_no_techniques_identified():
    from app.services.dna_extractor import extract_dna

    dna = extract_dna("A quiet week with no security events.", use_llm=False)
    simulation = build_simulation(dna, use_llm=False)
    assert simulation["title"]
    assert simulation["success_criteria"]
