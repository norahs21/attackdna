"""Ask the memory: what worked, who got in the same way, what came next."""
from app.services import guidance

DNA = {
    "initial_vector": "phishing",
    "tactics": ["initial-access", "execution"],
}

SIMILAR = [
    {
        "title": "Ransomware via phishing link", "similarity": 0.8, "provenance": "synthetic",
        "initial_vector": "phishing", "attack_type": "ransomware",
        "tactics": ["impact", "initial-access", "execution", "lateral-movement"],
        "techniques": [
            {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactics": ["lateral-movement"]},
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"]},
        ],
        "mitigations": [
            {"action": "Reset credentials", "effectiveness": 0.7},
            {"action": "Isolate endpoints", "effectiveness": 0.95},
        ],
    },
    {
        "title": "Exchange web shell", "similarity": 0.6, "provenance": "public",
        "initial_vector": "web_exploitation", "attack_type": "data_breach",
        "tactics": ["initial-access", "exfiltration", "impact"],
        "techniques": [{"id": "T1041", "name": "Exfiltration Over C2 Channel",
                        "tactics": ["exfiltration"]}],
        "mitigations": [],
    },
]

MITIGATIONS = {"recommended": [
    {"action": "Baseline control", "origin": "suggested", "sources": []},
    {"action": "Isolate endpoints", "origin": "recalled", "times_used": 2,
     "avg_effectiveness": 0.95, "sources": [{"title": "Ransomware via phishing link"}]},
]}


def test_what_worked_prefers_actions_recalled_from_past_incidents():
    worked = guidance.what_worked(MITIGATIONS)

    assert [w["action"] for w in worked] == ["Isolate endpoints"]
    assert worked[0]["sources"] == ["Ransomware via phishing link"]


def test_what_worked_falls_back_to_baseline_controls_when_memory_has_none():
    worked = guidance.what_worked({"recommended": MITIGATIONS["recommended"][:1]})

    assert [w["origin"] for w in worked] == ["suggested"]


def test_same_entry_keeps_only_attackers_who_got_in_the_same_way():
    entries = guidance.same_entry(DNA, SIMILAR)

    assert [e["title"] for e in entries] == ["Ransomware via phishing link"]
    entry = entries[0]
    assert entry["chain"] == ["Initial Access", "Execution", "Lateral Movement", "Impact"]
    assert entry["worked"][0]["action"] == "Isolate endpoints"


def test_same_entry_is_empty_when_the_way_in_is_unknown():
    assert guidance.same_entry({"initial_vector": "unknown", "tactics": []}, SIMILAR) == []


def test_next_steps_only_lists_stages_after_the_furthest_point_reached():
    nxt = guidance.next_steps(DNA, SIMILAR)

    assert nxt["reached"] == "Execution"
    assert nxt["out_of"] == 2
    tactics = [s["tactic"] for s in nxt["steps"]]
    assert "Initial Access" not in tactics and "Execution" not in tactics
    assert tactics == ["Lateral Movement", "Exfiltration", "Impact"]   # kill-chain order
    impact = next(s for s in nxt["steps"] if s["tactic"] == "Impact")
    assert impact["incidents"] == 2
    assert impact["examples"] == ["Data Encrypted for Impact"]


def test_next_steps_with_nothing_similar_is_empty_not_an_error():
    nxt = guidance.next_steps(DNA, [])

    assert nxt["steps"] == [] and nxt["out_of"] == 0


def test_build_returns_all_three_answers():
    result = {"dna": DNA, "similar_incidents": SIMILAR, "mitigations": MITIGATIONS}

    assert set(guidance.build(result)) == {"what_worked", "same_entry", "next_steps"}
