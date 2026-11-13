"""What the report denies, and what MITRE's examples teach.

Two changes that came out of measuring the extractor on reports it had never
seen. It counted things the report said had *not* happened, and it was silent
about anything nobody had written a phrase for.
"""
import json
from pathlib import Path

import pytest

from app.services import example_mapper
from app.services.dna_extractor import extract_dna
from app.services.mitre_mapper import map_to_attack
from app.services.negation import negated_spans

SEED = Path(__file__).resolve().parent.parent / "data" / "seed"


def _ids(text: str) -> set:
    return {technique["id"] for technique in map_to_attack(text)["techniques"]}


# --- Negation --------------------------------------------------------------

@pytest.mark.parametrize("report,impact", [
    ("Ransomware encrypted two servers. No data was exfiltrated.", "data_exfiltrated"),
    ("The trojan was removed. There was no evidence of data theft or exfiltration.",
     "data_exfiltrated"),
    ("Password spraying hit the portal and accounts were locked as a precaution.", "data_encrypted"),
])
def test_an_impact_the_report_rules_out_is_not_recorded(report, impact):
    assert impact not in extract_dna(report, use_llm=False)["impacts"]


def test_a_denied_technique_is_not_mapped():
    report = ("A backdoor beaconed to its C2 server. No lateral movement into the "
              "control network occurred.")
    ids = _ids(report)
    assert "T1071" in ids
    assert not any(technique.startswith("T1021") for technique in ids)


def test_the_absence_of_mfa_is_not_the_technique_of_modifying_it():
    """T1556.006 is named "Multi-Factor Authentication", so matching the name
    mapped every report that mentions MFA — including its absence."""
    ids = _ids("Initial access used stolen credentials against a portal that was not "
               "protected by multi-factor authentication.")
    assert "T1556.006" not in ids
    assert "T1556.006" in _ids("The attacker disabled MFA for the service account.")


def test_a_negation_does_not_swallow_the_clause_after_it():
    """"did not block the payload and files were encrypted" still encrypted files."""
    report = "The EDR agent did not block the payload and files were encrypted."
    assert "T1486" in _ids(report)

    report = ("Initial access was through a VPN account without multi-factor "
              "authentication whose password had appeared in a credential dump.")
    assert extract_dna(report, use_llm=False)["initial_vector"] == "credential_attack"


def test_a_list_after_no_is_denied_as_a_whole():
    text = "no intrusion, malware or data exfiltration was identified."
    spans = [text[start:end] for start, end in negated_spans(text)]
    assert any("data exfiltration" in span for span in spans)


# --- Classification reads more than a keyword list -------------------------

def test_a_plural_is_still_the_phrase():
    assert "T1021.002" in _ids("They spread over SMB shares to the file servers.")
    assert "T1505.003" in _ids("Two web shells were found on the server.")


def test_a_ransomware_family_names_the_attack_without_the_word():
    dna = extract_dna("LockBit was pushed to every Windows machine through group policy.",
                      use_llm=False)
    assert dna["attack_type"] == "ransomware"


def test_a_build_pipeline_is_not_an_oil_pipeline():
    dna = extract_dna("A CI pipeline at a software company pulled a typosquatted npm package.",
                      use_llm=False)
    assert dna["sector"] == "technology"


def test_a_contained_foothold_is_not_low_severity():
    report = ("A phishing email installed a backdoor that beaconed to its C2 server. "
              "The host was isolated before any lateral movement and no data was exfiltrated.")
    assert extract_dna(report, use_llm=False)["severity"] != "low"


# --- The mapper learned from MITRE's examples ------------------------------

needs_examples = pytest.mark.skipif(
    not example_mapper.load_examples(), reason="procedure examples not processed")


@needs_examples
def test_it_finds_a_technique_no_alias_was_written_for():
    report = "The malware collected the MAC address and hostname from the victim machine."
    suggestions = example_mapper.suggest(report)
    assert suggestions, "expected a suggestion for a textbook discovery sentence"
    assert suggestions[0]["technique_id"].startswith(("T1016", "T1082"))


@needs_examples
def test_its_evidence_is_the_mitre_sentence_and_never_the_report():
    """What it attaches to the Attack DNA must be public text."""
    marker = "ZUBAIRCORP"
    report = f"The implant on {marker} collected the MAC address from the victim's machine."
    techniques = map_to_attack(report)["techniques"]
    learned = [t for t in techniques if any("MITRE example" in e for e in t["evidence"])]

    assert learned, "the learned mapper should contribute here"
    for technique in techniques:
        assert all(marker not in evidence for evidence in technique["evidence"])
    assert all(t["confidence"] <= 0.7 for t in learned), "inferred, so weighted as a lead"


@needs_examples
def test_it_abstains_when_nothing_resembles():
    assert example_mapper.suggest("The cafeteria will be closed on Thursday for cleaning.") == []


@needs_examples
def test_it_does_not_vote_for_what_the_report_denies():
    sentences = example_mapper.split_sentences(
        "No credential dumping from LSASS memory was observed on the host.")
    assert not any("lsass" in sentence.lower() for sentence in sentences)


@needs_examples
def test_it_is_deterministic():
    report = ("The actor enumerated domain trusts, dumped credentials and created a "
              "scheduled task for persistence before exfiltrating archives.")
    assert example_mapper.suggest(report) == example_mapper.suggest(report)


def test_it_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("ATTACKDNA_LEARNED_MAPPER", "0")
    assert example_mapper.suggest("The malware collected the MAC address.") == []


def test_a_rule_match_is_not_duplicated_by_a_learned_one():
    """One behaviour, one technique: the rule quotes the report and stands."""
    techniques = map_to_attack("The attacker ran encoded PowerShell commands.")["techniques"]
    families = [technique["id"].split(".")[0] for technique in techniques]
    assert families.count("T1059") == 1


# --- The evaluation sets say what they are ---------------------------------

def test_the_held_out_set_is_real_text_with_its_sources():
    with open(SEED / "evaluation_heldout.json", "r", encoding="utf-8") as handle:
        cases = json.load(handle)["cases"]

    assert len(cases) >= 30
    for case in cases:
        assert case["source_url"].startswith("https://en.wikipedia.org/"), case["id"]
        assert len(case["text"]) > 200, case["id"]
        expected = case["expected"]
        assert any(expected[field] for field in ("attack_type", "sector")), case["id"]


def test_the_development_set_does_not_overlap_the_held_out_one():
    with open(SEED / "evaluation_dev.json", "r", encoding="utf-8") as handle:
        development = {case["text"] for case in json.load(handle)["cases"]}
    with open(SEED / "evaluation_heldout.json", "r", encoding="utf-8") as handle:
        held_out = {case["text"] for case in json.load(handle)["cases"]}
    assert not development & held_out
