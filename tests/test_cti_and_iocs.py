"""CTI enrichment, official mitigations, IoC extraction and DNA validation."""
import pytest

from app.services.attribution import attribute
from app.services.dna_extractor import extract_dna, validate_dna
from app.services.ioc_extractor import extract_iocs, ioc_summary_line
from app.services.knowledge_base import (
    cti_available, load_campaigns, load_groups, load_mitigations, load_software,
    mitigations_by_technique,
)
from app.services.mitigation_memory import recall_mitigations

RANSOMWARE = (
    "Ransomware in the finance department. A spearphishing link harvested credentials. "
    "The attacker used valid accounts, ran encoded PowerShell, dumped credentials from LSASS, "
    "moved laterally over SMB shares, deleted shadow copies and files were encrypted."
)

pytestmark = pytest.mark.skipif(
    not cti_available(),
    reason="CTI layers not processed; run scripts/process_cti.py",
)


# --- Knowledge base -------------------------------------------------------
def test_cti_layers_loaded():
    assert len(load_mitigations()) > 20
    assert len(load_groups()) > 100
    assert len(load_software()) > 300
    assert len(load_campaigns()) > 10


def test_every_mitigation_links_to_techniques():
    for identifier, mitigation in load_mitigations().items():
        assert identifier.startswith("M"), f"{identifier} is not an M-prefixed mitigation"
        assert mitigation["techniques"], f"{identifier} mitigates nothing"


def test_mitigation_index_is_invertible():
    index = mitigations_by_technique()
    assert "T1486" in index
    names = {m["name"] for m in index["T1486"]}
    assert "Data Backup" in names


# --- Official mitigation retrieval ----------------------------------------
def test_framework_mitigations_are_returned_and_ranked_by_coverage():
    dna = extract_dna(RANSOMWARE, use_llm=False)
    result = recall_mitigations([], [t["id"] for t in dna["techniques"]])

    framework = result["framework_mitigations"]
    assert framework, "expected official ATT&CK mitigations"
    assert result["framework_count"] == len(framework)

    coverages = [m["coverage_count"] for m in framework]
    assert coverages == sorted(coverages, reverse=True)
    for mitigation in framework:
        assert mitigation["origin"] == "framework"
        assert mitigation["id"].startswith("M")
        assert mitigation["covers_techniques"]


def test_framework_mitigations_are_separate_from_recalled_actions():
    """The three origins must never be conflated in the output."""
    result = recall_mitigations([], ["T1486"])
    origins = {item["origin"] for item in result["recommended"]}
    assert "framework" not in origins, "framework entries belong in their own list"
    assert all(m["origin"] == "framework" for m in result["framework_mitigations"])


def test_sub_technique_inherits_parent_mitigations():
    result = recall_mitigations([], ["T1566.002"])
    assert result["framework_mitigations"], "T1566.002 should inherit T1566's mitigations"


# --- Attribution ----------------------------------------------------------
def test_attribution_finds_plausible_ransomware_actors():
    dna = extract_dna(RANSOMWARE, use_llm=False)
    result = attribute([t["id"] for t in dna["techniques"]])

    assert result["available"] is True
    assert result["groups"], "expected at least one behavioural match"
    for group in result["groups"]:
        assert group["shared_count"] >= 2
        assert 0.0 <= group["coverage"] <= 1.0
        assert group["confidence"] in {"weak", "moderate", "notable"}


def test_attribution_never_claims_certainty():
    """The caveat is the feature: resemblance is not attribution."""
    result = attribute(["T1486", "T1566.002", "T1059.001"])
    assert "not attribution" in result["caveat"].lower()
    for group in result["groups"]:
        assert group["confidence"] != "confirmed"


def test_attribution_ignores_a_single_shared_technique():
    """One overlapping technique is noise, not a lead."""
    result = attribute(["T1059.001"])
    assert result["groups"] == []


def test_attribution_is_empty_for_no_techniques():
    result = attribute([])
    assert result["groups"] == [] and result["software"] == []


# --- IoC extraction -------------------------------------------------------
def test_shareable_indicators_are_extracted_with_values():
    text = (
        "Payload sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 "
        "and md5 5d41402abc4b2a76b9719d911017c592. Persistence via "
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run. "
        "Lateral movement over SMB on port 445. Files renamed to .locked. "
        "Exploited CVE-2024-21412."
    )
    profile = extract_iocs(text, {})
    shareable = profile["shareable"]

    assert {h["type"] for h in shareable["hashes"]} == {"sha256", "md5"}
    assert shareable["cves"] == ["CVE-2024-21412"]
    assert ".locked" in shareable["file_extensions"]
    assert "SMB" in shareable["protocols"]
    assert 445 in shareable["ports"]
    assert shareable["registry_keys"]


def test_a_sha256_is_not_also_counted_as_a_shorter_hash():
    digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    profile = extract_iocs(f"Payload {digest}.", {})
    assert len(profile["shareable"]["hashes"]) == 1
    assert profile["shareable"]["hashes"][0]["type"] == "sha256"


def test_victim_linked_indicators_are_counted_not_valued():
    profile = extract_iocs("Redacted report text.", {"IP": 3, "EMAIL": 1, "HOSTNAME": 2})
    labels = {entry["label"]: entry["distinct_count"] for entry in profile["redacted_indicators"]}

    assert labels["network addresses"] == 3
    assert labels["mailboxes"] == 1
    assert profile["redacted_count"] == 6
    # Counts only — no values anywhere in the profile.
    assert all("value" not in entry for entry in profile["redacted_indicators"])


def test_ioc_summary_line_is_readable():
    profile = extract_iocs("Exploited CVE-2024-21412 over SMB.", {"IP": 1})
    assert "CVE" in ioc_summary_line(profile)


def test_iocs_are_attached_to_the_dna():
    dna = extract_dna(RANSOMWARE, use_llm=False)
    assert "iocs" in dna
    assert "shareable" in dna["iocs"]
    assert "redacted_indicators" in dna["iocs"]


# --- DNA schema validation ------------------------------------------------
def test_a_well_formed_dna_validates():
    dna = extract_dna(RANSOMWARE, use_llm=False)
    assert dna["validation"]["valid"], dna["validation"]["problems"]


def test_validation_catches_a_missing_field():
    dna = extract_dna(RANSOMWARE, use_llm=False)
    del dna["severity"]
    assert any("severity" in problem for problem in validate_dna(dna))


def test_validation_catches_an_invalid_technique_id():
    dna = extract_dna(RANSOMWARE, use_llm=False)
    dna["techniques"].append({"id": "NOT-A-TECHNIQUE", "evidence": ["x"], "tactics": []})
    assert any("invalid technique id" in problem for problem in validate_dna(dna))


def test_validation_catches_a_privacy_regression_in_the_embedding():
    """If identifying data ever reaches embedding_text, validation must fail."""
    dna = extract_dna(RANSOMWARE, use_llm=False)
    dna["embedding_text"] += " contact sara@falconbank.sa"
    assert any("email address" in problem for problem in validate_dna(dna))
