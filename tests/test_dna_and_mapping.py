"""Attack DNA extraction, ATT&CK mapping and KEV enrichment tests."""
import pytest

from app.services.dna_extractor import build_signature, extract_dna
from app.services.kev_enricher import enrich_cves, extract_cves, kev_summary
from app.services.mitre_mapper import map_to_attack

RANSOMWARE_REPORT = (
    "A spearphishing link led to credential theft. The attacker ran encoded PowerShell, "
    "disabled the EDR agent, moved laterally over SMB shares, deleted shadow copies, and "
    "files were encrypted across the finance department file servers. Customer data was "
    "exfiltrated to cloud storage. Exploited CVE-2024-21412. Operations halted for 14 hours."
)


def test_explicit_technique_ids_are_trusted():
    mapping = map_to_attack("The report cites T1486 and T1059.001 explicitly.")
    ids = {t["id"] for t in mapping["techniques"]}
    assert {"T1486", "T1059.001"} <= ids
    for technique in mapping["techniques"]:
        assert technique["confidence"] >= 0.9


def test_behaviour_phrases_map_to_techniques():
    mapping = map_to_attack("Files were encrypted after a phishing link was clicked.")
    ids = {t["id"] for t in mapping["techniques"]}
    assert "T1486" in ids
    assert "T1566.002" in ids


def test_every_mapping_carries_its_evidence():
    mapping = map_to_attack(RANSOMWARE_REPORT)
    assert mapping["techniques"]
    for technique in mapping["techniques"]:
        assert technique["evidence"], f"{technique['id']} has no evidence"


def test_generic_words_do_not_produce_bogus_techniques():
    """'credentials' alone must not invent a reconnaissance phase."""
    mapping = map_to_attack("The user's credentials were stored in the browser.")
    assert "T1589.001" not in {t["id"] for t in mapping["techniques"]}


def test_parent_technique_is_dropped_when_a_sub_technique_matched():
    mapping = map_to_attack("A spearphishing link was sent to the finance team.")
    ids = {t["id"] for t in mapping["techniques"]}
    assert "T1566.002" in ids
    assert "T1566" not in ids


def test_tactics_are_returned_in_kill_chain_order():
    from app.services.knowledge_base import TACTIC_ORDER

    mapping = map_to_attack(RANSOMWARE_REPORT)
    positions = [TACTIC_ORDER.index(t) for t in mapping["tactics"] if t in TACTIC_ORDER]
    assert positions == sorted(positions)


def test_outcome_outranks_entry_vector_in_classification():
    """Phishing that ends in ransomware is a ransomware incident."""
    dna = extract_dna(RANSOMWARE_REPORT, use_llm=False)
    assert dna["attack_type"] == "ransomware"
    assert dna["initial_vector"] == "phishing"


def test_dna_contains_every_expected_field():
    dna = extract_dna(RANSOMWARE_REPORT, use_llm=False)
    for field in ("attack_type", "initial_vector", "sector", "severity", "signature",
                  "techniques", "tactics", "cves", "cve_details", "kev", "impacts",
                  "summary", "embedding_text", "extraction_mode"):
        assert field in dna, f"missing {field}"


def test_severity_reflects_impact_and_kev():
    dna = extract_dna(RANSOMWARE_REPORT, use_llm=False)
    assert dna["severity"] in {"high", "critical"}

    minor = extract_dna("A single phishing email was reported and deleted.", use_llm=False)
    assert minor["severity"] in {"low", "medium"}


def test_embedding_text_never_contains_redaction_tokens_or_raw_identifiers():
    """Only DNA-derived language is embedded — this is a privacy invariant."""
    from app.services.sanitizer import sanitize

    sanitized = sanitize(
        "Falcon Bank: sara@falcon.sa was phished from 91.240.118.22 and files were encrypted."
    )
    dna = extract_dna(sanitized.sanitized_text, sanitized.counts, use_llm=False)
    assert "sara@falcon.sa" not in dna["embedding_text"]
    assert "91.240.118.22" not in dna["embedding_text"]
    assert "REDACTED" not in dna["embedding_text"]


def test_signature_is_ordered_by_the_kill_chain():
    from app.services.knowledge_base import TACTIC_ORDER

    dna = extract_dna(RANSOMWARE_REPORT, use_llm=False)
    signature = build_signature(dna)
    chain = signature.split("|")[2].strip()
    tactics = [step.split(":")[0] for step in chain.split(" > ")]
    positions = [TACTIC_ORDER.index(t) for t in tactics if t in TACTIC_ORDER]
    assert positions == sorted(positions)


def test_extraction_without_llm_is_labelled_rule_based():
    dna = extract_dna(RANSOMWARE_REPORT, use_llm=False)
    assert dna["extraction_mode"] == "rule-based"


def test_unparseable_text_still_produces_a_complete_dna():
    dna = extract_dna("Nothing of note happened on the network this week.", use_llm=False)
    assert dna["attack_type"] == "unknown"
    assert dna["signature"]
    assert dna["summary"]


# --- CISA KEV -------------------------------------------------------------
def test_cve_extraction_is_deduplicated_and_uppercased():
    cves = extract_cves("cve-2024-21412 and CVE-2024-21412 and CVE-2023-1234.")
    assert cves == ["CVE-2024-21412", "CVE-2023-1234"]


def test_known_exploited_cve_is_flagged_with_its_required_action():
    enriched = enrich_cves(["CVE-2024-21412"])
    record = enriched[0]
    assert record["known_exploited"] is True
    assert record["required_action"]
    assert kev_summary(enriched)["urgency"] == "critical"


def test_unknown_cve_is_not_flagged():
    enriched = enrich_cves(["CVE-1999-0001"])
    assert enriched[0]["known_exploited"] is False
    assert kev_summary(enriched)["urgency"] == "review"


@pytest.mark.parametrize("text", ["", "   ", "no indicators here"])
def test_extractors_tolerate_empty_input(text):
    assert extract_cves(text) == []
    assert map_to_attack(text)["techniques"] == []
