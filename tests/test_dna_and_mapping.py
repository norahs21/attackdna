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


@pytest.mark.parametrize("report,expected", [
    # An exploited edge appliance is how a large share of real intrusions now
    # begin, and none of these reports would say "web application".
    ("The attacker exploited a vulnerability in an internet-facing VPN appliance, "
     "CVE-2024-21762, to gain access without credentials.", "web_exploitation"),
    ("Session tokens were stolen from an unpatched appliance at the remote access "
     "gateway, bypassing multi-factor authentication.", "web_exploitation"),
    # A password that reached the attacker before the attack began.
    ("Initial access was through a legacy VPN account without multi-factor "
     "authentication whose password had appeared in a credential dump.",
     "credential_attack"),
    ("The attacker obtained a contractor's password, purchased from a credential "
     "marketplace, then repeatedly pushed approval prompts.", "credential_attack"),
    # A signed update carrying a backdoor.
    ("The build environment was compromised and used to distribute trojanised, "
     "digitally signed updates containing a backdoor.", "supply_chain"),
])
def test_the_entry_vector_is_named_for_the_shapes_real_reports_take(report, expected):
    """"Unknown" was a third of the corpus, including an incident whose own
    title named the vector, because the vocabulary only covered web apps."""
    assert extract_dna(report, use_llm=False)["initial_vector"] == expected


def test_an_entry_vector_that_is_genuinely_unknown_stays_unknown():
    """The fix must widen coverage without inventing a vector that is not there.

    A flood with no intrusion has no entry vector, and guessing one would be
    worse than reporting none.
    """
    report = ("A telecom operator experienced a distributed denial of service attack. "
              "A traffic flood targeted the subscriber portal causing an outage for "
              "five hours. No intrusion, malware or data exfiltration was identified.")
    assert extract_dna(report, use_llm=False)["initial_vector"] == "unknown"


def test_dna_contains_every_expected_field():
    dna = extract_dna(RANSOMWARE_REPORT, use_llm=False)
    for field in ("attack_type", "initial_vector", "severity", "signature",
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


# --------------------------------------------------------------------------
# No sector, and the entry vector on real reports
# --------------------------------------------------------------------------
def test_the_dna_does_not_guess_the_victims_sector():
    """Once names are removed, the victim's industry is not inferred or shared."""
    from app.services.dna_extractor import extract_dna

    text = ("Ransomware encrypted the library services and the reading rooms closed. "
            "Patient records at the hospital and the bank's payment systems were spared.")
    dna = extract_dna(text, {}, use_llm=False)
    assert "sector" not in dna
    for word in ("library", "hospital", "bank", "healthcare", "finance", "culture"):
        assert word not in dna["signature"].lower()
        assert word not in dna["embedding_text"].lower()
        assert word not in dna["summary"].lower()


def test_entry_through_stolen_credentials_without_mfa_is_a_credential_attack():
    from app.services.dna_extractor import extract_dna

    text = ("The attackers used compromised credentials of a third-party account on the "
            "terminal server, which was not subject to multi-factor authentication, and "
            "then encrypted the file servers with ransomware.")
    dna = extract_dna(text, {}, use_llm=False)
    assert dna["attack_type"] == "ransomware"
    assert dna["initial_vector"] == "credential_attack"


def test_a_long_report_gets_a_handful_of_learned_techniques_not_one_per_sentence():
    from app.services import example_mapper

    if not example_mapper.CLASSIFIER_PATH.exists():
        return
    text = " ".join(f"The library opened exhibition number {i} to the public." for i in range(40))
    text += " The attackers ran PowerShell to download a payload and encrypted the servers."
    assert len(example_mapper.suggest(text)) <= example_mapper.MAX_LEARNED_PER_REPORT
