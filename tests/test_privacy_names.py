"""Names without a shape, and the audit that checks for them.

An address or a mailbox can be found by what it looks like. "Aramco", "Sara"
and "Dammam" look like nothing, and they passed straight through the privacy
layer while its self-check reported the text clean. These tests hold that
closed, and they check against identifiers marked by hand — never against
what the layer itself believes it detected.
"""
import json
import re
from pathlib import Path

import pytest

from app.services import lexicon
from app.services.dna_extractor import extract_dna
from app.services.sanitizer import sanitize, verify_clean

AUDIT_PATH = Path(__file__).resolve().parent.parent / "data" / "seed" / "privacy_audit.json"


def _audit(split: str):
    with open(AUDIT_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)[split]


@pytest.mark.parametrize("item", _audit("development"), ids=lambda item: item["id"])
def test_every_marked_identifier_in_the_development_audit_is_removed(item):
    output = sanitize(item["text"]).sanitized_text.lower()
    survived = [value for value in item["must_not_survive"] if value.lower() in output]
    assert not survived, f"{survived} survived in: {output}"


@pytest.mark.parametrize("item", [i for i in _audit("development") + _audit("heldout")
                                  if i["must_survive"]], ids=lambda item: item["id"])
def test_attack_vocabulary_is_left_readable(item):
    """Failing closed must not mean redacting the report into noise."""
    output = sanitize(item["text"]).sanitized_text.lower()
    lost = [value for value in item["must_survive"] if value.lower() not in output]
    assert not lost, f"{lost} was redacted in: {output}"


@pytest.mark.parametrize("report,name", [
    # The two sentences the held-out audit caught on its first run: a machine
    # name at the end of a sentence, where the full stop was read as the start
    # of a domain.
    ("Lateral movement went from hr-lt-0147 to app-srv-03 and then to backup02.", "backup02"),
    ("PowerShell was launched on JED-POS-114 from mgmt01.", "mgmt01"),
    # And the two the real incident summaries caught.
    ("Banks including SBI, ICICI and Axis Bank were hit.", "ICICI"),
    ("The breach at 23andMe exposed ancestry data.", "23andMe"),
])
def test_leaks_found_by_the_held_out_audit_stay_fixed(report, name):
    assert name not in sanitize(report).sanitized_text


@pytest.mark.parametrize("report,kept", [
    ("The attacker used sha-256 hashes and base64-encoded PowerShell.", ["sha-256", "base64-encoded"]),
    ("rundll32.exe spawned from the document in mid-2021 during phase-1.", ["rundll32", "mid-2021", "phase-1"]),
    ("The threat actor used Cobalt Strike and Mimikatz over Remote Desktop.",
     ["Cobalt Strike", "Mimikatz", "Remote Desktop"]),
    ("Royal ransomware was deployed after Windows Defender was disabled via Group Policy.",
     ["Royal", "Windows Defender", "Group Policy"]),
    ("INITIAL ACCESS\nResponse Actions Taken\n1. Isolated the affected VLANs. Effective.",
     ["INITIAL ACCESS", "Response Actions Taken", "Isolated", "Effective"]),
    ("Mark the ticket as resolved once Finance confirms.", ["Mark", "Finance"]),
])
def test_things_that_only_look_like_names_are_left_alone(report, kept):
    output = sanitize(report).sanitized_text
    for phrase in kept:
        assert phrase in output, f"{phrase!r} was redacted: {output}"


def test_a_word_that_is_also_a_company_is_read_from_the_sentence():
    """"Target" is a word; "Target disclosed a breach" is a retailer."""
    output = sanitize("Target disclosed that cards were stolen. The breach at Target "
                      "began at a vendor. The target of the phishing was finance.").sanitized_text
    assert "Target" not in output
    assert "target of the phishing" in output


def test_a_vendor_is_a_victim_when_the_sentence_says_so():
    output = sanitize("Cisco confirmed a breach of its network. The attacker later "
                      "exploited Cisco IOS XE on the gateway.").sanitized_text
    assert output.startswith("[ORG_REDACTED] confirmed")
    assert "Cisco IOS XE" in output


def test_one_name_gets_one_token_everywhere():
    output = sanitize("Colonial Pipeline discovered ransomware. Colonial proactively shut "
                      "down operations.").sanitized_text
    assert "Colonial" not in output
    assert len(set(re.findall(r"\[(?:NAME|ORG)_REDACTED(?:_\d+)?\]", output))) == 1, output


def test_arabic_text_is_withheld_and_its_latin_terms_survive():
    """There is no capital letter to mark a name in Arabic, so none of it is passed on."""
    report = "تعرضت شركة أرامكو لهجوم فدية عبر PowerShell واستغلال CVE-2023-4966 في الرياض."
    result = sanitize(report)

    assert not any("؀" <= char <= "ۿ" for char in result.sanitized_text)
    assert "ARABIC_TEXT_REDACTED" in result.sanitized_text
    assert "PowerShell" in result.sanitized_text
    assert "CVE-2023-4966" in result.sanitized_text
    assert result.counts.get("ARABIC_TEXT", 0) >= 1


def test_form_fields_are_redacted_by_what_their_label_says():
    report = ("Location: Riyadh\nVendor: Gulf Managed IT\nDepartment: finance\n"
              "Hostname: fin-ws-042\nReference: IR-2026-0417")
    output = sanitize(report).sanitized_text

    for value in ("Riyadh", "Gulf Managed IT", "fin-ws-042", "IR-2026-0417"):
        assert value not in output
    assert "Department: finance" in output


def test_sanitizing_twice_changes_nothing():
    """The self-check is exactly this: a second pass finds nothing new."""
    report = ("On 4 March 2026 Qasr Financial Group detected encryption. Sara Al-Harbi "
              "at 10.4.2.8 on fin-ws-042 opened a link from billing@invoice-portal.top; "
              "the account jsmith was then used. Reported by: Layla Al-Otaibi.")
    once = sanitize(report).sanitized_text

    assert sanitize(once).sanitized_text == once
    assert verify_clean(once) == []


def test_the_self_check_reports_what_a_second_pass_finds():
    assert any(leak.startswith("PERSON") for leak in verify_clean("Sara clicked the link."))


def test_the_layer_fails_closed_without_its_word_lists(monkeypatch):
    """A missing vocabulary must mean more is removed, never less."""
    monkeypatch.setattr(lexicon, "ordinary_words", lambda: frozenset(lexicon.FUNCTION_WORDS))
    lexicon.is_ordinary.cache_clear()
    try:
        output = sanitize("Yesterday Zainab opened the Nakheel invoice.").sanitized_text
    finally:
        lexicon.is_ordinary.cache_clear()
    assert "Zainab" not in output and "Nakheel" not in output


def test_a_name_the_layer_misses_still_cannot_reach_the_attack_dna():
    """The guarantee that does not depend on redaction being perfect.

    The Attack DNA is assembled from closed vocabularies — enumerated types,
    ATT&CK ids and names, MITRE's own example sentences. This hands the
    extractor a raw report, as if the privacy layer had removed nothing at
    all, and checks that none of it comes out the other side.
    """
    raw = ("Zubair Qureshi at Marwah Petrochemical opened a phishing email on host "
           "mwp-eng-0042. The attacker ran PowerShell, dumped credentials from LSASS, "
           "moved laterally over RDP and files were encrypted in Yanbu.")
    dna = extract_dna(raw, use_llm=False)

    record = json.dumps({key: dna[key] for key in (
        "attack_type", "initial_vector", "sector", "severity", "signature", "summary",
        "embedding_text", "techniques", "tactics", "impacts", "cves")})
    for identifier in ("Zubair", "Qureshi", "Marwah", "mwp-eng-0042", "Yanbu"):
        assert identifier not in record, f"{identifier} reached the Attack DNA"
    assert dna["attack_type"] == "ransomware"


# --------------------------------------------------------------------------
# Long formal reports (found with the British Library's 2024 incident review)
# --------------------------------------------------------------------------
def test_the_attacker_s_name_is_kept_and_the_victim_s_removed():
    out = sanitize("The British Library said the attack was claimed by the Rhysida "
                   "ransomware gang, which exfiltrated data.").sanitized_text
    assert "Rhysida" in out
    assert "British Library" not in out


def test_an_english_word_that_names_a_gang_is_kept_only_as_an_actor():
    assert "Royal" in sanitize("Files were encrypted by the Royal ransomware group.").sanitized_text
    assert "Royal Mail" not in sanitize("Royal Mail said its export service was disrupted."
                                        ).sanitized_text


def test_capitalised_terms_of_the_trade_are_not_organisations():
    report = ("Access was gained at the Terminal Services server, which was not subject "
              "to Multi-Factor Authentication, and Privileged Access Management was absent.")
    out = sanitize(report).sanitized_text
    for term in ("Terminal Services", "Multi-Factor Authentication", "Privileged Access Management"):
        assert term in out, term


def test_words_after_a_pdf_bullet_glyph_are_read_as_line_starts():
    out = sanitize("Status:\n Some risk to the exhibition programme\n"
                   " Significant disruption to readers").sanitized_text
    assert "Some risk" in out and "Significant disruption" in out


def test_one_stray_capital_does_not_remove_a_word_from_the_whole_report():
    report = ("5. Implement network segmentation across the estate.\n"
              "16. Implement Government standards and review them yearly.")
    out = sanitize(report).sanitized_text
    assert "Implement network segmentation" in out
