"""Privacy Layer tests.

These are the tests that matter most: they are the evidence behind the claim
that identifying data never reaches the rest of the system.
"""
import pytest

from app.services.sanitizer import sanitize, verify_clean


@pytest.mark.parametrize("value", [
    "john.doe@company.sa",
    "attacker@evil-domain.com",
])
def test_emails_are_removed(value):
    result = sanitize(f"Phishing was sent to {value} on Monday.")
    assert value not in result.sanitized_text
    assert "EMAIL_REDACTED" in result.sanitized_text


@pytest.mark.parametrize("value", [
    "10.10.23.41",
    "185.220.101.7",
    "192.168.1.100/24",
])
def test_ipv4_addresses_are_removed(value):
    result = sanitize(f"C2 traffic went to {value} overnight.")
    assert value.split("/")[0] not in result.sanitized_text


def test_defanged_indicators_are_removed():
    result = sanitize("Beaconing to 10[.]0[.]0[.]5 and hxxp://evil[.]com/payload observed.")
    assert "10[.]0[.]0[.]5" not in result.sanitized_text
    assert "evil" not in result.sanitized_text


def test_secrets_are_removed():
    result = sanitize("The key AKIAJ4TESTKEYEXAMPLE was committed to the repository.")
    assert "AKIAJ4TESTKEYEXAMPLE" not in result.sanitized_text
    assert "SECRET_REDACTED" in result.sanitized_text


def test_financial_identifiers_are_removed():
    result = sanitize("Transfer to SA0380000000608010167519 from card 4111 1111 1111 1111.")
    assert "SA0380000000608010167519" not in result.sanitized_text
    assert "4111" not in result.sanitized_text


def test_person_and_org_names_are_removed():
    result = sanitize("Reported by CISO Ahmed Al-Rashid of Alpha Trading Company.")
    assert "Ahmed" not in result.sanitized_text
    assert "Al-Rashid" not in result.sanitized_text
    assert "Alpha Trading" not in result.sanitized_text


def test_windows_user_path_is_removed():
    result = sanitize(r"Files under C:\Users\jdoe\Documents were encrypted.")
    assert "jdoe" not in result.sanitized_text


def test_attack_fingerprint_survives():
    """CVEs, technique ids and hashes describe the attack, not the victim."""
    digest = "a3f5b2c1d4e6f7890123456789abcdef01234567890abcdef1234567890abcd"
    text = f"Exploited CVE-2024-21412 using T1486 with payload {digest}."
    result = sanitize(text)
    assert "CVE-2024-21412" in result.sanitized_text
    assert "T1486" in result.sanitized_text
    assert digest in result.sanitized_text


def test_security_vocabulary_is_not_mistaken_for_hostnames():
    text = "MFA and EDR were disabled; the SOC used SIEM and EDR-XDR telemetry."
    result = sanitize(text)
    for term in ("MFA", "EDR", "SOC", "SIEM"):
        assert term in result.sanitized_text


def test_redaction_is_consistent_and_distinguishes_values():
    """The same value maps to one token; different values stay distinguishable."""
    text = ("Mail from a@x.com to b@y.com, then a@x.com again. "
            "Traffic to 1.1.1.1 only.")
    result = sanitize(text)
    # Two distinct emails get numbered tokens.
    assert "[EMAIL_REDACTED_1]" in result.sanitized_text
    assert "[EMAIL_REDACTED_2]" in result.sanitized_text
    assert result.sanitized_text.count("[EMAIL_REDACTED_1]") == 2
    assert result.counts["EMAIL"] == 2
    # A single IP gets the clean unnumbered form.
    assert "[IP_REDACTED]" in result.sanitized_text
    assert result.counts["IP"] == 1


def test_verification_pass_finds_nothing_in_sanitized_output():
    text = ("Incident at Falcon Bank: sara@falcon.sa clicked a link, attacker at "
            "91.240.118.22 used CORP\\s.nasser on WKSTN-FIN-204, phone +966 55 123 4567, "
            "exploiting CVE-2024-21412.")
    result = sanitize(text)
    assert verify_clean(result.sanitized_text) == []


def test_empty_input_is_safe():
    result = sanitize("")
    assert result.sanitized_text == ""
    assert result.total_redactions == 0


def test_audit_rows_mask_original_values():
    result = sanitize("Contact john.doe@company.sa about the breach.")
    row = result.audit_rows()[0]
    assert "john.doe@company.sa" != row["original_preview"]
    assert "*" in row["original_preview"]


# --- Leaks found by running a realistic incident report through the layer ---
# Each of these survived sanitization while verify_clean reported the text
# clean, which is the one failure the green badge exists to make impossible.

def test_internal_fqdns_are_removed_including_the_host_label():
    """The most identifying names in a report never appear in public DNS."""
    report = ("The attacker reached the remote access gateway "
              "netscaler-edge01.alwaha-health.example and pivoted to "
              "jmp-ops-02.corp.local and the backup server bkp-prod-01.internal.")
    result = sanitize(report)

    for fragment in ("netscaler-edge01", "jmp-ops-02", "bkp-prod-01",
                     "alwaha-health", "corp.local", ".internal"):
        assert fragment not in result.sanitized_text, f"{fragment} survived"


@pytest.mark.parametrize("report,name", [
    ("Reported by: Layla Al-Otaibi, SOC Team Lead", "Al-Otaibi"),
    ("Escalated to: Faisal Alharbi", "Alharbi"),
    ("Investigated by Sara O'Brien", "O'Brien"),
    ("The contractor Ahmed Al-Rashid retained access", "Al-Rashid"),
])
def test_a_person_named_in_a_form_field_is_removed(report, name):
    """Incident reports are written as forms, and a colon is not whitespace."""
    assert name not in sanitize(report).sanitized_text


def test_the_verification_pass_covers_host_and_domain_names():
    """A server name is the victim's identity as surely as a mailbox is."""
    leaked = "Contact the team about fileserver-01.corp.local before Monday."
    assert any(leak.startswith("DOMAIN") for leak in verify_clean(leaked))


def test_widening_person_detection_does_not_eat_ordinary_words():
    """The regression this fix first introduced, held down by a test.

    Making the role keyword case-insensitive with a whole-pattern flag also
    folds the name group, where [A-Z][a-z]+ is what makes it a proper noun —
    so "the attacker ran encoded PowerShell" lost the words the ATT&CK mapper
    reads as evidence.
    """
    report = ("The attacker ran encoded PowerShell, the user opened the attachment, "
              "and the employee reported it to the service desk.")
    sanitized = sanitize(report).sanitized_text

    for word in ("ran", "encoded", "PowerShell", "opened", "attachment", "reported"):
        assert word in sanitized, f"{word} was redacted as a person's name"


def test_product_names_are_intelligence_not_identity():
    """What the attacker exploited is shareable; whose server it was is not."""
    report = ("The unpatched Citrix NetScaler appliance at gw-01.acme.local was "
              "exploited via CVE-2023-4966.")
    sanitized = sanitize(report).sanitized_text

    assert "Citrix NetScaler" in sanitized
    assert "CVE-2023-4966" in sanitized
    assert "gw-01" not in sanitized and "acme.local" not in sanitized
