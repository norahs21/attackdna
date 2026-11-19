"""How a responder describes an incident before anyone has named it.

The "Ask the memory" page is used mid-incident, in plain words: "a user
clicked a link in an email ... we now see logins to other machines". These
tests pin down that such a description is understood without an LLM, and that
the severity of an encrypting ransomware attack does not depend on how long
the report happens to be.
"""
from app.services.dna_extractor import extract_dna
from app.services.sanitizer import sanitize

DEMO_QUESTION = ("A user clicked a link in an email, PowerShell ran on their laptop, "
                 "and we now see logins to other machines")


def _dna(text: str) -> dict:
    return extract_dna(sanitize(text).sanitized_text, {}, use_llm=False)


def test_a_link_in_an_email_is_a_phishing_entry():
    assert _dna(DEMO_QUESTION)["initial_vector"] == "phishing"


def test_logins_to_other_machines_is_lateral_movement():
    dna = _dna(DEMO_QUESTION)
    assert "lateral-movement" in dna["tactics"]
    assert any(t["id"].startswith("T1021") for t in dna["techniques"])


def test_entry_wording_decides_the_vector_not_the_attack_type():
    """A Qakbot infection that arrived as an attachment is still malware."""
    dna = _dna("EDR flagged rundll32.exe spawning from a OneNote attachment. The payload "
               "was Qakbot, which established persistence through a scheduled task and "
               "beaconed to its C2 over HTTPS.")
    assert dna["initial_vector"] == "phishing"
    assert dna["attack_type"] != "phishing"


def test_a_denied_click_is_not_evidence():
    dna = _dna("The user did not click the link in the email; the message was reported "
               "and quarantined. No further activity was seen.")
    assert "T1204" not in {t["id"].split(".")[0] for t in dna["techniques"]}


def test_ransomware_that_encrypted_data_is_at_least_high():
    dna = _dna("Ransomware encrypted files on three file servers. A ransom note was left.")
    assert dna["attack_type"] == "ransomware"
    assert dna["severity"] in {"high", "critical"}


def test_the_severity_floor_does_not_touch_other_attacks():
    dna = _dna("A phishing email was reported by staff and blocked.")
    assert dna["severity"] == "low"
