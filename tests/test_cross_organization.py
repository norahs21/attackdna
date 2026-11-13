"""Cross-organization sharing: the project's central claim, as tests.

One organization's incident must become another organization's defensive
knowledge without the second one learning who the first one was. Each test
pins one part of that: what is stored, what is withheld, who is told "this is
yours", and that nothing unverified gets in.
"""
import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db.database import IncidentDB
from app.pipelines import analyze as pipeline
from app.pipelines.analyze import PrivacyGateError, analyze, contribute
from app.services.contributors import pseudonym, same_contributor
from app.services.document_reader import UnreadableReport, read_report

PAIRS = Path(__file__).resolve().parent.parent / "data" / "seed" / "crossorg_pairs.json"

ORG_A = "Al-Noor Specialist Hospital"
REPORT_A = (
    "On 3 March the SOC at Al-Noor Specialist Hospital received an alert from WKS-RAD-044. "
    "A nurse, Hessa Al-Mutairi (hessa.mutairi@alnoor-hospital.sa), clicked a phishing link "
    "and typed her credentials into a fake login page. The attacker signed in from "
    "45.137.21.9, ran encoded PowerShell to disable the EDR agent, moved laterally over SMB "
    "shares, deleted shadow copies with vssadmin and files were encrypted. A ransom note "
    "demanded payment."
)
ORG_B = "Gulf Freight Logistics"
REPORT_B = (
    "Gulf Freight Logistics lost access to its shared drives. An employee, Omar Haddad, had "
    "followed a link in a fake parcel email and entered his password on a spoofed login page. "
    "From 91.219.236.18 the intruders ran obfuscated PowerShell that turned off endpoint "
    "protection, spread through SMB file shares, removed the shadow copies, and every share "
    "was encrypted with a ransom note left behind."
)
A_IDENTIFIERS = ["Al-Noor", "Hessa", "Mutairi", "alnoor-hospital", "45.137.21.9", "WKS-RAD-044"]


def _share(session, text=REPORT_A, organisation=ORG_A, mitigations=None):
    result = analyze(session, text, use_llm=False, include_simulation=False)
    return contribute(session, result, organisation=organisation, mitigations=mitigations)


# --------------------------------------------------------------------------
# Pseudonyms
# --------------------------------------------------------------------------
def test_a_pseudonym_is_stable_and_does_not_contain_the_name():
    first = pseudonym("Al-Noor Specialist Hospital")
    assert first == pseudonym("  al-noor   SPECIALIST hospital ")
    assert "noor" not in first.lower()
    assert len(first) == 64


def test_different_organisations_get_different_pseudonyms():
    assert pseudonym(ORG_A) != pseudonym(ORG_B)


def test_no_name_means_no_pseudonym_and_never_a_match():
    assert pseudonym("") is None
    assert pseudonym(None) is None
    assert same_contributor(None, None) is False
    assert same_contributor(pseudonym(ORG_A), None) is False


# --------------------------------------------------------------------------
# What sharing stores
# --------------------------------------------------------------------------
def test_sharing_stores_the_fingerprint_and_never_the_report(clean_memory):
    receipt = _share(clean_memory)
    record = clean_memory.get(IncidentDB, receipt["incident_id"])

    assert record.provenance == "shared"
    assert record.raw_text is None
    stored = json.dumps(record.to_dict(include_raw=True))
    for value in A_IDENTIFIERS:
        assert value not in stored, f"{value} reached shared memory"


def test_the_pseudonym_never_appears_in_what_the_api_returns(clean_memory):
    receipt = _share(clean_memory)
    record = clean_memory.get(IncidentDB, receipt["incident_id"])

    assert record.contributor_ref == pseudonym(ORG_A)
    assert record.contributor_ref not in json.dumps(record.to_dict(include_raw=True))


def test_a_shared_record_carries_no_exact_date(clean_memory):
    receipt = _share(clean_memory)
    record = clean_memory.get(IncidentDB, receipt["incident_id"])

    assert record.occurred_at is None
    assert record.shared_at.day == 1 and record.shared_at.hour == 0
    assert record.created_at == record.shared_at
    assert not any(ch.isdigit() for ch in record.title)


def test_the_team_s_response_is_sanitized_before_it_is_shared(clean_memory):
    receipt = _share(clean_memory, mitigations=[
        {"action": "Isolated WKS-RAD-044 and called Hessa Al-Mutairi on +966 50 381 2290",
         "category": "contain", "effectiveness": 0.9},
        {"action": "", "category": "contain"},
    ])
    record = clean_memory.get(IncidentDB, receipt["incident_id"])

    assert receipt["shared"]["mitigations"] == 1
    action = record.mitigations[0].action
    assert "WKS-RAD-044" not in action and "Hessa" not in action and "381 2290" not in action
    assert "Isolated" in action


def test_sharing_the_same_incident_twice_stores_it_once(clean_memory):
    first = _share(clean_memory)
    second = _share(clean_memory)

    assert second["already_shared"] is True
    assert second["incident_id"] == first["incident_id"]
    assert clean_memory.query(IncidentDB).filter(IncidentDB.provenance == "shared").count() == 1


def test_an_incident_that_fails_the_privacy_check_cannot_be_shared(clean_memory, monkeypatch):
    result = analyze(clean_memory, REPORT_A, use_llm=False, include_simulation=False)
    monkeypatch.setattr(pipeline, "verify_clean", lambda text: ["PERSON: someone"])

    with pytest.raises(PrivacyGateError):
        contribute(clean_memory, result, organisation=ORG_A)
    assert clean_memory.query(IncidentDB).count() == 0


def test_a_failed_privacy_check_keeps_the_text_away_from_the_llm(clean_memory, monkeypatch):
    calls = []

    def spy(text, counts=None, use_llm=True):
        calls.append(use_llm)
        return original(text, counts, use_llm=False)

    original = pipeline.extract_dna
    monkeypatch.setattr(pipeline, "extract_dna", spy)
    monkeypatch.setattr(pipeline, "verify_clean", lambda text: ["PERSON: someone"])

    result = analyze(clean_memory, REPORT_A, use_llm=True, include_simulation=False)

    assert calls == [False]
    assert result["meta"]["llm_blocked_by_privacy_gate"] is True
    assert result["meta"]["shareable"] is False


# --------------------------------------------------------------------------
# What the second organisation sees
# --------------------------------------------------------------------------
def test_organisation_b_recalls_a_without_learning_who_a_is(clean_memory):
    receipt = _share(clean_memory, mitigations=[
        {"action": "Restore file servers from offline immutable backups",
         "category": "recover", "effectiveness": 0.85},
    ])

    result = analyze(clean_memory, REPORT_B, use_llm=False, include_simulation=False,
                     viewer_ref=pseudonym(ORG_B))

    top = result["similar_incidents"][0]
    assert top["incident_id"] == receipt["incident_id"]
    assert top["from_your_organisation"] is False
    screen = json.dumps(result)
    for value in A_IDENTIFIERS:
        assert value not in screen, f"{value} reached organisation B"
    recalled = [item for item in result["mitigations"]["recommended"]
                if item["origin"] == "recalled"]
    assert any(src["incident_id"] == receipt["incident_id"]
               for item in recalled for src in item["sources"])


def test_organisation_a_is_told_its_own_incident_is_its_own(clean_memory):
    receipt = _share(clean_memory)

    result = analyze(clean_memory, REPORT_A, use_llm=False, include_simulation=False,
                     viewer_ref=pseudonym(ORG_A))

    top = result["similar_incidents"][0]
    assert top["incident_id"] == receipt["incident_id"]
    assert top["from_your_organisation"] is True


def test_the_contribute_endpoint_shares_and_the_gate_refuses(clean_memory, monkeypatch):
    from app.main import app

    with TestClient(app) as client:
        response = client.post("/incidents/contribute", json={
            "text": REPORT_A, "organisation": ORG_A, "use_llm": False,
            "mitigations": [{"action": "Isolate the infected hosts", "category": "contain"}],
        })
        assert response.status_code == 201
        assert response.json()["shared"]["mitigations"] == 1

        monkeypatch.setattr(pipeline, "verify_clean", lambda text: ["ORG: someone"])
        refused = client.post("/incidents/contribute", json={
            "text": REPORT_B, "organisation": ORG_B, "use_llm": False})
        assert refused.status_code == 422


# --------------------------------------------------------------------------
# The experiment's data
# --------------------------------------------------------------------------
def test_the_cross_organisation_pairs_are_complete():
    pairs = json.loads(PAIRS.read_text(encoding="utf-8"))["pairs"]

    assert len(pairs) >= 20
    assert len({p["id"] for p in pairs}) == len(pairs)
    for pair in pairs:
        for side in ("a", "b"):
            report = pair[side]
            assert report["organization"] and len(report["text"]) > 150
            assert report["identifiers"], f"{pair['id']}{side} plants no identifiers"
            for value in report["identifiers"]:
                assert value in report["text"], f"{pair['id']}{side}: {value!r} not in text"
        assert pair["a"]["mitigations"], f"{pair['id']}A records no response"
        assert pair["labels"]["attack_type"] and pair["labels"]["techniques"]


# --------------------------------------------------------------------------
# Attached reports
# --------------------------------------------------------------------------
def _minimal_pdf(text: str) -> bytes:
    """A one-page PDF with a real text layer, built by hand."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets:
        out.write(f"{offset:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
              .encode())
    return out.getvalue()


def test_a_pdf_report_is_read_as_text():
    read = read_report("incident.pdf", _minimal_pdf("Ransomware encrypted the file servers"))

    assert read.kind == "pdf"
    assert "Ransomware encrypted the file servers" in read.text


def test_a_word_report_is_read_including_its_tables():
    import docx

    document = docx.Document()
    document.add_paragraph("A phishing link led to ransomware.")
    table = document.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "Affected host"
    table.rows[0].cells[1].text = "WKS-RAD-044"
    buffer = io.BytesIO()
    document.save(buffer)

    read = read_report("incident.docx", buffer.getvalue())

    assert read.kind == "docx"
    assert "phishing link" in read.text
    assert "WKS-RAD-044" in read.text


def test_an_unsupported_or_empty_file_is_refused_with_a_reason():
    with pytest.raises(UnreadableReport):
        read_report("incident.xlsx", b"PK\x03\x04")
    with pytest.raises(UnreadableReport):
        read_report("incident.pdf", b"not a pdf")
