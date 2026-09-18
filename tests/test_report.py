"""Report export tests.

The report leaves the machine — it gets pasted into tickets and emailed — so
the property that matters most is the one the whole system is built on: no
identifying value may appear in it. The rest is that it stays readable when
parts of the analysis are missing.
"""
import pytest

from app.pipelines.analyze import analyze
from app.services import report

REPORT = (
    "Falcon Bank Ltd reported ransomware in the finance department. The alert came from "
    "soc@falconbank.example and the beachhead was 10.20.30.40. A spearphishing link "
    "harvested credentials, the attacker ran encoded PowerShell, disabled the EDR agent "
    "and files were encrypted. Exploited CVE-2024-21412."
)


@pytest.fixture
def analysis(clean_memory):
    return analyze(clean_memory, REPORT, top_k=3, use_llm=False)


def test_no_identifying_value_reaches_the_report(analysis):
    """The guarantee the whole system rests on, checked where it leaves the app."""
    markdown = report.build(analysis)

    assert "Falcon Bank" not in markdown
    assert "falconbank" not in markdown
    assert "10.20.30.40" not in markdown
    assert "soc@" not in markdown


def test_the_technical_detail_survives_sanitization(analysis):
    """Redaction must cost identifiers, not intelligence."""
    markdown = report.build(analysis)

    assert "CVE-2024-21412" in markdown
    assert "ransomware" in markdown.lower()
    assert "T1486" in markdown


def test_the_report_leads_with_the_verdict(analysis):
    markdown = report.build(analysis)
    verdict = markdown.index("## Verdict")

    assert verdict < markdown.index("## Attack DNA")
    assert verdict < markdown.index("## Sanitized incident")


def test_the_redaction_count_is_stated(analysis):
    markdown = report.build(analysis)
    assert "Identifying values removed:" in markdown
    assert "verified clean" in markdown


def test_a_missing_section_does_not_break_the_document(clean_memory):
    """An empty memory is a normal state, not a broken report."""
    analysis = analyze(clean_memory, REPORT, top_k=3, use_llm=False)
    analysis["similar_incidents"] = []
    analysis["mitigations"] = {}

    markdown = report.build(analysis)

    assert "matched closely enough" in markdown
    assert markdown.endswith("\n")


def test_tables_render_as_markdown_tables(analysis):
    markdown = report.build(analysis)
    assert "| Technique | Name | Confidence | Evidence |" in markdown
    assert "|---|---|---|---|" in markdown


def test_the_filename_describes_the_incident(analysis):
    name = report.filename(analysis["dna"])
    assert name.startswith("attackdna-ransomware-")
    assert name.endswith(".md")
