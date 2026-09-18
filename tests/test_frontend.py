"""Demo interface smoke tests.

The demo is the deliverable — a traceback on stage on a screen nobody could
test is the worst possible failure, and the whole UI used to be untested. These
run the real Streamlit script headlessly in each mode and assert the things a
presenter depends on: that it renders at all, that the verdict card leads, and
that no identifying value survives onto the screen.
"""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from app.pipelines.analyze import ingest

# Absolute: AppTest resolves a relative path against the *calling* file, which
# would look for the app inside tests/.
APP = str(Path(__file__).resolve().parent.parent / "frontend" / "app.py")
TIMEOUT = 90

REPORT = (
    "Falcon Bank Ltd reported ransomware in the finance department. The alert came "
    "from soc@falconbank.example and the beachhead was 10.20.30.40. A spearphishing "
    "link harvested credentials, the attacker ran encoded PowerShell, disabled the "
    "EDR agent, moved laterally over SMB shares and files were encrypted. "
    "Exploited CVE-2024-21412."
)

DDOS = (
    "A telecom operator experienced a distributed denial of service attack. A traffic "
    "flood targeted the subscriber portal causing an outage for five hours."
)


@pytest.fixture
def corpus(clean_memory):
    session = clean_memory
    ingest(session, REPORT, title="Ransomware — finance", use_llm=False, mitigations=[
        {"action": "Isolate affected endpoints", "category": "contain", "effectiveness": 0.95},
    ])
    ingest(session, DDOS, title="DDoS — telecom", use_llm=False, mitigations=[
        {"action": "Enable upstream scrubbing", "category": "contain", "effectiveness": 0.9},
    ])
    return session


def _run(mode: str | None = None) -> AppTest:
    app = AppTest.from_file(APP, default_timeout=TIMEOUT).run()
    if mode:
        app.sidebar.radio[0].set_value(mode).run()
    return app


def _screen_text(app: AppTest) -> str:
    """Everything rendered, flattened — what a reader would actually see."""
    parts = []
    for name in ("markdown", "caption", "subheader", "title", "header",
                 "success", "warning", "error", "info", "text"):
        parts += [element.value for element in getattr(app, name)]
    return "\n".join(str(part) for part in parts)


def test_the_app_starts_without_an_exception(corpus):
    app = _run()
    assert not app.exception


def test_every_mode_renders(corpus):
    for mode in ["Analyze an incident", "Ask the memory", "Memory dashboard"]:
        app = _run(mode)
        assert not app.exception, f"{mode} raised {app.exception}"


def test_the_dashboard_reports_what_memory_holds(corpus):
    app = _run("Memory dashboard")

    assert not app.exception
    screen = _screen_text(app)
    assert "Incidents in memory" in screen
    assert "ATT&CK techniques seen" in screen


def test_an_empty_memory_dashboard_says_so_instead_of_crashing(clean_memory):
    app = _run("Memory dashboard")

    assert not app.exception
    assert any("Memory is empty" in str(w.value) for w in app.warning)


def test_analyzing_leads_with_the_verdict_then_the_evidence(corpus):
    app = _run()
    app.text_area[0].set_value(REPORT).run()
    app.button[0].click().run()

    assert not app.exception
    screen = _screen_text(app)
    verdict = screen.index("Verdict")
    assert verdict < screen.index("Privacy Shield")
    assert verdict < screen.index("Extract Attack DNA")


def test_the_verdict_names_the_attack_and_the_first_action(corpus):
    app = _run()
    app.text_area[0].set_value(REPORT).run()
    app.button[0].click().run()

    screen = _screen_text(app)
    assert "Ransomware via phishing" in screen
    assert "Do this first" in screen
    assert "identifying value(s) removed" in screen


def test_nothing_identifying_reaches_the_screen(corpus):
    """The system's central promise, checked at the last place it could break."""
    app = _run()
    app.text_area[0].set_value(REPORT).run()
    app.button[0].click().run()

    screen = _screen_text(app)
    assert "Falcon Bank" not in screen
    assert "10.20.30.40" not in screen
    assert "soc@falconbank" not in screen
    assert "REDACTED" in screen


def test_the_report_download_is_offered(corpus):
    app = _run()
    app.text_area[0].set_value(REPORT).run()
    app.button[0].click().run()

    assert not app.exception
    assert any("Download report" in str(b.label) for b in app.download_button)


def test_a_too_short_report_is_rejected_with_a_message(corpus):
    app = _run()
    app.text_area[0].set_value("nope").run()
    app.button[0].click().run()

    assert not app.exception
    assert any("at least a couple of sentences" in str(e.value) for e in app.error)


def test_asking_the_memory_puts_the_sources_under_the_answer(corpus):
    app = _run("Ask the memory")
    app.text_input[0].set_value("What worked against ransomware in finance?").run()
    next(b for b in app.button if b.label == "Ask").click().run()

    assert not app.exception
    screen = _screen_text(app)
    assert "Sources" in screen
    # The retrieval statistics are a footnote, never a wall between the answer
    # and the evidence it was built from.
    assert screen.index("Sources") < screen.index("incident(s) retrieved")
