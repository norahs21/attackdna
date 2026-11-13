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


def _button(app: AppTest, label: str):
    return next(b for b in app.button if b.label == label)


def _analyze(app: AppTest, text: str = REPORT) -> AppTest:
    """Paste a report and press the one button a team needs."""
    app.text_area[0].set_value(text).run()
    _button(app, "Analyze").click().run()
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


def test_the_app_starts_in_an_interpreter_that_has_imported_nothing():
    """The only honest check that `streamlit run` works.

    Every other test here runs after conftest has already imported the backend
    `app` package, so `sys.modules` is primed and an import that would fail
    from cold succeeds. That masked a real break: this file is itself named
    app.py, and with frontend/ ahead of backend/ on the path, `app.config`
    resolved `app` to this script and the demo died on launch — while the suite
    stayed green. A fresh interpreter is the only way to see it.
    """
    import subprocess
    import sys as _sys

    probe = (
        "from streamlit.testing.v1 import AppTest\n"
        f"at = AppTest.from_file({APP!r}, default_timeout={TIMEOUT}).run()\n"
        "raise SystemExit(str(at.exception[0].value) if at.exception else 0)\n"
    )
    finished = subprocess.run([_sys.executable, "-c", probe],
                              capture_output=True, text=True, timeout=TIMEOUT * 2)

    assert finished.returncode == 0, (
        f"the app fails to start from a cold interpreter: {finished.returncode}"
    )


def test_every_mode_renders(corpus):
    for mode in ["Analyze a report", "Dashboard", "Ask the memory"]:
        app = _run(mode)
        assert not app.exception, f"{mode} raised {app.exception}"


def test_the_dashboard_reports_what_memory_holds(corpus):
    app = _run("Dashboard")

    assert not app.exception
    screen = _screen_text(app)
    assert "Incidents in memory" in screen
    assert "ATT&CK techniques" in screen
    assert "Fingerprints in memory" in screen


def test_an_empty_memory_dashboard_says_so_instead_of_crashing(clean_memory):
    app = _run("Dashboard")

    assert not app.exception
    assert any("Memory is empty" in str(w.value) for w in app.warning)


def test_the_platform_opens_on_attaching_a_report(corpus):
    """A security team arrives with its own report: no tour, no picker, no notes."""
    app = _run()

    assert not app.exception
    assert not app.main.selectbox, "the analysis page should not open with a picker"
    screen = _screen_text(app)
    for gone in ("Presenter notes", "Step 1", "Demo", "Evidence"):
        assert gone not in screen, f"{gone!r} should not be on a working platform"
    assert not app.sidebar.text_input, "the organisation is configuration, not a field"


def test_privacy_is_the_first_result_then_the_verdict(corpus):
    app = _analyze(_run())

    assert not app.exception
    screen = _screen_text(app)
    assert screen.index("Sensitive information removed successfully") < screen.index(
        "Ransomware via phishing")


def test_the_verdict_names_the_attack_and_the_first_action(corpus):
    app = _analyze(_run())

    screen = _screen_text(app)
    assert "Ransomware via phishing" in screen
    assert "Do this first" in screen
    assert "identifying value(s) removed" in screen


def test_nothing_identifying_reaches_the_screen(corpus):
    """The system's central promise, checked at the last place it could break."""
    app = _analyze(_run())

    screen = _screen_text(app)
    assert "Falcon Bank" not in screen
    assert "10.20.30.40" not in screen
    assert "soc@falconbank" not in screen
    assert "REDACTED" in screen


def test_analysing_stores_nothing(corpus):
    from app.db.database import IncidentDB

    before = corpus.query(IncidentDB).count()
    _analyze(_run())

    assert corpus.query(IncidentDB).count() == before


def test_analysing_with_the_switch_off_stores_nothing(corpus):
    from app.db.database import IncidentDB

    app = _analyze(_run())

    assert not app.exception
    assert not app.success
    assert corpus.query(IncidentDB).filter(IncidentDB.provenance == "shared").count() == 0


def test_with_the_switch_on_the_analysis_adds_only_the_fingerprint(corpus):
    from app.db.database import IncidentDB

    app = _run()
    app.sidebar.toggle(key="add_to_memory").set_value(True).run()
    app.text_area(key="analyze_text").set_value(REPORT).run()
    app.text_area(key="team_actions").set_value("Isolated WKS-FIN-118 from the network").run()
    _button(app, "Analyze and add to memory").click().run()

    assert not app.exception
    assert any("Added to shared memory" in str(s.value) for s in app.success)
    shared = corpus.query(IncidentDB).filter(IncidentDB.provenance == "shared").all()
    assert len(shared) == 1
    record = shared[0]
    assert record.raw_text is None
    assert "Falcon" not in (record.sanitized_text + record.title)
    assert [m.action for m in record.mitigations] and "WKS-FIN-118" not in record.mitigations[0].action
    # Similar incidents were found before the report was added: it never recalls itself.
    assert "Ransomware via phishing" in _screen_text(app)


def test_the_report_download_is_offered(corpus):
    app = _analyze(_run())

    assert not app.exception
    assert any("Download report" in str(b.label) for b in app.download_button)


def test_a_too_short_report_is_rejected_with_a_message(corpus):
    app = _analyze(_run(), "nope")

    assert not app.exception
    assert any("at least a couple of sentences" in str(e.value) for e in app.error)


def test_asking_needs_no_report_first(corpus):
    app = _run("Ask the memory")
    app.text_input[0].set_value("What worked against ransomware in finance?").run()
    next(b for b in app.button if b.label == "Ask").click().run()

    assert not app.exception
    assert "Sources" in _screen_text(app)


def test_the_dashboard_has_no_incident_comparison(corpus):
    app = _run("Dashboard")

    assert not app.exception
    assert "Compare two incidents" not in _screen_text(app)
    assert not any("Compare" in str(e.label) for e in app.expander)


def test_the_interface_is_english_only(corpus):
    import re

    for page in ["Analyze a report", "Dashboard", "Ask the memory"]:
        app = _run(page)
        text = _screen_text(app) + " ".join(str(o) for s in app.selectbox for o in s.options)
        assert not re.search("[\u0600-\u06FF]", text), f"Arabic on {page}"


def test_day_and_night_both_render(corpus):
    app = _run("Dashboard")
    assert not app.exception
    app.sidebar.toggle(key="dark_mode").set_value(False).run()
    assert not app.exception
    assert "--bg: #eceef1" in _screen_text(app)
