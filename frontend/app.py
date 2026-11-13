"""ATTACKDNA: the security team's interface.

Who uses this screen: the security team of a member organisation, holding an
incident report about an attack on their own organisation. What they want from
it, in order:

    1. Attach the report                    (nothing to choose, nothing to set up)
    2. Be told the identity was removed     (before anything else happens)
    3. See the attack's fingerprint, what other organisations saw that
       resembles it, and what worked for them
    4. Decide whether to give their own fingerprint back to shared memory,
       knowing exactly what would leave and what would not

The order is the argument. Privacy is the first result on screen because it is
the condition for everything after it, and sharing is the last step because it
is a decision the team makes with the whole analysis in front of them.

Four pages:

    Analyze a report      the journey above
    Dashboard             what shared memory holds, in aggregate
    Ask the memory        a question answered only from what memory holds
    Evidence              the cross-organisation experiment and its numbers

The interface is English only and has a day and a night appearance; the switch
sits at the bottom of the navigation rail.

The app calls the pipeline in-process by default, so the demo needs a single
command and cannot fail because a second server did not start. Set
ATTACKDNA_API_URL to drive the FastAPI service over HTTP instead.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import streamlit as st


def _require_streamlit_runtime() -> None:
    """Fail loudly when run as a plain script instead of through Streamlit.

    A Streamlit script run with `python` executes top to bottom, renders
    nothing, prints a warning per widget and exits 0 — the single most
    confusing way this app can fail, because it looks like nothing happened at
    all. An IDE's Run button does exactly this.
    """
    from streamlit.runtime.scriptrunner import get_script_run_ctx

    if get_script_run_ctx() is not None:
        return

    print(
        "\nATTACKDNA is a Streamlit app — it cannot run as a plain Python script.\n"
        "Nothing was rendered because there is no Streamlit server to render into.\n\n"
        "Start it with:\n\n"
        "    make demo\n\n"
        "or, without make:\n\n"
        "    .venv/bin/streamlit run frontend/app.py\n\n"
        "Then open http://localhost:8501 if a browser tab does not appear.\n",
        file=sys.stderr,
    )
    raise SystemExit(1)


_require_streamlit_runtime()

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Order matters, and getting it wrong fails in a way that reads like nonsense.
# This file is itself named app.py, so with frontend/ ahead of backend/ the
# import `app.config` resolves `app` to *this script* and reports that "'app'
# is not a package". backend/ therefore has to be searched first; frontend/
# only needs to be reachable for the sibling modules below.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.config import DATA_DIR, DEMO_SCENARIOS_PATH  # noqa: E402
from app.db.database import SessionLocal, init_db  # noqa: E402
from app.pipelines.analyze import PrivacyGateError, analyze, contribute  # noqa: E402
from app.services import (  # noqa: E402
    corpus_stats, llm_client, rag_qa, report as report_builder, vector_memory,
)
from app.services.contributors import pseudonym  # noqa: E402
from app.services.document_reader import (  # noqa: E402
    SUPPORTED_EXTENSIONS, UnreadableReport, read_report,
)
from app.services.knowledge_base import (  # noqa: E402
    TACTIC_LABELS, cti_available, load_groups, load_kev, load_mitigations, load_techniques,
)

import dashboard  # noqa: E402
import theme  # noqa: E402

API_URL = os.getenv("ATTACKDNA_API_URL", "").rstrip("/")
CROSSORG_RESULTS = DATA_DIR / "evaluation" / "crossorg_results.json"
CROSSORG_PAIRS = DATA_DIR / "seed" / "crossorg_pairs.json"

PAGES = ["Analyze a report", "Dashboard", "Ask the memory", "Evidence"]
PHASES = ["detect", "contain", "eradicate", "recover", "harden"]

st.set_page_config(page_title="ATTACKDNA", page_icon="■", layout="wide")
state = st.session_state

# Day or night. Read before anything is drawn so the whole page, sidebar
# included, is styled for the mode the viewer chose.
mode = "dark" if state.get("dark_mode", True) else "light"
st.markdown(theme.style(mode), unsafe_allow_html=True)


# --------------------------------------------------------------------------
# Backend access
# --------------------------------------------------------------------------
@st.cache_resource
def bootstrap():
    init_db()
    return True


@st.cache_data(show_spinner=False)
def llm_status() -> dict:
    """Why the LLM layer is or is not working. Cached: it can call the API."""
    return llm_client.diagnose()


def _read_json(path: Path):
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        return None


@st.cache_data
def load_samples() -> list:
    """Sample reports for demonstrations, kept out of the team's own flow.

    The cross-organisation pair comes first: it is the demonstration the
    project exists for: one organisation shares, a second one benefits.
    """
    samples = []
    pairs = _read_json(CROSSORG_PAIRS)
    if pairs and pairs.get("pairs"):
        pair = pairs["pairs"][0]
        samples.append({"label": "Cross-org demo · Organisation A (contributes)",
                        "organisation": pair["a"]["organization"], "text": pair["a"]["text"],
                        "notes": ["Sensitive values are removed before anything else runs.",
                                  "Contribute the fingerprint at the end, then load "
                                  "Organisation B."]})
        samples.append({"label": "Cross-org demo · Organisation B (benefits)",
                        "organisation": pair["b"]["organization"], "text": pair["b"]["text"],
                        "notes": ["The top match is Organisation A's incident, marked "
                                  "'identity withheld'. Nothing names A.",
                                  "A's response is recommended, with its source."]})
    scenarios = _read_json(DEMO_SCENARIOS_PATH) or {}
    for scenario in scenarios.get("scenarios", []):
        samples.append({"label": scenario["label"], "organisation": "",
                        "text": scenario["text"],
                        "notes": [scenario.get("highlight", "")] + scenario.get("watch_for", [])})
    return samples


def corpus_provenance() -> dict:
    """How many incidents in memory come from each kind of source."""
    from sqlalchemy import func

    from app.db.database import IncidentDB

    session = SessionLocal()
    try:
        rows = (session.query(IncidentDB.provenance, func.count(IncidentDB.id))
                .group_by(IncidentDB.provenance).all())
        return {(provenance or "internal"): count for provenance, count in rows}
    finally:
        session.close()


def corpus_overview() -> dict:
    session = SessionLocal()
    try:
        return corpus_stats.overview(session)
    finally:
        session.close()


def corpus_incidents() -> list:
    """What the dashboard needs per incident: never the text, only the fingerprint."""
    from app.db.database import IncidentDB

    session = SessionLocal()
    try:
        return [{
            "id": incident.id,
            "title": incident.title,
            "provenance": incident.provenance or "internal",
            "year": incident.occurred_at.year if incident.occurred_at else None,
            "created": incident.created_at.isoformat() if incident.created_at else "",
            "attack_type": incident.attack_type or "unknown",
            "initial_vector": incident.initial_vector or "unknown",
            "sector": incident.sector or "unknown",
            "severity": incident.severity or "unknown",
            "technique_ids": incident.technique_ids(),
            "tactics": incident.get_json("tactics", []),
        } for incident in session.query(IncidentDB).order_by(IncidentDB.title).all()]
    finally:
        session.close()


def run_analysis(text: str, top_k: int, use_llm: bool, organisation: str) -> dict:
    """Analyze without storing anything: sharing is a separate, later decision."""
    if API_URL:
        import requests

        response = requests.post(
            f"{API_URL}/incidents/analyze",
            json={"text": text, "top_k": top_k, "use_llm": use_llm,
                  "organisation": organisation or None},
            timeout=120,
        )
        response.raise_for_status()
        return response.json()

    session = SessionLocal()
    try:
        return analyze(session, text, top_k=top_k, use_llm=use_llm,
                       viewer_ref=pseudonym(organisation))
    finally:
        session.close()


def run_contribution(result: dict, text: str, organisation: str, mitigations: list,
                     use_llm: bool) -> dict:
    """Add the fingerprint to shared memory: the team's explicit decision."""
    if API_URL:
        import requests

        response = requests.post(
            f"{API_URL}/incidents/contribute",
            json={"text": text, "organisation": organisation or None,
                  "mitigations": mitigations, "use_llm": use_llm},
            timeout=120,
        )
        if response.status_code == 422:
            raise PrivacyGateError(response.json().get("detail", "Refused by the privacy gate"))
        response.raise_for_status()
        return response.json()

    session = SessionLocal()
    try:
        return contribute(session, result, organisation=organisation, mitigations=mitigations)
    finally:
        session.close()


def highlight_redactions(text: str) -> str:
    """Make the redaction tokens the first thing the eye lands on."""
    import html
    import re

    escaped = html.escape(text)
    return re.sub(r"\[([A-Z_]+_REDACTED(?:_\d+)?)\]",
                  r'<span class="redact">[\1]</span>', escaped).replace("\n", "<br>")


def digest(text: str, organisation: str) -> str:
    return hashlib.sha256(f"{organisation}\x00{text}".encode("utf-8")).hexdigest()


def html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


# --------------------------------------------------------------------------
# Navigation rail
# --------------------------------------------------------------------------
bootstrap()

# A sample sets the organisation on the run after its button is pressed, before
# the organisation widget is drawn: changing a widget's value after it exists
# in the same run is an error in Streamlit.
if "organisation_pending" in state:
    state["organisation"] = state.pop("organisation_pending")

memory = vector_memory.memory_stats()
counts = corpus_provenance()

with st.sidebar:
    html(theme.brand())
    page = st.radio("Page", PAGES, label_visibility="collapsed")

    st.divider()
    html(theme.side_head("Your organisation"))
    organisation = st.text_input(
        "Organisation", key="organisation", label_visibility="collapsed",
        placeholder="e.g. Organisation A",
        help="Used for one thing only: to recognise your own incidents in shared "
             "memory. It is stored as a keyed pseudonym that cannot be read back, and "
             "no other organisation ever sees it.",
    )
    st.caption("Kept as a keyed pseudonym. Other organisations never see it.")

    st.divider()
    html(theme.side_head("Shared memory"))
    html(theme.mini_stats([
        ("Incidents", memory["incidents_in_memory"]),
        ("Shared", counts.get("shared", 0)),
        ("Real", counts.get("public", 0)),
        ("Synthetic", counts.get("synthetic", 0)),
    ]))

    with st.expander("Settings"):
        use_llm = st.toggle("Use LLM enrichment", value=llm_client.is_available(),
                            disabled=not llm_client.is_available(),
                            help="Only ever receives the sanitized text, and only when "
                                 "the privacy check passed.")
        if llm_client.is_available():
            st.caption(f"Hybrid mode · {llm_client.provider_name().title()} · "
                       f"`{llm_client.active_model()}`")
        else:
            status = llm_status()
            st.caption("Offline mode: every stage runs without an external model.")
            if status["stage"] != "no_key":
                st.warning(f"**LLM off — {status['detail']}**\n\n{status['remedy']}")
        top_k = st.slider("Similar incidents to recall", 1, 10, 5)
        st.caption(f"Memory backend: `{memory['backend']}`")
        try:
            st.caption(f"ATT&CK techniques: **{len(load_techniques()):,}** · "
                       f"CISA KEV: **{len(load_kev()):,}**")
        except FileNotFoundError:
            st.error("Knowledge base missing. Run `make data`.")
        if cti_available():
            st.caption(f"ATT&CK mitigations: **{len(load_mitigations())}** · "
                       f"Threat groups: **{len(load_groups())}**")
        if API_URL:
            st.caption(f"API mode: `{API_URL}`")

    # Demonstrations live here, not in the team's flow: a security team arrives
    # with its own report and should never be asked to pick someone else's.
    samples = load_samples()
    if samples:
        with st.expander("Demo · sample reports"):
            st.caption("For demonstrations only. Loading a sample fills in the report "
                       "and the organisation, as a member would.")
            labels = [s["label"] for s in samples]
            chosen = st.selectbox("Sample", labels, label_visibility="collapsed")
            if st.button("Load sample", width="stretch"):
                sample = next(s for s in samples if s["label"] == chosen)
                state["pasted_report"] = sample["text"]
                state["sample_notes"] = sample["notes"]
                if sample["organisation"]:
                    state["organisation_pending"] = sample["organisation"]
                state.pop("analysis", None)
                st.rerun()

    st.divider()
    st.toggle("Dark mode", key="dark_mode", value=True,
              help="Switch between the day and night appearance.")


def backend_tag() -> str:
    return theme.status_tag(f"{memory['incidents_in_memory']} incidents · {memory['backend']}")


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
if page == "Dashboard":
    html(theme.page_head("Memory dashboard",
                         "What shared memory holds: every fingerprint, where it came from, "
                         "the behaviour it covers and what worked against it.",
                         [backend_tag()]))
    dashboard.render(corpus_overview(), memory, corpus_incidents(), mode,
                     evaluation=_read_json(CROSSORG_RESULTS))
    st.stop()


# --------------------------------------------------------------------------
# Evidence — the cross-organisation experiment
# --------------------------------------------------------------------------
def render_evidence() -> None:
    html(theme.page_head(
        "Evidence",
        "Does one organisation's incident help another, without exposing it? Organisation A "
        "contributes 20 incidents; organisation B later reports the same 20 attack patterns "
        "in its own words."))

    results = _read_json(CROSSORG_RESULTS)
    if not results:
        st.warning("No results yet. Run `make eval-crossorg` (about 20 seconds) and reload.")
        return

    privacy = results["privacy_protection"]
    behaviour = results["behaviour_preservation"]
    recall = results["cross_org_recall"]
    off = results["privacy_utility"]["without_privacy_layer"]

    def pct(entry) -> str:
        return f"{entry['value']:.0%}" if entry and entry.get("value") is not None else "—"

    def ci(entry) -> str:
        low, high = entry["ci95"]
        return f"{entry['successes']}/{entry['total']} · 95% CI {low:.0%}–{high:.0%}"

    html(theme.kpis([
        {"label": "Identifiers removed", "value": pct(privacy["identifiers_removed"]),
         "note": ci(privacy["identifiers_removed"])},
        {"label": "Behaviour retained", "value": pct(behaviour["techniques_retained"]),
         "note": "ATT&CK techniques kept after sanitization"},
        {"label": "Cross-org Precision@1", "value": pct(recall["precision_at_1"]),
         "note": f"Recall@5 {pct(recall['recall_at_5'])} · MRR {recall['mrr']:.2f}"},
        {"label": "Screens exposing A", "value": recall["queries_exposing_A"],
         "note": f"of {recall['queries']} queries"},
        {"label": "Response reused", "value": pct(recall["mitigation_reuse"]),
         "note": "A's actions recommended to B"},
    ]))
    st.caption(f"Run {results['generated_at']} · code {results.get('code_revision') or '—'} · "
               f"{results['mode']} · memory backend {recall['memory']['backend']} · "
               f"{recall['memory']['corpus_incidents']} corpus incidents as distractors")

    left, right = st.columns(2)
    with left:
        residual = "".join(f"<li><code>{theme.esc(k)}</code>: {theme.esc(', '.join(v))}</li>"
                           for k, v in privacy["residual_detail"].items())
        html(theme.card("1 · Privacy protection",
                        "Identifiers marked by hand, checked by searching the output", f"""
            <ul>
              <li><strong>{privacy['identifiers_planted']}</strong> identifiers in
                  <strong>{privacy['reports']}</strong> reports</li>
              <li><strong>{privacy['identifiers_removed']['successes']}</strong> removed
                  ({ci(privacy['identifiers_removed'])})</li>
              <li><strong>{privacy['residual_identifiers']}</strong> remained in
                  {privacy['reports_with_residual']} report(s)</li>
              <li>Over-redaction: <strong>{privacy['over_redaction']['successes']}</strong> of
                  {privacy['over_redaction']['total']} attack terms lost</li>
            </ul>
            {f'<div class="sub">Survived (the next fixes):</div><ul>{residual}</ul>' if residual else ''}
        """))
    with right:
        raw, clean = behaviour["accuracy_raw"], behaviour["accuracy_sanitized"]
        html(theme.card("2 · Behaviour preservation",
                        "Attack DNA from the sanitized report vs the raw report",
                        theme.table([
                            {"Measure": "Attack type unchanged",
                             "Result": pct(behaviour["attack_type_unchanged"])},
                            {"Measure": "Entry vector unchanged",
                             "Result": pct(behaviour["initial_vector_unchanged"])},
                            {"Measure": "ATT&CK techniques retained",
                             "Result": pct(behaviour["techniques_retained"])},
                            {"Measure": "Attack type vs labels (raw → sanitized)",
                             "Result": f"{pct(raw['attack_type'])} → {pct(clean['attack_type'])}"},
                            {"Measure": "Technique recall vs labels (raw → sanitized)",
                             "Result": f"{raw['techniques']['recall']:.0%} → "
                                       f"{clean['techniques']['recall']:.0%}"},
                        ], numeric={"Result"})))

    bare = results.get("no_distractors")
    html(theme.card("3 · Cross-organisation recall",
                    "B's report is the query; A's contributed incident is the answer",
                    theme.table([
                        {"Measure": "Precision@1: B's top match is A's incident",
                         "Result": f"{pct(recall['precision_at_1'])} ({ci(recall['precision_at_1'])})"},
                        {"Measure": "Recall@5: A's incident in B's top five",
                         "Result": pct(recall["recall_at_5"])},
                        {"Measure": "Mean reciprocal rank", "Result": f"{recall['mrr']:.2f}"},
                        {"Measure": "Precision@5 (same attack type)",
                         "Result": f"{recall['precision_at_5']:.0%}"},
                        {"Measure": "Top match has the same attack type",
                         "Result": pct(recall["top1_same_attack_type"])},
                        {"Measure": "A's response recommended to B, with source",
                         "Result": pct(recall["mitigation_reuse"])},
                        {"Measure": "Shared records still naming A",
                         "Result": f"{recall['stored_records_exposing_A']} of "
                                   f"{recall['memory']['contributed_by_A']}"},
                        {"Measure": "Another organisation's incident shown as 'yours'",
                         "Result": str(recall["foreign_incident_marked_as_own"])},
                    ] + ([{"Measure": "Without corpus distractors: Precision@1 · MRR",
                           "Result": f"{pct(bare['precision_at_1'])} · {bare['mrr']:.2f}"}]
                         if bare else []), numeric={"Result"})))

    with st.expander("Every query"):
        html(theme.table([
            {"Pair": q["pair"], "Pattern": q["pattern"], "Rank of A": q["rank"] or "—",
             "B's top match": q["top1"],
             "Response reused": theme.pill("yes", "good") if q["a_mitigations_recalled"]
             else theme.pill("no", "neutral"),
             "Exposed": ", ".join(q["exposed_identifiers"]) or "none"}
            for q in recall["per_query"]], html_columns={"Response reused"},
            numeric={"Rank of A"}))

    html(theme.card("4 · What privacy costs", "The same experiment with the privacy layer off",
                    theme.table([
                        {"Shared memory": "With the privacy layer",
                         "Precision@1": pct(recall["precision_at_1"]), "MRR": f"{recall['mrr']:.2f}",
                         "Records naming A": f"{recall['stored_records_exposing_A']} of "
                                             f"{recall['memory']['contributed_by_A']}"},
                        {"Shared memory": "Without it (raw reports shared)",
                         "Precision@1": pct(off["precision_at_1"]), "MRR": f"{off['mrr']:.2f}",
                         "Records naming A": f"{off['stored_records_exposing_A']} of "
                                             f"{off['memory']['contributed_by_A']}"},
                    ], strong={"Shared memory"})))

    limits = "".join(f"<li>{theme.esc(c)}</li>" for c in results.get("caveats", []))
    html(theme.card("Limits", "Read every number with these in mind", f"<ul>{limits}</ul>"))
    st.caption("Held-out results for attack classification and ATT&CK mapping on real "
               "incident summaries are produced by `make eval` and `make eval-mapper`.")


if page == "Evidence":
    render_evidence()
    st.stop()


# --------------------------------------------------------------------------
# Ask the memory — retrieval-augmented Q&A over the corpus
# --------------------------------------------------------------------------
if page == "Ask the memory":
    html(theme.page_head("Ask the memory",
                         "Questions answered only from incidents members have already shared. "
                         "Every citation is checked against what was actually retrieved.",
                         [backend_tag()]))

    suggestions = rag_qa.suggested_questions()
    picked = st.selectbox("Example questions", ["— write my own —"] + suggestions, index=1)
    default_question = "" if picked.startswith("—") else picked

    question = st.text_input(
        "Your question", value=default_question,
        placeholder="e.g. What worked against ransomware in the finance sector?",
        key=f"q_{picked}",
    )
    asked = st.button("Ask", type="primary", width="stretch")

    if not asked or not question.strip():
        st.info(f"**{memory['incidents_in_memory']} incidents** are in memory. Pick an "
                "example above or write your own question, then press **Ask**.")
        st.stop()

    with st.spinner("Searching memory..."):
        session = SessionLocal()
        try:
            answer = rag_qa.ask(session, question, top_k=6, use_llm=use_llm)
        finally:
            session.close()

    if answer["answered_from_corpus"]:
        st.success(answer["answer"])
    else:
        st.warning(answer["answer"])

    if answer["unverified_citations"]:
        st.error(
            f"**{len(answer['unverified_citations'])} citation(s) were rejected** — the model "
            "referenced incident ids that were not in the retrieved set, so they were removed "
            "before display."
        )

    if answer["sources"]:
        st.markdown("#### Sources")
        st.caption("The incidents this answer was built from. Cited ones are marked.")
        for source in answer["sources"]:
            cited = "cited" if source["incident_id"] in answer["citations"] else "retrieved"
            with st.expander(f"{source['similarity']:.0%} — {source['title']} · {cited}"):
                html(theme.provenance_pill(source.get("provenance")))
                st.markdown(
                    f"**Type:** {source['attack_type']} · **Sector:** {source['sector']} · "
                    f"**Severity:** {source['severity']} · "
                    f"**Date:** {source['occurred_at'] or 'undated'}"
                )
                st.write(source["summary"])
                if source.get("source_url"):
                    st.caption(f"Source: [{source.get('source_name')}]({source['source_url']})")
    else:
        st.caption("Nothing in memory matched closely enough to cite.")

    st.divider()
    mode_label = "grounded LLM" if answer["mode"] == "llm-grounded" else "retrieval only"
    detail = (f"{answer['retrieved_count']} incident(s) retrieved · "
              f"{len(answer['citations'])} cited · "
              f"confidence {answer.get('confidence', '—')} · {mode_label}")
    if answer.get("language") == "ar" and answer["search_query"] != answer["question"]:
        detail += f" · Arabic question rewritten for retrieval: *{answer['search_query']}*"
    st.caption(detail)
    st.stop()


# --------------------------------------------------------------------------
# ① Attach the report
# --------------------------------------------------------------------------
analysis = state.get("analysis")
html(theme.page_head(
    "Analyze an incident report",
    "One organisation's incident becomes every member's defence, without revealing "
    "who was attacked.", [backend_tag()]))
# Drawn last, once this run knows how far the team got, but shown first.
journey_slot = st.empty()

html(theme.stage("1", "Attach your incident report"))
st.markdown("Attach the report exactly as your team wrote it. Names, IP addresses, emails "
            "and your organisation's details can stay in: **removing them is the system's "
            "first job**, and the original is never stored.")

uploaded = st.file_uploader(
    "Incident report", type=SUPPORTED_EXTENSIONS, label_visibility="collapsed",
    help="PDF, Word (.docx), or text. Read in memory, then discarded.",
)
with st.expander("…or paste the report text", expanded=bool(state.get("pasted_report"))):
    pasted = st.text_area("Report text", key="pasted_report", height=220,
                          label_visibility="collapsed",
                          placeholder="Paste the incident report here.")

if state.get("sample_notes") and not uploaded:
    with st.expander("Presenter notes — what to point at"):
        for note in state["sample_notes"]:
            if note:
                st.markdown(f"- {note}")

run = st.button("Remove identity and analyze", type="primary", width="stretch")

if run:
    report_text, source_label = "", ""
    if uploaded is not None:
        try:
            read = read_report(uploaded.name, uploaded.getvalue())
            report_text, source_label = read.text, uploaded.name
        except UnreadableReport as exc:
            st.error(str(exc))
            st.stop()
    else:
        report_text, source_label = pasted or "", "pasted text"

    if len(report_text.strip()) < 40:
        st.error("Attach an incident report, or paste one of at least a couple of sentences.")
        st.stop()

    with st.spinner("Removing identifying information, then extracting the Attack DNA…"):
        try:
            result = run_analysis(report_text, top_k, use_llm, organisation)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Analysis failed: {exc}")
            st.stop()
    state["analysis"] = {
        "result": result, "digest": digest(report_text, organisation),
        "organisation": organisation, "source": source_label,
        "decision": None, "receipt": None,
    }
    # The raw text is needed again only if the team shares over HTTP; in-process
    # sharing works from the sanitized result alone, so nothing raw is kept.
    state["_raw_for_api"] = report_text if API_URL else None
    analysis = state["analysis"]


def _show_journey() -> None:
    if not analysis:
        journey_slot.markdown(theme.journey(current=1), unsafe_allow_html=True)
    elif analysis.get("decision"):
        journey_slot.markdown(theme.journey(current=4, done=4), unsafe_allow_html=True)
    else:
        journey_slot.markdown(theme.journey(current=4, done=3), unsafe_allow_html=True)


_show_journey()
if not analysis:
    st.stop()

result = analysis["result"]
privacy = result["privacy"]
dna = result["dna"]
similar = result["similar_incidents"]
mitigations = result["mitigations"]
simulation = result.get("simulation")
shareable = privacy["verified_clean"]


# --------------------------------------------------------------------------
# ② Identity removed — the first result, because everything depends on it
# --------------------------------------------------------------------------
st.divider()
html(theme.stage("2", "Identity removed"))

removed = privacy["total_redactions"]
if shareable:
    title = ("Sensitive information removed successfully" if removed
             else "No sensitive information found")
    detail = (f"<strong>{removed}</strong> identifying value(s) were removed from "
              f"<em>{theme.esc(analysis['source'])}</em> before any analysis ran. A second pass "
              "found nothing further. From here on, the system only ever sees the sanitized text.")
    html(f'<div class="shield"><div class="title">{title}</div>'
         f'<div class="detail">{detail}</div>'
         f'{theme.chips(privacy["redactions_by_type"]) if removed else ""}</div>')
else:
    html('<div class="shield fail"><div class="title">Privacy check failed: this report '
         'stays private</div><div class="detail">After sanitization the second pass still found '
         f'<strong>{len(privacy["residual_findings"])}</strong> identifying value(s). The text was '
         'not sent to any AI model, and it cannot be shared. Edit the report and analyze '
         'it again.</div></div>')
    st.error("Residual findings: " + "; ".join(privacy["residual_findings"]))

left, right = st.columns([3, 2])
with left:
    with st.expander("View the sanitized report: this is all the system ever sees"):
        html(f'<div class="sig-box">{highlight_redactions(privacy["sanitized_text"])}</div>')
with right:
    with st.expander(f"What was removed: {removed} value(s)"):
        if privacy["audit"]:
            html(theme.table([{"Token": row["token"], "Type": row["type"],
                               "Original": row["original_preview"]} for row in privacy["audit"]]))
            st.caption("Originals are masked here and are never embedded, stored or sent "
                       "to any model.")
        else:
            st.caption("No identifying values were found in this report.")
st.caption("The second pass re-runs the same detectors, so it is a self-check rather than a "
           "guarantee; the hand-marked audit on the Evidence page measures how well it works.")
if result["meta"].get("llm_blocked_by_privacy_gate"):
    st.warning("The LLM was **not** used for this report because the privacy check did not "
               "pass. The analysis below is fully rule-based.")


# --------------------------------------------------------------------------
# ③ Attack DNA and what shared memory recalls
# --------------------------------------------------------------------------
def verdict_card() -> str:
    attack = dna["attack_type"].replace("_", " ").title()
    vector = (dna.get("initial_vector") or "unknown").replace("_", " ")
    rows = []

    if similar:
        best = similar[0]
        if best.get("from_your_organisation"):
            origin = "your organisation's earlier incident"
        elif best.get("provenance") == "shared":
            origin = "shared by another organisation · identity withheld"
        elif best.get("provenance") == "public":
            origin = "real documented breach"
        else:
            origin = "past incident"
        rows.append(("var(--accent)", "Closest incident in shared memory",
                     f"<strong>{best['similarity']:.0%}</strong> — {theme.esc(best['title'])} "
                     f"<em>({origin})</em>"))
    else:
        rows.append(("var(--muted)", "Closest incident in shared memory",
                     "<em>Nothing close enough: this pattern is new to shared memory.</em>"))

    recommended = mitigations.get("recommended") or []
    if recommended:
        first = recommended[0]
        track = (f" <em>· {first['avg_effectiveness']:.0%} average effectiveness across "
                 f"{first['times_used']} past incident(s)</em>"
                 if first.get("avg_effectiveness") is not None else
                 " <em>· baseline control, no recorded outcome yet</em>")
        rows.append(("var(--good)", "Do this first", f"{theme.esc(first['action'])}{track}"))

    row_html = "".join(
        f'<div class="row"><span class="rule" style="background:{colour}"></span>'
        f'<span><span class="k">{key}</span><span class="v">{value}</span></span></div>'
        for colour, key, value in rows
    )
    return (f'<div class="verdict"><div class="headline">{attack} via {vector}</div>'
            f'<div class="sub">{dna["sector"].title()} sector · {len(dna["techniques"])} ATT&CK '
            f'techniques · severity {dna["severity"]}</div>{row_html}</div>')


st.divider()
html(theme.stage("3", "Attack DNA and shared memory"))
html(verdict_card())

download_left, download_right = st.columns([1, 3])
with download_left:
    st.download_button(
        "Download report", data=report_builder.build(result),
        file_name=report_builder.filename(dna), mime="text/markdown", width="stretch",
    )
with download_right:
    st.caption("A Markdown report of this analysis for your incident file. It carries the "
               "sanitized text and the Attack DNA, never the original.")

tab_dna, tab_memory, tab_response, tab_exercise = st.tabs(
    ["Attack DNA", f"Similar incidents ({len(similar)})", "Recommended response",
     "Tabletop exercise"])

with tab_dna:
    html(theme.facts([
        ("Attack type", theme.esc(dna["attack_type"].replace("_", " ").title())),
        ("Initial vector", theme.esc((dna.get("initial_vector") or "unknown")
                                     .replace("_", " ").title())),
        ("Sector", theme.esc(dna["sector"].title())),
        ("ATT&CK techniques", str(len(dna["techniques"]))),
        ("Severity", theme.severity_pill(dna["severity"])),
    ]))

    st.markdown("**DNA signature**: the part that would be shared")
    html(f'<div class="sig-box">{theme.esc(dna["signature"])}</div>')
    st.caption(f"Extraction mode: {dna.get('extraction_mode', 'rule-based')} · {dna['summary']}")

    kill_chain = " → ".join(TACTIC_LABELS.get(t, t.title()) for t in dna["tactics"]) or "—"
    impacts = ", ".join(i.replace("_", " ").title() for i in dna["impacts"]) or "None recorded"
    st.markdown(f"**Kill chain** · {kill_chain}")
    st.markdown(f"**Impact** · {impacts}")

    st.markdown("**MITRE ATT&CK mapping, with the evidence for each technique**")
    html(theme.table([{
        "Technique": t["id"],
        "Name": t["name"],
        "Tactic": TACTIC_LABELS.get(t["tactics"][0], "—") if t["tactics"] else "—",
        "Confidence": t["confidence"],
        "Evidence": ", ".join(t["evidence"][:3]) or "—",
    } for t in dna["techniques"]], strong={"Technique"}, numeric={"Confidence"}))

    known_exploited = [c for c in dna["cve_details"] if c["known_exploited"]]
    if known_exploited:
        for cve in known_exploited:
            st.error(f"**{cve['cve']} — known exploited in the wild (CISA KEV).** "
                     f"{cve['vendor']} {cve['product']}. {cve['required_action']}")
    elif dna["cve_details"]:
        st.info("Referenced CVEs: "
                + ", ".join(f"{c['cve']} (not in the KEV catalog)" for c in dna["cve_details"]))

    iocs = dna.get("iocs", {})
    attribution = dna.get("attribution", {})
    has_attribution = attribution.get("available") and (attribution["groups"]
                                                        or attribution["software"])
    if iocs or has_attribution:
        with st.expander("Indicators of compromise and threat-actor resemblance"):
            if iocs:
                st.markdown(f"**Shareable**: {iocs['shareable_count']} indicator(s) that "
                            "identify the attacker's tooling and survive sanitization:")
                shareable_iocs = iocs["shareable"]
                for entry in shareable_iocs["hashes"]:
                    st.code(f"{entry['type']}: {entry['value']}", language=None)
                for label, key in [("CVEs", "cves"), ("File artefacts", "file_extensions"),
                                   ("Protocols", "protocols"), ("Registry keys", "registry_keys")]:
                    if shareable_iocs[key]:
                        st.markdown(f"- **{label}:** "
                                    f"{', '.join(str(v) for v in shareable_iocs[key])}")
                if shareable_iocs["ports"]:
                    st.markdown(f"- **Ports:** "
                                f"{', '.join(str(p) for p in shareable_iocs['ports'])}")
                st.markdown(f"**Victim-linked**: {iocs['redacted_count']} indicator(s) removed, "
                            "counts retained:")
                for entry in iocs["redacted_indicators"]:
                    st.markdown(f"- {entry['distinct_count']} distinct **{entry['label']}**")
                st.caption(iocs["note"])
            if has_attribution:
                st.markdown("**Behavioural resemblance to documented threat activity**")
                st.caption(attribution["caveat"])
                html(theme.table(
                    [{"Kind": "Group", "Name": f"{g['id']} {g['name']}",
                      "Overlap": f"{g['coverage']:.0%}", "Confidence": g["confidence"]}
                     for g in attribution["groups"]]
                    + [{"Kind": "Software", "Name": f"{s['id']} {s['name']}",
                        "Overlap": f"{s['coverage']:.0%}", "Confidence": s["confidence"]}
                       for s in attribution["software"]]))

    validation = dna.get("validation", {})
    if validation and not validation.get("valid", True):
        st.warning(f"DNA schema validation reported: {', '.join(validation['problems'])}")

with tab_memory:
    if not similar:
        st.warning("No similar incidents in shared memory yet. Seed the corpus with "
                   "`make seed`, or share incidents as you analyze them.")
    else:
        st.caption("Ranked by a blend of semantic similarity and shared structure. Incidents "
                   "from other organisations show their fingerprint and response only, never "
                   "their name, their people or their report.")
        for index, match in enumerate(similar):
            header = f"{match['similarity']:.0%} — {match['title']} · {match['severity']}"
            with st.expander(header, expanded=index == 0):
                html(theme.provenance_pill(match.get("provenance"),
                                           yours=match.get("from_your_organisation")))
                if match.get("source_url"):
                    st.caption(f"Source: [{match.get('source_name')}]({match['source_url']})")
                if match.get("why_it_matters"):
                    st.info(match["why_it_matters"])

                st.markdown("**Why this matched**")
                for reason in match["match_reasons"]:
                    st.markdown(f"- {reason}")

                st.markdown("**What happened**")
                st.write(match["summary"] or "—")

                if match["mitigations"]:
                    st.markdown("**What they did about it**")
                    html(theme.table(
                        [{"Phase": m["category"], "Action": m["action"],
                          "Effectiveness": f"{m['effectiveness']:.0%}"
                          if m["effectiveness"] is not None else "—"}
                         for m in match["mitigations"]], numeric={"Effectiveness"}))

                html(theme.facts([
                    ("Combined", f"{match['similarity']:.0%}"),
                    ("Semantic", f"{match['semantic_similarity']:.0%}"),
                    ("Structural", f"{match['structural_similarity']:.0%}"),
                ]))

with tab_response:
    st.caption(
        f"**{mitigations['recalled_count']}** action(s) recalled from incidents in shared memory, "
        f"**{mitigations['suggested_count']}** baseline control(s) added where memory had no "
        "coverage. Every recalled action names the incident it came from."
    )
    for group in mitigations["by_phase"]:
        st.markdown(f"#### {group['label']}")
        for action in group["actions"]:
            recalled = action["origin"] == "recalled"
            origin_label = (f"recalled · used in {action['times_used']} past incident(s)"
                            if recalled else "baseline control")
            effectiveness = (f" · avg effectiveness {action['avg_effectiveness']:.0%}"
                             if action.get("avg_effectiveness") is not None else "")
            html(f'{theme.pill(origin_label + effectiveness, "accent" if recalled else "neutral")} '
                 f'{theme.esc(action["action"])}')
            if action["sources"]:
                def _who(source) -> str:
                    if source.get("provenance") == "shared":
                        return " (shared by another organisation)"
                    if source.get("provenance") == "public":
                        return " (public breach)"
                    return ""
                names = ", ".join(f"{s['title']} ({s['similarity']:.0%}){_who(s)}"
                                  for s in action["sources"][:3])
                st.caption(f"Source: {names}")

    framework = mitigations.get("framework_mitigations", [])
    if framework:
        with st.expander(f"Official MITRE ATT&CK mitigations — {len(framework)}"):
            st.caption("Framework controls for the techniques observed, ranked by how much of "
                       "this attack chain each one covers.")
            html(theme.table([{"ID": m["id"], "Mitigation": m["name"], "Covers": m["coverage_count"],
                               "Techniques": ", ".join(m["covers_techniques"])} for m in framework],
                             strong={"ID"}, numeric={"Covers"}))

with tab_exercise:
    if not simulation:
        st.caption("No exercise was generated for this report.")
    else:
        st.subheader(simulation["title"])
        st.info(f"**{simulation['safety_notice']}**")
        head = simulation["headline"]
        scenario_cols = st.columns(2)
        with scenario_cols[0]:
            st.markdown(f"**Initial access:** {head['initial_access']}")
            st.markdown(f"**Technique:** `{head['technique']}`")
            st.markdown(f"**Target:** {head['target']}")
        with scenario_cols[1]:
            st.markdown(f"**Expected detection:** {head['expected_detection']}")
            st.markdown(f"**Detection source:** {head['detection_source']}")
            st.markdown(f"**Recommended controls:** {' + '.join(head['recommended_controls'])}")
        st.markdown(f"**Objective:** {simulation['objective']}")
        st.caption(f"Estimated duration: {simulation['estimated_duration_minutes']} minutes · "
                   f"Participants: {', '.join(simulation['participants'])}")
        for inject in simulation["injects"]:
            with st.expander(f"Inject {inject['step']} — {inject['phase_label']}"):
                st.markdown(f"*Read to the team:* {inject['inject']}")
                st.markdown(f"*Expected detection:* {inject['expected_detection']} "
                            f"— source: {inject['detection_source']}")
                st.markdown(f"*Decision point:* {inject['decision_point']}")
                for step in inject.get("expected_response_actions", []):
                    st.markdown(f"- {step}")
        st.markdown("**Success criteria**")
        for criterion in simulation["success_criteria"]:
            st.markdown(f"- {criterion}")


# --------------------------------------------------------------------------
# ④ Share with other organisations, or keep private
# --------------------------------------------------------------------------
st.divider()
html(theme.stage("4", "Share with other organisations (optional)"))

if analysis.get("decision") == "shared":
    receipt = analysis["receipt"] or {}
    if receipt.get("already_shared"):
        st.info("Your organisation had already shared this incident, so it was not added "
                "a second time.")
    st.success(
        "**Added to shared memory as an anonymous fingerprint.** Other organisations facing "
        "this pattern will now recall it, with your response, and see neither your name nor "
        "your report."
    )
    st.caption(f"Recorded as “{receipt.get('title', '')}” · "
               f"{receipt.get('shared', {}).get('mitigations', 0)} response action(s) shared · "
               "withheld: " + ", ".join(receipt.get("withheld", [])))
    st.stop()

if analysis.get("decision") == "private":
    st.info("**Kept private.** Nothing from this analysis was stored.")
    if st.button("Reconsider sharing"):
        analysis["decision"] = None
        st.rerun()
    st.stop()

st.markdown("Nothing has been stored yet. If your security team approves, the fingerprint "
            "of this incident joins shared memory, so the next organisation hit by the same "
            "pattern recalls it and sees what worked for you.")
techniques_preview = ", ".join(t["id"] for t in dna["techniques"][:6]) or "none"
html('<div class="consent">'
     '<div class="col share"><h4>Shared</h4><ul>'
     f'<li>Attack type and entry vector: {dna["attack_type"].replace("_", " ")}, '
     f'{(dna.get("initial_vector") or "unknown").replace("_", " ")}</li>'
     f'<li>ATT&amp;CK techniques and tactics: {techniques_preview}</li>'
     '<li>Sector, severity, CVEs and impacts</li>'
     '<li>The sanitized summary, with redaction tokens in place of identifiers</li>'
     '<li>The response actions you add below, sanitized as well</li></ul></div>'
     '<div class="col keep"><h4>Never leaves your organisation</h4><ul>'
     '<li>The original report and file</li>'
     '<li>Your organisation\'s name (stored only as a pseudonym that cannot be read back)</li>'
     f'<li>The {removed} identifying value(s) removed in step 2</li>'
     '<li>The incident date: shared records carry only the month they were shared</li>'
     '</ul></div></div>')

with st.expander("Add what your team did (recommended): it is what helps the next "
                 "organisation most"):
    st.caption("One action per row. Free text is sanitized again before it is stored.")
    team_rows = []
    for index in range(3):
        action_col, phase_col, score_col = st.columns([5, 2, 2])
        team_rows.append({
            "action": action_col.text_input(f"Action {index + 1}", key=f"team_action_{index}",
                                            placeholder="e.g. Isolated the affected hosts"),
            "category": phase_col.selectbox("Phase", PHASES, index=1, key=f"team_phase_{index}"),
            "effectiveness": score_col.number_input("Worked (%)", min_value=0, max_value=100,
                                                    value=None, step=5,
                                                    key=f"team_score_{index}"),
        })

approved = st.checkbox(
    "Our security team approves sharing this anonymised fingerprint with member organisations",
    disabled=not shareable,
)
if not shareable:
    st.caption("Sharing is disabled because the privacy check did not pass.")
elif not organisation:
    st.caption("Tip: enter your organisation in the sidebar so shared memory can tell you "
               "when a match is your own incident.")

share_col, private_col = st.columns(2)
with share_col:
    share = st.button("Contribute to shared memory", type="primary", width="stretch",
                      disabled=not (shareable and approved))
with private_col:
    keep_private = st.button("Keep private: analysis only", width="stretch")

if keep_private:
    analysis["decision"] = "private"
    st.rerun()

if share:
    team_actions = [
        {"action": row["action"].strip(), "category": row["category"],
         "effectiveness": row["effectiveness"] / 100 if row["effectiveness"] is not None else None}
        for row in team_rows if len((row["action"] or "").strip()) >= 3
    ]
    try:
        receipt = run_contribution(result, state.get("_raw_for_api") or "", organisation,
                                   team_actions, use_llm)
    except PrivacyGateError as exc:
        st.error(str(exc))
        st.stop()
    analysis["decision"] = "shared"
    analysis["receipt"] = receipt
    state.pop("_raw_for_api", None)
    st.rerun()
