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
    Ask shared memory     a question answered only from what memory holds
    Shared memory         what the corpus knows, in aggregate
    Evidence              the cross-organisation experiment and its numbers

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

PAGES = ["Analyze a report", "Ask shared memory", "Shared memory", "Evidence"]
PAGE_ARABIC = {
    "Analyze a report": "تحليل تقرير حادث",
    "Ask shared memory": "اسأل الذاكرة المشتركة",
    "Shared memory": "الذاكرة المشتركة",
    "Evidence": "النتائج والتجارب",
}
PHASES = ["detect", "contain", "eradicate", "recover", "harden"]

st.set_page_config(page_title="ATTACKDNA", page_icon="■", layout="wide")
st.markdown(theme.STYLE, unsafe_allow_html=True)


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
    """The minimum each incident needs to be compared against another."""
    from app.db.database import IncidentDB

    session = SessionLocal()
    try:
        return [{
            "id": incident.id,
            "title": incident.title,
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


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------
bootstrap()
state = st.session_state

# A sample sets the organisation on the run after its button is pressed, before
# the organisation widget is drawn: changing a widget's value after it exists
# in the same run is an error in Streamlit.
if "organisation_pending" in state:
    state["organisation"] = state.pop("organisation_pending")

with st.sidebar:
    st.markdown(theme.side_head("Navigate"), unsafe_allow_html=True)
    page = st.radio(
        "Page", PAGES, label_visibility="collapsed",
        format_func=lambda name: f"{name}  ·  {PAGE_ARABIC[name]}",
        help="Analyze runs your report through the privacy layer and shared memory. "
             "Ask questions the incidents already shared. Shared memory shows what it holds. "
             "Evidence shows the measured results.",
    )

    st.divider()
    st.markdown(theme.side_head("Your organisation"), unsafe_allow_html=True)
    organisation = st.text_input(
        "Organisation", key="organisation", label_visibility="collapsed",
        placeholder="e.g. Organisation A",
        help="Used for one thing only: to recognise your own incidents in shared "
             "memory. It is stored as a keyed pseudonym that cannot be read back, and "
             "no other organisation ever sees it.",
    )
    st.caption("Kept as a keyed pseudonym. Other organisations never see it. "
               "اسم المؤسسة لا يُخزَّن ولا يظهر لأي جهة أخرى.")

    st.divider()
    st.markdown(theme.side_head("Shared memory"), unsafe_allow_html=True)
    memory = vector_memory.memory_stats()
    st.metric("Incidents in memory", memory["incidents_in_memory"])
    counts = corpus_provenance()
    if counts.get("shared"):
        st.markdown(theme.legend_row(theme.SERIES[0], counts["shared"],
                                     "shared by member organisations"), unsafe_allow_html=True)
    if counts.get("public"):
        st.markdown(theme.legend_row(theme.SERIES[2], counts["public"],
                                     "real, publicly documented breaches"),
                    unsafe_allow_html=True)
    if counts.get("synthetic"):
        st.markdown(theme.legend_row(theme.SERIES[1], counts["synthetic"],
                                     "synthetic incidents"), unsafe_allow_html=True)
    if counts.get("internal"):
        st.markdown(theme.legend_row(theme.INK_MUTED, counts["internal"],
                                     "internal incidents"), unsafe_allow_html=True)

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



# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------
st.markdown(
    '<div class="dna-hero"><h1>ATTACKDNA</h1>'
    '<p>One organisation\'s incident becomes every member\'s defence, without '
    'revealing who was attacked.</p>'
    '<p class="ar">حادثة مؤسسة واحدة تصبح معرفة دفاعية لبقية المؤسسات، '
    'دون كشف هوية الضحية أو مشاركة تقريرها.</p>'
    '</div>',
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------
# Shared memory dashboard
# --------------------------------------------------------------------------
if page == "Shared memory":
    st.markdown(theme.stage("—", "Shared memory", "الذاكرة المشتركة"),
                unsafe_allow_html=True)
    st.subheader("What shared memory holds")
    st.markdown("Aggregate view of every fingerprint in memory: the answer to *“what does "
                "this system actually know?”* before it is asked to advise on anything.")
    dashboard.render(corpus_overview(), vector_memory.memory_stats(), corpus_incidents())
    st.stop()


# --------------------------------------------------------------------------
# Evidence — the cross-organisation experiment
# --------------------------------------------------------------------------
def render_evidence() -> None:
    st.markdown(theme.stage("—", "Evidence", "النتائج"), unsafe_allow_html=True)
    st.subheader("Does one organisation's incident help another, without exposing it?")
    st.markdown(
        "Organisation A contributes 20 incidents to shared memory. Organisation B later "
        "reports the same 20 attack patterns **in its own words**. The experiment measures "
        "whether B recalls A's incident, whether anything naming A reaches B, and whether "
        "removing A's identity costs any retrieval quality."
    )

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

    tiles = st.columns(4)
    tiles[0].markdown(theme.tile("Identifiers removed", pct(privacy["identifiers_removed"]),
                                 ci(privacy["identifiers_removed"])), unsafe_allow_html=True)
    tiles[1].markdown(theme.tile("Behaviour retained", pct(behaviour["techniques_retained"]),
                                 "ATT&CK techniques kept after sanitization"),
                      unsafe_allow_html=True)
    tiles[2].markdown(theme.tile("Cross-org Precision@1", pct(recall["precision_at_1"]),
                                 f"Recall@5 {pct(recall['recall_at_5'])} · MRR "
                                 f"{recall['mrr']:.2f}"), unsafe_allow_html=True)
    tiles[3].markdown(theme.tile("Exposed to B", str(recall["queries_exposing_A"]),
                                 f"of {recall['queries']} screens named A"),
                      unsafe_allow_html=True)
    st.caption(f"Run {results['generated_at']} · code `{results.get('code_revision') or '—'}` · "
               f"{results['mode']} · memory backend `{recall['memory']['backend']}` · "
               f"{recall['memory']['corpus_incidents']} corpus incidents as distractors")

    st.markdown("#### 1 · Privacy protection")
    st.markdown(
        f"- **{privacy['identifiers_planted']}** identifiers were marked by hand across "
        f"**{privacy['reports']}** reports (people, organisations, emails, IPs, hosts, phones).\n"
        f"- **{privacy['identifiers_removed']['successes']}** were removed "
        f"({ci(privacy['identifiers_removed'])}), checked by searching the output for each one, "
        "not by asking the privacy layer what it found.\n"
        f"- **{privacy['residual_identifiers']}** remained in "
        f"{privacy['reports_with_residual']} report(s) after this independent check.\n"
        f"- Over-redaction: **{privacy['over_redaction']['successes']}** of "
        f"{privacy['over_redaction']['total']} attack terms were lost "
        f"({pct(privacy['over_redaction'])})."
    )
    if privacy["residual_detail"]:
        with st.expander("Which identifiers survived"):
            st.caption("Reported as found. These are the next fixes for the privacy layer.")
            for report_id, values in privacy["residual_detail"].items():
                st.markdown(f"- `{report_id}`: {', '.join(values)}")

    st.markdown("#### 2 · Behaviour preservation")
    st.markdown(
        "Attack DNA from the sanitized report compared with Attack DNA from the raw report:\n\n"
        f"- Attack type unchanged: **{pct(behaviour['attack_type_unchanged'])}** · entry vector "
        f"unchanged: **{pct(behaviour['initial_vector_unchanged'])}**\n"
        f"- ATT&CK techniques retained: **{pct(behaviour['techniques_retained'])}** "
        f"({ci(behaviour['techniques_retained'])})\n"
        f"- Accuracy against the labels: attack type "
        f"{pct(behaviour['accuracy_raw']['attack_type'])} raw vs "
        f"{pct(behaviour['accuracy_sanitized']['attack_type'])} sanitized; technique recall "
        f"{behaviour['accuracy_raw']['techniques']['recall']:.0%} vs "
        f"{behaviour['accuracy_sanitized']['techniques']['recall']:.0%}"
    )

    st.markdown("#### 3 · Cross-organisation recall")
    st.markdown(
        f"- **Precision@1 {pct(recall['precision_at_1'])}** ({ci(recall['precision_at_1'])}): "
        "B's top match was A's incident.\n"
        f"- **Recall@5 {pct(recall['recall_at_5'])}**: A's incident was in B's top five.\n"
        f"- **MRR {recall['mrr']:.2f}** · Precision@5 (same attack type) "
        f"{recall['precision_at_5']:.0%} · top match of the same attack type "
        f"{pct(recall['top1_same_attack_type'])}\n"
        f"- A's recorded response recommended to B: **{pct(recall['mitigation_reuse'])}** of "
        "queries, always with its source.\n"
        f"- Screens that named A: **{recall['queries_exposing_A']}** of {recall['queries']} · "
        f"shared records still naming A: **{recall['stored_records_exposing_A']}** of "
        f"{recall['memory']['contributed_by_A']}\n"
        f"- Another organisation's incident shown as “yours”: "
        f"**{recall['foreign_incident_marked_as_own']}** · A's own incident recognised as "
        f"“yours”: **{pct(results['own_incident_recognised'])}**"
    )
    if results.get("no_distractors"):
        bare = results["no_distractors"]
        st.caption(f"Without the corpus distractors (memory = A's 20 only): Precision@1 "
                   f"{pct(bare['precision_at_1'])} · Recall@5 {pct(bare['recall_at_5'])} · "
                   f"MRR {bare['mrr']:.2f}")
    with st.expander("Every query"):
        st.dataframe(
            [{"Pair": q["pair"], "Pattern": q["pattern"],
              "Rank of A": q["rank"] or "—",
              "B's top match": q["top1"],
              "A's response recalled": "yes" if q["a_mitigations_recalled"] else "no",
              "Exposed": ", ".join(q["exposed_identifiers"]) or "none"}
             for q in recall["per_query"]],
            width="stretch", hide_index=True,
        )

    st.markdown("#### 4 · What privacy costs")
    st.dataframe([
        {"Shared memory": "With the privacy layer",
         "Precision@1": pct(recall["precision_at_1"]), "MRR": f"{recall['mrr']:.2f}",
         "Shared records naming A": f"{recall['stored_records_exposing_A']} of "
                                    f"{recall['memory']['contributed_by_A']}"},
        {"Shared memory": "Without it (raw reports shared)",
         "Precision@1": pct(off["precision_at_1"]), "MRR": f"{off['mrr']:.2f}",
         "Shared records naming A": f"{off['stored_records_exposing_A']} of "
                                    f"{off['memory']['contributed_by_A']}"},
    ], width="stretch", hide_index=True)

    st.markdown("#### Limits")
    for caveat in results.get("caveats", []):
        st.markdown(f"- {caveat}")
    st.caption("Held-out results for attack classification and ATT&CK mapping on real "
               "incident summaries are produced by `make eval` and `make eval-mapper`.")


if page == "Evidence":
    render_evidence()
    st.stop()


# --------------------------------------------------------------------------
# Ask shared memory — retrieval-augmented Q&A over the corpus
# --------------------------------------------------------------------------
if page == "Ask shared memory":
    st.markdown(theme.stage("—", "Ask shared memory", "اسأل الذاكرة"), unsafe_allow_html=True)
    st.subheader("Question the incidents members have already shared")
    st.markdown(
        "Answers are built **only** from incidents in memory. Every citation is "
        "checked against what was actually retrieved, so a source the model "
        "invents never reaches you."
    )

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
        st.info(f"**{vector_memory.memory_stats()['incidents_in_memory']} incidents** are in "
                "memory. Pick an example above or write your own question, then press **Ask**.")
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
                st.markdown(theme.provenance_pill(source.get("provenance")),
                            unsafe_allow_html=True)
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
# Drawn last, once this run knows how far the team got, but shown first.
journey_slot = st.empty()

st.markdown(theme.stage("1", "Attach your incident report", "إرفاق تقرير الحادث"),
            unsafe_allow_html=True)
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
st.markdown(theme.stage("2", "Identity removed", "إزالة المعلومات الحساسة"),
            unsafe_allow_html=True)

removed = privacy["total_redactions"]
if shareable:
    title = ("Sensitive information removed successfully" if removed
             else "No sensitive information found")
    title_ar = ("تمت إزالة المعلومات الحساسة بنجاح" if removed
                else "لم يُعثر على معلومات حساسة في التقرير")
    detail = (f"<strong>{removed}</strong> identifying value(s) were removed from "
              f"<em>{analysis['source']}</em> before any analysis ran. A second pass found "
              "nothing further. From here on, the system only ever sees the sanitized text.")
    st.markdown(
        f'<div class="shield"><div class="title">{title}</div>'
        f'<div class="title-ar">{title_ar}</div>'
        f'<div class="detail">{detail}</div>'
        f'{theme.chips(privacy["redactions_by_type"]) if removed else ""}</div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="shield fail"><div class="title">Privacy check failed: this report '
        'stays private</div><div class="title-ar">فشل فحص الخصوصية: لن تتم مشاركة التقرير'
        '</div><div class="detail">After sanitization the second pass still found '
        f'<strong>{len(privacy["residual_findings"])}</strong> identifying value(s). The text was '
        'not sent to any AI model, and it cannot be shared. Edit the report and analyze '
        'it again.</div></div>',
        unsafe_allow_html=True,
    )
    st.error("Residual findings: " + "; ".join(privacy["residual_findings"]))

left, right = st.columns([3, 2])
with left:
    with st.expander("View the sanitized report: this is all the system ever sees"):
        st.markdown(f'<div class="sig-box">{highlight_redactions(privacy["sanitized_text"])}'
                    '</div>', unsafe_allow_html=True)
with right:
    with st.expander(f"What was removed: {removed} value(s)"):
        if privacy["audit"]:
            st.dataframe(
                [{"Token": row["token"], "Type": row["type"], "Original": row["original_preview"]}
                 for row in privacy["audit"]],
                width="stretch", hide_index=True,
            )
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
    headline = f"{attack} via {vector}"
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
        rows.append((theme.ACCENT, "Closest incident in shared memory",
                     f"<strong>{best['similarity']:.0%}</strong> — {best['title']} "
                     f"<em>({origin})</em>"))
    else:
        rows.append((theme.INK_MUTED, "Closest incident in shared memory",
                     "<em>Nothing close enough: this pattern is new to shared memory.</em>"))

    recommended = mitigations.get("recommended") or []
    if recommended:
        first = recommended[0]
        track = (f" <em>· {first['avg_effectiveness']:.0%} average effectiveness across "
                 f"{first['times_used']} past incident(s)</em>"
                 if first.get("avg_effectiveness") is not None else
                 " <em>· baseline control, no recorded outcome yet</em>")
        rows.append((theme.SERIES[2], "Do this first", f"{first['action']}{track}"))

    row_html = "".join(
        f'<div class="row"><span class="rule" style="background:{colour}"></span>'
        f'<span><span class="k">{key}</span><span class="v">{value}</span></span></div>'
        for colour, key, value in rows
    )
    return (
        f'<div class="verdict">'
        f'<div class="headline">{headline}</div>'
        f'<div class="sub">{dna["sector"].title()} sector · '
        f'{len(dna["techniques"])} ATT&CK techniques · severity '
        f'{dna["severity"]}</div>{row_html}</div>'
    )


st.divider()
st.markdown(theme.stage("3", "Attack DNA and shared memory", "البصمة والحوادث المشابهة"),
            unsafe_allow_html=True)
st.markdown(verdict_card(), unsafe_allow_html=True)

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
    st.markdown(theme.facts([
        ("Attack type", dna["attack_type"].replace("_", " ").title()),
        ("Initial vector", (dna.get("initial_vector") or "unknown").replace("_", " ").title()),
        ("Sector", dna["sector"].title()),
        ("ATT&CK techniques", str(len(dna["techniques"]))),
        ("Severity", theme.severity_pill(dna["severity"])),
    ]), unsafe_allow_html=True)

    st.markdown("**DNA signature**: the part that would be shared")
    st.markdown(f'<div class="sig-box">{dna["signature"]}</div>', unsafe_allow_html=True)
    st.caption(f"Extraction mode: {dna.get('extraction_mode', 'rule-based')} · {dna['summary']}")

    kill_chain = " → ".join(TACTIC_LABELS.get(t, t.title()) for t in dna["tactics"]) or "—"
    impacts = ", ".join(i.replace("_", " ").title() for i in dna["impacts"]) or "None recorded"
    st.markdown(f"**Kill chain** · {kill_chain}")
    st.markdown(f"**Impact** · {impacts}")

    st.markdown("**MITRE ATT&CK mapping, with the evidence for each technique**")
    st.dataframe(
        [{
            "Technique": t["id"],
            "Name": t["name"],
            "Tactic": TACTIC_LABELS.get(t["tactics"][0], "—") if t["tactics"] else "—",
            "Confidence": t["confidence"],
            "Evidence": ", ".join(t["evidence"][:3]) or "—",
        } for t in dna["techniques"]],
        width="stretch", hide_index=True,
    )

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
                rows = ([{"Kind": "Group", "Name": f"{g['id']} {g['name']}",
                          "Overlap": f"{g['coverage']:.0%}", "Confidence": g["confidence"]}
                         for g in attribution["groups"]]
                        + [{"Kind": "Software", "Name": f"{s['id']} {s['name']}",
                            "Overlap": f"{s['coverage']:.0%}", "Confidence": s["confidence"]}
                           for s in attribution["software"]])
                st.dataframe(rows, width="stretch", hide_index=True)

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
            header = (f"{match['similarity']:.0%} — {match['title']} · {match['severity']}")
            with st.expander(header, expanded=index == 0):
                st.markdown(theme.provenance_pill(match.get("provenance"),
                                                  yours=match.get("from_your_organisation")),
                            unsafe_allow_html=True)
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
                    st.dataframe(
                        [{"Phase": m["category"], "Action": m["action"],
                          "Effectiveness": m["effectiveness"], "Notes": m["notes"] or ""}
                         for m in match["mitigations"]],
                        width="stretch", hide_index=True,
                    )

                score_cols = st.columns(3)
                score_cols[0].metric("Combined", f"{match['similarity']:.0%}")
                score_cols[1].metric("Semantic", f"{match['semantic_similarity']:.0%}",
                                     help="Embedding similarity of the Attack DNA")
                score_cols[2].metric("Structural", f"{match['structural_similarity']:.0%}",
                                     help="Shared techniques, tactics, attack type, "
                                          "sector and CVEs")

with tab_response:
    st.caption(
        f"**{mitigations['recalled_count']}** action(s) recalled from incidents in shared memory, "
        f"**{mitigations['suggested_count']}** baseline control(s) added where memory had no "
        "coverage. Every recalled action names the incident it came from."
    )
    for group in mitigations["by_phase"]:
        st.markdown(f"#### {group['label']}")
        for action in group["actions"]:
            origin_class = "pill-recalled" if action["origin"] == "recalled" else "pill-baseline"
            origin_label = (f"recalled · used in {action['times_used']} past incident(s)"
                            if action["origin"] == "recalled" else "baseline control")
            effectiveness = (f" · avg effectiveness {action['avg_effectiveness']:.0%}"
                             if action.get("avg_effectiveness") is not None else "")
            st.markdown(
                f'<span class="pill {origin_class}">{origin_label}{effectiveness}</span> '
                f'{action["action"]}',
                unsafe_allow_html=True,
            )
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
            st.dataframe(
                [{"ID": m["id"], "Mitigation": m["name"], "Covers": m["coverage_count"],
                  "Techniques": ", ".join(m["covers_techniques"])} for m in framework],
                width="stretch", hide_index=True,
            )

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
st.markdown(theme.stage("4", "Share with other organisations (optional)",
                        "المشاركة مع المؤسسات الأخرى (اختياري)"), unsafe_allow_html=True)

if analysis.get("decision") == "shared":
    receipt = analysis["receipt"] or {}
    if receipt.get("already_shared"):
        st.info("Your organisation had already shared this incident, so it was not added "
                "a second time.")
    st.success(
        "**Added to shared memory as an anonymous fingerprint.** Other organisations facing "
        "this pattern will now recall it, with your response, and see neither your name nor "
        "your report.\n\nتمت إضافة البصمة إلى الذاكرة المشتركة دون هوية المؤسسة."
    )
    st.caption(f"Recorded as “{receipt.get('title', '')}” · "
               f"{receipt.get('shared', {}).get('mitigations', 0)} response action(s) shared · "
               "withheld: " + ", ".join(receipt.get("withheld", [])))
    st.stop()

if analysis.get("decision") == "private":
    st.info("**Kept private.** Nothing from this analysis was stored. "
            "تم الاحتفاظ بالتحليل بشكل خاص ولم يُخزَّن أي شيء.")
    if st.button("Reconsider sharing"):
        analysis["decision"] = None
        st.rerun()
    st.stop()

st.markdown("Nothing has been stored yet. If your security team approves, the fingerprint "
            "of this incident joins shared memory, so the next organisation hit by the same "
            "pattern recalls it and sees what worked for you.")
techniques_preview = ", ".join(t["id"] for t in dna["techniques"][:6]) or "none"
st.markdown(
    '<div class="consent">'
    '<div class="col share"><h4>Shared · يُشارك</h4><ul>'
    f'<li>Attack type and entry vector: {dna["attack_type"].replace("_", " ")}, '
    f'{(dna.get("initial_vector") or "unknown").replace("_", " ")}</li>'
    f'<li>ATT&amp;CK techniques and tactics: {techniques_preview}</li>'
    '<li>Sector, severity, CVEs and impacts</li>'
    '<li>The sanitized summary, with redaction tokens in place of identifiers</li>'
    '<li>The response actions you add below, sanitized as well</li></ul></div>'
    '<div class="col keep"><h4>Never leaves · لا يغادر المؤسسة</h4><ul>'
    '<li>The original report and file</li>'
    '<li>Your organisation\'s name (stored only as a pseudonym that cannot be read back)</li>'
    f'<li>The {removed} identifying value(s) removed in step 2</li>'
    '<li>The incident date: shared records carry only the month they were shared</li>'
    '</ul></div></div>',
    unsafe_allow_html=True,
)

with st.expander("Add what your team did (recommended): it is what helps the next "
                 "organisation most"):
    st.caption("One row per action. Free text is sanitized again before it is stored.")
    edited = st.data_editor(
        [{"Action": "", "Phase": "contain", "Effectiveness %": None} for _ in range(3)],
        num_rows="dynamic", width="stretch", hide_index=True, key="team_actions",
        column_config={
            "Action": st.column_config.TextColumn("Action", width="large"),
            "Phase": st.column_config.SelectboxColumn("Phase", options=PHASES),
            "Effectiveness %": st.column_config.NumberColumn(
                "Effectiveness %", min_value=0, max_value=100, step=5,
                help="How well it worked, in your team's judgement"),
        },
    )

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
    team_actions = []
    for row in edited or []:
        action = (row.get("Action") or "").strip()
        if len(action) < 3:
            continue
        effectiveness = row.get("Effectiveness %")
        team_actions.append({
            "action": action, "category": row.get("Phase") or "contain",
            "effectiveness": (float(effectiveness) / 100
                              if effectiveness not in (None, "") else None),
        })
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
