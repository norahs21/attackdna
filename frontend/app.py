"""ATTACKDNA demo interface.

Three modes, one pipeline:

    Analyze    Upload → Privacy Shield → Attack DNA → Memory → Learn → Simulate
    Ask        A question answered only from what memory actually holds
    Dashboard  What the corpus knows, in aggregate

The screen is arranged around one idea: **the verdict comes first, the evidence
comes on request.** A reader who stops after the first card still has the whole
finding — attack type, what was removed, the closest thing memory has seen, and
the action with the best track record against it. Everything below that card is
the evidence for it, and anything that is not load-bearing for the headline
sits inside a collapsed section, because a screen where nothing is emphasised
is a screen where nothing is read.

The app calls the pipeline in-process by default, so the demo needs a single
command and cannot fail because a second server did not start. Set
ATTACKDNA_API_URL to drive the FastAPI service over HTTP instead.
"""
from __future__ import annotations

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
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.config import DEMO_SCENARIOS_PATH  # noqa: E402
from app.db.database import SessionLocal, init_db  # noqa: E402
from app.pipelines.analyze import analyze, ingest  # noqa: E402
from app.services import (  # noqa: E402
    corpus_stats, llm_client, rag_qa, report as report_builder, vector_memory,
)
from app.services.knowledge_base import (  # noqa: E402
    TACTIC_LABELS, cti_available, load_groups, load_kev, load_mitigations, load_techniques,
)

import dashboard  # noqa: E402
import theme  # noqa: E402

API_URL = os.getenv("ATTACKDNA_API_URL", "").rstrip("/")

st.set_page_config(page_title="ATTACKDNA", page_icon="🧬", layout="wide")
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


@st.cache_data
def load_scenarios() -> list:
    """Prepared demo scenarios, each exercising a different part of the pipeline."""
    import json

    if not DEMO_SCENARIOS_PATH.exists():
        return []
    try:
        with open(DEMO_SCENARIOS_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)["scenarios"]
    except (json.JSONDecodeError, OSError, KeyError):
        return []


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


def run_pipeline(text: str, top_k: int, use_llm: bool, persist: bool, title: str | None):
    """Run the six stages, in-process or over HTTP."""
    if API_URL:
        import requests

        endpoint = "/incidents/" if persist else "/incidents/analyze"
        response = requests.post(
            f"{API_URL}{endpoint}",
            json={"text": text, "top_k": top_k, "use_llm": use_llm, "title": title},
            timeout=120,
        )
        response.raise_for_status()
        return response.json()

    session = SessionLocal()
    try:
        if persist:
            return ingest(session, text, title=title, top_k=top_k, use_llm=use_llm)
        return analyze(session, text, top_k=top_k, use_llm=use_llm)
    finally:
        session.close()


def highlight_redactions(text: str) -> str:
    """Make the redaction tokens the first thing the eye lands on."""
    import html
    import re

    escaped = html.escape(text)
    return re.sub(r"\[([A-Z_]+_REDACTED(?:_\d+)?)\]",
                  r'<span class="redact">[\1]</span>', escaped).replace("\n", "<br>")


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------
bootstrap()

with st.sidebar:
    st.markdown("### 🧭 Mode")
    mode = st.radio(
        "Mode", ["Analyze an incident", "Ask the memory", "Memory dashboard"],
        label_visibility="collapsed",
        help="Analyze runs the six-stage pipeline on a report. Ask queries the "
             "incidents already in memory. Dashboard shows what the corpus holds.",
    )

    st.divider()
    st.markdown("### ⚙️ Configuration")
    use_llm = st.toggle("Use LLM enrichment", value=llm_client.is_available(),
                        disabled=not llm_client.is_available())
    if llm_client.is_available():
        st.caption(f"Hybrid mode · {llm_client.provider_name().title()} · "
                   f"`{llm_client.active_model()}`")
    else:
        # A key that is set but not usable is a different problem from no key
        # at all, and saying "no API key set" for both sends the reader looking
        # in the wrong place — the toggle stays greyed out and nothing on
        # screen says why. diagnose() already knows which case it is.
        status = llm_status()
        st.caption("Rule-based mode · every stage still runs; "
                   "extraction is deterministic.")
        if status["stage"] == "no_key":
            st.caption("No API key set — add one to `backend/.env`, then restart.")
        else:
            st.warning(f"**LLM off — {status['detail']}**\n\n{status['remedy']}\n\n"
                       "Run `make check-llm` for the full diagnosis.")

    top_k = st.slider("Similar incidents to retrieve", 1, 10, 5)
    persist = st.toggle("Commit to memory", value=False,
                        help="Store this incident so future incidents can learn from it. "
                             "Only the sanitized text and its DNA are kept.")
    demo_mode = st.toggle("Demo mode", value=True,
                          help="Show presenter notes on what to point at in each scenario.")

    st.divider()
    st.markdown("### 🧠 Memory")
    memory = vector_memory.memory_stats()
    st.metric("Incidents in memory", memory["incidents_in_memory"])

    # Provenance is the answer to "where does the memory come from?", so it is
    # on screen permanently rather than buried in a data file.
    counts = corpus_provenance()
    if counts.get("public"):
        st.caption(f"🟢 **{counts['public']}** real, publicly documented breaches")
    if counts.get("synthetic"):
        st.caption(f"🟠 **{counts['synthetic']}** synthetic incidents")
    if counts.get("internal"):
        st.caption(f"🔵 **{counts['internal']}** your own incidents")
    st.caption(f"Backend: `{memory['backend']}`")

    with st.expander("Knowledge bases"):
        try:
            st.caption(f"ATT&CK techniques: **{len(load_techniques()):,}**")
            st.caption(f"CISA KEV entries: **{len(load_kev()):,}**")
        except FileNotFoundError:
            st.error("Knowledge base missing. Run the download and process scripts.")

        if cti_available():
            st.caption(f"ATT&CK mitigations: **{len(load_mitigations())}**")
            st.caption(f"Threat groups: **{len(load_groups())}**")
        else:
            st.caption("CTI layers not loaded — run `python scripts/process_cti.py`")

        if API_URL:
            st.caption(f"API mode: `{API_URL}`")


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------
st.markdown(
    '<div class="dna-hero"><h1>🧬 ATTACKDNA</h1>'
    '<p>An AI-powered cyber memory that turns past incidents into reusable '
    'attack intelligence.</p>'
    '<p class="ar">ذاكرة سيبرانية تحوّل الحوادث السابقة إلى ذكاء قابل لإعادة الاستخدام</p>'
    '</div>',
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------
# Memory dashboard
# --------------------------------------------------------------------------
if mode == "Memory dashboard":
    st.markdown(theme.stage("◆", "Memory dashboard", "لوحة الذاكرة"),
                unsafe_allow_html=True)
    st.subheader("What this memory holds")
    st.markdown("Aggregate view of the corpus — the answer to *“what does this "
                "system actually know?”* before it is asked to advise on anything.")
    dashboard.render(corpus_overview(), vector_memory.memory_stats(), corpus_incidents())
    st.stop()


# --------------------------------------------------------------------------
# Ask the memory — retrieval-augmented Q&A over the corpus
# --------------------------------------------------------------------------
if mode == "Ask the memory":
    st.markdown(theme.stage("◆", "Ask the memory", "اسأل الذاكرة"), unsafe_allow_html=True)
    st.subheader("Question the incidents you already have")
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

    # The answer, then what it was built from. Anything about *how* the system
    # arrived at it goes last: a reader wants the finding and its evidence
    # adjacent, not separated by statistics about the retrieval.
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
            cited = "✅ cited" if source["incident_id"] in answer["citations"] else "retrieved"
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
                st.caption(f"`{source['incident_id']}`")
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
    st.caption(
        "Incidents are embedded into a vector store, retrieved by meaning, and the answer "
        "is generated strictly from what came back. With no API key the same retrieval runs "
        "and returns a structured digest."
    )
    st.stop()


# --------------------------------------------------------------------------
# ① Analyze an incident — the six-stage pipeline
# --------------------------------------------------------------------------
st.markdown(theme.stage("①", "Upload", "الإدخال"), unsafe_allow_html=True)
st.markdown("Paste an incident report, upload one, or pick a prepared scenario. Names, IPs, "
            "emails and company information can be left in — removing them is the system's "
            "first job.")

scenarios = load_scenarios()
scenario = None
if scenarios:
    labels = [s["label"] for s in scenarios]
    chosen = st.selectbox("Prepared scenario", labels, index=0,
                          help="Each scenario exercises a different part of the pipeline.")
    scenario = next(s for s in scenarios if s["label"] == chosen)

uploaded = st.file_uploader("Incident report", type=["txt", "md", "log"],
                            label_visibility="collapsed")

if uploaded:
    default_text = uploaded.read().decode("utf-8", errors="replace")
elif scenario:
    default_text = scenario["text"]
else:
    default_text = ""

if scenario and demo_mode and not uploaded:
    st.info(f"**{scenario['highlight']}**")
    with st.expander("Presenter notes — what to point at"):
        for note in scenario["watch_for"]:
            st.markdown(f"- {note}")

report = st.text_area("Incident report", value=default_text, height=260,
                      label_visibility="collapsed",
                      key=f"report_{scenario['id'] if scenario else 'blank'}")

run = st.button("Analyze incident", type="primary", width="stretch")

if not run:
    st.stop()

if len(report.strip()) < 40:
    st.error("Paste an incident report of at least a couple of sentences.")
    st.stop()

with st.spinner("Running the pipeline..."):
    try:
        result = run_pipeline(report, top_k, use_llm, persist, title=None)
    except Exception as exc:  # noqa: BLE001
        st.error(f"Pipeline failed: {exc}")
        st.stop()

privacy = result["privacy"]
dna = result["dna"]
similar = result["similar_incidents"]
mitigations = result["mitigations"]
simulation = result.get("simulation")


# --------------------------------------------------------------------------
# The verdict — the whole finding, before any of the evidence for it
# --------------------------------------------------------------------------
def verdict_card() -> str:
    attack = dna["attack_type"].replace("_", " ").title()
    vector = (dna.get("initial_vector") or "unknown").replace("_", " ")
    headline = f"{attack} via {vector}"

    rows = [(
        "🛡️",
        "Privacy",
        f"<strong>{privacy['total_redactions']}</strong> identifying value(s) removed · "
        + ("<em>independently verified clean</em>" if privacy["verified_clean"]
           else "<strong>verification FAILED</strong>"),
    )]

    if similar:
        best = similar[0]
        origin = "real documented breach" if best.get("provenance") == "public" \
            else "past incident"
        rows.append((
            "🧠", "Closest thing memory has seen",
            f"<strong>{best['similarity']:.0%}</strong> — {best['title']} "
            f"<em>({origin})</em>",
        ))
    else:
        rows.append(("🧠", "Closest thing memory has seen",
                     "<em>Nothing close enough — this pattern is new here.</em>"))

    recommended = mitigations.get("recommended") or []
    if recommended:
        first = recommended[0]
        track = (f" <em>· {first['avg_effectiveness']:.0%} average effectiveness across "
                 f"{first['times_used']} past incident(s)</em>"
                 if first.get("avg_effectiveness") is not None else
                 " <em>· baseline control, no recorded outcome yet</em>")
        rows.append(("💊", "Do this first", f"{first['action']}{track}"))

    row_html = "".join(
        f'<div class="row"><span class="ico">{icon}</span>'
        f'<span><span class="k">{key}</span><span class="v">{value}</span></span></div>'
        for icon, key, value in rows
    )
    return (
        f'<div class="verdict">'
        f'<div class="headline">{headline}</div>'
        f'<div class="sub">{dna["sector"].title()} sector · '
        f'{len(dna["techniques"])} ATT&CK techniques · severity '
        f'{dna["severity"]}</div>{row_html}</div>'
    )


if result.get("incident_id"):
    st.success(f"Committed to memory as `{result['incident_id']}`. "
               "Future incidents can now learn from this one.")

st.markdown(theme.stage("✦", "Verdict", "الخلاصة"), unsafe_allow_html=True)
st.markdown(verdict_card(), unsafe_allow_html=True)

download_left, download_right = st.columns([1, 3])
with download_left:
    st.download_button(
        "⬇ Download report",
        data=report_builder.build(result),
        file_name=report_builder.filename(dna),
        mime="text/markdown",
        width="stretch",
    )
with download_right:
    st.caption("A self-contained Markdown report of everything below — the sanitized "
               "incident, its DNA, what memory recalled and the recommended response. "
               "Nothing identifying is in it.")

st.caption("Everything below is the evidence behind that card, stage by stage.")


# --------------------------------------------------------------------------
# ② Privacy Shield
# --------------------------------------------------------------------------
st.divider()
st.markdown(theme.stage("②", "Privacy Shield", "الدرع"), unsafe_allow_html=True)
st.subheader("Nothing identifying leaves the building")

col_a, col_b, col_c = st.columns(3)
col_a.metric("Values removed", privacy["total_redactions"])
col_b.metric("Categories", len(privacy["redactions_by_type"]))
col_c.metric("Verification", "PASS" if privacy["verified_clean"] else "FAIL")

if privacy["verified_clean"]:
    st.caption("A second, independent pass re-scanned the sanitized text for emails, "
               "IP addresses, secrets and financial identifiers and found none.")
else:
    st.error(f"Residual findings: {privacy['residual_findings']}")

st.markdown("**Sanitized incident** — this is what the rest of the system ever sees:")
st.markdown(f'<div class="sig-box">{highlight_redactions(privacy["sanitized_text"])}</div>',
            unsafe_allow_html=True)

with st.expander(f"What was removed — {privacy['total_redactions']} value(s)"):
    if privacy["audit"]:
        st.dataframe(
            [{"Token": row["token"], "Type": row["type"], "Original": row["original_preview"]}
             for row in privacy["audit"]],
            width="stretch", hide_index=True,
        )
        st.caption("Original values are masked here and are never embedded, "
                   "stored in the vector index, or sent to any model.")
    else:
        st.caption("No identifying values were found in this report.")


# --------------------------------------------------------------------------
# ③ Attack DNA
# --------------------------------------------------------------------------
st.divider()
st.markdown(theme.stage("③", "Extract Attack DNA", "البصمة"), unsafe_allow_html=True)
st.subheader("The reusable fingerprint of this attack")

meta_cols = st.columns(5)
meta_cols[0].metric("Attack type", dna["attack_type"].replace("_", " ").title())
meta_cols[1].metric("Initial vector",
                    (dna.get("initial_vector") or "unknown").replace("_", " ").title())
meta_cols[2].metric("Sector", dna["sector"].title())
meta_cols[3].metric("Techniques", len(dna["techniques"]))
meta_cols[4].markdown(f"**Severity**<br>{theme.severity_pill(dna['severity'])}",
                      unsafe_allow_html=True)

st.markdown("**DNA signature**")
st.markdown(f'<div class="sig-box">{dna["signature"]}</div>', unsafe_allow_html=True)
st.caption(f"Extraction mode: {dna.get('extraction_mode', 'rule-based')} · {dna['summary']}")

kill_chain = " → ".join(TACTIC_LABELS.get(t, t.title()) for t in dna["tactics"]) or "—"
impacts = ", ".join(i.replace("_", " ").title() for i in dna["impacts"]) or "None recorded"
st.markdown(f"**Kill chain** · {kill_chain}")
st.markdown(f"**Impact** · {impacts}")

st.markdown("**MITRE ATT&CK mapping**")
st.dataframe(
    [{
        "Technique": t["id"],
        "Name": t["name"],
        "Tactic": TACTIC_LABELS.get(t["tactics"][0], "—") if t["tactics"] else "—",
        "Confidence": t["confidence"],
    } for t in dna["techniques"]],
    width="stretch", hide_index=True,
)

with st.expander("The evidence behind each technique"):
    st.caption("Every mapping is traceable to the phrase in the report that produced it. "
               "Nothing here is inferred without a quotable reason.")
    st.dataframe(
        [{
            "Technique": f"{t['id']} {t['name']}",
            "Confidence": t["confidence"],
            "Evidence": ", ".join(t["evidence"][:4]) or "—",
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
            st.markdown(f"**Shareable** — {iocs['shareable_count']} indicator(s) that "
                        "identify the attacker's tooling and survive sanitization:")
            shareable = iocs["shareable"]
            for entry in shareable["hashes"]:
                st.code(f"{entry['type']}: {entry['value']}", language=None)
            for label, key in [("CVEs", "cves"), ("File artefacts", "file_extensions"),
                               ("Protocols", "protocols"), ("Registry keys", "registry_keys")]:
                if shareable[key]:
                    st.markdown(f"- **{label}:** {', '.join(str(v) for v in shareable[key])}")
            if shareable["ports"]:
                st.markdown(f"- **Ports:** {', '.join(str(p) for p in shareable['ports'])}")
            if not iocs["shareable_count"]:
                st.caption("None identified.")

            st.markdown(f"**Victim-linked** — {iocs['redacted_count']} indicator(s) removed, "
                        "counts retained:")
            for entry in iocs["redacted_indicators"]:
                st.markdown(f"- {entry['distinct_count']} distinct **{entry['label']}**")
            st.caption(iocs["note"])

        if has_attribution:
            st.markdown("**Behavioural resemblance to documented threat activity**")
            st.caption(attribution["caveat"])
            attr_left, attr_right = st.columns(2)
            with attr_left:
                st.markdown("*Threat groups*")
                if attribution["groups"]:
                    st.dataframe(
                        [{"Group": f"{g['id']} {g['name']}",
                          "Overlap": f"{g['coverage']:.0%}",
                          "Shared": g["shared_count"],
                          "Confidence": g["confidence"]} for g in attribution["groups"]],
                        width="stretch", hide_index=True,
                    )
                else:
                    st.caption("No group above the reporting threshold.")
            with attr_right:
                st.markdown("*Malware / tooling*")
                if attribution["software"]:
                    st.dataframe(
                        [{"Software": f"{s['id']} {s['name']}",
                          "Overlap": f"{s['coverage']:.0%}",
                          "Shared": s["shared_count"],
                          "Confidence": s["confidence"]} for s in attribution["software"]],
                        width="stretch", hide_index=True,
                    )
                else:
                    st.caption("No software above the reporting threshold.")
            if attribution["campaigns"]:
                st.caption("Related documented campaigns: " + ", ".join(
                    f"{c['name']} ({c['attributed_to_name']})"
                    for c in attribution["campaigns"][:3]))

validation = dna.get("validation", {})
if validation and not validation.get("valid", True):
    st.warning(f"DNA schema validation reported: {', '.join(validation['problems'])}")


# --------------------------------------------------------------------------
# ④ Memory Search
# --------------------------------------------------------------------------
st.divider()
st.markdown(theme.stage("④", "Memory Search", "الذاكرة"), unsafe_allow_html=True)
st.subheader("Have we seen this attack pattern before?")

if not similar:
    st.warning("No similar incidents in memory yet. Seed the corpus with "
               "`make seed`, or commit incidents as you analyze them.")
else:
    st.caption(f"{len(similar)} similar incident(s) found, ranked by a blend of semantic "
               "similarity and shared structure. Only the closest is open.")
    for index, match in enumerate(similar):
        header = (f"{match['similarity']:.0%} — {match['title']} · {match['severity']} · "
                  f"{match['occurred_at'][:10] if match['occurred_at'] else 'undated'}")
        with st.expander(header, expanded=index == 0):
            st.markdown(theme.provenance_pill(match.get("provenance")),
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

            with st.expander("Match detail"):
                score_cols = st.columns(3)
                score_cols[0].metric("Combined", f"{match['similarity']:.0%}")
                score_cols[1].metric("Semantic", f"{match['semantic_similarity']:.0%}",
                                     help="Embedding similarity of the Attack DNA")
                score_cols[2].metric("Structural", f"{match['structural_similarity']:.0%}",
                                     help="Shared techniques, tactics, attack type, "
                                          "sector and CVEs")
                st.markdown(f'<div class="sig-box">{match["signature"]}</div>',
                            unsafe_allow_html=True)


# --------------------------------------------------------------------------
# ⑤ Learn — Mitigation Memory
# --------------------------------------------------------------------------
st.divider()
st.markdown(theme.stage("⑤", "Learn", "العلاج"), unsafe_allow_html=True)
st.subheader("Recommended response, drawn from what worked before")

st.caption(
    f"**{mitigations['recalled_count']}** action(s) recalled from past incidents, "
    f"**{mitigations['suggested_count']}** baseline control(s) added where memory had "
    "no coverage. Recalled actions cite the incident they came from."
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
            names = ", ".join(
                f"{s['title']} ({s['similarity']:.0%})"
                + (" ⬤" if s.get("provenance") == "public" else "")
                for s in action["sources"][:3]
            )
            st.caption(f"Source: {names}")

framework = mitigations.get("framework_mitigations", [])
if framework:
    with st.expander(f"Official MITRE ATT&CK mitigations — {len(framework)}"):
        st.caption("Authoritative framework controls for the techniques observed, ranked "
                   "by how much of this attack chain each one covers. Generic to every "
                   "organisation — the recalled actions above are specific to yours.")
        st.dataframe(
            [{"ID": m["id"], "Mitigation": m["name"], "Covers": m["coverage_count"],
              "Techniques": ", ".join(m["covers_techniques"])} for m in framework],
            width="stretch", hide_index=True,
        )


# --------------------------------------------------------------------------
# ⑥ Simulate
# --------------------------------------------------------------------------
if simulation:
    st.divider()
    st.markdown(theme.stage("⑥", "Simulate", "المحاكاة"), unsafe_allow_html=True)
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

    with st.expander(f"Exercise injects — {len(simulation['injects'])} steps"):
        for inject in simulation["injects"]:
            st.markdown(f"**Inject {inject['step']} — {inject['phase_label']}** "
                        f"({', '.join(inject['techniques'])})")
            st.markdown(f"*Read to the team:* {inject['inject']}")
            st.markdown(f"*Expected detection:* {inject['expected_detection']} "
                        f"— source: {inject['detection_source']}")
            st.markdown(f"*Decision point:* {inject['decision_point']}")
            for step in inject.get("expected_response_actions", []):
                st.markdown(f"- {step}")
            st.divider()

    st.markdown("**Success criteria**")
    for criterion in simulation["success_criteria"]:
        st.markdown(f"- {criterion}")

st.divider()
st.caption(f"Pipeline mode: {result['meta']['extraction_mode']} · "
           f"Memory backend: {result['meta']['memory']['backend']} · "
           f"{result['meta']['memory']['incidents_in_memory']} incidents in memory")
