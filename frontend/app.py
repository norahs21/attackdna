"""ATTACKDNA: the security team's interface.

Who uses this screen: the security team of a member organisation, holding an
incident report about an attack on their own organisation. The interface is a
working tool for that team, not a guided demo: no tour, no prepared scenarios,
no explanations it does not need.

Three pages:

    Analyze a report   attach a report; see the identity removed first, then the
                       Attack DNA, similar incidents and the recommended response
    Dashboard          what shared memory holds, in aggregate
    Ask the memory     a question answered only from what memory holds

Two switches at the foot of the navigation rail: "Add to memory", which, when
on, adds each analysed report's fingerprint to shared memory as part of the
analysis (turning it on is the team's approval), and "Dark mode".

The organisation this installation belongs to is configuration
(ATTACKDNA_ORGANISATION in backend/.env), as it would come from a login in a
deployed platform. The interface is English only, with day and night modes.

The app calls the pipeline in-process by default, so the demo needs a single
command and cannot fail because a second server did not start. Set
ATTACKDNA_API_URL to drive the FastAPI service over HTTP instead.
"""
from __future__ import annotations

import base64
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

from app.config import ORGANISATION  # noqa: E402
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
ASSETS = Path(__file__).resolve().parent / "assets"

PAGES = ["Analyze a report", "Dashboard", "Ask the memory"]

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


@st.cache_data
def logo_uri(variant: str) -> str:
    path = ASSETS / f"logo_{variant}.png"
    if not path.exists():
        return ""
    return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


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


def run_analysis(text: str, top_k: int, use_llm: bool, simulation: bool = True) -> dict:
    """Analyze without storing anything: adding to memory is a separate decision."""
    if API_URL:
        import requests

        response = requests.post(
            f"{API_URL}/incidents/analyze",
            json={"text": text, "top_k": top_k, "use_llm": use_llm,
                  "include_simulation": simulation, "organisation": ORGANISATION or None},
            timeout=120,
        )
        response.raise_for_status()
        return response.json()

    session = SessionLocal()
    try:
        return analyze(session, text, top_k=top_k, use_llm=use_llm,
                       include_simulation=simulation, viewer_ref=pseudonym(ORGANISATION))
    finally:
        session.close()


def run_contribution(result: dict, text: str, mitigations: list, use_llm: bool) -> dict:
    """Add the fingerprint to shared memory: the team's explicit decision."""
    if API_URL:
        import requests

        response = requests.post(
            f"{API_URL}/incidents/contribute",
            json={"text": text, "organisation": ORGANISATION or None,
                  "mitigations": mitigations, "use_llm": use_llm},
            timeout=120,
        )
        if response.status_code == 422:
            raise PrivacyGateError(response.json().get("detail", "Refused by the privacy gate"))
        response.raise_for_status()
        return response.json()

    session = SessionLocal()
    try:
        return contribute(session, result, organisation=ORGANISATION, mitigations=mitigations)
    finally:
        session.close()


def highlight_redactions(text: str) -> str:
    """Make the redaction tokens the first thing the eye lands on."""
    import html
    import re

    escaped = html.escape(text)
    return re.sub(r"\[([A-Z_]+_REDACTED(?:_\d+)?)\]",
                  r'<span class="redact">[\1]</span>', escaped).replace("\n", "<br>")


def html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def report_input(key: str):
    """One attach area and a paste fallback. Returns (text, source) or (None, None)."""
    uploaded = st.file_uploader(
        "Incident report", type=SUPPORTED_EXTENSIONS, key=f"{key}_file",
        label_visibility="collapsed",
        help="PDF, Word (.docx) or text. Read in memory, never stored.",
    )
    with st.expander("Paste the report text instead"):
        pasted = st.text_area("Report text", key=f"{key}_text", height=200,
                              label_visibility="collapsed",
                              placeholder="Paste the incident report here.")
    return uploaded, pasted


def read_input(uploaded, pasted):
    """The report's text and where it came from, or an error message."""
    if uploaded is not None:
        try:
            read = read_report(uploaded.name, uploaded.getvalue())
            return read.text, uploaded.name, None
        except UnreadableReport as exc:
            return None, None, str(exc)
    text = (pasted or "").strip()
    if len(text) < 40:
        return None, None, "Attach an incident report, or paste one of at least a couple of sentences."
    return text, "pasted text", None


def privacy_banner(privacy: dict, source: str) -> None:
    removed = privacy["total_redactions"]
    if privacy["verified_clean"]:
        title = ("Sensitive information removed successfully" if removed
                 else "No sensitive information found")
        detail = (f"<strong>{removed}</strong> identifying value(s) removed from "
                  f"<em>{theme.esc(source)}</em> before any analysis ran.")
        html(f'<div class="shield"><div class="title">{title}</div>'
             f'<div class="detail">{detail}</div>'
             f'{theme.chips(privacy["redactions_by_type"]) if removed else ""}</div>')
    else:
        html('<div class="shield fail"><div class="title">Privacy check failed: this report '
             'stays private</div><div class="detail">The second pass still found '
             f'<strong>{len(privacy["residual_findings"])}</strong> identifying value(s). The text '
             'was not sent to any AI model and cannot be added to memory.</div></div>')
        st.error("Residual findings: " + "; ".join(privacy["residual_findings"]))


def privacy_details(privacy: dict) -> None:
    left, right = st.columns([3, 2])
    with left:
        with st.expander("Sanitized report"):
            html(f'<div class="sig-box">{highlight_redactions(privacy["sanitized_text"])}</div>')
    with right:
        with st.expander(f"Removed values ({privacy['total_redactions']})"):
            if privacy["audit"]:
                html(theme.table([{"Token": row["token"], "Type": row["type"],
                                   "Original": row["original_preview"]}
                                  for row in privacy["audit"]]))
            else:
                st.caption("None.")


def verdict_card(dna: dict, similar: list, mitigations: dict) -> str:
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
        rows.append(("var(--accent)", "Closest incident in memory",
                     f"<strong>{best['similarity']:.0%}</strong> — {theme.esc(best['title'])} "
                     f"<em>({origin})</em>"))
    else:
        rows.append(("var(--muted)", "Closest incident in memory",
                     "<em>Nothing close enough: this pattern is new to memory.</em>"))
    recommended = mitigations.get("recommended") or []
    if recommended:
        first = recommended[0]
        track = (f" <em>· {first['avg_effectiveness']:.0%} average effectiveness across "
                 f"{first['times_used']} past incident(s)</em>"
                 if first.get("avg_effectiveness") is not None else
                 " <em>· baseline control</em>")
        rows.append(("var(--good)", "Do this first", f"{theme.esc(first['action'])}{track}"))
    row_html = "".join(
        f'<div class="row"><span class="rule" style="background:{colour}"></span>'
        f'<span><span class="k">{key}</span><span class="v">{value}</span></span></div>'
        for colour, key, value in rows)
    return (f'<div class="verdict"><div class="headline">{attack} via {vector}</div>'
            f'<div class="sub">{dna["sector"].title()} sector · {len(dna["techniques"])} ATT&CK '
            f'techniques · severity {dna["severity"]}</div>{row_html}</div>')


# --------------------------------------------------------------------------
# Navigation rail
# --------------------------------------------------------------------------
bootstrap()
memory = vector_memory.memory_stats()
counts = corpus_provenance()

with st.sidebar:
    logo = logo_uri("dark" if mode == "dark" else "light")
    if logo:
        html(f'<div class="brand-logo"><img src="{logo}" alt="ATTACKDNA"/></div>')
    else:
        html(theme.brand())
    page = st.radio("Page", PAGES, key="page", label_visibility="collapsed")

    st.divider()
    html(theme.side_head("Memory"))
    html(theme.mini_stats([
        ("Incidents", memory["incidents_in_memory"]),
        ("Shared", counts.get("shared", 0)),
        ("Real", counts.get("public", 0)),
        ("Synthetic", counts.get("synthetic", 0)),
    ]))

    with st.expander("Settings"):
        use_llm = st.toggle("Use LLM enrichment", value=llm_client.is_available(),
                            disabled=not llm_client.is_available())
        if llm_client.is_available():
            st.caption(f"{llm_client.provider_name().title()} · `{llm_client.active_model()}`")
        else:
            status = llm_status()
            st.caption("Offline mode.")
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
        if ORGANISATION:
            st.caption("Organisation: configured")
        if API_URL:
            st.caption(f"API mode: `{API_URL}`")

    st.divider()
    # Switched on before a report is analysed, it adds that report's fingerprint
    # to shared memory as part of the same analysis. Turning it on is the
    # security team's approval; a report that fails the privacy check is never
    # added, whatever the switch says.
    st.toggle("Add to memory", key="add_to_memory", value=False,
              help="Shared: the attack's fingerprint, the sanitized summary and the response "
                   "actions you list. Never shared: the original report, your organisation's "
                   "name, the removed identifiers or the incident date.")
    st.toggle("Dark mode", key="dark_mode", value=True)


def backend_tag() -> str:
    return theme.status_tag(f"{memory['incidents_in_memory']} incidents in memory")


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
if page == "Dashboard":
    html(theme.page_head("Memory dashboard", "", [backend_tag()]))
    dashboard.render(corpus_overview(), memory, corpus_incidents(), mode)
    st.stop()


# --------------------------------------------------------------------------
# Ask the memory
# --------------------------------------------------------------------------
if page == "Ask the memory":
    html(theme.page_head("Ask the memory", "", [backend_tag()]))

    # The interface is English only; the backend still answers Arabic questions.
    suggestions = [q for q in rag_qa.suggested_questions() if q.isascii()]
    picked = st.selectbox("Example questions", ["— write my own —"] + suggestions, index=1)
    default_question = "" if picked.startswith("—") else picked
    question = st.text_input(
        "Your question", value=default_question,
        placeholder="e.g. What worked against ransomware in the finance sector?",
        key=f"q_{picked}",
    )
    asked = st.button("Ask", type="primary", width="stretch")
    if not asked or not question.strip():
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
        st.error(f"**{len(answer['unverified_citations'])} citation(s) were rejected** because "
                 "they referenced incidents that were not retrieved.")

    if answer["sources"]:
        st.markdown("#### Sources")
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
    st.stop()


# --------------------------------------------------------------------------
# Analyze a report
# --------------------------------------------------------------------------
adding = bool(state.get("add_to_memory"))
tags = [backend_tag()] + ([theme.status_tag("Add to memory: on")] if adding else [])
html(theme.page_head("Analyze an incident report", "", tags))
uploaded, pasted = report_input("analyze")
if adding:
    team_text = st.text_area(
        "Response actions to share (optional, one per line)", key="team_actions", height=90,
        placeholder="Isolated the affected hosts\nReset the compromised accounts")
run = st.button("Analyze and add to memory" if adding else "Analyze",
                type="primary", width="stretch")

if run:
    text, source, problem = read_input(uploaded, pasted)
    if problem:
        st.error(problem)
        st.stop()
    with st.spinner("Removing identifying information, then extracting the Attack DNA…"):
        try:
            result = run_analysis(text, top_k, use_llm)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Analysis failed: {exc}")
            st.stop()
    receipt, refused = None, None
    # Similar incidents were found before the report is added, so it never
    # recalls itself.
    if adding and result["privacy"]["verified_clean"]:
        actions = [{"action": line.strip(), "category": "contain"}
                   for line in (team_text or "").splitlines() if len(line.strip()) >= 3]
        try:
            receipt = run_contribution(result, text if API_URL else "", actions, use_llm)
        except PrivacyGateError as exc:
            refused = str(exc)
    elif adding:
        refused = "Not added to memory: the privacy check did not pass."
    state["analysis"] = {"result": result, "source": source, "receipt": receipt,
                         "refused": refused}
    if receipt:
        st.rerun()   # so the memory figures in the rail include the new incident

analysis = state.get("analysis")
if not analysis:
    st.stop()

result = analysis["result"]
privacy = result["privacy"]
dna = result["dna"]
similar = result["similar_incidents"]
mitigations = result["mitigations"]
simulation = result.get("simulation")

st.divider()
privacy_banner(privacy, analysis["source"])
privacy_details(privacy)
if result["meta"].get("llm_blocked_by_privacy_gate"):
    st.warning("The LLM was not used for this report because the privacy check did not pass.")

html(verdict_card(dna, similar, mitigations))

receipt = analysis.get("receipt")
if receipt:
    if receipt.get("already_shared"):
        st.info("Already in shared memory; not added again.")
    else:
        st.success(f"**Added to shared memory** as “{receipt.get('title', '')}”"
                   + (f", with {receipt['shared']['mitigations']} response action(s)."
                      if receipt.get("shared", {}).get("mitigations") else "."))
elif analysis.get("refused"):
    st.error(analysis["refused"])

actions_left, _spacer = st.columns([1, 3])
with actions_left:
    st.download_button("Download report", data=report_builder.build(result),
                       file_name=report_builder.filename(dna), mime="text/markdown",
                       width="stretch")

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
    st.markdown("**DNA signature**")
    html(f'<div class="sig-box">{theme.esc(dna["signature"])}</div>')
    st.caption(dna["summary"])

    kill_chain = " → ".join(TACTIC_LABELS.get(t, t.title()) for t in dna["tactics"]) or "—"
    impacts = ", ".join(i.replace("_", " ").title() for i in dna["impacts"]) or "None recorded"
    st.markdown(f"**Kill chain** · {kill_chain}")
    st.markdown(f"**Impact** · {impacts}")

    st.markdown("**MITRE ATT&CK techniques**")
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
                st.markdown(f"**Shareable**: {iocs['shareable_count']} indicator(s)")
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
                st.markdown(f"**Victim-linked**: {iocs['redacted_count']} indicator(s) removed")
                for entry in iocs["redacted_indicators"]:
                    st.markdown(f"- {entry['distinct_count']} distinct **{entry['label']}**")
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

with tab_memory:
    if not similar:
        st.warning("No similar incidents in memory yet.")
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
