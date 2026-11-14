"""ATTACKDNA: the security team's interface.

Who uses this screen: the security team of a member organisation, holding an
incident report about an attack on their own organisation. The interface is a
working tool for that team, not a guided demo: no tour, no prepared scenarios,
no explanations it does not need.

Three pages:

    Analyze a report   attach a report; the result reads top to bottom in four
                       sections: 1 identity removed, 2 Attack DNA, 3 similar
                       attacks in memory and what worked, 4 what to do
    Dashboard          what shared memory holds, in aggregate
    Ask the memory     describe what has happened so far; memory answers with
                       what worked, attackers who got in the same way, and
                       what they did next

This is a prototype: it shows the core flow only. Parts the pipeline computes
but the screen does not show yet (threat-actor resemblance, indicators,
official ATT&CK mitigations, the tabletop exercise, the downloadable report,
LLM settings) are future work, kept in the backend and its tests.

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
from app.services import corpus_stats, guidance, llm_client, vector_memory  # noqa: E402
from app.services.contributors import pseudonym  # noqa: E402
from app.services.document_reader import (  # noqa: E402
    SUPPORTED_EXTENSIONS, UnreadableReport, read_report,
)
from app.services.knowledge_base import TACTIC_LABELS  # noqa: E402

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


def section(number: int, title: str) -> None:
    """A numbered section heading: the result reads top to bottom."""
    st.markdown(f"### {number} · {title}")


def origin_note(match: dict) -> str:
    if match.get("from_your_organisation"):
        return "your organisation's earlier incident"
    if match.get("provenance") == "shared":
        return "shared by another organisation · identity withheld"
    if match.get("provenance") == "public":
        return "real documented breach"
    return "past incident"


def action_track(action: dict) -> tuple:
    """The label beside a recommended action, and its pill colour."""
    if action.get("origin") == "recalled":
        label = f"worked before · used in {action['times_used']} past incident(s)"
        if action.get("avg_effectiveness") is not None:
            label += f" · avg effectiveness {action['avg_effectiveness']:.0%}"
        return label, "accent"
    return "baseline control", "neutral"


# --------------------------------------------------------------------------
# Navigation rail
# --------------------------------------------------------------------------
bootstrap()
memory = vector_memory.memory_stats()
# No settings on screen in the prototype: the LLM is used only if a key is
# configured in backend/.env, and five similar incidents are recalled.
use_llm = llm_client.is_available()
top_k = 5
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
    situation = st.text_area(
        "What has happened so far?", key="situation", height=140,
        placeholder="e.g. A user clicked a link in an email, PowerShell ran on their laptop, "
                    "and we now see logins to other machines.")
    asked = st.button("Ask", type="primary", width="stretch")
    if not asked:
        st.stop()
    if len((situation or "").strip()) < 20:
        st.error("Describe what has happened so far in a sentence or two.")
        st.stop()

    # The description goes through the same pipeline as a report: identifying
    # values are removed first, and nothing is stored.
    with st.spinner("Searching memory..."):
        try:
            result = run_analysis(situation, top_k, use_llm, simulation=False)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Search failed: {exc}")
            st.stop()
    privacy = result["privacy"]
    if not privacy["verified_clean"]:
        privacy_banner(privacy, "your description")
        st.stop()
    if privacy["total_redactions"]:
        st.caption(f"{privacy['total_redactions']} identifying value(s) were removed from "
                   "your description before memory was searched.")
    if not result["similar_incidents"]:
        st.warning("Nothing in memory is close enough to this situation yet.")
        st.stop()

    advice = guidance.build(result)

    section(1, "What worked against this")
    for item in advice["what_worked"]:
        label, kind = action_track(item)
        html(f'{theme.pill(label, kind)} {theme.esc(item["action"])}')
        if item["sources"]:
            st.caption("Source: " + ", ".join(item["sources"]))

    vector = (result["dna"].get("initial_vector") or "unknown").replace("_", " ")
    section(2, f"Attackers who got in the same way ({vector})")
    if not advice["same_entry"]:
        st.caption("No incident in memory started the same way.")
    for index, entry in enumerate(advice["same_entry"]):
        with st.expander(f"{entry['similarity']:.0%} — {entry['title']}", expanded=index == 0):
            html(theme.provenance_pill(entry.get("provenance"),
                                       yours=entry.get("from_your_organisation")))
            st.markdown("**What the attacker did:** " + (" → ".join(entry["chain"]) or "—"))
            if entry["techniques"]:
                st.caption("Techniques: " + ", ".join(entry["techniques"]))
            if entry["worked"]:
                st.markdown("**What worked**")
                for done in entry["worked"]:
                    score = (f" ({done['effectiveness']:.0%} effective)"
                             if done.get("effectiveness") is not None else "")
                    st.markdown(f"- {done['action']}{score}")

    nxt = advice["next_steps"]
    section(3, "What attackers did next in similar incidents")
    st.caption("A record of what happened in similar past incidents, not a prediction."
               + (f" So far this attack has reached: {nxt['reached']}." if nxt["reached"] else ""))
    if not nxt["steps"]:
        st.caption("No later stage was recorded in the similar incidents.")
    for step in nxt["steps"]:
        examples = f" · e.g. {', '.join(step['examples'])}" if step["examples"] else ""
        st.markdown(f"- **{step['tactic']}** — in {step['incidents']} of "
                    f"{nxt['out_of']} similar incidents{examples}")
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
            result = run_analysis(text, top_k, use_llm, simulation=False)
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

st.divider()

# 1 — the identity is removed before anything else happens.
section(1, "Sensitive information removed")
privacy_banner(privacy, analysis["source"])
privacy_details(privacy)
if result["meta"].get("llm_blocked_by_privacy_gate"):
    st.warning("The LLM was not used for this report because the privacy check did not pass.")

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

# 2 — the attack's behaviour, without the victim.
section(2, "Attack DNA of this report")
attack = dna["attack_type"].replace("_", " ").title()
vector = (dna.get("initial_vector") or "unknown").replace("_", " ")
html(f'<div class="verdict"><div class="headline">{theme.esc(attack)} via {theme.esc(vector)}'
     f'</div></div>')
html(theme.facts([
    ("Attack type", theme.esc(attack)),
    ("Initial vector", theme.esc(vector.title())),
    ("ATT&CK techniques", str(len(dna["techniques"]))),
    ("Severity", theme.severity_pill(dna["severity"])),
]))
kill_chain = " → ".join(TACTIC_LABELS.get(t, t.title()) for t in dna["tactics"]) or "—"
impacts = ", ".join(i.replace("_", " ").title() for i in dna["impacts"]) or "None recorded"
st.markdown(f"**Kill chain** · {kill_chain}")
st.markdown(f"**Impact** · {impacts}")
st.markdown("**MITRE ATT&CK techniques**")
html(theme.table([{
    "Technique": t["id"],
    "Name": t["name"],
    "Tactic": TACTIC_LABELS.get(t["tactics"][0], "—") if t["tactics"] else "—",
    "Evidence": ", ".join(t["evidence"][:3]) or "—",
} for t in dna["techniques"]], strong={"Technique"}))
known_exploited = [c for c in dna["cve_details"] if c["known_exploited"]]
for cve in known_exploited:
    st.error(f"**{cve['cve']} — known exploited in the wild (CISA KEV).** "
             f"{cve['vendor']} {cve['product']}. {cve['required_action']}")

# 3 — the same behaviour in memory: what happened, what they did, what worked.
section(3, f"Similar attacks in memory ({len(similar)})")
if not similar:
    st.warning("Nothing in memory is close enough: this pattern is new to memory.")
for index, match in enumerate(similar):
    header = f"{match['similarity']:.0%} — {match['title']} · {origin_note(match)}"
    with st.expander(header, expanded=index == 0):
        html(theme.provenance_pill(match.get("provenance"),
                                   yours=match.get("from_your_organisation")))
        if match.get("source_url"):
            st.caption(f"Source: [{match.get('source_name')}]({match['source_url']})")
        st.markdown("**Why this matched**")
        for reason in match["match_reasons"]:
            st.markdown(f"- {reason}")
        st.markdown("**What happened**")
        st.write(match["summary"] or "—")
        if match["mitigations"]:
            st.markdown("**What they did, and how well it worked**")
            html(theme.table(
                [{"Phase": m["category"], "Action": m["action"],
                  "Effectiveness": f"{m['effectiveness']:.0%}"
                  if m["effectiveness"] is not None else "—"}
                 for m in match["mitigations"]], numeric={"Effectiveness"}))

# 4 — what to do if this attack is met again.
section(4, "If you face this attack: what to do")
for group in mitigations["by_phase"]:
    st.markdown(f"#### {group['label']}")
    for action in group["actions"]:
        label, kind = action_track(action)
        html(f'{theme.pill(label, kind)} {theme.esc(action["action"])}')
        if action["sources"]:
            names = ", ".join(f"{s['title']} ({s['similarity']:.0%})"
                              + (" · shared by another organisation"
                                 if s.get("provenance") == "shared" else "")
                              for s in action["sources"][:3])
            st.caption(f"Source: {names}")
