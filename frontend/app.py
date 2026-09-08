"""ATTACKDNA demo interface.

One journey, six steps, matching the pipeline exactly:

    Upload → Privacy Shield → Attack DNA → Memory Search → Learn → Simulate

The app calls the pipeline in-process by default, so the demo needs a single
command and cannot fail because a second server did not start. Set
ATTACKDNA_API_URL to drive the FastAPI service over HTTP instead.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.config import LLM_MODEL  # noqa: E402
from app.db.database import SessionLocal, init_db  # noqa: E402
from app.pipelines.analyze import analyze, ingest  # noqa: E402
from app.services import llm_client, vector_memory  # noqa: E402
from app.services.knowledge_base import TACTIC_LABELS, load_kev, load_techniques  # noqa: E402

API_URL = os.getenv("ATTACKDNA_API_URL", "").rstrip("/")

st.set_page_config(page_title="ATTACKDNA", page_icon="🧬", layout="wide")

STYLE = """
<style>
  .block-container { padding-top: 2.2rem; max-width: 1200px; }
  .dna-hero h1 { margin-bottom: .2rem; font-size: 2.5rem; letter-spacing: -.02em; }
  .dna-hero p { color: #8b95a5; font-size: 1.05rem; margin-top: 0; }
  .sig-box {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem;
    background: rgba(127,127,127,.10); border-left: 3px solid #4f8cff;
    padding: .8rem 1rem; border-radius: 6px; word-break: break-word; line-height: 1.7;
  }
  .pill {
    display: inline-block; padding: .18rem .6rem; border-radius: 999px;
    font-size: .74rem; font-weight: 600; margin: .12rem .25rem .12rem 0;
    border: 1px solid rgba(127,127,127,.35);
  }
  .pill-critical { background: rgba(239,68,68,.16);  color: #f87171; border-color: rgba(239,68,68,.4); }
  .pill-high     { background: rgba(249,115,22,.16); color: #fb923c; border-color: rgba(249,115,22,.4); }
  .pill-medium   { background: rgba(234,179,8,.16);  color: #facc15; border-color: rgba(234,179,8,.4); }
  .pill-low      { background: rgba(34,197,94,.16);  color: #4ade80; border-color: rgba(34,197,94,.4); }
  .pill-recalled { background: rgba(79,140,255,.16); color: #7aa8ff; border-color: rgba(79,140,255,.4); }
  .pill-baseline { background: rgba(127,127,127,.14); color: #9aa4b2; }
  .redact { color: #f87171; font-weight: 600; }
  .step-head { font-size: .78rem; letter-spacing: .12em; color: #6b7280; text-transform: uppercase; }
</style>
"""
st.markdown(STYLE, unsafe_allow_html=True)

SAMPLE_REPORT = """On 12 February 2026 the SOC at Falcon National Bank detected ransomware on \
WKSTN-FIN-204 in the finance department.

Initial access came from a spearphishing link emailed to sara.nasser@falconbank.com.sa from \
billing@secure-invoice-portal.top. The user clicked the link and entered credentials on a fake login page.

The attacker signed in with the valid account from 91.240.118.22, ran encoded PowerShell, and disabled \
the EDR agent on the host. They moved laterally over SMB shares to FS-CORP-02, deleted shadow copies, \
and files were encrypted across two file servers. Approximately 40 GB of customer data was exfiltrated \
to cloud storage before encryption began. C2 beaconing was observed to 45.83.192.17.

The vulnerability CVE-2024-21412 was exploited on an unpatched host during lateral movement. \
Operations were disrupted for 14 hours. Reported by CISO Ahmed Alrashid, +966 55 123 4567."""


# --------------------------------------------------------------------------
# Backend access
# --------------------------------------------------------------------------
@st.cache_resource
def bootstrap():
    init_db()
    return True


def run_pipeline(text: str, top_k: int, use_llm: bool, persist: bool, title: str | None):
    """Run the pipeline in-process, or against the API when one is configured."""
    if API_URL:
        import requests

        endpoint = f"{API_URL}/incidents/" if persist else f"{API_URL}/incidents/analyze"
        payload = {"text": text, "top_k": top_k, "use_llm": use_llm}
        if persist:
            payload["title"] = title
        response = requests.post(endpoint, json=payload, timeout=120)
        response.raise_for_status()
        return response.json()

    session = SessionLocal()
    try:
        if persist:
            return ingest(session, text, title=title, source="demo",
                          use_llm=use_llm, top_k=top_k)
        return analyze(session, text, top_k=top_k, use_llm=use_llm)
    finally:
        session.close()


def severity_pill(severity: str) -> str:
    return f'<span class="pill pill-{severity}">{severity.upper()}</span>'


def highlight_redactions(text: str) -> str:
    """Render redaction tokens in red so removals are visible at a glance."""
    import html
    import re

    escaped = html.escape(text)
    return re.sub(r"(\[[A-Z_]+_REDACTED(?:_\d+)?\])", r'<span class="redact">\1</span>', escaped)


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------
bootstrap()

with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    use_llm = st.toggle("Use LLM enrichment", value=llm_client.is_available(),
                        disabled=not llm_client.is_available())
    if llm_client.is_available():
        st.caption(f"Hybrid mode · `{LLM_MODEL}`")
    else:
        st.caption("Rule-based mode · no API key set. "
                   "Every stage still runs; extraction is deterministic.")

    top_k = st.slider("Similar incidents to retrieve", 1, 10, 5)
    persist = st.toggle("Commit to memory", value=False,
                        help="Store this incident so future incidents can learn from it. "
                             "Only the sanitized text and its DNA are kept.")

    st.divider()
    st.markdown("### 🧠 Memory")
    memory = vector_memory.memory_stats()
    st.metric("Incidents in memory", memory["incidents_in_memory"])
    st.caption(f"Backend: `{memory['backend']}`")

    try:
        st.caption(f"ATT&CK techniques: **{len(load_techniques()):,}**")
        st.caption(f"CISA KEV entries: **{len(load_kev()):,}**")
    except FileNotFoundError:
        st.error("Knowledge base missing. Run the download and process scripts.")

    if API_URL:
        st.caption(f"API mode: `{API_URL}`")


# --------------------------------------------------------------------------
# Header + input
# --------------------------------------------------------------------------
st.markdown(
    '<div class="dna-hero"><h1>🧬 ATTACKDNA</h1>'
    '<p>An AI-powered cyber memory that turns past incidents into reusable attack intelligence.</p></div>',
    unsafe_allow_html=True,
)

st.markdown('<div class="step-head">① Upload</div>', unsafe_allow_html=True)
st.markdown("Paste an incident report, or upload one. Names, IPs, emails and company "
            "information can be left in — removing them is the system's first job.")

uploaded = st.file_uploader("Incident report", type=["txt", "md", "log"],
                            label_visibility="collapsed")
default_text = uploaded.read().decode("utf-8", errors="replace") if uploaded else SAMPLE_REPORT

report = st.text_area("Incident report", value=default_text, height=260,
                      label_visibility="collapsed")

run = st.button("Analyze incident", type="primary", width="stretch")

if not run:
    st.info("The report above is a synthetic sample. Press **Analyze incident** to run "
            "all six stages of the pipeline.")
    st.stop()

if len(report.strip()) < 20:
    st.error("The report is too short to analyze.")
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

if result.get("incident_id"):
    st.success(f"Committed to memory as `{result['incident_id']}`. "
               "Future incidents can now learn from this one.")

# --------------------------------------------------------------------------
# ② Privacy Shield
# --------------------------------------------------------------------------
st.divider()
st.markdown('<div class="step-head">② Privacy Shield</div>', unsafe_allow_html=True)
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

left, right = st.columns([3, 2])
with left:
    st.markdown("**Sanitized incident** — this is what the rest of the system ever sees:")
    st.markdown(
        f'<div class="sig-box">{highlight_redactions(privacy["sanitized_text"])}</div>',
        unsafe_allow_html=True,
    )
with right:
    st.markdown("**What was removed**")
    if privacy["audit"]:
        st.dataframe(
            [{"Token": row["token"], "Type": row["type"], "Original": row["original_preview"]}
             for row in privacy["audit"]],
            width="stretch", hide_index=True, height=320,
        )
        st.caption("Original values are masked here and are never embedded, "
                   "stored in the vector index, or sent to any model.")
    else:
        st.caption("No identifying values were found in this report.")

# --------------------------------------------------------------------------
# ③ Attack DNA
# --------------------------------------------------------------------------
st.divider()
st.markdown('<div class="step-head">③ Extract Attack DNA</div>', unsafe_allow_html=True)
st.subheader("The reusable fingerprint of this attack")

meta_cols = st.columns(5)
meta_cols[0].metric("Attack type", dna["attack_type"].replace("_", " ").title())
meta_cols[1].metric("Initial vector", (dna.get("initial_vector") or "unknown").replace("_", " ").title())
meta_cols[2].metric("Sector", dna["sector"].title())
meta_cols[3].metric("Techniques", len(dna["techniques"]))
meta_cols[4].markdown(f"**Severity**<br>{severity_pill(dna['severity'])}", unsafe_allow_html=True)

st.markdown("**DNA signature**")
st.markdown(f'<div class="sig-box">{dna["signature"]}</div>', unsafe_allow_html=True)
st.caption(f"Extraction mode: {dna.get('extraction_mode', 'rule-based')} · {dna['summary']}")

tech_col, ctx_col = st.columns([3, 2])
with tech_col:
    st.markdown("**MITRE ATT&CK mapping** — every row shows the evidence behind it")
    st.dataframe(
        [{
            "Technique": t["id"],
            "Name": t["name"],
            "Tactic": TACTIC_LABELS.get(t["tactics"][0], "—") if t["tactics"] else "—",
            "Confidence": t["confidence"],
            "Evidence": ", ".join(t["evidence"][:3]),
        } for t in dna["techniques"]],
        width="stretch", hide_index=True, height=340,
    )

with ctx_col:
    st.markdown("**Kill chain observed**")
    st.write(" → ".join(TACTIC_LABELS.get(t, t.title()) for t in dna["tactics"]) or "—")

    st.markdown("**Impact**")
    st.write(", ".join(i.replace("_", " ").title() for i in dna["impacts"]) or "None recorded")

    st.markdown("**Vulnerabilities · CISA KEV**")
    if dna["cve_details"]:
        for cve in dna["cve_details"]:
            if cve["known_exploited"]:
                st.error(f"**{cve['cve']}** — known exploited")
                st.caption(f"{cve['vendor']} {cve['product']} · added to KEV {cve['date_added_to_kev']}")
                st.caption(f"Required action: {cve['required_action']}")
            else:
                st.info(f"**{cve['cve']}** — not in the KEV catalog")
    else:
        st.caption("No CVEs referenced in this report.")

# --------------------------------------------------------------------------
# ④ Memory Search
# --------------------------------------------------------------------------
st.divider()
st.markdown('<div class="step-head">④ Memory Search</div>', unsafe_allow_html=True)
st.subheader("Have we seen this attack pattern before?")

if not similar:
    st.warning("No similar incidents in memory yet. Seed the corpus with "
               "`python scripts/seed_memory.py --reset`, or commit incidents as you analyze them.")
else:
    st.success(f"**{len(similar)} similar incident(s) found.**")
    for match in similar:
        header = (f"{match['similarity']:.0%} — {match['title']} "
                  f"· {match['severity']} · {match['occurred_at'][:10] if match['occurred_at'] else 'undated'}")
        with st.expander(header, expanded=match is similar[0]):
            score_cols = st.columns(3)
            score_cols[0].metric("Combined", f"{match['similarity']:.0%}")
            score_cols[1].metric("Semantic", f"{match['semantic_similarity']:.0%}",
                                 help="Embedding similarity of the Attack DNA")
            score_cols[2].metric("Structural", f"{match['structural_similarity']:.0%}",
                                 help="Shared techniques, tactics, attack type, sector and CVEs")

            st.markdown("**Why this matched**")
            for reason in match["match_reasons"]:
                st.markdown(f"- {reason}")

            st.markdown("**What happened**")
            st.write(match["summary"] or "—")
            st.markdown(f'<div class="sig-box">{match["signature"]}</div>', unsafe_allow_html=True)

            if match["mitigations"]:
                st.markdown("**What they did about it**")
                st.dataframe(
                    [{
                        "Phase": m["category"],
                        "Action": m["action"],
                        "Effectiveness": m["effectiveness"],
                        "Notes": m["notes"] or "",
                    } for m in match["mitigations"]],
                    width="stretch", hide_index=True,
                )

# --------------------------------------------------------------------------
# ⑤ Learn — Mitigation Memory
# --------------------------------------------------------------------------
st.divider()
st.markdown('<div class="step-head">⑤ Learn</div>', unsafe_allow_html=True)
st.subheader("Recommended response, drawn from what worked before")

st.caption(
    f"**{mitigations['recalled_count']}** action(s) recalled from past incidents, "
    f"**{mitigations['suggested_count']}** baseline control(s) added where memory had no coverage. "
    "Recalled actions cite the incident they came from."
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
                f"{s['title']} ({s['similarity']:.0%})" for s in action["sources"][:3]
            )
            st.caption(f"Source: {names}")

# --------------------------------------------------------------------------
# ⑥ Simulate
# --------------------------------------------------------------------------
if simulation:
    st.divider()
    st.markdown('<div class="step-head">⑥ Simulate</div>', unsafe_allow_html=True)
    st.subheader(simulation["title"])
    st.info(f"**{simulation['safety_notice']}**")

    head = simulation["headline"]
    st.markdown("### Simulation Scenario")
    scenario_cols = st.columns(2)
    with scenario_cols[0]:
        st.markdown(f"**Initial Access:** {head['initial_access']}")
        st.markdown(f"**Technique:** `{head['technique']}`")
        st.markdown(f"**Target:** {head['target']}")
    with scenario_cols[1]:
        st.markdown(f"**Expected Detection:** {head['expected_detection']}")
        st.markdown(f"**Detection Source:** {head['detection_source']}")
        st.markdown(f"**Recommended Controls:** {' + '.join(head['recommended_controls'])}")

    st.markdown(f"**Objective:** {simulation['objective']}")
    st.caption(f"Estimated duration: {simulation['estimated_duration_minutes']} minutes · "
               f"Participants: {', '.join(simulation['participants'])}")

    st.markdown("### Exercise injects")
    for inject in simulation["injects"]:
        with st.expander(f"Inject {inject['step']} — {inject['phase_label']} "
                         f"({', '.join(inject['techniques'])})"):
            st.markdown(f"**Read to the team:** {inject['inject']}")
            st.markdown(f"**Expected detection:** {inject['expected_detection']}  \n"
                        f"*Source: {inject['detection_source']}*")
            st.markdown(f"**Decision point:** {inject['decision_point']}")

    st.markdown("### Success criteria")
    for criterion in simulation["success_criteria"]:
        st.markdown(f"- {criterion}")

st.divider()
st.caption(f"Pipeline mode: {result['meta']['extraction_mode']} · "
           f"Memory backend: {result['meta']['memory']['backend']} · "
           f"{result['meta']['memory']['incidents_in_memory']} incidents in memory")
