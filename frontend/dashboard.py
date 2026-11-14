"""Memory dashboard: what shared memory knows, rather than what one report says.

Every other page answers "what about this incident?". This one answers "what
does this memory actually hold, and is it worth asking?", which is what a
member organisation needs to know before it trusts a recommendation.

What it shows, top to bottom:

    Key figures        incidents, member contributions, techniques covered,
                       response actions with outcomes, identifiers removed
    Timeline           incidents by year, coloured by where they came from
    Composition        member contributions vs real breaches vs synthetic
    Attack mix         a donut of attack types
    Behaviour          most-seen ATT&CK techniques and kill-chain coverage
    Context            entry vectors, severity
    Incidents          the most recent fingerprints, with provenance
    What worked        actions ranked by reported effectiveness

Charting decisions, so they are not re-litigated by eye later:

* **Length encodes magnitude; colour does not**, except where colour *is* the
  category (provenance, attack type in the donut) and then always with a legend
  or a direct label.
* **Severity draws from the status palette, in its own fixed order.**
* Every chart takes its colours from the active day/night palette.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

import altair as alt
import pandas as pd
import streamlit as st

import theme

ROW_HEIGHT = 28
CHART_PADDING = 20


def _cfg(chart, colours: Dict[str, str]):
    """Transparent background and themed axes for every chart."""
    return (chart.configure(background="transparent")
            .configure_view(strokeWidth=0)
            .configure_axis(labelColor=colours["ink2"], titleColor=colours["muted"],
                            gridColor=colours["grid"], domain=False, ticks=False,
                            labelFontSize=11, titleFontSize=11)
            .configure_legend(labelColor=colours["ink2"], titleColor=colours["muted"],
                              orient="bottom", labelFontSize=11))


def _bar(rows: List[Dict], colours: Dict[str, str], *, value_title: str,
         colour_map: Optional[Dict[str, str]] = None, keep_order: bool = False,
         max_rows: int = 10):
    rows = [r for r in rows if r.get("count", 0) > 0 or keep_order][:max_rows]
    if not rows:
        return None
    frame = pd.DataFrame([{"label": r["label"], "count": r["count"],
                           "detail": r.get("name") or r["label"]} for r in rows])
    y = alt.Y("label:N", sort=list(frame["label"]) if keep_order else "-x", title=None,
              axis=alt.Axis(labelLimit=240, labelColor=colours["ink"]))
    colour = (alt.Color("label:N", legend=None,
                        scale=alt.Scale(domain=list(colour_map), range=list(colour_map.values())))
              if colour_map else alt.value(colours["accent"]))
    bars = alt.Chart(frame).mark_bar(height=13, cornerRadiusEnd=5).encode(
        x=alt.X("count:Q", title=value_title, axis=alt.Axis(tickCount=4)),
        y=y, color=colour,
        tooltip=[alt.Tooltip("detail:N", title="Item"), alt.Tooltip("count:Q", title=value_title)])
    labels = alt.Chart(frame).mark_text(align="left", dx=6, fontSize=11,
                                        color=colours["ink"]).encode(x="count:Q", y=y, text="count:Q")
    return _cfg((bars + labels).properties(height=len(frame) * ROW_HEIGHT + CHART_PADDING), colours)


def _donut(rows: List[Dict], colours: Dict[str, str], total: int):
    rows = [r for r in rows if r["count"] > 0][:6]
    if not rows:
        return None
    series = [colours[f"series{i}"] for i in range(1, 7)]
    frame = pd.DataFrame(rows)
    base = alt.Chart(frame).encode(
        theta=alt.Theta("count:Q", stack=True),
        color=alt.Color("label:N", title=None, sort=[r["label"] for r in rows],
                        scale=alt.Scale(domain=[r["label"] for r in rows], range=series[:len(rows)]),
                        legend=alt.Legend(orient="right", labelLimit=180, symbolType="circle")),
        tooltip=[alt.Tooltip("label:N", title="Attack type"), alt.Tooltip("count:Q", title="Incidents")])
    arcs = base.mark_arc(innerRadius=62, outerRadius=96, padAngle=0.012, cornerRadius=3)
    centre = alt.Chart(pd.DataFrame([{"t": str(total)}])).mark_text(
        fontSize=26, fontWeight="bold", color=colours["ink"], dy=-6).encode(text="t:N")
    under = alt.Chart(pd.DataFrame([{"t": "incidents"}])).mark_text(
        fontSize=11, color=colours["muted"], dy=14).encode(text="t:N")
    return _cfg((arcs + centre + under).properties(height=220), colours)


def _timeline(incidents: List[Dict], colours: Dict[str, str]):
    rows = []
    for incident in incidents:
        year = incident.get("year")
        if not year:
            continue
        rows.append({"year": str(year), "source": theme.PROVENANCE.get(
            incident["provenance"], (incident["provenance"].title(), "muted"))[0]})
    if not rows:
        return None
    frame = pd.DataFrame(rows).groupby(["year", "source"]).size().reset_index(name="count")
    sources = [label for key, (label, _) in theme.PROVENANCE.items()
               if label in set(frame["source"])]
    scale = alt.Scale(domain=sources, range=[colours[theme.PROVENANCE[key][1]]
                                             for key, (label, _) in theme.PROVENANCE.items()
                                             if label in sources])
    chart = alt.Chart(frame).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=22).encode(
        x=alt.X("year:O", title=None, axis=alt.Axis(labelAngle=0)),
        y=alt.Y("count:Q", title="Incidents", axis=alt.Axis(tickCount=4)),
        color=alt.Color("source:N", title=None, scale=scale),
        tooltip=["year:N", "source:N", "count:Q"])
    return _cfg(chart.properties(height=230), colours)


def card_box(title: str, subtitle: str = ""):
    """A card that can hold Streamlit elements (charts), styled by its key."""
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    box = st.container(border=True, key=f"card-{slug}")
    sub = f'<div class="sub">{theme.esc(subtitle)}</div>' if subtitle else ""
    box.markdown(f'<div class="cardhead"><h3>{theme.esc(title)}</h3>{sub}</div>',
                 unsafe_allow_html=True)
    return box


def _show(chart) -> None:
    if chart is None:
        st.caption("Nothing recorded yet.")
    else:
        st.altair_chart(chart, width="stretch", theme=None)


def render(overview: dict, memory_stats: dict, incidents: List[Dict], mode: str,
           evaluation: Optional[dict] = None) -> None:
    """Draw the dashboard from a corpus overview."""
    colours = theme.palette(mode)
    if not overview["incidents"]:
        st.warning("Memory is empty. Run `make seed` to load the incident corpus, or share "
                   "an incident from the Analyze page.")
        return

    provenance = {row["label"]: row["count"] for row in overview["by_provenance"]}
    shared = provenance.get("shared", 0)

    st.markdown(theme.kpis([
        {"label": "Incidents in memory", "value": overview["incidents"],
         "delta": f"+{shared}" if shared else "", "note": "shared by members" if shared
         else f"{provenance.get('public', 0)} real · {provenance.get('synthetic', 0)} synthetic"},
        {"label": "ATT&CK techniques", "value": overview["distinct_techniques"],
         "note": f"across {len(overview['by_tactic'])} tactics"},
        {"label": "Response actions", "value": overview["mitigations_recorded"],
         "note": "each with its outcome"},
        {"label": "Identifiers removed", "value": f"{overview['total_redactions']:,}",
         "note": "none stored, none embedded"},
        {"label": "Shared by members", "value": shared,
         "note": "fingerprints, no names or reports"},
    ]), unsafe_allow_html=True)

    # --- Row 1: timeline + composition -----------------------------------
    left, right = st.columns([3, 2])
    with left:
        with card_box("Incidents over time",
                      "By year of occurrence; shared incidents carry no date"):
            _show(_timeline(incidents, colours))
    with right:
        parts = [("Shared by members", shared, "series1"),
                 ("Real breaches", provenance.get("public", 0), "series3"),
                 ("Synthetic", provenance.get("synthetic", 0), "series2")]
        if provenance.get("internal"):
            parts.append(("Internal", provenance["internal"], "muted"))
        st.markdown(theme.card(
            "Where the memory comes from",
            "Every recalled action is shown with its source",
            f'<div style="font-size:2rem;font-weight:700;color:var(--ink)">{overview["incidents"]}'
            f'<span style="font-size:.85rem;color:var(--muted);font-weight:500"> fingerprints</span></div>'
            + theme.composition(parts, mode)), unsafe_allow_html=True)
        top_type = overview["by_attack_type"][0] if overview["by_attack_type"] else None
        top_tech = overview["top_techniques"][0] if overview["top_techniques"] else None
        st.markdown(theme.card(
            "At a glance", "",
            theme.table([
                {"Most common attack": (top_type or {}).get("label", "—").title(),
                 "Most seen technique": f"{top_tech['label']} {top_tech['name']}" if top_tech else "—"},
            ])), unsafe_allow_html=True)

    # --- Row 2: donut + techniques ---------------------------------------
    left, right = st.columns([2, 3])
    with left:
        with card_box("Attack mix", "What the memory has seen"):
            _show(_donut(overview["by_attack_type"], colours, overview["incidents"]))
    with right:
        with card_box("Most-seen ATT&CK techniques",
                      "The behaviour this memory is best placed to recognise"):
            _show(_bar([{"label": f"{r['label']} {r['name']}".strip(), "count": r["count"],
                         "name": r["name"]} for r in overview["top_techniques"]],
                       colours, value_title="Incidents", max_rows=8))

    # --- Row 3: vectors, severity ------------------------------------------
    cols = st.columns(2)
    with cols[0]:
        with card_box("How attackers got in", "Entry vector, kept apart from outcome"):
            _show(_bar(overview["by_initial_vector"], colours, value_title="Incidents", max_rows=6))
    with cols[1]:
        severity_colours = {band["label"]: colours[theme.SEVERITY_STATUS[band["label"]]]
                            for band in overview["by_severity"]}
        with card_box("Severity", "In fixed order, never sorted by count"):
            _show(_bar(overview["by_severity"], colours, value_title="Incidents",
                       colour_map=severity_colours, keep_order=True))

    with card_box("Kill-chain coverage",
                  "Thin coverage of a tactic is a gap in what memory can advise on"):
        _show(_bar(overview["by_tactic"], colours, value_title="Incidents", max_rows=12))

    # --- Incidents table ---------------------------------------------------
    recent = sorted(incidents, key=lambda i: i.get("created") or "", reverse=True)[:12]
    st.markdown(theme.card(
        "Fingerprints in memory", f"The {len(recent)} most recently added",
        theme.table([{
            "Incident": i["title"],
            "Source": theme.provenance_pill(i["provenance"]),
            "Attack": i["attack_type"].replace("_", " "),
            "Entry": i["initial_vector"].replace("_", " "),
            "Severity": theme.severity_pill(i["severity"]),
            "Techniques": len(i["technique_ids"]),
        } for i in recent], html_columns={"Source", "Severity"}, strong={"Incident"},
            numeric={"Techniques"})), unsafe_allow_html=True)

    # --- What worked -------------------------------------------------------
    if overview["proven_actions"]:
        st.markdown(theme.card(
            "Actions with the strongest track record",
            "Ranked by the average outcome reported across every incident that used them",
            theme.table([{"Action": r["action"],
                          "Avg. effectiveness": f"{r['effectiveness']:.0%}",
                          "Incidents": r["times_used"]} for r in overview["proven_actions"]],
                        numeric={"Avg. effectiveness", "Incidents"})), unsafe_allow_html=True)

    st.caption(f"Memory backend: {memory_stats['backend']} · "
               f"{memory_stats['incidents_in_memory']} incidents indexed")
