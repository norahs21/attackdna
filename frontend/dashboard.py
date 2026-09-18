"""Memory dashboard — what the corpus knows, rather than what one report says.

Every other screen answers "what about this incident?". This one answers "what
does this system actually hold?", which is the question anyone seeing it for the
first time asks before they will trust an answer it gives them.

Charting decisions, so they are not re-litigated by eye later:

* **Length encodes magnitude; colour does not.** The distribution charts are one
  hue because the bar's length already says everything, and a second encoding of
  the same number would only add noise.
* **Severity is the exception**, because severity is a status rather than a
  quantity. It draws from the reserved status palette, in its own fixed order —
  a chart that puts "critical" between "low" and "medium" because of how many
  there are cannot be read.
* **Category names live on the axis**, so identity never depends on telling two
  colours apart, and no chart here needs a legend.
"""
from __future__ import annotations

from typing import Dict, List, Optional

import altair as alt
import pandas as pd
import streamlit as st

from theme import ACCENT, GRIDLINE, INK, INK_MUTED, SEVERITY_STATUS, STATUS, tile

# Room for a bar plus breathing space; the axis is the label, so rows must not
# be so tight that the names collide.
ROW_HEIGHT = 30
CHART_PADDING = 24


def _empty(message: str) -> None:
    st.caption(message)


def _bar(rows: List[Dict], *, value_title: str, color: Optional[Dict[str, str]] = None,
         keep_order: bool = False, max_rows: int = 12) -> Optional[alt.LayerChart]:
    """A horizontal bar chart with direct value labels.

    Horizontal because the categories are words — sector names, technique names —
    and a vertical chart would either rotate them or truncate them.
    """
    rows = [r for r in rows if r.get("count", 0) > 0 or keep_order][:max_rows]
    if not rows:
        return None

    frame = pd.DataFrame([
        {"label": row["label"], "count": row["count"],
         "detail": row.get("name") or row["label"]}
        for row in rows
    ])

    order = list(frame["label"]) if keep_order else None
    y_axis = alt.Y(
        "label:N",
        sort=order if order else "-x",
        title=None,
        axis=alt.Axis(labelColor=INK, labelFontSize=12, labelLimit=260,
                      domain=False, ticks=False),
    )

    if color:
        mark_color = alt.Color(
            "label:N", legend=None,
            scale=alt.Scale(domain=list(color.keys()), range=list(color.values())),
        )
    else:
        mark_color = alt.value(ACCENT)

    # cornerRadiusEnd rounds only the data end, so the bar stays anchored to the
    # baseline it is measured from.
    bars = alt.Chart(frame).mark_bar(
        height=14, cornerRadiusEnd=4,
    ).encode(
        x=alt.X("count:Q", title=value_title,
                axis=alt.Axis(labelColor=INK_MUTED, titleColor=INK_MUTED,
                              gridColor=GRIDLINE, domain=False, tickCount=4)),
        y=y_axis,
        color=mark_color,
        tooltip=[alt.Tooltip("detail:N", title="Item"),
                 alt.Tooltip("count:Q", title=value_title)],
    )

    labels = alt.Chart(frame).mark_text(
        align="left", dx=6, fontSize=12, color=INK,
    ).encode(x="count:Q", y=y_axis, text="count:Q")

    return (bars + labels).properties(
        height=len(frame) * ROW_HEIGHT + CHART_PADDING,
    ).configure_view(strokeWidth=0).configure_axis(labelFontSize=12)


def _chart(title: str, caption: str, chart, empty_message: str) -> None:
    st.markdown(f"**{title}**")
    st.caption(caption)
    if chart is None:
        _empty(empty_message)
    else:
        st.altair_chart(chart, width="stretch", theme=None)


def render(overview: dict, memory_stats: dict, incidents: List[Dict]) -> None:
    """Draw the dashboard from a corpus overview."""
    if not overview["incidents"]:
        st.warning("Memory is empty. Run `make seed` to load the incident corpus.")
        return

    # --- Headline figures ------------------------------------------------
    provenance = {row["label"]: row["count"] for row in overview["by_provenance"]}
    tiles = st.columns(4)
    tiles[0].markdown(
        tile("Incidents in memory", str(overview["incidents"]),
             f"{provenance.get('public', 0)} real · {provenance.get('synthetic', 0)} synthetic"),
        unsafe_allow_html=True)
    tiles[1].markdown(
        tile("ATT&CK techniques seen", str(overview["distinct_techniques"]),
             f"across {len(overview['by_tactic'])} kill-chain phases"),
        unsafe_allow_html=True)
    tiles[2].markdown(
        tile("Response actions recorded", str(overview["mitigations_recorded"]),
             "each with the outcome it produced"),
        unsafe_allow_html=True)
    tiles[3].markdown(
        tile("Identifiers removed", str(overview["total_redactions"]),
             "none stored, none embedded"),
        unsafe_allow_html=True)

    st.divider()

    # --- Distributions ---------------------------------------------------
    left, right = st.columns(2)
    with left:
        _chart(
            "Attack types", "What the memory has actually seen.",
            _bar(overview["by_attack_type"], value_title="Incidents"),
            "No attack types recorded.",
        )
    with right:
        _chart(
            "Sectors", "Which industries these incidents came from.",
            _bar(overview["by_sector"], value_title="Incidents"),
            "No sectors recorded.",
        )

    left, right = st.columns(2)
    with left:
        _chart(
            "How the attacker got in",
            "Entry vector is tracked separately from outcome — the same "
            "ransomware outcome can arrive five different ways.",
            _bar(overview["by_initial_vector"], value_title="Incidents"),
            "No entry vectors recorded.",
        )
    with right:
        severity_colors = {
            band["label"]: STATUS[SEVERITY_STATUS[band["label"]]]
            for band in overview["by_severity"]
        }
        _chart(
            "Severity mix",
            "Bands stay in their own order, never sorted by count.",
            _bar(overview["by_severity"], value_title="Incidents",
                 color=severity_colors, keep_order=True),
            "No severities recorded.",
        )

    _chart(
        "Most-seen ATT&CK techniques",
        "The behaviour this memory is best placed to recognise in something new.",
        _bar([{"label": f"{row['label']} {row['name']}".strip(), "count": row["count"],
               "name": row["name"]} for row in overview["top_techniques"]],
             value_title="Incidents", max_rows=10),
        "No techniques mapped yet.",
    )

    with st.expander("Kill-chain coverage"):
        st.caption("Which phases of the attack lifecycle the corpus covers. Thin "
                   "coverage of a phase is a gap in what the memory can advise on.")
        chart = _bar(overview["by_tactic"], value_title="Incidents", max_rows=12)
        if chart is None:
            _empty("No tactics recorded.")
        else:
            st.altair_chart(chart, width="stretch", theme=None)

    # --- What actually worked -------------------------------------------
    st.divider()
    st.markdown("**Actions with the strongest track record**")
    st.caption("Ranked by the average outcome reported across every incident that "
               "used them — not by how often they are recommended elsewhere.")
    if overview["proven_actions"]:
        st.dataframe(
            [{
                "Action": row["action"],
                "Average effectiveness": f"{row['effectiveness']:.0%}",
                "Incidents": row["times_used"],
            } for row in overview["proven_actions"]],
            width="stretch", hide_index=True,
        )
    else:
        _empty("No action has a reported effectiveness yet.")

    # --- Side by side ----------------------------------------------------
    st.divider()
    compare(incidents)

    st.caption(f"Memory backend: `{memory_stats['backend']}` · "
               f"{memory_stats['incidents_in_memory']} incidents indexed")


def compare(incidents: List[Dict]) -> None:
    """Two incidents side by side, with the overlap computed rather than eyeballed."""
    st.markdown("**Compare two incidents**")
    st.caption("The overlap is what makes one incident useful for another: shared "
               "technique IDs and shared kill-chain phases.")

    if len(incidents) < 2:
        _empty("At least two incidents are needed to compare.")
        return

    titles = {incident["title"] or incident["id"]: incident for incident in incidents}
    names = list(titles)
    left_col, right_col = st.columns(2)
    left_name = left_col.selectbox("First incident", names, index=0)
    right_name = right_col.selectbox("Second incident", names,
                                     index=1 if len(names) > 1 else 0)

    left, right = titles[left_name], titles[right_name]
    if left["id"] == right["id"]:
        _empty("Pick two different incidents.")
        return

    shared_techniques = sorted(set(left["technique_ids"]) & set(right["technique_ids"]))
    shared_tactics = sorted(set(left["tactics"]) & set(right["tactics"]))

    rows = [
        ("Attack type", left["attack_type"], right["attack_type"]),
        ("Initial vector", left["initial_vector"], right["initial_vector"]),
        ("Sector", left["sector"], right["sector"]),
        ("Severity", left["severity"], right["severity"]),
        ("Techniques", len(left["technique_ids"]), len(right["technique_ids"])),
    ]
    st.dataframe(
        [{"": label, left_name: a, right_name: b} for label, a, b in rows],
        width="stretch", hide_index=True,
    )

    if shared_techniques:
        st.markdown(f"**{len(shared_techniques)} shared technique(s):** "
                    + ", ".join(shared_techniques))
    else:
        st.caption("No shared techniques — these two attacks behave differently.")
    if shared_tactics:
        st.markdown(f"**{len(shared_tactics)} shared kill-chain phase(s):** "
                    + ", ".join(t.replace("-", " ") for t in shared_tactics))
