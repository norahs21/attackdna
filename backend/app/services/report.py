"""Turn an analysis into a document someone can keep.

A demo that ends when the browser tab closes has not produced anything. This
renders the same result the screen shows into self-contained Markdown — the one
format that opens everywhere, pastes into a ticket, and survives being emailed.

The report is built from the analysis result alone, so it inherits the privacy
guarantee exactly: it quotes the sanitized text, never the original, and there
is no code path here that could reach the raw report even if one were kept.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from app.services.knowledge_base import TACTIC_LABELS


def _percent(value: Optional[float]) -> str:
    return f"{value:.0%}" if value is not None else "not reported"


def _heading(text: str, level: int = 2) -> List[str]:
    return ["", f"{'#' * level} {text}", ""]


def _table(headers: List[str], rows: List[List[str]]) -> List[str]:
    if not rows:
        return ["_None recorded._"]
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return lines


def build(result: dict, title: str = "Incident analysis",
          generated_at: Optional[datetime] = None) -> str:
    """Render an analysis result as Markdown."""
    privacy = result["privacy"]
    dna = result["dna"]
    similar = result.get("similar_incidents") or []
    mitigations = result.get("mitigations") or {}
    meta = result.get("meta", {})

    stamp = (generated_at or datetime.utcnow()).strftime("%Y-%m-%d %H:%M UTC")

    lines: List[str] = [
        f"# {title}",
        "",
        f"*Generated {stamp} · ATTACKDNA*",
        "",
        "> Every identifying value was removed before analysis. This report "
        "contains the sanitized incident and its Attack DNA only.",
    ]

    # --- Verdict ---------------------------------------------------------
    lines += _heading("Verdict")
    lines += [
        f"- **Attack type:** {dna['attack_type'].replace('_', ' ')}",
        f"- **Initial vector:** {(dna.get('initial_vector') or 'unknown').replace('_', ' ')}",
        f"- **Sector:** {dna['sector']}",
        f"- **Severity:** {dna['severity']}",
        f"- **Identifying values removed:** {privacy['total_redactions']} "
        f"({'verified clean' if privacy['verified_clean'] else 'VERIFICATION FAILED'})",
    ]
    if similar:
        best = similar[0]
        lines.append(f"- **Closest incident in memory:** {best['title']} "
                     f"({best['similarity']:.0%} match)")

    # --- DNA -------------------------------------------------------------
    lines += _heading("Attack DNA")
    lines += ["```", dna["signature"], "```", ""]
    if dna.get("summary"):
        lines += [dna["summary"], ""]
    lines += [
        "**Kill chain:** " + (" → ".join(
            TACTIC_LABELS.get(t, t) for t in dna.get("tactics", [])) or "—"),
        "",
        "**Impact:** " + (", ".join(
            i.replace("_", " ") for i in dna.get("impacts", [])) or "none recorded"),
    ]

    lines += _heading("MITRE ATT&CK techniques", level=3)
    lines += _table(
        ["Technique", "Name", "Confidence", "Evidence"],
        [[t["id"], t.get("name", ""), t.get("confidence", ""),
          ", ".join(t.get("evidence", [])[:3])] for t in dna.get("techniques", [])],
    )

    known_exploited = [c for c in dna.get("cve_details", []) if c.get("known_exploited")]
    if known_exploited:
        lines += _heading("Known exploited vulnerabilities (CISA KEV)", level=3)
        for cve in known_exploited:
            lines.append(f"- **{cve['cve']}** — {cve.get('vendor', '')} "
                         f"{cve.get('product', '')}. {cve.get('required_action', '')}")

    # --- Memory ----------------------------------------------------------
    lines += _heading("Similar incidents recalled from memory")
    if similar:
        lines += _table(
            ["Match", "Incident", "Source", "Why it matched"],
            [[f"{m['similarity']:.0%}", m["title"], m.get("provenance", "internal"),
              "; ".join(m.get("match_reasons", [])[:2])] for m in similar],
        )
    else:
        lines.append("_Nothing in memory matched closely enough._")

    # --- Response --------------------------------------------------------
    lines += _heading("Recommended response")
    lines.append(
        f"{mitigations.get('recalled_count', 0)} action(s) recalled from past incidents, "
        f"{mitigations.get('suggested_count', 0)} baseline control(s) added where memory "
        "had no coverage."
    )
    for group in mitigations.get("by_phase", []):
        lines += _heading(group["label"], level=3)
        for action in group["actions"]:
            origin = (f"recalled, used in {action['times_used']} past incident(s), "
                      f"average effectiveness {_percent(action.get('avg_effectiveness'))}"
                      if action["origin"] == "recalled" else "baseline control")
            lines.append(f"- {action['action']}  _({origin})_")

    framework = mitigations.get("framework_mitigations", [])
    if framework:
        lines += _heading("Official MITRE ATT&CK mitigations", level=3)
        lines += _table(
            ["ID", "Mitigation", "Covers"],
            [[m["id"], m["name"], ", ".join(m["covers_techniques"])] for m in framework],
        )

    # --- Evidence --------------------------------------------------------
    lines += _heading("Sanitized incident")
    lines += ["```", privacy["sanitized_text"], "```"]

    lines += _heading("Provenance of this report", level=3)
    lines.append(
        f"Extraction mode: {meta.get('extraction_mode', 'rule-based')} · "
        f"Memory backend: {meta.get('memory', {}).get('backend', 'unknown')} · "
        f"{meta.get('memory', {}).get('incidents_in_memory', 0)} incidents in memory"
    )

    return "\n".join(lines) + "\n"


def filename(dna: dict, generated_at: Optional[datetime] = None) -> str:
    stamp = (generated_at or datetime.utcnow()).strftime("%Y%m%d-%H%M")
    attack_type = (dna.get("attack_type") or "incident").replace("_", "-")
    return f"attackdna-{attack_type}-{stamp}.md"
