"""Loads the offline knowledge bases (MITRE ATT&CK + CISA KEV) once per process.

Both files are produced by scripts/process_mitre.py and scripts/process_kev.py
and are committed to the repo, so the system works with no network access.
"""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Dict, List

from app.config import KEV_PATH, TECHNIQUES_PATH

# ATT&CK tactic slugs in kill-chain order, so a technique list can always be
# rendered as a coherent attack story instead of an unordered bag.
# Note: current ATT&CK releases split the old "defense-evasion" tactic into
# "stealth" and "defense-impairment"; both spellings are kept so the pipeline
# survives a knowledge-base refresh in either direction.
TACTIC_ORDER: List[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_LABELS: Dict[str, str] = {slug: slug.replace("-", " ").title() for slug in TACTIC_ORDER}
TACTIC_LABELS["stealth"] = "Stealth (Defense Evasion)"
TACTIC_LABELS["defense-impairment"] = "Defense Impairment"


@lru_cache(maxsize=1)
def load_techniques() -> List[dict]:
    """All non-revoked ATT&CK Enterprise techniques."""
    if not TECHNIQUES_PATH.exists():
        raise FileNotFoundError(
            f"Missing {TECHNIQUES_PATH}. Run: python scripts/download_mitre.py && "
            "python scripts/process_mitre.py"
        )
    with open(TECHNIQUES_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def technique_index() -> Dict[str, dict]:
    """technique id -> technique record."""
    return {t["id"]: t for t in load_techniques()}


@lru_cache(maxsize=1)
def load_kev() -> Dict[str, dict]:
    """CVE id -> CISA Known Exploited Vulnerability record."""
    if not KEV_PATH.exists():
        raise FileNotFoundError(
            f"Missing {KEV_PATH}. Run: python scripts/download_kev.py && "
            "python scripts/process_kev.py"
        )
    with open(KEV_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def sort_tactics(tactics: List[str]) -> List[str]:
    """Order tactics by their position in the kill chain."""
    known = [t for t in TACTIC_ORDER if t in set(tactics)]
    unknown = sorted(set(tactics) - set(TACTIC_ORDER))
    return known + unknown


def describe_technique(technique_id: str) -> dict:
    """Look up a technique, tolerating sub-technique ids not present in the KB."""
    index = technique_index()
    if technique_id in index:
        record = index[technique_id]
        return {
            "id": record["id"],
            "name": record["name"],
            "tactics": record.get("tactics", []),
            "description": record.get("description", ""),
        }
    # Fall back to the parent technique so "T1566.002" still resolves usefully.
    parent = technique_id.split(".")[0]
    if parent in index:
        record = index[parent]
        return {
            "id": technique_id,
            "name": f"{record['name']} (sub-technique)",
            "tactics": record.get("tactics", []),
            "description": record.get("description", ""),
        }
    return {"id": technique_id, "name": "Unknown technique", "tactics": [], "description": ""}
