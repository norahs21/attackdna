"""CTI enrichment — which known adversaries behave like this incident?

Compares an incident's Attack DNA against the TTP profile of every ATT&CK
threat group, malware family and tool, and reports the closest behavioural
matches.

**This is not attribution in the intelligence sense, and the output says so.**
A technique overlap means "this incident resembles how G0082 is documented to
operate", not "G0082 did this". Real attribution needs infrastructure,
tooling artefacts and geopolitical context that a sanitized report deliberately
does not contain. Overstating it would be the single easiest way for this
system to mislead a SOC, so the scoring is built to be conservative:

  * **Coverage** is what fraction of *this incident's* techniques the actor is
    known to use — the question that actually matters.
  * A **specificity** weight discounts techniques that almost every actor uses
    (T1059 tells you nothing; T1621 tells you something).
  * Matches below a floor are not reported at all, and a match is labelled
    `weak` / `moderate` / `notable` — never "confirmed".
"""
from __future__ import annotations

import math
from typing import Dict, List

from app.services.knowledge_base import load_campaigns, load_groups, load_software

# A match needs this much weighted coverage of the incident's techniques before
# it is worth showing at all.
MIN_COVERAGE = 0.30
# And this many shared techniques — one shared technique is noise, not a lead.
MIN_SHARED = 2

CONFIDENCE_BANDS = [
    (0.75, "notable"),
    (0.50, "moderate"),
    (0.0, "weak"),
]


def _specificity_weights(profiles: List[dict]) -> Dict[str, float]:
    """Inverse-frequency weight per technique across all known actors.

    A technique used by 150 of 172 groups carries almost no signal; one used by
    three carries a lot. This is IDF, applied to adversary behaviour.
    """
    total = max(1, len(profiles))
    document_frequency: Dict[str, int] = {}
    for profile in profiles:
        for technique_id in set(profile.get("techniques", [])):
            document_frequency[technique_id] = document_frequency.get(technique_id, 0) + 1

    return {
        technique_id: math.log((total + 1) / (count + 1)) + 1.0
        for technique_id, count in document_frequency.items()
    }


def _band(score: float) -> str:
    for threshold, label in CONFIDENCE_BANDS:
        if score >= threshold:
            return label
    return "weak"


def _match_profiles(observed: set, profiles: List[dict], weights: Dict[str, float],
                    top_k: int) -> List[dict]:
    if not observed:
        return []

    # Normalise against the incident's own techniques: we are asking how much of
    # THIS incident the actor's known behaviour explains.
    observed_weight = sum(weights.get(t, 1.0) for t in observed) or 1.0

    results = []
    for profile in profiles:
        known = set(profile.get("techniques", []))
        shared = observed & known
        if len(shared) < MIN_SHARED:
            continue

        coverage = sum(weights.get(t, 1.0) for t in shared) / observed_weight
        if coverage < MIN_COVERAGE:
            continue

        results.append({
            "id": profile["id"],
            "name": profile["name"],
            "aliases": profile.get("aliases", []),
            "type": profile.get("type", "group"),
            "coverage": round(coverage, 4),
            "shared_techniques": sorted(shared),
            "shared_count": len(shared),
            "known_technique_count": len(known),
            "confidence": _band(coverage),
            "description": profile.get("description", ""),
        })

    results.sort(key=lambda r: (-r["coverage"], -r["shared_count"]))
    return results[:top_k]


def attribute(technique_ids: List[str], top_k: int = 3) -> dict:
    """Find known actors and toolkits whose documented TTPs resemble this DNA."""
    observed = {t for t in technique_ids if t}

    groups = load_groups()
    software = load_software()
    if not groups and not software:
        return {
            "available": False,
            "note": "CTI layers not processed. Run: python scripts/process_cti.py",
            "groups": [], "software": [], "campaigns": [],
        }

    group_matches = _match_profiles(observed, groups, _specificity_weights(groups), top_k)
    software_matches = _match_profiles(observed, software, _specificity_weights(software), top_k)

    # Surface campaigns run by any group that matched — a named operation is a
    # more concrete reference point for a defender than a group id alone.
    matched_group_ids = {g["id"] for g in group_matches}
    campaigns = [
        {
            "id": campaign["id"],
            "name": campaign["name"],
            "attributed_to": campaign["attributed_to"],
            "attributed_to_name": campaign["attributed_to_name"],
            "first_seen": campaign.get("first_seen"),
        }
        for campaign in load_campaigns()
        if campaign.get("attributed_to") in matched_group_ids
    ][:5]

    return {
        "available": True,
        "groups": group_matches,
        "software": software_matches,
        "campaigns": campaigns,
        "caveat": (
            "Behavioural resemblance only. Technique overlap indicates similarity to "
            "how these actors are documented to operate — it is not attribution. "
            "Confirming an actor requires infrastructure and tooling evidence that a "
            "sanitized report does not contain."
        ),
    }
