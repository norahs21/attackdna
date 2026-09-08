"""Enriches CVEs found in an incident with CISA Known Exploited Vulnerability data.

A CVE that appears in the KEV catalog is not theoretical — CISA has confirmed
real-world exploitation and published a required remediation action. Surfacing
that turns "a CVE was mentioned" into "this is a known-exploited vulnerability
with a mandated fix", which is the difference between trivia and triage.
"""
from __future__ import annotations

import re
from typing import Dict, List

from app.services.knowledge_base import load_kev

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def extract_cves(text: str) -> List[str]:
    """All distinct CVE ids in the text, upper-cased and order-preserved."""
    return list(dict.fromkeys(cve.upper() for cve in CVE_RE.findall(text or "")))


def enrich_cves(cves: List[str]) -> List[Dict]:
    """Attach KEV context to each CVE, flagging known-exploited ones."""
    try:
        kev = load_kev()
    except FileNotFoundError:
        kev = {}

    enriched: List[Dict] = []
    for cve in cves:
        record = kev.get(cve.upper())
        if record:
            enriched.append({
                "cve": cve,
                "known_exploited": True,
                "vendor": record.get("vendor"),
                "product": record.get("product"),
                "name": record.get("name"),
                "date_added_to_kev": record.get("date_added"),
                "required_action": record.get("required_action"),
            })
        else:
            enriched.append({
                "cve": cve,
                "known_exploited": False,
                "vendor": None,
                "product": None,
                "name": None,
                "date_added_to_kev": None,
                "required_action": None,
            })
    return enriched


def kev_summary(enriched: List[Dict]) -> Dict:
    """Headline numbers for the UI banner."""
    exploited = [item for item in enriched if item["known_exploited"]]
    return {
        "total_cves": len(enriched),
        "known_exploited_count": len(exploited),
        "known_exploited": [item["cve"] for item in exploited],
        "urgency": "critical" if exploited else ("review" if enriched else "none"),
    }
