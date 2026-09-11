"""Mitigation Memory — what the organisation already knows how to do.

Given the incidents that resemble the current one, this ranks the responses
that were taken before. An action recommended here is not generated advice:
it is something this organisation actually did, with a citation back to the
incident it came from.

Ranking blends three things:
  * how similar the source incident was (a near-identical case counts more),
  * how effective the responders rated the action,
  * how many separate incidents used it (repeatedly-used actions are proven).

Recommendations come from three clearly-separated origins, and the label is
never dropped, because a defender needs to know how much weight to give each:

  ``recalled``   what this organisation actually did before, with a citation
  ``framework``  an official MITRE ATT&CK mitigation (M####) for an observed
                 technique — authoritative, but generic to every organisation
  ``suggested``  a concrete baseline control filling a gap neither covers

Where similar incidents run out, the framework and baseline layers fill the
gap, so "what worked here" and "what the framework advises" never blur.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from app.services.knowledge_base import mitigations_by_technique

# Response phase ordering, so a recommended plan reads in the order a
# responder would actually execute it.
CATEGORY_ORDER = ["detect", "contain", "eradicate", "recover", "harden"]
CATEGORY_LABELS = {
    "detect": "Detect",
    "contain": "Contain",
    "eradicate": "Eradicate",
    "recover": "Recover",
    "harden": "Harden",
}

# Baseline controls keyed by ATT&CK technique. Used only to fill gaps when
# memory has nothing to recall for a technique that was observed.
BASELINE_CONTROLS: Dict[str, List[tuple]] = {
    "T1566": [("contain", "Quarantine the delivered message across all mailboxes and block the sender"),
              ("harden", "Enable URL rewriting/detonation and attachment sandboxing on the mail gateway"),
              ("detect", "Alert on first-time-seen sender domains targeting finance and executive users")],
    "T1566.001": [("contain", "Pull the malicious attachment from every mailbox that received it"),
                  ("harden", "Block macro execution in documents originating from the internet")],
    "T1566.002": [("contain", "Block the phishing URL at the proxy and reset credentials for users who clicked"),
                  ("harden", "Enforce phishing-resistant MFA (FIDO2/WebAuthn) for all users"),
                  ("detect", "Alert on OAuth consent grants and logins from unfamiliar ASNs")],
    "T1078": [("contain", "Disable the compromised account and revoke all active sessions and tokens"),
              ("harden", "Apply conditional access policies based on device compliance and location")],
    "T1190": [("eradicate", "Patch the exploited service and inspect for web shells left behind"),
              ("harden", "Place the public-facing application behind a WAF with virtual patching")],
    "T1059.001": [("detect", "Enable PowerShell script-block and module logging, forward to the SIEM"),
                  ("harden", "Enforce PowerShell Constrained Language Mode on non-admin endpoints")],
    "T1027": [("detect", "Alert on base64/encoded command lines spawned by Office or browser processes")],
    "T1003": [("contain", "Force a domain-wide credential reset, including krbtgt twice"),
              ("harden", "Enable LSA protection and Credential Guard on all Windows hosts")],
    "T1110": [("contain", "Lock targeted accounts and block the source ranges"),
              ("harden", "Enforce account lockout thresholds and deploy MFA on all external logins")],
    "T1621": [("harden", "Switch from push-based MFA to number matching or FIDO2 keys"),
              ("detect", "Alert on repeated denied MFA prompts for a single account")],
    "T1021.001": [("contain", "Block RDP between workstation subnets and require jump-host access"),
                  ("harden", "Remove direct RDP exposure; require VPN plus MFA")],
    "T1021.002": [("contain", "Disable administrative shares on workstations and block SMB laterally"),
                  ("detect", "Alert on service creation over SMB from non-admin hosts")],
    "T1071": [("contain", "Sinkhole the C2 domain and block the destination at the egress firewall"),
              ("detect", "Baseline outbound beacon intervals and alert on periodic low-volume traffic")],
    "T1041": [("contain", "Block the exfiltration destination and throttle large outbound transfers"),
              ("detect", "Alert on abnormal outbound data volume per user or per host")],
    "T1567": [("contain", "Block unsanctioned cloud storage domains at the proxy"),
              ("harden", "Deploy DLP policies covering uploads to personal cloud storage")],
    "T1486": [("contain", "Isolate affected endpoints from the network immediately"),
              ("recover", "Restore from the most recent verified-clean offline backup"),
              ("harden", "Maintain immutable, air-gapped backups and rehearse restore times")],
    "T1490": [("recover", "Rebuild affected hosts from image; shadow copies cannot be trusted"),
              ("harden", "Restrict vssadmin/wbadmin execution to administrators via application control")],
    "T1562": [("detect", "Alert whenever an EDR agent stops reporting or a security service is stopped"),
              ("harden", "Enable tamper protection on all endpoint security agents")],
    "T1070": [("detect", "Forward logs off-host in real time so local deletion cannot destroy evidence"),
              ("harden", "Make the SIEM the authoritative log store with write-once retention")],
    "T1657": [("contain", "Freeze the transaction and notify the receiving bank within the recall window"),
              ("harden", "Require out-of-band verification for payment-detail changes")],
    "T1498": [("contain", "Enable upstream scrubbing with the ISP and rate-limit at the edge"),
              ("harden", "Pre-arrange DDoS mitigation capacity and rehearse failover")],
}

GENERIC_CONTROLS: List[tuple] = [
    ("detect", "Sweep the estate for the same behaviour using the ATT&CK techniques identified above"),
    ("contain", "Isolate affected assets and revoke credentials associated with the incident"),
    ("recover", "Restore affected services from verified-clean backups and validate integrity"),
    ("harden", "Close the control gap named in the root cause before reopening the incident"),
]


def recall_mitigations(similar_incidents: List[dict], observed_technique_ids: List[str],
                       limit: int = 12) -> dict:
    """Rank past mitigations and fill remaining gaps with baseline controls."""
    aggregated: Dict[str, dict] = {}

    for incident in similar_incidents:
        weight = incident.get("similarity", 0.0)
        for mitigation in incident.get("mitigations", []):
            action = (mitigation.get("action") or "").strip()
            if not action:
                continue
            key = action.lower()
            entry = aggregated.setdefault(key, {
                "action": action,
                "category": mitigation.get("category") or "contain",
                "score": 0.0,
                "times_used": 0,
                "effectiveness_samples": [],
                "sources": [],
            })
            effectiveness = mitigation.get("effectiveness")
            if effectiveness is not None:
                entry["effectiveness_samples"].append(float(effectiveness))
            entry["times_used"] += 1
            entry["score"] += weight * (float(effectiveness) if effectiveness is not None else 0.6)
            entry["sources"].append({
                "incident_id": incident.get("incident_id"),
                "title": incident.get("title"),
                "similarity": weight,
                "provenance": incident.get("provenance", "internal"),
                "source_url": incident.get("source_url"),
            })

    recalled = []
    for entry in aggregated.values():
        samples = entry.pop("effectiveness_samples")
        entry["avg_effectiveness"] = round(sum(samples) / len(samples), 2) if samples else None
        # Actions used across several past incidents are more trustworthy than
        # a single one-off, so reward reuse without letting it dominate.
        entry["score"] = round(entry["score"] * (1 + 0.15 * (entry["times_used"] - 1)), 4)
        entry["origin"] = "recalled"
        recalled.append(entry)

    recalled.sort(key=lambda item: -item["score"])
    recalled = recalled[:limit]

    framework = _framework_mitigations(observed_technique_ids)
    suggested = _baseline_gap_fill(observed_technique_ids, recalled)

    combined = recalled + suggested
    combined.sort(key=lambda item: (
        CATEGORY_ORDER.index(item["category"]) if item["category"] in CATEGORY_ORDER else 99,
        -item.get("score", 0.0),
    ))

    return {
        "recommended": combined,
        "framework_mitigations": framework,
        "recalled_count": len(recalled),
        "suggested_count": len(suggested),
        "framework_count": len(framework),
        "by_phase": _group_by_phase(combined),
    }


def _framework_mitigations(technique_ids: List[str], limit: int = 10) -> List[dict]:
    """Official ATT&CK mitigations covering the observed techniques.

    Ranked by how many of *this incident's* techniques each one addresses, so
    the control that closes the most of this attack chain comes first.
    """
    index = mitigations_by_technique()
    if not index:
        return []

    observed = [t for t in technique_ids if t]
    coverage: Dict[str, dict] = {}

    for technique_id in observed:
        # A sub-technique inherits its parent's mitigations.
        candidates = index.get(technique_id) or index.get(technique_id.split(".")[0], [])
        for mitigation in candidates:
            entry = coverage.setdefault(mitigation["id"], {
                "id": mitigation["id"],
                "name": mitigation["name"],
                "description": mitigation["description"],
                "origin": "framework",
                "covers_techniques": [],
            })
            if technique_id not in entry["covers_techniques"]:
                entry["covers_techniques"].append(technique_id)

    results = list(coverage.values())
    for entry in results:
        entry["coverage_count"] = len(entry["covers_techniques"])
        entry["covers_techniques"].sort()
    results.sort(key=lambda item: (-item["coverage_count"], item["id"]))
    return results[:limit]


def _baseline_gap_fill(technique_ids: List[str], recalled: List[dict]) -> List[dict]:
    """Baseline controls for observed techniques that memory did not cover."""
    already = {item["action"].lower() for item in recalled}
    suggested: List[dict] = []

    for technique_id in technique_ids:
        controls = BASELINE_CONTROLS.get(technique_id)
        if controls is None:
            # A sub-technique inherits its parent's baseline controls.
            controls = BASELINE_CONTROLS.get(technique_id.split(".")[0], [])
        for category, action in controls:
            if action.lower() in already:
                continue
            already.add(action.lower())
            suggested.append({
                "action": action,
                "category": category,
                "origin": "suggested",
                "score": 0.0,
                "times_used": 0,
                "avg_effectiveness": None,
                "sources": [],
                "for_technique": technique_id,
            })

    if not recalled and not suggested:
        for category, action in GENERIC_CONTROLS:
            suggested.append({
                "action": action,
                "category": category,
                "origin": "suggested",
                "score": 0.0,
                "times_used": 0,
                "avg_effectiveness": None,
                "sources": [],
                "for_technique": None,
            })
    return suggested


def _group_by_phase(items: List[dict]) -> List[dict]:
    grouped = defaultdict(list)
    for item in items:
        grouped[item["category"]].append(item)
    return [
        {"phase": category, "label": CATEGORY_LABELS.get(category, category.title()),
         "actions": grouped[category]}
        for category in CATEGORY_ORDER if grouped[category]
    ]
