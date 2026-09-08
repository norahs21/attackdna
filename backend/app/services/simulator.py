"""Safe Simulation — turns an incident into a defensive tabletop exercise.

**Safety boundary.** This module produces blue-team material only: what the
defenders should *see*, *decide* and *do*. It never emits payloads, commands,
exploit code, phishing copy, infrastructure to register, or any other operational
attacker instruction. Each phase is expressed as an *inject* ("the SOC receives
this alert") together with the detection that should fire and the decision the
team must make.

That is not a limitation bolted on afterwards — it is what makes the output
useful. A tabletop exercise tests whether detection and response actually work,
which is the question a SOC needs answered. Generating a working attack would
answer no question the organisation has.
"""
from __future__ import annotations

from typing import Dict, List

from app.services import llm_client
from app.services.knowledge_base import TACTIC_LABELS, TACTIC_ORDER, describe_technique

# What a defender should expect to observe when a technique is exercised, and
# where that observation comes from. Detection-engineering vocabulary only.
DETECTION_CATALOG: Dict[str, Dict[str, str]] = {
    "T1566": {"signal": "Inbound message from a newly-registered sender domain to multiple users",
              "source": "Email security gateway"},
    "T1566.001": {"signal": "Office document with macro spawning a script interpreter",
                  "source": "EDR process telemetry"},
    "T1566.002": {"signal": "User authentication to an unfamiliar identity provider or OAuth consent grant",
                  "source": "Identity provider sign-in logs"},
    "T1078": {"signal": "Valid credentials used from an unusual geography or impossible-travel pair",
              "source": "Identity provider / UEBA"},
    "T1190": {"signal": "Anomalous request pattern to a public-facing service followed by a new child process",
              "source": "WAF logs + server EDR"},
    "T1059.001": {"signal": "Encoded PowerShell command line with a non-interactive parent process",
                  "source": "PowerShell script-block logging"},
    "T1059.003": {"signal": "Command shell spawned by a document or browser process",
                  "source": "EDR process tree"},
    "T1204": {"signal": "User-initiated execution of a file downloaded within the last hour",
              "source": "EDR + proxy correlation"},
    "T1027": {"signal": "High-entropy or base64-encoded command arguments",
              "source": "EDR command-line telemetry"},
    "T1562": {"signal": "Security agent stops reporting, or a protective service is disabled",
              "source": "EDR health monitoring"},
    "T1070": {"signal": "Event log cleared, or a gap appears in forwarded log continuity",
              "source": "SIEM log-integrity monitoring"},
    "T1003": {"signal": "Non-standard process opening a handle to LSASS",
              "source": "EDR credential-access detection"},
    "T1110": {"signal": "High-volume authentication failures across many accounts from one source",
              "source": "Identity provider sign-in logs"},
    "T1621": {"signal": "Repeated denied MFA prompts followed by an approval for one account",
              "source": "MFA provider logs"},
    "T1087": {"signal": "Bulk directory enumeration from a workstation account",
              "source": "Domain controller audit logs"},
    "T1018": {"signal": "Internal host sweeping many peers on a short interval",
              "source": "Network flow / NDR"},
    "T1021.001": {"signal": "First-time RDP session between two workstations",
                  "source": "Windows security event log 4624 type 10"},
    "T1021.002": {"signal": "Remote service creation or admin-share write from a non-admin host",
                  "source": "Windows event logs 7045 / 5145"},
    "T1071": {"signal": "Periodic low-volume outbound traffic to a rare external destination",
              "source": "Network flow / proxy beacon analytics"},
    "T1573": {"signal": "Encrypted session to a destination with no TLS reputation history",
              "source": "TLS metadata inspection"},
    "T1041": {"signal": "Outbound transfer volume far above the host's baseline",
              "source": "Network flow / DLP"},
    "T1567": {"signal": "Large upload to a personal cloud-storage service",
              "source": "Proxy / CASB"},
    "T1486": {"signal": "Rapid, high-volume file modification with entropy change across a share",
              "source": "EDR ransomware canary / file-integrity monitoring"},
    "T1490": {"signal": "Shadow copy deletion or backup catalogue tampering",
              "source": "EDR command-line telemetry"},
    "T1489": {"signal": "Bulk service or process termination on a server",
              "source": "EDR / Windows service control manager logs"},
    "T1657": {"signal": "Payment beneficiary details changed shortly before a transfer",
              "source": "Finance system audit trail"},
}

DEFAULT_DETECTION = {
    "signal": "Deviation from this asset's established behavioural baseline",
    "source": "SIEM correlation",
}

# Decision points are what the exercise is really testing: does the team know
# who decides, and how fast?
DECISION_PROMPTS: Dict[str, str] = {
    "initial-access": "Who authorises pulling the message from all mailboxes, and how long does that take?",
    "execution": "At what point does the SOC isolate an endpoint without waiting for business approval?",
    "persistence": "How do you confirm the environment is clean rather than merely quiet?",
    "privilege-escalation": "Who is called when a domain-level compromise is suspected, out of hours?",
    "stealth": "If the EDR agent goes silent, does that page someone within minutes?",
    "defense-evasion": "If the EDR agent goes silent, does that page someone within minutes?",
    "defense-impairment": "Can security tooling be disabled by a local administrator today?",
    "credential-access": "What is the decision threshold for a domain-wide credential reset?",
    "discovery": "Would internal scanning from a workstation raise an alert or pass unnoticed?",
    "lateral-movement": "Can you segment a subnet during business hours, and who signs that off?",
    "collection": "Do you know which data stores the affected account could reach?",
    "command-and-control": "Who can block an outbound destination at the firewall right now?",
    "exfiltration": "At what data volume does an alert become an incident?",
    "impact": "What is the declared RTO, and when was a restore last actually rehearsed?",
}

SAFETY_NOTICE = (
    "Defensive tabletop exercise. Contains no payloads, commands, exploit code or "
    "attacker infrastructure. Injects are scenario prompts to be read aloud to "
    "participants; they are not to be executed against any system."
)

LLM_SYSTEM = """You design defensive cyber tabletop exercises for SOC teams.

STRICT RULES:
- Output blue-team content ONLY: what defenders observe, decide and do.
- NEVER output payloads, commands, scripts, exploit code, phishing message text,
  domains to register, or any step an attacker could execute.
- Injects describe what the SOC is TOLD has happened, in the passive voice.
- The input is already sanitized; never speculate about redacted values.

Return ONLY JSON:
{
  "objective": "<one sentence: what this exercise tests>",
  "injects": [{"phase": "<tactic slug>", "inject": "<what the team is told>",
               "question": "<the decision the team must make>"}],
  "success_criteria": ["<observable pass condition>", "..."]
}"""


def _headline(dna: dict) -> dict:
    """The scenario header: the at-a-glance card shown in the UI."""
    entry_technique = None
    for technique in dna.get("techniques", []):
        if "initial-access" in technique.get("tactics", []):
            entry_technique = technique
            break
    if entry_technique is None and dna.get("techniques"):
        entry_technique = dna["techniques"][0]

    technique_id = entry_technique["id"] if entry_technique else "—"
    detection = DETECTION_CATALOG.get(technique_id, DEFAULT_DETECTION)

    sector = dna.get("sector", "unknown")
    target = "the affected business unit" if sector == "unknown" else f"{sector.title()} function"

    controls = _headline_controls(dna)
    return {
        "initial_access": entry_technique["name"] if entry_technique else "Not determined",
        "technique": technique_id,
        "target": target,
        "expected_detection": detection["signal"],
        "detection_source": detection["source"],
        "recommended_controls": controls,
    }


def _headline_controls(dna: dict) -> List[str]:
    """Two-to-four headline controls implied by the observed behaviour."""
    technique_ids = {t["id"] for t in dna.get("techniques", [])}
    parents = {tid.split(".")[0] for tid in technique_ids}
    all_ids = technique_ids | parents

    controls: List[str] = []

    def add(control: str) -> None:
        if control not in controls:
            controls.append(control)

    if all_ids & {"T1566", "T1078", "T1110", "T1621"}:
        add("Phishing-resistant MFA")
    if all_ids & {"T1566", "T1204"}:
        add("URL filtering and attachment detonation")
    if all_ids & {"T1078", "T1621", "T1110"}:
        add("Identity monitoring and conditional access")
    if all_ids & {"T1486", "T1490", "T1485"}:
        add("Immutable offline backups with rehearsed restore")
    if all_ids & {"T1059", "T1027", "T1218"}:
        add("Script-block logging and application control")
    if all_ids & {"T1021", "T1550"}:
        add("Network segmentation and privileged access workstations")
    if all_ids & {"T1041", "T1567", "T1048"}:
        add("Egress filtering and DLP on outbound transfers")
    if all_ids & {"T1562", "T1070"}:
        add("EDR tamper protection and off-host log forwarding")
    if all_ids & {"T1190", "T1133"}:
        add("Patch SLAs for internet-facing services and WAF coverage")

    return controls[:4] or ["Baseline logging, MFA and network segmentation"]


def _build_injects(dna: dict) -> List[dict]:
    """One inject per kill-chain phase actually observed, in order."""
    by_tactic: Dict[str, List[dict]] = {}
    for technique in dna.get("techniques", []):
        for tactic in technique.get("tactics", []):
            by_tactic.setdefault(tactic, []).append(technique)

    injects: List[dict] = []
    for step, tactic in enumerate(
        [t for t in TACTIC_ORDER if t in by_tactic], start=1
    ):
        techniques = by_tactic[tactic][:2]
        names = ", ".join(f"{t['name']} ({t['id']})" for t in techniques)
        detection = DETECTION_CATALOG.get(techniques[0]["id"], DEFAULT_DETECTION)

        injects.append({
            "step": step,
            "phase": tactic,
            "phase_label": TACTIC_LABELS.get(tactic, tactic.replace("-", " ").title()),
            "techniques": [t["id"] for t in techniques],
            "inject": (
                f"The SOC is informed that activity consistent with {names} "
                f"has been observed in the environment."
            ),
            "expected_detection": detection["signal"],
            "detection_source": detection["source"],
            "decision_point": DECISION_PROMPTS.get(
                tactic, "What is the next action, and who owns the decision?"
            ),
        })
    return injects


def _success_criteria(dna: dict, injects: List[dict]) -> List[str]:
    criteria = [
        f"Every one of the {len(injects)} phases is detected by an existing rule, "
        "or a detection gap is formally logged.",
        "Containment of the first affected asset is decided within the team's stated MTTR target.",
        "The escalation path to a decision-maker is exercised end to end, including out of hours.",
    ]
    if "data_encrypted" in dna.get("impacts", []):
        criteria.append("A restore from backup is demonstrated against the declared RTO, not merely asserted.")
    if "data_exfiltrated" in dna.get("impacts", []):
        criteria.append("Regulatory notification timelines are identified and the responsible owner named.")
    if dna.get("kev", {}).get("known_exploited_count"):
        criteria.append(
            "The CISA KEV remediation action for "
            f"{', '.join(dna['kev']['known_exploited'])} is confirmed applied or formally risk-accepted."
        )
    return criteria


def _merge_llm_injects(injects: List[dict], llm_result: dict) -> List[dict]:
    """Let the LLM sharpen inject wording; structure and detections stay ours."""
    by_phase = {item.get("phase"): item for item in llm_result.get("injects", [])
                if isinstance(item, dict)}
    for inject in injects:
        enhancement = by_phase.get(inject["phase"])
        if not enhancement:
            continue
        if isinstance(enhancement.get("inject"), str) and enhancement["inject"].strip():
            inject["inject"] = enhancement["inject"].strip()
        if isinstance(enhancement.get("question"), str) and enhancement["question"].strip():
            inject["decision_point"] = enhancement["question"].strip()
    return injects


def build_simulation(dna: dict, use_llm: bool = True) -> dict:
    """Build a safe, defensive tabletop exercise from an incident's Attack DNA."""
    injects = _build_injects(dna)
    headline = _headline(dna)

    objective = (
        f"Test whether the organisation detects and contains a "
        f"{dna.get('attack_type', 'unknown').replace('_', ' ')} incident that begins with "
        f"{headline['initial_access'].lower()}."
    )

    if use_llm and llm_client.is_available() and injects:
        llm_result = llm_client.complete_json(
            LLM_SYSTEM,
            f"Attack DNA:\n{dna.get('signature')}\n\nSummary:\n{dna.get('summary')}\n\n"
            f"Phases observed: {[i['phase'] for i in injects]}",
        )
        if llm_result:
            injects = _merge_llm_injects(injects, llm_result)
            if isinstance(llm_result.get("objective"), str) and llm_result["objective"].strip():
                objective = llm_result["objective"].strip()

    duration = 30 + 10 * len(injects)
    return {
        "title": f"Tabletop: {dna.get('attack_type', 'incident').replace('_', ' ').title()} "
                 f"via {headline['initial_access']}",
        "objective": objective,
        "headline": headline,
        "severity": dna.get("severity", "medium"),
        "estimated_duration_minutes": min(duration, 120),
        "participants": ["SOC analyst (L1/L2)", "Incident response lead", "IT operations",
                         "Business owner of the affected function", "Communications / legal observer"],
        "injects": injects,
        "success_criteria": _success_criteria(dna, injects),
        "safety_notice": SAFETY_NOTICE,
    }
