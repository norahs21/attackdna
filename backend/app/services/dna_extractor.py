"""Attack DNA extraction — the core abstraction of ATTACKDNA.

"Attack DNA" is the reusable, victim-free fingerprint of an incident: what kind
of attack it was, which ATT&CK behaviours it used, which known-exploited
vulnerabilities were involved, what classes of indicator appeared, and what the
business impact was.

Two incidents at two different organisations that share a DNA signature are
comparable — which is what makes a past incident's response reusable today.

Extraction is hybrid:
  * a deterministic rule layer always runs and always produces a complete DNA;
  * an optional LLM layer enriches it (narrative summary, extra techniques,
    sharper sector/impact calls) and is merged conservatively.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from app.services import llm_client
from app.services.attribution import attribute
from app.services.ioc_extractor import extract_iocs
from app.services.kev_enricher import enrich_cves, extract_cves, kev_summary
from app.services.knowledge_base import TACTIC_LABELS, TACTIC_ORDER
from app.services.mitre_mapper import map_to_attack

# --------------------------------------------------------------------------
# Classification vocabularies. Weighted so a single strong keyword beats
# several weak ones ("ransom note" is decisive; "malware" is not).
# --------------------------------------------------------------------------
ATTACK_TYPES: Dict[str, List[tuple]] = {
    "ransomware": [("ransom note", 5), ("ransomware", 5), ("ransom demand", 5),
                   ("files were encrypted", 4), ("encrypted files", 3), ("decryption key", 4),
                   ("double extortion", 4), ("leak site", 3)],
    "phishing": [("phishing", 4), ("spearphishing", 5), ("spear phishing", 5),
                 ("credential harvesting", 4), ("fake login page", 4), ("malicious link", 2),
                 ("malicious attachment", 3)],
    "business_email_compromise": [("business email compromise", 5), ("bec", 4),
                                  ("fraudulent transfer", 5), ("invoice fraud", 5),
                                  ("wire transfer", 3), ("ceo fraud", 5), ("inbox rule", 3)],
    "data_breach": [("data breach", 5), ("data exfiltration", 4), ("exfiltrated", 3),
                    ("records were stolen", 5), ("customer data", 3), ("data leak", 4),
                    ("data was stolen", 4), ("records were exfiltrated", 5),
                    ("customer records", 3), ("disclosed a data breach", 5),
                    ("notification obligations", 3), ("data theft", 4)],
    "web_exploitation": [("sql injection", 5), ("web shell", 5), ("public-facing application", 4),
                         ("remote code execution", 4), ("rce", 3), ("unpatched server", 3),
                         ("web application", 2)],
    "credential_attack": [("password spraying", 5), ("brute force", 4), ("credential stuffing", 5),
                          ("mfa fatigue", 5), ("stolen credentials", 3), ("account takeover", 4)],
    "insider_threat": [("insider", 5), ("disgruntled employee", 5), ("departing employee", 4),
                       ("privilege abuse", 3), ("unauthorized access by staff", 4)],
    "supply_chain": [("supply chain", 5), ("third-party vendor", 4), ("compromised update", 5),
                     ("managed service provider", 4), ("msp", 3)],
    "denial_of_service": [("ddos", 5), ("denial of service", 5), ("traffic flood", 4),
                          ("service unavailable", 2)],
    "malware_infection": [("trojan", 4), ("infostealer", 5), ("backdoor", 3), ("rootkit", 4),
                          ("botnet", 4), ("cryptominer", 5), ("malware", 2)],
}

# How the attacker got in vs. what they ultimately did. A report that says
# "phishing led to ransomware" is a ransomware incident that arrived by
# phishing — classifying it as "phishing" would file it next to the wrong
# playbooks. Splitting the two keeps both facts.
VECTOR_TYPES = {"phishing", "credential_attack", "web_exploitation", "supply_chain"}
OUTCOME_TYPES = set(ATTACK_TYPES) - VECTOR_TYPES

# Minimum score for an outcome to outrank a higher-scoring entry vector.
OUTCOME_PRIORITY_THRESHOLD = 4

# Phrases that settle the classification on their own, whatever else scored.
# Without these, a double-extortion ransomware incident gets filed as a data
# breach: it mentions exfiltration and stolen customer data several times, but
# encrypts files once. Encryption for impact is unambiguous, so it decides —
# the exfiltration is still recorded in `impacts`, so nothing is lost.
DECISIVE_MARKERS: List[tuple] = [
    ("ransomware", ["ransomware", "ransom note", "ransom demand", "files were encrypted",
                    "encrypted files", "double extortion", "decryption key"]),
    ("business_email_compromise", ["business email compromise", "fraudulent transfer",
                                   "invoice fraud", "ceo fraud"]),
    ("denial_of_service", ["ddos", "denial of service"]),
    ("insider_threat", ["insider", "disgruntled employee"]),
]

# Sector vocabulary. These deliberately favour words describing the affected
# *function* over words in the organisation's name, because the Privacy Layer
# redacts company names: "Qasr Financial Group" becomes "[ORG_REDACTED] Group"
# and takes the word "Financial" with it. What survives is how the analyst
# described the business — "the accounting division", "clinical workstations",
# "the subscriber portal" — so that is what the classifier reads.
SECTORS: Dict[str, List[str]] = {
    "finance": ["bank", "banking", "financial", "fintech", "insurance", "payment", "sama",
                "trading", "brokerage", "finance department", "finance team", "finance officer",
                "accounting", "accounts payable", "treasury", "wire transfer", "client records",
                "investment"],
    "healthcare": ["hospital", "clinic", "patient", "medical", "healthcare", "pharmacy", "phi",
                   "clinical", "health regulator", "care provider"],
    "government": ["ministry", "government", "public sector", "municipal", "federal", "agency",
                   "civil service", "state entity"],
    "energy": ["oil", "gas", "petrochemical", "refinery", "utility", "power grid", "energy",
               "scada", "ics", "control network", "grid operator"],
    "education": ["university", "school", "student", "college", "campus", "academic", "faculty"],
    # Note: no bare "store" — it matches "object store", "data store" and would
    # file every cloud incident under retail.
    "retail": ["retail", "e-commerce", "ecommerce", "point of sale", "pos terminal",
               "storefront", "retail chain", "merchant", "marketplace", "customer database",
               "online marketplace"],
    "telecom": ["telecom", "operator", "isp", "subscriber", "mobile network", "customer portal"],
    "technology": ["saas", "software company", "cloud provider", "tech company", "developer",
                   "software vendor", "engineering team", "source code", "repository",
                   "software provider", "platform provider"],
    "manufacturing": ["factory", "manufacturing", "production line", "plant", "industrial",
                      "assembly line"],
    "logistics": ["logistics", "shipping", "port", "freight", "supply depot", "warehouse",
                  "container tracking", "cargo"],
}

IMPACTS: Dict[str, List[str]] = {
    "data_encrypted": ["encrypted", "ransomware", "unable to open files", "locked"],
    "data_exfiltrated": ["exfiltrated", "data theft", "stolen data", "uploaded to", "data leak"],
    "service_disruption": ["outage", "downtime", "unavailable", "disrupted", "offline",
                           "operations halted", "service disruption"],
    "financial_loss": ["financial loss", "fraudulent transfer", "funds", "sar ", "usd ",
                       "ransom paid", "monetary"],
    "credential_compromise": ["credentials were compromised", "password reset", "account compromised",
                              "credential dumping", "stolen credentials"],
    "regulatory_exposure": ["regulator", "notification obligation", "gdpr", "pdpl", "compliance breach",
                            "reportable"],
}

SEVERITY_WEIGHTS = {
    "data_encrypted": 3,
    "data_exfiltrated": 3,
    "service_disruption": 2,
    "financial_loss": 3,
    "credential_compromise": 2,
    "regulatory_exposure": 2,
}

LLM_SYSTEM = """You are a defensive cyber-threat-intelligence analyst.
You receive an ALREADY SANITIZED incident report — all identifying values have
been replaced with tokens like [IP_REDACTED] or [ORG_REDACTED]. Never try to
guess, reconstruct or invent what those tokens originally were.

Summarise the attack's behaviour for defensive reuse. Output ONLY a JSON object:
{
  "attack_type": "<one of: ransomware, phishing, business_email_compromise, data_breach, web_exploitation, credential_attack, insider_threat, supply_chain, denial_of_service, malware_infection, unknown>",
  "sector": "<one of: finance, healthcare, government, energy, education, retail, telecom, technology, manufacturing, logistics, unknown>",
  "technique_ids": ["T1566.002", "..."],
  "impacts": ["<subset of: data_encrypted, data_exfiltrated, service_disruption, financial_loss, credential_compromise, regulatory_exposure>"],
  "summary": "<two-sentence, victim-free description of the attack chain>",
  "root_cause": "<one sentence on the control gap that allowed it>"
}
Only include technique_ids you can justify from the text."""


def _score_category(text_lower: str, vocab: Dict[str, List[tuple]]) -> Dict[str, int]:
    scores: Dict[str, int] = {}
    for label, terms in vocab.items():
        total = 0
        for term, weight in terms:
            if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text_lower):
                total += weight
        if total:
            scores[label] = total
    return scores


def _decisive_type(text_lower: str) -> Optional[str]:
    """The attack type fixed by an unambiguous marker, if one is present."""
    for attack_type, markers in DECISIVE_MARKERS:
        for marker in markers:
            if re.search(rf"(?<![a-z0-9]){re.escape(marker)}(?![a-z0-9])", text_lower):
                return attack_type
    return None


def _classify_attack(type_scores: Dict[str, int], text_lower: str) -> tuple:
    """Split the classification into (what it became, how it started)."""
    if not type_scores:
        return "unknown", "unknown"

    outcomes = {k: v for k, v in type_scores.items() if k in OUTCOME_TYPES}
    vectors = {k: v for k, v in type_scores.items() if k in VECTOR_TYPES}

    initial_vector = max(vectors, key=vectors.get) if vectors else "unknown"

    decisive = _decisive_type(text_lower)
    if decisive:
        attack_type = decisive
    elif outcomes and max(outcomes.values()) >= OUTCOME_PRIORITY_THRESHOLD:
        # A clearly-evidenced outcome defines the incident even when the entry
        # vector was mentioned more often.
        attack_type = max(outcomes, key=outcomes.get)
    else:
        attack_type = max(type_scores, key=type_scores.get)
    return attack_type, initial_vector


def _match_keywords(text_lower: str, vocab: Dict[str, List[str]]) -> Dict[str, int]:
    scores: Dict[str, int] = {}
    for label, terms in vocab.items():
        hits = sum(1 for term in terms if term in text_lower)
        if hits:
            scores[label] = hits
    return scores


def _rule_based_dna(sanitized_text: str, ioc_counts: Dict[str, int]) -> dict:
    text_lower = (sanitized_text or "").lower()

    type_scores = _score_category(text_lower, ATTACK_TYPES)
    attack_type, initial_vector = _classify_attack(type_scores, text_lower)

    sector_scores = _match_keywords(text_lower, SECTORS)
    sector = max(sector_scores, key=sector_scores.get) if sector_scores else "unknown"

    impact_scores = _match_keywords(text_lower, IMPACTS)
    impacts = sorted(impact_scores, key=impact_scores.get, reverse=True)

    mapping = map_to_attack(sanitized_text)
    cves = extract_cves(sanitized_text)

    return {
        "attack_type": attack_type,
        "initial_vector": initial_vector,
        "attack_type_candidates": dict(sorted(type_scores.items(), key=lambda kv: -kv[1])),
        "sector": sector,
        "techniques": mapping["techniques"],
        "tactics": mapping["tactics"],
        "cves": cves,
        "impacts": impacts,
        "ioc_classes": ioc_counts,
        "summary": "",
        "root_cause": "",
    }


def _merge_llm(dna: dict, sanitized_text: str, llm_result: Optional[dict]) -> dict:
    """Fold LLM output into rule-based DNA. The rules win on ties."""
    if not llm_result:
        dna["extraction_mode"] = "rule-based"
        return dna

    dna["extraction_mode"] = "hybrid (rules + LLM)"

    # The LLM only decides classification where the rules found nothing.
    if dna["attack_type"] == "unknown" and llm_result.get("attack_type") in ATTACK_TYPES:
        dna["attack_type"] = llm_result["attack_type"]
        if dna.get("initial_vector") == "unknown" and dna["attack_type"] in VECTOR_TYPES:
            dna["initial_vector"] = dna["attack_type"]
    if dna["sector"] == "unknown" and llm_result.get("sector") in SECTORS:
        dna["sector"] = llm_result["sector"]

    # Techniques are additive: re-run the mapper so LLM ids get the same
    # enrichment, confidence scoring and parent/sub-technique handling.
    extra_ids = [tid for tid in llm_result.get("technique_ids", []) if isinstance(tid, str)]
    if extra_ids:
        merged = map_to_attack(sanitized_text, extra_technique_ids=extra_ids)
        dna["techniques"] = merged["techniques"]
        dna["tactics"] = merged["tactics"]

    for impact in llm_result.get("impacts", []):
        if impact in IMPACTS and impact not in dna["impacts"]:
            dna["impacts"].append(impact)

    if isinstance(llm_result.get("summary"), str):
        dna["summary"] = llm_result["summary"].strip()
    if isinstance(llm_result.get("root_cause"), str):
        dna["root_cause"] = llm_result["root_cause"].strip()
    return dna


def _fallback_summary(dna: dict) -> str:
    """A readable summary when no LLM produced one."""
    type_label = dna["attack_type"].replace("_", " ")
    chain = " → ".join(TACTIC_LABELS.get(t, t.title()) for t in dna["tactics"][:5]) or "an unclassified chain"
    impacts = ", ".join(i.replace("_", " ") for i in dna["impacts"][:3]) or "no impact recorded"
    sector = dna["sector"].replace("_", " ")
    where = f" against a {sector} organisation" if sector != "unknown" else ""
    vector = dna.get("initial_vector", "unknown")
    entry = f" entered via {vector.replace('_', ' ')}," if vector not in ("unknown", dna["attack_type"]) else ""
    return (
        f"A {type_label} incident{where}{entry} following {chain}. "
        f"Observed impact: {impacts}."
    )


def _severity(dna: dict, kev_info: dict) -> str:
    score = sum(SEVERITY_WEIGHTS.get(impact, 1) for impact in dna["impacts"])
    score += 3 if kev_info["known_exploited_count"] else 0
    score += min(3, len(dna["techniques"]) // 3)
    if score >= 9:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def build_signature(dna: dict) -> str:
    """A compact, human-readable fingerprint used for display and matching.

    Example:
        RANSOMWARE | finance | initial-access:T1566.002 > execution:T1059.001
        > impact:T1486 | impact:data_encrypted+data_exfiltrated

    The chain is ordered by the kill chain, not by confidence, so the signature
    reads as the attack actually unfolded.
    """
    def chain_position(technique: dict) -> int:
        tactic = technique["tactics"][0] if technique["tactics"] else ""
        return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)

    top = sorted(dna["techniques"][:6], key=chain_position)
    steps = []
    for technique in top:
        tactic = technique["tactics"][0] if technique["tactics"] else "unmapped"
        steps.append(f"{tactic}:{technique['id']}")
    chain = " > ".join(steps) if steps else "no-techniques"
    impacts = "+".join(dna["impacts"][:4]) if dna["impacts"] else "none"
    return f"{dna['attack_type'].upper()} | {dna['sector']} | {chain} | impact:{impacts}"


def embedding_text(dna: dict) -> str:
    """The text actually embedded into vector memory.

    Deliberately built from DNA fields — never from the raw report — so the
    vector store can only ever contain victim-free behavioural language.
    """
    technique_text = ", ".join(f"{t['id']} {t['name']}" for t in dna["techniques"])
    tactic_text = ", ".join(TACTIC_LABELS.get(t, t) for t in dna["tactics"])
    return (
        f"Attack type: {dna['attack_type'].replace('_', ' ')}. "
        f"Initial vector: {dna.get('initial_vector', 'unknown').replace('_', ' ')}. "
        f"Sector: {dna['sector']}. "
        f"Tactics: {tactic_text}. "
        f"Techniques: {technique_text}. "
        f"Vulnerabilities: {', '.join(dna['cves']) or 'none'}. "
        f"Impact: {', '.join(dna['impacts']) or 'none'}. "
        f"{dna.get('summary', '')}"
    ).strip()


def extract_dna(sanitized_text: str, ioc_counts: Dict[str, int] | None = None,
                use_llm: bool = True) -> dict:
    """Extract the full Attack DNA from a sanitized incident report."""
    dna = _rule_based_dna(sanitized_text, ioc_counts or {})

    llm_result = None
    if use_llm and llm_client.is_available():
        llm_result = llm_client.complete_json(LLM_SYSTEM, sanitized_text)
    dna = _merge_llm(dna, sanitized_text, llm_result)

    if not dna.get("summary"):
        dna["summary"] = _fallback_summary(dna)

    enriched_cves = enrich_cves(dna["cves"])
    dna["cve_details"] = enriched_cves
    dna["kev"] = kev_summary(enriched_cves)
    dna["iocs"] = extract_iocs(sanitized_text, ioc_counts or {})
    dna["attribution"] = attribute([t["id"] for t in dna["techniques"]])
    dna["severity"] = _severity(dna, dna["kev"])
    dna["signature"] = build_signature(dna)
    dna["embedding_text"] = embedding_text(dna)

    problems = validate_dna(dna)
    dna["validation"] = {"valid": not problems, "problems": problems}
    return dna


# --------------------------------------------------------------------------
# Schema validation
# --------------------------------------------------------------------------
REQUIRED_FIELDS = {
    "attack_type": str, "initial_vector": str, "sector": str, "severity": str,
    "signature": str, "summary": str, "embedding_text": str, "extraction_mode": str,
    "techniques": list, "tactics": list, "cves": list, "cve_details": list,
    "impacts": list, "ioc_classes": dict, "kev": dict, "iocs": dict, "attribution": dict,
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def validate_dna(dna: dict) -> List[str]:
    """Check an extracted DNA against its schema. Returns a list of problems.

    Run on every extraction so a malformed result is visible immediately rather
    than surfacing three stages later as an empty panel in the UI.
    """
    problems: List[str] = []

    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in dna:
            problems.append(f"missing field: {field}")
        elif not isinstance(dna[field], expected_type):
            problems.append(
                f"{field} should be {expected_type.__name__}, got {type(dna[field]).__name__}"
            )

    if dna.get("attack_type") not in set(ATTACK_TYPES) | {"unknown"}:
        problems.append(f"unknown attack_type: {dna.get('attack_type')}")
    if dna.get("sector") not in set(SECTORS) | {"unknown"}:
        problems.append(f"unknown sector: {dna.get('sector')}")
    if dna.get("severity") not in VALID_SEVERITIES:
        problems.append(f"invalid severity: {dna.get('severity')}")

    for technique in dna.get("techniques", []):
        if not isinstance(technique, dict) or "id" not in technique:
            problems.append(f"malformed technique entry: {technique!r}")
            continue
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique["id"]):
            problems.append(f"invalid technique id: {technique['id']}")
        if not technique.get("evidence"):
            problems.append(f"{technique['id']} has no supporting evidence")

    for impact in dna.get("impacts", []):
        if impact not in IMPACTS:
            problems.append(f"unknown impact: {impact}")

    # The privacy invariant: nothing identifying may reach the vector store.
    embedded = dna.get("embedding_text", "")
    if "REDACTED" in embedded:
        problems.append("embedding_text contains redaction tokens")
    if re.search(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", embedded):
        problems.append("embedding_text contains an email address")

    return problems
