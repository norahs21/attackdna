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
    extra impacts) and is merged conservatively.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, List, Optional

from app.services import llm_client
from app.services.attribution import attribute
from app.services.ioc_extractor import extract_iocs
from app.services.kev_enricher import enrich_cves, extract_cves, kev_summary
from app.services.knowledge_base import TACTIC_LABELS, TACTIC_ORDER
from app.services.mitre_mapper import map_to_attack
from app.services.negation import is_negated

# --------------------------------------------------------------------------
# Classification vocabularies. Weighted so a single strong keyword beats
# several weak ones ("ransom note" is decisive; "malware" is not).
# --------------------------------------------------------------------------
ATTACK_TYPES: Dict[str, List[tuple]] = {
    "ransomware": [("ransom note", 5), ("ransomware", 5), ("ransom demand", 5),
                   ("files were encrypted", 4), ("encrypted files", 3), ("decryption key", 4),
                   ("double extortion", 4), ("leak site", 3), ("demanded a ransom", 5),
                   ("ransom was paid", 4), ("paid the ransom", 4), ("encrypted the", 3),
                   ("encrypting files", 4), ("decryptor", 4)],
    "phishing": [("phishing", 4), ("spearphishing", 5), ("spear phishing", 5),
                 ("credential harvesting", 4), ("fake login page", 4), ("malicious link", 2),
                 ("malicious attachment", 3), ("smishing", 4), ("vishing", 4),
                 ("spoofed login page", 4), ("fake sign-in page", 4), ("lookalike domain", 3),
                 ("malicious email", 3), ("messages impersonating", 3),
                 ("sign-on page hosted elsewhere", 3)],
    "business_email_compromise": [("business email compromise", 5), ("bec", 4),
                                  ("fraudulent transfer", 5), ("invoice fraud", 5),
                                  ("wire transfer", 3), ("ceo fraud", 5), ("inbox rule", 3),
                                  ("updated banking details", 5), ("new bank account", 4),
                                  ("change of bank details", 5), ("payment redirection", 5),
                                  ("vendor impersonation", 5), ("payroll diversion", 5),
                                  ("paid to a fraudster", 4), ("emails that appeared to come from", 3)],
    "data_breach": [("data breach", 5), ("data exfiltration", 4), ("exfiltrated", 3),
                    ("records were stolen", 5), ("customer data", 3), ("data leak", 4),
                    ("data was stolen", 4), ("records were exfiltrated", 5),
                    ("customer records", 3), ("disclosed a data breach", 5),
                    ("notification obligations", 3), ("data theft", 4),
                    ("records were compromised", 5), ("payment card record", 5),
                    ("were exposed", 4), ("published stolen data", 5),
                    ("leak site", 3), ("stole around", 3), ("personal details", 3),
                    ("personal data", 3), ("personal information", 3), ("was stolen", 4),
                    ("were stolen", 4), ("were taken", 3), ("offered for sale", 4),
                    ("posted on a forum", 4), ("hacking forum", 3), ("were scraped", 4),
                    ("unauthorised access to data", 4), ("unauthorized access to data", 4),
                    ("were accessed", 3), ("data on", 2), ("records with", 2)],
    # Exploitation of an internet-facing system. The original vocabulary here
    # covered web applications only, which left the entry vector of a third of
    # the corpus — including an incident titled "via unpatched VPN appliance" —
    # recorded as "unknown". Edge appliances (VPN concentrators, gateways, file
    # transfer servers) are how a large share of real intrusions now begin, and
    # a report describing one rarely says "web application".
    "web_exploitation": [("sql injection", 5), ("web shell", 5), ("public-facing application", 4),
                         ("remote code execution", 4), ("rce", 3), ("unpatched server", 3),
                         ("web application", 2), ("vpn appliance", 5), ("unpatched appliance", 5),
                         ("file transfer appliance", 5), ("remote access gateway", 4),
                         ("internet-facing", 4), ("edge device", 4), ("perimeter device", 4),
                         ("exploited a vulnerability", 4), ("exploited a zero-day", 5),
                         ("reachable from the internet", 4), ("exposed on the internet", 4),
                         ("exposed to the internet", 4), ("did not require authentication", 4),
                         ("unauthenticated", 3), ("server-side request forgery", 5), ("ssrf", 5),
                         ("idor", 5), ("previously unknown flaw", 4), ("zero-day", 3),
                         ("had not been patched", 4), ("unpatched", 3), ("misconfigured", 2),
                         ("exposed api", 4), ("api endpoint", 2)],
    "credential_attack": [("password spraying", 5), ("brute force", 4), ("credential stuffing", 5),
                          ("mfa fatigue", 5), ("stolen credentials", 3), ("account takeover", 4),
                          # A password that reached the attacker before the attack
                          # began is a credential vector, however it got there.
                          ("credential dump", 4), ("credential marketplace", 4),
                          ("leaked password", 4), ("mfa bombing", 5),
                          ("purchased from a credential", 4), ("failed authentication", 4),
                          ("failed login", 4), ("login attempt", 3), ("password guessing", 4),
                          ("guessed weak password", 4), ("weak password", 3),
                          ("default password", 3), ("password reuse", 4), ("reused password", 4),
                          ("username and password pairs", 5), ("no mfa", 2),
                          ("dormant account", 3),
                          # Access through an account whose password the attacker
                          # already had, on a remote-access server without MFA.
                          ("compromised credentials", 4), ("credentials were compromised", 4),
                          ("compromise of privileged account", 5),
                          ("privileged account credentials", 4),
                          ("not subject to multi-factor", 4), ("without multi-factor", 4),
                          ("no multi-factor", 4), ("lack of mfa", 3),
                          ("third-party access", 2), ("terminal server", 2)],
    "insider_threat": [("insider", 5), ("disgruntled employee", 5), ("departing employee", 4),
                       ("privilege abuse", 3), ("unauthorized access by staff", 4),
                       ("former employee", 5), ("ex-employee", 5), ("terminated employee", 5),
                       ("rogue employee", 5), ("abused their access", 5),
                       ("abused his access", 5), ("abused her access", 5),
                       ("after their employment had ended", 5), ("performance plan", 3),
                       ("outside business hours", 2), ("access had not been removed", 4)],
    "supply_chain": [("supply chain", 5), ("third-party vendor", 4), ("compromised update", 5),
                     ("managed service provider", 4), ("msp", 3),
                     # A signed update carrying a backdoor is the defining shape
                     # of this vector, and reports describe it in these words.
                     ("trojanised update", 5), ("trojanized update", 5),
                     ("build environment", 4), ("signed update", 4), ("auto-update", 4),
                     ("tampered with before release", 5), ("build server", 4),
                     ("typosquatted", 5), ("malicious package", 5), ("dependency confusion", 5),
                     ("outside supplier", 3), ("software supplier", 3)],
    "denial_of_service": [("ddos", 5), ("denial of service", 5), ("traffic flood", 4),
                          ("service unavailable", 2), ("denial-of-service", 5),
                          ("junk traffic", 5), ("flood of traffic", 4), ("volumetric", 4),
                          ("amplification", 4), ("syn flood", 5), ("knocked offline", 3),
                          ("gigabits per second", 4), ("gbps", 4), ("packets per second", 4)],
    "malware_infection": [("trojan", 4), ("infostealer", 5), ("backdoor", 3), ("rootkit", 4),
                          ("botnet", 4), ("cryptominer", 5), ("malware", 2),
                          ("destructive malware", 5), ("wiper", 5), ("information stealer", 5),
                          ("mine cryptocurrency", 5), ("cryptomining", 5), ("xmrig", 5),
                          ("loader", 2), ("payload", 1)],
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
                                   "invoice fraud", "ceo fraud", "payment redirection",
                                   "vendor impersonation", "payroll diversion"]),
    ("denial_of_service", ["ddos", "denial of service", "denial-of-service"]),
    ("insider_threat", ["insider", "disgruntled employee", "former employee", "ex-employee",
                        "rogue employee"]),
]

# What a mapped ATT&CK technique says about the kind of incident. The keyword
# vocabulary above only knows the words someone listed; a technique can be
# found from wording nobody listed (see example_mapper), and an Impact
# technique names the outcome whatever words described it.
TECHNIQUE_TYPE_HINTS: Dict[str, tuple] = {
    "T1486": ("ransomware", 5), "T1490": ("ransomware", 2),
    "T1498": ("denial_of_service", 5), "T1499": ("denial_of_service", 5),
    "T1657": ("business_email_compromise", 3),
    "T1496": ("malware_infection", 4), "T1485": ("malware_infection", 4),
    "T1561": ("malware_infection", 4),
    "T1041": ("data_breach", 2), "T1567": ("data_breach", 2), "T1048": ("data_breach", 2),
    "T1530": ("data_breach", 3), "T1213": ("data_breach", 2),
    "T1566": ("phishing", 4), "T1598": ("phishing", 3),
    "T1110": ("credential_attack", 4), "T1621": ("credential_attack", 4),
    "T1190": ("web_exploitation", 4),
    "T1195": ("supply_chain", 5), "T1199": ("supply_chain", 3),
}

# Words for what kind of organisation something is. Attack DNA does NOT record
# a sector: once names are removed, which industry the victim is in is itself
# something that can point back to it, so it is not inferred or shared. The
# Privacy Layer still uses these words (lexicon.sector_words) to recognise
# company names such as "Colonial Pipeline".
SECTORS: Dict[str, List[str]] = {
    # Only words for what a financial organisation *is*. Every organisation has
    # a finance team, pays invoices, invests in its systems and counts the
    # financial cost of an attack; those words said "finance" about a national
    # library's incident review, so they no longer count.
    "finance": ["bank", "banking", "fintech", "insurance", "sama", "brokerage",
                "financial institution", "financial services", "financial firm",
                "investment firm", "investment bank", "asset manager", "trading platform",
                "credit bureau", "card issuer", "payments firm", "payment processor",
                "payments company", "lender", "stock exchange", "online banking", "insurer",
                "credit union", "bank account holders", "account holders"],
    "healthcare": ["hospital", "clinic", "patient", "medical", "healthcare", "pharmacy", "phi",
                   "clinical", "health regulator", "care provider",
                   "protected health information", "prescription", "healthcare claims",
                   "healthcare payments", "health service", "radiology", "outpatient"],
    "government": ["ministry", "government", "public sector", "municipal", "federal", "agency",
                   "civil service", "state entity", "city government", "state auditor",
                   "council", "municipality", "public agency", "residents", "citizens"],
    "energy": ["oil", "gas", "petrochemical", "refinery", "utility", "power grid", "energy",
               # No bare "pipeline": a CI pipeline is software, not fuel.
               "scada", "ics", "control network", "grid operator", "fuel pipeline",
               "oil pipeline", "gas pipeline", "pipeline operator", "pipeline operations",
               "pipeline company", "fuel", "electricity", "power plant", "drilling"],
    "education": ["university", "school", "student", "college", "campus", "academic", "faculty",
                  "school district"],
    # Note: no bare "store" — it matches "object store", "data store" and would
    # file every cloud incident under retail.
    # "marketplace" alone is dropped: "credential marketplace" is where stolen
    # logins are sold, not a retailer.
    "retail": ["retail", "e-commerce", "ecommerce", "point of sale", "pos terminal",
               "storefront", "retail chain", "merchant", "customer database",
               "online marketplace", "retailer", "shoppers", "online store", "web store",
               "checkout", "point-of-sale", "self-checkout", "loyalty point"],
    # "operator" alone is dropped: pipeline, grid and plant operators are not telecoms.
    "telecom": ["telecom", "isp", "subscriber", "mobile network", "customer portal",
                "mobile operator", "network operator", "mobile carrier", "wireless provider",
                "broadband", "call detail records"],
    "technology": ["saas", "software company", "cloud provider", "tech company", "developer",
                   "software vendor", "engineering team", "source code", "repository",
                   "software provider", "platform provider", "managed service provider",
                   "software product", "management platform", "build environment",
                   "software supplier", "technology company", "software maker",
                   "software startup", "startup", "ci pipeline", "build server", "npm package",
                   "kubernetes", "cloud bill"],
    "manufacturing": ["factory", "manufacturing", "production line", "plant", "industrial",
                      "assembly line", "manufacturer", "production scheduling"],
    # Libraries, museums, archives and heritage bodies: frequent ransomware
    # targets with no sector of their own before (found with the British
    # Library's 2024 incident review). No bare "library": a code library is
    # software.
    "culture": ["national library", "public library", "public libraries", "the library",
                "library services", "library users", "reading room", "reading rooms",
                "libraries", "museum", "museums", "heritage", "archives", "gallery",
                "galleries", "exhibition", "exhibitions", "cultural", "collections",
                "manuscripts"],
    "logistics": ["logistics", "shipping", "port", "freight", "supply depot", "warehouse",
                  "container tracking", "cargo", "freight forwarder", "shipment", "customs",
                  "consignment"],
}

IMPACTS: Dict[str, List[str]] = {
    # No bare "locked": "accounts were locked" is the response to a password
    # attack, and reading it as encryption made a credential incident critical.
    "data_encrypted": ["encrypted", "ransomware", "unable to open files", "files were locked",
                       "locked files", "systems were locked", "encrypting"],
    "data_exfiltrated": ["exfiltrated", "data theft", "stolen data", "uploaded to", "data leak"],
    "service_disruption": ["outage", "downtime", "unavailable", "disrupted", "offline",
                           "operations halted", "service disruption"],
    # Currency codes carry no trailing space: whole-word matching handles the
    # separator, and a trailing space would make the term unmatchable.
    "financial_loss": ["financial loss", "fraudulent transfer", "funds", "sar", "usd",
                       "ransom paid", "monetary", "financial impact", "paid a ransom",
                       "cost of around", "estimated cost"],
    "credential_compromise": ["credentials were compromised", "password reset", "account compromised",
                              "credential dumping", "stolen credentials", "stolen password",
                              "compromised password", "corporate password", "obtained a password",
                              "credentials were stolen", "accounts were compromised",
                              "account was compromised", "were compromised", "compromised accounts",
                              "accounts were accessed", "submitted credentials",
                              "typed in their username and password", "harvested credentials"],
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
  "technique_ids": ["T1566.002", "..."],
  "impacts": ["<subset of: data_encrypted, data_exfiltrated, service_disruption, financial_loss, credential_compromise, regulatory_exposure>"],
  "summary": "<two-sentence, victim-free description of the attack chain>",
  "root_cause": "<one sentence on the control gap that allowed it>"
}
Only include technique_ids you can justify from the text."""


_IS_RANSOMWARE_RE = re.compile(
    r"\bis (?:a |an )?(?:[\w\-]+ ){0,4}ransomware\b|\bransomware-as-a-service\b", re.I)


@lru_cache(maxsize=1)
def _ransomware_families() -> tuple:
    """Names of ransomware families, read from ATT&CK's software catalogue.

    "LockBit was pushed to every machine" never says ransomware. Only names
    that are not also English words are used — "Royal" and "Play" are
    families too, and matching those would file every report that mentions a
    royal commission under ransomware.
    """
    from app.services import lexicon
    from app.services.knowledge_base import load_software

    families = set()
    for record in load_software():
        # "X is a ransomware ...", not "X is a tool ransomware groups use".
        if not _IS_RANSOMWARE_RE.search((record.get("description") or "")[:300]):
            continue
        first = re.split(r"[^A-Za-z0-9]+", record.get("name", "").strip())[0].lower()
        if len(first) >= 4 and not lexicon.is_ordinary(first):
            families.add(first)
    return tuple(sorted(families))


def _term_matches(term: str, text_lower: str) -> bool:
    """Whole-word match that tolerates a simple plural.

    Boundaries stop "isp" firing inside "dispute"; the optional plural stops the
    boundaries from rejecting "plants" for the term "plant". Both failures were
    found by running real published breach reports through the extractor, and
    each silently mis-filed incidents.
    """
    pattern = re.compile(rf"(?<![a-z0-9]){re.escape(term)}(?:e?s)?(?![a-z0-9])")
    # A term the report denies is not evidence: "no data was exfiltrated" must
    # not raise the severity for exfiltration.
    return any(not is_negated(text_lower, match.start())
               for match in pattern.finditer(text_lower))


def _score_category(text_lower: str, vocab: Dict[str, List[tuple]]) -> Dict[str, int]:
    scores: Dict[str, int] = {}
    for label, terms in vocab.items():
        total = sum(weight for term, weight in terms if _term_matches(term, text_lower))
        if total:
            scores[label] = total
    return scores


def _decisive_type(text_lower: str) -> Optional[str]:
    """The attack type fixed by an unambiguous marker, if one is present."""
    for attack_type, markers in DECISIVE_MARKERS:
        for marker in markers:
            if _term_matches(marker, text_lower):
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
    """Count distinct vocabulary terms present, matching on word boundaries.

    Boundaries are not optional here. Plain substring matching makes "isp" fire
    on "dispute" and "ics" on "logistics", which silently files incidents under
    the wrong category — a bug found by running real public breach reports through
    the extractor.
    """
    scores: Dict[str, int] = {}
    for label, terms in vocab.items():
        hits = sum(1 for term in terms if _term_matches(term, text_lower))
        if hits:
            scores[label] = hits
    return scores


def _rule_based_dna(sanitized_text: str, ioc_counts: Dict[str, int]) -> dict:
    text_lower = (sanitized_text or "").lower()

    mapping = map_to_attack(sanitized_text)

    type_scores = _score_category(text_lower, ATTACK_TYPES)
    for family in _ransomware_families():
        if _term_matches(family, text_lower):
            type_scores["ransomware"] = type_scores.get("ransomware", 0) + 4
            break
    for technique in mapping["techniques"]:
        hint = TECHNIQUE_TYPE_HINTS.get(technique["id"].split(".")[0])
        if hint:
            label, weight = hint
            # A technique the report states outright counts in full; one that
            # was only inferred from resemblance counts for less.
            if technique["confidence"] < 0.7:
                weight = max(1, weight - 2)
            type_scores[label] = type_scores.get(label, 0) + weight
    attack_type, initial_vector = _classify_attack(type_scores, text_lower)

    impact_scores = _match_keywords(text_lower, IMPACTS)
    impacts = sorted(impact_scores, key=impact_scores.get, reverse=True)

    cves = extract_cves(sanitized_text)

    return {
        "attack_type": attack_type,
        "initial_vector": initial_vector,
        "attack_type_candidates": dict(sorted(type_scores.items(), key=lambda kv: -kv[1])),
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
    vector = dna.get("initial_vector", "unknown")
    entry = f" entered via {vector.replace('_', ' ')}," if vector not in ("unknown", dna["attack_type"]) else ""
    return (
        f"A {type_label} incident{entry} following {chain}. "
        f"Observed impact: {impacts}."
    )


# Tactics that mean the attacker was operating inside the environment, as
# opposed to knocking on it from outside.
INTRUSION_TACTICS = {"execution", "persistence", "privilege-escalation", "credential-access",
                     "lateral-movement", "command-and-control", "exfiltration"}


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
    # A confirmed foothold is never "low", even when it was contained before
    # it cost anything: a remote access trojan that was caught is still an
    # intrusion, and the next one may not be.
    if INTRUSION_TACTICS & set(dna.get("tactics", [])):
        return "medium"
    return "low"


def build_signature(dna: dict) -> str:
    """A compact, human-readable fingerprint used for display and matching.

    Example:
        RANSOMWARE | initial-access:T1566.002 > execution:T1059.001
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
    return f"{dna['attack_type'].upper()} | {chain} | impact:{impacts}"


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
    "attack_type": str, "initial_vector": str, "severity": str,
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
