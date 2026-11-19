"""Two independent opinions on what an incident was and how it started.

The attack type ("ransomware") and the entry vector ("phishing") used to come
from one place: vocabularies of words in the report. Words miss paraphrase.
"A user clicked a link in an email" says phishing to any analyst and to no
keyword list that lacks those exact words.

This module adds a second opinion that does not read words at all. It reads
the *behaviour* the pipeline already found: the ATT&CK techniques (some found
by rules, some by the classifier trained on MITRE's ~17,600 labelled
examples) and the CISA known-exploited vulnerabilities. A report mapped to
T1566 started with phishing whatever words it used; a report naming a CVE
that CISA lists as exploited in the wild most likely began with exploitation.

    words voter       vocabularies over the report text
    behaviour voter   techniques + KEV, no text

The two are combined the way the technique mapper already combines its paths:

* **They agree**: confidence high. Two independent paths found the same answer.
* **Only one speaks**: its answer stands, confidence medium.
* **They disagree**: the pipeline's combined answer stands, confidence low,
  and the other answer is kept as the alternative, so an analyst sees the doubt
  instead of a confident label.
* **Neither speaks**: "unknown". Nothing is guessed.

The behaviour voter never overrides a known answer. It fills an "unknown" and
it measures confidence. That keeps every score already reported for the
pipeline (and every test that pins one) unchanged, while the gaps close.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

# --------------------------------------------------------------------------
# What each behaviour says about the incident. Technique families only: a
# sub-technique (T1566.002) counts for its parent (T1566).
# --------------------------------------------------------------------------
BEHAVIOUR_EVIDENCE: Dict[str, List[tuple]] = {
    # How the attacker got in.
    "T1566": [("phishing", 4)],                 # Phishing
    "T1598": [("phishing", 3)],                 # Phishing for Information
    "T1204": [("phishing", 3)],                 # User Execution (opened a link or file)
    "T1190": [("web_exploitation", 4)],         # Exploit Public-Facing Application
    "T1110": [("credential_attack", 4)],        # Brute Force (spraying, stuffing)
    "T1621": [("credential_attack", 4)],        # MFA Request Generation (MFA fatigue)
    # Not T1078 (Valid Accounts): attackers use valid accounts *after* every
    # kind of entry, so it says little about how they got in. Counting it made
    # an exploited Citrix gateway and an insider read as credential attacks.
    "T1195": [("supply_chain", 5)],             # Supply Chain Compromise
    "T1199": [("supply_chain", 3)],             # Trusted Relationship
    # What it became.
    "T1486": [("ransomware", 5)],               # Data Encrypted for Impact
    "T1490": [("ransomware", 2)],               # Inhibit System Recovery
    "T1498": [("denial_of_service", 5)],        # Network Denial of Service
    "T1499": [("denial_of_service", 5)],        # Endpoint Denial of Service
    "T1657": [("business_email_compromise", 3)],  # Financial Theft
    "T1496": [("malware_infection", 4)],        # Resource Hijacking (cryptomining)
    "T1485": [("malware_infection", 4)],        # Data Destruction (wipers)
    "T1561": [("malware_infection", 4)],        # Disk Wipe
    "T1041": [("data_breach", 2)],              # Exfiltration Over C2 Channel
    "T1567": [("data_breach", 2)],              # Exfiltration Over Web Service
    "T1048": [("data_breach", 2)],              # Exfiltration Over Alternative Protocol
    "T1530": [("data_breach", 3)],              # Data from Cloud Storage
    "T1213": [("data_breach", 2)],              # Data from Information Repositories
}

# A CVE that CISA lists as exploited in the wild is evidence the attack began
# with exploitation, but only when nothing else explains the entry: a phishing
# document that abuses a Windows flaw is still phishing.
KEV_EVIDENCE = ("web_exploitation", 3)

# A technique the report states outright counts in full; one that was only
# inferred (by resemblance to MITRE's examples) counts for less. Same rule the
# words path applies to its technique hints.
INFERRED_BELOW = 0.7
INFERRED_PENALTY = 2

VECTOR_LABELS = {"phishing", "credential_attack", "web_exploitation", "supply_chain"}

UNKNOWN = "unknown"


def behaviour_scores(techniques: List[dict], kev: Optional[dict]) -> Dict[str, int]:
    """Class scores from detected behaviour alone, no report text."""
    scores: Dict[str, int] = {}
    for technique in techniques or []:
        family = str(technique.get("id", "")).split(".")[0]
        for label, weight in BEHAVIOUR_EVIDENCE.get(family, []):
            if technique.get("confidence", 1.0) < INFERRED_BELOW:
                weight = max(1, weight - INFERRED_PENALTY)
            scores[label] = scores.get(label, 0) + weight

    if (kev or {}).get("known_exploited_count") and not VECTOR_LABELS & set(scores):
        label, weight = KEV_EVIDENCE
        scores[label] = scores.get(label, 0) + weight
    return scores


def _agreement(words: str, behaviour: str) -> str:
    if words != UNKNOWN and behaviour != UNKNOWN:
        return "agree" if words == behaviour else "disagree"
    if words != UNKNOWN:
        return "words only"
    if behaviour != UNKNOWN:
        return "behaviour only"
    return "none"


CONFIDENCE = {
    "agree": "high",
    "words only": "medium",
    "behaviour only": "medium",
    "disagree": "low",
    "none": "none",
}


def vote(dna: dict, words: Dict[str, str], behaviour: Dict[str, str]) -> dict:
    """Fill unknowns from behaviour and record how sure each answer is.

    `dna` holds the pipeline's combined answer and is updated in place only
    where that answer is "unknown". `words` and `behaviour` are each voter's
    own answer: {"attack_type": ..., "initial_vector": ...}.
    """
    record = {}
    for field in ("attack_type", "initial_vector"):
        said_by_words = words.get(field) or UNKNOWN
        said_by_behaviour = behaviour.get(field) or UNKNOWN
        heard_from_behaviour = said_by_behaviour
        # When behaviour saw only how the attack started (its "attack type" is
        # an entry vector) and the words name an outcome, behaviour has no
        # opinion on the outcome: that is silence, not disagreement. Invoice
        # fraud that arrived by phishing is not in dispute.
        if (field == "attack_type" and said_by_behaviour in VECTOR_LABELS
                and said_by_words not in VECTOR_LABELS | {UNKNOWN}):
            heard_from_behaviour = UNKNOWN
        agreement = _agreement(said_by_words, heard_from_behaviour)

        # Behaviour may name what the attack *became* only from an outcome
        # (encryption, exfiltration, wiping). Entry evidence alone (a phishing
        # technique, an exploited CVE) says how it started, not what it was.
        may_fill = said_by_behaviour != UNKNOWN and not (
            field == "attack_type" and said_by_behaviour in VECTOR_LABELS)

        decided_by = "combined"
        if (dna.get(field) or UNKNOWN) == UNKNOWN and may_fill:
            dna[field] = said_by_behaviour
            decided_by = "behaviour"
        elif (dna.get(field) or UNKNOWN) == UNKNOWN:
            decided_by = "none"

        final = dna.get(field) or UNKNOWN
        alternative = None
        if agreement == "disagree":
            alternative = said_by_behaviour if final == said_by_words else said_by_words

        record[field] = {
            # True when behaviour only showed how the attack started, so it
            # was not counted as an opinion on what the attack became.
            "behaviour_entry_only": heard_from_behaviour != said_by_behaviour,
            "value": final,
            "confidence": CONFIDENCE[agreement],
            "agreement": agreement,
            "words": said_by_words,
            "behaviour": said_by_behaviour,
            "decided_by": decided_by,
            "alternative": alternative,
        }
    return record


def classify_both(word_type_scores: Dict[str, int], word_entry_scores: Dict[str, int],
                  techniques: List[dict], kev: Optional[dict],
                  classify: Callable[..., tuple], text_lower: str = "") -> Dict[str, Dict[str, str]]:
    """Each voter's answer, using the pipeline's own classification rule.

    `classify(type_scores, text_lower, entry_scores)` is the extractor's
    `_classify_attack`, passed in so both voters split "what it became" from
    "how it started" by exactly the same rule. Only the words voter sees the
    text (for decisive markers such as "ransom note"); the behaviour voter
    sees none.
    """
    w_type, w_vector = classify(dict(word_type_scores), text_lower, dict(word_entry_scores))
    b_type, b_vector = classify(behaviour_scores(techniques, kev), "", {})
    return {
        "words": {"attack_type": w_type, "initial_vector": w_vector},
        "behaviour": {"attack_type": b_type, "initial_vector": b_vector},
    }
