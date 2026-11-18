"""The words-and-behaviour vote on attack type and entry vector."""
from app.services import classification_vote as cv
from app.services.dna_extractor import extract_dna
from app.services.sanitizer import sanitize


def _dna(text: str) -> dict:
    return extract_dna(sanitize(text).sanitized_text, {}, use_llm=False)


def _technique(tid: str, confidence: float = 0.9) -> dict:
    return {"id": tid, "confidence": confidence}


# --- the behaviour voter on its own ---------------------------------------

def test_behaviour_reads_techniques_not_words():
    scores = cv.behaviour_scores([_technique("T1566.002"), _technique("T1486")], kev={})
    assert scores["phishing"] > 0 and scores["ransomware"] > 0


def test_an_inferred_technique_counts_for_less():
    stated = cv.behaviour_scores([_technique("T1190", 0.9)], kev={})
    inferred = cv.behaviour_scores([_technique("T1190", 0.6)], kev={})
    assert inferred["web_exploitation"] < stated["web_exploitation"]


def test_a_known_exploited_cve_suggests_exploitation_when_nothing_else_does():
    scores = cv.behaviour_scores([], kev={"known_exploited_count": 1})
    assert scores == {"web_exploitation": cv.KEV_EVIDENCE[1]}


def test_a_known_exploited_cve_does_not_override_phishing():
    """A phishing document abusing a Windows flaw is still phishing."""
    scores = cv.behaviour_scores([_technique("T1566")], kev={"known_exploited_count": 1})
    assert "web_exploitation" not in scores


def test_valid_accounts_is_not_entry_evidence():
    """Attackers use valid accounts after every kind of entry."""
    assert cv.behaviour_scores([_technique("T1078")], kev={}) == {}


# --- the vote ---------------------------------------------------------------

def test_agreement_is_high_confidence():
    dna = {"attack_type": "ransomware", "initial_vector": "phishing"}
    both = {"attack_type": "ransomware", "initial_vector": "phishing"}
    record = cv.vote(dna, both, both)
    assert record["attack_type"]["confidence"] == "high"
    assert record["initial_vector"]["agreement"] == "agree"


def test_behaviour_fills_an_unknown_vector():
    dna = {"attack_type": "data_breach", "initial_vector": "unknown"}
    record = cv.vote(dna, {"attack_type": "data_breach", "initial_vector": "unknown"},
                     {"attack_type": "unknown", "initial_vector": "web_exploitation"})
    assert dna["initial_vector"] == "web_exploitation"
    assert record["initial_vector"]["decided_by"] == "behaviour"
    assert record["initial_vector"]["confidence"] == "medium"


def test_behaviour_never_overrides_a_known_answer():
    dna = {"attack_type": "ransomware", "initial_vector": "phishing"}
    record = cv.vote(dna, {"attack_type": "ransomware", "initial_vector": "phishing"},
                     {"attack_type": "ransomware", "initial_vector": "supply_chain"})
    assert dna["initial_vector"] == "phishing"
    assert record["initial_vector"]["confidence"] == "low"
    assert record["initial_vector"]["alternative"] == "supply_chain"


def test_entry_evidence_alone_does_not_name_the_attack_type():
    dna = {"attack_type": "unknown", "initial_vector": "unknown"}
    cv.vote(dna, {"attack_type": "unknown", "initial_vector": "unknown"},
            {"attack_type": "web_exploitation", "initial_vector": "web_exploitation"})
    assert dna["attack_type"] == "unknown"
    assert dna["initial_vector"] == "web_exploitation"


def test_entry_only_behaviour_is_silence_not_disagreement():
    """Invoice fraud that arrived by phishing is not in dispute."""
    dna = {"attack_type": "business_email_compromise", "initial_vector": "phishing"}
    record = cv.vote(dna, {"attack_type": "business_email_compromise",
                           "initial_vector": "phishing"},
                     {"attack_type": "phishing", "initial_vector": "phishing"})
    assert record["attack_type"]["agreement"] == "words only"


def test_nothing_is_guessed():
    dna = {"attack_type": "unknown", "initial_vector": "unknown"}
    unknown = {"attack_type": "unknown", "initial_vector": "unknown"}
    record = cv.vote(dna, unknown, unknown)
    assert dna["initial_vector"] == "unknown"
    assert record["initial_vector"]["confidence"] == "none"


# --- end to end ---------------------------------------------------------------

def test_an_exploited_cve_names_the_entry_without_the_words():
    """Citrix Bleed is in CISA KEV; the report never says 'exploited a vulnerability'."""
    dna = _dna("The threat actor abused CVE-2023-4966 on the NetScaler gateway to hijack "
               "authenticated sessions, then harvested credentials with Mimikatz.")
    assert dna["initial_vector"] == "web_exploitation"
    assert dna["classification"]["initial_vector"]["behaviour"] == "web_exploitation"


def test_every_dna_carries_its_classification_record():
    dna = _dna("Ransomware encrypted the file servers after a phishing email.")
    for field in ("attack_type", "initial_vector"):
        record = dna["classification"][field]
        assert record["value"] == dna[field]
        assert record["confidence"] in {"high", "medium", "low", "none"}


def test_vote_inputs_do_not_leak_into_the_dna():
    dna = _dna("Ransomware encrypted the file servers after a phishing email.")
    assert not any(key.startswith("_") for key in dna)
