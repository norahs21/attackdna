"""TF-IDF memory tests — the tier that runs when ChromaDB is not installed.

This backend is not a stub: on a machine where the vector extras could not be
installed it is the whole memory, so its scoring has to separate a relevant
question from an unrelated one on its own. The two properties below are what
make that possible, and both were absent in the first implementation — which
scored "have we seen ransomware?" at 0.03 against a ransomware incident while
scoring "satellite uplink attack" higher.
"""
import pytest

from app.services.vector_memory import QUESTION_STOPWORDS, TfidfMemory


@pytest.fixture
def memory(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.vector_memory.CHROMA_DIR", tmp_path)
    store = TfidfMemory()
    store.reset()
    for incident_id, text in [
        ("inc_ransom", "Attack type: ransomware. Sector: finance. Impact: data encrypted."),
        ("inc_ddos", "Attack type: denial of service. Sector: telecom. Impact: outage."),
        ("inc_phish", "Attack type: phishing. Sector: retail. Impact: credentials stolen."),
        ("inc_supply", "Attack type: supply chain. Sector: technology. Impact: backdoor."),
        ("inc_insider", "Attack type: insider theft. Sector: healthcare. Impact: records copied."),
    ]:
        store.add(incident_id, text, {"title": incident_id})
    return store


def _score(memory, question, incident_id):
    return next(r["similarity"] for r in memory.query(question, top_k=10)
                if r["incident_id"] == incident_id)


def test_question_scaffolding_does_not_drown_the_real_term(memory):
    """"Have we ever seen X?" must score like "X", not like noise.

    IDF rewards rarity, and no incident record contains "have we ever seen" —
    so left in, the scaffolding is weighted higher than the one word that
    matters and takes nearly all of the query vector's length with it.
    """
    bare = _score(memory, "ransomware", "inc_ransom")
    padded = _score(memory, "Have we ever seen ransomware before?", "inc_ransom")

    assert padded == pytest.approx(bare, rel=0.05)
    assert "have" in QUESTION_STOPWORDS and "seen" in QUESTION_STOPWORDS


def test_a_question_the_corpus_cannot_answer_scores_below_one_it_can(memory):
    """The property the offline relevance floor depends on.

    Both questions contain the word "attack", which every record contains. Only
    one of them names something the corpus holds, and that has to be what
    separates them.
    """
    relevant = _score(memory, "ransomware attack", "inc_ransom")
    off_topic = max(r["similarity"]
                    for r in memory.query("satellite uplink attack", top_k=10))

    assert off_topic < relevant


def test_unknown_terms_lower_the_score_rather_than_being_ignored(memory):
    """Dropping them outright would make any question with one matching word
    look like a direct hit."""
    focused = _score(memory, "ransomware", "inc_ransom")
    diluted = _score(memory, "ransomware quantum satellite cryogenic", "inc_ransom")

    assert diluted < focused


def test_a_question_with_no_known_terms_retrieves_nothing(memory):
    assert memory.query("quantum cryogenic satellite", top_k=5) == []


def test_the_index_follows_the_corpus(memory):
    """IDF shifts with every document, so a stale index would score wrongly."""
    assert memory.count() == 5
    before = _score(memory, "ransomware", "inc_ransom")

    memory.add("inc_ransom2", "Attack type: ransomware. Sector: energy.", {})
    assert memory.count() == 6
    after = _score(memory, "ransomware", "inc_ransom")
    assert after < before, "a second ransomware incident makes the term less distinctive"

    memory.delete("inc_ransom2")
    assert memory.count() == 5
    assert _score(memory, "ransomware", "inc_ransom") == pytest.approx(before)


def test_an_incident_is_not_returned_as_its_own_match(memory):
    ids = [r["incident_id"] for r in memory.query("ransomware", top_k=5,
                                                  exclude_id="inc_ransom")]
    assert "inc_ransom" not in ids


def test_memory_survives_a_corrupt_index_file(tmp_path, monkeypatch):
    """A half-written JSON file must not take the demo down with it."""
    monkeypatch.setattr("app.services.vector_memory.CHROMA_DIR", tmp_path)
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "tfidf_memory.json").write_text("{not json")

    store = TfidfMemory()
    assert store.count() == 0
