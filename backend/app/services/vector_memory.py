"""Vector Memory — the institutional memory of ATTACKDNA.

Every incident's Attack DNA is embedded and stored so that a new incident can
be answered with the question the SOC actually cares about:
*"have we seen this before, and what worked last time?"*

Only DNA-derived text is ever embedded (see `dna_extractor.embedding_text`),
so the vector store is structurally incapable of holding victim identifiers.

Embedding backends, in order of preference:
  1. sentence-transformers (`all-MiniLM-L6-v2`) — proper semantic embeddings.
  2. ChromaDB's bundled ONNX MiniLM — the same model, no torch dependency.
  3. TF-IDF over the stored corpus — no downloads, always available.

The third tier is what makes this demo-safe: the memory still works on a
laptop with no internet, it just matches on wording rather than meaning.
"""
from __future__ import annotations

import json
import logging
import math
import re
import threading
from typing import Dict, List, Optional

from app.config import CHROMA_DIR, COLLECTION_NAME, EMBEDDING_MODEL, SIMILARITY_THRESHOLD

logger = logging.getLogger(__name__)

_lock = threading.Lock()


# ==========================================================================
# Tier 3: dependency-free TF-IDF store (also the fallback for the others)
# ==========================================================================
# Question scaffolding carries no retrieval signal: every question contains
# some of it and no incident record contains any of it. Left in, these words
# are not merely useless — they are the *most* heavily weighted terms in the
# query, because a word absent from the corpus gets the highest IDF of all.
QUESTION_STOPWORDS = frozenset("""
a about after again against all also am an and any are as at be because been
before being below between both but by can cannot could did do does doing
done down during each few for from further had has have having he her here
hers him his how i if in into is it its just me more most my no nor not of
off on once only or other our ours out over own same she should so some such
than that the their theirs them then there these they this those through to
too under until up us very was we were what when where which while who whom
why will with would you your yours ever seen get got give take tell show
""".split())


class TfidfMemory:
    """A small in-process TF-IDF index persisted as JSON.

    Adequate for hackathon-scale corpora (hundreds of incidents) and it needs
    no model download, so `python -m scripts.seed_memory` always works.

    Two things separate this from a naive TF-IDF and both are load-bearing:

    * **Question scaffolding is stopped.** See QUESTION_STOPWORDS. Without
      this, "Have we seen ransomware?" scored 0.03 against a document holding
      the word "ransomware" — the scaffolding took nearly all the query's
      weight, because IDF rewards rarity and no incident record says "have we
      seen". The one real term was left with almost none of it.

    * **A content word the corpus has never seen still counts, against the
      match.** It cannot contribute to any score, but dropping it would make
      "satellite uplink attack" score as well as "ransomware" on the strength
      of the word "attack" alone. Keeping it in the query's norm is what makes
      an absolute relevance floor meaningful: the score then reflects how much
      of what was asked the corpus actually covers, not just whether some word
      happened to overlap.

    Document vectors are built once per corpus state rather than per query,
    which also turns querying from O(docs x terms) rebuilds into a lookup.
    """

    backend_name = "tfidf"

    def __init__(self) -> None:
        self.path = CHROMA_DIR / "tfidf_memory.json"
        self.docs: Dict[str, dict] = {}
        self._index: Optional[Dict[str, Dict[str, float]]] = None
        self._idf: Dict[str, float] = {}
        self._unseen_idf: float = 1.0
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    self.docs = json.load(handle)
            except (json.JSONDecodeError, OSError):
                logger.warning("TF-IDF memory unreadable; starting empty")
                self.docs = {}
        self._index = None

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(self.docs, handle, ensure_ascii=False)

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Split into terms, keeping internal dots and dashes.

        Those have to survive inside a term — CVE-2024-21412, T1059.001 and
        evil.example.com are single terms, not three. A *trailing* one is
        sentence punctuation, and stripping it is what makes a question about
        "ransomware" match a record that ends a sentence with "ransomware."
        """
        tokens = re.findall(r"[a-z0-9][a-z0-9.\-]*", (text or "").lower())
        stripped = (token.rstrip(".-") for token in tokens)
        return [token for token in stripped
                if token and token not in QUESTION_STOPWORDS]

    # ---- Index -----------------------------------------------------------
    def _build_index(self) -> None:
        """Compute IDF over the corpus, then every document's unit vector."""
        total_docs = max(1, len(self.docs))
        doc_freq: Dict[str, int] = {}
        for doc in self.docs.values():
            for token in set(doc["tokens"]):
                doc_freq[token] = doc_freq.get(token, 0) + 1

        self._idf = {
            token: math.log((total_docs + 1) / (frequency + 1)) + 1.0
            for token, frequency in doc_freq.items()
        }
        # What an unseen term would score: the rarest possible, doc_freq zero.
        self._unseen_idf = math.log(total_docs + 1) + 1.0
        self._index = {
            incident_id: self._document_vector(self._tokenize(doc["text"]))
            for incident_id, doc in self.docs.items()
        }

    def _document_vector(self, tokens: List[str]) -> Dict[str, float]:
        """TF-IDF for a stored document, normalised to unit length."""
        if not tokens:
            return {}
        counts: Dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1

        vector = {token: (count / len(tokens)) * self._idf.get(token, self._unseen_idf)
                  for token, count in counts.items()}
        norm = math.sqrt(sum(value * value for value in vector.values())) or 1.0
        return {token: value / norm for token, value in vector.items()}

    def _query_vector(self, tokens: List[str]) -> Dict[str, float]:
        """TF-IDF for a question, keeping unknown terms in the norm only.

        An unknown term matches nothing, so it is left out of the returned
        vector — but its weight still divides into the terms that remain. That
        is deliberate: a question the corpus mostly cannot speak to should
        score low even when one of its words happens to appear everywhere.
        """
        if not tokens:
            return {}
        counts: Dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1

        weights = {token: (count / len(tokens)) * self._idf.get(token, self._unseen_idf)
                   for token, count in counts.items()}
        norm = math.sqrt(sum(value * value for value in weights.values())) or 1.0
        return {token: value / norm
                for token, value in weights.items() if token in self._idf}

    def _vectors(self) -> Dict[str, Dict[str, float]]:
        if self._index is None:
            self._build_index()
        return self._index or {}

    # ---- Store -----------------------------------------------------------
    def add(self, incident_id: str, text: str, metadata: dict) -> None:
        self.docs[incident_id] = {
            "text": text,
            "tokens": list(set(self._tokenize(text))),
            "metadata": metadata,
        }
        self._index = None  # IDF shifts with every document, so rebuild lazily.
        self._persist()

    def delete(self, incident_id: str) -> None:
        if self.docs.pop(incident_id, None) is not None:
            self._index = None
            self._persist()

    def query(self, text: str, top_k: int, exclude_id: Optional[str] = None) -> List[dict]:
        vectors = self._vectors()
        query_vector = self._query_vector(self._tokenize(text))
        if not query_vector:
            return []

        results = []
        for incident_id, doc in self.docs.items():
            if incident_id == exclude_id:
                continue
            doc_vector = vectors.get(incident_id, {})
            score = sum(weight * doc_vector.get(token, 0.0)
                        for token, weight in query_vector.items())
            results.append({
                "incident_id": incident_id,
                "similarity": round(max(0.0, min(1.0, score)), 4),
                "metadata": doc["metadata"],
                "document": doc["text"],
            })
        results.sort(key=lambda r: -r["similarity"])
        return results[:top_k]

    def count(self) -> int:
        return len(self.docs)

    def reset(self) -> None:
        self.docs = {}
        self._index = None
        self._persist()


# ==========================================================================
# Tiers 1 & 2: ChromaDB
# ==========================================================================
class ChromaMemory:
    """Persistent ChromaDB collection over Attack DNA embeddings."""

    def __init__(self) -> None:
        import chromadb
        from chromadb.config import Settings

        CHROMA_DIR.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(
            path=str(CHROMA_DIR),
            settings=Settings(anonymized_telemetry=False, allow_reset=True),
        )
        embedding_function, self.backend_name = self._build_embedding_function()
        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_function,
            metadata={"hnsw:space": "cosine"},
        )

    @staticmethod
    def _build_embedding_function():
        """Prefer sentence-transformers; fall back to Chroma's bundled MiniLM."""
        try:
            from chromadb.utils import embedding_functions

            return (
                embedding_functions.SentenceTransformerEmbeddingFunction(
                    model_name=EMBEDDING_MODEL
                ),
                f"sentence-transformers:{EMBEDDING_MODEL}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.info("sentence-transformers unavailable (%s); using Chroma default MiniLM", exc)
            from chromadb.utils import embedding_functions

            return embedding_functions.DefaultEmbeddingFunction(), "chroma-default:MiniLM-L6-v2"

    def add(self, incident_id: str, text: str, metadata: dict) -> None:
        self.collection.upsert(
            ids=[incident_id],
            documents=[text],
            metadatas=[_flatten_metadata(metadata)],
        )

    def delete(self, incident_id: str) -> None:
        self.collection.delete(ids=[incident_id])

    def query(self, text: str, top_k: int, exclude_id: Optional[str] = None) -> List[dict]:
        stored = self.collection.count()
        if stored == 0:
            return []
        # Over-fetch by one so excluding the incident itself still fills top_k.
        response = self.collection.query(
            query_texts=[text],
            n_results=min(stored, top_k + (1 if exclude_id else 0)),
        )

        results = []
        ids = response.get("ids", [[]])[0]
        distances = response.get("distances", [[]])[0]
        metadatas = response.get("metadatas", [[]])[0]
        documents = response.get("documents", [[]])[0]
        for index, incident_id in enumerate(ids):
            if incident_id == exclude_id:
                continue
            # Cosine distance in [0, 2]; convert to a similarity in [0, 1].
            distance = distances[index] if index < len(distances) else 1.0
            similarity = max(0.0, min(1.0, 1.0 - (distance / 2.0)))
            results.append({
                "incident_id": incident_id,
                "similarity": round(similarity, 4),
                "metadata": _unflatten_metadata(metadatas[index] if index < len(metadatas) else {}),
                "document": documents[index] if index < len(documents) else "",
            })
        return results[:top_k]

    def count(self) -> int:
        return self.collection.count()

    def reset(self) -> None:
        self.client.delete_collection(COLLECTION_NAME)
        embedding_function, _ = self._build_embedding_function()
        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_function,
            metadata={"hnsw:space": "cosine"},
        )


# --------------------------------------------------------------------------
# Chroma metadata must be scalar, so lists are stored as delimited strings.
# --------------------------------------------------------------------------
_LIST_PREFIX = "list::"
_LIST_SEP = "|"


def _flatten_metadata(metadata: dict) -> dict:
    flat = {}
    for key, value in metadata.items():
        if isinstance(value, (list, tuple)):
            flat[key] = _LIST_PREFIX + _LIST_SEP.join(str(v) for v in value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            flat[key] = "" if value is None else value
        else:
            flat[key] = json.dumps(value, ensure_ascii=False)
    return flat


def _unflatten_metadata(metadata: dict) -> dict:
    restored = {}
    for key, value in (metadata or {}).items():
        if isinstance(value, str) and value.startswith(_LIST_PREFIX):
            payload = value[len(_LIST_PREFIX):]
            restored[key] = payload.split(_LIST_SEP) if payload else []
        else:
            restored[key] = value
    return restored


# ==========================================================================
# Public API
# ==========================================================================
_memory = None


def get_memory():
    """The process-wide memory backend, built once on first use."""
    global _memory
    if _memory is not None:
        return _memory
    with _lock:
        if _memory is not None:
            return _memory
        try:
            _memory = ChromaMemory()
            logger.info("Vector memory backend: %s", _memory.backend_name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ChromaDB unavailable (%s); falling back to TF-IDF memory", exc)
            _memory = TfidfMemory()
    return _memory


def remember(incident_id: str, embedding_text: str, metadata: dict) -> None:
    """Store one incident's Attack DNA in memory."""
    get_memory().add(incident_id, embedding_text, metadata)


def forget(incident_id: str) -> None:
    get_memory().delete(incident_id)


def find_similar(embedding_text: str, top_k: int, exclude_id: Optional[str] = None,
                 threshold: Optional[float] = None) -> List[dict]:
    """Retrieve past incidents whose Attack DNA resembles this one."""
    cutoff = SIMILARITY_THRESHOLD if threshold is None else threshold
    matches = get_memory().query(embedding_text, top_k=top_k, exclude_id=exclude_id)
    return [m for m in matches if m["similarity"] >= cutoff]


# --------------------------------------------------------------------------
# Relevance floors are per backend because the scores are not comparable.
#
# Measured on the 24-incident demo corpus, top hit per question:
#
#   backend   relevant questions   off-topic questions   floor
#   MiniLM    0.64 - 0.86          0.53 - 0.70           0.73
#   TF-IDF    0.03 - 0.59          0.00 - 0.06           0.10
#
# MiniLM's range is compressed and high because any two security texts are
# semantically close; TF-IDF's is low and sparse because it needs literal word
# overlap. One number cannot serve both — a floor of 0.73 on TF-IDF rejects
# every question ever asked, which is exactly what it did before this existed.
#
# Both floors sit above the off-topic band rather than below the relevant one:
# the offline path has no judgement of its own, so it should stay silent when
# unsure rather than present a loose match as an answer.
RELEVANCE_FLOORS = {"tfidf": 0.10}
DEFAULT_RELEVANCE_FLOOR = 0.73


def relevance_floor() -> float:
    """The similarity below which a match should not be called an answer."""
    return RELEVANCE_FLOORS.get(get_memory().backend_name, DEFAULT_RELEVANCE_FLOOR)


def memory_stats() -> dict:
    memory = get_memory()
    return {"backend": memory.backend_name, "incidents_in_memory": memory.count()}


def reset_memory() -> None:
    """Wipe the store. Used by the seeding script and the test suite."""
    get_memory().reset()
