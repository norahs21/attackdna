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
class TfidfMemory:
    """A small in-process TF-IDF index persisted as JSON.

    Adequate for hackathon-scale corpora (hundreds of incidents) and it needs
    no model download, so `python -m scripts.seed_memory` always works.
    """

    backend_name = "tfidf"

    def __init__(self) -> None:
        self.path = CHROMA_DIR / "tfidf_memory.json"
        self.docs: Dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    self.docs = json.load(handle)
            except (json.JSONDecodeError, OSError):
                logger.warning("TF-IDF memory unreadable; starting empty")
                self.docs = {}

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(self.docs, handle, ensure_ascii=False)

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r"[a-z0-9][a-z0-9.\-]*", (text or "").lower())

    def _vector(self, text: str) -> Dict[str, float]:
        tokens = self._tokenize(text)
        if not tokens:
            return {}
        counts: Dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1

        total_docs = max(1, len(self.docs))
        vector: Dict[str, float] = {}
        for token, count in counts.items():
            doc_freq = sum(1 for d in self.docs.values() if token in d["tokens"])
            idf = math.log((total_docs + 1) / (doc_freq + 1)) + 1.0
            vector[token] = (count / len(tokens)) * idf

        norm = math.sqrt(sum(v * v for v in vector.values())) or 1.0
        return {token: value / norm for token, value in vector.items()}

    def add(self, incident_id: str, text: str, metadata: dict) -> None:
        self.docs[incident_id] = {
            "text": text,
            "tokens": list(set(self._tokenize(text))),
            "metadata": metadata,
        }
        self._persist()

    def delete(self, incident_id: str) -> None:
        if self.docs.pop(incident_id, None) is not None:
            self._persist()

    def query(self, text: str, top_k: int, exclude_id: Optional[str] = None) -> List[dict]:
        query_vector = self._vector(text)
        if not query_vector:
            return []

        results = []
        for incident_id, doc in self.docs.items():
            if incident_id == exclude_id:
                continue
            doc_vector = self._vector(doc["text"])
            score = sum(query_vector.get(t, 0.0) * doc_vector.get(t, 0.0) for t in query_vector)
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


def memory_stats() -> dict:
    memory = get_memory()
    return {"backend": memory.backend_name, "incidents_in_memory": memory.count()}


def reset_memory() -> None:
    """Wipe the store. Used by the seeding script and the test suite."""
    get_memory().reset()
