"""Technique mapping learned from MITRE's own examples.

The alias table in `mitre_mapper` is precise and narrow: it finds a technique
when a report uses a phrase somebody thought to write down. Measured on
reports it had never seen, it was right nine times in ten when it spoke, and
silent about most of what was there.

MITRE publishes the other half. For every technique, ATT&CK records how each
known group and malware family used it, as a sentence — about 17,600 of them.
This module answers "which technique is this sentence describing?" by finding
the sentences MITRE's analysts labelled that read most like it, and letting
them vote.

    report sentence   "the actor dumped credentials from LSASS with ProcDump"
    nearest examples  T1003.001  "... credential dumping using ProcDump"
                      T1003.001  "... dumps LSASS memory ..."
    suggestion        T1003.001, evidence: the MITRE example itself

Three properties are deliberate.

* **No model to download.** TF-IDF and cosine similarity from scikit-learn,
  fitted in under a second at first use, identical on every run.
* **It abstains.** A suggestion needs the neighbours to agree (VOTE_FLOOR).
  Below that it says nothing, and the rules stand alone.
* **Its evidence is public.** What is attached to a suggested technique is the
  MITRE sentence it resembled, never the report's own words — so nothing from
  the report's prose enters the Attack DNA through this path either.

`scripts/evaluate_mapper.py` measures it honestly: examples from one fifth of
the sources are held out entirely, so it is scored on actors and malware it
has never seen a sentence about.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import re
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from app.config import DATA_DIR
from app.services.knowledge_base import technique_index
from app.services.negation import negated_spans

logger = logging.getLogger(__name__)

EXAMPLES_PATH = DATA_DIR / "processed" / "procedure_examples.json.gz"
# MiniLM embeddings of the same examples, made by scripts/embed_examples.py.
EMBEDDINGS_PATH = DATA_DIR / "processed" / "procedure_embeddings.npz"
# A classifier trained on those embeddings (scripts/train_technique_classifier.py).
CLASSIFIER_PATH = DATA_DIR / "processed" / "technique_classifier.npz"

# How the trained classifier's probabilities and the nearest-example votes are
# combined, and what it takes to suggest a technique. Chosen on development
# data only: a split carved from the training sources for single sentences,
# and 76 team-labelled development reports for whole reports.
#   * 70% classifier, 30% nearest-example votes;
#   * in one sentence, a technique is suggested at a combined probability of
#     0.2, and a second one too when it also reaches 0.2;
#   * across a whole report, only suggestions at 0.7 or more count, and at most
#     the five strongest: a long report would otherwise collect a weak guess
#     from every sentence, including the ones not about the attack.
#   * a sentence whose closest MITRE example is less similar than 0.5 is not
#     about an attack at all ("the cafeteria is closed on Thursday": 0.25),
#     and gets no suggestion: a classifier always spreads its probability over
#     some technique, however unrelated the sentence.
CLASSIFIER_WEIGHT = 0.7
PICK_FLOOR = 0.2
MEANING_GATE = 0.5
REPORT_FLOOR = 0.7
MAX_LEARNED_PER_REPORT = 5

# How many labelled sentences vote on each report sentence.
NEIGHBOURS = 10
# The summed similarity the winning technique needs. Calibrated on held-out
# MITRE examples: at 2.0 the suggestion is right about 85% of the time and is
# made for about 44% of sentences; lower floors trade precision for coverage.
VOTE_FLOOR = 2.0
# The closest example must itself be a real resemblance, not just the best of
# a bad lot.
SIMILARITY_FLOOR = 0.35

_TOKEN_RE = re.compile(r"\[[A-Z_]+_REDACTED(?:_\d+)?\]")
_SENTENCE_RE = re.compile(r"(?<=[.!?;])\s+|\n+")

Example = Tuple[str, str, str, str]   # technique id, source id, source name, sentence


def enabled() -> bool:
    """On unless switched off, and only if the examples have been processed."""
    return os.getenv("ATTACKDNA_LEARNED_MAPPER", "1") != "0" and EXAMPLES_PATH.exists()


@lru_cache(maxsize=1)
def load_examples() -> List[Example]:
    """Every procedure example whose technique the knowledge base knows."""
    if not EXAMPLES_PATH.exists():
        return []
    try:
        with gzip.open(EXAMPLES_PATH, "rt", encoding="utf-8") as handle:
            rows = json.load(handle)["examples"]
    except (OSError, json.JSONDecodeError, KeyError):
        logger.warning("Procedure examples unreadable; learned mapping is off")
        return []
    known = technique_index()
    return [tuple(row) for row in rows if row[0] in known]


def mask_subject(sentence: str, name: str) -> str:
    """Replace the actor's own name, so behaviour is learned, not branding.

    "Mimikatz can dump LSASS" would otherwise teach the index that the word
    "Mimikatz" *is* the technique, and a held-out test would only be measuring
    whether it has seen the name before.
    """
    if not name or len(name) < 3:
        return sentence
    return re.sub(re.escape(name), "the actor", sentence, flags=re.I)


class ExampleIndex:
    """A fitted nearest-example index over a set of labelled sentences."""

    def __init__(self, examples: Sequence[Example]) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.examples = list(examples)
        self.techniques = [example[0] for example in self.examples]
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2), sublinear_tf=True, min_df=2,
            stop_words="english", lowercase=True,
        )
        self.matrix = self.vectorizer.fit_transform(
            mask_subject(sentence, name) for _tid, _sid, name, sentence in self.examples
        )

    def vote(self, sentences: Sequence[str]) -> List[Optional[dict]]:
        """For each sentence, the technique its neighbours agree on, if any."""
        import numpy as np

        if not sentences:
            return []
        similarities = (self.vectorizer.transform(sentences) @ self.matrix.T).toarray()
        results: List[Optional[dict]] = []
        for row in similarities:
            # A stable sort keeps ties in corpus order, so the same report
            # always gets the same answer.
            nearest = np.argsort(-row, kind="stable")[:NEIGHBOURS]
            votes: Dict[str, float] = {}
            best: Dict[str, int] = {}
            for index in nearest:
                technique_id = self.techniques[index]
                votes[technique_id] = votes.get(technique_id, 0.0) + float(row[index])
                best.setdefault(technique_id, int(index))
            if not votes:
                results.append(None)
                continue
            winner = max(votes, key=lambda tid: (votes[tid], tid))
            results.append({
                "technique_id": winner,
                "vote": round(votes[winner], 4),
                "similarity": round(float(row[best[winner]]), 4),
                "example": self.examples[best[winner]],
                "ranked": sorted(votes, key=lambda tid: (-votes[tid], tid))[:3],
                "votes": votes,
                "best": {tid: self.examples[i] for tid, i in best.items()},
            })
        return results


@lru_cache(maxsize=1)
def _index() -> Optional[ExampleIndex]:
    examples = load_examples()
    if not examples:
        return None
    try:
        return ExampleIndex(examples)
    except Exception as exc:  # noqa: BLE001 - scikit-learn missing or broken
        logger.warning("Learned mapping unavailable (%s); rules only", exc)
        return None


def split_sentences(text: str) -> List[str]:
    """Sentences of a sanitized report, with denied clauses and tokens removed.

    "No lateral movement occurred" must not vote for lateral movement, and a
    redaction token is not a word the examples have ever contained.
    """
    lowered = (text or "").lower()
    kept = list(text or "")
    for start, end in negated_spans(lowered):
        for position in range(start, min(end, len(kept))):
            kept[position] = " "
    cleaned = _TOKEN_RE.sub(" ", "".join(kept))
    sentences = [re.sub(r"\s+", " ", part).strip() for part in _SENTENCE_RE.split(cleaned)]
    return [sentence for sentence in sentences if len(sentence.split()) >= 4]


# The previous hybrid rule (TF-IDF + MiniLM votes, no classifier). Still used
# when the trained classifier is not available.
FUSED_FLOOR = 3.0


def fuse(tfidf: Optional[dict], semantic: Optional[dict],
         floor: float = FUSED_FLOOR) -> Optional[dict]:
    """One sentence's nearest-example verdict, or None when the evidence is too thin."""
    votes: Dict[str, float] = {}
    for outcome in (tfidf, semantic):
        if outcome:
            for technique_id, vote in outcome["votes"].items():
                votes[technique_id] = votes.get(technique_id, 0.0) + vote
    if not votes:
        return None
    winner = max(votes, key=lambda tid: (votes[tid], tid))
    if votes[winner] < floor:
        return None
    for outcome in (semantic, tfidf):
        if outcome and winner in outcome["best"]:
            example = outcome["best"][winner]
            break
    return {"technique_id": winner, "vote": round(votes[winner], 4), "example": example}


def family(technique_id: str) -> str:
    return technique_id.split(".")[0]


class TechniqueClassifier:
    """Logistic regression from a sentence's MiniLM vector to an ATT&CK technique."""

    def __init__(self, classes, coef, intercept) -> None:
        self.classes = list(classes)
        self.coef = coef
        self.intercept = intercept

    @classmethod
    def fit(cls, examples: Sequence[Example], vectors, regularisation: float = 30.0):
        import numpy as np
        from sklearn.linear_model import LogisticRegression

        labels = np.array([family(example[0]) for example in examples])
        model = LogisticRegression(C=regularisation, max_iter=300)
        model.fit(vectors, labels)
        return cls(model.classes_, model.coef_.astype(np.float32),
                   model.intercept_.astype(np.float32))

    def save(self, path, examples: Sequence[Example]) -> None:
        import numpy as np

        np.savez_compressed(path, classes=np.asarray(self.classes), coef=self.coef,
                            intercept=self.intercept, count=np.int64(len(examples)))

    @classmethod
    def load(cls, path):
        import numpy as np

        stored = np.load(path)
        return cls([str(c) for c in stored["classes"]], stored["coef"], stored["intercept"])

    def probabilities(self, vectors):
        import numpy as np

        scores = vectors @ self.coef.T + self.intercept
        scores -= scores.max(axis=1, keepdims=True)
        exp = np.exp(scores)
        return exp / exp.sum(axis=1, keepdims=True)


@lru_cache(maxsize=1)
def _classifier() -> Optional[TechniqueClassifier]:
    if os.getenv("ATTACKDNA_CLASSIFIER", "1") == "0" or not CLASSIFIER_PATH.exists():
        return None
    try:
        return TechniqueClassifier.load(CLASSIFIER_PATH)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Technique classifier unreadable (%s)", exc)
        return None


def decide(probabilities, classes: Sequence[str], tfidf: Optional[dict],
           semantic: Optional[dict]) -> List[dict]:
    """One sentence's suggestions.

    Shared by the pipeline and scripts/evaluate_mapper.py, so the benchmark
    measures exactly what a report goes through.
    """
    import numpy as np

    if semantic is not None and semantic["similarity"] < MEANING_GATE:
        return []
    index = {name: i for i, name in enumerate(classes)}
    votes = np.zeros(len(classes), dtype=np.float32)
    for outcome in (tfidf, semantic):
        if outcome:
            for technique_id, vote in outcome["votes"].items():
                position = index.get(family(technique_id))
                if position is not None:
                    votes[position] += vote
    if votes.sum() > 0:
        votes /= votes.sum()
    combined = CLASSIFIER_WEIGHT * probabilities + (1 - CLASSIFIER_WEIGHT) * votes
    order = np.argsort(-combined, kind="stable")

    picks = []
    for rank in (0, 1):
        position = order[rank]
        if combined[position] < PICK_FLOOR:
            break
        chosen = classes[position]
        # The classifier names the technique; the nearest examples say which
        # sub-technique, when one of them is that specific.
        specific: Dict[str, float] = {}
        example = None
        for outcome in (semantic, tfidf):
            if not outcome:
                continue
            for technique_id, vote in outcome["votes"].items():
                if family(technique_id) == chosen:
                    specific[technique_id] = specific.get(technique_id, 0.0) + vote
        technique_id = max(specific, key=lambda t: (specific[t], t)) if specific else chosen
        for outcome in (semantic, tfidf):
            if outcome and technique_id in outcome.get("best", {}):
                example = outcome["best"][technique_id]
                break
        picks.append({"technique_id": technique_id,
                      "probability": round(float(combined[position]), 4),
                      "example": example})
    return picks


def _evidence(example: Optional[Example], how: str) -> str:
    if example is None:
        return "classified from MITRE's labelled examples"
    _tid, source_id, _name, sentence = example
    preview = sentence if len(sentence) <= 140 else sentence[:137].rstrip() + "..."
    return f"{how} MITRE example ({source_id}): \"{preview}\""


def analyse(text: str, vote_floor: float = VOTE_FLOOR) -> dict:
    """Learned suggestions for a report, strongest first."""
    empty = {"suggestions": []}
    if not enabled():
        return empty
    index = _index()
    if index is None:
        return empty

    sentences = split_sentences(text)
    tfidf_votes = index.vote(sentences)
    semantic = _semantic_index()
    head = _classifier()
    strongest: Dict[str, dict] = {}

    def keep(technique_id, score, example, how, method):
        current = strongest.get(technique_id)
        if current is None or score > current["vote"]:
            strongest[technique_id] = {"technique_id": technique_id, "vote": score,
                                       "method": method, "evidence": _evidence(example, how)}

    meaning_votes, vectors = None, None
    if semantic is not None and sentences:
        try:
            vectors = semantic.encode(sentences)
            meaning_votes = semantic.vote(sentences, vectors=vectors)
        except Exception as exc:  # noqa: BLE001 - the model failing mid-run
            logger.warning("Semantic mapping failed (%s); TF-IDF only", exc)

    if meaning_votes is not None and head is not None:
        probabilities = head.probabilities(vectors)
        for row, tfidf, meaning in zip(probabilities, tfidf_votes, meaning_votes):
            for pick in decide(row, head.classes, tfidf, meaning):
                keep(pick["technique_id"], pick["probability"], pick["example"],
                     "resembles", "classifier")
        ranked = sorted(strongest.values(), key=lambda s: (-s["vote"], s["technique_id"]))
        if len(sentences) > 1:
            ranked = [s for s in ranked if s["vote"] >= REPORT_FLOOR][:MAX_LEARNED_PER_REPORT]
        return {"suggestions": ranked}

    if meaning_votes is not None:
        for tfidf, meaning in zip(tfidf_votes, meaning_votes):
            verdict = fuse(tfidf, meaning)
            if verdict:
                keep(verdict["technique_id"], verdict["vote"], verdict["example"],
                     "resembles (by meaning and wording)", "hybrid")
    else:
        for outcome in tfidf_votes:
            if (outcome and outcome["vote"] >= vote_floor
                    and outcome["similarity"] >= SIMILARITY_FLOOR):
                keep(outcome["technique_id"], outcome["vote"], outcome["example"],
                     "resembles", "tfidf")
    return {"suggestions": sorted(strongest.values(), key=lambda s: (-s["vote"], s["technique_id"]))}


def suggest(text: str, vote_floor: float = VOTE_FLOOR) -> List[dict]:
    """Techniques the report's sentences resemble, strongest first."""
    return analyse(text, vote_floor)["suggestions"]


# --------------------------------------------------------------------------
# The semantic half: the same examples, compared by meaning
# --------------------------------------------------------------------------
# TF-IDF only sees shared words, so "the operator pulled hashes out of LSASS"
# and "credential dumping from process memory" look unrelated to it. MiniLM
# embeddings place them close together. The semantic index votes exactly like
# the TF-IDF one, over the same labelled examples, and `suggest` combines the
# two (HYBRID below). Everything stays local: the model is the ONNX build that
# ChromaDB ships, and the example vectors are precomputed.


def semantic_enabled() -> bool:
    return (os.getenv("ATTACKDNA_SEMANTIC_MAPPER", "1") != "0"
            and EMBEDDINGS_PATH.exists() and enabled())


@lru_cache(maxsize=1)
def embedding_function():
    """MiniLM as a callable over a list of sentences, or None if unavailable.

    Fails soft: no ChromaDB, no cached model and no network all mean the
    semantic half is off and the TF-IDF half answers alone.
    """
    try:
        from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2

        function = ONNXMiniLM_L6_V2()
        function(["warm-up"])
        return function
    except Exception as exc:  # noqa: BLE001 - import, download or runtime failure
        logger.info("Semantic mapping unavailable (%s); TF-IDF only", exc)
        return None


# A few hundred new examples are embedded on first use; more than this means
# the stored file belongs to a different ATT&CK release and should be rebuilt.
MAX_EMBED_ON_THE_FLY = 1000


def example_key(example: Example) -> str:
    """A stable fingerprint of one labelled example, used to match stored vectors."""
    import hashlib

    technique_id, source_id, _name, sentence = example
    return hashlib.sha1(f"{technique_id}\x00{source_id}\x00{sentence}".encode("utf-8")).hexdigest()[:16]


def align_vectors(examples: Sequence[Example], stored_keys, stored_vectors, embed=None):
    """Vectors for `examples`, reusing stored ones by fingerprint.

    ATT&CK is re-downloaded by `make data`, and each release adds, edits or
    drops a handful of examples. Matching by fingerprint keeps every vector
    that still applies; only the examples with none are embedded, so a newer
    release costs seconds, not the ten minutes of a full rebuild. Returns
    (vectors, missing_count); vectors is None when examples are missing and
    cannot be embedded here.
    """
    import numpy as np

    index = {str(key): row for row, key in enumerate(stored_keys)}
    rows = [index.get(example_key(example)) for example in examples]
    missing = [i for i, row in enumerate(rows) if row is None]
    out = np.zeros((len(examples), stored_vectors.shape[1]), dtype=np.float32)
    for i, row in enumerate(rows):
        if row is not None:
            out[i] = stored_vectors[row]
    if missing:
        if embed is None:
            return None, len(missing)
        sentences = [mask_subject(examples[i][3], examples[i][2]) for i in missing]
        fresh = []
        for start in range(0, len(sentences), 256):
            fresh.extend(embed(sentences[start:start + 256]))
        out[missing] = np.asarray(fresh, dtype=np.float32)
    return out / np.linalg.norm(out, axis=1, keepdims=True), len(missing)


def read_embeddings_file():
    """(keys, vectors) from the stored file, or (None, None)."""
    import numpy as np

    if not EMBEDDINGS_PATH.exists():
        return None, None
    stored = np.load(EMBEDDINGS_PATH)
    vectors = stored["vectors"].astype(np.float32) / 127.0
    if "keys" in stored.files:
        return stored["keys"], vectors
    # A file from before fingerprints: valid only for exactly the examples it
    # was made from, which the count alone cannot prove beyond matching sizes.
    if int(stored["count"]) == len(load_examples()):
        return [example_key(e) for e in load_examples()], vectors
    return None, None


@lru_cache(maxsize=1)
def load_embeddings():
    """The example vectors as unit-length float32, aligned with load_examples()."""
    try:
        keys, vectors = read_embeddings_file()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Example embeddings unreadable (%s)", exc)
        return None
    if keys is None:
        if EMBEDDINGS_PATH.exists():
            logger.warning("Example embeddings do not match the examples; "
                           "run: make embeddings")
        return None
    examples = load_examples()
    aligned, missing = align_vectors(examples, keys, vectors)
    if aligned is not None:
        return aligned
    if missing > MAX_EMBED_ON_THE_FLY:
        logger.warning("%d examples have no embedding; run: make embeddings", missing)
        return None
    embed = embedding_function()
    if embed is None:
        logger.warning("%d new examples need embedding but MiniLM is unavailable; "
                       "install backend/requirements-vector.txt", missing)
        return None
    logger.info("Embedding %d examples new in this ATT&CK release", missing)
    aligned, _ = align_vectors(examples, keys, vectors, embed=embed)
    return aligned


class SemanticIndex:
    """Nearest-example vote over MiniLM vectors; same shape as ExampleIndex."""

    def __init__(self, examples: Sequence[Example], vectors, embed) -> None:
        self.examples = list(examples)
        self.techniques = [example[0] for example in self.examples]
        self.vectors = vectors
        self.embed = embed

    def encode(self, sentences: Sequence[str]):
        import numpy as np

        vectors = np.asarray(self.embed(list(sentences)), dtype=np.float32)
        return vectors / np.linalg.norm(vectors, axis=1, keepdims=True)

    def vote(self, sentences: Sequence[str], vectors=None) -> List[Optional[dict]]:
        import numpy as np

        if not sentences:
            return []
        if vectors is None:
            vectors = self.encode(sentences)
        similarities = vectors @ self.vectors.T
        results: List[Optional[dict]] = []
        for row in similarities:
            nearest = np.argsort(-row, kind="stable")[:NEIGHBOURS]
            votes: Dict[str, float] = {}
            best: Dict[str, int] = {}
            for index in nearest:
                technique_id = self.techniques[index]
                votes[technique_id] = votes.get(technique_id, 0.0) + float(row[index])
                best.setdefault(technique_id, int(index))
            winner = max(votes, key=lambda tid: (votes[tid], tid))
            results.append({
                "technique_id": winner,
                "vote": round(votes[winner], 4),
                "similarity": round(float(row[best[winner]]), 4),
                "example": self.examples[best[winner]],
                "ranked": sorted(votes, key=lambda tid: (-votes[tid], tid))[:3],
                "votes": votes,
                "best": {tid: self.examples[i] for tid, i in best.items()},
            })
        return results


@lru_cache(maxsize=1)
def _semantic_index() -> Optional[SemanticIndex]:
    if not semantic_enabled():
        return None
    vectors = load_embeddings()
    embed = embedding_function() if vectors is not None else None
    if vectors is None or embed is None:
        return None
    return SemanticIndex(load_examples(), vectors, embed)


def stats() -> dict:
    examples = load_examples()
    return {
        "enabled": enabled() and bool(examples),
        "semantic": _semantic_index() is not None,
        "classifier": _classifier() is not None,
        "examples": len(examples),
        "techniques_covered": len({example[0] for example in examples}),
    }
