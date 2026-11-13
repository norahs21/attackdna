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


def suggest(text: str, vote_floor: float = VOTE_FLOOR) -> List[dict]:
    """Techniques the report's sentences resemble, strongest first.

    Each suggestion carries the MITRE example it rests on. One technique is
    returned once, with its best-supported sentence.
    """
    if not enabled():
        return []
    index = _index()
    if index is None:
        return []

    strongest: Dict[str, dict] = {}
    for outcome in index.vote(split_sentences(text)):
        if (outcome is None or outcome["vote"] < vote_floor
                or outcome["similarity"] < SIMILARITY_FLOOR):
            continue
        technique_id, source_id, _name, sentence = outcome["example"]
        current = strongest.get(technique_id)
        if current is None or outcome["vote"] > current["vote"]:
            preview = sentence if len(sentence) <= 140 else sentence[:137].rstrip() + "..."
            strongest[technique_id] = {
                "technique_id": technique_id,
                "vote": outcome["vote"],
                "similarity": outcome["similarity"],
                "evidence": f"resembles MITRE example ({source_id}): \"{preview}\"",
            }
    return sorted(strongest.values(), key=lambda s: (-s["vote"], s["technique_id"]))


def stats() -> dict:
    examples = load_examples()
    return {
        "enabled": enabled() and bool(examples),
        "examples": len(examples),
        "techniques_covered": len({example[0] for example in examples}),
    }
