"""Train the technique classifier on MITRE's labelled examples, once.

A logistic-regression classifier over the MiniLM vectors of MITRE's ~17,600
procedure examples, predicting the ATT&CK technique (at the parent level,
T1059 rather than T1059.001) a sentence describes. It replaced voting by the
ten nearest examples as the main learned signal because, on a development
split carved from the training sources, it ranked the right technique first
far more often (74% against 66%).

The result is small (about 1 MB) and committed:

    data/processed/technique_classifier.npz

    python scripts/train_technique_classifier.py

Needs the example embeddings (scripts/embed_examples.py). Takes about a minute.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services import example_mapper  # noqa: E402


def main() -> None:
    examples = example_mapper.load_examples()
    vectors = example_mapper.load_embeddings()
    if not examples or vectors is None:
        raise SystemExit("Needs the examples and their embeddings: make data && make embeddings")
    started = time.time()
    head = example_mapper.TechniqueClassifier.fit(examples, vectors)
    head.save(example_mapper.CLASSIFIER_PATH, examples)
    size = example_mapper.CLASSIFIER_PATH.stat().st_size / 1e6
    print(f"Trained on {len(examples):,} examples, {len(head.classes)} techniques, "
          f"in {time.time() - started:.0f}s -> "
          f"{example_mapper.CLASSIFIER_PATH.relative_to(PROJECT_ROOT)} ({size:.1f} MB)")


if __name__ == "__main__":
    main()
