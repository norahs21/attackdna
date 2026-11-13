"""Embed MITRE's procedure examples with MiniLM, once, for the semantic mapper.

The semantic half of the hybrid technique mapper compares a report sentence
with MITRE's ~17,600 labelled example sentences by meaning rather than by
shared words. Embedding the examples takes several minutes on a laptop CPU, so
it is done here, once, and stored next to the examples:

    data/processed/procedure_embeddings.npz

The vectors are unit length and stored as int8 (value x 127), which keeps the
file small and changes cosine similarities by well under 0.01. The file records
how many examples it was built from, so a stale file is ignored rather than
misread.

Needs the vector extras (`pip install -r backend/requirements-vector.txt`):
ChromaDB ships the ONNX build of all-MiniLM-L6-v2, so no torch is required.

    python scripts/process_examples.py    # the examples themselves
    python scripts/embed_examples.py      # their embeddings
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services import example_mapper  # noqa: E402

BATCH = 256


def main() -> None:
    examples = example_mapper.load_examples()
    if not examples:
        raise SystemExit("No procedure examples. Run: python scripts/process_examples.py")
    embed = example_mapper.embedding_function()
    if embed is None:
        raise SystemExit("MiniLM is unavailable. Install: pip install -r backend/requirements-vector.txt")

    sentences = [example_mapper.mask_subject(sentence, name)
                 for _tid, _sid, name, sentence in examples]
    vectors = []
    started = time.time()
    for start in range(0, len(sentences), BATCH):
        vectors.extend(embed(sentences[start:start + BATCH]))
        done = min(start + BATCH, len(sentences))
        print(f"  {done:,} / {len(sentences):,}  ({time.time() - started:.0f}s)", flush=True)

    matrix = np.asarray(vectors, dtype=np.float32)
    matrix /= np.linalg.norm(matrix, axis=1, keepdims=True)
    quantised = np.round(matrix * 127).astype(np.int8)
    np.savez_compressed(example_mapper.EMBEDDINGS_PATH, vectors=quantised,
                        count=np.int64(len(examples)))
    size = example_mapper.EMBEDDINGS_PATH.stat().st_size / 1e6
    print(f"\nWrote {example_mapper.EMBEDDINGS_PATH.relative_to(PROJECT_ROOT)} "
          f"({len(examples):,} x {matrix.shape[1]}, {size:.1f} MB)")


if __name__ == "__main__":
    main()
