"""Embed MITRE's procedure examples with MiniLM, once, for the semantic mapper.

The semantic half of the hybrid technique mapper compares a report sentence
with MITRE's ~17,600 labelled example sentences by meaning rather than by
shared words. Embedding the examples takes several minutes on a laptop CPU, so
it is done here, once, and stored next to the examples:

    data/processed/procedure_embeddings.npz

The vectors are unit length and stored as int8 (value x 127), which keeps the
file small and changes cosine similarities by about 0.01 at most.

Needs the vector extras (`pip install -r backend/requirements-vector.txt`):
ChromaDB ships the ONNX build of all-MiniLM-L6-v2, so no torch is required.

    python scripts/process_examples.py    # the examples themselves
    python scripts/embed_examples.py      # their embeddings (only new ones)
    python scripts/embed_examples.py --full

Each vector is stored with a fingerprint of its example, so after `make data`
fetches a newer ATT&CK release only the examples that are new or changed are
embedded, which takes seconds.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services import example_mapper  # noqa: E402

BATCH = 256


def main() -> None:
    parser = argparse.ArgumentParser(description="Embed MITRE's procedure examples")
    parser.add_argument("--full", action="store_true",
                        help="Re-embed every example instead of only the new ones")
    args = parser.parse_args()

    examples = example_mapper.load_examples()
    if not examples:
        raise SystemExit("No procedure examples. Run: python scripts/process_examples.py")
    embed = example_mapper.embedding_function()
    if embed is None:
        raise SystemExit("MiniLM is unavailable. Install: pip install -r backend/requirements-vector.txt")

    keys, stored = (None, None) if args.full else example_mapper.read_embeddings_file()
    if keys is None:
        keys, stored = [], np.zeros((0, 384), dtype=np.float32)

    def batched(sentences):
        started, out = time.time(), []
        for start in range(0, len(sentences), BATCH):
            out.extend(embed(sentences[start:start + BATCH]))
            print(f"  {min(start + BATCH, len(sentences)):,} / {len(sentences):,}  "
                  f"({time.time() - started:.0f}s)", flush=True)
        return out

    matrix, missing = example_mapper.align_vectors(examples, keys, stored, embed=batched)
    if missing == 0:
        print(f"All {len(examples):,} examples already embedded; nothing to do.")
        if not args.full and "keys" in np.load(example_mapper.EMBEDDINGS_PATH).files:
            return
    quantised = np.round(matrix * 127).astype(np.int8)
    np.savez_compressed(example_mapper.EMBEDDINGS_PATH, vectors=quantised,
                        count=np.int64(len(examples)),
                        keys=np.asarray([example_mapper.example_key(e) for e in examples]))
    size = example_mapper.EMBEDDINGS_PATH.stat().st_size / 1e6
    print(f"\nWrote {example_mapper.EMBEDDINGS_PATH.relative_to(PROJECT_ROOT)} "
          f"({len(examples):,} examples, {missing:,} newly embedded, {size:.1f} MB)")


if __name__ == "__main__":
    main()
