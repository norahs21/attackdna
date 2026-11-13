"""How well ATTACKDNA finds the ATT&CK technique a sentence describes.

The test: MITRE publishes ~17,600 sentences, each written by its analysts to
describe one group or malware family using one technique. Every sentence about
one fifth of the groups and malware families is held out. The system is
trained on the other four fifths and scored on the held-out ones, so it is
judged on attackers it has never read a word about.

Every setting of the system (how the classifier and the nearest examples are
combined, and the thresholds) was chosen on development data: a split carved
from the training fifths, and team-labelled development reports.

    make eval-mapper                 # the result
    python scripts/evaluate_mapper.py --compare    # also earlier versions

Each sentence has one correct label, so when a sentence really does describe
a second technique and the system names it, that counts as wrong here: the
precision shown is a lower bound.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Dict, List, Set

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

# The pipeline's learned parts are trained on every example, including the
# held-out ones, so they are switched off here and rebuilt from the training
# fifths only. The keyword rules are untouched.
os.environ["ATTACKDNA_LEARNED_MAPPER"] = "0"
os.environ["ATTACKDNA_SEMANTIC_MAPPER"] = "0"
os.environ["ATTACKDNA_CLASSIFIER"] = "0"

from app.services import example_mapper  # noqa: E402
from app.services.mitre_mapper import map_to_attack  # noqa: E402

HELD_OUT_FRACTION = 5      # one source in five
SEED = 7
RESULTS_PATH = PROJECT_ROOT / "data" / "evaluation" / "mapper_results.json"

family = example_mapper.family


def score(predictions: List[Set[str]], gold: List[str]) -> Dict[str, float]:
    hits = sum(1 for p, g in zip(predictions, gold) if g in p)
    made = sum(len(p) for p in predictions)
    recall = hits / len(gold)
    precision = hits / made if made else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"recall": recall, "precision": precision, "f1": f1, "found": hits,
            "sentences": len(gold), "suggested": made}


def main() -> None:
    parser = argparse.ArgumentParser(description="Technique mapping on MITRE-labelled sentences")
    parser.add_argument("--compare", action="store_true",
                        help="Also show the earlier versions of the mapper")
    args = parser.parse_args()

    examples = example_mapper.load_examples()
    if not examples:
        raise SystemExit("No procedure examples. Run: make data")
    vectors = example_mapper.load_embeddings()
    if vectors is None:
        raise SystemExit("No example embeddings (or MiniLM unavailable). "
                         "Run: pip install -r backend/requirements-vector.txt && make embeddings")

    sources = sorted({example[1] for example in examples})
    random.Random(SEED).shuffle(sources)
    held_out = set(sources[: len(sources) // HELD_OUT_FRACTION])
    train_rows = [i for i, e in enumerate(examples) if e[1] not in held_out]
    test_rows = [i for i, e in enumerate(examples) if e[1] in held_out]
    train = [examples[i] for i in train_rows]
    test = [examples[i] for i in test_rows]
    sentences = [example_mapper.mask_subject(e[3], e[2]) for e in test]
    gold = [family(e[0]) for e in test]

    print("Training on MITRE's examples about the other sources…", flush=True)
    tfidf = example_mapper.ExampleIndex(train).vote(sentences)
    meaning = example_mapper.SemanticIndex(train, vectors[train_rows], embed=None).vote(
        sentences, vectors=vectors[test_rows])
    head = example_mapper.TechniqueClassifier.fit(train, vectors[train_rows])
    probabilities = head.probabilities(vectors[test_rows])

    rules = [map_to_attack(sentence)["techniques"] for sentence in sentences]
    final = []
    for row, t, m, found in zip(probabilities, tfidf, meaning, rules):
        picks = example_mapper.decide(row, head.classes, t, m)
        final.append({family(r["id"]) for r in found} | {family(p["technique_id"]) for p in picks})
    result = score(final, gold)

    print()
    print("=" * 66)
    print("ATT&CK TECHNIQUE MAPPING")
    print("=" * 66)
    print(f"Test: {len(test):,} sentences from MITRE about {len(held_out)} attackers and")
    print("malware families the system was never trained on.")
    print()
    print(f"  Recall     {result['recall']:6.1%}   the right technique was found "
          f"({result['found']:,} of {len(test):,})")
    print(f"  Precision  {result['precision']:6.1%}   of the techniques it suggested, "
          "this share was right")
    print(f"  F1         {result['f1']:6.1%}   the balance of the two")
    print()

    output = {"test_sentences": len(test), "held_out_sources": len(held_out),
              "final": result}
    if args.compare:
        rule_only = [{family(r["id"]) for r in found} for found in rules]
        tfidf_only = [{family(v["technique_id"])} if v and v["vote"] >= example_mapper.VOTE_FLOOR
                      and v["similarity"] >= example_mapper.SIMILARITY_FLOOR else set()
                      for v in tfidf]
        fused = [example_mapper.fuse(t, m) for t, m in zip(tfidf, meaning)]
        versions = {
            "v1  keyword rules + wording": [r | t for r, t in zip(rule_only, tfidf_only)],
            "v2  + meaning (MiniLM votes)": [r | ({family(f["technique_id"])} if f else set())
                                             for r, f in zip(rule_only, fused)],
            "v3  trained classifier (current)": final,
        }
        print(f"  {'version':<36} {'recall':>7} {'precision':>10} {'F1':>7}")
        for name, predictions in versions.items():
            s = score(predictions, gold)
            output.setdefault("versions", {})[name] = s
            print(f"  {name:<36} {s['recall']:>7.1%} {s['precision']:>10.1%} {s['f1']:>7.1%}")
        print()

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
