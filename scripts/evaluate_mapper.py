"""Benchmark technique mapping on sentences MITRE labelled.

The incident sets in `evaluate.py` are small, because labelling an incident
takes an analyst. Technique mapping can be tested at a different scale: ATT&CK
ships ~17,600 sentences, each written by MITRE to describe one actor or
malware family using one technique. That is an answer key nobody on this
project wrote.

The split is by *source*. Every sentence about one fifth of the groups and
malware families is held out together, so the mapper is scored on actors it
has seen nothing about — holding out random sentences instead would let it
recognise "the same malware, described again".

Three mappers are compared on the held-out sentences:

    rules      the alias table and technique names in mitre_mapper
    learned    the nearest-example vote in example_mapper, fitted on the
               other four fifths
    combined   what the pipeline actually uses

Each sentence has one label, so a second technique the sentence really does
describe counts as wrong here. Precision is therefore a lower bound.

    python scripts/process_examples.py     # once, after download_mitre.py
    python scripts/evaluate_mapper.py
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

# The learned mapper inside the pipeline is fitted on every example, including
# the ones held out here, so it is switched off and a clean index is built.
os.environ["ATTACKDNA_LEARNED_MAPPER"] = "0"

from app.services import example_mapper  # noqa: E402
from app.services.mitre_mapper import map_to_attack  # noqa: E402

HELD_OUT_FRACTION = 5      # one source in five
SEED = 7


def family(technique_id: str) -> str:
    return technique_id.split(".")[0]


def score(name: str, predictions: List[Set[str]], gold: List[str]) -> Dict[str, float]:
    answered = sum(1 for p in predictions if p)
    hits = sum(1 for p, g in zip(predictions, gold) if g in p)
    made = sum(len(p) for p in predictions)
    result = {
        "mapper": name,
        "recall": hits / len(gold),
        "precision": hits / made if made else 0.0,
        "coverage": answered / len(gold),
        "predictions": made,
    }
    p, r = result["precision"], result["recall"]
    result["f1"] = 2 * p * r / (p + r) if p + r else 0.0
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark technique mapping on MITRE examples")
    parser.add_argument("--json", dest="json_out", metavar="PATH")
    args = parser.parse_args()

    examples = example_mapper.load_examples()
    if not examples:
        raise SystemExit("No procedure examples. Run: python scripts/process_examples.py")

    sources = sorted({example[1] for example in examples})
    random.Random(SEED).shuffle(sources)
    held_out = set(sources[: len(sources) // HELD_OUT_FRACTION])
    train = [e for e in examples if e[1] not in held_out]
    test = [e for e in examples if e[1] in held_out]

    index = example_mapper.ExampleIndex(train)
    sentences = [example_mapper.mask_subject(sentence, name) for _t, _s, name, sentence in test]
    gold = [family(example[0]) for example in test]

    votes = index.vote(sentences)
    top1 = sum(1 for v, g in zip(votes, gold) if v and family(v["technique_id"]) == g)
    top3 = sum(1 for v, g in zip(votes, gold) if v and g in {family(t) for t in v["ranked"]})
    exact = sum(1 for v, e in zip(votes, test) if v and v["technique_id"] == e[0])

    def confident(vote) -> bool:
        return (vote is not None and vote["vote"] >= example_mapper.VOTE_FLOOR
                and vote["similarity"] >= example_mapper.SIMILARITY_FLOOR)

    learned = [{family(v["technique_id"])} if confident(v) else set() for v in votes]
    rules = [{family(t["id"]) for t in map_to_attack(sentence)["techniques"]}
             for sentence in sentences]
    # The pipeline lets a rule speak first and adds the learned suggestion
    # only where no rule found that technique family.
    combined = [r | l for r, l in zip(rules, learned)]

    results = [score("rules", rules, gold), score("learned", learned, gold),
               score("combined", combined, gold)]

    print("=" * 74)
    print("TECHNIQUE MAPPING ON MITRE-LABELLED SENTENCES — held out by source")
    print("=" * 74)
    print(f"  {len(examples):,} examples from {len(sources):,} groups, malware families and tools")
    print(f"  fitted on {len(train):,} sentences; tested on {len(test):,} sentences "
          f"about {len(held_out)} sources never seen in fitting")
    print(f"  {len({e[0] for e in examples})} techniques to choose from\n")
    print(f"  {'mapper':<10} {'recall':>8} {'precision':>10} {'F1':>7} {'answers':>9}")
    for r in results:
        print(f"  {r['mapper']:<10} {r['recall']:>8.1%} {r['precision']:>10.1%} "
              f"{r['f1']:>7.1%} {r['coverage']:>9.1%}")
    print(f"\n  learned mapper with no confidence floor: right technique first "
          f"{top1 / len(test):.1%}, in the top three {top3 / len(test):.1%} "
          f"(exact sub-technique first: {exact / len(test):.1%})")
    print(f"  confidence floor in use: vote >= {example_mapper.VOTE_FLOOR}, "
          f"similarity >= {example_mapper.SIMILARITY_FLOOR}\n")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump({"examples": len(examples), "sources": len(sources),
                       "train": len(train), "test": len(test),
                       "held_out_sources": len(held_out),
                       "top1": top1 / len(test), "top3": top3 / len(test),
                       "exact_top1": exact / len(test), "results": results}, handle, indent=2)
        print(f"Written to {args.json_out}\n")


if __name__ == "__main__":
    main()
