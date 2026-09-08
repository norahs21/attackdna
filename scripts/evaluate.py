"""Measure ATTACKDNA's accuracy against a labelled evaluation set.

Covers the plan's three measurement tasks:
  * Attack DNA accuracy    — classification and ATT&CK mapping quality
  * Retrieval accuracy     — does memory surface the right past incident first?
  * Privacy assurance      — does anything identifying survive sanitization?

Run after seeding:

    python scripts/seed_memory.py --reset
    python scripts/evaluate.py

The evaluation cases in data/seed/evaluation_set.json are written independently
of the seed corpus, so retrieval is scored on incidents the system has not been
shown in that wording.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.config import DATA_DIR  # noqa: E402
from app.db.database import SessionLocal, init_db  # noqa: E402
from app.pipelines.analyze import analyze  # noqa: E402
from app.services.sanitizer import sanitize, verify_clean  # noqa: E402

EVAL_PATH = DATA_DIR / "seed" / "evaluation_set.json"


def load_cases() -> List[dict]:
    if not EVAL_PATH.exists():
        raise SystemExit(f"Evaluation set not found: {EVAL_PATH}")
    with open(EVAL_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)["cases"]


def prf(predicted: set, expected: set) -> Dict[str, float]:
    """Precision, recall and F1 for one case's technique set."""
    if not expected:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    true_positives = len(predicted & expected)
    precision = true_positives / len(predicted) if predicted else 0.0
    recall = true_positives / len(expected)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ATTACKDNA accuracy")
    parser.add_argument("--use-llm", action="store_true",
                        help="Evaluate the hybrid path instead of the rule-based one")
    parser.add_argument("--json", dest="json_out", metavar="PATH",
                        help="Also write the full report to a JSON file")
    args = parser.parse_args()

    init_db()
    session = SessionLocal()
    cases = load_cases()

    rows: List[dict] = []
    latencies: List[float] = []

    try:
        for case in cases:
            started = time.perf_counter()
            result = analyze(session, case["text"], use_llm=args.use_llm)
            latencies.append(time.perf_counter() - started)

            dna = result["dna"]
            expected = case["expected"]

            predicted_techniques = {t["id"] for t in dna["techniques"]}
            expected_techniques = set(expected.get("techniques", []))
            scores = prf(predicted_techniques, expected_techniques)

            similar = result["similar_incidents"]
            top_match = similar[0]["title"] if similar else None
            expected_match = case.get("expected_similar_to")
            retrieved_titles = [m["title"] for m in similar]

            rows.append({
                "id": case["id"],
                "attack_type_ok": dna["attack_type"] == expected["attack_type"],
                "attack_type": f"{dna['attack_type']} (want {expected['attack_type']})",
                "vector_ok": dna.get("initial_vector") == expected.get("initial_vector"),
                "sector_ok": dna["sector"] == expected["sector"],
                "severity_ok": dna["severity"] in expected.get("severity", []),
                "technique_precision": scores["precision"],
                "technique_recall": scores["recall"],
                "technique_f1": scores["f1"],
                "missed_techniques": sorted(expected_techniques - predicted_techniques),
                "extra_techniques": sorted(predicted_techniques - expected_techniques),
                "impact_recall": prf(set(dna["impacts"]), set(expected.get("impacts", [])))["recall"],
                "retrieval_top1_ok": top_match == expected_match,
                "retrieval_hit_at_3": expected_match in retrieved_titles[:3],
                "top_match": top_match,
                "expected_match": expected_match,
                "dna_valid": dna.get("validation", {}).get("valid", False),
                "privacy_clean": result["privacy"]["verified_clean"],
            })

        # --- Independent privacy assurance over every case ---
        privacy_leaks = []
        for case in cases:
            residual = verify_clean(sanitize(case["text"]).sanitized_text)
            if residual:
                privacy_leaks.append({"id": case["id"], "leaks": residual})

        _report(rows, latencies, privacy_leaks, args)
    finally:
        session.close()


def _report(rows: List[dict], latencies: List[float], privacy_leaks: List[dict],
            args) -> None:
    total = len(rows)
    summary = {
        "cases": total,
        "mode": "hybrid (rules + LLM)" if args.use_llm else "rule-based",
        "attack_type_accuracy": mean([r["attack_type_ok"] for r in rows]),
        "initial_vector_accuracy": mean([r["vector_ok"] for r in rows]),
        "sector_accuracy": mean([r["sector_ok"] for r in rows]),
        "severity_accuracy": mean([r["severity_ok"] for r in rows]),
        "technique_precision": mean([r["technique_precision"] for r in rows]),
        "technique_recall": mean([r["technique_recall"] for r in rows]),
        "technique_f1": mean([r["technique_f1"] for r in rows]),
        "impact_recall": mean([r["impact_recall"] for r in rows]),
        "retrieval_precision_at_1": mean([r["retrieval_top1_ok"] for r in rows]),
        "retrieval_hit_rate_at_3": mean([r["retrieval_hit_at_3"] for r in rows]),
        "dna_schema_valid": mean([r["dna_valid"] for r in rows]),
        "privacy_verified_clean": mean([r["privacy_clean"] for r in rows]),
        "privacy_leaks": len(privacy_leaks),
        "latency_mean_s": mean(latencies),
        "latency_max_s": max(latencies) if latencies else 0.0,
    }

    print(f"\n{'=' * 72}")
    print(f"ATTACKDNA EVALUATION — {summary['mode']} — {total} labelled cases")
    print("=" * 72)

    print("\nAttack DNA extraction")
    for label, key in [("Attack type", "attack_type_accuracy"),
                       ("Initial vector", "initial_vector_accuracy"),
                       ("Sector", "sector_accuracy"),
                       ("Severity band", "severity_accuracy"),
                       ("Impact recall", "impact_recall")]:
        print(f"  {label:<22} {summary[key]:6.1%}")

    print("\nMITRE ATT&CK mapping")
    for label, key in [("Precision", "technique_precision"),
                       ("Recall", "technique_recall"),
                       ("F1", "technique_f1")]:
        print(f"  {label:<22} {summary[key]:6.1%}")

    print("\nMemory retrieval")
    print(f"  {'Precision@1':<22} {summary['retrieval_precision_at_1']:6.1%}")
    print(f"  {'Hit rate@3':<22} {summary['retrieval_hit_rate_at_3']:6.1%}")

    print("\nAssurance")
    print(f"  {'DNA schema valid':<22} {summary['dna_schema_valid']:6.1%}")
    print(f"  {'Privacy verified clean':<22} {summary['privacy_verified_clean']:6.1%}")
    print(f"  {'Residual leaks found':<22} {summary['privacy_leaks']:>6}")

    print("\nPerformance")
    print(f"  {'Mean latency':<22} {summary['latency_mean_s']:6.2f}s")
    print(f"  {'Max latency':<22} {summary['latency_max_s']:6.2f}s")

    print("\nPer-case detail")
    print(f"  {'case':<9} {'type':<6} {'vec':<5} {'sect':<5} {'F1':<7} {'top-1':<6} match")
    for row in rows:
        print(f"  {row['id']:<9} "
              f"{'ok' if row['attack_type_ok'] else 'MISS':<6} "
              f"{'ok' if row['vector_ok'] else 'MISS':<5} "
              f"{'ok' if row['sector_ok'] else 'MISS':<5} "
              f"{row['technique_f1']:<7.2f} "
              f"{'ok' if row['retrieval_top1_ok'] else 'MISS':<6} "
              f"{(row['top_match'] or '—')[:38]}")

    misses = [r for r in rows if not r["attack_type_ok"] or r["technique_f1"] < 0.6
              or not r["retrieval_top1_ok"]]
    if misses:
        print("\nCases worth reviewing")
        for row in misses:
            print(f"  {row['id']}: {row['attack_type']}")
            if row["missed_techniques"]:
                print(f"    missed:   {', '.join(row['missed_techniques'])}")
            if row["extra_techniques"]:
                print(f"    extra:    {', '.join(row['extra_techniques'])}")
            if not row["retrieval_top1_ok"]:
                print(f"    expected: {row['expected_match']}")

    if privacy_leaks:
        print("\nPRIVACY LEAKS — these must be fixed before submission")
        for leak in privacy_leaks:
            print(f"  {leak['id']}: {leak['leaks']}")

    print()

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump({"summary": summary, "cases": rows,
                       "privacy_leaks": privacy_leaks}, handle, indent=2)
        print(f"Full report written to {args.json_out}\n")


if __name__ == "__main__":
    main()
