"""Measure ATTACKDNA against labelled data, and say which numbers mean what.

There are two kinds of number here and they must not be confused.

**Development sets** are cases the rules were built and tuned on. A high score
on them shows the system does what it was designed to do. It does not show
that it works on a report nobody has seen.

    evaluation_set.json    8 cases, written with the first version of the rules
    evaluation_dev.json    28 cases, first used as an unseen probe, then to
                           improve the rules

**The held-out set** is the test. Its texts are lead summaries of real,
publicly documented incidents, written by nobody on this project; the labels
were fixed before the system was run on them, and nothing was tuned afterwards.

    evaluation_heldout.json    32 real incident summaries

The privacy claim gets its own audit (`privacy_audit.json`): identifiers
marked by hand, checked with a plain substring test on the output, so the
result does not depend on what the privacy layer believes it found.

Run after seeding:

    python scripts/seed_memory.py --reset
    python scripts/evaluate.py                 # everything
    python scripts/evaluate.py --set heldout   # the test set only
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.config import DATA_DIR  # noqa: E402
from app.db.database import SessionLocal, init_db  # noqa: E402
from app.pipelines.analyze import analyze  # noqa: E402
from app.services.sanitizer import sanitize, verify_clean  # noqa: E402

SEED = DATA_DIR / "seed"
SETS = {
    "dev": [("development A", SEED / "evaluation_set.json"),
            ("development B", SEED / "evaluation_dev.json")],
    "heldout": [("held-out test", SEED / "evaluation_heldout.json")],
}
PRIVACY_AUDIT = SEED / "privacy_audit.json"


# --------------------------------------------------------------------------
# Small statistics
# --------------------------------------------------------------------------
def wilson(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """95% Wilson interval for a proportion.

    Reported next to every accuracy because "100%" of eight cases and "100%"
    of eight hundred are different claims, and only the interval says so.
    """
    if total == 0:
        return 0.0, 0.0
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def rate(successes: int, total: int) -> str:
    if total == 0:
        return "   n/a"
    low, high = wilson(successes, total)
    return f"{successes}/{total} = {successes / total:5.1%}  (95% CI {low:.0%}–{high:.0%})"


def family(technique_id: str) -> str:
    """T1059.001 -> T1059. Mapping is scored on the technique, not the variant."""
    return technique_id.split(".")[0]


def as_list(value) -> Optional[List[str]]:
    """Expected values may be one answer or every acceptable answer."""
    if value is None:
        return None
    return [value] if isinstance(value, str) else list(value)


# --------------------------------------------------------------------------
# Running a set
# --------------------------------------------------------------------------
def load(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)["cases"]


def run_case(session, case: dict, use_llm: bool) -> dict:
    started = time.perf_counter()
    result = analyze(session, case["text"], use_llm=use_llm, include_simulation=False)
    elapsed = time.perf_counter() - started

    dna, expected = result["dna"], case["expected"]
    sanitized = result["privacy"]["sanitized_text"]
    row = {"id": case["id"], "latency": elapsed,
           "predicted": {"attack_type": dna["attack_type"],
                         "initial_vector": dna.get("initial_vector"),
                         "severity": dna["severity"]},
           "self_check_clean": result["privacy"]["verified_clean"],
           "dna_valid": dna.get("validation", {}).get("valid", False)}

    for field in ("attack_type", "initial_vector"):
        accepted = as_list(expected.get(field))
        row[field] = None if accepted is None else dna.get(field) in accepted
    if expected.get("severity"):
        row["severity"] = dna["severity"] in expected["severity"]

    if expected.get("techniques"):
        predicted = {family(t["id"]) for t in dna["techniques"]}
        wanted = {family(t) for t in expected["techniques"]}
        row["techniques"] = {"tp": len(predicted & wanted), "fp": len(predicted - wanted),
                             "fn": len(wanted - predicted),
                             "missed": sorted(wanted - predicted),
                             "extra": sorted(predicted - wanted)}
    if expected.get("impacts") is not None and "impacts" in expected:
        wanted = set(expected["impacts"])
        got = set(dna["impacts"])
        row["impacts"] = {"tp": len(got & wanted), "fp": len(got - wanted), "fn": len(wanted - got)}

    if case.get("expected_similar_to"):
        titles = [match["title"] for match in result["similar_incidents"]]
        row["retrieval_top1"] = bool(titles) and titles[0] == case["expected_similar_to"]
        row["retrieval_top3"] = case["expected_similar_to"] in titles[:3]

    lowered = sanitized.lower()
    row["leaked"] = [value for value in case.get("must_not_survive", []) if value.lower() in lowered]
    row["hidden"] = len(case.get("must_not_survive", []))
    row["lost"] = [value for value in case.get("must_survive", []) if value.lower() not in lowered]
    row["kept"] = len(case.get("must_survive", []))
    return row


def prf(rows: Iterable[dict], key: str) -> Optional[dict]:
    """Micro-averaged precision, recall and F1 over every case that has labels."""
    scored = [row[key] for row in rows if key in row]
    if not scored:
        return None
    tp = sum(s["tp"] for s in scored)
    fp = sum(s["fp"] for s in scored)
    fn = sum(s["fn"] for s in scored)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"cases": len(scored), "tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1}


def summarise(rows: List[dict]) -> dict:
    def tally(field: str) -> Tuple[int, int]:
        scored = [row[field] for row in rows if row.get(field) is not None]
        return sum(scored), len(scored)

    summary = {"cases": len(rows)}
    for field in ("attack_type", "initial_vector", "severity",
                  "retrieval_top1", "retrieval_top3"):
        summary[field] = tally(field)
    summary["techniques"] = prf(rows, "techniques")
    summary["impacts"] = prf(rows, "impacts")
    summary["identifiers_hidden"] = (sum(row["hidden"] - len(row["leaked"]) for row in rows),
                                     sum(row["hidden"] for row in rows))
    summary["terms_kept"] = (sum(row["kept"] - len(row["lost"]) for row in rows),
                             sum(row["kept"] for row in rows))
    summary["self_check_clean"] = (sum(row["self_check_clean"] for row in rows), len(rows))
    summary["latency_mean"] = sum(row["latency"] for row in rows) / len(rows) if rows else 0.0
    summary["latency_max"] = max((row["latency"] for row in rows), default=0.0)
    return summary


def report(label: str, summary: dict, rows: List[dict], detail: bool) -> None:
    print(f"\n{label} — {summary['cases']} cases")
    print("-" * 72)
    for name, field in [("Attack type", "attack_type"), ("Initial vector", "initial_vector"),
                        ("Severity band", "severity")]:
        hits, total = summary[field]
        if total:
            print(f"  {name:<24} {rate(hits, total)}")
    techniques = summary["techniques"]
    if techniques:
        print(f"  {'ATT&CK techniques':<24} precision {techniques['precision']:.1%}  "
              f"recall {techniques['recall']:.1%}  F1 {techniques['f1']:.1%}"
              f"   ({techniques['tp']} found, {techniques['fp']} wrong, {techniques['fn']} missed)")
    impacts = summary["impacts"]
    if impacts:
        print(f"  {'Impacts':<24} precision {impacts['precision']:.1%}  recall {impacts['recall']:.1%}")
    hits, total = summary["retrieval_top1"]
    if total:
        print(f"  {'Retrieval precision@1':<24} {rate(hits, total)}")
    hits, total = summary["identifiers_hidden"]
    if total:
        print(f"  {'Identifiers removed':<24} {rate(hits, total)}")
    hits, total = summary["terms_kept"]
    if total:
        print(f"  {'Attack terms preserved':<24} {rate(hits, total)}")
    print(f"  {'Latency':<24} mean {summary['latency_mean']:.2f}s, max {summary['latency_max']:.2f}s")

    if not detail:
        return
    for row in rows:
        problems = []
        for field in ("attack_type", "initial_vector"):
            if row.get(field) is False:
                problems.append(f"{field}={row['predicted'][field]}")
        if row.get("techniques", {}).get("extra"):
            problems.append("extra " + ",".join(row["techniques"]["extra"]))
        if row["leaked"]:
            problems.append("LEAKED " + ", ".join(row["leaked"]))
        if row["lost"]:
            problems.append("lost " + ", ".join(row["lost"]))
        if problems:
            print(f"    {row['id']:<10} " + " | ".join(problems))


# --------------------------------------------------------------------------
# Privacy audit
# --------------------------------------------------------------------------
def privacy_audit(detail: bool, splits: List[str]) -> dict:
    if not PRIVACY_AUDIT.exists():
        return {}
    with open(PRIVACY_AUDIT, "r", encoding="utf-8") as handle:
        audit = json.load(handle)

    results = {}
    print("\nPrivacy audit — identifiers marked by hand, checked by substring")
    print("-" * 72)
    for split in splits:
        per_category: Dict[str, List[int]] = {}
        leaked_rows, kept, kept_total, self_check_misses = [], 0, 0, 0
        for item in audit.get(split, []):
            output = sanitize(item["text"]).sanitized_text
            lowered = output.lower()
            leaked = [v for v in item["must_not_survive"] if v.lower() in lowered]
            bucket = per_category.setdefault(item["category"], [0, 0])
            bucket[0] += len(item["must_not_survive"]) - len(leaked)
            bucket[1] += len(item["must_not_survive"])
            kept += sum(1 for v in item.get("must_survive", []) if v.lower() in lowered)
            kept_total += len(item.get("must_survive", []))
            if leaked:
                leaked_rows.append((item["id"], leaked, output))
                # The self-check agreeing that leaking text is clean is the
                # failure this audit exists to expose.
                if not verify_clean(output):
                    self_check_misses += 1

        removed = sum(b[0] for b in per_category.values())
        total = sum(b[1] for b in per_category.values())
        results[split] = {"removed": removed, "total": total, "terms_kept": kept,
                          "terms_total": kept_total,
                          "by_category": {k: tuple(v) for k, v in per_category.items()},
                          "sentences": len(audit.get(split, [])),
                          "sentences_with_leak": len(leaked_rows)}
        title = "development" if split == "development" else "held-out"
        print(f"  {title:<12} identifiers removed   {rate(removed, total)}")
        print(f"  {'':<12} attack terms preserved {rate(kept, kept_total)}")
        print("  " + " " * 12 + " · ".join(
            f"{category} {b[0]}/{b[1]}" for category, b in sorted(per_category.items())))
        if leaked_rows:
            print(f"  {'':<12} {len(leaked_rows)} sentence(s) leaked; the self-check missed "
                  f"{self_check_misses} of them")
            if detail:
                for item_id, leaked, output in leaked_rows:
                    print(f"      {item_id}: {leaked}  ->  {output}")
    return results


# --------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ATTACKDNA")
    parser.add_argument("--set", choices=["all", "dev", "heldout"], default="all")
    parser.add_argument("--use-llm", action="store_true",
                        help="Evaluate the hybrid path instead of the rule-based one")
    parser.add_argument("--detail", action="store_true", help="List every miss")
    parser.add_argument("--json", dest="json_out", metavar="PATH",
                        help="Also write the full report to a JSON file")
    args = parser.parse_args()

    init_db()
    session = SessionLocal()
    mode = "hybrid (rules + learned + LLM)" if args.use_llm else "offline (rules + learned mapper)"
    print("=" * 72)
    print(f"ATTACKDNA EVALUATION — {mode}")
    print("=" * 72)

    output = {"mode": mode, "sets": {}}
    try:
        chosen = ["dev", "heldout"] if args.set == "all" else [args.set]
        for group in chosen:
            group_rows: List[dict] = []
            for label, path in SETS[group]:
                cases = load(path)
                if not cases:
                    continue
                rows = [run_case(session, case, args.use_llm) for case in cases]
                group_rows.extend(rows)
                output["sets"][label] = {"summary": summarise(rows), "cases": rows}
                if len(SETS[group]) > 1:
                    report(label.upper(), summarise(rows), rows, args.detail)
            if group_rows:
                heading = ("DEVELOPMENT (tuned on these — not a test result)" if group == "dev"
                           else "HELD-OUT TEST (real incident summaries, labels fixed in advance)")
                combined = summarise(group_rows)
                output["sets"][group] = {"summary": combined}
                report(heading, combined, group_rows, args.detail and len(SETS[group]) == 1)
    finally:
        session.close()

    splits = {"all": ["development", "heldout"], "dev": ["development"], "heldout": ["heldout"]}
    output["privacy_audit"] = privacy_audit(args.detail, splits[args.set])
    print()

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2, default=list)
        print(f"Full report written to {args.json_out}\n")


if __name__ == "__main__":
    main()
