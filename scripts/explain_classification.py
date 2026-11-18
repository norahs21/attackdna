"""Show how ATTACKDNA classified a report: what the words said, what the
behaviour said, and how sure the final answer is.

Runs on the core pipeline only (no database, no API, no LLM), so it works
straight after `make setup`.

    # one sentence
    python scripts/explain_classification.py --text "A user clicked a link in an email ..."

    # one or more report files (.txt, .pdf, .docx)
    python scripts/explain_classification.py sample_reports/01_A_hospital_ransomware_via_phishing.txt

    # every sample report, one line each
    python scripts/explain_classification.py --samples

    # is "high confidence" really more often right? (labelled evaluation sets)
    python scripts/explain_classification.py --calibration
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
# This script explains the deterministic pipeline; never call an LLM from it.
os.environ["LLM_API_KEY"] = ""

from app.services.document_reader import read_report  # noqa: E402
from app.services.dna_extractor import extract_dna  # noqa: E402
from app.services.sanitizer import sanitize  # noqa: E402

FIELDS = (("attack_type", "Attack type"), ("initial_vector", "Initial vector"))
SEED = PROJECT_ROOT / "data" / "seed"
EVALUATION_SETS = ("evaluation_dev", "evaluation_heldout", "evaluation_set")


def pretty(value) -> str:
    return (value or "unknown").replace("_", " ")


def dna_for(text: str) -> dict:
    return extract_dna(sanitize(text).sanitized_text, {}, use_llm=False)


def read_file(path: Path) -> str:
    return read_report(path.name, path.read_bytes()).text


def explain(title: str, text: str) -> None:
    dna = dna_for(text)
    print("=" * 78)
    print(title)
    print("=" * 78)
    for field, name in FIELDS:
        record = dna["classification"][field]
        print(f"\n{name}: {pretty(record['value']).upper()}"
              f"   [{record['confidence']} confidence]")
        print(f"  report's words say    : {pretty(record['words'])}")
        behaviour = pretty(record["behaviour"])
        if record.get("behaviour_entry_only"):
            behaviour += "  (only how it started, not counted for the type)"
        print(f"  detected behaviour says: {behaviour}")
        print(f"  agreement             : {record['agreement']}"
              f"  (decided by: {record['decided_by']})")
        if record.get("alternative"):
            print(f"  alternative           : {pretty(record['alternative'])}")
    print(f"\nSeverity: {dna['severity']}")
    print("Techniques (the behaviour the second voter reads):")
    for technique in dna["techniques"]:
        evidence = ", ".join(technique["evidence"][:2])
        print(f"  {technique['id']:<10} {technique['name'][:38]:<38} "
              f"conf {technique['confidence']:.2f}  ({evidence[:40]})")
    if dna["kev"]["known_exploited_count"]:
        print("Known exploited CVEs (CISA KEV): " + ", ".join(dna["kev"]["known_exploited"]))
    print()


def samples() -> None:
    folder = PROJECT_ROOT / "sample_reports"
    print(f"{'report':<44} {'attack type':<26} {'vector':<18} {'conf (type/vector)'}")
    for path in sorted(folder.iterdir()):
        if path.name.startswith("."):
            continue
        dna = dna_for(read_file(path))
        c = dna["classification"]
        print(f"{path.name[:43]:<44} {pretty(dna['attack_type']):<26} "
              f"{pretty(dna['initial_vector']):<18} "
              f"{c['attack_type']['confidence']}/{c['initial_vector']['confidence']}")


def calibration() -> None:
    """Accuracy at each confidence level, on the team's labelled sets."""
    tally = defaultdict(lambda: [0, 0])
    for name in EVALUATION_SETS:
        cases = json.loads((SEED / f"{name}.json").read_text())["cases"]
        for case in cases:
            dna = dna_for(case["text"])
            for field, _ in FIELDS:
                expected = case["expected"].get(field)
                if not expected:
                    continue
                accepted = expected if isinstance(expected, list) else [expected]
                level = dna["classification"][field]["confidence"]
                tally[(field, level)][1] += 1
                tally[(field, level)][0] += dna[field] in accepted
    print("How often each confidence level was right (dev + held-out + scored set):\n")
    for field, name in FIELDS:
        print(name)
        for level in ("high", "medium", "low", "none"):
            right, total = tally.get((field, level), [0, 0])
            if total:
                print(f"  {level:<7} {right:>3}/{total:<3} correct  ({right / total:.0%})")
        print()
    print("'none' means neither voter found evidence; the answer is 'unknown',\n"
          "which is correct when the text really does not say.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="*", help="report files (.txt, .pdf, .docx)")
    parser.add_argument("--text", help="a description to classify instead of a file")
    parser.add_argument("--samples", action="store_true", help="every sample report, one line each")
    parser.add_argument("--calibration", action="store_true",
                        help="accuracy at each confidence level on the evaluation sets")
    args = parser.parse_args()

    if args.calibration:
        calibration()
    elif args.samples:
        samples()
    elif args.text:
        explain("Your text", args.text)
    elif args.files:
        for name in args.files:
            explain(name, read_file(Path(name)))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
