"""ATTACKDNA's results on one page.

    make results

Every figure is measured on data the system was not tuned on, and each line
says what it means. The detailed scripts behind them:

    scripts/evaluate_mapper.py     ATT&CK technique mapping
    scripts/evaluate_crossorg.py   organisation A shares, organisation B recalls
    scripts/evaluate_next_step.py  predicting the attacker's next step
    scripts/evaluate.py            per-case detail of the held-out incident set

Writes data/evaluation/results.json.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services.dna_extractor import extract_dna  # noqa: E402
from app.services.sanitizer import sanitize  # noqa: E402

SEED = PROJECT_ROOT / "data" / "seed"
EVALUATION = PROJECT_ROOT / "data" / "evaluation"


def present(value: str, text: str) -> bool:
    return re.search(r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])",
                     text, re.I) is not None


def load(name: str):
    path = SEED / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def privacy() -> dict:
    """Identifiers marked by hand in texts written after the rules were frozen."""
    removed = total = kept = terms = 0
    texts = []
    audit = load("privacy_audit.json") or {}
    texts += [(i["text"], i["must_not_survive"], i.get("must_survive", []))
              for i in audit.get("heldout", [])]
    held = load("evaluation_heldout.json") or {"cases": []}
    texts += [(c["text"], c.get("must_not_survive", []), c.get("must_survive", []))
              for c in held["cases"]]
    pairs = load("crossorg_pairs.json") or {"pairs": []}
    texts += [(p[s]["text"], p[s]["identifiers"], p[s]["behaviour"])
              for p in pairs["pairs"] for s in "ab"]
    for text, identifiers, behaviour in texts:
        out = sanitize(text).sanitized_text
        removed += sum(1 for v in identifiers if not present(v, out))
        total += len(identifiers)
        kept += sum(1 for v in behaviour if present(v, out))
        terms += len(behaviour)
    return {"identifiers_removed": removed, "identifiers": total,
            "terms_kept": kept, "terms": terms, "texts": len(texts)}


def classification() -> dict:
    """Attack type on real incident summaries, labels fixed in advance."""
    held = load("evaluation_heldout.json") or {"cases": []}
    scores = {"attack_type": [0, 0]}
    for case in held["cases"]:
        clean = sanitize(case["text"])
        dna = extract_dna(clean.sanitized_text, clean.counts, use_llm=False)
        for field in scores:
            want = case["expected"].get(field)
            if want is None:
                continue
            want = [want] if isinstance(want, str) else want
            scores[field][0] += dna[field] in want
            scores[field][1] += 1
    return {field: {"correct": c, "total": t} for field, (c, t) in scores.items()}


def read(name: str):
    path = EVALUATION / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def pct(a: float, b: float) -> str:
    return f"{a / b:5.1%}" if b else "  n/a"


def main() -> None:
    p = privacy()
    c = classification()
    mapper = read("mapper_results.json")
    crossorg = read("crossorg_results.json")
    nxt = read("next_step_results.json")

    rows = [
        ("PRIVACY", None, None),
        ("Identifiers removed", pct(p["identifiers_removed"], p["identifiers"]),
         f"{p['identifiers_removed']} of {p['identifiers']} names, emails, IPs, hosts... "
         f"marked by hand in {p['texts']} texts"),
        ("Attack terms kept", pct(p["terms_kept"], p["terms"]),
         f"{p['terms_kept']} of {p['terms']} behaviour words survived the redaction"),
        ("ATTACK DNA", None, None),
        ("Attack type correct", pct(c["attack_type"]["correct"], c["attack_type"]["total"]),
         f"{c['attack_type']['correct']} of {c['attack_type']['total']} real incident summaries"),
    ]
    if mapper:
        f = mapper["final"]
        rows += [("ATT&CK techniques found", f"{f['recall']:5.1%}",
                  f"{f['found']:,} of {f['sentences']:,} MITRE sentences about attackers never "
                  "seen in training"),
                 ("…of suggestions, correct", f"{f['precision']:5.1%}",
                  "a lower bound: each sentence has one label")]
    if nxt:
        a, t = nxt["attackers"], nxt["tools"]
        rows += [
            ("NEXT STEP", None, None),
            ("Next step predicted", f"{a['hit_at_3']:5.1%}",
             f"{a['found']} of {a['cases']} threat groups/campaigns never seen in training: 1 of 3 "
             f"predictions right (guessing: {a['shortcut_hit_at_3']:.0%})"),
            ("…for malware and tools", f"{t['hit_at_3']:5.1%}",
             f"{t['found']} of {t['cases']} (guessing: {t['shortcut_hit_at_3']:.0%})"),
        ]
    if crossorg:
        r = crossorg["cross_org_recall"]
        rows += [
            ("ACROSS ORGANISATIONS", None, None),
            ("B finds A's incident first", f"{r['precision_at_1']['value']:5.1%}",
             f"{r['precision_at_1']['successes']} of {r['queries']} attacks reported by two "
             "organisations"),
            ("…in its top five", f"{r['recall_at_5']['value']:5.1%}",
             f"{r['recall_at_5']['successes']} of {r['queries']}"),
            ("A's response reused by B", f"{r['mitigation_reuse']['value']:5.1%}",
             "recommended with its source named"),
            ("Screens that named A", f"{r['queries_exposing_A']} / {r['queries']}",
             "B never sees who A is"),
        ]

    print()
    print("ATTACKDNA RESULTS")
    print("=" * 78)
    for label, value, note in rows:
        if value is None:
            print(f"\n{label}")
            continue
        print(f"  {label:<28} {value:>7}   {note}")
    missing = [n for n, v in (("make eval-mapper", mapper), ("make eval-crossorg", crossorg),
                              ("make eval-next-step", nxt)) if not v]
    if missing:
        print(f"\n  (run {' and '.join(missing)} for the remaining rows)")
    print()

    EVALUATION.mkdir(parents=True, exist_ok=True)
    (EVALUATION / "results.json").write_text(json.dumps(
        {"privacy": p, "classification": c,
         "techniques": mapper["final"] if mapper else None,
         "next_step": {k: nxt[k] for k in ("attackers", "tools", "all")} if nxt else None,
         "cross_org": {k: crossorg["cross_org_recall"][k] for k in
                       ("precision_at_1", "recall_at_5", "mitigation_reuse",
                        "queries_exposing_A", "queries")} if crossorg else None},
        indent=2, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
