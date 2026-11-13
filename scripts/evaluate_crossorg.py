"""The experiment behind the project's central claim.

    One organization's cyber incident becomes another organization's
    defensive knowledge, without sharing the victim's identity or report.

That sentence makes four separate claims, and each gets its own measurement:

  1. Privacy protection     The identifiers planted in every report are gone,
                            checked by a word-boundary search on the output,
                            not by asking the privacy layer what it found.
                            Over-redaction (attack terms lost) is counted too.
  2. Behaviour preservation The Attack DNA extracted from the sanitized report
                            is compared with the DNA extracted from the raw
                            report. Removing the victim must not remove the
                            attack.
  3. Cross-organization     Organization A contributes 20 incidents to shared
     recall                 memory, alongside the 24-incident public and
                            synthetic corpus. Organization B reports the same
                            20 attack patterns in its own words. Does B recall
                            A's incident? Precision@1, Recall@5, Precision@5
                            and MRR. Does anything that names A reach B's
                            screen? Does A's recorded response reach B?
  4. Privacy vs utility     The same recall experiment with the privacy layer
                            switched off. The difference between (3) and (4) is
                            what privacy costs in retrieval quality.

Everything runs in a throwaway database and vector store, so the demo memory
is never touched. Results are written to data/evaluation/crossorg_results.json,
which the interface reads for its Evidence page.

    python scripts/evaluate_crossorg.py
    python scripts/evaluate_crossorg.py --no-corpus   # shared memory = A's 20 only
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

# Isolate the experiment BEFORE app.config is imported anywhere.
_scratch = Path(tempfile.mkdtemp(prefix="attackdna-crossorg-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_scratch / 'crossorg.db'}"
os.environ["CHROMA_DIR"] = str(_scratch / "chroma")

from app.config import DATA_DIR, SEED_INCIDENTS_PATH  # noqa: E402
from app.db.database import IncidentDB, SessionLocal, init_db  # noqa: E402
from app.pipelines.analyze import _persist, analyze, contribute, ingest  # noqa: E402
from app.services import vector_memory  # noqa: E402
from app.services.contributors import pseudonym  # noqa: E402
from app.services.dna_extractor import extract_dna  # noqa: E402
from app.services.mitigation_memory import recall_mitigations  # noqa: E402
from app.services.sanitizer import sanitize, verify_clean  # noqa: E402
from app.services.similarity import find_similar_incidents  # noqa: E402

PAIRS_PATH = DATA_DIR / "seed" / "crossorg_pairs.json"
PUBLIC_PATH = DATA_DIR / "seed" / "public_incidents.json"
RESULTS_PATH = DATA_DIR / "evaluation" / "crossorg_results.json"
RANK_DEPTH = 10


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def wilson(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """95% Wilson interval: twenty cases is a small sample, and this says how small."""
    if total == 0:
        return 0.0, 0.0
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)


def proportion(successes: int, total: int) -> dict:
    return {"value": round(successes / total, 4) if total else None,
            "successes": successes, "total": total, "ci95": wilson(successes, total)}


def present(value: str, text: str) -> bool:
    """Is an identifier still readable in `text`?

    Word boundaries, case-insensitive: a plain substring test would report the
    surname "Ali" as surviving inside the word "malicious".
    """
    pattern = r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def family(technique_id: str) -> str:
    return technique_id.split(".")[0]


def strings_in(value) -> Iterable[str]:
    """Every string anywhere inside a nested result, for the exposure check."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings_in(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from strings_in(item)


def git_revision() -> Optional[str]:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=PROJECT_ROOT,
                              capture_output=True, text=True, timeout=5).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


# --------------------------------------------------------------------------
# Memory setup
# --------------------------------------------------------------------------
def wipe(session) -> None:
    session.query(IncidentDB).delete()
    session.commit()
    vector_memory.reset_memory()


def seed_corpus(session) -> int:
    """The same public + synthetic corpus the demo starts with, as distractors."""
    count = 0
    for path, provenance in ((PUBLIC_PATH, "public"), (SEED_INCIDENTS_PATH, "synthetic")):
        if not path.exists():
            continue
        with open(path, "r", encoding="utf-8") as handle:
            for entry in json.load(handle)["incidents"]:
                occurred = (datetime.strptime(entry["occurred_at"], "%Y-%m-%d")
                            if entry.get("occurred_at") else None)
                ingest(session, entry["text"], title=entry.get("title"), source="seed",
                       occurred_at=occurred, mitigations=entry.get("mitigations", []),
                       use_llm=False, provenance=provenance,
                       source_name=entry.get("source_name"), source_url=entry.get("source_url"))
                count += 1
    return count


def raw_result(text: str) -> dict:
    """What `analyze` would return if there were no privacy layer at all."""
    dna = extract_dna(text, {}, use_llm=False)
    return {"privacy": {"sanitized_text": text, "total_redactions": 0}, "dna": dna}


# --------------------------------------------------------------------------
# Experiments 1 and 2: per report
# --------------------------------------------------------------------------
def privacy_and_behaviour(pairs: List[dict]) -> Tuple[dict, dict, List[dict]]:
    rows = []
    for pair in pairs:
        for side in ("a", "b"):
            report = pair[side]
            text = report["text"]
            sanitized = sanitize(text).sanitized_text
            leaked = [v for v in report["identifiers"] if present(v, sanitized)]
            lost = [v for v in report["behaviour"] if not present(v, sanitized)]

            raw_dna = extract_dna(text, {}, use_llm=False)
            clean_dna = extract_dna(sanitized, sanitize(text).counts, use_llm=False)
            raw_tech = {family(t["id"]) for t in raw_dna["techniques"]}
            clean_tech = {family(t["id"]) for t in clean_dna["techniques"]}
            labels = pair["labels"]
            wanted = {family(t) for t in labels["techniques"]}

            rows.append({
                "report": f"{pair['id']}{side.upper()}",
                "identifiers": len(report["identifiers"]),
                "leaked": leaked,
                "behaviour_terms": len(report["behaviour"]),
                "behaviour_lost": lost,
                "self_check_clean": not verify_clean(sanitized),
                "raw": {"attack_type": raw_dna["attack_type"],
                        "initial_vector": raw_dna.get("initial_vector"),
                        "techniques": sorted(raw_tech), "impacts": sorted(raw_dna["impacts"]),
                        "cves": sorted(raw_dna["cves"])},
                "sanitized": {"attack_type": clean_dna["attack_type"],
                              "initial_vector": clean_dna.get("initial_vector"),
                              "techniques": sorted(clean_tech),
                              "impacts": sorted(clean_dna["impacts"]),
                              "cves": sorted(clean_dna["cves"])},
                "label_attack_type": labels["attack_type"],
                "label_vector": labels["initial_vector"],
                "label_techniques": sorted(wanted),
            })

    planted = sum(r["identifiers"] for r in rows)
    leaked = sum(len(r["leaked"]) for r in rows)
    terms = sum(r["behaviour_terms"] for r in rows)
    lost = sum(len(r["behaviour_lost"]) for r in rows)
    reports_with_leak = [r for r in rows if r["leaked"]]
    self_check_missed = sum(1 for r in reports_with_leak if r["self_check_clean"])

    privacy = {
        "reports": len(rows),
        "identifiers_planted": planted,
        "identifiers_removed": proportion(planted - leaked, planted),
        "residual_identifiers": leaked,
        "residual_detail": {r["report"]: r["leaked"] for r in reports_with_leak},
        "reports_with_residual": len(reports_with_leak),
        "self_check_missed": self_check_missed,
        "over_redaction": proportion(lost, terms),
        "over_redaction_detail": {r["report"]: r["behaviour_lost"] for r in rows
                                  if r["behaviour_lost"]},
    }

    def same(field: str) -> int:
        return sum(1 for r in rows if r["raw"][field] == r["sanitized"][field])

    raw_tech_total = sum(len(r["raw"]["techniques"]) for r in rows)
    kept_tech = sum(len(set(r["raw"]["techniques"]) & set(r["sanitized"]["techniques"]))
                    for r in rows)
    raw_impacts = sum(len(r["raw"]["impacts"]) for r in rows)
    kept_impacts = sum(len(set(r["raw"]["impacts"]) & set(r["sanitized"]["impacts"]))
                       for r in rows)
    raw_cves = sum(len(r["raw"]["cves"]) for r in rows)
    kept_cves = sum(len(set(r["raw"]["cves"]) & set(r["sanitized"]["cves"])) for r in rows)

    def against_labels(which: str) -> dict:
        attack = sum(1 for r in rows if r[which]["attack_type"] == r["label_attack_type"])
        vector = sum(1 for r in rows if r[which]["initial_vector"] == r["label_vector"])
        tp = sum(len(set(r[which]["techniques"]) & set(r["label_techniques"])) for r in rows)
        fp = sum(len(set(r[which]["techniques"]) - set(r["label_techniques"])) for r in rows)
        fn = sum(len(set(r["label_techniques"]) - set(r[which]["techniques"])) for r in rows)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        return {"attack_type": proportion(attack, len(rows)),
                "initial_vector": proportion(vector, len(rows)),
                "techniques": {"precision": round(precision, 4), "recall": round(recall, 4),
                               "f1": round(2 * precision * recall / (precision + recall), 4)
                               if precision + recall else 0.0,
                               "tp": tp, "fp": fp, "fn": fn}}

    behaviour = {
        "reports": len(rows),
        "attack_type_unchanged": proportion(same("attack_type"), len(rows)),
        "initial_vector_unchanged": proportion(same("initial_vector"), len(rows)),
        "techniques_retained": proportion(kept_tech, raw_tech_total),
        "impacts_retained": proportion(kept_impacts, raw_impacts),
        "cves_retained": proportion(kept_cves, raw_cves),
        "accuracy_raw": against_labels("raw"),
        "accuracy_sanitized": against_labels("sanitized"),
    }
    return privacy, behaviour, rows


# --------------------------------------------------------------------------
# Experiments 3 and 4: recall across organizations
# --------------------------------------------------------------------------
def recall_experiment(session, pairs: List[dict], with_corpus: bool, private: bool) -> dict:
    """Contribute every A, query with every B, and score where A lands."""
    wipe(session)
    corpus = seed_corpus(session) if with_corpus else 0

    contributed: Dict[str, str] = {}   # pair id -> incident id
    label_of: Dict[str, str] = {}      # incident id -> labelled attack type
    for pair in pairs:
        a = pair["a"]
        if private:
            result = analyze(session, a["text"], use_llm=False, include_simulation=False)
            receipt = contribute(session, result, organisation=a["organization"],
                                 mitigations=a["mitigations"])
            incident_id = receipt["incident_id"]
        else:
            incident = _persist(session, raw_result(a["text"]), title=f"{pair['id']}A",
                                source="shared", provenance="shared", occurred_at=None,
                                mitigations=a["mitigations"], raw_text=a["text"],
                                contributor_ref=pseudonym(a["organization"]))
            incident_id = incident.id
        contributed[pair["id"]] = incident_id
        label_of[incident_id] = pair["labels"]["attack_type"]

    a_identifiers = sorted({v for pair in pairs for v in pair["a"]["identifiers"]})

    # What shared memory holds, as any member reading a record through the API
    # would get it. B's screen shows only the fingerprint; this is the stronger
    # test, because it covers the stored text as well.
    stored_exposed: Dict[str, List[str]] = {}
    for pair in pairs:
        record = session.get(IncidentDB, contributed[pair["id"]]).to_dict()
        found = [v for v in pair["a"]["identifiers"]
                 if any(present(v, text) for text in strings_in(record))]
        if found:
            stored_exposed[f"{pair['id']}A"] = found
    queries = []
    for pair in pairs:
        b = pair["b"]
        viewer = pseudonym(b["organization"])
        if private:
            result = analyze(session, b["text"], top_k=RANK_DEPTH, use_llm=False,
                             include_simulation=False, viewer_ref=viewer)
            similar, mitigations = result["similar_incidents"], result["mitigations"]
        else:
            dna = extract_dna(b["text"], {}, use_llm=False)
            similar = find_similar_incidents(session, dna, top_k=RANK_DEPTH, viewer_ref=viewer)
            mitigations = recall_mitigations(similar, [t["id"] for t in dna["techniques"]])

        target = contributed[pair["id"]]
        ids = [m["incident_id"] for m in similar]
        rank = ids.index(target) + 1 if target in ids else None
        wanted = pair["labels"]["attack_type"]
        top5 = similar[:5]
        top1_same_attack = bool(similar) and label_of.get(
            similar[0]["incident_id"], similar[0].get("attack_type")) == wanted
        relevant_top5 = sum(1 for m in top5
                            if label_of.get(m["incident_id"], m.get("attack_type")) == wanted)

        # What reaches B's screen: the matches and the recommendations.
        visible = list(strings_in(similar)) + list(strings_in(mitigations["recommended"]))
        exposed = sorted({v for v in a_identifiers if any(present(v, s) for s in visible)})

        a_actions = {m["action"].lower() for m in pair["a"]["mitigations"]}
        reused = [item for item in mitigations["recommended"]
                  if item.get("origin") == "recalled"
                  and any(src.get("incident_id") == target for src in item.get("sources", []))]
        reused_from_a = [item for item in reused
                         if sanitize(item["action"]).sanitized_text.lower() in a_actions
                         or item["action"].lower() in a_actions]
        unattributed = [item for item in mitigations["recommended"]
                        if item.get("origin") == "recalled" and not item.get("sources")]

        queries.append({
            "pair": pair["id"], "pattern": pair["pattern"], "rank": rank,
            "top1": similar[0]["title"] if similar else None,
            "top1_is_target": rank == 1,
            "top1_same_attack_type": top1_same_attack,
            "relevant_in_top5": relevant_top5, "retrieved_top5": len(top5),
            "exposed_identifiers": exposed,
            "marked_as_own": any(m.get("from_your_organisation") for m in similar),
            "a_mitigations_recalled": len(reused_from_a),
            "unattributed_recommendations": len(unattributed),
            "match_reasons": similar[rank - 1]["match_reasons"] if rank else [],
        })

    n = len(queries)
    hits1 = sum(1 for q in queries if q["rank"] == 1)
    hits5 = sum(1 for q in queries if q["rank"] and q["rank"] <= 5)
    mrr = sum(1 / q["rank"] for q in queries if q["rank"]) / n if n else 0.0
    p_at_5 = (sum(q["relevant_in_top5"] for q in queries)
              / sum(max(q["retrieved_top5"], 1) for q in queries)) if n else 0.0
    return {
        "privacy_layer": "on" if private else "off",
        "memory": {"corpus_incidents": corpus, "contributed_by_A": len(contributed),
                   "backend": vector_memory.memory_stats()["backend"]},
        "queries": n,
        "precision_at_1": proportion(hits1, n),
        "recall_at_5": proportion(hits5, n),
        "top1_same_attack_type": proportion(sum(q["top1_same_attack_type"] for q in queries), n),
        "precision_at_5": round(p_at_5, 4),
        "mrr": round(mrr, 4),
        "queries_exposing_A": sum(1 for q in queries if q["exposed_identifiers"]),
        "stored_records_exposing_A": len(stored_exposed),
        "stored_exposure_detail": stored_exposed,
        "A_identifiers_exposed": sorted({v for q in queries for v in q["exposed_identifiers"]}),
        "foreign_incident_marked_as_own": sum(1 for q in queries if q["marked_as_own"]),
        "mitigation_reuse": proportion(sum(1 for q in queries if q["a_mitigations_recalled"]), n),
        "unattributed_recommendations": sum(q["unattributed_recommendations"] for q in queries),
        "per_query": queries,
    }


def own_incident_check(session, pairs: List[dict]) -> dict:
    """A re-reading its own report must see "yours"; that is what makes B's "not yours" mean something."""
    marked = 0
    for pair in pairs:
        a = pair["a"]
        result = analyze(session, a["text"], top_k=3, use_llm=False, include_simulation=False,
                         viewer_ref=pseudonym(a["organization"]))
        top = result["similar_incidents"][:1]
        marked += bool(top and top[0].get("from_your_organisation"))
    return proportion(marked, len(pairs))


# --------------------------------------------------------------------------
def print_report(output: dict) -> None:
    def pct(entry) -> str:
        if isinstance(entry, dict):
            low, high = entry["ci95"]
            return (f"{entry['successes']}/{entry['total']} = {entry['value']:.0%}  "
                    f"(95% CI {low:.0%}–{high:.0%})")
        return f"{entry:.2f}"

    p, b = output["privacy_protection"], output["behaviour_preservation"]
    on, off = output["cross_org_recall"], output["privacy_utility"]["without_privacy_layer"]
    print("=" * 76)
    print("ATTACKDNA — CROSS-ORGANIZATION EXPERIMENT")
    print(f"{output['pairs']} attack patterns × 2 organizations · memory backend: "
          f"{on['memory']['backend']} · corpus distractors: {on['memory']['corpus_incidents']}")
    print("=" * 76)
    print("\n1. Privacy protection (40 reports, identifiers marked by hand)")
    print(f"   Identifiers planted          {p['identifiers_planted']}")
    print(f"   Removed                      {pct(p['identifiers_removed'])}")
    print(f"   Residual after audit         {p['residual_identifiers']}  "
          f"in {p['reports_with_residual']} report(s)")
    for report, values in p["residual_detail"].items():
        print(f"       {report}: {', '.join(values)}")
    print(f"   Over-redaction (terms lost)  {pct(p['over_redaction'])}")
    for report, values in p["over_redaction_detail"].items():
        print(f"       {report}: {', '.join(values)}")
    print("\n2. Behaviour preservation (raw DNA vs sanitized DNA)")
    print(f"   Attack type unchanged        {pct(b['attack_type_unchanged'])}")
    print(f"   Entry vector unchanged       {pct(b['initial_vector_unchanged'])}")
    print(f"   ATT&CK techniques retained   {pct(b['techniques_retained'])}")
    print(f"   Impacts retained             {pct(b['impacts_retained'])}")
    print(f"   CVEs retained                {pct(b['cves_retained'])}")
    for which in ("raw", "sanitized"):
        acc = b[f"accuracy_{which}"]
        print(f"   vs labels, {which:<9}         attack type {acc['attack_type']['value']:.0%} · "
              f"vector {acc['initial_vector']['value']:.0%} · techniques P "
              f"{acc['techniques']['precision']:.0%} R {acc['techniques']['recall']:.0%}")
    print("\n3. Cross-organization recall (B queries, A's incident is the answer)")
    print(f"   Precision@1                  {pct(on['precision_at_1'])}")
    print(f"   Recall@5                     {pct(on['recall_at_5'])}")
    print(f"   Precision@5 (same attack)    {on['precision_at_5']:.0%}")
    print(f"   MRR                          {on['mrr']:.2f}")
    print(f"   Top-1 has the same attack    {pct(on['top1_same_attack_type'])}")
    print(f"   Shared records naming A      {on['stored_records_exposing_A']} of "
          f"{on['memory']['contributed_by_A']}"
          + "".join(f"\n       {k}: {', '.join(v)}" for k, v in on["stored_exposure_detail"].items()))
    print(f"   B's screens that exposed A   {on['queries_exposing_A']} of {on['queries']}"
          + (f"  ({', '.join(on['A_identifiers_exposed'])})" if on["A_identifiers_exposed"] else ""))
    print(f"   A's response recalled for B  {pct(on['mitigation_reuse'])}")
    print(f"   Other org shown as 'yours'   {on['foreign_incident_marked_as_own']}  "
          f"· own incident shown as 'yours' {pct(output['own_incident_recognised'])}")
    misses = [q for q in on["per_query"] if q["rank"] != 1]
    for q in misses:
        print(f"       {q['pair']}: rank {q['rank'] or '>' + str(RANK_DEPTH)} — top was "
              f"'{q['top1']}'")
    print("\n4. Privacy vs utility (same experiment, privacy layer off)")
    print(f"   Precision@1   on {on['precision_at_1']['value']:.0%}  vs  "
          f"off {off['precision_at_1']['value']:.0%}")
    print(f"   MRR           on {on['mrr']:.2f}  vs  off {off['mrr']:.2f}")
    print(f"   Shared records naming A: on {on['stored_records_exposing_A']}  vs  "
          f"off {off['stored_records_exposing_A']} of {off['memory']['contributed_by_A']}")
    if "no_distractors" in output:
        nd = output["no_distractors"]
        print("\n   Without the 24 corpus distractors (shared memory = A's 20 only):")
        print(f"   Precision@1 {nd['precision_at_1']['value']:.0%} · Recall@5 "
              f"{nd['recall_at_5']['value']:.0%} · MRR {nd['mrr']:.2f}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Cross-organization experiment")
    parser.add_argument("--no-corpus", action="store_true",
                        help="Shared memory holds only A's contributions (no distractors)")
    parser.add_argument("--out", default=str(RESULTS_PATH),
                        help=f"Where to write the results (default {RESULTS_PATH})")
    args = parser.parse_args()

    with open(PAIRS_PATH, "r", encoding="utf-8") as handle:
        pairs = json.load(handle)["pairs"]

    init_db()
    session = SessionLocal()
    try:
        privacy, behaviour, _rows = privacy_and_behaviour(pairs)
        with_corpus = not args.no_corpus
        off = recall_experiment(session, pairs, with_corpus=with_corpus, private=False)
        on = recall_experiment(session, pairs, with_corpus=with_corpus, private=True)
        own = own_incident_check(session, pairs)
        bare = (recall_experiment(session, pairs, with_corpus=False, private=True)
                if with_corpus else None)
    finally:
        session.close()

    output = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "code_revision": git_revision(),
        "dataset": str(PAIRS_PATH.relative_to(PROJECT_ROOT)),
        "pairs": len(pairs),
        "mode": "offline (rule-based extraction, no LLM)",
        "privacy_protection": privacy,
        "behaviour_preservation": behaviour,
        "cross_org_recall": on,
        "own_incident_recognised": own,
        "privacy_utility": {
            "with_privacy_layer": {k: on[k] for k in ("precision_at_1", "recall_at_5", "mrr",
                                                      "queries_exposing_A",
                                                      "stored_records_exposing_A")},
            "without_privacy_layer": {k: off[k] for k in ("precision_at_1", "recall_at_5",
                                                          "mrr", "queries_exposing_A",
                                                          "stored_records_exposing_A",
                                                          "queries", "memory")},
        },
        **({"no_distractors": {k: bare[k] for k in ("precision_at_1", "recall_at_5", "mrr",
                                                     "memory")}} if bare else {}),
        "caveats": [
            "The 40 reports are synthetic, written for this experiment after the rules were "
            "frozen; labels were fixed before the first run and written by the project team, "
            "not by independent analysts.",
            "Twenty queries is a small sample; read every rate with its 95% interval.",
            "Retrieval scores depend on the memory backend (MiniLM with ChromaDB, or the "
            "offline TF-IDF fallback); the backend used is recorded with the results.",
            "Removing identifiers is not full anonymity: details such as timing, sector and "
            "scale can still point to an organization.",
        ],
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, ensure_ascii=False, default=list)
    print_report(output)
    print(f"Results written to {out.relative_to(PROJECT_ROOT) if out.is_absolute() and PROJECT_ROOT in out.parents else out}")


if __name__ == "__main__":
    main()
