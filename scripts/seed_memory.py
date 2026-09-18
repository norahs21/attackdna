"""Seed ATTACKDNA's memory with historical incidents.

Run this once before the demo:

    python scripts/seed_memory.py --reset

Two corpora are loaded, and the difference matters:

  * **public** — real, publicly documented breaches (Norsk Hydro, Colonial
    Pipeline, MOVEit, NotPetya, Equifax...) compiled from public reporting,
    each carrying its source URL. These answer the obvious question about a
    memory system: where does the memory come from? They are real incidents
    with real, documented responses.
  * **synthetic** — invented incidents covering sectors and attack types the
    public set does not, so retrieval has breadth. Every organisation, person
    and identifier in them is fabricated.

Every report — public or synthetic — goes through the real Privacy Layer and
the real DNA extractor. Nothing is pre-cleaned. The seeded corpus is therefore
a demonstration that the pipeline works, not a fixture that hides it.

Note that titles are not sanitized: for an incident the victim has already
disclosed publicly, the name is public record and keeping it is what makes the
memory auditable. The report body is sanitized like everything else.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.config import DATA_DIR, SEED_INCIDENTS_PATH  # noqa: E402
from app.db.database import IncidentDB, SessionLocal, init_db  # noqa: E402
from app.pipelines.analyze import ingest  # noqa: E402
from app.services import vector_memory  # noqa: E402

PUBLIC_INCIDENTS_PATH = DATA_DIR / "seed" / "public_incidents.json"


def load_corpus(path: Path, provenance: str) -> list:
    """Read one corpus file, tagging every incident with its provenance."""
    if not path.exists():
        print(f"  (skipping {path.name} — not found)")
        return []
    with open(path, "r", encoding="utf-8") as handle:
        incidents = json.load(handle)["incidents"]
    for incident in incidents:
        incident["provenance"] = provenance
    return incidents


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ATTACKDNA memory")
    parser.add_argument("--reset", action="store_true",
                        help="Delete existing incidents and vector memory first")
    parser.add_argument("--no-llm", action="store_true",
                        help="Force the deterministic rule-based path")
    parser.add_argument("--public-only", action="store_true",
                        help="Seed only the real publicly-documented incidents")
    parser.add_argument("--synthetic-only", action="store_true",
                        help="Seed only the synthetic incidents")
    args = parser.parse_args()

    init_db()
    session = SessionLocal()

    try:
        if args.reset:
            deleted = session.query(IncidentDB).delete()
            session.commit()
            vector_memory.reset_memory()
            print(f"Reset: removed {deleted} incident(s) and cleared vector memory.\n")

        incidents = []
        if not args.synthetic_only:
            incidents += load_corpus(PUBLIC_INCIDENTS_PATH, "public")
        if not args.public_only:
            incidents += load_corpus(SEED_INCIDENTS_PATH, "synthetic")

        if not incidents:
            raise SystemExit("No incidents to seed.")

        public_count = sum(1 for i in incidents if i["provenance"] == "public")
        print(f"Seeding {len(incidents)} incident(s) "
              f"({public_count} real public, {len(incidents) - public_count} synthetic)...\n")

        for entry in incidents:
            occurred_at = None
            if entry.get("occurred_at"):
                occurred_at = datetime.strptime(entry["occurred_at"], "%Y-%m-%d")

            result = ingest(
                session,
                entry["text"],
                title=entry.get("title"),
                source="seed",
                occurred_at=occurred_at,
                mitigations=entry.get("mitigations", []),
                store_raw=False,
                use_llm=not args.no_llm,
                provenance=entry["provenance"],
                source_name=entry.get("source_name"),
                source_url=entry.get("source_url"),
                why_it_matters=entry.get("why_it_matters"),
            )
            dna = result["dna"]
            tag = "PUBLIC" if entry["provenance"] == "public" else "synth "
            print(
                f"  [{tag}] [{dna['severity']:>8}] {entry['title']}\n"
                f"             type={dna['attack_type']} vector={dna['initial_vector']} "
                f"sector={dna['sector']} techniques={len(dna['techniques'])} "
                f"redactions={result['privacy']['total_redactions']} "
                f"clean={result['privacy']['verified_clean']}"
            )

        stats = vector_memory.memory_stats()
        print(f"\nDone. Memory backend: {stats['backend']} | "
              f"incidents in memory: {stats['incidents_in_memory']} "
              f"({public_count} from real public breaches)")
    finally:
        session.close()


if __name__ == "__main__":
    main()
