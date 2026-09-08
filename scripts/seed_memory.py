"""Seed ATTACKDNA's memory with historical incidents.

Run this once before the demo:

    python scripts/seed_memory.py --reset

Every seeded report goes through the real Privacy Layer and the real DNA
extractor — nothing is pre-cleaned or hand-tuned. The seeded corpus is
therefore a demonstration that the pipeline works, not a fixture that hides it.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.config import SEED_INCIDENTS_PATH  # noqa: E402
from app.db.database import IncidentDB, SessionLocal, init_db  # noqa: E402
from app.pipelines.analyze import ingest  # noqa: E402
from app.services import vector_memory  # noqa: E402


def load_seed() -> list:
    if not SEED_INCIDENTS_PATH.exists():
        raise SystemExit(f"Seed file not found: {SEED_INCIDENTS_PATH}")
    with open(SEED_INCIDENTS_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)["incidents"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ATTACKDNA memory")
    parser.add_argument("--reset", action="store_true",
                        help="Delete existing incidents and vector memory first")
    parser.add_argument("--no-llm", action="store_true",
                        help="Force the deterministic rule-based path")
    args = parser.parse_args()

    init_db()
    session = SessionLocal()

    try:
        if args.reset:
            deleted = session.query(IncidentDB).delete()
            session.commit()
            vector_memory.reset_memory()
            print(f"Reset: removed {deleted} incident(s) and cleared vector memory.")

        incidents = load_seed()
        print(f"Seeding {len(incidents)} incident(s)...\n")

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
            )
            dna = result["dna"]
            print(
                f"  [{dna['severity']:>8}] {entry['title']}\n"
                f"             type={dna['attack_type']} vector={dna['initial_vector']} "
                f"sector={dna['sector']} techniques={len(dna['techniques'])} "
                f"redactions={result['privacy']['total_redactions']} "
                f"clean={result['privacy']['verified_clean']}"
            )

        stats = vector_memory.memory_stats()
        print(f"\nDone. Memory backend: {stats['backend']} | "
              f"incidents in memory: {stats['incidents_in_memory']}")
    finally:
        session.close()


if __name__ == "__main__":
    main()
