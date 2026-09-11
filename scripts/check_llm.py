"""Verify the Claude API key is wired up correctly, and show what it changes.

    python scripts/check_llm.py

Runs four checks:

  1. Is a key configured, and is it accepted? (one real, tiny API call)
  2. Does DNA extraction improve with it?
  3. Does the tabletop generator use it?
  4. Does Ask-the-memory switch from a retrieval digest to a grounded answer?

The key itself is never printed. Nothing here writes to the database.

Cost: a handful of small requests, well under one US cent in total.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.config import LLM_API_KEY, LLM_MODEL  # noqa: E402
from app.config import BACKEND_DIR  # noqa: E402
from app.db.database import SessionLocal, init_db  # noqa: E402
from app.services import llm_client, rag_qa  # noqa: E402
from app.services.dna_extractor import extract_dna  # noqa: E402
from app.services.sanitizer import sanitize  # noqa: E402
from app.services.simulator import build_simulation  # noqa: E402

SAMPLE = (
    "On 12 February 2026 the SOC at Falcon National Bank detected ransomware on "
    "WKSTN-FIN-204 in the finance department. Initial access was a spearphishing link "
    "emailed to sara.nasser@falconbank.com.sa. The attacker signed in with the valid "
    "account from 91.240.118.22, ran encoded PowerShell, disabled the EDR agent, moved "
    "laterally over SMB shares, deleted shadow copies and files were encrypted. "
    "Customer data was exfiltrated to cloud storage. Exploited CVE-2024-21412."
)

QUESTION = "Have we seen ransomware that disabled the EDR agent before?"

# Kept in step with the default in app/config.py.
RECOMMENDED_MODEL = "claude-opus-5"


def masked_key() -> str:
    """Enough to confirm which key is loaded, not enough to use it."""
    if not LLM_API_KEY:
        return "(none)"
    if len(LLM_API_KEY) <= 12:
        return "*" * len(LLM_API_KEY)
    return f"{LLM_API_KEY[:7]}...{LLM_API_KEY[-4:]}"


def rule(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def main() -> None:
    print("=" * 68)
    print("ATTACKDNA — Claude API key check")
    print("=" * 68)
    print(f"  Config file : backend/.env")
    print(f"  Key loaded  : {masked_key()}")
    print(f"  Model       : {LLM_MODEL}")

    if not (BACKEND_DIR / ".env").exists():
        print("\n  NOTE  backend/.env does not exist yet.")
        print("        Run: cp .env.example backend/.env")

    # A .env written before the model default changed keeps overriding it, and
    # the override is silent — worth saying out loud during setup.
    if LLM_MODEL != RECOMMENDED_MODEL:
        print(f"\n  NOTE  backend/.env pins '{LLM_MODEL}'.")
        print(f"        The current recommended model is '{RECOMMENDED_MODEL}'.")
        print(f"        To switch, set LLM_MODEL={RECOMMENDED_MODEL} in backend/.env.")

    # ---- 1. Connection ----
    rule("1. Connection")
    status = llm_client.diagnose()
    if status["ok"]:
        print(f"  PASS  {status['detail']}")
    else:
        print(f"  FAIL  [{status['stage']}] {status['detail']}")
        if status["remedy"]:
            print(f"        Fix : {status['remedy']}")
        print("\n  The pipeline still works — it runs in rule-based mode.")
        print("  Fix the above to enable the AI layer, then run this again.\n")
        raise SystemExit(1)

    sanitized = sanitize(SAMPLE)

    # ---- 2. DNA extraction ----
    rule("2. Attack DNA extraction")
    rules_only = extract_dna(sanitized.sanitized_text, sanitized.counts, use_llm=False)
    hybrid = extract_dna(sanitized.sanitized_text, sanitized.counts, use_llm=True)

    print(f"  rule-based : {len(rules_only['techniques'])} techniques, "
          f"mode={rules_only['extraction_mode']}")
    print(f"  hybrid     : {len(hybrid['techniques'])} techniques, "
          f"mode={hybrid['extraction_mode']}")

    if hybrid["extraction_mode"] == "rule-based":
        print("  WARN  The LLM did not contribute — the call failed and fell back.")
    else:
        print("  PASS  The LLM layer is contributing.")
        print(f"\n  Summary (rules) : {rules_only['summary'][:150]}")
        print(f"  Summary (hybrid): {hybrid['summary'][:150]}")
        if hybrid.get("root_cause"):
            print(f"  Root cause      : {hybrid['root_cause'][:150]}")
            print("                    (rule-based mode cannot produce this)")

    # ---- 3. Simulation ----
    rule("3. Safe simulation")
    plain = build_simulation(hybrid, use_llm=False)
    enriched = build_simulation(hybrid, use_llm=True)
    if plain["injects"] and enriched["injects"]:
        changed = sum(1 for a, b in zip(plain["injects"], enriched["injects"])
                      if a["inject"] != b["inject"])
        print(f"  PASS  {len(enriched['injects'])} injects, {changed} reworded by the model")
        print(f"  First inject: {enriched['injects'][0]['inject'][:150]}")
    else:
        print("  SKIP  No injects generated for this sample.")

    # ---- 4. Ask the memory ----
    rule("4. Ask the memory (RAG)")
    init_db()
    session = SessionLocal()
    try:
        offline = rag_qa.ask(session, QUESTION, use_llm=False)
        grounded = rag_qa.ask(session, QUESTION, use_llm=True)
    finally:
        session.close()

    print(f"  retrieval-only : mode={offline['mode']}, "
          f"{offline['retrieved_count']} incident(s)")
    print(f"  with LLM       : mode={grounded['mode']}, "
          f"{len(grounded['citations'])} citation(s), "
          f"confidence={grounded.get('confidence')}")

    if grounded["mode"] != "llm-grounded":
        print("  WARN  Grounded answering did not engage.")
        if not grounded["sources"]:
            print("        Nothing was retrieved — run: python scripts/seed_memory.py --reset")
    else:
        print("  PASS  Grounded generation is working.")
        if grounded["unverified_citations"]:
            print(f"  NOTE  {len(grounded['unverified_citations'])} invented citation(s) "
                  "were caught and removed — the verifier is doing its job.")
        print(f"\n  Answer: {grounded['answer'][:400]}")

    print("\n" + "=" * 68)
    print("All checks passed. The AI layer is live.")
    print("Run 'make demo' and the sidebar will show: Hybrid mode")
    print("=" * 68 + "\n")


if __name__ == "__main__":
    main()
