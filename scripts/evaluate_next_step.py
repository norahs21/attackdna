"""Can ATTACKDNA predict the attacker's next step?

The test: MITRE ATT&CK profiles ~930 threat groups, malware families, tools and
campaigns by the techniques they use. One fifth of them are held out. For each
held-out attacker the techniques are put in kill-chain order, the system is
shown the first half, and it must name the second half: three predictions,
counted correct when at least one is a technique the attacker really used at a
later stage.

The ten techniques nearly every attack uses (command and control, tool
transfer, obfuscation...) are never predicted and never counted: guessing them
is easy and tells a defender nothing.

The comparison is the obvious shortcut: always predict the most common later
techniques, whatever the attack looked like so far. Results are given
separately for threat groups and campaigns (what attackers did) and for
malware and tools (what a tool can do).

Settings were chosen on a development split of the training profiles; this
script only measures.

    make eval-next-step

Writes data/evaluation/next_step_results.json.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services import next_step  # noqa: E402

HELD_OUT_FRACTION = 5
SEED = 7
RESULTS_PATH = PROJECT_ROOT / "data" / "evaluation" / "next_step_results.json"


def split_in_half(techniques):
    """First half of an attack in kill-chain order, and what came after it."""
    ordered = sorted(techniques, key=lambda t: (next_step.first_stage(t), t))
    cut = next_step.first_stage(ordered[len(ordered) // 2 - 1])
    seen = {t for t in techniques if next_step.first_stage(t) <= cut}
    later = {t for t in techniques if next_step.first_stage(t) > cut}
    return seen, later, cut


def main() -> None:
    profiles = next_step.attack_profiles()
    if not profiles:
        raise SystemExit("No ATT&CK profiles. Run: make data")
    ids = sorted(profiles)
    random.Random(SEED).shuffle(ids)
    held_out = ids[: len(ids) // HELD_OUT_FRACTION]
    train = [profiles[i] for i in ids if i not in set(held_out)]
    model = next_step.NextStepModel(train)

    def measure(attackers):
        cases = hits = shortcut_hits = 0
        precision = 0.0
        for attacker in attackers:
            seen, later, cut = split_in_half(profiles[attacker])
            later -= model.universal
            if not seen or not later:
                continue
            cases += 1
            predicted = [p["technique_id"] for p in model.rank(seen, after_stage=cut)]
            right = len(set(predicted) & later)
            hits += right > 0
            precision += right / len(predicted) if predicted else 0.0

            options = [t for t in model.frequency if t not in seen and t not in model.universal
                       and (next_step.last_stage(t) or -1) > cut]
            shortcut = sorted(options, key=lambda t: (-model.frequency[t], t))[:next_step.PREDICTIONS]
            shortcut_hits += bool(set(shortcut) & later)
        return {"cases": cases, "found": hits, "hit_at_3": hits / cases if cases else 0.0,
                "precision_at_3": precision / cases if cases else 0.0,
                "shortcut_found": shortcut_hits,
                "shortcut_hit_at_3": shortcut_hits / cases if cases else 0.0}

    # Groups (G) and campaigns (C) describe what attackers did; software (S)
    # profiles list what a tool can do, which is a different question.
    attackers = [i for i in held_out if i[0] in "GC"]
    tools = [i for i in held_out if i[0] == "S"]
    result = {
        "held_out_profiles": len(held_out),
        "attackers": measure(attackers),
        "tools": measure(tools),
        "all": measure(held_out),
        "universal_techniques_excluded": sorted(model.universal),
    }

    print()
    print("=" * 66)
    print("PREDICTING THE ATTACKER'S NEXT STEP")
    print("=" * 66)
    print("Shown the first half of each attack (kill-chain order), the system")
    print("names three likely next steps. Profiles never used in training.")
    print()
    print(f"  {'':<32} {'ATTACKDNA':>10} {'guessing':>10}")
    for key, label in (("attackers", "Threat groups and campaigns"),
                       ("tools", "Malware and tools"), ("all", "All")):
        r = result[key]
        name = f"{label} ({r['cases']})"
        print(f"  {name:<32} {r['hit_at_3']:>10.1%} {r['shortcut_hit_at_3']:>10.1%}")
    print()
    print("  'guessing' always predicts the most common next steps.")
    print()

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
