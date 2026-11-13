"""Extract MITRE's procedure examples from the ATT&CK bundle.

ATT&CK does not only name techniques. For every technique it records how each
known group, malware family and tool has used it, in a sentence written by a
MITRE analyst:

    T1003.001   "Indrik Spider used Cobalt Strike to carry out credential
                 dumping using ProcDump."

There are about 17,600 of these. They are the closest thing the field has to a
labelled corpus of "this is what that technique looks like when someone writes
it down", and `example_mapper` learns technique mapping from them.

    python scripts/download_mitre.py
    python scripts/process_examples.py
"""
from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_PATH = PROJECT_ROOT / "data" / "raw" / "mitre_attack.json"
OUT_PATH = PROJECT_ROOT / "data" / "processed" / "procedure_examples.json.gz"

SOURCE_TYPES = {"malware", "tool", "intrusion-set", "campaign"}


def external_id(obj: dict) -> str:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id", "")
    return ""


def clean(description: str) -> str:
    """Strip the markup ATT&CK descriptions carry, keeping the sentence."""
    text = re.sub(r"\(Citation:[^)]*\)", "", description)
    text = re.sub(r"\[([^\]]+)\]\(https?://[^)]+\)", r"\1", text)   # [Name](url) -> Name
    text = re.sub(r"</?code>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def main() -> None:
    if not RAW_PATH.exists():
        raise SystemExit(f"Missing {RAW_PATH}. Run: python scripts/download_mitre.py")
    with open(RAW_PATH, "r", encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]

    def live(obj: dict) -> bool:
        return not obj.get("revoked") and not obj.get("x_mitre_deprecated")

    techniques = {o["id"]: external_id(o) for o in objects
                  if o["type"] == "attack-pattern" and live(o) and external_id(o)}
    sources = {o["id"]: (external_id(o), o.get("name", "")) for o in objects
               if o["type"] in SOURCE_TYPES and live(o)}

    examples = []
    for obj in objects:
        if obj["type"] != "relationship" or obj.get("relationship_type") != "uses" or not live(obj):
            continue
        technique_id = techniques.get(obj.get("target_ref"))
        source = sources.get(obj.get("source_ref"))
        text = clean(obj.get("description", ""))
        if technique_id and source and len(text.split()) >= 4:
            examples.append([technique_id, source[0], source[1], text])

    examples.sort()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_readme": ("Procedure examples from MITRE ATT&CK Enterprise: one sentence per "
                    "(actor or software, technique) pair, as written by MITRE. "
                    "Each row is [technique id, source id, source name, sentence]. "
                    "(c) The MITRE Corporation, reproduced under the ATT&CK terms of use."),
        "examples": examples,
    }
    with gzip.open(OUT_PATH, "wt", encoding="utf-8", compresslevel=9) as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))

    print(f"Processed {len(examples)} procedure examples covering "
          f"{len({e[0] for e in examples})} techniques from "
          f"{len({e[1] for e in examples})} sources → {OUT_PATH}")


if __name__ == "__main__":
    main()
