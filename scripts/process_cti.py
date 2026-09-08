"""Process the CTI layers of the MITRE ATT&CK STIX bundle.

`process_mitre.py` extracts techniques. This script extracts everything else
ATTACKDNA needs from the same bundle:

  * **Mitigations** (`course-of-action`) — ATT&CK's own recommended defences,
    linked to the techniques they mitigate via `mitigates` relationships.
  * **Threat groups** (`intrusion-set`) — the TTP set of each known actor,
    which lets an incident's Attack DNA be compared against known adversaries.
  * **Software** (`malware` / `tool`) — the TTP set of each known toolkit.
  * **Campaigns** — named operations, attributed to groups where known.

Output: data/processed/{mitigations,groups,software,campaigns}.json

Run after scripts/download_mitre.py:

    python scripts/download_mitre.py
    python scripts/process_mitre.py
    python scripts/process_cti.py
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Dict, List, Optional

RAW_PATH = "data/raw/mitre_attack.json"
OUT_DIR = "data/processed"

# ATT&CK ids by object family. Mitigations use M####; the bundle still carries
# legacy per-technique "... Mitigation" objects keyed T#### which ATT&CK has
# retired, so those are skipped.
MITIGATION_PREFIX = "M"
GROUP_PREFIX = "G"
SOFTWARE_PREFIXES = ("S",)
CAMPAIGN_PREFIX = "C"


def attack_id(obj: dict) -> Optional[str]:
    """The ATT&CK external id (T1486, M1049, G0082, S0002...) of a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def clip(text: str, limit: int = 600) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit].rstrip() + "..."


def main() -> None:
    with open(RAW_PATH, "r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    objects = bundle["objects"]

    # ---- Index every object by its STIX id so relationships can be resolved ----
    by_stix_id: Dict[str, dict] = {obj["id"]: obj for obj in objects}

    # ---- Walk relationships once, bucketing what we need ----
    # technique STIX id -> [mitigation STIX ids]
    mitigates: Dict[str, List[str]] = defaultdict(list)
    # actor/software STIX id -> [technique STIX ids]
    uses: Dict[str, List[str]] = defaultdict(list)
    # campaign STIX id -> group STIX id
    attributed: Dict[str, str] = {}

    for obj in objects:
        if obj.get("type") != "relationship" or not is_active(obj):
            continue
        source, target = obj.get("source_ref", ""), obj.get("target_ref", "")
        kind = obj.get("relationship_type")

        if kind == "mitigates" and target.startswith("attack-pattern--"):
            mitigates[target].append(source)
        elif kind == "uses" and target.startswith("attack-pattern--"):
            uses[source].append(target)
        elif kind == "attributed-to":
            attributed[source] = target

    def technique_ids(stix_ids: List[str]) -> List[str]:
        """Resolve STIX ids to ATT&CK technique ids, de-duplicated and sorted."""
        resolved = set()
        for stix_id in stix_ids:
            obj = by_stix_id.get(stix_id)
            if obj and is_active(obj):
                identifier = attack_id(obj)
                if identifier:
                    resolved.add(identifier)
        return sorted(resolved)

    # ---- Mitigations: M#### -> the techniques it defends against ----
    # Invert `mitigates` so each mitigation lists its techniques.
    mitigation_to_techniques: Dict[str, List[str]] = defaultdict(list)
    for technique_stix, mitigation_stix_ids in mitigates.items():
        technique = by_stix_id.get(technique_stix)
        if not technique or not is_active(technique):
            continue
        technique_id = attack_id(technique)
        if not technique_id:
            continue
        for mitigation_stix in mitigation_stix_ids:
            mitigation_to_techniques[mitigation_stix].append(technique_id)

    mitigations = {}
    for obj in objects:
        if obj.get("type") != "course-of-action" or not is_active(obj):
            continue
        identifier = attack_id(obj)
        if not identifier or not identifier.startswith(MITIGATION_PREFIX):
            continue  # skip retired per-technique "Mitigation" objects
        mitigations[identifier] = {
            "id": identifier,
            "name": obj.get("name"),
            "description": clip(obj.get("description", "")),
            "techniques": sorted(set(mitigation_to_techniques.get(obj["id"], []))),
        }

    # ---- Threat groups ----
    groups = []
    for obj in objects:
        if obj.get("type") != "intrusion-set" or not is_active(obj):
            continue
        identifier = attack_id(obj)
        if not identifier or not identifier.startswith(GROUP_PREFIX):
            continue
        techniques = technique_ids(uses.get(obj["id"], []))
        if not techniques:
            continue  # a group with no known TTPs cannot be matched against
        groups.append({
            "id": identifier,
            "name": obj.get("name"),
            "aliases": obj.get("aliases", []),
            "description": clip(obj.get("description", ""), 400),
            "techniques": techniques,
        })

    # ---- Software (malware and tools) ----
    software = []
    for obj in objects:
        if obj.get("type") not in ("malware", "tool") or not is_active(obj):
            continue
        identifier = attack_id(obj)
        if not identifier or not identifier.startswith(SOFTWARE_PREFIXES):
            continue
        techniques = technique_ids(uses.get(obj["id"], []))
        if not techniques:
            continue
        software.append({
            "id": identifier,
            "name": obj.get("name"),
            "type": obj["type"],
            "description": clip(obj.get("description", ""), 300),
            "techniques": techniques,
        })

    # ---- Campaigns ----
    campaigns = []
    for obj in objects:
        if obj.get("type") != "campaign" or not is_active(obj):
            continue
        identifier = attack_id(obj)
        if not identifier or not identifier.startswith(CAMPAIGN_PREFIX):
            continue
        actor = by_stix_id.get(attributed.get(obj["id"], ""))
        campaigns.append({
            "id": identifier,
            "name": obj.get("name"),
            "description": clip(obj.get("description", ""), 300),
            "first_seen": obj.get("first_seen"),
            "last_seen": obj.get("last_seen"),
            "attributed_to": attack_id(actor) if actor else None,
            "attributed_to_name": actor.get("name") if actor else None,
            "techniques": technique_ids(uses.get(obj["id"], [])),
        })

    os.makedirs(OUT_DIR, exist_ok=True)
    outputs = {
        "mitigations.json": mitigations,
        "groups.json": groups,
        "software.json": software,
        "campaigns.json": campaigns,
    }
    for filename, payload in outputs.items():
        with open(os.path.join(OUT_DIR, filename), "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        count = len(payload)
        print(f"Processed {count:>5} → {OUT_DIR}/{filename}")

    linked = sum(1 for m in mitigations.values() if m["techniques"])
    print(f"\n{linked}/{len(mitigations)} mitigations are linked to at least one technique.")


if __name__ == "__main__":
    main()
