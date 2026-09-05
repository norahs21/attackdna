import json

RAW_PATH = "data/raw/mitre_attack.json"
OUT_PATH = "data/processed/techniques.json"

def process_mitre():
    with open(RAW_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    techniques = []
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            if not technique_id:
                continue

            tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]

            techniques.append({
                "id": technique_id,
                "name": obj.get("name"),
                "description": obj.get("description", "")[:500],
                "tactics": tactics,
            })

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(techniques, f, ensure_ascii=False, indent=2)

    print(f"Processed {len(techniques)} techniques → {OUT_PATH}")

if __name__ == "__main__":
    process_mitre()