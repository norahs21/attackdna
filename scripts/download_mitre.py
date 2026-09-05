import requests
import json
import os

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT_PATH = "data/raw/mitre_attack.json"

def download_mitre_data():
    print("Downloading MITRE ATT&CK STIX data...")
    resp = requests.get(MITRE_URL)
    resp.raise_for_status()
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(resp.json(), f, ensure_ascii=False)
    print(f"Saved to {OUT_PATH}")

if __name__ == "__main__":
    download_mitre_data()