import requests
import json
import os

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT_PATH = "data/raw/cisa_kev.json"

def download_kev():
    print("Downloading CISA KEV data...")
    resp = requests.get(KEV_URL)
    resp.raise_for_status()
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(resp.json(), f, ensure_ascii=False)
    print(f"Saved to {OUT_PATH}")

if __name__ == "__main__":
    download_kev()