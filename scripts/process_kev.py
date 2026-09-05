import json

RAW_PATH = "data/raw/cisa_kev.json"
OUT_PATH = "data/processed/kev_lookup.json"

def process_kev():
    with open(RAW_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    lookup = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        if cve_id:
            lookup[cve_id] = {
                "vendor": vuln.get("vendorProject"),
                "product": vuln.get("product"),
                "name": vuln.get("vulnerabilityName"),
                "date_added": vuln.get("dateAdded"),
                "required_action": vuln.get("requiredAction"),
            }

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(lookup, f, ensure_ascii=False, indent=2)

    print(f"Processed {len(lookup)} known-exploited CVEs → {OUT_PATH}")

if __name__ == "__main__":
    process_kev()