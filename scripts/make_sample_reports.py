"""Write the sample incident reports a team can attach in the interface.

    python scripts/make_sample_reports.py      # writes sample_reports/

Every organisation, person, address and host in these reports is fabricated.
They come from two places:

  * the cross-organisation pairs (data/seed/crossorg_pairs.json): the same
    attack reported by organisation A and later by organisation B, so a team
    can add A's report to memory and then analyse B's and see A recalled;
  * the prepared scenarios (data/seed/demo_scenarios.json).

Some are written as Word and PDF files, so those upload paths get exercised too.
PDF output needs reportlab (`pip install reportlab`); it is not a runtime
dependency, because the PDFs are committed.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT = PROJECT_ROOT / "sample_reports"
PAIRS = PROJECT_ROOT / "data" / "seed" / "crossorg_pairs.json"
SCENARIOS = PROJECT_ROOT / "data" / "seed" / "demo_scenarios.json"

# (file stem, pair id, side, format)
FROM_PAIRS = [
    ("01_A_hospital_ransomware_via_phishing", "p01", "a", "txt"),
    ("02_B_logistics_ransomware_via_phishing", "p01", "b", "txt"),
    ("03_A_university_ransomware_via_vpn", "p02", "a", "docx"),
    ("04_B_manufacturer_ransomware_via_vpn", "p02", "b", "pdf"),
    ("05_A_contractor_invoice_fraud", "p03", "a", "txt"),
    ("06_B_municipality_invoice_fraud", "p03", "b", "docx"),
    ("07_A_power_company_exchange_webshell", "p08", "a", "pdf"),
    ("08_B_engineering_firm_exchange_webshell", "p08", "b", "txt"),
    ("09_A_bank_trojanised_vendor_update", "p09", "a", "txt"),
    ("10_B_agency_trojanised_vendor_update", "p09", "b", "txt"),
]
FROM_SCENARIOS = {
    "financial_services": "11_bank_ransomware_scenario",
    "healthcare": "12_healthcare_supply_chain_scenario",
    "vulnerability": "13_vulnerability_exploitation_scenario",
    "near_miss": "14_near_miss_scenario",
}


def title_for(stem: str) -> str:
    words = stem.split("_")[1:]
    if words and words[0] in {"A", "B"}:
        words = words[1:]
    return "Incident report: " + " ".join(words)


def write_txt(path: Path, title: str, text: str) -> None:
    body = "\n".join(textwrap.fill(p, 90) for p in text.split("\n"))
    path.write_text(f"{title}\n{'=' * len(title)}\n\n{body}\n", encoding="utf-8")


def write_docx(path: Path, title: str, text: str) -> None:
    import docx

    document = docx.Document()
    document.add_heading(title, level=1)
    for paragraph in text.split("\n"):
        if paragraph.strip():
            document.add_paragraph(paragraph)
    document.save(path)


def write_pdf(path: Path, title: str, text: str) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    styles = getSampleStyleSheet()
    story = [Paragraph(title, styles["Heading1"]), Spacer(1, 8)]
    for paragraph in text.split("\n"):
        if paragraph.strip():
            safe = paragraph.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story += [Paragraph(safe, styles["BodyText"]), Spacer(1, 6)]
    SimpleDocTemplate(str(path), pagesize=A4, title=title).build(story)


WRITERS = {"txt": write_txt, "docx": write_docx, "pdf": write_pdf}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    pairs = {p["id"]: p for p in json.loads(PAIRS.read_text(encoding="utf-8"))["pairs"]}
    written = []
    for stem, pair_id, side, fmt in FROM_PAIRS:
        report = pairs[pair_id][side]
        path = OUT / f"{stem}.{fmt}"
        WRITERS[fmt](path, title_for(stem), report["text"])
        written.append(path)

    scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))["scenarios"]
    for scenario in scenarios:
        stem = FROM_SCENARIOS.get(scenario["id"])
        if stem:
            path = OUT / f"{stem}.txt"
            write_txt(path, title_for(stem), scenario["text"])
            written.append(path)

    for path in written:
        print(f"  {path.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
