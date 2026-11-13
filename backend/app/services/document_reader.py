"""Turn an attached incident report into plain text.

Security teams write incident reports in Word or export them to PDF; a demo
that only accepts .txt asks them to copy and paste first, which is the step
where a report gets pasted somewhere it should not be.

Nothing here keeps the file. The bytes are read in memory, the text goes to
the privacy layer, and the original is dropped with the request.
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from typing import List

SUPPORTED_EXTENSIONS = ["txt", "md", "log", "pdf", "docx"]


class UnreadableReport(ValueError):
    """The file was attached but no text could be taken from it."""


@dataclass
class ReadReport:
    text: str
    kind: str
    pages: int = 0


def read_report(filename: str, data: bytes) -> ReadReport:
    """Extract the text of one attached report."""
    extension = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    if extension == "pdf":
        return _read_pdf(data)
    if extension == "docx":
        return _read_docx(data)
    if extension in {"txt", "md", "log", ""}:
        return ReadReport(text=_decode(data), kind="text")
    raise UnreadableReport(
        f"'.{extension}' files are not supported. Attach a "
        + ", ".join(f".{e}" for e in SUPPORTED_EXTENSIONS) + " file."
    )


def _decode(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _read_pdf(data: bytes) -> ReadReport:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - dependency listed in requirements
        raise UnreadableReport("PDF support needs the 'pypdf' package: pip install pypdf") from exc
    try:
        reader = PdfReader(io.BytesIO(data))
        pages: List[str] = [(page.extract_text() or "") for page in reader.pages]
    except Exception as exc:  # noqa: BLE001 - pypdf raises many types for bad files
        raise UnreadableReport(f"The PDF could not be read: {exc}") from exc
    text = "\n".join(p.strip() for p in pages if p.strip())
    if not text.strip():
        raise UnreadableReport(
            "The PDF has no text layer (it is probably a scan). Export the report "
            "as text, or attach the original Word document."
        )
    return ReadReport(text=text, kind="pdf", pages=len(pages))


def _read_docx(data: bytes) -> ReadReport:
    try:
        import docx
    except ImportError as exc:  # pragma: no cover - dependency listed in requirements
        raise UnreadableReport(
            "Word support needs the 'python-docx' package: pip install python-docx") from exc
    try:
        document = docx.Document(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        raise UnreadableReport(f"The Word document could not be read: {exc}") from exc
    parts = [p.text for p in document.paragraphs if p.text.strip()]
    # Incident templates keep half their content in tables: affected hosts,
    # timelines, contacts. Those are exactly the identifiers that must be seen.
    for table in document.tables:
        for row in table.rows:
            cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
            if cells:
                parts.append(" | ".join(dict.fromkeys(cells)))
    text = "\n".join(parts)
    if not text.strip():
        raise UnreadableReport("The Word document contains no text.")
    return ReadReport(text=text, kind="docx")
