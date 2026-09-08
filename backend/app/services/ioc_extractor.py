"""Indicator of Compromise extraction from a sanitized incident.

There is a real tension here that the design resolves explicitly rather than
ignoring: the Privacy Layer removes IP addresses, domains and email addresses,
and those are exactly the indicators a SOC normally shares. So ATTACKDNA splits
indicators into two kinds:

**Shareable indicators** survive sanitization because they identify the
*attacker's tooling*, not the victim: file hashes, CVE ids, ransomware
extensions, protocols and ports. These are extracted with their values intact
and are safe to circulate between organisations.

**Victim-linked indicators** — IPs, domains, mailboxes, hostnames, accounts —
are removed, but their *shape* is kept: how many distinct C2 addresses, how
many mailboxes, how many hosts. That is what makes "one compromised account"
and "fourteen compromised accounts" different incidents even after redaction.

The result is an IoC profile that is shareable without being identifying.
"""
from __future__ import annotations

import re
from typing import Dict, List

# --- Shareable: these describe the attacker's tooling ---
HASH_PATTERNS = [
    ("sha256", re.compile(r"\b[a-f0-9]{64}\b", re.I)),
    ("sha1", re.compile(r"\b[a-f0-9]{40}\b", re.I)),
    ("md5", re.compile(r"\b[a-f0-9]{32}\b", re.I)),
]

# Ransomware and payload file extensions named in the report.
EXTENSION_RE = re.compile(
    r"\.(locked|encrypted|crypt|crypted|locky|wcry|wncry|ryk|conti|lockbit|akira|"
    r"basta|phobos|djvu|cerber|zepto|onion|exe|dll|ps1|vbs|js|jar|hta|lnk|iso|"
    r"img|scr|bat|cmd|msi|docm|xlsm|pptm)\b", re.I,
)

PROTOCOL_RE = re.compile(
    r"\b(smb|rdp|ssh|ftp|sftp|tftp|http|https|dns|ldap|kerberos|winrm|wmi|telnet|"
    r"smtp|imap|pop3|snmp|icmp|tls|ssl|vnc|nfs)\b", re.I,
)

PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b|\b(?:tcp|udp)[/:](\d{1,5})\b", re.I)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# Registry persistence locations are attacker artefacts, not victim identifiers.
REGISTRY_RE = re.compile(
    r"\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[\w\\\-]+", re.I,
)

# --- Victim-linked: redacted by the Privacy Layer, counted here ---
# Maps a sanitizer entity type to how it should be described in an IoC profile.
NETWORK_INDICATOR_LABELS = {
    "IP": "network addresses",
    "DOMAIN": "domains",
    "URL": "URLs",
    "EMAIL": "mailboxes",
    "HOSTNAME": "affected hosts",
    "ACCOUNT": "accounts",
    "MAC": "hardware addresses",
    "USER_PATH": "user profile paths",
    "SECRET": "credentials or keys",
}


def _find_hashes(text: str) -> List[dict]:
    """File hashes, longest form first so a SHA-256 is not also read as an MD5."""
    found: List[dict] = []
    claimed: set = set()
    for label, pattern in HASH_PATTERNS:
        for match in pattern.finditer(text or ""):
            value = match.group(0).lower()
            # A 64-char hash contains 40- and 32-char substrings; skip overlaps.
            if any(value in existing or existing in value for existing in claimed):
                continue
            claimed.add(value)
            found.append({"type": label, "value": value})
    return found


def _find_ports(text: str) -> List[int]:
    ports = set()
    for match in PORT_RE.finditer(text or ""):
        raw = match.group(1) or match.group(2)
        if raw and 0 < int(raw) <= 65535:
            ports.add(int(raw))
    return sorted(ports)


def extract_iocs(sanitized_text: str, redaction_counts: Dict[str, int] | None = None) -> dict:
    """Build the IoC profile of a sanitized incident."""
    text = sanitized_text or ""
    counts = redaction_counts or {}

    hashes = _find_hashes(text)
    cves = sorted({c.upper() for c in CVE_RE.findall(text)})
    extensions = sorted({f".{m.group(1).lower()}" for m in EXTENSION_RE.finditer(text)})
    protocols = sorted({m.group(1).upper() for m in PROTOCOL_RE.finditer(text)})
    ports = _find_ports(text)
    registry_keys = sorted({m.group(0) for m in REGISTRY_RE.finditer(text)})

    shareable = {
        "hashes": hashes,
        "cves": cves,
        "file_extensions": extensions,
        "protocols": protocols,
        "ports": ports,
        "registry_keys": registry_keys,
    }
    shareable_total = (len(hashes) + len(cves) + len(extensions)
                       + len(protocols) + len(ports) + len(registry_keys))

    # Victim-linked indicators: the values are gone, the counts remain.
    redacted = [
        {"type": entity_type, "label": NETWORK_INDICATOR_LABELS[entity_type], "distinct_count": count}
        for entity_type, count in counts.items()
        if entity_type in NETWORK_INDICATOR_LABELS and count
    ]
    redacted.sort(key=lambda item: -item["distinct_count"])

    return {
        "shareable": shareable,
        "shareable_count": shareable_total,
        "redacted_indicators": redacted,
        "redacted_count": sum(item["distinct_count"] for item in redacted),
        "note": (
            "Shareable indicators identify the attacker's tooling and survive "
            "sanitization. Victim-linked indicators (addresses, domains, mailboxes, "
            "hosts) are removed; only their distinct counts are retained."
        ),
    }


def ioc_summary_line(profile: dict) -> str:
    """A single line describing the IoC profile, for compact display."""
    parts = []
    shareable = profile["shareable"]
    if shareable["hashes"]:
        parts.append(f"{len(shareable['hashes'])} hash(es)")
    if shareable["cves"]:
        parts.append(f"{len(shareable['cves'])} CVE(s)")
    if shareable["file_extensions"]:
        parts.append(f"{len(shareable['file_extensions'])} file artefact(s)")
    if shareable["protocols"]:
        parts.append(f"protocols: {', '.join(shareable['protocols'][:4])}")
    if profile["redacted_count"]:
        parts.append(f"{profile['redacted_count']} redacted indicator(s)")
    return " · ".join(parts) or "No indicators identified"
