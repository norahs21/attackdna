"""Privacy Layer — the Privacy Shield in the ATTACKDNA pipeline.

Turns a raw incident report into a *sanitized* incident that carries the
attack's behaviour but none of the victim's identity.

Design rules that make this defensible in front of judges:

1. **Deterministic first.** Identifier removal is done with regular
   expressions, not an LLM. A regex cannot "decide" to leak an IP address.
2. **Fail closed.** An optional LLM pass may only *add* redactions
   (names, organisations it recognises). It can never un-redact anything.
3. **Analytically lossless.** Redaction is consistent: the same email
   always maps to the same token, so "one attacker mailbox" and "three
   attacker mailboxes" remain distinguishable after sanitization.
4. **Preserve the DNA.** CVE identifiers, ATT&CK technique IDs and file
   hashes are *not* PII — they are the attack's fingerprint — so they are
   explicitly protected from redaction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Tuple

# --------------------------------------------------------------------------
# Patterns that must SURVIVE sanitization: they describe the attack, not the
# victim. They are swapped for sentinels before redaction and restored after.
# --------------------------------------------------------------------------
PRESERVE_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    ("CVE", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    ("TECHNIQUE", re.compile(r"\bT\d{4}(?:\.\d{3})?\b")),
    ("HASH", re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)),
]

# --------------------------------------------------------------------------
# Redaction patterns, applied in this exact order. Order matters: a URL must
# be caught before the bare-domain rule, an email before the username rule.
# --------------------------------------------------------------------------
REDACTION_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    # Credentials & secrets first — highest blast radius if leaked.
    ("SECRET", re.compile(
        r"\b(?:AKIA[0-9A-Z]{16}"                      # AWS access key id
        r"|sk-[A-Za-z0-9_\-]{20,}"                    # generic API secret
        r"|gh[pousr]_[A-Za-z0-9]{20,}"                # GitHub tokens
        r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"  # JWT
    )),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("URL", re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.I)),
    # Defanged URLs, e.g. hxxp://evil[.]com/path
    ("URL", re.compile(r"\bhxxps?(?::|\[:\])//[^\s<>\"')\]]+", re.I)),
    ("IP", re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(?:\.|\[\.\])){3}"                          # supports defanged 10[.]0[.]0[.]1
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(?:/\d{1,2})?\b"                            # optional CIDR
    )),
    ("IP", re.compile(r"\b(?:[A-F0-9]{1,4}:){5}[A-F0-9:]{2,}\b", re.I)),  # IPv6
    ("MAC", re.compile(r"\b(?:[0-9A-F]{2}[:\-]){5}[0-9A-F]{2}\b", re.I)),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[ \-]?){3}\d{3,4}\b")),
    ("NATIONAL_ID", re.compile(r"\b[12]\d{9}\b")),                 # Saudi national/iqama ID
    ("PHONE", re.compile(r"(?:\+\d{1,3}[ \-]?)?(?:\(?0\)?)?\d{2,4}[ \-]?\d{3}[ \-]?\d{4}\b")),
    # Windows user profile paths leak the account name.
    ("USER_PATH", re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+", re.I)),
    ("USER_PATH", re.compile(r"/(?:home|Users)/[A-Za-z0-9._\-]+", re.I)),
    ("ACCOUNT", re.compile(r"\b[A-Za-z0-9\-]{2,30}\\[A-Za-z0-9._\-]{2,30}\b")),  # DOMAIN\user
    # Asset names such as WKSTN-FIN-042, SRV-DC01, LAP-HR-7.
    ("HOSTNAME", re.compile(r"\b[A-Z]{2,}(?:-[A-Z0-9]{1,10}){1,3}\b")),
    ("DOMAIN", re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.|\[\.\]))+"
        r"(?:com|net|org|sa|gov|edu|io|co|ru|cn|info|biz|xyz|top|onion)\b", re.I
    )),
    # Person names introduced by a title or role keyword. NAME_PART allows
    # hyphenated and apostrophed forms so "Ahmed Al-Rashid" and "O'Brien" are
    # removed whole rather than leaving a recognisable fragment behind.
    ("PERSON", re.compile(
        r"\b(?:Mr|Mrs|Ms|Dr|Eng|Engineer|Analyst|Manager|Director|Officer|CISO|CTO|CEO)\.?\s+"
        r"((?:[A-Z][a-z]+(?:[-'][A-Z][a-z]+)*)(?:\s+[A-Z][a-z]+(?:[-'][A-Z][a-z]+)*){0,2})"
    )),
    ("PERSON", re.compile(
        r"\b(?:employee|user|staff member|victim|attacker|contractor|reported by|assigned to)\s+"
        r"((?:[A-Z][a-z]+(?:[-'][A-Z][a-z]+)*)(?:\s+[A-Z][a-z]+(?:[-'][A-Z][a-z]+)*){0,2})\b"
    )),
    # Organisation names introduced by a legal suffix.
    ("ORG", re.compile(
        r"\b([A-Z][A-Za-z0-9&\.\-]*(?:\s+[A-Z][A-Za-z0-9&\.\-]*){0,3})\s+"
        r"(?:Inc|LLC|Ltd|Limited|Corp|Corporation|Company|Co\.|GmbH|PLC|LLP|Bank|Group|Holdings)\b"
    )),
]

# Words that look like hostnames but are standard security vocabulary. Without
# this list "MFA", "EDR-XDR" style tokens would be redacted as asset names and
# the sanitized report would become unreadable.
HOSTNAME_ALLOWLIST = {
    "MITRE", "ATT", "CK", "ATT-CK", "CISA", "KEV", "NIST", "ISO", "SOC", "SIEM",
    "EDR", "XDR", "MDR", "NDR", "DLP", "MFA", "SSO", "VPN", "RDP", "SMB", "DNS",
    "DHCP", "LDAP", "SAML", "OAUTH", "API", "URL", "URI", "PII", "IOC", "IOA",
    "TTP", "APT", "C2", "TLS", "SSL", "HTTP", "HTTPS", "FTP", "SSH", "WAF",
    "IDS", "IPS", "AV", "UEBA", "SOAR", "CVE", "CVSS", "NVD", "OWASP", "PDF",
    "EXE", "DLL", "PS1", "VBA", "LOLBIN", "AD", "DC", "GPO", "PAM", "IAM",
    "T1486", "T1059", "T1027", "US-CERT", "SANS", "FBI", "NSA", "GDPR", "PDPL",
    "SLA", "RTO", "RPO", "IT", "OT", "ICS", "SCADA", "IOT", "SMS", "OTP",
    "CSV", "JSON", "XML", "SQL", "CPU", "RAM", "USB", "LAN", "WAN", "NAC",
}


@dataclass
class SanitizationResult:
    """Outcome of the Privacy Shield."""

    sanitized_text: str
    entity_map: Dict[str, str] = field(default_factory=dict)
    """token -> original value. Stays server-side; never embedded or shared."""
    counts: Dict[str, int] = field(default_factory=dict)
    """entity type -> number of distinct values removed."""

    @property
    def total_redactions(self) -> int:
        return len(self.entity_map)

    def audit_rows(self) -> List[Dict[str, str]]:
        """Rows for the UI's 'what was removed' panel (values masked)."""
        rows = []
        for token, original in self.entity_map.items():
            rows.append({
                "token": token,
                "type": token.strip("[]").rsplit("_REDACTED", 1)[0],
                "original_preview": _mask(original),
            })
        return rows


def _mask(value: str) -> str:
    """Show just enough of a removed value to prove it was really there."""
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def _is_allowlisted_hostname(value: str) -> bool:
    parts = value.replace("-", " ").split()
    return all(p.upper() in HOSTNAME_ALLOWLIST for p in parts) or value.upper() in HOSTNAME_ALLOWLIST


def sanitize(text: str) -> SanitizationResult:
    """Redact identifying information from an incident report.

    Returns the sanitized text plus a reversible map kept server-side.
    """
    if not text:
        return SanitizationResult(sanitized_text="")

    working = text
    # ---- Phase 1: protect the attack fingerprint from redaction ----
    preserved: Dict[str, str] = {}
    for label, pattern in PRESERVE_PATTERNS:
        def _protect(match: re.Match, _label=label) -> str:
            sentinel = f"\x00{_label}{len(preserved)}\x00"
            preserved[sentinel] = match.group(0)
            return sentinel

        working = pattern.sub(_protect, working)

    # ---- Phase 2: redact, assigning one stable token per distinct value ----
    # value -> token, and type -> ordered distinct values
    assigned: Dict[Tuple[str, str], str] = {}
    per_type: Dict[str, List[str]] = {}
    entity_map: Dict[str, str] = {}

    for label, pattern in REDACTION_PATTERNS:
        def _redact(match: re.Match, _label=label) -> str:
            # Patterns with a capture group redact only the captured name,
            # keeping the introducing keyword ("employee", "Dr.") readable.
            original = match.group(1) if match.groups() else match.group(0)
            if _label == "HOSTNAME" and _is_allowlisted_hostname(original):
                return match.group(0)

            key = (_label, original)
            if key not in assigned:
                per_type.setdefault(_label, []).append(original)
                # Placeholder index; final token names are resolved in phase 3.
                assigned[key] = f"\x01{_label}:{len(per_type[_label]) - 1}\x01"
            token = assigned[key]
            return match.group(0).replace(original, token) if match.groups() else token

        working = pattern.sub(_redact, working)

    # ---- Phase 3: name the tokens ----
    # A single value of a type gets the clean form [IP_REDACTED]; multiple
    # distinct values get [IP_REDACTED_1], [IP_REDACTED_2], ... so that the
    # report still shows how many distinct assets or accounts were involved.
    for label, values in per_type.items():
        for index, original in enumerate(values):
            if len(values) == 1:
                token = f"[{label}_REDACTED]"
            else:
                token = f"[{label}_REDACTED_{index + 1}]"
            working = working.replace(f"\x01{label}:{index}\x01", token)
            entity_map[token] = original

    # ---- Phase 4: restore the preserved attack fingerprint ----
    for sentinel, original in preserved.items():
        working = working.replace(sentinel, original)

    counts = {label: len(values) for label, values in per_type.items()}
    return SanitizationResult(sanitized_text=working, entity_map=entity_map, counts=counts)


def verify_clean(sanitized_text: str) -> List[str]:
    """Second-pass assurance check.

    Re-runs the highest-risk detectors over already-sanitized text and returns
    any leaks found. Used by tests and shown in the UI as a green check, so the
    claim "nothing identifying left the building" is demonstrated, not asserted.
    """
    leaks: List[str] = []
    high_risk = {"EMAIL", "IP", "SECRET", "IBAN", "CREDIT_CARD", "NATIONAL_ID", "MAC"}
    protected = {m.group(0) for _, p in PRESERVE_PATTERNS for m in p.finditer(sanitized_text)}

    for label, pattern in REDACTION_PATTERNS:
        if label not in high_risk:
            continue
        for match in pattern.finditer(sanitized_text):
            value = match.group(0)
            if value in protected or value.startswith("["):
                continue
            leaks.append(f"{label}: {value}")
    return leaks
