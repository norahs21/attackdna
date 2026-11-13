"""Privacy Layer — the Privacy Shield in the ATTACKDNA pipeline.

Turns a raw incident report into a *sanitized* incident that carries the
attack's behaviour but none of the victim's identity.

Design rules that make this defensible in front of judges:

1. **Deterministic.** Identifier removal is done with patterns and word
   lists, not a language model. A rule cannot "decide" to leak an IP address,
   and the same report always produces the same output.
2. **Fail closed.** Where the layer cannot tell a name from a word, it removes
   it: a capitalised token that public security vocabulary does not know is
   treated as a name, and text in a script the layer cannot read is withheld
   whole. An unfamiliar product is lost; an unfamiliar person is not leaked.
3. **Analytically lossless.** Redaction is consistent: the same email
   always maps to the same token, so "one attacker mailbox" and "three
   attacker mailboxes" remain distinguishable after sanitization.
4. **Preserve the DNA.** CVE identifiers, ATT&CK technique IDs, file hashes
   and registry keys are *not* PII — they are the attack's fingerprint — so
   they are explicitly protected from redaction.

Two kinds of identifier are handled by two mechanisms:

* identifiers with a *shape* — addresses, mailboxes, host names, accounts —
  by the regular expressions in this module;
* identifiers without one — people, organisations, places — by
  `name_detector`, which reads capitalisation against the vocabularies in
  `lexicon`.

What this layer does not claim: it is not a guarantee that free text is
anonymous. Quasi-identifiers (dates, sizes, a rare sector) can still narrow
down a victim. The guarantee the system rests on is structural and lives one
stage later — the Attack DNA is built from closed vocabularies, so nothing
from the report's prose can enter the record that is embedded and shared.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Pattern, Tuple

from app.services import lexicon
from app.services.name_detector import find_names

# --------------------------------------------------------------------------
# Patterns that must SURVIVE sanitization: they describe the attack, not the
# victim. They are swapped for sentinels before redaction and restored after.
# --------------------------------------------------------------------------
PRESERVE_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    # Tokens this layer wrote itself, so sanitizing a sanitized text is a no-op.
    ("TOKEN", re.compile(r"\[[A-Z_]+_REDACTED(?:_\d+)?\]")),
    ("CVE", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    ("TECHNIQUE", re.compile(r"\bT\d{4}(?:\.\d{3})?\b")),
    ("HASH", re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)),
    # Registry persistence locations are attacker artefacts and a shareable
    # indicator; the key names inside them are not anyone's name.
    ("REGISTRY", re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[\w\\\-]+", re.I)),
]

# Text in a script the layer cannot read. There is no capitalisation to mark a
# name in Arabic, and no word list behind it here, so nothing in it can be
# checked — and what cannot be checked is not passed on.
_NON_LATIN_LETTER = r"(?:(?![A-Za-zÀ-ɏ])[^\W\d_])"
NON_LATIN_RE = re.compile(
    rf"{_NON_LATIN_LETTER}+(?:[\s،؛؟.,:;!?()\-–—\"'«»/٠-٩]*{_NON_LATIN_LETTER}+)*"
)

# --------------------------------------------------------------------------
# Redaction patterns, applied in this exact order. Order matters: a URL must
# be caught before the bare-domain rule, an email before the username rule.
# --------------------------------------------------------------------------
# One component of a personal name. The apostrophe and hyphen forms need a
# first segment that may be a single letter — O'Brien, D'Souza — which
# [A-Z][a-z]+ cannot match, so those names were only half-redacted.
_NAME_PART = r"(?:[A-Z][a-z]*(?:[-'][A-Z][a-z]+)+|[A-Z][a-z]+)"

# What kind of body something is. Kept readable — the sector classifier reads
# "Bank" and "Hospital" — while the name in front of it is removed.
_ORG_SUFFIX = (
    r"(?:Inc|LLC|Ltd|Limited|Corp|Corporation|Company|Co\.|GmbH|PLC|LLP|Bank|Group|Holdings"
    r"|Centre|Center|Hospital|Clinic|Authority|Ministry|University|College"
    r"|Institute|Agency|Foundation|Association|Council|Commission|Trust)"
)
_ORG_HEAD = (
    r"(?:Ministry|University|Bank|Authority|College|Institute|Agency|Council|Commission"
    r"|Department|Hospital|Municipality|Government|City|State|Province|Republic|Kingdom"
    r"|Embassy|Chamber|Society|Organisation|Organization|Association|Foundation|Office)"
)

# What may follow a machine name. A dot that continues into more name
# ("web01.corp") means the domain rule owns it; a dot that ends the sentence
# does not — and treating the two alike left "... and then to backup02."
# unredacted, which the held-out privacy audit caught.
_NOT_INSIDE_A_NAME = r"(?![\w\-@]|\.[A-Za-z0-9])"

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
    # Compressed IPv6 (2001:db8::1). The double colon is what separates it
    # from a time of day, which the full form above cannot be confused with.
    ("IP", re.compile(
        r"(?<![\w:.])(?:[A-F0-9]{1,4}:){1,7}(?::[A-F0-9]{1,4}){1,7}(?![\w:])", re.I)),
    ("MAC", re.compile(r"\b(?:[0-9A-F]{2}[:\-]){5}[0-9A-F]{2}\b", re.I)),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[ \-]?){3}\d{3,4}\b")),
    ("NATIONAL_ID", re.compile(r"\b[12]\d{9}\b")),                 # Saudi national/iqama ID
    ("PHONE", re.compile(r"(?:\+\d{1,3}[ \-]?)?(?:\(?0\)?)?\d{2,4}[ \-]?\d{3}[ \-]?\d{4}\b")),
    # Windows user profile paths leak the account name.
    ("USER_PATH", re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+", re.I)),
    ("USER_PATH", re.compile(r"/(?:home|Users)/[A-Za-z0-9._\-]+", re.I)),
    ("ACCOUNT", re.compile(r"\b[A-Za-z0-9\-]{2,30}\\[A-Za-z0-9._\-]{2,30}\b")),  # DOMAIN\user
    # Ticket and case numbers: internal, and unique to the organisation.
    ("REFERENCE", re.compile(
        r"\b(?:IR|INC|INCIDENT|CASE|TKT|TICKET|REF|SR|CHG|PRB|RITM|SEC|CR|REQ)[-_#]?\d{2,}(?:[-_/]\d+)*\b")),
    # Asset names such as WKSTN-FIN-042, SRV-DC01, LAP-HR-7.
    ("HOSTNAME", re.compile(r"\b[A-Z]{2,}(?:-[A-Z0-9]{1,10}){1,3}\b")),
    # Fully-qualified names, including the host label in front of them, so
    # "fileserver-01.corp.example" is removed whole rather than leaving the
    # host recognisable. The suffix list covers internal and reserved zones on
    # purpose: an incident report's most identifying names are the ones that
    # never appear in public DNS — .local, .corp and .internal are where an
    # Active Directory estate lives, and matching only public TLDs left every
    # internal FQDN in a report untouched.
    ("DOMAIN", re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.|\[\.\]))+"
        r"(?:com|net|org|gov|edu|mil|int|info|biz|xyz|top|onion|io|co|me|tv|app|dev|cloud|"
        r"health|bank|shop|online|site|live|"
        r"sa|ae|qa|kw|bh|om|eg|jo|lb|ma|tn|tr|"
        r"uk|de|fr|nl|se|no|fi|dk|es|it|pl|ch|at|be|ie|pt|gr|cz|ro|"
        r"ru|cn|jp|kr|in|pk|id|my|sg|au|nz|ca|mx|br|ar|za|ng|ke|"
        r"local|internal|corp|lan|intranet|home|arpa|example|test|invalid|localdomain)\b",
        re.I
    )),
    # Machine names written in lower case or without a hyphen: fin-ws-042,
    # dc01. A guard decides (see _looks_like_host) because "sha-256" and
    # "rundll32" have the same shape and are vocabulary, not machines.
    ("HOSTNAME", re.compile(
        rf"(?<![\w.\-@/\\])[A-Za-z][A-Za-z0-9]{{1,14}}(?:-[A-Za-z0-9]{{1,14}}){{1,4}}{_NOT_INSIDE_A_NAME}")),
    ("HOSTNAME", re.compile(
        rf"(?<![\w.\-@/\\])[A-Za-z]{{2,10}}\d{{2,4}}[a-z]?{_NOT_INSIDE_A_NAME}")),
    # Service accounts: svc_backup, adm-ops.
    ("ACCOUNT", re.compile(
        r"(?<![\w.\-@/\\])(?i:svc|srv|adm|admin|sa|sys|bkp|ops)[_.][A-Za-z0-9][A-Za-z0-9_.\-]{1,24}(?![\w@])")),
    # An account the sentence introduces: "the account jsmith", "logged in as jdoe".
    ("ACCOUNT", re.compile(
        r"\b(?i:service account|user account|admin account|administrator account|"
        r"domain account|local account|account|username|user name|user id|userid|"
        r"login name|logon name|logged in as|signed in as|logged on as)"
        r"\s+(?i:named\s+|called\s+|name\s+)?[\"'“]?([A-Za-z][A-Za-z0-9._\-]{2,30})")),
    # Person names introduced by a title or role keyword, built from NAME_PART
    # so a hyphenated or apostrophed name is removed whole. Leaving half of one
    # behind is worse than leaving it alone: "[PERSON_REDACTED] O'Brien" still
    # names the person, while looking like the layer did its job.
    #
    # The separator after the keyword has to tolerate punctuation. Incident
    # reports are written as forms — "Reported by: Layla Al-Otaibi" — and a
    # pattern that only allowed whitespace walked straight past the single most
    # common way a person is named in one.
    ("PERSON", re.compile(
        r"\b(?:Mr|Mrs|Ms|Dr|Eng|Engineer|Analyst|Manager|Director|Officer|CISO|CTO|CEO)"
        r"\.?[:,]?\s+"
        rf"({_NAME_PART}(?:\s+{_NAME_PART}){{0,2}})"
    )),
    # Only the role keyword is case-insensitive. A re.I flag on the whole
    # pattern would also fold the name part, where [A-Z][a-z]+ is doing the
    # work of "this is a proper noun" — under re.I it matches any word at all,
    # so "the attacker ran encoded PowerShell" loses "ran", and with it the
    # evidence the ATT&CK mapper reads.
    ("PERSON", re.compile(
        r"\b(?i:employee|user|staff member|victim|attacker|contractor|reported by|"
        r"escalated to|assigned to|investigated by|approved by|contacted|notified)"
        r"[:,]?\s+"
        rf"({_NAME_PART}(?:\s+{_NAME_PART}){{0,2}})\b"
    )),
    # Organisation names introduced by what kind of body they are.
    # The suffix list decides which organisations are recognisable at all, and
    # it started with commercial forms only — so "Aseer Medical Centre" was not
    # an organisation as far as this layer was concerned. Hospitals, clinics,
    # ministries, authorities and universities are exactly the bodies whose
    # incidents carry the most sensitive data, and none of them is an "Ltd".
    ("ORG", re.compile(
        rf"\b([A-Z][A-Za-z0-9&\.\-]*(?:\s+[A-Z][A-Za-z0-9&\.\-]*){{0,3}})\s+{_ORG_SUFFIX}\b"
    )),
    # The same bodies named the other way round: "Ministry of Health",
    # "University of Jeddah". The kind stays, whose it is goes.
    ("ORG", re.compile(
        rf"\b{_ORG_HEAD}\s+of\s+((?:the\s+)?[A-Z][A-Za-z0-9&\.\-]*"
        r"(?:\s+(?:and\s+|&\s+)?[A-Z][A-Za-z0-9&\.\-]*){0,3})"
    )),
]

# Form fields whose value is, by the label's own account, an identifier.
# Incident reports are written as forms; "Location: Riyadh" needs no
# capitalisation analysis to know what Riyadh is.
_FIELD_LABELS: Dict[str, str] = {
    **dict.fromkeys(
        ["organisation", "organization", "company", "client", "customer", "vendor",
         "supplier", "partner", "victim", "entity", "institution", "employer",
         "affected organisation", "affected organization", "subsidiary"], "ORG"),
    **dict.fromkeys(
        ["name", "full name", "employee", "user", "analyst", "reporter", "contact",
         "owner", "author", "prepared by", "reported by", "approved by",
         "assigned to", "escalated to", "investigated by", "reviewed by",
         "requested by", "submitted by", "handled by", "responder"], "PERSON"),
    **dict.fromkeys(
        ["location", "site", "branch", "city", "country", "region", "office",
         "facility", "plant", "address", "building"], "LOCATION"),
    **dict.fromkeys(
        ["hostname", "host", "device", "asset", "machine", "computer",
         "workstation", "server", "endpoint", "system name"], "HOSTNAME"),
    **dict.fromkeys(["account", "username", "user name", "user id", "login"], "ACCOUNT"),
    **dict.fromkeys(
        ["reference", "ref", "ticket", "case", "case id", "incident id",
         "report id", "tracking id"], "REFERENCE"),
}
FIELD_RE = re.compile(
    r"(?im)^(?P<lead>[ \t]*(?:[-*•][ \t]*)?(?P<label>"
    + "|".join(sorted((re.escape(label) for label in _FIELD_LABELS), key=len, reverse=True))
    + r")[ \t]*[:：][ \t]*)(?P<value>[^\n,;(\x00\x01\[]{2,80})"
)

# Words that look like hostnames but are standard security vocabulary. Without
# this list "MFA", "EDR-XDR" style tokens would be redacted as asset names and
# the sanitized report would become unreadable.
HOSTNAME_ALLOWLIST = set(lexicon.SECURITY_ACRONYMS)


# Phrases that end in an organisation suffix but name a function, not a body.
# Widening the suffix list to reach hospitals and ministries also reached
# "Security Operations Centre", and a report that calls its own SOC
# "[ORG_REDACTED] Centre" has been made less readable for no privacy gain.
ORG_ALLOWLIST = {
    "security operations centre", "security operations center",
    "network operations centre", "network operations center",
    "operations centre", "operations center",
    "data centre", "data center", "command centre", "command center",
    "call centre", "call center", "contact centre", "contact center",
    "service centre", "service center", "incident response centre",
}

_LEADING_ARTICLE_RE = re.compile(r"^(?:the|a|an|our|its|their|this|that)\s+", re.I)
_YEAR_RE = re.compile(r"(?:19|20)\d\d")


def _is_allowlisted_org(value: str) -> bool:
    """True for a generic function that merely ends in an org-like word.

    A leading article is dropped first: the name pattern captures up to four
    capitalised words, so "The Security Operations Centre" arrives here with
    the "The" attached and would otherwise miss the list.
    """
    cleaned = _LEADING_ARTICLE_RE.sub("", value.strip())
    return cleaned.lower() in ORG_ALLOWLIST


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


def _alpha_prefix(segment: str) -> str:
    match = re.match(r"[A-Za-z]+", segment)
    return match.group(0).lower() if match else ""


def _is_vocabulary(word: str) -> bool:
    return (word in lexicon.TECH_PREFIXES or lexicon.is_public(word)
            or lexicon.is_ordinary(word))


def _looks_like_host(value: str) -> bool:
    """Whether a letters-and-digits token names a machine.

    "fin-ws-042" and "dc01" do; "sha-256", "rundll32", "phase-1" and
    "mid-2021" have the same shape and do not. What separates them is a
    zero-padded number, which machines carry and vocabulary does not, or a
    leading part that is not a word of any kind.
    """
    if not any(c.isdigit() for c in value) or _is_allowlisted_hostname(value):
        return False
    if lexicon.is_public(value):
        return False

    segments = value.split("-")
    prefix = _alpha_prefix(segments[0])
    if len(prefix) < 2 or prefix in lexicon.TECH_PREFIXES:
        return False
    if any(_YEAR_RE.fullmatch(segment) for segment in segments):
        return False

    numbers = [re.search(r"\d+", segment).group(0) for segment in segments
               if re.search(r"\d", segment)]
    if any(len(number) >= 2 and number.startswith("0") for number in numbers):
        return True
    if not _is_vocabulary(prefix):
        return True
    return len(segments) >= 3 and segments[-1].isdigit()


def _strip_org_article(name: str) -> str:
    """"The Eastern Health" -> "Eastern Health"; "The" -> ""."""
    return _LEADING_ARTICLE_RE.sub("", name + " ").strip()


def _field_needs_redaction(value: str) -> bool:
    """A form value is kept only if it is plainly a description, not a name."""
    words = re.findall(r"[A-Za-z][A-Za-z0-9'\-]*", value)
    if not words:
        return any(c.isdigit() for c in value)
    return not all(word[0].islower() and lexicon.is_ordinary(word) for word in words)


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

    def claim(label: str, original: str) -> str:
        """The placeholder for one value; final token names come in phase 3."""
        key = (label, original)
        if key not in assigned:
            per_type.setdefault(label, []).append(original)
            assigned[key] = f"\x01{label}:{len(per_type[label]) - 1}\x01"
        return assigned[key]

    # Text the layer cannot read is withheld before anything else looks at it.
    def _withhold(match: re.Match) -> str:
        first = match.group(0)[0]
        label = "ARABIC_TEXT" if "؀" <= first <= "ࣿ" or first >= "ﭐ" else "FOREIGN_TEXT"
        return claim(label, match.group(0))

    working = NON_LATIN_RE.sub(_withhold, working)

    guards: Dict[str, Callable[[str, str], Optional[str]]] = {}
    for label, pattern in REDACTION_PATTERNS:
        def _redact(match: re.Match, _label=label) -> str:
            # Patterns with a capture group redact only the captured name,
            # keeping the introducing keyword ("employee", "Dr.") readable.
            original = match.group(1) if match.groups() else match.group(0)
            if _label == "HOSTNAME":
                if _is_allowlisted_hostname(original):
                    return match.group(0)
                # The upper-case asset pattern is trusted as it always was;
                # anything else has to look like a machine, not a term.
                upper_asset = re.fullmatch(r"[A-Z]{2,}(?:-[A-Z0-9]{1,10}){1,3}", original)
                if not upper_asset and not _looks_like_host(original):
                    return match.group(0)
            if _label == "ORG":
                if _is_allowlisted_org(match.group(0)):
                    return match.group(0)
                original = _strip_org_article(original)
                if not original or original.lower() in lexicon.FUNCTION_WORDS:
                    return match.group(0)
            if _label == "ACCOUNT" and match.groups():
                # "the account was disabled": the word after "account" is
                # usually just a word.
                if "\x00" in original or "\x01" in original or _is_vocabulary(original.lower()):
                    return match.group(0)

            token = claim(_label, original)
            return match.group(0).replace(original, token) if match.groups() else token

        working = pattern.sub(_redact, working)

    # ---- Phase 2b: form fields that say what their value is ----
    def _field(match: re.Match) -> str:
        value = match.group("value").strip()
        if not value or not _field_needs_redaction(value):
            return match.group(0)
        label = _FIELD_LABELS[match.group("label").lower()]
        trailing = match.group("value")[len(match.group("value").rstrip()):]
        return f"{match.group('lead')}{claim(label, value)}{trailing}"

    working = FIELD_RE.sub(_field, working)

    # ---- Phase 2c: names that have no shape ----
    # One value gets one token, whichever rule found it: "Target" read as an
    # organisation in one sentence is the same Target two sentences later.
    spans = find_names(working)
    rank = {"PERSON": 2, "ORG": 1, "NAME": 0}
    best: Dict[str, str] = {}
    for start, end, label in spans:
        value = working[start:end]
        if rank[label] >= rank.get(best.get(value, "NAME"), 0):
            best[value] = label
    # A short mention is the same entity as the full one: "Colonial" after
    # "Colonial Pipeline" gets the token the full name got.
    full_names = [value for value in best if " " in value]
    alias: Dict[str, str] = {}
    for value in best:
        if " " in value:
            continue
        owners = [name for name in full_names if value in name.split()]
        if len(owners) == 1:
            alias[value] = owners[0]
    # Applied back to front so earlier spans keep their positions.
    for start, end, _label in reversed(spans):
        value = alias.get(working[start:end], working[start:end])
        working = working[:start] + claim(best[value], value) + working[end:]

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
    """Self-check: run every detector again over text that is already sanitized.

    Returns whatever the second pass still finds, as "TYPE: value" strings.
    An empty list means sanitizing was complete *by this layer's own lights* —
    a replacement can expose a new match, and this is what catches it.

    It is deliberately not called independent verification. The second pass
    uses the same detectors as the first, so it cannot find a kind of
    identifier they do not know. The independent measurement is the audit in
    `scripts/evaluate.py`, which checks identifiers marked by hand.
    """
    if not sanitized_text:
        return []
    second_pass = sanitize(sanitized_text)
    return [
        f"{token.strip('[]').rsplit('_REDACTED', 1)[0]}: {original}"
        for token, original in second_pass.entity_map.items()
    ]
