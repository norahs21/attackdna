"""Finds the names that have no shape.

The regex patterns in `sanitizer` find what looks like an identifier. This
module finds what does not look like anything: "Aramco", "Sara", "Dammam".
The only evidence that those are names is that they are capitalised where
English does not capitalise, or that they are not words at all.

The rules, in the order they are applied to each capitalised token:

1. A known given name is a person, whatever else it might be.
2. Public security vocabulary stays: "PowerShell", "Mimikatz", "Citrix",
   "Bank". It describes the attack, or what kind of body was hit — not which.
3. At the start of a sentence English capitalises everything, so only a token
   that is not a word at all is removed there ("Sara clicked", "Aramco said").
4. Anywhere else, a capitalised token that is not public vocabulary is a
   proper noun and is removed — even if it is also a word ("Target", "Royal").

Two further passes then read the sentence rather than the token:

* A name spills into its neighbours. "Colonial" is a word and "Pipeline" is a
  sector term, but together at the start of a sentence they are a company.
* The subject of "disclosed", "paid" or "confirmed" is the victim, even when
  it is a vendor the knowledge base knows — "Cisco confirmed a breach".

Every rule errs the same way. An unfamiliar product name is lost; an
unfamiliar person is not leaked.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from app.services import lexicon

# A word, keeping the hyphen and apostrophe inside "Al-Qahtani" and "O'Brien".
_L = "A-Za-z\u00C0-\u024F"
TOKEN_RE = re.compile(rf"[{_L}][{_L}0-9]*(?:['’\-][{_L}0-9]+)*")

# Text the detector must not look inside: tokens the sanitizer has already
# written, and the fingerprint it is protecting.
PROTECTED_RE = re.compile(
    r"\x00[^\x00]*\x00|\x01[^\x01]*\x01|\[[A-Z_]+_(?:REDACTED|WITHHELD)(?:_\d+)?\]"
)

_ROMAN_RE = re.compile(r"[IVXLC]{1,6}")
_OPENERS = " \t\"'“”‘’([{«"
_SENTENCE_BREAKS = "\n\r.!?:;—–•*|/"

# What belongs to an organisation. "Cisco's network" names a victim;
# "Cisco's advisory" does not.
_OWNED_RE = re.compile(
    r"(?:network|networks|systems|servers|employees|staff|customers|data|"
    r"environment|infrastructure|domain|tenant|offices|subsidiary|soc|security|"
    r"internal|corporate|production|backups?|email|payment|website|portal|"
    r"operations|plants?|branches|stores|users)\b", re.I,
)
_VICTIM_LEAD_RE = re.compile(
    r"(?:breach|attack|intrusion|incident|compromise|outage|hack|employees?|"
    r"staff|customers?|soc|team|engineers?|analysts?)\s+"
    r"(?:at|of|on|against|for|from|belonging\s+to)\s+(?:the\s+)?$", re.I,
)


@dataclass
class _Token:
    start: int
    end: int
    text: str
    initial: bool = False       # opens a sentence, a bullet or a heading
    redact: Optional[str] = None  # label to redact under, if any
    in_public_name: bool = False  # part of "Cobalt Strike", "Exchange Server"

    @property
    def lower(self) -> str:
        return self.text.lower()

    @property
    def capitalised(self) -> bool:
        return self.text[0].isupper()

    @property
    def all_caps(self) -> bool:
        letters = [c for c in self.text if c.isalpha()]
        return len(letters) >= 2 and all(c.isupper() for c in letters)


def _starts_sentence(text: str, start: int) -> bool:
    """Whether the token at `start` is where English would capitalise anyway."""
    index = start - 1
    while index >= 0 and text[index] in _OPENERS:
        index -= 1
    if index < 0:
        return True
    char = text[index]
    if char in _SENTENCE_BREAKS:
        return True
    if char == "-":
        # A bullet: the dash is the first thing on its line.
        back = index - 1
        while back >= 0 and text[back] in " \t":
            back -= 1
        return back < 0 or text[back] in "\n\r"
    return False


def _heading_lines(text: str) -> List[Tuple[int, int]]:
    """Spans of lines written as headings — "Response Actions Taken".

    Every word of a heading is capitalised, so capitalisation says nothing
    there; its words are judged the way a sentence opener is.
    """
    spans: List[Tuple[int, int]] = []
    offset = 0
    for line in text.split("\n"):
        stripped = line.strip()
        clean = PROTECTED_RE.sub(" ", stripped)
        words = TOKEN_RE.findall(clean)
        if (1 <= len(words) <= 8 and not stripped.endswith((".", "!", "?"))
                and all(w[0].isupper() or w.lower() in lexicon.FUNCTION_WORDS for w in words)
                and any(w[0].isupper() for w in words)):
            spans.append((offset, offset + len(line)))
        offset += len(line) + 1
    return spans


def _tokenize(text: str) -> List[_Token]:
    protected = [(m.start(), m.end()) for m in PROTECTED_RE.finditer(text)]
    headings = _heading_lines(text)

    def inside(spans: List[Tuple[int, int]], position: int) -> bool:
        return any(start <= position < end for start, end in spans)

    tokens: List[_Token] = []
    for match in TOKEN_RE.finditer(text):
        if inside(protected, match.start()):
            continue
        word = match.group(0)
        end = match.end()
        # "Qasr's" is the name plus a possessive; only the name is removed.
        for possessive in ("'s", "’s"):
            if word.endswith(possessive):
                word = word[: -len(possessive)]
                end -= len(possessive)
        if len(word) < 2:
            continue
        initial = _starts_sentence(text, match.start()) or inside(headings, match.start())
        tokens.append(_Token(match.start(), end, word, initial=initial))
    return tokens


def _is_incidental(token: _Token) -> bool:
    """Short codes that are never a name: "Q3", "V2", "II"."""
    if _ROMAN_RE.fullmatch(token.text):
        return True
    return len(token.text) <= 4 and any(c.isdigit() for c in token.text)


def _next_word(text: str, token: _Token) -> str:
    match = re.match(r"['’]?s?\s+([A-Za-z][A-Za-z\-]*)", text[token.end:token.end + 40])
    return match.group(1) if match else ""


def _adjacent(text: str, left: _Token, right: _Token) -> bool:
    """Two tokens that read as one name: "Ahmed Al-Qahtani", "Marks & Spencer"."""
    return text[left.end:right.start] in (" ", " & ", "-", " of ", " bin ", " al ", " al-")


def _mark_public_names(text: str, tokens: List[_Token]) -> None:
    """Flag tokens that together spell a published multi-word name."""
    grams = lexicon.public_ngrams()
    for start in range(len(tokens)):
        for size in (5, 4, 3, 2):
            run = tokens[start:start + size]
            if len(run) < size:
                continue
            if any(text[a.end:b.start] not in (" ", "-") for a, b in zip(run, run[1:])):
                continue
            if " ".join(t.lower for t in run) in grams and any(t.capitalised for t in run):
                for token in run:
                    token.in_public_name = True
                break


def _classify(text: str, token: _Token) -> Optional[str]:
    """The label a single token should be redacted under, or None to keep it."""
    if not token.capitalised or _is_incidental(token) or token.in_public_name:
        return None
    if lexicon.is_strong_name(token.text):
        return "PERSON"
    if lexicon.is_public(token.text):
        return None

    ordinary = lexicon.is_ordinary(token.text)
    if token.initial:
        if not ordinary:
            return "NAME"
        if (lexicon.is_ambiguous_name(token.text)
                and _next_word(text, token).lower() in lexicon.PERSON_VERBS):
            return "PERSON"
        return None

    # Mid-sentence. English capitalises nothing here but proper nouns, so a
    # word in capitals is emphasis ("NOT") and anything else is a name.
    if token.all_caps and ordinary:
        return None
    return "NAME"


def _spill(text: str, tokens: List[_Token]) -> None:
    """Let a name claim the ordinary words written as part of it."""
    changed = True
    while changed:
        changed = False
        for index, token in enumerate(tokens):
            if (token.redact or not token.capitalised or _is_incidental(token)
                    or token.in_public_name):
                continue
            lowered = token.lower
            if lowered in lexicon.FUNCTION_WORDS or lowered in lexicon.STRUCTURE_WORDS:
                continue
            if not lexicon.is_ordinary(token.text) or lexicon.is_public(token.text):
                continue

            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if following is None or not following.capitalised or not _adjacent(text, token, following):
                continue
            # "Colonial [Pipeline]": the neighbour is already a name, or is a
            # sector word, which on its own reads as part of a company name.
            if following.redact or lexicon.is_sector_word(following.text):
                token.redact = "NAME"
                changed = True


def _run_before(text: str, tokens: List[_Token], index: int) -> List[_Token]:
    """The capitalised run that ends at tokens[index] and opens its sentence."""
    run = [tokens[index]]
    position = index
    while not run[0].initial and position > 0:
        previous = tokens[position - 1]
        if not previous.capitalised or not _adjacent(text, previous, run[0]) or len(run) >= 4:
            return []
        run.insert(0, previous)
        position -= 1
    return run if run[0].initial else []


def _subjects(text: str, tokens: List[_Token]) -> None:
    """Redact the organisation a sentence is about, vendors included."""
    for index, token in enumerate(tokens):
        if not token.capitalised or _is_incidental(token):
            continue

        # "Cisco's internal network", "the breach at Okta".
        if lexicon.is_company(token.text) and not token.redact:
            after = text[token.end:token.end + 40]
            owned = re.match(r"['’]s\s+", after)
            if owned and _OWNED_RE.match(after[owned.end():]):
                token.redact = "ORG"
                continue
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            names_product = (following is not None and following.capitalised
                             and _adjacent(text, token, following)
                             and lexicon.is_public(following.text))
            if _VICTIM_LEAD_RE.search(text[max(0, token.start - 60):token.start]) and not names_product:
                token.redact = "ORG"
                continue

        if _next_word(text, token).lower() not in lexicon.ORG_VERBS:
            continue
        if re.match(r"['’]s", text[token.end:token.end + 2]):
            continue
        run = _run_before(text, tokens, index)
        if not run:
            continue

        first, last = run[0], run[-1]
        if first.lower in lexicon.FUNCTION_WORDS or first.lower in lexicon.GENERIC_SUBJECTS:
            continue
        if len(run) == 1:
            if first.lower.endswith("s") and lexicon.is_ordinary(first.text):
                continue  # a plural noun, not a company
            if lexicon.is_public(first.text) and not lexicon.is_company(first.text):
                continue  # a tool or a department doing the detecting
        elif (lexicon.is_public(last.text) and not lexicon.is_company(last.text)
              and not lexicon.is_sector_word(last.text)):
            continue      # "Microsoft Defender detected ..." is a product

        for member in run:
            if member.lower in lexicon.STRUCTURE_WORDS or member.text.upper() in lexicon.SECURITY_ACRONYMS:
                continue
            member.redact = member.redact or "ORG"


def _repeat(tokens: List[_Token]) -> None:
    """Once a word has been read as a name, it is that name everywhere.

    "Colonial Pipeline" identifies Colonial; the next sentence opening with
    "Colonial shut down ..." has no capital letter to give it away, but it is
    the same company. Only words longer than three letters are carried over,
    so a short word swept into one name does not disappear from the report.
    """
    known = {token.text: token.redact for token in tokens if token.redact and len(token.text) > 3}
    for token in tokens:
        if (not token.redact and token.capitalised and not token.in_public_name
                and token.text in known):
            token.redact = known[token.text]


def find_names(text: str) -> List[Tuple[int, int, str]]:
    """Spans of `text` that name a person, an organisation or a place.

    Returns (start, end, label) triples, non-overlapping and in order, with
    adjacent parts of one name merged into a single span.
    """
    tokens = _tokenize(text)
    _mark_public_names(text, tokens)
    for token in tokens:
        token.redact = _classify(text, token)
    _spill(text, tokens)
    _subjects(text, tokens)
    _repeat(tokens)

    spans: List[Tuple[int, int, str]] = []
    for index, token in enumerate(tokens):
        if not token.redact:
            continue
        previous = tokens[index - 1] if index else None
        if (spans and previous is not None and previous.redact
                and spans[-1][1] == previous.end and _adjacent(text, previous, token)):
            start, _end, label = spans[-1]
            # A given name fixes the reading of the whole span.
            merged = "PERSON" if "PERSON" in (label, token.redact) else label
            spans[-1] = (start, token.end, merged)
        else:
            spans.append((token.start, token.end, token.redact))
    return spans
