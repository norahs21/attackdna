"""Negation: the difference between a finding and its absence.

"No data was exfiltrated" contains the word "exfiltrated". A keyword matcher
that stops there reports exfiltration, raises the severity, and recommends a
response to something the report explicitly rules out. Incident reports say
what did *not* happen all the time — it is how they bound the damage — so the
matchers ask this module first.

The model is deliberately small. A cue opens a scope: the noun phrase after
"no" or "without", the rest of the clause after "was not" or "failed to". A
comma ends it unless the clause is a list ("no intrusion, malware or data
exfiltration"), which is the one place a comma inside a negation is not a
boundary.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import List, Tuple

# Cues that deny a *thing*: "no lateral movement", "without MFA". Their scope
# is the noun phrase that follows, which may be a list.
_NOUN_CUE = (
    r"no evidence of|no sign of|no signs of|no indication of|absence of|lack of|"
    r"before any|rather than|instead of|without|neither|none|no"
)
# Cues that deny an *action*: "was not exfiltrated", "failed to detect". Their
# scope is the rest of the clause.
_VERB_CUE = (
    r"did not|does not|do not|was not|were not|is not|are not|has not|have not|had not|"
    r"could not|would not|cannot|can not|failed to|unable to|"
    r"didn't|doesn't|don't|wasn't|weren't|isn't|aren't|hasn't|haven't|hadn't|"
    r"couldn't|wouldn't|can't|never|not|nor"
)
_CUE_RE = re.compile(rf"\b(?:(?P<noun>{_NOUN_CUE})|(?P<verb>{_VERB_CUE}))\b")

# Where a clause ends whatever it contains. The relative pronouns matter:
# "an account without MFA whose password had appeared in a credential dump"
# denies the MFA, not the dump.
_HARD_STOP_RE = re.compile(
    r"[.;:!?\n]|\b(?:but|however|although|while|whereas|until|whose|which|who|where|because)\b"
)
_AND_RE = re.compile(r"\band\b")
_LIST_RE = re.compile(r"\b(?:or|nor)\b")

# A scope is at most this many words: negation does not reach across a
# paragraph, and a long sentence usually changes subject on the way.
_MAX_WORDS = {"noun": 8, "verb": 12}


@lru_cache(maxsize=256)
def negated_spans(text_lower: str) -> Tuple[Tuple[int, int], ...]:
    """Character spans of `text_lower` that sit inside a negation."""
    spans: List[Tuple[int, int]] = []
    for cue in _CUE_RE.finditer(text_lower):
        kind = "noun" if cue.group("noun") else "verb"
        start = cue.end()
        stop = _HARD_STOP_RE.search(text_lower, start)
        end = stop.start() if stop else len(text_lower)

        # "did not block the payload and files were encrypted": the second
        # half is a new statement. A denied *thing* can be a pair, though —
        # "no lateral movement and no exfiltration" carries its own cue.
        if kind == "verb":
            conjunction = _AND_RE.search(text_lower, start, end)
            if conjunction:
                end = conjunction.start()

        clause = text_lower[start:end]
        comma = clause.find(",")
        if comma != -1 and not _LIST_RE.search(clause):
            end = start + comma

        words = list(re.finditer(r"\S+", text_lower[start:end]))
        limit = _MAX_WORDS[kind]
        if len(words) > limit:
            end = start + words[limit - 1].end()
        if end > start:
            spans.append((start, end))
    return tuple(spans)


def is_negated(text_lower: str, position: int) -> bool:
    """Whether the match starting at `position` is something the text denies."""
    return any(start <= position < end for start, end in negated_spans(text_lower))


def affirmed(pattern: "re.Pattern[str]", text_lower: str) -> bool:
    """Whether `pattern` occurs somewhere the text is not denying it."""
    return any(not is_negated(text_lower, match.start())
               for match in pattern.finditer(text_lower))
