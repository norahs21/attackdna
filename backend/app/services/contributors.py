"""Who contributed an incident, without storing who contributed it.

Shared memory has to answer one question about each record, "is this one of
mine?", so an organisation is not told that a match from another organisation
is its own incident, and the reverse. It must not answer "whose is this?",
because that would undo the privacy layer.

The answer is a keyed pseudonym: HMAC-SHA256 of the normalised organisation
name under a server-side key. With the key, the server can recompute an
organisation's pseudonym and compare it. Without the key, the stored value
cannot be reversed or tested against a list of likely names. The pseudonym
never leaves the server. API responses and the UI only carry the result of the
comparison (`from_your_organisation`), so even a reader of every response
cannot tell whether two shared incidents came from the same contributor.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import unicodedata
from pathlib import Path
from typing import Optional

from app.config import BACKEND_DIR

KEY_PATH = BACKEND_DIR / ".pseudonym_key"


def _key() -> bytes:
    """The server's pseudonym key: from the environment, else a local file."""
    configured = os.getenv("ATTACKDNA_PSEUDONYM_KEY", "").strip()
    if configured:
        return configured.encode("utf-8")
    try:
        if KEY_PATH.exists():
            return KEY_PATH.read_bytes().strip()
        key = secrets.token_hex(32).encode("ascii")
        KEY_PATH.write_bytes(key)
        try:
            os.chmod(KEY_PATH, 0o600)
        except OSError:
            pass
        return key
    except OSError:
        # A read-only checkout still works; pseudonyms then only hold for the
        # life of this process, which is the safe direction to fail in.
        return _PROCESS_KEY


_PROCESS_KEY = secrets.token_hex(32).encode("ascii")


def _normalise(name: str) -> str:
    folded = unicodedata.normalize("NFKC", name).casefold()
    return " ".join(folded.split())


def pseudonym(organisation: Optional[str]) -> Optional[str]:
    """The stored stand-in for an organisation's name, or None if no name."""
    if not organisation or not organisation.strip():
        return None
    digest = hmac.new(_key(), _normalise(organisation).encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def same_contributor(stored: Optional[str], viewer: Optional[str]) -> bool:
    """True only when both pseudonyms exist and match. Constant-time."""
    if not stored or not viewer:
        return False
    return hmac.compare_digest(stored, viewer)


def key_location() -> Path:
    return KEY_PATH
