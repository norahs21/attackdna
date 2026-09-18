"""Google Gemini backend.

Talks to the Generative Language REST API directly over `requests` rather than
through the `google-genai` SDK. That is a deliberate trade, not laziness: the
SDK pulls in `google-auth`, which requires `cryptography`, which is a Rust
extension with no wheel for every platform — so a machine without a Rust
toolchain cannot install this project at all. The SDK exists to handle OAuth
and service-account credentials; ATTACKDNA authenticates with a single API key
header and needs none of it. Two HTTP calls replace ~40MB of dependencies, and
`make setup` works on any Python that can run the rest of the app.

Two things make Gemini a good fit for this project's LLM calls:

* **Native JSON output.** `responseMimeType: application/json` makes the model
  return parseable JSON directly, so the fragile "find the JSON inside the
  prose" step the Anthropic path needs is unnecessary here.
* **A free tier.** Enough for development and a demo without a credit card.

Model names move faster than this file does, so nothing is hardcoded as truth:
`diagnose()` asks the API which models the key can actually use and reports
them. A wrong `LLM_MODEL` therefore produces a list of right ones rather than a
dead end.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from app.config import LLM_API_KEY, LLM_MODEL

logger = logging.getLogger(__name__)

# A widely-available free-tier model. Overridden by LLM_MODEL in backend/.env,
# and diagnose() lists what the key can actually reach.
DEFAULT_MODEL = "gemini-2.5-flash"

# Google issues AI Studio keys in two formats, and which one you get depends on
# when and where the key was created rather than on anything the user chooses.
# Recognising only the older "AIza" form left anyone with a newer key staring at
# "the key does not match any known provider prefix" for a key that was
# perfectly valid. Used only to auto-detect the provider; LLM_PROVIDER still
# overrides, and a key of either shape that Google rejects is reported by
# diagnose() rather than guessed at.
KEY_PREFIXES = ("AIza", "AQ.")
KEY_PREFIX = KEY_PREFIXES[0]  # The one to name in messages.

API_BASE = "https://generativelanguage.googleapis.com/v1beta"
TIMEOUT_SECONDS = 60

# Gemini has no `effort` parameter; it has a thinking budget in tokens.
# These keep the mapping explicit rather than scattering magic numbers.
EFFORT_THINKING_BUDGET = {"low": 0, "medium": 2048, "high": 8192}

_client = None
_client_failed = False


class GeminiAPIError(RuntimeError):
    """An error the API itself reported, carrying the HTTP status.

    `diagnose()` turns the status into an explanation, so it must survive the
    trip out of the transport layer rather than collapsing into a string.
    """

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def model_name() -> str:
    return LLM_MODEL if LLM_MODEL and "gemini" in LLM_MODEL.lower() else DEFAULT_MODEL


# --- Transport ------------------------------------------------------------
# The nested `client.models.generate_content(...)` shape mirrors the SDK the
# rest of this file was written against, so swapping the transport did not
# ripple into the call sites or the tests.

class _Model:
    """One entry from the models listing."""

    def __init__(self, name: str, supported_actions: List[str]):
        self.name = name
        self.supported_actions = supported_actions


class _Response:
    """A generateContent reply, flattened to the two fields callers read."""

    def __init__(self, text: Optional[str], usage_metadata: Any = None):
        self.text = text
        self.usage_metadata = usage_metadata


class _Usage:
    def __init__(self, prompt_token_count: int, candidates_token_count: int):
        self.prompt_token_count = prompt_token_count
        self.candidates_token_count = candidates_token_count


class _Models:
    def generate_content(self, *, model: str, contents: str,
                         system: Optional[str] = None, max_tokens: int = 2000,
                         thinking_budget: int = 0) -> _Response:
        payload: Dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": contents}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "responseMimeType": "application/json",
                "thinkingConfig": {"thinkingBudget": thinking_budget},
            },
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        body = _request("POST", f"/models/{model}:generateContent", json_body=payload)

        # A safety filter or an exhausted budget yields a candidate with no
        # parts, so every step here has to tolerate absence.
        candidates = body.get("candidates") or []
        parts = (candidates[0].get("content", {}).get("parts", []) if candidates else [])
        text = "".join(part.get("text", "") for part in parts) or None

        usage_body = body.get("usageMetadata") or {}
        usage = _Usage(usage_body.get("promptTokenCount", 0),
                       usage_body.get("candidatesTokenCount", 0)) if usage_body else None
        return _Response(text, usage)

    def list(self) -> List[_Model]:
        body = _request("GET", "/models")
        return [
            _Model(model.get("name", ""), model.get("supportedGenerationMethods", []))
            for model in body.get("models", [])
        ]


class _RestClient:
    def __init__(self):
        self.models = _Models()


def _request(method: str, path: str, json_body: Optional[dict] = None) -> dict:
    """One API call. Raises GeminiAPIError for anything the API rejected.

    The key travels in a header rather than the query string so it cannot end
    up in a proxy log or a traceback that quotes the URL.
    """
    import requests

    response = requests.request(
        method,
        f"{API_BASE}{path}",
        headers={"x-goog-api-key": LLM_API_KEY, "Content-Type": "application/json"},
        json=json_body,
        timeout=TIMEOUT_SECONDS,
    )

    if response.status_code >= 400:
        try:
            detail = response.json().get("error", {}).get("message", response.text)
        except ValueError:
            detail = response.text
        raise GeminiAPIError(response.status_code, detail)

    return response.json()


def _get_client():
    global _client, _client_failed
    if _client is not None or _client_failed:
        return _client
    try:
        import requests  # noqa: F401  — checked here so failure is diagnosable
    except Exception as exc:  # noqa: BLE001
        logger.warning("Gemini unavailable, using rule-based path: %s", exc)
        _client_failed = True
        return None
    _client = _RestClient()
    return _client


def available() -> bool:
    return bool(LLM_API_KEY) and not _client_failed and _get_client() is not None


def complete_json(system: str, prompt: str, max_tokens: int = 2000,
                  effort: str = "low") -> Optional[dict]:
    """Ask Gemini for JSON. Returns None on any failure — never raises."""
    client = _get_client()
    if client is None:
        return None

    try:
        response = client.models.generate_content(
            model=model_name(),
            contents=prompt,
            system=system,
            max_tokens=max_tokens,
            thinking_budget=EFFORT_THINKING_BUDGET.get(effort, 0),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Gemini call failed, using rule-based path: %s", exc)
        return None

    text = getattr(response, "text", None)
    if not text:
        # A safety filter or an exhausted token budget leaves no text to parse.
        logger.warning("Gemini returned no text; using rule-based path")
        return None
    return _parse_json(text)


def _parse_json(text: str) -> Optional[dict]:
    """Parse the response. JSON mode makes this the common case, not a rescue."""
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    # Fall back to extraction in case a future model ignores the mime type.
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fenced.group(1) if fenced else text
    if not fenced:
        start, end = candidate.find("{"), candidate.rfind("}")
        if start == -1 or end <= start:
            return None
        candidate = candidate[start:end + 1]
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def list_models(limit: int = 12) -> List[str]:
    """Models this key can generate content with. Empty if the call fails."""
    client = _get_client()
    if client is None:
        return []
    try:
        names = []
        for model in client.models.list():
            actions = getattr(model, "supported_actions", None) or []
            if actions and "generateContent" not in actions:
                continue
            name = (model.name or "").removeprefix("models/")
            if name:
                names.append(name)
        return sorted(names)[:limit]
    except Exception:  # noqa: BLE001
        return []


def diagnose() -> dict:
    """Explain precisely why the Gemini path is or is not working."""
    result = {"ok": False, "stage": "unknown", "provider": "gemini",
              "model": model_name(), "detail": "", "remedy": ""}

    if not LLM_API_KEY:
        return {**result, "stage": "no_key",
                "detail": "LLM_API_KEY is empty in backend/.env",
                "remedy": "Add your Gemini key (starts with AIza) from aistudio.google.com."}

    client = _get_client()
    if client is None:
        return {**result, "stage": "sdk_missing",
                "detail": "The HTTP client could not be initialised",
                "remedy": "Run: pip install -r backend/requirements.txt"}

    try:
        response = client.models.generate_content(
            model=model_name(),
            contents="Reply with JSON: {\"status\": \"ok\"}",
            max_tokens=64,
            thinking_budget=0,
        )
        usage = getattr(response, "usage_metadata", None)
        tokens = (f" ({usage.prompt_token_count} in / "
                  f"{usage.candidates_token_count} out tokens)" if usage else "")
        return {**result, "ok": True, "stage": "ok",
                "detail": f"Model replied: {(response.text or '').strip()!r}{tokens}"}

    except GeminiAPIError as exc:
        status, message = exc.code, exc.message

        if status == 400 and "API key not valid" in message:
            return {**result, "stage": "auth_failed",
                    "detail": "The API key was rejected",
                    "remedy": "Check the key is copied whole. Create a new one at "
                              "aistudio.google.com/apikey if needed."}
        if status in (401, 403):
            return {**result, "stage": "auth_failed",
                    "detail": f"The key was rejected or lacks permission ({status})",
                    "remedy": "Check the key and that the Generative Language API is enabled."}
        if status == 404:
            models = list_models()
            hint = f" Available to this key: {', '.join(models)}" if models else ""
            return {**result, "stage": "model_not_found",
                    "detail": f"Model '{model_name()}' was not found.{hint}",
                    "remedy": "Set LLM_MODEL in backend/.env to one of the models listed."}
        if status == 429:
            return {**result, "stage": "rate_limited",
                    "detail": "Rate limit or free-tier quota exhausted (429)",
                    "remedy": "Wait for the quota window to reset, or use a lighter model."}
        if status >= 500:
            return {**result, "stage": "api_error",
                    "detail": f"Gemini server error: {message}",
                    "remedy": "Transient — retry in a moment."}
        return {**result, "stage": "api_error",
                "detail": f"{status}: {message}",
                "remedy": "Check the key and model name in backend/.env."}

    except Exception as exc:  # noqa: BLE001
        name = type(exc).__name__
        if "Connect" in name or "Timeout" in name:
            return {**result, "stage": "network",
                    "detail": f"Could not reach the API: {exc}",
                    "remedy": "Check the internet connection, VPN or proxy."}
        return {**result, "stage": "unexpected", "detail": f"{name}: {exc}", "remedy": ""}
