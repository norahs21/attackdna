"""Google Gemini backend.

Uses the `google-genai` SDK. Two things make Gemini a good fit for this
project's LLM calls:

* **Native JSON output.** `response_mime_type="application/json"` makes the
  model return parseable JSON directly, so the fragile "find the JSON inside
  the prose" step the Anthropic path needs is unnecessary here.
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
from typing import List, Optional

from app.config import LLM_API_KEY, LLM_MODEL

logger = logging.getLogger(__name__)

# A widely-available free-tier model. Overridden by LLM_MODEL in backend/.env,
# and diagnose() lists what the key can actually reach.
DEFAULT_MODEL = "gemini-2.5-flash"

# Google AI Studio keys start with this. Used only to auto-detect the provider.
KEY_PREFIX = "AIza"

# Gemini has no `effort` parameter; it has a thinking budget in tokens.
# These keep the mapping explicit rather than scattering magic numbers.
EFFORT_THINKING_BUDGET = {"low": 0, "medium": 2048, "high": 8192}

_client = None
_client_failed = False


def model_name() -> str:
    return LLM_MODEL if LLM_MODEL and "gemini" in LLM_MODEL.lower() else DEFAULT_MODEL


def _get_client():
    global _client, _client_failed
    if _client is not None or _client_failed:
        return _client
    try:
        from google import genai

        _client = genai.Client(api_key=LLM_API_KEY)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Gemini unavailable, using rule-based path: %s", exc)
        _client_failed = True
        return None
    return _client


def available() -> bool:
    return bool(LLM_API_KEY) and not _client_failed and _get_client() is not None


def complete_json(system: str, prompt: str, max_tokens: int = 2000,
                  effort: str = "low") -> Optional[dict]:
    """Ask Gemini for JSON. Returns None on any failure — never raises."""
    client = _get_client()
    if client is None:
        return None

    from google.genai import types

    config = types.GenerateContentConfig(
        system_instruction=system,
        max_output_tokens=max_tokens,
        response_mime_type="application/json",
        thinking_config=types.ThinkingConfig(
            thinking_budget=EFFORT_THINKING_BUDGET.get(effort, 0)
        ),
    )

    try:
        response = client.models.generate_content(
            model=model_name(), contents=prompt, config=config
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
    from google.genai import errors

    result = {"ok": False, "stage": "unknown", "provider": "gemini",
              "model": model_name(), "detail": "", "remedy": ""}

    if not LLM_API_KEY:
        return {**result, "stage": "no_key",
                "detail": "LLM_API_KEY is empty in backend/.env",
                "remedy": "Add your Gemini key (starts with AIza) from aistudio.google.com."}

    client = _get_client()
    if client is None:
        return {**result, "stage": "sdk_missing",
                "detail": "The google-genai SDK could not be initialised",
                "remedy": "Run: pip install -r backend/requirements.txt"}

    try:
        from google.genai import types

        response = client.models.generate_content(
            model=model_name(),
            contents="Reply with JSON: {\"status\": \"ok\"}",
            config=types.GenerateContentConfig(
                max_output_tokens=64,
                response_mime_type="application/json",
                thinking_config=types.ThinkingConfig(thinking_budget=0),
            ),
        )
        usage = getattr(response, "usage_metadata", None)
        tokens = (f" ({usage.prompt_token_count} in / "
                  f"{usage.candidates_token_count} out tokens)" if usage else "")
        return {**result, "ok": True, "stage": "ok",
                "detail": f"Model replied: {(response.text or '').strip()!r}{tokens}"}

    except errors.ClientError as exc:
        status = getattr(exc, "code", None) or getattr(exc, "status_code", None)
        message = str(exc)

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
        return {**result, "stage": "api_error",
                "detail": f"{status}: {message}",
                "remedy": "Check the key and model name in backend/.env."}

    except errors.ServerError as exc:
        return {**result, "stage": "api_error",
                "detail": f"Gemini server error: {exc}",
                "remedy": "Transient — retry in a moment."}
    except Exception as exc:  # noqa: BLE001
        name = type(exc).__name__
        if "Connect" in name or "Timeout" in name:
            return {**result, "stage": "network",
                    "detail": f"Could not reach the API: {exc}",
                    "remedy": "Check the internet connection, VPN or proxy."}
        return {**result, "stage": "unexpected", "detail": f"{name}: {exc}", "remedy": ""}
