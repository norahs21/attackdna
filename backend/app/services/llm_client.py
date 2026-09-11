"""Thin, optional wrapper around the Claude API.

ATTACKDNA never *depends* on the LLM. Every caller must supply a deterministic
fallback, so an expired key, a rate limit or a dead conference Wi-Fi connection
degrades the output instead of breaking the demo.

Two knobs matter here:

* **effort** — how much the model thinks before answering. These are structured
  extraction and grounded-QA tasks over short documents, not hard reasoning
  problems, so they run at low/medium effort. That keeps a live demo snappy;
  raise it if extraction quality ever needs it.
* **graceful degradation** — `output_config` is rejected by some older models.
  Rather than silently losing the whole LLM path over one unsupported
  parameter, the first failure retries once without it.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from app.config import LLM_ENABLED, LLM_API_KEY, LLM_MODEL

logger = logging.getLogger(__name__)

_client = None
_client_failed = False
# Set once a request is rejected for sending output_config, so later calls skip it.
_effort_unsupported = False


def is_available() -> bool:
    """True when a usable key is configured and the SDK is importable."""
    return LLM_ENABLED and not _client_failed and _get_client() is not None


def _get_client():
    global _client, _client_failed
    if _client is not None or _client_failed:
        return _client
    if not LLM_ENABLED:
        return None
    try:
        import anthropic

        _client = anthropic.Anthropic(api_key=LLM_API_KEY)
    except Exception as exc:  # noqa: BLE001 - any failure means "no LLM"
        logger.warning("LLM unavailable, using rule-based path: %s", exc)
        _client_failed = True
        return None
    return _client


def complete_json(system: str, prompt: str, max_tokens: int = 2000,
                  effort: str = "low") -> Optional[dict]:
    """Ask the model for JSON. Returns None on any failure — never raises.

    Returning None (rather than a partial dict) is deliberate: callers can then
    make one clean decision about falling back, instead of defending against
    half-populated results at every field.
    """
    global _effort_unsupported

    client = _get_client()
    if client is None:
        return None

    def _call(with_effort: bool):
        kwargs = {
            "model": LLM_MODEL,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        if with_effort:
            kwargs["output_config"] = {"effort": effort}
        return client.messages.create(**kwargs)

    try:
        response = _call(with_effort=not _effort_unsupported)
    except Exception as exc:  # noqa: BLE001
        # A model that rejects output_config should cost us the parameter, not
        # the entire LLM path.
        if not _effort_unsupported:
            logger.info("Retrying without output_config (%s)", exc)
            _effort_unsupported = True
            try:
                response = _call(with_effort=False)
            except Exception as retry_exc:  # noqa: BLE001
                logger.warning("LLM call failed, using rule-based path: %s", retry_exc)
                return None
        else:
            logger.warning("LLM call failed, using rule-based path: %s", exc)
            return None

    # A safety classifier may decline the request; that is not an error, but
    # there is no content to parse.
    if getattr(response, "stop_reason", None) == "refusal":
        logger.warning("LLM declined the request; using rule-based path")
        return None

    text = "".join(block.text for block in response.content
                   if getattr(block, "type", None) == "text")
    return _parse_json(text)


def diagnose() -> dict:
    """Explain precisely why the LLM path is or is not working.

    `complete_json` fails soft by design — a broken key must never break the
    demo. But silent degradation is the wrong behaviour during setup: "rule-based
    mode" looks identical whether no key is configured, the key is rejected, or
    the account has no credit. This makes one real call and names the cause.

    Never returns the key, and never raises.
    """
    import anthropic

    result = {"ok": False, "stage": "unknown", "model": LLM_MODEL,
              "detail": "", "remedy": ""}

    if not LLM_API_KEY:
        return {**result, "stage": "no_key",
                "detail": "LLM_API_KEY is empty in backend/.env",
                "remedy": "Add LLM_API_KEY=sk-ant-... to backend/.env, then restart."}

    if not LLM_ENABLED:
        return {**result, "stage": "placeholder_key",
                "detail": "LLM_API_KEY is still the placeholder value",
                "remedy": "Replace 'your_key_here' with a real key from console.anthropic.com."}

    client = _get_client()
    if client is None:
        return {**result, "stage": "sdk_missing",
                "detail": "The anthropic SDK could not be initialised",
                "remedy": "Run: pip install -r backend/requirements.txt"}

    try:
        response = client.messages.create(
            model=LLM_MODEL,
            max_tokens=16,
            messages=[{"role": "user", "content": "Reply with the single word: ok"}],
            output_config={"effort": "low"},
        )
        text = "".join(b.text for b in response.content
                       if getattr(b, "type", None) == "text").strip()
        return {**result, "ok": True, "stage": "ok",
                "detail": f"Model replied: {text!r} "
                          f"({response.usage.input_tokens} in / "
                          f"{response.usage.output_tokens} out tokens)",
                "remedy": ""}

    # Most specific first: each of these needs a different fix.
    except anthropic.AuthenticationError:
        return {**result, "stage": "auth_failed",
                "detail": "The API key was rejected (401)",
                "remedy": "Check the key is copied whole and not expired or revoked."}
    except anthropic.PermissionDeniedError:
        return {**result, "stage": "permission_denied",
                "detail": f"The key is valid but not permitted to use {LLM_MODEL} (403)",
                "remedy": "Check the workspace has access to this model, or set "
                          "LLM_MODEL to one it does."}
    except anthropic.NotFoundError:
        return {**result, "stage": "model_not_found",
                "detail": f"Model '{LLM_MODEL}' was not found (404)",
                "remedy": "Check LLM_MODEL in backend/.env against the model list."}
    except anthropic.BadRequestError as exc:
        return {**result, "stage": "bad_request",
                "detail": f"The request was rejected (400): {exc}",
                "remedy": "Often means this model does not accept a parameter we sent; "
                          "the pipeline retries without it, so this may be harmless."}
    except anthropic.RateLimitError:
        return {**result, "stage": "rate_limited",
                "detail": "Rate limited or out of credit (429)",
                "remedy": "Check the credit balance on the account, then retry."}
    except anthropic.APIConnectionError as exc:
        return {**result, "stage": "network",
                "detail": f"Could not reach the API: {exc}",
                "remedy": "Check the internet connection, VPN or proxy."}
    except anthropic.APIStatusError as exc:
        return {**result, "stage": "api_error",
                "detail": f"HTTP {exc.status_code}: {exc}",
                "remedy": "Retry; if it persists, check the Anthropic status page."}
    except Exception as exc:  # noqa: BLE001
        return {**result, "stage": "unexpected",
                "detail": f"{type(exc).__name__}: {exc}", "remedy": ""}


def _parse_json(text: str) -> Optional[dict]:
    """Pull a JSON object out of a model response, fenced or bare."""
    if not text:
        return None
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
