"""The optional LLM layer — provider-agnostic facade.

ATTACKDNA never *depends* on a language model. Every caller supplies a
deterministic fallback, so a missing key, an expired key, a rate limit or a dead
conference Wi-Fi connection degrades the output instead of breaking the demo.

This module is the only LLM surface the rest of the system sees. It picks a
backend from `app/services/llm_providers/` and forwards to it, which means:

* adding a provider touches that package and nothing else;
* extraction, simulation and Ask-the-memory are written once, not per provider;
* switching provider is an edit to `backend/.env`, not to code.

**Provider selection.** By default the provider is inferred from the key's
prefix — `sk-ant-` is Anthropic, `AIza` is Google Gemini — because that is the
one thing a user cannot get wrong when pasting a key they were just given.
`LLM_PROVIDER` in `backend/.env` overrides the inference when needed.
"""
from __future__ import annotations

from typing import Optional

from app.config import LLM_API_KEY, LLM_ENABLED, LLM_PROVIDER
from app.services.llm_providers import anthropic_provider, gemini_provider

PROVIDERS = {
    "anthropic": anthropic_provider,
    "gemini": gemini_provider,
}


def resolve_provider() -> Optional[str]:
    """Which backend to use, or None when the key cannot be attributed."""
    configured = (LLM_PROVIDER or "auto").strip().lower()
    if configured in PROVIDERS:
        return configured

    if not LLM_ENABLED:
        return None
    for name, backend in PROVIDERS.items():
        if LLM_API_KEY.startswith(backend.KEY_PREFIX):
            return name
    return None


def _backend():
    name = resolve_provider()
    return PROVIDERS[name] if name else None


def provider_name() -> str:
    return resolve_provider() or "none"


def active_model() -> str:
    backend = _backend()
    return backend.model_name() if backend else "none"


def is_available() -> bool:
    """True when a provider is selected, keyed and reachable."""
    if not LLM_ENABLED:
        return False
    backend = _backend()
    return bool(backend) and backend.available()


def complete_json(system: str, prompt: str, max_tokens: int = 2000,
                  effort: str = "low") -> Optional[dict]:
    """Ask the configured model for JSON. Returns None on any failure.

    Returning None (rather than a partial dict) is deliberate: callers make one
    clean decision about falling back, instead of defending against
    half-populated results at every field.
    """
    if not LLM_ENABLED:
        return None
    backend = _backend()
    if backend is None:
        return None
    return backend.complete_json(system, prompt, max_tokens=max_tokens, effort=effort)


def diagnose() -> dict:
    """Explain precisely why the LLM layer is or is not working.

    Handles the provider-independent failures — no key, a placeholder key, an
    unrecognised key — then delegates to the selected backend, which knows what
    its own API's errors mean. Never returns the key, and never raises.
    """
    base = {"ok": False, "stage": "unknown", "provider": provider_name(),
            "model": active_model(), "detail": "", "remedy": ""}

    if not LLM_API_KEY:
        return {**base, "stage": "no_key",
                "detail": "LLM_API_KEY is empty in backend/.env",
                "remedy": "Add a key: sk-ant-... for Claude (console.anthropic.com) "
                          "or AIza... for Gemini (aistudio.google.com/apikey)."}

    if not LLM_ENABLED:
        return {**base, "stage": "placeholder_key",
                "detail": "LLM_API_KEY is still the placeholder value",
                "remedy": "Replace 'your_key_here' with a real key."}

    backend = _backend()
    if backend is None:
        return {**base, "stage": "unknown_provider",
                "detail": "The key does not match any known provider prefix "
                          f"({', '.join(b.KEY_PREFIX for b in PROVIDERS.values())})",
                "remedy": "Set LLM_PROVIDER=anthropic or LLM_PROVIDER=gemini in "
                          "backend/.env to say which API this key belongs to."}

    return backend.diagnose()
