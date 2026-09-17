"""Tests for the optional LLM layer.

Three things matter and none involves calling a real API: the key must never
escape, a broken key must degrade the system rather than break it while still
being diagnosable, and the provider abstraction must hold so that swapping
Claude for Gemini is a `.env` edit rather than a code change.
"""
import pytest

from app.services import llm_client
from app.services.llm_providers import anthropic_provider, gemini_provider

ANTHROPIC_KEY = "sk-ant-api03-exampleexamplevalue"
GEMINI_KEY = "AIzaSyExampleExampleExampleValue"


# --- The key must not leak ------------------------------------------------
def test_diagnose_never_returns_the_key(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_API_KEY", "sk-ant-supersecret-value-12345")
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)
    monkeypatch.setattr(anthropic_provider, "LLM_API_KEY", "sk-ant-supersecret-value-12345")
    monkeypatch.setattr(anthropic_provider, "_get_client", lambda: None)

    assert "supersecret" not in repr(llm_client.diagnose())


def test_stats_endpoint_exposes_the_model_but_not_the_key(clean_memory):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        body = client.get("/stats").json()

    assert "model" in body["llm"]
    assert "sk-ant" not in repr(body) and "AIza" not in repr(body)


def test_the_env_file_is_gitignored():
    """The one mistake that cannot be undone once pushed."""
    from pathlib import Path

    gitignore = (Path(__file__).resolve().parent.parent / ".gitignore").read_text()
    assert ".env" in gitignore
    assert "backend/.env" in gitignore


# --- Provider selection ---------------------------------------------------
@pytest.mark.parametrize("key,expected", [
    (ANTHROPIC_KEY, "anthropic"),
    (GEMINI_KEY, "gemini"),
])
def test_the_provider_is_inferred_from_the_key_prefix(monkeypatch, key, expected):
    """Pasting a key should be enough — no second setting to get wrong."""
    monkeypatch.setattr(llm_client, "LLM_API_KEY", key)
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)
    monkeypatch.setattr(llm_client, "LLM_PROVIDER", "auto")

    assert llm_client.resolve_provider() == expected


def test_an_explicit_provider_overrides_the_inference(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_API_KEY", ANTHROPIC_KEY)
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)
    monkeypatch.setattr(llm_client, "LLM_PROVIDER", "gemini")

    assert llm_client.resolve_provider() == "gemini"


def test_an_unrecognised_key_is_reported_rather_than_guessed(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_API_KEY", "xyz-some-other-provider-key")
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)
    monkeypatch.setattr(llm_client, "LLM_PROVIDER", "auto")

    result = llm_client.diagnose()
    assert result["stage"] == "unknown_provider"
    assert "LLM_PROVIDER" in result["remedy"]


def test_every_provider_implements_the_whole_interface():
    """The abstraction is only real if each backend satisfies all of it."""
    for backend in llm_client.PROVIDERS.values():
        for name in ("available", "complete_json", "diagnose", "model_name"):
            assert callable(getattr(backend, name)), f"{backend.__name__} lacks {name}"
        assert isinstance(backend.KEY_PREFIX, str) and backend.KEY_PREFIX


def test_each_provider_falls_back_to_its_own_default_model(monkeypatch):
    """An empty LLM_MODEL must not leave a provider pointing at a rival's model."""
    for backend in (anthropic_provider, gemini_provider):
        monkeypatch.setattr(backend, "LLM_MODEL", "")
        assert backend.model_name() == backend.DEFAULT_MODEL

    # A model belonging to the other provider is ignored, not passed through.
    monkeypatch.setattr(gemini_provider, "LLM_MODEL", "claude-opus-5")
    assert gemini_provider.model_name() == gemini_provider.DEFAULT_MODEL
    monkeypatch.setattr(anthropic_provider, "LLM_MODEL", "gemini-2.5-flash")
    assert anthropic_provider.model_name() == anthropic_provider.DEFAULT_MODEL


# --- Diagnosis names the cause -------------------------------------------
def test_a_missing_key_is_reported_as_such(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_API_KEY", "")
    result = llm_client.diagnose()

    assert result["ok"] is False
    assert result["stage"] == "no_key"
    assert "aistudio" in result["remedy"] and "console.anthropic" in result["remedy"], \
        "the remedy should name both providers, since either key works"


def test_a_placeholder_key_is_reported_as_such(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_API_KEY", "your_key_here")
    monkeypatch.setattr(llm_client, "LLM_ENABLED", False)

    assert llm_client.diagnose()["stage"] == "placeholder_key"


def _api_error(exc_class, status: int):
    """Build a real SDK exception — these need a genuine httpx response."""
    import httpx2 as httpx

    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return exc_class("simulated failure", response=httpx.Response(status, request=request),
                     body=None)


@pytest.mark.parametrize("exc_name,status,expected_stage", [
    ("AuthenticationError", 401, "auth_failed"),
    ("PermissionDeniedError", 403, "permission_denied"),
    ("NotFoundError", 404, "model_not_found"),
    ("RateLimitError", 429, "rate_limited"),
])
def test_each_anthropic_failure_is_diagnosed_distinctly(monkeypatch, exc_name, status,
                                                        expected_stage):
    """A rejected key, a forbidden model and no credit need different fixes."""
    import anthropic

    exc = _api_error(getattr(anthropic, exc_name), status)

    class _Failing:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise exc

    monkeypatch.setattr(anthropic_provider, "LLM_API_KEY", ANTHROPIC_KEY)
    monkeypatch.setattr(anthropic_provider, "_get_client", lambda: _Failing())

    result = anthropic_provider.diagnose()
    assert result["stage"] == expected_stage
    assert result["provider"] == "anthropic"
    assert result["remedy"], "every diagnosed failure must name a fix"


def test_gemini_reports_a_missing_key(monkeypatch):
    monkeypatch.setattr(gemini_provider, "LLM_API_KEY", "")
    result = gemini_provider.diagnose()

    assert result["stage"] == "no_key"
    assert result["provider"] == "gemini"
    assert "aistudio" in result["remedy"]


def test_gemini_lists_available_models_when_the_model_is_wrong(monkeypatch):
    """A wrong model name should produce the right ones, not a dead end."""
    from google.genai import errors

    class _NotFound:
        class models:
            @staticmethod
            def generate_content(**kwargs):
                raise errors.ClientError(404, {"error": {"message": "model not found"}})

    monkeypatch.setattr(gemini_provider, "LLM_API_KEY", GEMINI_KEY)
    monkeypatch.setattr(gemini_provider, "_get_client", lambda: _NotFound())
    monkeypatch.setattr(gemini_provider, "list_models",
                        lambda limit=12: ["gemini-2.5-flash", "gemini-2.5-pro"])

    result = gemini_provider.diagnose()
    assert result["stage"] == "model_not_found"
    assert "gemini-2.5-flash" in result["detail"]


@pytest.mark.parametrize("backend", [anthropic_provider, gemini_provider])
def test_diagnose_never_raises(monkeypatch, backend):
    """However it fails, setup must get an answer rather than a traceback."""
    class _Exploding:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise RuntimeError("something entirely unexpected")

        class models:
            @staticmethod
            def generate_content(**kwargs):
                raise RuntimeError("something entirely unexpected")

    monkeypatch.setattr(backend, "LLM_API_KEY", "key-of-some-kind")
    monkeypatch.setattr(backend, "_get_client", lambda: _Exploding())

    result = backend.diagnose()
    assert result["ok"] is False
    assert result["stage"] == "unexpected"


# --- Failure degrades, never breaks --------------------------------------
@pytest.mark.parametrize("backend", [anthropic_provider, gemini_provider])
def test_a_failing_call_returns_none_rather_than_raising(monkeypatch, backend):
    class _Failing:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise RuntimeError("API down")

        class models:
            @staticmethod
            def generate_content(**kwargs):
                raise RuntimeError("API down")

    monkeypatch.setattr(backend, "_get_client", lambda: _Failing())
    monkeypatch.setattr(anthropic_provider, "_effort_unsupported", True)

    assert backend.complete_json("system", "prompt") is None


def test_the_facade_returns_none_when_no_provider_is_configured(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_ENABLED", False)
    assert llm_client.complete_json("system", "prompt") is None
    assert llm_client.is_available() is False


def test_a_model_rejecting_output_config_retries_without_it(monkeypatch):
    """One unsupported parameter must not cost us the entire LLM path."""
    calls = []

    class _Picky:
        class messages:
            @staticmethod
            def create(**kwargs):
                calls.append(kwargs)
                if "output_config" in kwargs:
                    raise RuntimeError("output_config is not supported for this model")
                return type("R", (), {
                    "stop_reason": "end_turn",
                    "content": [type("B", (), {"type": "text", "text": '{"ok": true}'})()],
                })()

    monkeypatch.setattr(anthropic_provider, "_get_client", lambda: _Picky())
    monkeypatch.setattr(anthropic_provider, "_effort_unsupported", False)

    assert anthropic_provider.complete_json("system", "prompt") == {"ok": True}
    assert len(calls) == 2
    assert "output_config" in calls[0] and "output_config" not in calls[1]


def test_a_refusal_is_treated_as_no_answer_not_a_crash(monkeypatch):
    class _Refusing:
        class messages:
            @staticmethod
            def create(**kwargs):
                return type("R", (), {"stop_reason": "refusal", "content": []})()

    monkeypatch.setattr(anthropic_provider, "_get_client", lambda: _Refusing())
    assert anthropic_provider.complete_json("system", "prompt") is None


def test_gemini_handles_an_empty_response(monkeypatch):
    """A safety filter or an exhausted token budget leaves no text to parse."""
    class _Empty:
        class models:
            @staticmethod
            def generate_content(**kwargs):
                return type("R", (), {"text": None})()

    monkeypatch.setattr(gemini_provider, "_get_client", lambda: _Empty())
    assert gemini_provider.complete_json("system", "prompt") is None


def test_gemini_parses_json_mode_output(monkeypatch):
    class _Json:
        class models:
            @staticmethod
            def generate_content(**kwargs):
                return type("R", (), {"text": '{"attack_type": "ransomware"}'})()

    monkeypatch.setattr(gemini_provider, "_get_client", lambda: _Json())
    assert gemini_provider.complete_json("s", "p") == {"attack_type": "ransomware"}


@pytest.mark.parametrize("backend", [anthropic_provider, gemini_provider])
@pytest.mark.parametrize("payload,expected", [
    ('{"a": 1}', {"a": 1}),
    ('```json\n{"a": 1}\n```', {"a": 1}),
    ('Here you go:\n{"a": 1}\nHope that helps.', {"a": 1}),
    ("not json at all", None),
    ("", None),
    ("[1, 2, 3]", None),
])
def test_json_extraction_handles_the_shapes_models_actually_return(backend, payload,
                                                                   expected):
    assert backend._parse_json(payload) == expected
