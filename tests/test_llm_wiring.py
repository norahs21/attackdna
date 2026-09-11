"""Tests for the optional Claude API layer.

Two things matter and neither involves calling the API: the key must never
escape, and a broken key must degrade the system rather than break it — while
still being diagnosable, because silent degradation during setup is its own bug.
"""
import pytest

from app.services import llm_client


# --- The key must not leak ------------------------------------------------
def test_diagnose_never_returns_the_key(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_API_KEY", "sk-ant-supersecret-value-12345")
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)
    monkeypatch.setattr(llm_client, "_get_client", lambda: None)

    blob = repr(llm_client.diagnose())
    assert "supersecret" not in blob


def test_stats_endpoint_exposes_the_model_but_not_the_key(clean_memory):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        body = client.get("/stats").json()

    assert "model" in body["llm"]
    assert "key" not in repr(body).lower().replace("known_exploited", "")


def test_the_env_file_is_gitignored():
    """The one mistake that cannot be undone once pushed."""
    from pathlib import Path

    gitignore = (Path(__file__).resolve().parent.parent / ".gitignore").read_text()
    assert ".env" in gitignore
    assert "backend/.env" in gitignore


# --- Diagnosis names the cause -------------------------------------------
def test_a_missing_key_is_reported_as_such(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_API_KEY", "")
    result = llm_client.diagnose()

    assert result["ok"] is False
    assert result["stage"] == "no_key"
    assert result["remedy"], "every failure must name a fix"


def test_a_placeholder_key_is_reported_as_such(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_API_KEY", "your_key_here")
    monkeypatch.setattr(llm_client, "LLM_ENABLED", False)
    result = llm_client.diagnose()

    assert result["stage"] == "placeholder_key"
    assert "console.anthropic.com" in result["remedy"]


def _api_error(exc_class, status: int):
    """Build a real SDK exception — these need a genuine httpx response."""
    import httpx2 as httpx

    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    response = httpx.Response(status, request=request)
    return exc_class("simulated failure", response=response, body=None)


@pytest.mark.parametrize("exc_name,status,expected_stage", [
    ("AuthenticationError", 401, "auth_failed"),
    ("PermissionDeniedError", 403, "permission_denied"),
    ("NotFoundError", 404, "model_not_found"),
    ("RateLimitError", 429, "rate_limited"),
])
def test_each_api_failure_is_diagnosed_distinctly(monkeypatch, exc_name, status,
                                                  expected_stage):
    """A rejected key, a forbidden model and no credit need different fixes."""
    import anthropic

    exc = _api_error(getattr(anthropic, exc_name), status)

    class _Failing:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise exc

    monkeypatch.setattr(llm_client, "LLM_API_KEY", "sk-ant-wrong")
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)
    monkeypatch.setattr(llm_client, "_get_client", lambda: _Failing())

    result = llm_client.diagnose()
    assert result["stage"] == expected_stage
    assert result["ok"] is False
    assert result["remedy"], "every diagnosed failure must name a fix"


def test_diagnose_never_raises(monkeypatch):
    """However it fails, setup must get an answer rather than a traceback."""
    class _Exploding:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise RuntimeError("something entirely unexpected")

    monkeypatch.setattr(llm_client, "LLM_API_KEY", "sk-ant-test")
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)
    monkeypatch.setattr(llm_client, "_get_client", lambda: _Exploding())

    result = llm_client.diagnose()
    assert result["ok"] is False
    assert result["stage"] == "unexpected"


# --- Failure degrades, never breaks --------------------------------------
def test_a_failing_call_returns_none_rather_than_raising(monkeypatch):
    class _Failing:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise RuntimeError("API down")

    monkeypatch.setattr(llm_client, "_get_client", lambda: _Failing())
    monkeypatch.setattr(llm_client, "_effort_unsupported", True)

    assert llm_client.complete_json("system", "prompt") is None


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

    monkeypatch.setattr(llm_client, "_get_client", lambda: _Picky())
    monkeypatch.setattr(llm_client, "_effort_unsupported", False)

    assert llm_client.complete_json("system", "prompt") == {"ok": True}
    assert len(calls) == 2
    assert "output_config" in calls[0] and "output_config" not in calls[1]


def test_a_refusal_is_treated_as_no_answer_not_a_crash(monkeypatch):
    class _Refusing:
        class messages:
            @staticmethod
            def create(**kwargs):
                return type("R", (), {"stop_reason": "refusal", "content": []})()

    monkeypatch.setattr(llm_client, "_get_client", lambda: _Refusing())
    assert llm_client.complete_json("system", "prompt") is None


@pytest.mark.parametrize("payload,expected", [
    ('{"a": 1}', {"a": 1}),
    ('```json\n{"a": 1}\n```', {"a": 1}),
    ('Here you go:\n{"a": 1}\nHope that helps.', {"a": 1}),
    ("not json at all", None),
    ("", None),
    ('[1, 2, 3]', None),
])
def test_json_extraction_handles_the_shapes_models_actually_return(payload, expected):
    assert llm_client._parse_json(payload) == expected
