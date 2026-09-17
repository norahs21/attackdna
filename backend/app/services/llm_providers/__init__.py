"""LLM provider backends.

Each backend exposes the same four names, and nothing else:

    available() -> bool
    complete_json(system, prompt, max_tokens, effort) -> dict | None
    diagnose() -> dict
    model_name() -> str

`llm_client` picks one and dispatches to it. Everything upstream — DNA
extraction, the simulator, Ask-the-memory — only ever sees `llm_client`, so
adding a provider touches this package and nowhere else.
"""
