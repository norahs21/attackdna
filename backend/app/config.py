"""Central configuration for ATTACKDNA.

Everything is environment-driven with safe defaults so the project runs
out of the box (offline, no API key) and scales up when a key is present.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

# backend/app/config.py -> backend/app -> backend -> project root
BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent

load_dotenv(BACKEND_DIR / ".env")

# --- Database ---
def _resolve_database_url(raw: str) -> str:
    """Anchor relative SQLite paths to backend/ instead of the working directory.

    Without this, `sqlite:///./attackdna.db` means a different file depending on
    where the command was run from — so seeding from the project root and
    serving from backend/ would silently use two separate databases.
    """
    for prefix in ("sqlite:///./", "sqlite:///"):
        if raw.startswith(prefix):
            path = raw[len(prefix):]
            if path and not path.startswith("/"):
                return f"sqlite:///{(BACKEND_DIR / path).resolve()}"
            break
    return raw


DATABASE_URL = _resolve_database_url(
    os.getenv("DATABASE_URL", f"sqlite:///{BACKEND_DIR / 'attackdna.db'}")
)

# --- LLM ---
LLM_API_KEY = os.getenv("LLM_API_KEY", "").strip()
LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-6")
# A placeholder key must never be treated as usable.
LLM_ENABLED = bool(LLM_API_KEY) and LLM_API_KEY not in {"your_key_here", "changeme"}

# --- Knowledge bases (produced by scripts/process_*.py) ---
DATA_DIR = PROJECT_ROOT / "data"
TECHNIQUES_PATH = DATA_DIR / "processed" / "techniques.json"
KEV_PATH = DATA_DIR / "processed" / "kev_lookup.json"
# CTI layers, produced by scripts/process_cti.py
MITIGATIONS_PATH = DATA_DIR / "processed" / "mitigations.json"
GROUPS_PATH = DATA_DIR / "processed" / "groups.json"
SOFTWARE_PATH = DATA_DIR / "processed" / "software.json"
CAMPAIGNS_PATH = DATA_DIR / "processed" / "campaigns.json"
SEED_INCIDENTS_PATH = DATA_DIR / "seed" / "incidents.json"
DEMO_SCENARIOS_PATH = DATA_DIR / "seed" / "demo_scenarios.json"
EVALUATION_SET_PATH = DATA_DIR / "seed" / "evaluation_set.json"

# --- Vector memory ---
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
# Relative paths are anchored to the project root for the same cwd-independence
# reason as DATABASE_URL above.
_chroma_raw = Path(os.getenv("CHROMA_DIR", DATA_DIR / "chroma"))
CHROMA_DIR = _chroma_raw if _chroma_raw.is_absolute() else (PROJECT_ROOT / _chroma_raw).resolve()
COLLECTION_NAME = "attack_dna"

# --- Retrieval tuning ---
SIMILARITY_TOP_K = int(os.getenv("SIMILARITY_TOP_K", "5"))
SIMILARITY_THRESHOLD = float(os.getenv("SIMILARITY_THRESHOLD", "0.25"))
