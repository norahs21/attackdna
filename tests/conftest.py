"""Test fixtures.

Every test runs against a throwaway SQLite database and a throwaway vector
store, so the suite never touches the demo corpus.
"""
import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

# Point the app at temporary storage BEFORE app.config is imported anywhere.
_tmp = tempfile.mkdtemp(prefix="attackdna-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_tmp) / 'test.db'}"
os.environ["CHROMA_DIR"] = str(Path(_tmp) / "chroma")
os.environ.setdefault("LLM_API_KEY", "")

import pytest  # noqa: E402

from app.db.database import Base, SessionLocal, engine  # noqa: E402
from app.services import vector_memory  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _schema():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def clean_memory(session):
    """A database and vector store emptied before and after the test."""
    from app.db.database import IncidentDB

    def _wipe():
        session.query(IncidentDB).delete()
        session.commit()
        vector_memory.reset_memory()

    _wipe()
    yield session
    _wipe()
