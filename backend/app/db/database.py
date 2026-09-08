"""Persistence layer for ATTACKDNA.

Privacy note, and the most important design decision in this file: the raw
incident report is **not stored by default**. `raw_text` is only populated
when a caller explicitly opts in (`store_raw=True`). The system's durable
record of an incident is the sanitized text plus its Attack DNA — which is all
the analytics ever need. That way "we don't keep your identifying data" is a
property of the schema, not a promise in a slide.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, List

from sqlalchemy import (
    Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from app.config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()


def new_id(prefix: str = "inc") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class IncidentDB(Base):
    """A sanitized incident and its extracted Attack DNA."""

    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=new_id)
    title = Column(String, nullable=True)
    source = Column(String, nullable=True, default="upload")
    occurred_at = Column(DateTime, nullable=True)

    # Opt-in only — see the module docstring.
    raw_text = Column(Text, nullable=True)
    sanitized_text = Column(Text, nullable=False)

    # --- Attack DNA ---
    attack_type = Column(String, index=True, nullable=True)
    initial_vector = Column(String, index=True, nullable=True)
    sector = Column(String, index=True, nullable=True)
    severity = Column(String, index=True, nullable=True)
    signature = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    extraction_mode = Column(String, nullable=True)

    # JSON-encoded lists/dicts (SQLite-friendly, no dialect-specific types).
    tactics = Column(Text, default="[]")
    techniques = Column(Text, default="[]")
    cves = Column(Text, default="[]")
    cve_details = Column(Text, default="[]")
    impacts = Column(Text, default="[]")
    ioc_classes = Column(Text, default="{}")

    redaction_count = Column(Integer, default=0)
    embedding_text = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    mitigations = relationship(
        "MitigationDB",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="MitigationDB.position",
    )

    # ---- JSON helpers keep call sites free of encode/decode noise ----
    def get_json(self, field: str, default: Any = None) -> Any:
        try:
            return json.loads(getattr(self, field) or "null") or (
                default if default is not None else []
            )
        except (json.JSONDecodeError, TypeError):
            return default if default is not None else []

    def set_json(self, field: str, value: Any) -> None:
        setattr(self, field, json.dumps(value, ensure_ascii=False, default=str))

    def technique_ids(self) -> List[str]:
        return [t.get("id") for t in self.get_json("techniques", []) if isinstance(t, dict)]

    def to_dict(self, include_raw: bool = False) -> dict:
        payload = {
            "id": self.id,
            "title": self.title,
            "source": self.source,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
            "sanitized_text": self.sanitized_text,
            "attack_type": self.attack_type,
            "initial_vector": self.initial_vector,
            "sector": self.sector,
            "severity": self.severity,
            "signature": self.signature,
            "summary": self.summary,
            "root_cause": self.root_cause,
            "extraction_mode": self.extraction_mode,
            "tactics": self.get_json("tactics", []),
            "techniques": self.get_json("techniques", []),
            "cves": self.get_json("cves", []),
            "cve_details": self.get_json("cve_details", []),
            "impacts": self.get_json("impacts", []),
            "ioc_classes": self.get_json("ioc_classes", {}),
            "redaction_count": self.redaction_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "mitigations": [m.to_dict() for m in self.mitigations],
        }
        if include_raw:
            payload["raw_text"] = self.raw_text
        return payload


class MitigationDB(Base):
    """One response action taken for an incident.

    Stored per-action rather than as free text so Mitigation Memory can rank
    what actually worked across many incidents.
    """

    __tablename__ = "mitigations"

    id = Column(String, primary_key=True, default=lambda: new_id("mit"))
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    action = Column(Text, nullable=False)
    category = Column(String, nullable=True)      # contain | eradicate | recover | harden | detect
    effectiveness = Column(Float, nullable=True)  # 0.0 - 1.0, as reported by the responders
    notes = Column(Text, nullable=True)
    position = Column(Integer, default=0)

    incident = relationship("IncidentDB", back_populates="mitigations")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "action": self.action,
            "category": self.category,
            "effectiveness": self.effectiveness,
            "notes": self.notes,
            "position": self.position,
        }


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_session():
    """FastAPI dependency yielding a scoped session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
