"""Request/response schemas for the ATTACKDNA API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class MitigationIn(BaseModel):
    action: str = Field(..., min_length=3, description="What the responders did")
    category: str = Field("contain", description="detect | contain | eradicate | recover | harden")
    effectiveness: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="How well it worked, as rated by the responders"
    )
    notes: Optional[str] = None


class AnalyzeRequest(BaseModel):
    """Run the pipeline without storing anything."""

    text: str = Field(..., min_length=20, description="Raw incident report")
    top_k: int = Field(5, ge=1, le=20)
    use_llm: bool = True
    include_simulation: bool = True


class IngestRequest(BaseModel):
    """Run the pipeline and commit the incident to memory."""

    text: str = Field(..., min_length=20)
    title: Optional[str] = None
    source: str = "upload"
    occurred_at: Optional[datetime] = None
    mitigations: List[MitigationIn] = Field(default_factory=list)
    store_raw: bool = Field(
        False,
        description="Keep the original un-sanitized report. Off by default: the "
                    "system's durable record is the sanitized text plus its DNA.",
    )
    use_llm: bool = True
    top_k: int = Field(5, ge=1, le=20)


class SanitizeRequest(BaseModel):
    text: str = Field(..., min_length=1)


class SearchRequest(BaseModel):
    """Ask memory: have we seen this attack pattern before?"""

    text: str = Field(..., min_length=20)
    top_k: int = Field(5, ge=1, le=20)
    use_llm: bool = True


class SimulateRequest(BaseModel):
    """Build a tabletop exercise from free text or from a stored incident."""

    text: Optional[str] = Field(None, min_length=20)
    incident_id: Optional[str] = None
    use_llm: bool = True


class MitigationAppendRequest(BaseModel):
    mitigations: List[MitigationIn] = Field(..., min_length=1)


class PipelineResponse(BaseModel):
    """Free-form so the pipeline can evolve without breaking clients."""

    privacy: Dict[str, Any]
    dna: Dict[str, Any]
    similar_incidents: List[Dict[str, Any]]
    mitigations: Dict[str, Any]
    simulation: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any]
    incident_id: Optional[str] = None
    incident: Optional[Dict[str, Any]] = None
