"""ATTACKDNA API.

An AI-powered cyber memory that turns past incidents into reusable attack
intelligence — without ever retaining the victim's identifying data.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db.database import init_db
from app.routes import incidents, search, stats

DESCRIPTION = """
Upload an incident report and ATTACKDNA will:

1. **Sanitize it** — remove every identifying value with deterministic rules.
2. **Extract Attack DNA** — the reusable behavioural fingerprint of the attack.
3. **Map it to MITRE ATT&CK** and enrich CVEs with the **CISA KEV** catalog.
4. **Search memory** for similar historical incidents, with the evidence behind each match.
5. **Recall mitigations** that worked before, cited back to the incident they came from.
6. **Generate a safe simulation** — a defensive tabletop exercise, never an executable attack.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="ATTACKDNA API",
    description=DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
)

# The Streamlit demo runs on a different port, so it needs CORS. Tighten the
# origin list before this is exposed anywhere beyond a local demo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(incidents.router)
app.include_router(search.router)
app.include_router(stats.router)


@app.get("/", tags=["health"], summary="Health check")
def health():
    return {"status": "ok", "service": "ATTACKDNA API", "version": "1.0.0", "docs": "/docs"}
