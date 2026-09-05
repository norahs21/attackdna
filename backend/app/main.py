from fastapi import FastAPI
from app.db.database import init_db

app = FastAPI(title="ATTACKDNA API")

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/")
def health():
    return {"status": "ATTACKDNA API running"}