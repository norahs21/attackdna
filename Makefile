PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: help setup data seed api demo test clean reset

help:
	@echo "ATTACKDNA"
	@echo ""
	@echo "  make setup   Create the virtualenv and install dependencies"
	@echo "  make data    Download and process MITRE ATT&CK + CISA KEV"
	@echo "  make seed    Load the historical incident corpus into memory"
	@echo "  make demo    Run the Streamlit demo        (http://localhost:8501)"
	@echo "  make api     Run the FastAPI service        (http://localhost:8000/docs)"
	@echo "  make test    Run the test suite"
	@echo "  make reset   Wipe the database and vector memory, then reseed"

setup:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements.txt
	@test -f backend/.env || cp .env.example backend/.env
	@echo "Setup complete. Next: make data && make seed"

data:
	$(PY) scripts/download_mitre.py
	$(PY) scripts/process_mitre.py
	$(PY) scripts/download_kev.py
	$(PY) scripts/process_kev.py

seed:
	$(PY) scripts/seed_memory.py --reset

demo:
	.venv/bin/streamlit run frontend/app.py

api:
	cd backend && ../.venv/bin/uvicorn app.main:app --reload --port 8000

test:
	$(PY) -m pytest

reset:
	rm -f backend/attackdna.db
	rm -rf data/chroma
	$(PY) scripts/seed_memory.py --reset

clean:
	find . -name "__pycache__" -type d -not -path "./.venv/*" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
