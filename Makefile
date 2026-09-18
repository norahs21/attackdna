PY := .venv/bin/python
PIP := .venv/bin/pip

# Pick the newest Python that the dependency set actually supports.
#
# chromadb needs onnxruntime, which lags new Python releases by months — on
# 3.13 pip fails with ResolutionImpossible and takes the whole setup with it.
# Preferring 3.12 avoids that, and `setup` degrades gracefully if the vector
# extras cannot be installed at all.
PYTHON := $(shell command -v python3.12 || command -v python3.11 || \
                  command -v python3.10 || command -v python3)

.PHONY: help setup data seed api demo test eval check-llm clean reset all

help:
	@echo "ATTACKDNA"
	@echo ""
	@echo "  make all     Full setup: dependencies, data, seed  (run this first)"
	@echo "  make setup   Create the virtualenv and install dependencies"
	@echo "  make data    Download and process MITRE ATT&CK, CISA KEV and CTI layers"
	@echo "  make seed    Load the historical incident corpus into memory"
	@echo "  make demo    Run the Streamlit demo        (http://localhost:8501)"
	@echo "  make api     Run the FastAPI service        (http://localhost:8000/docs)"
	@echo "  make test    Run the test suite"
	@echo "  make eval    Measure accuracy against the labelled evaluation set"
	@echo "  make check-llm  Verify the Claude API key works and show what it adds"
	@echo "  make reset   Wipe the database and vector memory, then reseed"

all: setup data seed
	@echo ""
	@echo "ATTACKDNA is ready. Run 'make demo' to start."

setup:
	@echo "Using $(PYTHON) ($$($(PYTHON) --version 2>&1))"
	$(PYTHON) -m venv .venv
	# A venv ships an old pip, which cannot read the wheel tags of recent
	# releases and falls back to building from source — cryptography then needs
	# a Rust toolchain and the install dies. Upgrading first avoids all of it.
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -r backend/requirements.txt
	@echo ""
	@echo "Installing vector-search extras (optional)..."
	@$(PIP) install -r backend/requirements-vector.txt || ( \
	  echo ""; \
	  echo "  NOTE  ChromaDB could not be installed on this Python."; \
	  echo "        Everything still works: vector memory falls back to TF-IDF,"; \
	  echo "        which needs no downloads and runs offline. Retrieval matches"; \
	  echo "        on wording rather than meaning, so quality is lower."; \
	  echo "        To get semantic search, re-run setup on Python 3.12:"; \
	  echo "          rm -rf .venv && make setup PYTHON=\$$(command -v python3.12)"; \
	  echo "" )
	@test -f backend/.env || cp .env.example backend/.env
	@echo "Setup complete. Next: make seed"

data:
	$(PY) scripts/download_mitre.py
	$(PY) scripts/process_mitre.py
	$(PY) scripts/process_cti.py
	$(PY) scripts/download_kev.py
	$(PY) scripts/process_kev.py

eval:
	$(PY) scripts/evaluate.py

check-llm:
	$(PY) scripts/check_llm.py

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
