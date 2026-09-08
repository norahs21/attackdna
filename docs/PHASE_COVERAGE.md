# Phase coverage map

Every task from the project plan, mapped to where it lives in the repository
and how it can be verified. Use this to tick off the spreadsheet.

Legend: ✅ done · ⬜ your task (presentation / submission work)

---

## Phase 1 — Project Setup

| Task | Status | Where |
|---|---|---|
| Create Git Repository | ✅ | repository root |
| Set Up Python Environment | ✅ | `make setup` |
| Create Project Structure | ✅ | `backend/`, `frontend/`, `scripts/`, `data/`, `tests/` |
| Configure Environment Variables | ✅ | `.env.example`, `backend/app/config.py` |
| Set Up Backend | ✅ | `backend/app/main.py` (FastAPI) |
| Set Up Database | ✅ | `backend/app/db/database.py` (SQLAlchemy + SQLite) |
| Define Data Models | ✅ | `IncidentDB`, `MitigationDB` |

## Phase 2 — Data Preparation

| Task | Status | Where |
|---|---|---|
| Download MITRE ATT&CK Data | ✅ | `scripts/download_mitre.py` |
| Process MITRE Techniques & Tactics | ✅ | `scripts/process_mitre.py` — 709 techniques |
| Download CISA KEV Data | ✅ | `scripts/download_kev.py` |
| Process CVE Information | ✅ | `scripts/process_kev.py` — 1,695 CVEs |
| Select Public CTI Sources | ✅ | ATT&CK groups, software, campaigns, mitigations |
| Process CTI Data | ✅ | `scripts/process_cti.py` — 172 groups, 825 software, 56 campaigns, 44 mitigations |
| Design Incident Dataset Schema | ✅ | `data/seed/incidents.json` schema |
| Create Synthetic Incident Reports | ✅ | 14 incidents across 10 sectors |
| Map Incidents to MITRE Techniques | ✅ | done at seed time by the real pipeline |
| Store Datasets Locally | ✅ | `data/processed/` (committed, works offline) |

## Phase 3 — Privacy Sanitization

| Task | Status | Where |
|---|---|---|
| Define Sensitive Data Types | ✅ | `REDACTION_PATTERNS` — 15 entity types |
| Build Privacy Sanitization Pipeline | ✅ | `services/sanitizer.py` |
| Detect Sensitive Corporate Identifiers | ✅ | orgs, hostnames, accounts, user paths, secrets |
| Sanitize Incident Reports | ✅ | `sanitize()` |
| Validate Sanitized Output | ✅ | `verify_clean()` — independent second pass |
| Test Privacy Pipeline | ✅ | `tests/test_sanitizer.py` — 13 tests |

## Phase 4 — Attack DNA Extraction

| Task | Status | Where |
|---|---|---|
| Define Attack DNA Schema | ✅ | `REQUIRED_FIELDS` in `dna_extractor.py` |
| Build Attack DNA Extraction Pipeline | ✅ | `extract_dna()` |
| Extract Attack Type | ✅ | 10 types + decisive markers · **100%** accuracy |
| Extract MITRE Tactics | ✅ | kill-chain ordered |
| Extract MITRE Techniques | ✅ | **87% precision / 86% recall** |
| Extract IoCs | ✅ | `services/ioc_extractor.py` — shareable vs. victim-linked |
| Extract CVEs | ✅ | `services/kev_enricher.py` |
| Extract Target Sector | ✅ | 10 sectors · **100%** accuracy |
| Extract Impact | ✅ | 6 impact classes · 81% recall |
| Validate Attack DNA Output | ✅ | `validate_dna()` runs on every extraction |
| Test Attack DNA Extraction | ✅ | `tests/test_dna_and_mapping.py` |

## Phase 5 — Threat Intelligence Mapping

| Task | Status | Where |
|---|---|---|
| Map Attack DNA to MITRE ATT&CK | ✅ | `services/mitre_mapper.py` |
| Retrieve Technique Details | ✅ | `describe_technique()` |
| Retrieve Tactics | ✅ | `sort_tactics()` |
| Retrieve Relevant Mitigations | ✅ | official M#### via `_framework_mitigations()` |
| Match CVEs with CISA KEV | ✅ | `enrich_cves()` + required action |
| Enrich Incidents with CTI | ✅ | `services/attribution.py` — groups, software, campaigns |
| Validate Threat Intelligence Results | ✅ | `tests/test_cti_and_iocs.py` |

## Phase 6 — Cyber Memory

| Task | Status | Where |
|---|---|---|
| Define Incident Embedding Strategy | ✅ | `embedding_text()` — DNA fields only, never the report |
| Generate Incident Embeddings | ✅ | MiniLM-L6-v2 |
| Set Up Vector Database | ✅ | ChromaDB, persistent |
| Store Historical Incidents | ✅ | `vector_memory.remember()` |
| Store Attack DNA Metadata | ✅ | flattened metadata on each vector |
| Implement Semantic Search | ✅ | `vector_memory.find_similar()` |
| Retrieve Similar Historical Incidents | ✅ | `similarity.find_similar_incidents()` |
| Rank Similar Incidents | ✅ | two-stage: semantic recall + structural re-rank |
| Test Retrieval Accuracy | ✅ | `scripts/evaluate.py` — **precision@1 = 100%** |

## Phase 7 — Mitigation Retrieval

| Task | Status | Where |
|---|---|---|
| Extract Previous Mitigations | ✅ | `MitigationDB` per action |
| Link Mitigations to Historical Incidents | ✅ | every recalled action cites its source |
| Rank Relevant Mitigations | ✅ | similarity × effectiveness × reuse |
| Remove Duplicate Recommendations | ✅ | de-duplicated across all three origins |
| Display Previous Mitigation Steps | ✅ | grouped by response phase in the UI |

## Phase 8 — Safe Attack Simulation

| Task | Status | Where |
|---|---|---|
| Define Simulation Schema | ✅ | `build_simulation()` |
| Generate Safe Attack Scenarios | ✅ | defensive tabletop injects |
| Link Scenarios to Attack DNA | ✅ | injects derive from observed tactics |
| Link Scenarios to MITRE Techniques | ✅ | each inject names its techniques |
| Define Target Context | ✅ | `headline.target` |
| Define Expected Detections | ✅ | `DETECTION_CATALOG` + telemetry source |
| Define Recommended Controls | ✅ | `_headline_controls()` |
| Define Expected Response Actions | ✅ | `RESPONSE_ACTIONS` per phase |
| Validate Simulation Safety | ✅ | test asserts no executable content |

## Phase 9 — Frontend

| Task | Status | Where |
|---|---|---|
| Design Dashboard | ✅ | `frontend/app.py` |
| Add Incident Upload | ✅ | file upload + paste |
| Add Demo Incident | ✅ | 4 prepared scenarios |
| Display Privacy Sanitization | ✅ | redactions highlighted + audit table |
| Display Attack DNA | ✅ | signature, type, vector, sector, severity |
| Display MITRE Mapping | ✅ | with evidence and confidence per technique |
| Display Threat Intelligence | ✅ | KEV, IoC profile, group/software resemblance |
| Display Similar Incidents | ✅ | with match reasons and sub-scores |
| Display Previous Mitigations | ✅ | recalled / framework / baseline, labelled |
| Display Safe Simulation | ✅ | headline card + injects + success criteria |
| Add Loading & Error States | ✅ | spinner, error surface, empty states |

## Phase 10 — System Integration

| Task | Status | Where |
|---|---|---|
| Connect Frontend to Backend | ✅ | in-process by default, HTTP via `ATTACKDNA_API_URL` |
| Connect Privacy Pipeline | ✅ | `pipelines/analyze.py` stage 1 |
| Connect Attack DNA Pipeline | ✅ | stage 2 |
| Connect MITRE Data | ✅ | `knowledge_base.py` |
| Connect CISA KEV | ✅ | `kev_enricher.py` |
| Connect CTI | ✅ | `attribution.py` |
| Connect Vector Database | ✅ | `vector_memory.py` |
| Connect Mitigation Retrieval | ✅ | stage 4 |
| Connect Safe Simulation | ✅ | stage 5 |
| Test End-to-End Workflow | ✅ | `tests/test_pipeline.py`, `tests/test_api.py` |

## Phase 11 — Testing

| Task | Status | Where |
|---|---|---|
| Functional Testing | ✅ | 93 tests |
| AI Output Testing | ✅ | `tests/test_dna_and_mapping.py` |
| Attack DNA Accuracy Testing | ✅ | `make eval` — 100% type / sector / vector |
| MITRE Mapping Testing | ✅ | F1 = 84% on labelled cases |
| Similarity Search Testing | ✅ | precision@1 = 100% |
| Mitigation Relevance Testing | ✅ | citation and ranking assertions |
| Privacy Testing | ✅ | 13 tests + 0 residual leaks across all cases |
| Edge Case Testing | ✅ | empty input, no techniques, unparseable text |
| Error Handling Testing | ✅ | 404/400/422 paths, LLM failure fallback |
| Performance Testing | ✅ | 5 s budget per scenario; mean 0.40 s |

## Phase 12 — Demo Preparation

| Task | Status | Where |
|---|---|---|
| Prepare Financial Services Scenario | ✅ | `demo_scenarios.json` → `financial_services` |
| Prepare Healthcare Scenario | ✅ | → `healthcare` |
| Prepare Vulnerability Scenario | ✅ | → `vulnerability` |
| Prepare Historical Similar Incident | ✅ | → `near_miss` |
| Prepare Demo Dataset | ✅ | `data/seed/incidents.json` |
| Preload External Datasets | ✅ | `data/processed/` committed |
| Cache Embeddings | ✅ | ChromaDB persists to `data/chroma/` |
| Minimize API Calls | ✅ | LLM optional; rule path makes zero calls |
| Add Demo Mode | ✅ | sidebar toggle + presenter notes per scenario |
| Test Demo Without Internet | ✅ | `test_the_pipeline_runs_with_no_network` |
| Test Full Demo Multiple Times | ✅ | determinism tests |

## Phase 13 — Final Presentation

| Task | Status | Notes |
|---|---|---|
| Prepare Problem Statement | ⬜ | Every organisation solves the same attack twice — see README opening |
| Prepare Solution Explanation | ⬜ | README pipeline diagram |
| Prepare Attack DNA Explanation | ⬜ | README "Attack DNA" table |
| Prepare Architecture Explanation | ⬜ | README diagram + this file |
| Prepare Live Demo | ⬜ | `make demo`, demo mode on, walk the 4 scenarios |
| Prepare Impact | ⬜ | use the measured numbers from `make eval` |
| Prepare Future Work | ⬜ | suggestions below |
| Prepare Pitch | ⬜ | your work |
| Prepare Backup Demo Video | ⬜ | record one full run per scenario |
| Prepare Backup Screenshots | ⬜ | capture each of the six stages |

## Phase 14 — Final Submission

| Task | Status | Notes |
|---|---|---|
| Final Code Review | ✅ | consistent structure, documented modules |
| Final Security Review | ✅ | no secrets committed; `.env` gitignored; raw text not stored |
| Final Privacy Review | ✅ | 0 residual leaks; schema-enforced; validated per extraction |
| Final UI Review | ✅ | all six stages render, no exceptions |
| Final Documentation | ✅ | README + this coverage map |
| Final README | ✅ | `README.md` |
| Final Project PDF | ⬜ | export README or your slides |
| Backup Project Files | ⬜ | the repository is the backup; tag a release |
| Freeze MVP | ⬜ | tag when you stop changing code |
| Final Demo Run | ⬜ | `make reset && make eval && make demo` |
| Submit Project 🏆 | ⬜ | |

---

## Suggested "Future Work" slide content

Honest, concrete next steps — these read better than vague ambitions:

1. **Federated memory.** The privacy layer already makes incidents shareable;
   the natural next step is multiple organisations contributing to one memory
   without any of them seeing each other's raw reports.
2. **Detection-as-code output.** The simulation already names the expected
   detection and its telemetry source — emitting Sigma rules from that is a
   short step.
3. **Feedback loop on mitigation effectiveness.** Responders currently record
   effectiveness manually; capturing outcome data automatically would let the
   ranking learn.
4. **Arabic-language incident reports.** The regex layer is language-specific
   today; extending the vocabularies and adding Arabic name detection would
   widen the addressable market considerably.
5. **Evaluation set growth.** 8 labelled cases is enough to catch regressions,
   not enough to claim generalisation. Growing it is the cheapest way to make
   the accuracy numbers stronger.
