# 🧬 ATTACKDNA

**An AI-powered cyber memory that turns past incidents into reusable attack intelligence.**

Every organisation solves the same attack twice. The first time it is an incident;
the second time it should be a lookup. It usually isn't, because the useful part of
an incident report is buried inside data nobody is allowed to share.

ATTACKDNA separates the two. It strips the victim's identity out of an incident
report and keeps the attack's *behaviour* — its **Attack DNA** — as a searchable,
shareable record. The next incident that looks like it gets answered with what
actually worked last time.

---

## The pipeline

```
                        Incident Report
                              │
                    ① Privacy Layer            deterministic redaction
                              ▼
                       Sanitized Incident
                              │
                    ② Attack DNA extraction    hybrid rules + LLM
                              ▼
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
       MITRE ATT&CK     Vector Memory     CISA KEV
         709 techniques   ChromaDB        1,695 known-exploited CVEs
              └───────────────┼───────────────┘
                              ▼
                    ③ Similar Incidents        explainable re-ranking
                              ▼
                    ④ Mitigation Memory        what worked before, cited
                              ▼
                    ⑤ Safe Simulation          defensive tabletop exercise
```

---

## Quick start

```bash
make setup     # virtualenv + dependencies
make data      # download & process MITRE ATT&CK and CISA KEV
make seed      # load the historical incident corpus into memory
make demo      # http://localhost:8501
```

No API key is required. Without one the system runs in **rule-based mode**: every
stage still executes, extraction is deterministic instead of model-assisted. Add a
key to `backend/.env` to enable hybrid mode.

To explore the API instead of the UI:

```bash
make api       # http://localhost:8000/docs
```

---

## What makes each stage defensible

### ① Privacy Layer — `backend/app/services/sanitizer.py`

Redaction is done with regular expressions, not a model. A regex cannot decide to
leak an IP address.

- **Fails closed.** The optional LLM pass may only *add* redactions, never remove them.
- **Analytically lossless.** The same value always maps to the same token, so
  "one attacker mailbox" and "three attacker mailboxes" stay distinguishable.
  A single value of a type renders as `[IP_REDACTED]`; multiple distinct values
  become `[IP_REDACTED_1]`, `[IP_REDACTED_2]`.
- **Preserves the fingerprint.** CVE ids, ATT&CK technique ids and file hashes are
  the *attack's* identity, not the victim's, so they are explicitly protected.
- **Self-verifying.** `verify_clean()` re-scans the sanitized output for
  high-risk identifiers. The UI shows the result as a PASS/FAIL, so the privacy
  claim is demonstrated rather than asserted.

```
john@company.sa   →  [EMAIL_REDACTED]
10.10.23.41       →  [IP_REDACTED]
CVE-2024-21412    →  CVE-2024-21412     (preserved — this is the attack's DNA)
```

### ② Attack DNA — `backend/app/services/dna_extractor.py`

The reusable fingerprint of an incident:

| Field | Meaning |
|---|---|
| `attack_type` | What the incident *became* (ransomware, data breach, BEC, …) |
| `initial_vector` | How it *started* (phishing, credential attack, web exploitation, …) |
| `techniques` / `tactics` | MITRE ATT&CK mapping, each with the evidence behind it |
| `cve_details` / `kev` | CVEs enriched with the CISA KEV catalog |
| `impacts` | Encryption, exfiltration, disruption, financial loss, … |
| `severity` | Derived from impact, KEV status and chain length |
| `signature` | A compact, kill-chain-ordered fingerprint |

Splitting `attack_type` from `initial_vector` matters: phishing that ends in
ransomware is a **ransomware** incident that *arrived by* phishing. Filing it as
"phishing" would sit it next to the wrong playbooks.

### ③ Vector Memory — `backend/app/services/vector_memory.py`

Only DNA-derived text is embedded — never the report — so the vector store is
structurally incapable of holding victim identifiers. Backends, in preference order:

1. `sentence-transformers` (`all-MiniLM-L6-v2`) if installed
2. ChromaDB's bundled ONNX MiniLM — the same model, no torch (**default**)
3. TF-IDF — no downloads, works fully offline

### ④ Similar Incidents — `backend/app/services/similarity.py`

Embedding distance alone is a poor answer to "have we seen this before?". Two
reports written in similar prose can score 0.95 while sharing no behaviour, and the
analyst has no way to check the machine's work. So retrieval is two-stage:

1. **Recall** — vector memory returns semantically nearby DNA.
2. **Re-rank** — candidates are re-scored on *structural* overlap: shared ATT&CK
   techniques, shared tactics, attack type, initial vector, shared CVEs, sector.

Every match carries the reasons that produced it:

```
0.77 — Ransomware via phishing link — regional bank
       - 4 shared ATT&CK technique(s): T1059.001, T1486, T1490, T1566.002
       - Overlapping kill-chain phases: execution, impact, initial-access, lateral-movement
       - Same attack type: ransomware
```

The two sub-scores are reported separately, which is what shows the re-rank doing
real work: on the demo corpus, five ransomware incidents all score 0.92–0.97
semantically, and only structural overlap separates them.

### ⑤ Mitigation Memory — `backend/app/services/mitigation_memory.py`

Ranks what was actually done before, blending source-incident similarity, the
effectiveness responders recorded, and how many separate incidents used the action.
Recalled actions cite the incident they came from. Where memory has no coverage for
an observed technique, ATT&CK-aligned baseline controls fill the gap and are clearly
labelled `suggested` — recalled and generated advice never blur.

```
Contain
  [recalled · used in 5 past incidents · avg effectiveness 92%]  Isolate affected endpoints immediately
  [recalled · used in 2 past incidents · avg effectiveness 95%]  Disable the compromised account and revoke sessions
  [baseline control]                                             Alert on service creation over SMB from non-admin hosts
```

### ⑥ Safe Simulation — `backend/app/services/simulator.py`

Produces a **defensive tabletop exercise**: injects the SOC is told about, the
detection that should fire, its telemetry source, and the decision the team must
make. It contains no payloads, commands, exploit code, phishing copy or attacker
infrastructure — and `tests/test_pipeline.py` asserts that.

This is not a limitation bolted on afterwards. A tabletop tests whether detection
and response actually work, which is the question a SOC has. Generating a working
attack would answer no question the organisation is asking.

---

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/incidents/sanitize` | Privacy Layer only — demonstrate redaction in isolation |
| `POST` | `/incidents/analyze` | Full pipeline, stores nothing |
| `POST` | `/incidents/` | Full pipeline, commits to memory |
| `GET` | `/incidents/` | List / filter stored incidents |
| `GET` | `/incidents/{id}` | Fetch one incident |
| `POST` | `/incidents/{id}/mitigations` | Record what was done — closes the learning loop |
| `DELETE` | `/incidents/{id}` | Delete and forget |
| `POST` | `/incidents/reindex` | Rebuild vector memory from the database |
| `POST` | `/search` | "Have we seen this attack pattern before?" |
| `POST` | `/simulate` | Generate a tabletop from text or a stored incident |
| `GET` | `/stats` | Corpus and knowledge-base statistics |

---

## Privacy by construction

The privacy promise is enforced by the schema, not by convention:

- `raw_text` is **`NULL` by default**. Storing the original report requires an
  explicit `store_raw=True`. The durable record is the sanitized text plus its DNA.
- The vector store only ever receives `dna["embedding_text"]`, built from DNA
  fields — never from the report.
- The token→original map stays in memory for the audit panel; it is never persisted,
  embedded, or sent to a model.
- The LLM, when enabled, only ever sees text that has already been sanitized.

`tests/test_pipeline.py` asserts each of these.

---

## Project layout

```
backend/app/
  config.py                    environment-driven configuration
  db/database.py               SQLAlchemy models (raw_text NULL by default)
  models/schemas.py            request/response contracts
  services/
    sanitizer.py               ① Privacy Layer
    knowledge_base.py          MITRE ATT&CK + CISA KEV loaders
    mitre_mapper.py            behaviour → ATT&CK, with evidence
    kev_enricher.py            CVE → known-exploited status
    dna_extractor.py           ② Attack DNA
    llm_client.py              optional Claude wrapper, fails soft
    vector_memory.py           ③ Vector Memory (3-tier backend)
    similarity.py              ④ explainable re-ranking
    mitigation_memory.py       ⑤ what worked before
    simulator.py               ⑥ safe tabletop generation
  pipelines/analyze.py         analyze() / ingest() / reindex_memory()
  routes/                      FastAPI endpoints
frontend/app.py                Streamlit demo — the full six-step journey
scripts/                       data download/processing + memory seeding
data/
  processed/                   ATT&CK techniques + KEV lookup (committed)
  seed/incidents.json          synthetic historical corpus
tests/                         62 tests
```

---

## Testing

```bash
make test
```

62 tests covering redaction correctness, fingerprint preservation, ATT&CK mapping
precision, DNA classification, memory recall and ranking, the API contract, and the
simulation safety boundary.

---

## Notes on the data

- **MITRE ATT&CK** and **CISA KEV** are refreshed with `make data`. Current ATT&CK
  releases split the old `defense-evasion` tactic into `stealth` and
  `defense-impairment`; both spellings are handled.
- `data/seed/incidents.json` is **entirely synthetic**. Every organisation, person
  and identifier is invented. The reports are stored un-sanitized on purpose:
  seeding runs them through the real Privacy Layer, so the seeded corpus is proof
  the pipeline works rather than a hand-cleaned shortcut.
