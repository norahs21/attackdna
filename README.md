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
        ┌─────────────┬───────┼────────┬──────────────┐
        ▼             ▼       ▼        ▼              ▼
  MITRE ATT&CK   CISA KEV  Vector   ATT&CK CTI    IoC profile
  709 techniques  1,695     Memory  44 mitigations  shareable vs.
                  KEV CVEs  ChromaDB 172 groups     victim-linked
        └─────────────┴───────┼────────┴──────────────┘
                              ▼
                    ③ Similar Incidents        explainable re-ranking
                              ▼
                    ④ Mitigation Memory        what worked before, cited
                              ▼
                    ⑤ Safe Simulation          defensive tabletop exercise
```

---

## Documentation

| Document | What it covers |
|---|---|
| [`docs/DEVELOPER_GUIDE_AR.md`](docs/DEVELOPER_GUIDE_AR.md) | دليل المطوّر بالعربي — الملفات، التشغيل، سير العمل، وأين تعدّل كل شيء |
| [`docs/PITCH_AR.md`](docs/PITCH_AR.md) | نص البيتش بالعربي + الردود على الأسئلة الصعبة + تشيك ليست العرض |
| [`docs/PHASE_COVERAGE.md`](docs/PHASE_COVERAGE.md) | All 142 plan tasks mapped to code and verification |

---

## Quick start

```bash
make all       # dependencies + knowledge bases + seeded memory
make demo      # http://localhost:8501
```

Or step by step:

```bash
make setup     # virtualenv + dependencies
make data      # download & process MITRE ATT&CK, CISA KEV and the CTI layers
make seed      # load the historical incident corpus into memory
make demo      # http://localhost:8501
make eval      # measure accuracy against the labelled evaluation set
```

### Measured results

`make eval` scores the pipeline against 8 labelled cases written independently
of the seed corpus. Current rule-based numbers (no API key, no network):

| Metric | Result |
|---|---|
| Attack type accuracy | **100%** |
| Initial vector accuracy | **100%** |
| Sector accuracy | **100%** |
| Severity band accuracy | **100%** |
| ATT&CK mapping precision / recall / F1 | **87% / 88% / 86%** |
| Memory retrieval precision@1 | **100%** |
| Privacy verified clean (0 residual leaks) | **100%** |
| Mean end-to-end latency | **0.40 s** |

No API key is required. Without one the system runs in **rule-based mode**: every
stage still executes, extraction is deterministic instead of model-assisted.

To enable the AI layer, put a key in `backend/.env` and verify it:

```bash
cp .env.example backend/.env     # then set LLM_API_KEY=sk-ant-...
make check-llm                   # proves the key works and shows what it adds
```

`make check-llm` makes one small real call and names the exact cause when it
fails — no key, placeholder key, rejected key, model not permitted, no credit,
or no network — because `complete_json` fails soft by design, and silent
degradation during setup is indistinguishable from having no key at all.

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

Every extraction is checked against the DNA schema (`validate_dna`), including
the privacy invariant that `embedding_text` may never contain a redaction token
or an email address. A malformed result is visible immediately, not three
stages later as an empty panel.

### IoC extraction — the tension, resolved

The Privacy Layer removes IPs, domains and mailboxes, which are exactly the
indicators a SOC normally shares. So indicators are split in two:

- **Shareable** — file hashes, CVEs, ransomware extensions, protocols, ports,
  registry keys. These identify the *attacker's tooling*, survive sanitization
  with their values intact, and are safe to circulate between organisations.
- **Victim-linked** — addresses, domains, mailboxes, hosts, accounts. Removed,
  but their *shape* is kept: "3 distinct network addresses, 1 mailbox". That is
  what keeps one compromised account distinguishable from fourteen.

### Threat intelligence — resemblance, not attribution

An incident's technique set is compared against the documented TTPs of 172
ATT&CK threat groups and 825 malware families and tools, weighted by technique
specificity (a technique used by 150 groups carries almost no signal; one used
by three carries a lot).

The output is deliberately conservative. Matches are labelled `weak`,
`moderate` or `notable` — **never "confirmed"** — and every result carries the
caveat that technique overlap indicates resemblance to how an actor is
*documented* to operate, not evidence that they did this. Real attribution
needs infrastructure and tooling evidence that a sanitized report deliberately
does not contain. Overstating this would be the easiest way for the system to
mislead a SOC, so the scoring is built to refuse to.

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

Recommendations come from three clearly-separated origins, and the label is
never dropped, because a defender needs to know how much weight to give each:

| Origin | Meaning |
|---|---|
| `recalled` | What **this organisation** actually did before, cited back to the incident |
| `framework` | An official **MITRE ATT&CK mitigation** (M####) for an observed technique |
| `suggested` | A concrete baseline control filling a gap neither covers |

Recalled actions are ranked by source-incident similarity, the effectiveness
responders recorded, and how many separate incidents used the action.

```
Contain
  [recalled · used in 5 past incidents · avg effectiveness 92%]  Isolate affected endpoints immediately
  [recalled · used in 2 past incidents · avg effectiveness 95%]  Disable the compromised account and revoke sessions
  [baseline control]                                             Alert on service creation over SMB from non-admin hosts

Official MITRE ATT&CK mitigations
  M1018  User Account Management         covers 4: T1021, T1078, T1490, T1566.002
  M1017  User Training                   covers 3: T1003, T1078, T1566.002
  M1026  Privileged Account Management   covers 3: T1003, T1059.001, T1078
```

### ⑥ Safe Simulation — `backend/app/services/simulator.py`

Produces a **defensive tabletop exercise**: injects the SOC is told about, the
detection that should fire, its telemetry source, the decision the team must
make, and the response actions a competent team should take. It contains no
payloads, commands, exploit code, phishing copy or attacker infrastructure —
and `tests/test_pipeline.py` asserts that.

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
    knowledge_base.py          ATT&CK, KEV and CTI loaders
    mitre_mapper.py            behaviour → ATT&CK, with evidence
    kev_enricher.py            CVE → known-exploited status
    ioc_extractor.py           shareable vs. victim-linked indicators
    attribution.py             behavioural resemblance to known actors
    dna_extractor.py           ② Attack DNA + schema validation
    llm_client.py              optional Claude wrapper, fails soft
    vector_memory.py           ③ Vector Memory (3-tier backend)
    similarity.py              ④ explainable re-ranking
    mitigation_memory.py       ⑤ recalled + framework + baseline actions
    simulator.py               ⑥ safe tabletop generation
  pipelines/analyze.py         analyze() / ingest() / reindex_memory()
  routes/                      FastAPI endpoints
frontend/app.py                Streamlit demo — the full six-step journey
scripts/
  download_*.py, process_*.py  knowledge-base preparation
  process_cti.py               ATT&CK mitigations, groups, software, campaigns
  seed_memory.py               load the historical corpus
  evaluate.py                  accuracy measurement
data/
  processed/                   ATT&CK, KEV and CTI layers (committed)
  seed/public_incidents.json   10 real publicly-documented breaches, cited
  seed/incidents.json          14 synthetic incidents for sector breadth
  seed/evaluation_set.json     labelled cases for accuracy measurement
  seed/demo_scenarios.json     prepared demo scenarios with presenter notes
tests/                         138 tests
```

---

## Testing

```bash
make test     # 138 tests
make eval     # accuracy measurement against labelled cases
```

The suite covers redaction correctness, fingerprint preservation, ATT&CK mapping
precision, DNA classification and schema validation, IoC separation, CTI
attribution conservatism, memory recall and ranking, the API contract, the
simulation safety boundary, and demo readiness.

Demo-readiness tests are worth calling out — they answer *"will this hold up on
stage?"*:

- **Offline operation.** Every outbound socket is blocked and the full pipeline
  must still complete. If any stage quietly depends on the network, this fails.
- **Determinism.** The same report analysed repeatedly must produce an identical
  signature, severity and technique list.
- **Performance.** Every prepared scenario must finish within a 5-second budget
  (current mean: 0.40 s).
- **Scenario hygiene.** No prepared demo scenario may leak an identifier.

---

## Notes on the data

- **MITRE ATT&CK** and **CISA KEV** are refreshed with `make data`. Current ATT&CK
  releases split the old `defense-evasion` tactic into `stealth` and
  `defense-impairment`; both spellings are handled.
- The **CTI layers** (`scripts/process_cti.py`) are optional enrichment. Without
  them the pipeline still runs — it just cannot attribute or cite official
  mitigations — so a fresh clone never breaks.
- **No model training is involved anywhere.** The rule layers are curated
  vocabularies, the embeddings come from a pre-trained MiniLM, and the optional
  LLM is used through its API. There is nothing to fine-tune, and no training
  data to collect.
- The corpus has **two provenances**, and the UI never shows a recalled action
  without saying which:
  - `data/seed/public_incidents.json` — **10 real, publicly documented breaches**
    (Norsk Hydro, Colonial Pipeline, Change Healthcare, MOVEit, NotPetya, Equifax,
    Target, SolarWinds, Kaseya, Uber), compiled from public reporting with the
    source URL on every entry. These answer the first question anyone asks of a
    memory system: where does the memory come from?
  - `data/seed/incidents.json` — **14 synthetic incidents** covering sectors the
    public set does not. Every organisation, person and identifier is invented.
- Reports of both kinds are stored un-sanitized on purpose: seeding runs them
  through the real Privacy Layer, so the seeded corpus is proof the pipeline works
  rather than a hand-cleaned shortcut. Titles are not sanitized — for a breach the
  victim has already disclosed, the name is public record, and keeping it is what
  makes the memory auditable.
