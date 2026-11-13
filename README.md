# 🧬 ATTACKDNA

**One organisation's cyber incident becomes another organisation's defensive
knowledge, without sharing the victim's identity or its report.**

Every organisation solves the same attack twice. The first time it is an incident;
the second time it should be a lookup. It usually isn't, because the useful part of
an incident report is buried inside data nobody is allowed to share.

ATTACKDNA separates the two. It strips the victim's identity out of an incident
report and keeps the attack's *behaviour*, its **Attack DNA**, as a searchable
record. With the security team's approval, that fingerprint joins a **shared
memory**: the next organisation hit by the same pattern recalls it, sees why it
matched and what worked, and never learns who was attacked.

---

## How a security team uses it

| Step | What the team does | What it sees |
|---|---|---|
| 1. Attach report | Attaches the report as written: PDF, Word or text | Nothing to choose, nothing to configure |
| 2. Remove identity | — | **"Sensitive information removed successfully"**, with counts per category, the sanitized text and the masked audit |
| 3. Attack DNA & matches | — | The verdict, the ATT&CK mapping with evidence, similar incidents from shared memory (other organisations' incidents marked *identity withheld*) and the recommended response, each action citing its source |
| 4. Share (optional) | Ticks the approval box and, optionally, adds what it did | Exactly what would be shared and what never leaves, side by side; then **Contribute** or **Keep private** |

Nothing is stored until step 4. The organisation's name is kept only as a keyed
pseudonym (`services/contributors.py`), used to tell a team "this match is your
own incident" and never returned by the API. Shared records carry the month they
were shared, not the incident date. If the privacy check fails, the text is not
sent to any LLM and cannot be shared.

### The cross-organisation experiment

`make eval-crossorg` runs the experiment behind the claim
(`scripts/evaluate_crossorg.py`, data in `data/seed/crossorg_pairs.json`).
Organisation A contributes 20 incidents; organisation B reports the same 20
attack patterns in its own words. A's incidents sit among the 24-incident
corpus, which acts as distractors. Offline mode, TF-IDF memory backend:

| Measurement | Result |
|---|---|
| Identifiers removed: 171 marked by hand in 40 reports | **167 / 171 = 98%** (95% CI 94–99%) |
| Attack terms lost to over-redaction | 2 / 165 = 1% |
| ATT&CK techniques kept after sanitization (raw DNA vs sanitized DNA) | **72 / 72 = 100%** |
| B recalls A's incident first: Precision@1 | **12 / 20 = 60%** (95% CI 39–78%) |
| …in its top five: Recall@5 · MRR | **19 / 20 = 95%** · 0.75 |
| B's top match has the same attack type | 18 / 20 = 90% |
| A's recorded response recommended to B, with its source | 18 / 20 = 90% |
| B's screens that showed anything naming A | **0 / 20** |
| Shared records still naming A | 1 / 20 (two identifiers in one report) |
| Same experiment without the privacy layer: Precision@1 · records naming A | 60% · **20 / 20** |

Removing the victim's identity cost no retrieval quality on this set, and without
the privacy layer every shared record named its victim. The four identifiers that
survived (a phone number written with spaces, two single-word company names, a
storage-bucket name) are reported as found rather than fixed after the fact. The
40 reports are synthetic and were labelled by the project team, so independent
annotation and real SOC reports are the next step. The Evidence page in the demo
shows every number with its interval and every query.

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
| [`docs/PHASE_COVERAGE.md`](docs/PHASE_COVERAGE.md) | All 142 plan tasks mapped to code and verification |

---

## Quick start

```bash
make all       # dependencies + knowledge bases + seeded memory
make demo      # http://localhost:8501
```

Or step by step:

```bash
make setup     # virtualenv + dependencies (picks Python 3.12 when available)
make data      # download & process MITRE ATT&CK, CISA KEV and the CTI layers
make seed      # load the historical incident corpus into memory
make demo      # http://localhost:8501
make eval      # measure accuracy against the labelled evaluation set
make eval-crossorg  # the cross-organisation sharing experiment
```

### Measured results

Two kinds of number, kept apart on purpose. **Development** cases are the ones
the rules were built and tuned on; a high score there shows the system does
what it was designed to do. **Held-out** cases are the test: the system had
never seen them, their labels were fixed first, and it was run on them once.

`make eval` prints both. Offline mode, no API key, no network:

| Held-out test | Result |
|---|---|
| Attack type — 32 real incident summaries (Wikipedia, verbatim) | **24 / 28 = 86%** (95% CI 69–94%) |
| Sector — same summaries | 11 / 25 = 44% (95% CI 27–63%) |
| Identifiers removed — names marked by hand in those summaries | **53 / 55 = 96%** |
| Identifiers removed — 40 new sentences, 10 categories | **51 / 53 = 96%** |
| ATT&CK technique mapping — 3,945 MITRE-labelled sentences about 214 sources never seen in fitting | recall **44%**, precision 62% |
| …of which the learned mapper, when it answers | precision **87%** |

| Development (36 cases, tuned on these) | Result |
|---|---|
| Attack type / initial vector / sector | 86% / 92% / 92% |
| ATT&CK techniques — precision / recall / F1 | 95% / 52% / 67% |
| Memory retrieval precision@1 (8 cases) | 8 / 8 |
| Mean end-to-end latency | ≈ 0.3 s |

What these say, plainly:

- **Sector is the weak number.** A real write-up names the organisation rather
  than describing its business, and the privacy layer removes the name. The
  classifier is left with whatever generic words remain.
- **The privacy figures are first-run figures.** The four identifiers that
  survived exposed three bugs (a machine name before a full stop, a bank read
  as a roman numeral, a brand that starts with a digit). They are fixed and
  have regression tests, and the held-out sets now pass in full — but 96% is
  what an untouched test measured, so 96% is what is reported.
- **Technique mapping has one label per sentence**, so a second technique the
  sentence really does describe counts as wrong. Precision is a lower bound.
- **Before these changes**, on 28 reports the rules had never seen, the
  extractor named the attack type for 8 and found 17% of the techniques, and
  19 of 34 realistic sentences leaked an identifier.

```bash
make eval           # development + held-out + privacy audit
make eval-mapper    # technique mapping on MITRE-labelled sentences
make eval-crossorg  # organisation A shares, organisation B recalls
```

No API key is required. Without one the system runs in **rule-based mode**: every
stage still executes, extraction is deterministic instead of model-assisted.

To enable the AI layer, put a key in `backend/.env` and verify it. **Either
provider works** — paste one key and the provider is inferred from its prefix:

| Provider | Key prefix | Where |
|---|---|---|
| Google Gemini | `AIza...` | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) — has a free tier |
| Anthropic Claude | `sk-ant-...` | [console.anthropic.com](https://console.anthropic.com) — pay as you go |

```bash
cp .env.example backend/.env     # then set LLM_API_KEY=...
make check-llm                   # proves the key works and shows what it adds
```

Adding a provider touches `backend/app/services/llm_providers/` and nothing
else: extraction, simulation and Ask-the-memory are written once against the
`llm_client` facade, never against a vendor SDK.

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

### ① Privacy Layer — `sanitizer.py`, `name_detector.py`, `lexicon.py`

Redaction is done with rules and word lists, not a model. A rule cannot decide
to leak an IP address, and the same report always gives the same output.

Identifiers come in two kinds, and each has its own mechanism:

- **Identifiers with a shape** — addresses, mailboxes, host names, accounts,
  ticket numbers — are found by regular expressions.
- **Identifiers without one** — people, organisations, places. Nothing marks
  "Aramco" or "Sara" as a name except that it is capitalised and is not a
  word. So the layer reads capitalisation against three vocabularies: ordinary
  English words, public security terms (every technique, malware, group,
  vendor and product name MITRE and CISA publish), and given names. A
  capitalised token that is in none of them is a name.

Properties:

- **Fails closed.** Where it cannot tell a name from a word, it removes it. An
  unfamiliar product name is lost; an unfamiliar person is not leaked. Text in
  a script it cannot read — Arabic has no capital letter to mark a name — is
  withheld whole, with the Latin-script terms inside it left for the extractor.
- **Reads the sentence, not just the token.** "Target" is a word; "Target
  disclosed a breach" is a retailer. "Cisco IOS XE" is a product; "Cisco
  confirmed a breach of its network" is a victim.
- **Analytically lossless.** The same value always maps to the same token, so
  "one attacker mailbox" and "three attacker mailboxes" stay distinguishable.
- **Preserves the fingerprint.** CVE ids, ATT&CK technique ids, file hashes
  and registry keys are the *attack's* identity, so they are protected.
- **Self-checking.** `verify_clean()` runs every detector a second time over
  the output. It is a self-check, not independent verification — the
  independent measurement is the hand-marked audit in `make eval`.

```
Saudi Aramco detected the intrusion   →  [NAME_REDACTED] detected the intrusion
Ahmed Al-Qahtani opened the file      →  [PERSON_REDACTED] opened the file
moved from fin-ws-042 to dc01         →  moved from [HOSTNAME_REDACTED_1] to [HOSTNAME_REDACTED_2]
10.10.23.41                           →  [IP_REDACTED]
CVE-2024-21412, Mimikatz, PowerShell  →  unchanged — this is the attack's DNA
```

What it does not claim: that free text is anonymous. A date, a size and a rare
sector can still narrow down a victim. The guarantee the system rests on is
structural and lives one stage later — see *Privacy by construction* below.

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

Techniques are found three ways, and each mapping says which: an id the
report states, a phrase from a curated table, or **resemblance to the ~17,600
sentences MITRE has labelled** (`example_mapper.py`) — a nearest-example vote
that needs no model download, abstains unless its neighbours agree, and
attaches the MITRE sentence as evidence rather than the report's own words.
Nothing the report denies is counted: "no data was exfiltrated" is not
exfiltration (`negation.py`).

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

ChromaDB is installed from `backend/requirements-vector.txt`, separately from the
core set, because it depends on `onnxruntime`, which lags new Python releases and
fails to resolve on 3.13. Keeping it out of the core set means a failed install
costs semantic search, not the whole application — `make setup` says so and
carries on, and the TF-IDF backend takes over automatically.

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
- The LLM, when enabled, only ever sees text that has already been sanitized,
  and only when the privacy check passed.
- Sharing is a separate, explicit step (`contribute()`), which takes the
  analysed result and never the raw report, re-runs the privacy check, and
  sanitizes the team's free-text response notes as well.
- The contributing organisation is stored as an HMAC pseudonym under a
  server-side key (`backend/.pseudonym_key` or `ATTACKDNA_PSEUDONYM_KEY`), absent
  from every API response.

- The Attack DNA itself is assembled from closed vocabularies: enumerated
  types, ATT&CK ids and names, and MITRE's own example sentences. No free
  text from the report can enter it — so a name the privacy layer misses
  still cannot reach the record that is embedded and shared.

`tests/test_pipeline.py`, `tests/test_privacy_names.py` and
`tests/test_cross_organization.py` assert each of these.

---

## Project layout

```
backend/app/
  config.py                    environment-driven configuration
  db/database.py               SQLAlchemy models (raw_text NULL by default)
  models/schemas.py            request/response contracts
  services/
    sanitizer.py               ① Privacy Layer — identifiers with a shape
    name_detector.py           ① … and the names that have none
    lexicon.py                 the vocabularies that tell a name from a word
    negation.py                what the report says did not happen
    example_mapper.py          technique mapping learned from MITRE's examples
    knowledge_base.py          ATT&CK, KEV and CTI loaders
    mitre_mapper.py            behaviour → ATT&CK, with evidence
    kev_enricher.py            CVE → known-exploited status
    ioc_extractor.py           shareable vs. victim-linked indicators
    attribution.py             behavioural resemblance to known actors
    dna_extractor.py           ② Attack DNA + schema validation
    llm_client.py              provider-agnostic LLM facade, fails soft
    llm_providers/             Anthropic and Gemini backends
    vector_memory.py           ③ Vector Memory (3-tier backend)
    similarity.py              ④ explainable re-ranking
    mitigation_memory.py       ⑤ recalled + framework + baseline actions
    simulator.py               ⑥ safe tabletop generation
    contributors.py            keyed pseudonyms for contributing organisations
    document_reader.py         PDF / Word / text reports to plain text
  pipelines/analyze.py         analyze() / contribute() / ingest() / reindex_memory()
  routes/                      FastAPI endpoints
frontend/app.py                Streamlit interface: attach → identity removed → DNA & matches → share
scripts/
  download_*.py, process_*.py  knowledge-base preparation
  process_cti.py               ATT&CK mitigations, groups, software, campaigns
  seed_memory.py               load the historical corpus
  process_examples.py          MITRE's labelled procedure examples
  evaluate.py                  development sets, held-out test, privacy audit
  evaluate_mapper.py           technique mapping on MITRE-labelled sentences
  evaluate_crossorg.py         cross-organisation recall, privacy and behaviour
data/
  processed/                   ATT&CK, KEV and CTI layers (committed)
  seed/public_incidents.json   10 real publicly-documented breaches, cited
  seed/incidents.json          14 synthetic incidents for sector breadth
  seed/evaluation_set.json     development set A (8 cases)
  seed/evaluation_dev.json     development set B (28 cases)
  seed/evaluation_heldout.json held-out test: 32 real incident summaries
  seed/privacy_audit.json      identifiers marked by hand, 73 sentences
  seed/demo_scenarios.json     prepared demo scenarios with presenter notes
  seed/crossorg_pairs.json     20 attack patterns reported by two organisations
  evaluation/                  latest cross-organisation results (read by the UI)
tests/                         348 tests
```

---

## Testing

```bash
make test          # 348 tests
make eval          # development sets, held-out test, privacy audit
make eval-mapper   # technique mapping on MITRE-labelled sentences
make eval-crossorg # cross-organisation recall, privacy and behaviour
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
  (current mean: about 0.3 s).
- **Scenario hygiene.** No prepared demo scenario may leak an identifier.

---

## Notes on the data

- **MITRE ATT&CK** and **CISA KEV** are refreshed with `make data`. Current ATT&CK
  releases split the old `defense-evasion` tactic into `stealth` and
  `defense-impairment`; both spellings are handled.
- The **CTI layers** (`scripts/process_cti.py`) are optional enrichment. Without
  them the pipeline still runs — it just cannot attribute or cite official
  mitigations — so a fresh clone never breaks.
- **Nothing is trained on anyone's incidents.** The rule layers are curated
  vocabularies, the embeddings come from a pre-trained MiniLM, and the optional
  LLM is used through its API. The one component that learns —
  `example_mapper` — learns only from sentences MITRE publishes, is fitted in
  under a second at first use, and has no weights to ship or fine-tune.
- **Third-party data.** `data/processed/english_words.txt.gz` is the lower-case
  entries of Webster's Second International (1934, copyright lapsed).
  `procedure_examples.json.gz` is © The MITRE Corporation, reproduced under
  the ATT&CK terms of use. The held-out summaries are © Wikipedia
  contributors, CC BY-SA 4.0, each cited to its article.
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

---

## Team

- **Aryam Al-Qahtani** — [@aryam-Q](https://github.com/aryam-Q)
- **Norah Almishdaq** — [@norahs21](https://github.com/norahs21)
