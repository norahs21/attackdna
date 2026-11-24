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

| Page | What the team does | What it sees |
|---|---|---|
| **Analyze a report** | Attaches the report as written (PDF, Word or text) and presses **Analyze** | Four sections, top to bottom: **1** sensitive information removed, with counts per category; **2** the Attack DNA with ATT&CK evidence; **3** similar attacks in memory (another organisation's marked *identity withheld*), why they match, what was done and how well it worked; **4** what to do if this attack is met again, each action with its source |
| **Dashboard** | — | What shared memory holds: key figures, incidents over time, where the memory comes from, attack mix, most-seen ATT&CK techniques, entry vectors, severity, kill-chain coverage, latest fingerprints, best-performing actions |
| **Ask the memory** | Describes what has happened so far | Three answers from memory: **1** what worked against this; **2** attackers who got in the same way, and what they did; **3** what attackers did next in similar past incidents (a record, not a prediction) |

**Add to memory** is a switch in the navigation rail, next to **Dark mode**. With
it on, the team can list the response actions it took, and **Analyze and add to
memory** analyses the report and then adds its fingerprint to shared memory.
Turning it on is the team's approval; a report that fails the privacy check is
never added.


## Results

`make results` measures everything and prints this page. Every figure comes from
data the system was not tuned on; offline, no LLM.

| | Result | What it means |
|---|---|---|
| **Privacy** | | |
| Identifiers removed | **98.6%** | 275 of 279 names, emails, IPs, hosts and phone numbers, marked by hand in 112 texts |
| Attack terms kept | **99.0%** | 189 of 191 behaviour words survived the redaction |
| **Attack DNA** | | |
| Attack type correct | **85.7%** | 24 of 28 real incident summaries (Wikipedia, verbatim) |
| ATT&CK techniques found | **81.6%** | 3,218 of 3,945 MITRE sentences about attackers never seen in training |
| …of suggestions, correct | 60.1% | a lower bound: each sentence has a single label |

The technique figures are measured on single sentences from MITRE, each
describing one technique. On whole reports the mapping is more precise but
misses more: on the 40 cross-organisation reports, 84% of suggested techniques
were correct and 49% of labelled techniques were found
(`data/evaluation/crossorg_results.json`).
| **Across organisations** | | |
| B finds A's incident first | **55%** | 11 of 20 attacks reported by two organisations in different words; second in 7 of the other 9 |
| …in its top five | **95%** | 19 of 20 |
| A's response reused by B | 90% | recommended with its source named |
| Screens that named A | **0 of 20** | B never learns who A is |

The samples are small, so these figures are indicative, not conclusive: the
95% confidence interval for "B finds A's incident first" runs from 34% to 74%,
and for attack type from 69% to 94%.

Organisation A's 20 incidents sit among 24 corpus incidents that act as
distractors; the 40 reports are synthetic and labelled by the team, so
independent annotation and real SOC reports are the next step. The four
identifiers that survived (a phone number written with spaces, two one-word
company names, a storage-bucket name) are reported, not fixed after the fact.

The system has also been run end to end on a real published incident review,
the British Library's 2024 report on its ransomware attack (18-page PDF): the
library, its sites and its staff are removed, the attacker (Rhysida) is kept,
and it is read as ransomware entering through compromised credentials, with
14 ATT&CK techniques.

**No sector.** Attack DNA does not record which industry the victim is in.
Once names are removed, the sector is itself a clue to who the victim was, so
it is neither inferred nor shared, and matching uses behaviour alone. The
measured cost: B finds A's incident first in 55% of attacks instead of 65%;
the top-five figure (95%) and response reuse (90%) are unchanged.

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

## Prototype status

ATTACKDNA is a working prototype: it shows the whole idea end to end, offline,
on one machine, and measures itself on data it was not tuned on. It is not yet
a product.

**Works now:** the privacy layer, the Attack DNA with ATT&CK evidence, shared
memory with explainable recall, response actions with their source,
contribution between organisations, the dashboard and Ask the memory.

**Limits of this prototype**

- Evaluation sets are small (28 real summaries, 20 cross-organisation pairs),
  and the cross-organisation reports are synthetic, written and labelled by
  the team.
- No real SOC reports yet, and no independent annotation of the test sets.
- English-language reports only.
- One machine, SQLite, no user accounts, roles or deployment.

**Computed but not shown on screen yet** (kept in the backend and its tests,
for the next version): threat-actor resemblance, the indicator profile,
official ATT&CK mitigations, the defensive tabletop exercise, the
downloadable report, and LLM settings.

**Next steps towards the full system**

1. Larger, independently labelled evaluation sets, including practitioner reports.
2. A pilot with a SOC on its own sanitized reports.
3. Predicting the attacker's next step. A first version is
   shown the first half of 177 held-out ATT&CK profiles, at least one of its
   three predictions was a step the attacker really took later in 56.5% of
   cases, against 53.1% for guessing the most common steps (66.7% against 59.0%
   on the 39 threat groups and campaigns). The lead is small and the sample
   modest, so it is not part of this prototype; until then, Ask the memory
   shows what attackers did next in similar past incidents, as a record.
4. Export of Attack DNA in STIX 2.1 for existing sharing platforms.
5. A multi-organisation deployment with accounts and access control.

---

## References

1. B. E. Strom et al., "MITRE ATT&CK: Design and Philosophy," The MITRE Corporation, 2018. https://attack.mitre.org
2. Cybersecurity and Infrastructure Security Agency, "Known Exploited Vulnerabilities Catalog." https://www.cisa.gov/known-exploited-vulnerabilities-catalog
3. C. Wagner, A. Dulaunoy, G. Wagener and A. Iklody, "MISP: The Design and Implementation of a Collaborative Threat Intelligence Sharing Platform," ACM WISCS, 2016.
4. OASIS, "STIX Version 2.1," OASIS Standard, 2021.
5. N. Reimers and I. Gurevych, "Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks," EMNLP-IJCNLP, 2019.
6. W. Wang et al., "MiniLM: Deep Self-Attention Distillation for Task-Agnostic Compression of Pre-Trained Transformers," NeurIPS, 2020.
7. P. Lewis et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," NeurIPS, 2020.
8. G. Salton and C. Buckley, "Term-weighting approaches in automatic text retrieval," Information Processing & Management 24(5), 1988.
9. MITRE ATT&CK procedure examples (`data/processed/procedure_examples.json.gz`), © The MITRE Corporation, under the ATT&CK terms of use.
10. Held-out incident summaries: English Wikipedia, CC BY-SA 4.0, each cited to its article in `data/seed/evaluation_heldout.json`.
11. Public breaches in memory: Norsk Hydro, Colonial Pipeline, Change Healthcare, MOVEit, NotPetya, Equifax, Target, SolarWinds, Kaseya, Uber — source URL per entry in `data/seed/public_incidents.json`.

---

## Team

- **Aryam Al-Qahtani** — [@aryam-Q](https://github.com/aryam-Q)
- **Norah Almishdaq** — [@norahs21](https://github.com/norahs21)
