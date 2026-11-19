# Automated TTP extraction from incident and threat reports and mapping to MITRE ATT&CK: prior systems, datasets, benchmarks and evaluation practice (related work for ATTACKDNA)

Scope note for the report writer. ATTACKDNA's own figures used for comparison below come from the project itself:
- Sentence level: 3,945 held-out MITRE procedure-example sentences from 214 held-out sources (attackers/software never seen in training); 5,356 suggestions; recall ("techniques found") 81.6%, precision 60.1%, F1 69.2% — [mapper_results.json](/home/user/attackdna/data/evaluation/mapper_results.json); [README](/home/user/attackdna/README.md)
- Document level: 40 cross-organisation reports, offline rule-based mode; TP 61, FP 12, FN 63 → precision 83.6%, recall 49.2%, F1 61.9% (micro-pooled over reports); attack type 92.5% (37/40), initial vector 100% (40/40) on these same reports — [crossorg_results.json](/home/user/attackdna/data/evaluation/crossorg_results.json)
- The 40 reports are synthetic, "written for this experiment after the rules were frozen; labels ... written by the project team, not by independent analysts" — [crossorg_results.json caveats](/home/user/attackdna/data/evaluation/crossorg_results.json); README also says "no independent annotation of the test sets" — [README](/home/user/attackdna/README.md)
- Attack type: 85.7% (24/28) on real Wikipedia incident summaries — [README](/home/user/attackdna/README.md)

Bibliographic items whose DOI or venue I could not confirm from a primary page are marked [UNVERIFIED]. Numbers reported only in secondary sources are marked [SECONDARY].

## Q1. Classic and tool-based systems (TRAM, rcATT, TTPDrill, ActionMiner, EXTRACTOR, AttacKG, ThreatKG, LADDER, TTPHunter/TTPXHunter, others): what do they do and what P/R/F1 do they report on which data?

### Takeaway
Early systems used rules or ontologies (TTPDrill, ActionMiner), document-level bag-of-words classifiers (rcATT), or graph and template matching against MITRE procedure examples (AttacKG). Later tools fine-tune BERT-family sentence classifiers (TRAM, TTPHunter/TTPXHunter) or chain sentence filtering with embedding similarity (LADDER). Self-reported F1 runs from about 0.35 (rcATT techniques, F0.5) to 0.97 (TTPXHunter). Independent re-evaluations often find these systems much weaker on other people's data, e.g. TTPDrill F1 0.14 and AttacKG F1 0.15 in LADDER's test, and AttacKG F1 0.258 in AttacKG+'s test. Headline numbers are therefore not comparable across papers.

### Cited Findings

**MITRE TRAM (Threat Report ATT&CK Mapper), Center for Threat-Informed Defense.** GitHub: https://github.com/center-for-threat-informed-defense/tram ; project page: https://ctid.mitre.org/projects/threat-report-attck-mapper-tram/
- Open-source platform to map CTI reports to ATT&CK. It ships Jupyter notebooks for "SciBERT-based single-label and multi-label models", and the out-of-the-box model identifies "up to 50 common ATT&CK techniques". It is Apache-2.0 licensed and references ATT&CK v13 — [TRAM GitHub](https://github.com/center-for-threat-informed-defense/tram)
- The CTID project page (dated 24 Aug 2023) says earlier phases built an annotation tool and supervised models, and the latest phase improved training-data quality and used fine-tuned LLMs. It gives no P/R/F1 figures — [CTID TRAM page](https://ctid.mitre.org/projects/threat-report-attck-mapper-tram/)
- MITRE's blog says the fine-tuned SciBERT beat the logistic-regression baseline "in all but one area where we measured Precision, Recall, and F1-score". A search snippet summarises it as about 88/100 samples correct. The blog itself returned HTTP 403 to my fetch, so treat the figure as [SECONDARY] — [MITRE Engenuity blog (Medium)](https://medium.com/mitre-engenuity/our-tram-large-language-model-automates-ttp-identification-in-cti-reports-5bc0a30d4567)
- Independent re-evaluations of TRAM:
  - The SoK tested TRAM2 (SciBERT) "as provided by the authors": TRAM2 test F1 66.64% (P 82.38, R 57.51); AnnoCTR F1 52.69% (P 73.11, R 44.87) — [Büchel et al., USENIX Sec 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/buechel)
  - Nguyen et al. report a TRAM/SciBERT baseline F1 of "just over 0.4", attributed to overfitting and class imbalance — [Nguyen et al., WWW'25 Companion](https://arxiv.org/html/2505.03147v1)
  - Kumarasinghe et al.'s TRAM baseline: R@3 0.4028, P@1 0.3204, F1-macro 0.1179 — [Kumarasinghe et al.](https://arxiv.org/html/2403.17068v1)
  - AnnoCTR's TRAM baseline: document-level technique micro-F1 24.8 — [Lange et al., LREC-COLING 2024](https://arxiv.org/html/2404.07765v1)
  - TTPXHunter's re-evaluation on its 149 reports: TRAM P 94.54 / R 94.33 / F1 93.49 (macro) — [Rani et al., TTPXHunter](https://arxiv.org/html/2403.03267v3)

**rcATT.** V. Legoy, M. Caselli, C. Seifert, A. Peter, "Automated Retrieval of ATT&CK Tactics and Techniques for Cyber Threat Reports", arXiv:2004.14322, 29 Apr 2020. Code: https://github.com/vlegoy/rcATT. One search summary says it was presented at a 2020 CTI symposium [UNVERIFIED venue] — [arXiv](https://arxiv.org/abs/2004.14322)
- Document-level multi-label classification (TF-IDF/TF features with linear SVC, binary relevance and other classifiers). The data are 1,490 reports referenced by ATT&CK Enterprise (1,311 HTML, 179 PDF). Techniques with fewer than 5 reports were dropped, and evaluation used 5-fold CV — [arXiv PDF](https://arxiv.org/pdf/2004.14322)
- The metric is F0.5 ("precision is considered twice as important as the recall"), micro and macro — [arXiv PDF](https://arxiv.org/pdf/2004.14322)
- Best independent classification:
  - Tactics: micro P 65.64%, R 64.69%, F0.5 65.38%; macro F0.5 59.47%
  - Techniques: micro P 37.18%, R 29.79%, F0.5 35.02%; macro F0.5 25.06%
  - The majority-label baseline for techniques was micro F0.5 6.11% — [arXiv PDF, Tables 1 and 4](https://arxiv.org/pdf/2004.14322)
- The SoK lists rcATT as document-level: 1,490 CTRs, 12 tactics, 215 techniques — [Büchel et al. 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/buechel)
- TTPXHunter's re-evaluation of rcATT: P 30.47 / R 44.03 / F1 30.56 — [TTPXHunter](https://arxiv.org/html/2403.03267v3)
- Ryan et al. describe Legoy et al. as focused on "12 broad categories (tactics)". That contradicts rcATT's own technique-level results above — [Ryan et al. 2026](https://arxiv.org/abs/2606.18166)

**TTPDrill.** G. Husari, E. Al-Shaer, M. Ahmed, B. Chu, X. Niu, "TTPDrill: Automatic and Accurate Extraction of Threat Actions from Unstructured Text of CTI Sources", ACSAC 2017, pp. 103–115, DOI 10.1145/3134600.3134646 — [ACSAC program](https://acsac.org/2017/program-files/s297.html); [dblp](https://dblp1.uni-trier.de/rec/bibtex/conf/acsac/HusariAACN17)
- It extracts threat actions (subject–verb–object) and matches them to a TTP ontology/knowledge base with BM25. It was evaluated on randomly selected Symantec threat reports and reports "more than 82% of precision and recall in a variety of measures" — [ACSAC 2017 program](https://acsac.org/2017/program-files/s297.html)
- Ryan et al. say TTPDrill "relies on 392 hand-crafted rules" — [Ryan et al. 2026](https://arxiv.org/abs/2606.18166)
- LADDER's end-to-end re-evaluation on 5 malware: TTPDrill TP 22, FN 43, FP 231 → P 0.09, R 0.34, F1 0.14 — [LADDER, Table 9](https://arxiv.org/html/2211.01753v2)

**ActionMiner.** G. Husari, X. Niu, B. Chu, E. Al-Shaer, "Using Entropy and Mutual Information to Extract Threat Actions from Cyber Threat Intelligence", IEEE ISI 2018, DOI 10.1109/ISI.2018.8587343 (it is 2018, not 2019) — [researchr](https://researchr.org/publication/HusariNCA18); [KFUPM record](https://pure.kfupm.edu.sa/en/publications/using-entropy-and-mutual-information-to-extract-threat-actions-fr/)
- It extracts low-level threat actions using entropy and mutual information. The authors claim higher precision and recall than the Stanford typed-dependency parser. I could not retrieve the numeric values — [CPS-VO record](https://archive.cps-vo.org/node/59253)

**EXTRACTOR.** K. Satvat, R. Gjomemo, V. N. Venkatakrishnan, "Extractor: Extracting Attack Behavior from Threat Reports", IEEE EuroS&P 2021, pp. 598–615, DOI 10.1109/EuroSP51992.2021.00046; arXiv:2104.08618; code github.com/ksatvat/EXTRACTOR — [dblp](https://dblp1.uni-trier.de/rec/conf/eurosp/SatvatGV21.html); [arXiv](https://arxiv.org/pdf/2104.08618.pdf)
- It uses Semantic Role Labeling to turn report text into concise attack-behaviour (provenance-style) graphs for threat hunting, rather than ATT&CK IDs. It was evaluated on real incident reports and DARPA Transparent Computing engagement reports — [arXiv](https://ar5iv.labs.arxiv.org/html/2104.08618)
- The authors' slides show P/R/F1 of 0.89/0.94/0.92 and 0.96/0.93/0.94, compared with POIROT. The slide text was jumbled, so the dataset each set belongs to is unclear [SECONDARY / partially verified] — [EuroS&P 2021 slides](https://www.ieee-security.org/TC/EuroSP2021/slides/Kiavash%20Satvat%20-%20Extractor%20Extracting%20Attack%20Behavior%20from%20Threat%20Reports.pdf)

**AttacKG.** Z. Li, J. Zeng, Y. Chen, Z. Liang, "AttacKG: Constructing Technique Knowledge Graph from Cyber Threat Intelligence Reports", ESORICS 2022, LNCS, pp. 589–609, DOI 10.1007/978-3-031-17140-6_29; arXiv:2111.07093 — [Springer](https://link.springer.com/chapter/10.1007/978-3-031-17140-6_29); [arXiv](https://arxiv.org/pdf/2111.07093)
- It builds attack graphs from reports and aligns them, with a revised graph-alignment algorithm, to technique templates. The templates are built from 7,373 procedure examples of 179 techniques crawled from MITRE ATT&CK, plus 1,515 CTI reports. Ground truth is 16 manually labelled reports (incl. 5 DARPA TC). Reported F1: entities 0.887, dependencies 0.896, techniques 0.789 — [arXiv abstract](https://arxiv.org/pdf/2111.07093)
- Independent re-evaluations disagree sharply:
  - LADDER (5 malware): P 0.12, R 0.18, F1 0.15 — [LADDER Table 9](https://arxiv.org/html/2211.01753v2)
  - AttacKG+ (15 labelled reports): AttacKG technique F1 0.258 against 0.566 for AttacKG+, with about 14.4 false positives per report [SECONDARY, from search summary] — [AttacKG+ arXiv:2405.04753](https://arxiv.org/pdf/2405.04753)
  - Kumarasinghe et al.: R@3 0.1261, F1-macro 0.0059 — [Kumarasinghe et al.](https://arxiv.org/html/2403.17068v1)
  - TTPXHunter (149 reports): F1 88.52 — [TTPXHunter](https://arxiv.org/html/2403.03267v3)

**ThreatKG.** P. Gao et al., "ThreatKG: A Threat Knowledge Graph for Automated Open-Source Cyber Threat Intelligence Gathering and Management", arXiv:2212.10388. The arXiv entry says it was accepted at the LAMPS 2024 workshop [UNVERIFIED in proceedings]; a 2023 "AI-Powered System" version is in the Virginia Tech repository — [arXiv](https://arxiv.org/abs/2212.10388v2); [VTechWorks](https://vtechworks.lib.vt.edu/items/1d72e06d-275a-4f48-99eb-9cd4410511dd)
- It has a three-layer threat ontology, a parser/checker/extractor pipeline, and a continuously updated knowledge graph built from OSCTI reports. I did not retrieve its numeric results — [arXiv](https://arxiv.org/abs/2212.10388v2)

**LADDER.** M. T. Alam, D. Bhusal, Y. Park, N. Rastogi, "Looking Beyond IoCs: Automatically Extracting Attack Patterns from External CTI", RAID '23 (Hong Kong); arXiv:2211.01753; code github.com/aiforsec/LADDER. The ACM DOI was not confirmed [UNVERIFIED DOI] — [arXiv v2](https://arxiv.org/html/2211.01753v2)
- Pipeline:
  1. A binary classifier finds attack-pattern sentences.
  2. A token tagger extracts attack phrases.
  3. Each phrase is mapped to one ATT&CK technique by sentence-transformer cosine similarity to technique title and description (w_t = 0.4, τ = 0.6).
  4. Separately, NER and relation extraction build a knowledge graph.
  — [arXiv v2](https://arxiv.org/html/2211.01753v2)
- Data: 36 annotated malware reports (140,447 tokens) and over 12,000 crawled CTI reports; attack-pattern ground truth for 5 malware (65 attack patterns) — [arXiv v2](https://arxiv.org/html/2211.01753v2)
- Results:
  - Attack-pattern sentence detection F1 89.62 (RoBERTa-large)
  - Attack-phrase extraction F1 90.64
  - NER F1 78.98 (XLM-R-large)
  - Relation extraction F1 92.62
  - No standalone mapping P/R/F1 or top-k is reported
  - End-to-end on 5 malware, against MITRE-listed techniques: LADDER (TTPClassifier) P 0.65, R 0.63, F1 0.64. The MITRE listing itself had only 38 of 65 ground-truth techniques (R 0.58)
  — [arXiv v2, Tables 3–5 and 9](https://arxiv.org/html/2211.01753v2)

**TTPHunter and TTPXHunter (IIT Kanpur).**
- TTPHunter: N. Rani, B. Saha, V. Maurya, S. K. Shukla, "TTPHunter: Automated Extraction of Actionable Intelligence as TTPs from Narrative Threat Reports", ACSW 2023, ACM, pp. 126–134. It fine-tunes BERT/RoBERTa on the 50 most frequent TTPs and reports F1 0.88 — [TTPXHunter related work](https://arxiv.org/html/2403.03267v3); [Ryan et al. refs](https://arxiv.org/abs/2606.18166)
- TTPXHunter: same authors, "TTPXHunter: Actionable Threat Intelligence Extraction as TTPs from Finished Cyber Threat Reports". It is cited as Digital Threats: Research and Practice 5(4):1–19, 2024 [venue per Ryan et al.'s reference list; DOI not confirmed]; arXiv:2403.03267 — [arXiv v3](https://arxiv.org/html/2403.03267v3)
  - Method: SecureBERT with a linear head; one TTP per sentence. Sentences below confidence 0.644 are discarded, the rest are unioned into the report-level prediction, and IOCs are normalised by regex — [arXiv v3](https://arxiv.org/html/2403.03267v3)
  - Data: sentences "derived from the MITRE ATT&CK knowledgebase" (TTPHunter data), augmented with SecureBERT masked-LM paraphrases from 10,906 to 39,296 sentences over 193 TTPs (per class from 3 to 800, mean 203), with an 80:20 split. There is also a 149-report dataset with manual TTP labels — [arXiv v3](https://arxiv.org/html/2403.03267v3)
  - Results: sentence-level macro-F1 92.42%. On the 149 reports (macro): TTPXHunter P 97.38 / R 96.15 / F1 97.09; LADDER 93.90; TRAM 93.49; AttacKG 88.52; rcATT 30.56. The text has minor inconsistencies (97.07 vs 97.09; 93.09 vs 93.90) — [arXiv v3, Table IV](https://arxiv.org/html/2403.03267v3)
  - Stated limitations: one TTP per sentence, and retraining is needed when ATT&CK changes — [arXiv v3](https://arxiv.org/html/2403.03267v3)

**Rahman & Williams (comparative re-implementation).** M. R. Rahman, L. Williams, "From Threat Reports to Continuous Threat Intelligence: A Comparison of Attack Technique Extraction Methods from Textual Artifacts", arXiv:2210.02601, Oct 2022 (no venue listed) — [arXiv](https://arxiv.org/abs/2210.02601)
- They re-implemented 5 of 10 published methods on one dataset built from MITRE ATT&CK procedure descriptions, with 2 to 64 technique classes (up to 7,061 descriptions at n = 64), 5-fold CV and oversampling. TF-IDF and LSI methods were best, with F1 84% and 83% averaged across settings, and F1 drops as the label count rises — [arXiv PDF](https://arxiv.org/pdf/2210.02601v1.pdf)

**Orbinato et al. (experimental study).** V. Orbinato, M. Barbaraci, R. Natella, D. Cotroneo, "Automatic Mapping of Unstructured Cyber Threat Intelligence: An Experimental Study", IEEE ISSRE 2022 (Practical Experience Report), DOI 10.1109/ISSRE55969.2022.00027; arXiv:2208.12144; data github.com/dessertlab/cti-to-mitre-with-nlp — [sos-vo record](https://sos-vo.org/bibcite/reference/1889); [arXiv](https://arxiv.org/abs/2208.12144v1)
- Dataset: 12,945 MITRE ATT&CK samples (procedure descriptions), 188 techniques, single-label, imbalanced. Cross-validated results:
  - SecureBERT: F 72.5%, AC@3 86.9%
  - MLP 70.4%, SVM 69.9%, balanced LR 64.6%
  - On the smaller TRAM data (1,482 samples), SecureBERT F 52.5%
  — [arXiv PDF, Tables I–V](https://arxiv.org/pdf/2208.12144.pdf)
- Document-level test: 6 reports (2× FIN6, 2× menuPass, 2× Wizard Spider; 17–99 techniques each), with ground truth from ATT&CK. Probability threshold 0.2 was best, and the average F-measure was about 50%, lower than at sentence level because of many non-technique sentences — [arXiv PDF, Sec. V and Fig. 3](https://arxiv.org/pdf/2208.12144.pdf)

**Kumarasinghe et al. (semantic ranking).** U. Kumarasinghe, A. Lekssays, H. T. Sencar, S. Boughorbel, C. Elvitigala, P. Nakov, "Semantic Ranking for Automated Adversarial Technique Annotation in Security Text", reported as ACM AsiaCCS '24 [venue per search summary; the arXiv PDF has an unfilled ACM template]; arXiv:2403.17068; data github.com/qcri/Text2TTP — [arXiv](https://arxiv.org/html/2403.17068v1); [GitHub](https://github.com/qcri/Text2TTP)
- Pipeline: BM25 → fine-tuned SentSecBERT → MonoT5 re-ranking. Results: R@3 0.8102, R@10 0.9207, P@1 0.5783, MRR 0.7068 — [arXiv, Table 3](https://arxiv.org/html/2403.17068v1)
- Baselines on the same test set:

  | Method | R@3 | F1-macro |
  |---|---|---|
  | TRAM | 0.4028 | 0.1179 |
  | LADDER | 0.4435 | 0.2256 |
  | AttacKG | 0.1261 | 0.0059 |
  | gpt-4-32k zero-shot | 0.4406 | — |

  — [arXiv, Tables 4 and 6](https://arxiv.org/html/2403.17068v1)
- Dataset: 6,612 behaviours over 410 techniques, from ATT&CK procedure examples (2,017, traced back to original report text), CISA (1,718, multi-label), TRAM (1,506) and WeLiveSecurity (1,474). The test set is 1,212 samples over 168 techniques. IOCs are replaced by placeholders, and text containing the corresponding procedure examples was excluded to avoid bias — [arXiv](https://arxiv.org/html/2403.17068v1)

**SMET / ATT&CK BERT (CVE → ATT&CK).** B. Abdeen, E. Al-Shaer, A. Singhal, L. Khan, K. Hamlen, "SMET: Semantic Mapping of CVE to ATT&CK and its Application to Cybersecurity", DBSec 2023, DOI 10.1007/978-3-031-37586-6_15. A journal version is in the Journal of Computer Security, DOI 10.3233/JCS-230218 — [NIST CSRC](https://csrc.nist.gov/pubs/conference/2023/07/12/smet-semantic-mapping-of-cve-to-attck-and-its-appl/final); [IOS Press](https://content.iospress.com/articles/journal-of-computer-security/jcs230218)
- Method: SRL extracts attack vectors, a Siamese-tuned "ATT&CK BERT" embeds them, and logistic regression predicts techniques. It needs no labelled CVE–technique pairs and covers 185 techniques. A later paper reports SMET Recall@5 67.71% [SECONDARY] — [arXiv:2508.18439](https://arxiv.org/pdf/2508.18439)

**Other LLM-era pipelines (detail in Q2):** aCTIon (Siracusano et al. 2023), IntelEX (Xu et al. 2024), AttacKG+ (2024).

### Inferences

Per-item comparison with ATTACKDNA:

- **TRAM:** TRAM covers about 50 techniques and needs GPU fine-tuning. ATTACKDNA scores the full ATT&CK label space with a CPU-only MiniLM + logistic regression, which is close to TRAM's original logistic-regression baseline idea. ATTACKDNA's document-level P 84% / R 49% sits in the same precision-heavy band as the SoK's TRAM2 (SciBERT) P 82% / R 58%. However, ATTACKDNA's 40 reports are synthetic and team-labelled, while TRAM2 is 150 real reports, so the two are not directly comparable.
- **rcATT:** Both favour precision; rcATT even adopted F0.5. rcATT is document-level bag-of-words with no evidence span. ATTACKDNA works per sentence and returns an evidence phrase per technique. rcATT's technique micro P 37% / R 30% comes from 1,490 real reports with about 215 labels, so it should not be set beside ATTACKDNA's synthetic-report numbers without that caveat.
- **TTPDrill / ActionMiner:** ATTACKDNA's curated keyword rules play the same role as TTPDrill's ontology and rules. LADDER's re-evaluation (TTPDrill precision 0.09 on others' data) is a warning that rule components should be tested on independently written reports. ATTACKDNA's rules were frozen before its synthetic reports were written, but by the same team.
- **EXTRACTOR / ThreatKG:** These produce behaviour graphs or knowledge graphs for hunting, not ATT&CK IDs with severity. ATTACKDNA's per-technique evidence phrase is a lighter form of the same traceability. No numeric comparison is meaningful.
- **AttacKG:** This is the closest conceptual ancestor of ATTACKDNA's semantic index, since both use MITRE procedure examples as the knowledge source (templates there, embedding index here). AttacKG's results swing from 0.79 (own 16 reports) to 0.15–0.26 (others' reports). ATTACKDNA's held-out sentence F1 of 0.69 should likewise not be assumed to transfer to real reports.
- **LADDER:** LADDER maps phrases by embedding similarity to technique descriptions. ATTACKDNA embeds procedure examples, whose wording is closer to report wording, and adds a supervised classifier and rules. Both expose an extracted phrase. LADDER's 0.65 / 0.63 on 5 real malware reports and ATTACKDNA's 0.84 / 0.49 on 40 synthetic reports are different tests.
- **TTPXHunter:** It is the most similar training recipe (MITRE-derived sentences → per-sentence classifier → union over the report). Its 80:20 split is over an augmented set in which masked-LM paraphrases of one source sentence can plausibly land on both sides. ATTACKDNA holds out whole attackers. TTPXHunter's 97% report-level F1 is far above every independent evaluation (SoK, Ryan et al.), so cite it as reported, not as a target.
- **Orbinato et al.:** This is the most similar overall study design: train on MITRE procedure examples, then test whole reports. Their sentence F 72.5% (SecureBERT, top-1, random CV, 188 classes) is in the same range as ATTACKDNA's F1 69.2%, and ATTACKDNA's split (held-out attackers) is stricter. The metrics differ, though: Orbinato is single-prediction accuracy-like F, while ATTACKDNA allows about 1.36 suggestions per sentence. Their document-level F of about 50% on 6 real reports is a fairer reference for ATTACKDNA's F1 of 62% on 40 synthetic reports than TTPXHunter's 97%.
- **Rahman & Williams:** Same data source as ATTACKDNA, but their 84% F1 averages over 2–64-class settings with random CV. That is a much easier task than ATTACKDNA's full label space with held-out attackers.
- **Kumarasinghe et al.:** This is the closest retrieval analogue to ATTACKDNA's semantic index. ATTACKDNA's 81.6% "found" with about 1.36 suggestions per sentence is in the same region as their R@3 of 81.0% (3 suggestions) and P@1 of 57.8%. The test sets differ, and theirs mixes CISA, TRAM and WeLiveSecurity text.
- **SMET:** Its architecture (sentence embedder + logistic regression, trained without target-domain labels) is very close to ATTACKDNA's MiniLM + LR trained only on MITRE sentences. Cite it as direct precedent for the design choice.

### Gaps
- I could not obtain TRAM's official per-technique P/R/F1 table. The MITRE blog was blocked (403) and the GitHub page gives no metrics.
- I did not retrieve numeric results for ActionMiner (ISI 2018), ThreatKG or CTI-BERT's ATT&CK task.
- I did not confirm the DOIs for LADDER (RAID '23), TTPXHunter (DTRAP) or Kumarasinghe et al. (AsiaCCS '24); check them in the ACM DL or dblp.
- The EXTRACTOR per-dataset P/R/F1 mapping is unclear from the slides; the full paper's tables were not read.

## Q2. Transformer and LLM approaches (SecureBERT, CySecBERT, CTI-BERT, TRAM-SciBERT, LLM TTP-classification studies, CTIBench, AnnoCTR, GPT-4/RAG): results and failure modes

### Takeaway
In the only large unified comparison (Büchel et al., USENIX Security 2025), fine-tuned encoder classifiers reach about 70% F1 on the top-50-technique TRAM2 set and about 63% on AnnoCTR. Unsupervised embedding similarity to ATT&CK descriptions, the approach closest to a semantic index, reaches only about 35–51%, and collapses to about 10–13% F1 when all techniques are allowed. Prompted LLMs do worse than fine-tuned classifiers unless fine-tuned. Recent independent tests on real multi-label report sentences give LLMs micro-F1 of 0.22 (0.32 with RAG). The recurring failure modes are low precision and over-prediction, confusion between sibling techniques, keyword-triggered hallucination, and degradation on long full reports.

### Cited Findings

**Domain language models**
- **SecureBERT:** E. Aghaei, X. Niu, W. Shadid, E. Al-Shaer, "SecureBERT: A Domain-Specific Language Model for Cybersecurity", SecureComm 2022 (EAI/Springer 2023), DOI 10.1007/978-3-031-25538-0_3; arXiv:2204.02685. It is RoBERTa-based with a custom tokenizer, evaluated on masked-LM and standard tasks — [EUDL](https://eudl.eu/doi/10.1007/978-3-031-25538-0_3); [HF model card](https://huggingface.co:443/ehsanaghaei/SecureBERT)
  - In the SoK: TRAM2 F1 70.24 / AnnoCTR 58.44 — [Büchel et al. 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/buechel)
  - In Orbinato et al.: F 72.5% on 12,945 MITRE procedure examples — [Orbinato et al.](https://arxiv.org/pdf/2208.12144.pdf)
- **CySecBERT:** M. Bayer, P. Kuehn, R. Shanehsaz, C. Reuter, "CySecBERT: A Domain-Adapted Language Model for the Cybersecurity Domain", ACM Transactions on Privacy and Security 27(2), 2024, DOI 10.1145/3652594; arXiv:2212.02974. It is BERT-base further pre-trained, and was evaluated on 15 domain tasks plus SuperGLUE — [PEASEC PDF](https://peasec.de/paper/2024/2024_BayerKuehnShanesazReuter_CySecBERT_TOPS.pdf); [HF](https://huggingface.co/markusbayer/CySecBERT)
  - In the SoK it is the best labelled model on AnnoCTR (F1 62.75; TRAM2 69.74) — [Büchel et al. 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/buechel)
- **CTI-BERT:** Y. Park, W. You, "A Pretrained Language Model for Cyber Threat Intelligence", EMNLP 2023 Industry Track, pp. 113–122, ACL Anthology 2023.emnlp-industry.12. Its pre-training corpus includes ATT&CK and CAPEC descriptions plus CTI news and white papers — [ACL Anthology](https://aclanthology.org/2023.emnlp-industry.12)
  - A follow-up uses CTI-BERT for two-stage ATT&CK sentence classification — [arXiv:2411.18755](https://arxiv.org/html/2411.18755v1)
- **SoK on domain pre-training:** "Models pre-trained on CTI do not show a consistent improvement on generic models". The best TRAM2 score came from general RoBERTa-large (F1 70.55; P 77.59, R 68.39) — [Büchel et al. 2025, Table 6](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)

**SoK (main unified benchmark).** M. Büchel, T. Paladini, S. Longari, M. Carminati, S. Zanero, H. Binyamini, G. Engelberg, D. Klein, G. Guizzardi, M. Caselli, A. Continella, M. van Steen, A. Peter, T. van Ede, "SoK: Automated TTP Extraction from CTI Reports – Are We There Yet?", 34th USENIX Security Symposium 2025, pp. 4621–4641. Artifacts: Zenodo DOI 10.5281/zenodo.15608555 — [USENIX page](https://www.usenix.org/conference/usenixsecurity25/presentation/buechel); [PDF](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- Scope: it systematises 38 papers and 2 blogs and re-implements NER, labelled classification, unlabelled (embedding-similarity) classification and generative LLMs on TRAM2 and AnnoCTR — [PDF](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- Headline insight: on top-50 TTPs the best solutions reach "a precision of around 80% for a recall of around 66%". For less common TTPs precision goes "way below 40% in realistic settings", and "traditional NLP approaches still notably outperform modern embedder-based and generative" approaches — [PDF, Sec. 1](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- Unlabelled approaches embed ATT&CK titles and descriptions and threshold the similarity. Results:

  | Model | TRAM2 F1 | AnnoCTR F1 | All TTPs F1 (precision) |
  |---|---|---|---|
  | ATTACK-BERT | 50.60 | 35.45 | 10.71 TRAM2 (P 7.24); 13.44 AnnoCTR (P 8.93) |
  | SBERT-MPNet | 44.58 | 34.58 | ≈12–13 |

  The authors call them "practically unusable due to their low Precision" — [PDF, Table 7](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- Generative LLMs (Llama-3.1-8B-Instruct) — [PDF, Table 9](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf):

  | Setting | TRAM2 F1 | AnnoCTR F1 |
  |---|---|---|
  | Raw prompt | 49.2 | 30.3 |
  | RAG (5 entries) | 54.1 | 35.9 |
  | LoRA SFT | 72.5 | 55.3 |
  | Few-shot | below Raw on both | below Raw on both |

- Document-level prompting (whole report) cut recall by up to about half; e.g. TRAM2 Raw F1 34.2, with recall down 32.3 points against sentence level — [PDF, Table 11](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- Closed-set best on TRAM2: Generation 72.50, Classification 71.41, NER 62.19 F1 — [PDF, Table 12](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- Augmentation: LLM-generated synthetic data lowered RoBERTa F1 by 5.13 (to 65.42); out-of-distribution data added +0.86 — [PDF, Table 8](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- Failure modes: frequent confusions such as T1112 vs T1547.001 and T1140 vs T1027. In AnnoCTR, two annotators had only 31% agreement on ATT&CK concepts. The authors "suspect that the ATT&CK framework is not always sufficiently unambiguous" — [PDF, Sec. 9](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- Recommendation: low-precision systems suit use as "data-labeling recommendation tools"; classification trained on high-quality data is preferable when precision matters — [PDF, Sec. 9](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)

**CTIBench (LLM benchmark).** M. T. Alam, D. Bhusal, L. Nguyen, N. Rastogi, "CTIBench: A Benchmark for Evaluating LLMs in Cyber Threat Intelligence", NeurIPS 2024 Datasets and Benchmarks Track; arXiv:2406.07599 — [arXiv PDF](https://arxiv.org/pdf/2406.07599v3); [project page](https://maveryn.github.io/cti-bench/)
- The CTI-ATE task is built from MITRE ATT&CK malware (software) descriptions: 30 malware reported in 2024 and 30 before 2024, with techniques only (no sub-techniques). The paper says the dataset "comprises 397 unique attack techniques" (as written) — [arXiv PDF, Sec. 3.4](https://arxiv.org/pdf/2406.07599v3)
- Metric inconsistency: the text says "We adopt the Micro-F1 score", but Table 1's header says "CTI-ATE (Macro-F1)" — [arXiv PDF](https://arxiv.org/pdf/2406.07599v3)
- Results: GPT-4 0.6388, LLAMA3-70B 0.4720, Gemini-1.5 0.4612, GPT-3.5 0.3108, LLAMA3-8B 0.1562. Before vs after the knowledge cutoff, GPT-4 scored 0.6542 vs 0.6208, and the differences were "generally insignificant" — [arXiv PDF, Tables 1–2](https://arxiv.org/pdf/2406.07599v3)
- Conflict: Ryan et al. (2026) state that CTIBench "places GPT-4 at micro F1 in the mid-0.30s". That does not match CTIBench's own Table 1 (0.6388) — [Ryan et al. 2026](https://arxiv.org/abs/2606.18166)
- **AthenaBench** (M. T. Alam, D. Bhusal et al., arXiv:2511.01144, Nov 2025, revised Feb 2026) extends CTIBench with deduplication, refined metrics and larger, more current ATE data. A secondary summary reports ATE of about 76% for GPT-5 and Gemini-2.5-Pro and as low as 5.6% for Qwen3-4B [SECONDARY] — [arXiv](https://arxiv.org/abs/2511.01144); [Liner summary](https://liner.com/review/athenabench-dynamic-benchmark-for-evaluating-llms-in-cyber-threat-intelligence)

**Ryan et al. 2026 (open-source LLMs, multi-label, real reports).** A. Ryan, S. S. Noor, M. Erfan, S. Mitra, S. Mittal, M. R. Rahman, "Evaluating Open-Source LLMs for Multi-Label ATT&CK Technique Classification on CTI Reports", arXiv:2606.18166, 16 Jun 2026, DOI 10.48550/arXiv.2606.18166 — [arXiv](https://arxiv.org/abs/2606.18166)
- Data: 2,076 sentences (1,281 technique-positive, 795 negative) from 83 DFIR Report incident reports (Apr 2020–Feb 2025), with 114 techniques, κ = 0.68 and mean label cardinality 1.58 — [arXiv PDF](https://arxiv.org/pdf/2606.18166)
- Results: 7 LLMs (8B–236B) were tested. The best micro-F1 was 0.22 (DeepSeek-V2 236B, T=0, 3-shot, CoT). RAG with Llama-3.1-70B reached micro-F1 0.32, with recall rising from 0.23 to 0.41. Model size was the only significant predictor (ρ = 0.85, p = 0.014), and prompt strategy and temperature had no significant effect — [arXiv PDF](https://arxiv.org/pdf/2606.18166)
- Failure modes:
  - Over-prediction: Gemma-3-12B recall was about 2.2× its precision
  - Under-prediction: gpt-oss-20B recall ≤ 0.04
  - Hallucinating techniques from keywords in benign sentences
  - Sibling-technique confusion
  — [arXiv PDF](https://arxiv.org/pdf/2606.18166)
- The authors attribute earlier tools' high numbers (TTPDrill 0.82, TTPHunter 0.88, TTPXHunter 0.97, AttacKG 0.79) to methodology: restriction to the top-50 techniques, training on ATT&CK procedure descriptions, and report-level scoring — [arXiv PDF, Sec. VI](https://arxiv.org/pdf/2606.18166)

**Other LLM studies**
- **Nguyen et al.:** H. C. Nguyen, S. Tariq, M. Baruwal Chhetri, B. Q. Vo, "Towards Effective Identification of Attack Techniques in Cyber Threat Intelligence Reports using Large Language Models", Companion Proc. ACM Web Conference (WWW '25); arXiv:2505.03147 — [arXiv](https://arxiv.org/html/2505.03147v1)
  - Zero-shot Llama2: F1 0.27 (7B), 0.12 (13B), 0.24 (70B) on Adversary Emulation Library reports; 70B found more true positives but many more false positives
  - TRAM-SciBERT baseline F1 "just over 0.4"
  - GPT-3.5 summarisation before SciBERT gave a slight gain; LLM-augmented rebalanced retraining raised median F1 by about 7 points
  — [arXiv](https://arxiv.org/html/2505.03147v1)
- **Mezzi et al.:** E. Mezzi, F. Massacci, K. Tuma, "Large Language Models Are Unreliable for Cyber Threat Intelligence", ARES 2025 [venue per search summary]; arXiv:2503.23175. Three LLMs on 350 reports were "inconsistent and overconfident". Few-shot and fine-tuning help only partially, and performance degrades on full-length reports — [arXiv](https://arxiv.org/abs/2503.23175v3)
- **Fayyazi et al.:** R. Fayyazi, R. Taghdimi, S. J. Yang, "Advancing TTP Analysis: Harnessing the Power of Large Language Models with Retrieval Augmented Generation", arXiv:2401.00280. They compare fine-tuned encoders with decoder LLMs plus RAG on ATT&CK v14.1 procedure descriptions. RAG decoders do better, especially when directly relevant context is retrieved, but show "low 'Precision' while achieving high 'Recall'" — [arXiv](https://arxiv.org/html/2401.00280v3)
  - Ryan et al. quote Samples-F1 of 0.60 prompt-only, 0.68 with similar-procedure RAG and 0.95 with exact-URL RAG [SECONDARY] — [Ryan et al. 2026](https://arxiv.org/pdf/2606.18166)
- **aCTIon:** G. Siracusano et al. (NEC Labs Europe), "Time for aCTIon: Automated Analysis of Cyber Threat Intelligence in the Wild", arXiv:2307.10214, 2023. It is a GPT-3.5 pipeline (condense, then extract and self-verify) with a 204-report STIX-labelled dataset, and claims F1 gains of 10–50 points over 10 prior tools — [arXiv](https://www.arxiv.org/abs/2307.10214)
- **IntelEX:** M. Xu, H. Wang, J. Liu et al., "IntelEX: A LLM-driven Attack-level Threat Intelligence Extraction Framework", arXiv:2412.10872. The same arXiv ID now resolves under the title "ThreatPilot: Attack-Driven Threat Intelligence Extraction", so the paper was renamed. It uses chunking, an ATT&CK vector DB and an LLM-as-judge against hallucination, and self-reports average technique F1 0.792 on 16 manually labelled reports — [arXiv v1](https://arxiv.org/html/2412.10872v1)
- **Haque et al.:** M. N. Haque, S. Hamer, B. Wroblewski, "Beyond Single Reports: Evaluating Automated ATT&CK Technique Extraction in Multi-Report Campaign Settings", arXiv:2604.07470 (Apr 2026); cited as ASE 2026 by Ryan et al. [venue UNVERIFIED]. It evaluates 29 methods on 90 reports about SolarWinds, XZ Utils and Log4j. Aggregating reports raised F1 by about 26%, with saturation after 5–15 reports. Maximum F1 was 78.6% (SolarWinds) and 54.9% (XZ Utils) — [arXiv](https://arxiv.org/pdf/2604.07470)
  - Ryan et al. cite Haque et al. for "sibling-technique confusion in 33.3% of misclassifications" [SECONDARY] — [Ryan et al. 2026](https://arxiv.org/pdf/2606.18166)
- **Kumarasinghe et al.:** zero-shot gpt-4-32k reached R@3 0.4406, against 0.8102 for their fine-tuned ranker — [arXiv](https://arxiv.org/html/2403.17068v1)

### Inferences
- **SoK unlabelled approaches:** These are the closest published analogue of ATTACKDNA's semantic index, and they show that pure similarity is precision-poor, especially with an open label set. ATTACKDNA differs in three ways that plausibly explain its higher precision:
  1. It indexes MITRE procedure-example sentences rather than technique descriptions.
  2. It adds a supervised logistic-regression vote and curated rules.
  3. It suggests about 1.36 techniques per sentence rather than every one above threshold.

  The report should present this as a hypothesis, since no ablation against the SoK setting has been run.
- **LLMs in general:** The LLM literature supports ATTACKDNA keeping the LLM optional. Prompted 8B–236B open models score micro-F1 of 0.22–0.32 on real multi-label sentences, and they degrade on whole reports (SoK Table 11; Mezzi et al.).
- **CTIBench CTI-ATE:** The inputs are MITRE ATT&CK software descriptions, which belong to the same source family as ATTACKDNA's training sentences. Running ATTACKDNA on CTI-ATE would be fair only if those 60 software entries and their procedure examples are excluded from its index and classifier.
- **Domain language models:** Since domain pre-training gives no consistent gain (SoK), ATTACKDNA's use of general-purpose MiniLM is defensible.

### Gaps
- I did not retrieve CTI-BERT's own ATT&CK classification numbers or the AthenaBench v2 tables (only a secondary summary).
- The exact meaning of CTIBench's "397 unique attack techniques" is unclear given ATT&CK's roughly 200 top-level techniques; it may count technique occurrences. I could not resolve this from the text.
- I found no published evaluation of a MiniLM-style small embedder + logistic regression on TRAM2 or AnnoCTR, so ATTACKDNA's design has no exact published twin.

## Q3. Datasets and benchmarks (TRAM, MITRE procedure examples, AnnoCTR, CTIBench CTI-ATE, TTPHunter data, others): label granularity and known issues

### Takeaway
Public ATT&CK-labelled data falls into three types:
- MITRE-derived single-label sentences (procedure examples; TTPHunter/TTPXHunter data; Orbinato's CTI-to-MITRE; parts of Kumarasinghe's set)
- Real-report sentence or span annotations (TRAM2, AnnoCTR, CTI-HAL, Ryan et al.'s DFIR Report set)
- Document-level label sets (rcATT, MITREtrieval, CTIBench CTI-ATE)

Known problems are heavy class imbalance, top-50 restriction (TRAM), single labels on sentences that really carry several techniques, missing negative (non-technique) sentences, low inter-annotator agreement, and leakage risk when the test text comes from MITRE itself.

### Cited Findings

**SoK comparison of labelled datasets** — [Büchel et al. 2025, Table 4](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf):

| Dataset | Granularity | Reports | Sentences | Labels |
|---|---|---|---|---|
| AnnoCTR | word | 120 | 4,491 | 12 tactics; 133 techniques/sub-techniques |
| TRAM2 | sentence | 150 | 19,011 | 50 techniques |
| CTI-to-MITRE (Orbinato) | sentence | — | 12,945 | 188 |
| Kumarasinghe et al. | sentence | — | 12,006 | 410 |
| rcATT | document | 1,490 | — | 12 tactics; 215 techniques |
| MITREtrieval | document | 700 | — | 14 tactics; 165 techniques |

- The SoK excluded MITRE-derived sets "because they lack real CTI report sentences". It split TRAM2 80/20 by whole reports (3,829 of 19,178 labels in test) — [Büchel et al. 2025, Sec. 3](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)

**TRAM data.** Ryan et al. say TRAM "restricts annotations to the 50 most prevalent techniques and trains on simplified procedure examples rather than unsanitized incident reports" — [Ryan et al. 2026](https://arxiv.org/pdf/2606.18166). Other descriptions of the TRAM data:
- AnnoCTR describes TRAM as sentence-level, multi-label, Apache-2.0, with 3,772 annotations — [AnnoCTR](https://arxiv.org/html/2404.07765v1)
- Orbinato et al. used 1,482 TRAM samples (techniques with more than one sample) from the earlier release — [Orbinato et al.](https://arxiv.org/pdf/2208.12144.pdf)

**MITRE procedure examples as training/test data.**
- Rahman & Williams built their benchmark from ATT&CK procedure descriptions, arguing that "the procedure-technique mapping done by these professionals are our ground truth" — [Rahman & Williams](https://arxiv.org/pdf/2210.02601v1.pdf)
- AttacKG used 7,373 procedure examples of 179 techniques as templates — [AttacKG](https://arxiv.org/pdf/2111.07093)
- Kumarasinghe et al. traced 1,180 procedure examples back to the matching text in 662 source reports — [Kumarasinghe et al.](https://arxiv.org/html/2403.17068v1)

**AnnoCTR.** L. Lange, M. Müller, G. Haratinezhad Torbati, D. Milchevski, P. Grau, S. Pujari, A. Friedrich, "AnnoCTR: A Dataset for Detecting and Linking Entities, Tactics, and Techniques in Cyber Threat Reports", LREC-COLING 2024, ACL Anthology 2024.lrec-main.103; arXiv:2404.07765 — [ACL Anthology](https://aclanthology.org/2024.lrec-main.103); [arXiv](https://arxiv.org/html/2404.07765v1)
- Contents: 400 CTRs with general entities, 120 of them also annotated by a domain expert with cybersecurity concepts. Technique and tactic spans are marked explicit or implicit (1,098 explicit vs 2,292 implicit technique mentions) and linked to ATT&CK — [arXiv](https://arxiv.org/html/2404.07765v1)
- Split: temporal, with each vendor in every split; 70/16/34 documents for train/dev/test — [arXiv](https://arxiv.org/html/2404.07765v1)
- Licence: CC-BY-SA per the paper; an Augsburg repository record lists CC-BY-NC 4.0 — [Augsburg OPUS](https://opus.bibliothek.uni-augsburg.de/opus4/frontdoor/index/index/docId/126484)
- Results:
  - Technique linking with gold spans: accuracy 66.9 (retrained GENRE, R@10 87.8)
  - Document-level technique detection, micro-F1: 45.2 (negative-class setting), 56.6 (with sentence filtering), 65.7 (gold sentences)
  - Adding 7,972 sentences from ATT&CK descriptions improved techniques (42.5 → 45.2) but was mixed for tactics
  — [arXiv](https://arxiv.org/html/2404.07765v1)
- Critique of prior data: earlier ATT&CK datasets "either provide a single label per document or annotate sentences out-of-context" — [arXiv](https://arxiv.org/abs/2404.07765)

**CTI-HAL.** S. Della Penna, R. Natella, et al., "CTI-HAL: A Human-Annotated Dataset for Cyber Threat Intelligence Analysis", IEEE EuroS&P 2025 Workshops; arXiv:2504.05866; github.com/dessertlab/CTI-HAL — [arXiv](https://www.arxiv.org/abs/2504.05866)
- Contents: 81 reports from the Adversary Emulation Library, with statement-level annotations traceable to source positions. It covers 116 techniques, 104 sub-techniques and 111 tools, aligned with ATT&CK v15.1. Agreement was measured with Krippendorff's α, and the set was used to evaluate a Claude 3 Haiku pipeline [details partly from search summary] — [arXiv](https://arxiv.org/pdf/2504.05866)
- Conflict: Ryan et al. say CTI-HAL "only includes 116 annotated sentences because it ignores sentences without techniques". That may conflate with the "116 techniques" count — [Ryan et al. 2026](https://arxiv.org/pdf/2606.18166)

**Ryan et al. DFIR Report set.** It has 2,076 sentences, 114 techniques, negatives included and κ = 0.68 — [Ryan et al. 2026](https://arxiv.org/pdf/2606.18166)
- Imbalance: about 50% of annotations fall in a few techniques (e.g. Command and Scripting Interpreter), with mean imbalance ratio 82.64
- Multi-label: 766 of 1,281 positive sentences (59.8%) have one label, so about 40% carry two or more
- Source: [Ryan et al. 2026](https://arxiv.org/pdf/2606.18166)

**TTPHunter/TTPXHunter data.** It is MITRE-derived, single-label, with 10,906 sentences augmented to 39,296 over 193 TTPs, imbalanced (3 to 800 samples per class), plus 149 manually labelled reports — [TTPXHunter](https://arxiv.org/html/2403.03267v3)

**Kumarasinghe et al. (Text2TTP).** 6,612 behaviours over 410 techniques from four sources; only the CISA portion is multi-label; an IOC-sanitised variant is released — [arXiv](https://arxiv.org/html/2403.17068v1); [GitHub](https://github.com/qcri/Text2TTP)

**CTIBench CTI-ATE.** 60 MITRE software descriptions, techniques only, document-level label sets, half dated after the models' cutoff to limit memorisation — [CTIBench](https://arxiv.org/pdf/2406.07599v3)

**aCTIon dataset.** 204 public reports with structured STIX CTI — [aCTIon](https://www.arxiv.org/abs/2307.10214)

**rcATT dataset.** Technique labels are imbalanced, with some techniques linked to a single report; techniques with fewer than 5 reports were dropped — [rcATT](https://arxiv.org/pdf/2004.14322)

**Single-label limitation.** The SoK notes that many works use "a single-label multi-class classification task, limiting models to identifying only one TTP per sentence" — [Büchel et al. 2025](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf). TTPXHunter states it "maps a given sentence to a single TTP" — [TTPXHunter](https://arxiv.org/html/2403.03267v3)

**Systematic review.** M. Tamanna et al., "What Are Adversaries Doing? Automating Tactics, Techniques, and Procedures Extraction: A Systematic Review", arXiv:2604.02377 (Apr 2026). It covers 80 peer-reviewed studies. Technique-level classification dominates, many studies use single-label classification and narrow datasets, and reproducibility is limited by proprietary data and missing code [details partly from secondary summary] — [arXiv](https://arxiv.org/abs/2604.02377)

### Inferences
- **Lower-bound precision:** ATTACKDNA's statement that its 60.1% sentence-level precision is a "lower bound" because MITRE sentences carry one label is supported by the literature. About 40% of technique-bearing real report sentences carry two or more techniques (Ryan et al.), so some "wrong" second suggestions on MITRE sentences are likely correct. The report should still call this a hypothesis unless a sample of false positives is re-annotated.
- **Held-out actors:** ATTACKDNA's held-out-actor test on procedure examples is the same data family as Orbinato, Rahman & Williams and TTPXHunter, but with a stricter split. It is not comparable to TRAM2 or AnnoCTR, which are real report sentences that include non-technique sentences.
- **Best independent test sets:** AnnoCTR (CC-BY-SA, real vendor reports, temporal split) and Ryan et al.'s DFIR Report set (realistic incident reports, negatives included) are the best public candidates for an independent ATTACKDNA document-level evaluation to replace or complement the 40 synthetic reports. TRAM2 is also usable, but only for top-50 techniques.

### Gaps
- I did not verify the current public download and licence of the TRAM2 annotated corpus or of Ryan et al.'s DFIR Report set (the paper says the dataset is provided; I did not check the repository).
- I did not find a published dataset that splits MITRE procedure examples by threat group or software. Held-out-actor evaluation on procedure examples appears to be uncommon or undocumented.

## Q4. Extraction of other incident attributes (attack type, initial access vector, severity) and CVE enrichment (e.g., CISA KEV)

### Takeaway
Almost all of this literature targets techniques and tactics. I found no standard benchmark for extracting an incident's attack type or initial-access vector from free-text reports. The nearest neighbours are VERIS-style entity extraction, CSIRT incident categorisation with LLMs, CTIBench's CVSS-from-description task (severity) and CVE-to-ATT&CK mapping (SMET). CVE enrichment from CISA KEV is a lookup task with documented fields and needs no learning.

### Cited Findings

**Severity**
- CTIBench CTI-VSP asks LLMs to predict a CVSS v3 base vector from 1,000 CVE descriptions from 2024, scored by mean absolute deviation (MAD) of the derived score. Results: Gemini-1.5 1.09 (best), GPT-4 1.31, GPT-3.5 1.57, LLAMA3-70B 1.83, LLAMA3-8B 1.91. Models tend to overestimate severity, especially the Llama models — [CTIBench](https://arxiv.org/pdf/2406.07599v3)
- CTIBench also has CTI-RCM (CVE → CWE root-cause mapping), where GPT-4 scores 72.0% accuracy — [CTIBench Table 1](https://arxiv.org/pdf/2406.07599v3)

**Attack type and incident vector**
- A 2026 CIGRE paper ("VERISBERT") fine-tuned a DarkBERT-based model on about 2,200 annotated incident narratives to extract VERIS 4A ACTOR/ACTION/ASSET entities and reports high token-level accuracy [SECONDARY; exact figures not retrieved] — [CIGRE D2-12394-2026](https://www.e-cigre.org/publications/detail/d2-12394-2026-verisbert-exploring-darkberts-capabilities-for-cyber-threat-intelligence-in-critical-infrastructure.html)
- A Brazilian SBSeg paper evaluates prompt engineering in commercial LLMs for CSIRT incident categorisation, citing the VERIS and FIRST taxonomies [details not retrieved] — [SBSeg](https://sol.sbc.org.br/index.php/sbseg/article/view/36624)
- A CEUR paper tests LLM generation of NIS2 incident vectors (Italian TC–ACN taxonomy) from logs — [CEUR Vol-4198](https://ceur-ws.org/Vol-4198/paper28.pdf)

**CVE to ATT&CK.** SMET maps CVE text to 185 ATT&CK techniques without labelled CVE–technique pairs (SRL + ATT&CK BERT + logistic regression) — [SMET](https://csrc.nist.gov/pubs/conference/2023/07/12/smet-semantic-mapping-of-cve-to-attck-and-its-appl/final). Its Recall@5 is reported as 67.71% in later work [SECONDARY] — [arXiv:2508.18439](https://arxiv.org/pdf/2508.18439)

**CVE normalisation in TTP pipelines.** CVEs are often normalised away as IOCs before classification:
- TTPXHunter replaces IPs, domains, file paths, registry keys and CVEs with base names — [TTPXHunter](https://arxiv.org/html/2403.03267v3)
- Kumarasinghe et al. replace IOCs, CVEs included, with placeholders using iocparser — [Kumarasinghe et al.](https://arxiv.org/html/2403.17068v1)

**CISA KEV catalog.**
- CISA calls KEV "the authoritative source of vulnerabilities that have been exploited in the wild" and recommends it as an input to vulnerability prioritisation — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Each entry shows CVE ID, Vendor/Project, Product, vulnerability name and description, Related CWE(s), "Known To Be Used in Ransomware Campaigns?", Date Added, Due Date, required action and notes. It is downloadable as CSV, JSON and JSON Schema, and the page showed 1,781 entries when fetched on 2026-11-14 — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- JSON field names reported by secondary sources: cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes. knownRansomwareCampaignUse (Known/Unknown) was reportedly added in Oct 2023 and has been changed after publication [SECONDARY] — [Socket glossary](https://socket.dev/glossary/cisa-kev); [GreyNoise](https://www.greynoise.io/blog/unmasking-cisas-hidden-kev-ransomware-updates)
- The current page references BOD 26-04 for forensic triage and mitigation; I did not verify that directive's details — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

### Inferences
- ATTACKDNA's attack-type classification (85.7% on 28 real Wikipedia summaries) and initial-vector extraction have no standard public benchmark to compare against. The report should present them as novel, small-sample results, not as beating a baseline.
- The 100% initial-vector and 92.5% attack-type figures on the 40 synthetic reports measure agreement with the team's own labels and should be reported with that caveat.
- Most TTP systems strip CVE IDs before classification. ATTACKDNA keeps CVEs as first-class output and can enrich them deterministically from KEV (exploited in the wild, ransomware use, CWE). That is a point of difference to state, and KEV adds no learned-model error.
- ATTACKDNA's severity is rule- or attribute-derived, while CTIBench CTI-VSP is CVSS from CVE text. They measure different things: incident severity vs vulnerability severity.

### Gaps
- I found no peer-reviewed benchmark for attack-type or initial-access-vector classification from incident narratives.
- The VERIS Community Database (VCDB) could serve as labelled ground truth (action/vector fields), but I did not retrieve sources on its use for NLP evaluation.
- I did not retrieve VERISBERT's or the SBSeg paper's numeric results.

## Q5. Recommended evaluation practices (held-out actors/groups, document-level vs sentence-level, metrics)

### Takeaway
Recent critical work converges on these practices:
- Split by whole report (or temporally or by vendor) rather than by sentence.
- Include non-technique sentences.
- Evaluate beyond the top-50 techniques.
- Report precision and recall separately, and state micro vs macro and per-document averaging.
- Guard against MITRE-text leakage and LLM memorisation.
- Treat single-label sentence benchmarks as optimistic.

No paper I found explicitly evaluates on held-out threat groups within MITRE procedure examples, so ATTACKDNA's held-out-attacker split is stricter than the random splits common in the MITRE-sentence literature.

### Cited Findings
- **Incomparability:** The SoK says existing solutions "are largely incomparable as they consider decisively different and constrained settings, rely on custom TTP ontologies, and use a multitude of custom, inaccessible CTI datasets" — [Büchel et al. 2025](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- **SoK protocol:** It assigns whole reports to train or test "to maintain compatibility with document-based approaches ... while ensuring that the context of each report remains intact". It computes F1 per document, combining sentence predictions per document, and averages across documents, noting "the average F1 score cannot be calculated from the average Recall and Precision" — [Büchel et al. 2025, Sec. 3](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- **Negative sentences:** The SoK prefers datasets with non-technique sentences, which are "relevant for replicating a realistic evaluation scenario" — [Büchel et al. 2025](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf). Ryan et al. include 795 negative sentences so the model must "distinguish between relevant and irrelevant information" — [Ryan et al. 2026](https://arxiv.org/pdf/2606.18166)
- **Label-set size:** Performance falls with the number of labels (SoK Fig. 4; Rahman & Williams) — [Büchel et al. 2025](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf); [Rahman & Williams](https://arxiv.org/pdf/2210.02601v1.pdf)
- **Temporal and vendor-stratified split:** AnnoCTR splits temporally and ensures each vendor appears in every split — [AnnoCTR](https://arxiv.org/html/2404.07765v1)
- **Memorisation control:** CTIBench separates samples from before and after each LLM's knowledge cutoff — [CTIBench](https://arxiv.org/pdf/2406.07599v3)
- **Leakage control:** Kumarasinghe et al. excluded "all text items containing the corresponding procedure examples" when testing on ATT&CK-derived reports, to avoid bias — [Kumarasinghe et al.](https://arxiv.org/html/2403.17068v1)
- **Sentence vs document level:**
  - Orbinato et al. evaluate both and find document-level F (about 50%) well below sentence-level F (72.5%) — [Orbinato et al.](https://arxiv.org/pdf/2208.12144.pdf)
  - SoK Table 11 shows LLM recall falling sharply at document level — [Büchel et al. 2025](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
  - Mezzi et al. say papers reporting high accuracy tested only sentences or short paragraphs — [Mezzi et al.](https://arxiv.org/abs/2503.23175v3)
- **Campaign level:** Haque et al. recommend moving beyond single-report evaluation; F1 rose about 26% when aggregating reports — [Haque et al.](https://arxiv.org/pdf/2604.07470)
- **Micro vs macro:** Ryan et al. report both and explain that macro shows rare-technique performance while micro reflects "operational coverage" — [Ryan et al. 2026](https://arxiv.org/pdf/2606.18166). TTPXHunter uses macro averaging — [TTPXHunter](https://arxiv.org/html/2403.03267v3). rcATT uses F0.5 micro and macro — [rcATT](https://arxiv.org/pdf/2004.14322)
- **Annotation reliability:** Ryan et al. report κ = 0.68 — [Ryan et al. 2026](https://arxiv.org/pdf/2606.18166). AnnoCTR's agreement on ATT&CK concepts was only 31%, per the SoK — [Büchel et al. 2025](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf)
- **Precision-recall trade-off:** The SoK recommends using low-precision systems as labelling recommenders for analysts — [Büchel et al. 2025](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf). rcATT deliberately weights precision with F0.5 — [rcATT](https://arxiv.org/pdf/2004.14322)
- **Group behaviour overlap:** Saha, Lindorfer and Caballero, "Kitten or Panda? Measuring the Specificity of Threat Group Behaviors in Public CTI Knowledge Bases", arXiv:2506.10645 (Jun 2025, v2 Jan 2026), find only 34% of ATT&CK groups have group-specific techniques, and after enrichment 64% of groups still have no group-specific behaviour — [arXiv](https://arxiv.org/abs/2506.10645)

### Comparison table: reported figures and why they are not directly comparable

| System / study | Test data | Unit | Label space | Metric | Reported | Source |
|---|---|---|---|---|---|---|
| ATTACKDNA (sentence) | 3,945 MITRE procedure sentences, 214 held-out sources | sentence, single gold label, ~1.36 suggestions/sentence | full ATT&CK | micro P/R | R 81.6, P 60.1, F1 69.2 | [mapper_results.json](/home/user/attackdna/data/evaluation/mapper_results.json) |
| ATTACKDNA (document) | 40 synthetic reports, team-labelled | report | full ATT&CK | micro-pooled P/R | P 83.6, R 49.2, F1 61.9 | [crossorg_results.json](/home/user/attackdna/data/evaluation/crossorg_results.json) |
| Orbinato et al. 2022 | 12,945 MITRE procedure samples, CV | sentence, single-label | 188 | F, AC@3 | F 72.5, AC@3 86.9 (SecureBERT) | [arXiv](https://arxiv.org/pdf/2208.12144.pdf) |
| Orbinato et al. 2022 | 6 real reports (ATT&CK-referenced) | document | 188 | F | about 50 | [arXiv](https://arxiv.org/pdf/2208.12144.pdf) |
| Rahman & Williams 2022 | MITRE procedure descriptions, 5-fold CV | description | 2–64 classes | F1 | 84 (TF-IDF) | [arXiv](https://arxiv.org/pdf/2210.02601v1.pdf) |
| TTPXHunter 2024 | augmented MITRE-derived sentences, 80:20 | sentence | 193 | macro-F1 | 92.42 | [arXiv](https://arxiv.org/html/2403.03267v3) |
| TTPXHunter 2024 | 149 reports | report | 193 | macro P/R/F1 | 97.38 / 96.15 / 97.09 | [arXiv](https://arxiv.org/html/2403.03267v3) |
| Kumarasinghe et al. 2024 | 1,212 mixed-source behaviours | passage | 410 (168 in test) | R@k, P@1 | R@3 81.0, P@1 57.8 | [arXiv](https://arxiv.org/html/2403.17068v1) |
| SoK 2025 (best labelled) | TRAM2 test reports / AnnoCTR test | per-doc averaged | 50 / 118 | F1 | 70.55 (RoBERTa-L) / 62.75 (CySecBERT) | [USENIX](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf) |
| SoK 2025 (embedding similarity) | TRAM2 / AnnoCTR | per-doc averaged | top set / all TTPs | F1 | 50.6 / 35.5; all-TTP 10.7 / 13.4 | [USENIX](https://www.usenix.org/system/files/usenixsecurity25-buechel.pdf) |
| LADDER 2023 | 5 malware reports | report | ATT&CK | P/R/F1 | 0.65 / 0.63 / 0.64 | [arXiv](https://arxiv.org/html/2211.01753v2) |
| AttacKG 2022 | 16 own labelled reports | report | 179 templates | F1 | 0.789 (re-evals 0.15–0.26) | [arXiv](https://arxiv.org/pdf/2111.07093) |
| rcATT 2020 | 1,490 ATT&CK-referenced reports, 5-fold CV | document | about 215 techniques | micro F0.5 (P/R) | 35.02 (37.18 / 29.79) | [arXiv](https://arxiv.org/pdf/2004.14322) |
| AnnoCTR 2024 | 34 test reports | document | ATT&CK | micro-F1 | 45.2 (realistic) to 65.7 (gold sentences) | [arXiv](https://arxiv.org/html/2404.07765v1) |
| CTIBench CTI-ATE 2024 | 60 MITRE software descriptions | document | techniques | micro/macro F1 (inconsistent) | GPT-4 0.6388 | [arXiv](https://arxiv.org/pdf/2406.07599v3) |
| Ryan et al. 2026 | 2,076 DFIR Report sentences | sentence, multi-label | 211 offered / 114 present | micro-F1 | 0.22 (0.32 with RAG) | [arXiv](https://arxiv.org/pdf/2606.18166) |
| Haque et al. 2026 | 90 reports, 3 campaigns | campaign | ATT&CK | F1 | max 78.6 / 54.9 | [arXiv](https://arxiv.org/pdf/2604.07470) |
| IntelEX 2024 | 16 labelled reports | report | ATT&CK | F1 | 0.792 (self-reported) | [arXiv](https://arxiv.org/html/2412.10872v1) |

### Inferences
- **Held-out attackers:** ATTACKDNA's split is stricter than the random CV or random 80:20 splits used by Orbinato, Rahman & Williams and TTPXHunter on the same kind of MITRE text, so its 69.2% sentence F1 is not inflated in the way theirs may be. "Kitten or Panda" shows that technique sets overlap heavily across groups. That makes held-out-actor splits fair for a technique classifier, because all labels remain in vocabulary, but it also means held-out actors do not guarantee unseen phrasing. Software shared across groups and MITRE's house writing style remain possible leakage routes. These are worth stating as limitations.
- **Metric choice:** ATTACKDNA's micro-pooled document P/R is not the SoK's per-document-averaged F1. Recomputing ATTACKDNA's document results as per-document averaged F1 would make them directly comparable with the SoK and AnnoCTR conventions.
- **Most defensible fair comparison:** Run ATTACKDNA unchanged on the AnnoCTR test split, and on the TRAM2 test split restricted to its 50 labels. Report per-document averaged P/R/F1 there, against the SoK's published figures (TRAM2 70.55 / AnnoCTR 62.75 labelled; 50.6 / 35.5 embedding-only).
- **Comparing with TTPXHunter, AttacKG and similar:** Their numbers are not comparable without re-running on the same test reports. The 0.15 to 0.97 spread for the same tools across papers shows how much test data and labelling dominate the score.

### Gaps
- I found no paper that splits MITRE procedure examples by threat group or software for evaluation, so I cannot cite precedent for ATTACKDNA's held-out-actor protocol. This may be a genuine gap that ATTACKDNA fills, but I cannot confirm it exhaustively.
- The SoK's appendix (error co-occurrence, Appendix F) and per-label breakdowns were not read in full.
- I did not obtain the Tamanna et al. review's RQ6 (metrics) and RQ7 (reproducibility) tallies in detail.
