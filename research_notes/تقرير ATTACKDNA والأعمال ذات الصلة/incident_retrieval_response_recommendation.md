# Similar-incident retrieval and response recommendation for cybersecurity incident response: related work for ATTACKDNA

How these notes were checked (read this before citing). Bibliographic data (authors, title, venue, year, DOI) was checked in this session against Crossref, the arXiv API or Semantic Scholar, unless an item is marked **[bib unverified]**. Quantitative results come from the paper's abstract or full text, which were read in this session, unless an item is marked **[result from search snippet / secondary summary – verify]**. Every bullet ends with an "ATTACKDNA:" line saying how the project compares. ATTACKDNA's own figures used for comparison: 20 cross-organisation pairs; top-1 55% (95% CI 34–74%); top-5 95%; response reused 90%.

## 1. Case-based reasoning (CBR) for incident response and intrusion handling: which systems, what results?

### Takeaway
CBR has been proposed for intrusion handling and incident response since the mid-1990s. The line runs from Esmaili et al. (1996) through IRSS (2006), Woskov et al. (2011), ReasONets (2012/2014) and CCIRS (2019) to "Cases and Clusters" (2025). Most systems retrieve past cases by attribute or ontology similarity and reuse the stored response plan. Evaluations are small or qualitative, and no shared benchmark exists. None of these systems uses ATT&CK-technique fingerprints with dense embeddings, shares a case base across organisations, or reports how often and how well a recalled response worked.

### Cited Findings
- **Foundation:** A. Aamodt and E. Plaza, "Case-Based Reasoning: Foundational Issues, Methodological Variations, and System Approaches," *AI Communications* 7(1), 1994. DOI [10.3233/AIC-1994-7104](https://doi.org/10.3233/AIC-1994-7104). This paper defines the canonical retrieve / reuse / revise / retain cycle. ([Crossref record](https://doi.org/10.3233/AIC-1994-7104))
  - ATTACKDNA: maps directly onto the cycle. "Ask the memory" is *retrieve*, recalled response actions are *reuse*, effectiveness feedback is *revise*, and adding the new fingerprint is *retain*. The report can present ATTACKDNA as a CBR system with an embedding-based retrieve step and a structural-overlap re-rank step.
- M. Esmaili, B. Balachandran, R. Safavi-Naini and J. Pieprzyk, "Case-based reasoning for intrusion detection," *Proc. 12th Annual Computer Security Applications Conference (ACSAC)*, 1996. DOI [10.1109/CSAC.1996.569702](https://doi.org/10.1109/CSAC.1996.569702). This is an early application of CBR to intrusion detection. ([Crossref](https://doi.org/10.1109/CSAC.1996.569702))
  - ATTACKDNA: uses CBR for *post-detection recall and response*, not for detection.
- G. Capuzzi, L. Spalazzi and F. Pagliarecci, "IRSS: Incident Response Support System," *Int. Symp. on Collaborative Technologies and Systems (CTS'06)*, 2006, pp. 81–88. DOI [10.1109/CTS.2006.55](https://doi.org/10.1109/CTS.2006.55). IRSS classifies an attack, searches a case base for similar past attacks, and reuses the adapted response plans. Its evaluation focuses on the retrieval and classification phase. **[result from search snippet – verify]** ([ResearchGate entry](https://www.researchgate.net/publication/249739168_An_Incident_Response_Support_System))
  - ATTACKDNA: closest conceptual ancestor, since both retrieve similar past attacks and reuse responses. ATTACKDNA adds ATT&CK/CVE fingerprints, semantic embeddings, per-match explanations, and usage and effectiveness statistics for recalled actions.
- S. M. Woskov, M. R. Grimaila, R. F. Mills and M. W. Haas, "Design considerations for a case-based reasoning engine for scenario-based cyber incident notification," *IEEE Symp. on Computational Intelligence in Cyber Security (CICS)*, 2011, pp. 84–91. DOI [10.1109/CICYBS.2011.5949397](https://doi.org/10.1109/CICYBS.2011.5949397). The authors compared CBR, rule-based systems, Bayesian networks and neural networks against incident-notification criteria and concluded that CBR was the most suitable. Their design issues are case representation, indexing, knowledge acquisition and usability. **[result from search snippet – verify]** ([ResearchGate](https://www.researchgate.net/publication/224246890_Design_considerations_for_a_case-based_reasoning_engine_for_scenario-based_cyber_incident_notification))
  - ATTACKDNA: its "Attack DNA" is a concrete answer to the case-representation and indexing questions this paper raises.
- A. C. Squicciarini, G. Petracca, W. G. Horne and A. Nath, "Situational awareness through reasoning on network incidents," *Proc. 4th ACM CODASPY*, 2014, pp. 111–122. DOI [10.1145/2557547.2557562](https://doi.org/10.1145/2557547.2557562). An earlier version is G. Petracca et al., "ReasONets," *ACM CCS 2012* (short paper/poster), DOI [10.1145/2382196.2382308](https://doi.org/10.1145/2382196.2382308). ReasONets combines anomaly detection with CBR to reason about the nature, severity and sources of network incidents. It was evaluated on real-world data over networks of various sizes. **[result from search snippet – verify]** ([PSU-hosted PDF](https://bpb-us-e1.wpmucdn.com/sites.psu.edu/dist/0/12804/files/2016/02/Situational-Awareness-through-Reasoning-on-Network-Incidents.pdf))
  - ATTACKDNA: works at the level of incident reports and TTPs rather than network-flow anomalies, and it adds response recommendation.
- F. Jiang, T. Gu, L. Chang and Z. Xu, "Case Retrieval for Network Security Emergency Response Based on Description Logic," Springer LNCS, 2014, pp. 284–293. DOI [10.1007/978-3-662-44980-6_32](https://doi.org/10.1007/978-3-662-44980-6_32). It uses ontology/description-logic similarity to retrieve past emergency-response cases. No quantitative results were seen. ([Springer](https://link.springer.com/chapter/10.1007/978-3-662-44980-6_32))
  - ATTACKDNA: uses embeddings plus symbolic overlap instead of DL subsumption. Ontological matching is an alternative explainable similarity.
- R. C. Nunes, M. Colomé, F. A. Barcelos, M. Garbin, G. B. Paulus and L. A. de Lima Silva, "A Case-Based Reasoning Approach for the Cybersecurity Incident Recording and Resolution," *Int. J. of Software Engineering and Knowledge Engineering* 29(11n12), 2019, pp. 1607–1627. DOI [10.1142/S021819401940014X](https://doi.org/10.1142/S021819401940014X). The system, CCIRS, combines CBR with the IODEF incident-exchange standard to "retain concrete problem-solving experiences of cybersecurity incident resolution to be reused in the resolution of new incidents." The authors report experiments showing that security knowledge "can be retained... in a reusable memory improving the resolution of new cybersecurity problems." No headline numbers appear in the abstract. ([Crossref abstract](https://doi.org/10.1142/S021819401940014X))
  - ATTACKDNA: very close in spirit (a "reusable memory" of resolutions). The differences are ATTACKDNA's ATT&CK-based fingerprint instead of IODEF fields, its cross-organisation evaluation, and its effectiveness-weighted action recall.
- P. A. C. Guerra, R. C. Nunes and L. A. de Lima Silva, "A cases and clusters framework for recording, retrieving, and reusing response plans in structured cybersecurity incident management," *Engineering Applications of Artificial Intelligence* 160, 111831, 2025. DOI [10.1016/j.engappai.2025.111831](https://doi.org/10.1016/j.engappai.2025.111831). It stores past response plans as cases, combines CBR with clustering for retrieval and reuse, and argues that CBR is an explainable way to reuse knowledge from past incidents. **[result from search snippet – abstract not readable, paywalled – verify]** ([ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0952197625018330))
  - ATTACKDNA: this is the most recent and closest peer-reviewed CBR comparator and should be cited prominently. ATTACKDNA differs by using semantic embeddings, by showing explicit shared-technique, tactic, CVE and vector reasons for each match, and by testing cross-organisation recall.
- M. R. Al-Mousa, "Analyzing Cyber-Attack Intention for Digital Forensics Using Case-Based Reasoning," *Int. J. of Advanced Trends in Computer Science and Engineering*, 2019/2020. DOI [10.30534/ijatcse/2019/92862019](https://doi.org/10.30534/ijatcse/2019/92862019); arXiv [2101.01395](https://arxiv.org/abs/2101.01395). A small CBR model for attack-intent analysis. ([arXiv](https://arxiv.org/abs/2101.01395))
  - ATTACKDNA: minor comparator, low-tier venue.
- N. Wiratunga et al., "CBR-RAG: Case-Based Reasoning for Retrieval Augmented Generation in LLMs for Legal Question Answering," *ICCBR 2024*, Springer LNCS. DOI [10.1007/978-3-031-63646-2_29](https://doi.org/10.1007/978-3-031-63646-2_29). It frames RAG retrieval as the CBR retrieve step. Its domain is legal, not security. ([Crossref](https://doi.org/10.1007/978-3-031-63646-2_29))
  - ATTACKDNA: supports framing ATTACKDNA's "Ask the memory" as CBR-style retrieval, which can optionally feed an LLM.

### Inferences
- The CBR line of work shows that "recall similar past incident, then reuse its response" is an established, defensible design. ATTACKDNA's novelty lies in the case representation (ATT&CK/CVE behaviour fingerprint), the two-stage retrieval (dense embedding, then explainable structural re-rank), action-level usage and effectiveness statistics, and cross-organisation evaluation.
- Prior CBR-for-IR papers rarely report retrieval metrics such as top-k hit rate. ATTACKDNA's top-1/top-5 reporting with a confidence interval is therefore more rigorous in form than most of them, even though n = 20 is small.

### Gaps
- I could not access full texts for IRSS, ReasONets, Jiang et al., or Guerra et al. 2025, so their exact similarity functions and quantitative results are unverified.
- I found no CBR-for-IR study that evaluates retrieval *across* organisations. That absence is from my search, not a proven negative.
- I found no CBR-for-IR work that indexes cases by ATT&CK technique sets specifically.

## 2. Similarity over ATT&CK technique sets, attack patterns and threat groups; incident correlation and deduplication in SOCs

### Takeaway
Two families exist. The first compares TTP *profiles*, mostly for threat-actor attribution or APT clustering, using Jaccard, weighted cosine, or vectorised ATT&CK matrices. It finds that raw technique overlap is weakly discriminative because a few generic techniques dominate. The second is industrial-scale SOC alert and incident correlation (DeepCASE, GraphWeaver, Microsoft CGR's similar-incident skill, NoDoze, Tiresias). It reports large workload reductions but uses detector or alert features, not ATT&CK fingerprints, and stays within a single tenant.

### Cited Findings
**TTP-profile similarity and threat-actor attribution**
- A. Saha, M. Lindorfer and J. Caballero, "Kitten or Panda? Measuring the Specificity of Threat Group Behaviors in Public CTI Knowledge Bases," *ACM ASIA CCS '26*, Bangalore, 2026. DOI [10.1145/3779208.3786258](https://doi.org/10.1145/3779208.3786258); arXiv [2506.10645](https://arxiv.org/abs/2506.10645).
  - Only 34% of ATT&CK groups have group-specific techniques. 73% have group-specific software, but only 24% in Malpedia.
  - After adding CVEs and report-extracted techniques, 64% of groups still lack any group-specific behaviour.
  - Pairwise Jaccard over group technique profiles, after removing the top-10 generic techniques: mean 0.04, median 0.02, max 0.50. The highest values arise from groups with very few non-generic techniques, where a single shared technique gives 0.50.
  - The most generic technique is T1204.002 (Malicious File, 79 groups), followed by T1105 (76) and T1566.001 (72).
  - The authors conclude that "removing generic behaviors is important to build accurate behavioral signatures."
  - Sources: [arXiv abstract](https://arxiv.org/abs/2506.10645); full text read in session.
  - A search-engine snippet gave different figures (mean 0.07, median 0.06, max 0.55), probably from another version. Use the published v2 figures.
  - ATTACKDNA: this is the key caution for the structural re-rank. Shared *generic* techniques (e.g., T1059, T1105, T1204) should be down-weighted, for example by IDF, or flagged as "weak evidence" in the "why it matched" explanation. ATTACKDNA's multi-field fingerprint (type, vector, CVEs, severity) partly mitigates this.
- K. Guru, R. J. Moss and M. J. Kochenderfer, "On Technique Identification and Threat-Actor Attribution using LLMs and Embedding Models," arXiv [2505.11547](https://arxiv.org/abs/2505.11547), 2025.
  - GPT-4 and text-embedding-3-large extract TTPs from CTI documents, and the results are compared against MITRE ATT&CK Groups.
  - LLM-generated TTP sets are noisy, with "low similarity to human-generated datasets," but they still train an attribution model that performs above baseline.
  - Reported average Jaccard for GPT-4 was about 0.39 ± 0.12 over 29 actors; embedding search scored higher; the baseline was about 6.6%. **[numbers from search snippet – verify]**
  - ATTACKDNA: shows that embedding search over CTI text is a viable route to TTP sets. ATTACKDNA's fingerprints inherit the same extraction noise if techniques are auto-extracted.
- Z.-S. Chen, R. Vaitheeshwari, E. H.-K. Wu, Y.-D. Lin, R.-H. Hwang, P.-C. Lin, Y.-C. Lai and A. Ali, "Clustering APT Groups Through Cyber Threat Intelligence by Weighted Similarity Measurement," *IEEE Access* 12, 2024. DOI [10.1109/ACCESS.2024.3469552](https://doi.org/10.1109/ACCESS.2024.3469552).
  - Features: ATT&CK techniques, software, target nations and industries, extracted from CTI reports by NER.
  - Similarity: weighted cosine with ML-derived feature weights, followed by hierarchical clustering.
  - Results: silhouette 0.76 and ARI 0.63; 23 labelled APT groups (35 in total) fall into 6 clusters. T1059 and T1036 appear in 18 of 23 groups.
  - Source: [author PDF](https://speed.cs.nycu.edu.tw/~ydlin/papers/Clustering_APT_Groups_Through_Cyber_Threat_Intelligence_by_Weighted_Similarity_Measurement.pdf), full text read.
  - ATTACKDNA: comparable "weighted multi-field similarity," but for incident-to-incident recall rather than group clustering. Chen et al. learn the weights, while ATTACKDNA uses hand-specified overlap terms, which are more explainable but untuned.
- R. Al-Shaer, J. M. Spring and E. Christou, "Learning the Associations of MITRE ATT&CK Adversarial Techniques," *IEEE CNS 2020*, pp. 1–9. DOI [10.1109/CNS48642.2020.9162207](https://doi.org/10.1109/CNS48642.2020.9162207). It learns technique associations and clusters from ATT&CK group and software data. ([Crossref](https://doi.org/10.1109/CNS48642.2020.9162207)) **[method details/results not read – verify]**
  - ATTACKDNA: technique co-occurrence could be used to predict likely next or unseen techniques for an in-progress attack in "Ask the memory."
- M. R. Rahman and L. Williams, "Investigating co-occurrences of MITRE ATT&CK Techniques," arXiv [2211.06495](https://arxiv.org/abs/2211.06495), 2022. It mines technique co-occurrence for 115 cybercrime groups and 484 malware with association rules and network analysis. T1059 and T1105 co-occur with many techniques, and Defense Evasion and Discovery are the most populated tactics. ([arXiv](https://arxiv.org/abs/2211.06495))
  - ATTACKDNA: confirms that generic, high-co-occurrence techniques will inflate overlap scores.
- K. Kim, Y. Shin, J. Lee and K. Lee, "Automatically Attributing Mobile Threat Actors by Vectorized ATT&CK Matrix and Paired Indicator," *Sensors* 21(19), 6522, 2021. DOI [10.3390/s21196522](https://doi.org/10.3390/s21196522). It vectorises the ATT&CK-for-Mobile matrix and pairs IoCs to reduce false flags; the evaluation covers 12 threat actors and 120 malware. Companion paper: Y. Shin, K. Kim, J. J. Lee and K. Lee, "ART: Automated Reclassification for Threat Actors based on ATT&CK Matrix Similarity," *World Automation Congress 2021*, pp. 15–20, DOI [10.23919/WAC50355.2021.9559514](https://doi.org/10.23919/WAC50355.2021.9559514). ([Crossref abstract](https://doi.org/10.3390/s21196522))
  - ATTACKDNA: an ATT&CK-matrix-vector similarity for actors. ATTACKDNA applies a similar idea at the incident level, adding CVEs and vector.
- U. Noor, Z. Anwar, T. Amjad and K.-K. R. Choo, "A machine learning-based FinTech cyber threat attribution framework using high-level indicators of compromise," *Future Generation Computer Systems*, 2019. DOI [10.1016/j.future.2019.02.013](https://doi.org/10.1016/j.future.2019.02.013). It attributes threats from TTP-level "high-level IoCs" in CTI reports. ([Crossref](https://doi.org/10.1016/j.future.2019.02.013)) **[results not read]**
- E. Irshad and A. B. Siddiqui, "Cyber threat attribution using unstructured reports in cyber threat intelligence," *Egyptian Informatics Journal*, 2023. DOI [10.1016/j.eij.2022.11.001](https://doi.org/10.1016/j.eij.2022.11.001). ([Crossref](https://doi.org/10.1016/j.eij.2022.11.001)) **[results not read]**
- Survey: N. Rani, B. Saha and S. K. Shukla, "A Comprehensive Survey of Advanced Persistent Threat Attribution: Taxonomy, Methods, Challenges and Open Research Problems," arXiv [2409.11415](https://arxiv.org/abs/2409.11415), 2024. According to the search snippet, it describes work using association-rule mining and a *weighted Jaccard* index over TTPs, and cosine similarity over TTP/IoC vectors. **[snippet – verify]**
  - ATTACKDNA: cite this survey for the general "Jaccard/cosine over TTP sets" approach that ATTACKDNA's structural overlap belongs to.
- F. Balassone et al., "Synthetic APTs: the Collapse of TTP-Based Attribution," arXiv [2606.07158](https://arxiv.org/abs/2606.07158), 2026. It questions whether TTP fingerprints stay distinctive when AI agents emulate APT groups (APT28, APT29, APT41, APT44, Lazarus) in cyber ranges. ([arXiv](https://arxiv.org/abs/2606.07158))
  - ATTACKDNA: a threat to validity for any TTP-fingerprint memory. ATTACKDNA's purpose is recall of *useful responses* rather than attribution, which makes it less sensitive to mimicry, and the report can say so.
- Technique extraction, which feeds fingerprints:
  - G. Husari et al., "TTPDrill," *ACSAC 2017*, DOI [10.1145/3134600.3134646](https://doi.org/10.1145/3134600.3134646).
  - V. Orbinato, M. Barbaraci, R. Natella and D. Cotroneo, "Automatic Mapping of Unstructured Cyber Threat Intelligence: An Experimental Study," *ISSRE 2022*, DOI [10.1109/ISSRE55969.2022.00027](https://doi.org/10.1109/ISSRE55969.2022.00027).
  - M. R. Rahman, R. Mahdavi Hezaveh and L. Williams, "What Are the Attackers Doing Now? … A Survey," *ACM Computing Surveys*, 2023, DOI [10.1145/3571726](https://doi.org/10.1145/3571726).
  - B. Abdeen, E. Al-Shaer, A. Singhal, L. Khan and K. Hamlen, "SMET: Semantic Mapping of CVE to ATT&CK and Its Application to Cybersecurity," *DBSec 2023* (LNCS), DOI [10.1007/978-3-031-37586-6_15](https://doi.org/10.1007/978-3-031-37586-6_15); extended in *Journal of Computer Security* 2024, DOI [10.3233/JCS-230218](https://doi.org/10.3233/JCS-230218).
  - All via Crossref.
  - ATTACKDNA: these are the upstream tools that would populate Attack DNA automatically. SMET is relevant because ATTACKDNA stores CVEs alongside techniques.

**Attack-pattern / alert-sequence similarity**
- A. Nadeem, S. Verwer, S. Moskal and S. J. Yang, "Alert-driven Attack Graph Generation using S-PDFA," *IEEE TDSC*, 2021, DOI [10.1109/TDSC.2021.3117348](https://doi.org/10.1109/TDSC.2021.3117348). Also A. Nadeem, S. Verwer and S. J. Yang, "SAGE: Intrusion Alert-driven Attack Graph Extractor," *IEEE VizSec 2021*, DOI [10.1109/VizSec53666.2021.00009](https://doi.org/10.1109/VizSec53666.2021.00009). Both build attack graphs, i.e. attacker strategies, from intrusion alerts. ([Crossref](https://doi.org/10.1109/TDSC.2021.3117348))
  - ATTACKDNA: represents an incident as an unordered technique set plus attributes, not as a sequence or graph. Order-aware similarity is a possible extension.
- Y. Shen, E. Mariconti, P.-A. Vervier and G. Stringhini, "Tiresias: Predicting Security Events Through Deep Learning," *ACM CCS 2018*. DOI [10.1145/3243734.3243811](https://doi.org/10.1145/3243734.3243811). It applies RNNs to 3.4 billion IPS events and predicts the next event with precision up to 0.93. ([Semantic Scholar abstract](https://doi.org/10.1145/3243734.3243811))
  - ATTACKDNA: Tiresias predicts the *next step*. ATTACKDNA recalls *whole past incidents* for a partial description, a related but different task.
- Y. Shen and G. Stringhini, "ATTACK2VEC: Leveraging Temporal Word Embeddings to Understand the Evolution of Cyberattacks," *USENIX Security 2019*, [usenix.org](https://www.usenix.org/conference/usenixsecurity19/presentation/shen). **[bib unverified in this session]**
  - ATTACKDNA: an early example of embedding security events. ATTACKDNA embeds incident text with MiniLM instead.

**SOC alert and incident correlation and deduplication**
- T. van Ede, H. Aghakhani, N. Spahn, R. Bortolameotti, et al., "DeepCASE: Semi-Supervised Contextual Analysis of Security Events," *IEEE S&P 2022*. DOI [10.1109/SP46214.2022.9833671](https://doi.org/10.1109/SP46214.2022.9833671).
  - It groups events by their context, which "provides valuable insights into why certain events are classified as malicious."
  - It automatically filters 86.72% of events and cuts manual workload by 90.53%, while underestimating risk in under 0.001% of cases.
  - Source: [Semantic Scholar abstract](https://doi.org/10.1109/SP46214.2022.9833671).
  - ATTACKDNA: both reuse analysts' past decisions on similar items. DeepCASE works at the event and alert level within one SOC; ATTACKDNA works at the incident and report level across organisations.
- S. Freitas and A. Gharib, "GraphWeaver: Billion-Scale Cybersecurity Incident Correlation," arXiv [2406.01842](https://arxiv.org/abs/2406.01842), 2024 (Microsoft Defender XDR).
  - It correlates alerts into incidents across hundreds of thousands of enterprises with "a 99% accuracy rate," based on customer feedback and expert review.
  - It reduces correlation storage by 7.4×, and the paper also reports a 7% drop in the singleton-incident rate.
  - Source: [arXiv](https://arxiv.org/abs/2406.01842).
  - ATTACKDNA: GraphWeaver answers "do these alerts belong to the same incident?" ATTACKDNA answers "which past incident does this one resemble?"
- S. Freitas, J. Kalajdjieski, A. Gharib and R. McCann, "AI-Driven Guided Response for Security Operation Centers with Microsoft Copilot for Security" (CGR), arXiv [2407.09017](https://arxiv.org/abs/2407.09017), 2024. Similar-incident skill:
  - Incidents are represented by an ordered-DetectorId hash plus a PCA embedding (k = 40, 95% variance) of 5 categorical and 67 numeric features.
  - Retrieval uses a 180-day window: exact hash matches first, then cosine-similarity matches above 0.9, keeping the top 5.
  - Matching is "within the same organization."
  - In an expert review of 1k incidents, 94% of recommended similar incidents were relevant and 2% dissimilar; 98% of incidents received at least one recommendation.
  - Source: [arXiv HTML, Secs. 4.1, 5.3, 7.4](https://arxiv.org/html/2407.09017v4).
  - ATTACKDNA: CGR is the strongest industrial comparator. Differences:
    - CGR matches on detector and alert telemetry, while ATTACKDNA matches on ATT&CK/CVE behaviour fingerprints.
    - CGR is restricted to one tenant, while ATTACKDNA tests *cross-organisation* recall.
    - CGR shows no per-match reasons, while ATTACKDNA explains each match.
    - CGR's 94% expert-relevance figure measures a different thing from ATTACKDNA's top-1 = 55% "finds the paired incident first."
- W. U. Hassan, S. Guo, D. Li, Z. Chen, K. Jee, Z. Li and A. Bates, "NoDoze: Combatting Threat Alert Fatigue with Automated Provenance Triage," *NDSS 2019*. DOI [10.14722/ndss.2019.23349](https://doi.org/10.14722/ndss.2019.23349). It scores alerts by how often related events occurred before in the enterprise (historical context). On 364 alerts it reduced false alarms by an estimated 84%. ([abstract](https://doi.org/10.14722/ndss.2019.23349))
  - ATTACKDNA: both use history to contextualise a new item. NoDoze uses frequency in provenance graphs for triage; ATTACKDNA uses incident similarity for response.

### Inferences
- The literature supports a hybrid "semantic plus symbolic" similarity. Embeddings give recall, and overlap terms give interpretability. Kitten-or-Panda shows the symbolic part must discount generic techniques. A defensible improvement for ATTACKDNA is IDF-weighted technique overlap, with explanations labelling generic shared techniques as weak evidence.
- ATTACKDNA's top-1 of 55% with 95% CI 34–74% at n = 20 is consistent with the literature's finding that TTP profiles are only moderately distinctive. Top-5 at 95% suggests shortlist-style presentation, as in CGR's top-5, is the right UX.

### Gaps
- No public benchmark was found for *incident-to-incident* retrieval keyed on ATT&CK fingerprints. Attribution datasets (ATT&CK Groups, Malpedia) and GUIDE (alerts, not TTP fingerprints) are the nearest substitutes.
- The exact numbers in Guru et al. (Jaccard 0.39) and Rani et al. (weighted Jaccard) came from snippets and were not confirmed against the full text.
- Full results of Al-Shaer et al. 2020, Noor et al. 2019 and Irshad & Siddiqui 2023 were not read.

## 3. Response and mitigation recommendation: knowledge graphs (ATT&CK → mitigations / D3FEND), SOC playbook recommenders, and evaluation of recommendation quality

### Takeaway
There are three strands:
- **Knowledge-driven** work (D3FEND, BRON, SEPSES, ATT&CK-mitigation and NIST-control mappings) links techniques to countermeasures *generically*, with little or no outcome evidence.
- **Data-driven** recommenders learn from historical analyst actions or playbooks (CGR remediation, IC-SECURE, LLM mitigation for cloud incidents) and report precision@k or precision/coverage.
- **Standards** work (CACAO, CSAF, playbook studies) makes responses shareable.

None found combines recalled actions with per-action usage frequency and effectiveness *and* labels each recommendation's source (memory vs. MITRE mitigation vs. baseline control), which is ATTACKDNA's distinguishing feature.

### Cited Findings
**Knowledge graphs and mappings**
- P. E. Kaloroumakis and M. J. Smith, "Toward a Knowledge Graph of Cybersecurity Countermeasures," The MITRE Corporation, 2021 (D3FEND), [d3fend.mitre.org/resources/D3FEND.pdf](https://d3fend.mitre.org/resources/D3FEND.pdf).
  - D3FEND is a knowledge graph with "semantically rigorous types and relations," built partly from "over 500 countermeasure patents" (2001–2018).
  - It "supports queries that can inferentially map cybersecurity countermeasures to offensive TTPs" through a Digital Artifact Ontology, which links offensive and defensive techniques via the artifacts they act on.
  - Full text read.
  - MITRE's D3FEND site offers an "ATT&CK Extractor" that extracts ATT&CK technique IDs from text and suggests D3FEND countermeasures: [D3FEND tool page](https://d3fend.mitre.org/tools/attack-extractor/).
  - ATTACKDNA: D3FEND or ATT&CK mitigations give *generic* countermeasures per technique. ATTACKDNA keeps those (labelled as such) and adds *experiential* actions recalled from similar incidents with usage and effectiveness evidence. A natural extension is to show D3FEND techniques next to the MITRE mitigations.
- E. Hemberg, J. Kelly, M. Shlapentokh-Rothman, B. Reinstadler, K. Xu, N. Rutar and U.-M. O'Reilly, "Linking Threat Tactics, Techniques, and Patterns with Defensive Weaknesses, Vulnerabilities and Affected Platform Configurations for Cyber Hunting" (BRON), arXiv [2010.00533](https://arxiv.org/abs/2010.00533), 2020. BRON is a graph linking ATT&CK, CAPEC, CWE and CVE with bidirectional path tracing; it was used, for example, to trace the top-10 exploited CVEs to techniques. ([arXiv](https://arxiv.org/abs/2010.00533))
  - ATTACKDNA: BRON-style CVE↔technique links could enrich fingerprints, for example by inferring techniques from a reported CVE.
- E. Kiesling, A. Ekelhart, K. Kurniawan and F. Ekaputra, "The SEPSES Knowledge Graph: An Integrated Resource for Cybersecurity," *ISWC 2019*, LNCS. DOI [10.1007/978-3-030-30796-7_13](https://doi.org/10.1007/978-3-030-30796-7_13). ([Crossref](https://doi.org/10.1007/978-3-030-30796-7_13))
- M. R. Rahman and L. Williams, "An investigation of security controls and MITRE ATT&CK techniques," arXiv [2211.06500](https://arxiv.org/abs/2211.06500), 2022.
  - Of 298 NIST SP 800-53 controls mapped to 188 techniques, only 101 can mitigate any technique, and 53 techniques have no mitigating control.
  - 20 "critical" controls mitigate 134 techniques, which on average covers 72% of the techniques used by 98% of ATT&CK adversaries.
  - Source: [arXiv](https://arxiv.org/abs/2211.06500).
  - ATTACKDNA: directly relevant to its "baseline controls" layer. The report can cite this as evidence that a small control baseline covers most catalogued behaviour, and that some techniques have no mapped control, which is where experiential memory adds value.
- P. Nespoli, D. Papamartzivanos, F. Gómez Mármol and G. Kambourakis, "Optimal Countermeasures Selection Against Cyber Attacks: A Comprehensive Survey on Reaction Frameworks," *IEEE Communications Surveys & Tutorials*, 2018. DOI [10.1109/COMST.2017.2781126](https://doi.org/10.1109/COMST.2017.2781126). A survey of automated countermeasure selection, including cost/benefit and attack-graph-based approaches. ([Crossref](https://doi.org/10.1109/COMST.2017.2781126)) **[content not read]**
  - ATTACKDNA: selects by similarity and observed effectiveness, not by optimisation over a cost model.
- M. Husák, L. Sadlek, S. Špaček, M. Laštovička, M. Javorník and J. Komárková, "CRUSOE: A toolset for cyber situational awareness and decision support in incident handling," *Computers & Security* 115, 102609, 2022. DOI [10.1016/j.cose.2022.102609](https://doi.org/10.1016/j.cose.2022.102609). ([Crossref](https://doi.org/10.1016/j.cose.2022.102609)) **[content not read – decision-support details unverified]**

**Data-driven recommenders and playbooks**
- CGR (Freitas et al., arXiv [2407.09017](https://arxiv.org/abs/2407.09017), 2024) remediation skill.
  - A random forest learns from *customer-provided analyst remediation actions* (contain user, isolate machine, stop VM).
  - It recommends only above a 0.9 precision threshold and reports "99% precision and 62% recall." The 62% is described elsewhere in the paper as online *coverage*, an inconsistency inside the paper.
  - Models are trained on pooled regional multi-organisation data with OrganizationId as a feature.
  - The positive user-response rate was 89%.
  - Source: [arXiv HTML Secs. 4–8](https://arxiv.org/html/2407.09017v4).
  - ATTACKDNA: CGR learns "what analysts did" across customers but hides provenance. ATTACKDNA exposes *which past incidents* an action came from, how often it was used, and how effective it was. CGR's action vocabulary has 3 actions; ATTACKDNA's is open.
- R. Kremer, P. N. Wudali, S. Momiyama, T. Araki, J. Furukawa, Y. Elovici and A. Shabtai, "IC-SECURE: Intelligent System for Assisting Security Experts in Generating Playbooks for Automated Incident Response," arXiv [2311.03825](https://arxiv.org/abs/2311.03825), 2023. A deep-learning recommender suggests the next SOAR playbook module from alert data and the partial playbook. On 3 datasets (alert rules plus playbooks) it reached precision@1 > 0.8 and recall@3 > 0.92, beating two recommender baselines. ([arXiv](https://arxiv.org/abs/2311.03825))
  - ATTACKDNA: IC-SECURE recommends *playbook structure* within one SOAR platform. ATTACKDNA recommends *response actions* recalled from similar incidents. IC-SECURE's precision@k reporting is a model for evaluating ATTACKDNA's action recommendations; ATTACKDNA currently reports "response reused in 90% of pairs."
- D. Schlette, P. Empl, M. Caselli, T. Schreck and G. Pernul, "Do You Play It by the Books? A Study on Incident Response Playbooks and Influencing Factors," *IEEE S&P 2024*, pp. 3625–3643. DOI [10.1109/SP54263.2024.00060](https://doi.org/10.1109/SP54263.2024.00060).
  - Method: an empirical analysis of 1,217 playbooks, an online study with 147 participants, and 9 interviews.
  - The abstract stresses that threat and organisational information are both crucial "for using, maintaining, and sharing playbooks across organizations" while ensuring "effectiveness and confidentiality."
  - Main finding: organisations do use playbooks but define their contents individually. **[the 9 interviews and this main finding come from a search-engine summary whose source could not be identified – verify in the paper]**
  - Source: [Semantic Scholar abstract](https://doi.org/10.1109/SP54263.2024.00060).
  - ATTACKDNA: supports the claim that cross-organisation response sharing is valued but constrained by organisational context and confidentiality. ATTACKDNA's fingerprint abstracts away organisation-specific details.
- P. Empl, D. Schlette, L. Stöger and G. Pernul, "Generating ICS vulnerability playbooks with open standards," *International Journal of Information Security* 23(2), 2024 (online 2023), pp. 1215–1230. DOI [10.1007/s10207-023-00760-5](https://doi.org/10.1007/s10207-023-00760-5). It transforms CSAF advisories into CACAO playbooks and shows structured advisories convert "seamlessly." ([Crossref abstract](https://doi.org/10.1007/s10207-023-00760-5))
  - ATTACKDNA: CACAO would be a natural export format for recalled response actions.
- D. Schlette, M. Caselli and G. Pernul, "A Comparative Study on Cyber Threat Intelligence: The Security Incident Response Perspective," *IEEE Communications Surveys & Tutorials*, 2021. DOI [10.1109/COMST.2021.3117338](https://doi.org/10.1109/COMST.2021.3117338). Also C. Islam, M. A. Babar and S. Nepal, "A Multi-Vocal Review of Security Orchestration," *ACM Computing Surveys* 52(2), 2019, DOI [10.1145/3305268](https://doi.org/10.1145/3305268). Both via Crossref.
  - ATTACKDNA: cite these for SOAR and CTI-for-IR background.
- "An Intelligent Playbook Recommendation Algorithm Based on Dynamic Interest Modeling for SOAR," *Symmetry*, 2025. DOI [10.3390/sym17111851](https://doi.org/10.3390/sym17111851). **[bib/authors and results unverified – search snippet only]**

**Analogous work in IT operations (cloud incidents)**
- T. Ahmed, S. Ghosh, C. Bansal, T. Zimmermann, X. Zhang and S. Rajmohan, "Recommending Root-Cause and Mitigation Steps for Cloud Incidents using Large Language Models," *ICSE 2023*. DOI [10.1109/ICSE48619.2023.00149](https://doi.org/10.1109/ICSE48619.2023.00149). This large-scale study at Microsoft covers more than 40,000 incidents. It compares GPT-3.x zero-shot, fine-tuned and multi-task settings using lexical and semantic metrics, plus human evaluation by incident owners. ([arXiv 2301.03797](https://arxiv.org/abs/2301.03797))
- Y. Chen et al., "Automatic Root Cause Analysis via Large Language Models for Cloud Incidents" (RCACopilot), *EuroSys 2024*. DOI [10.1145/3627703.3629553](https://doi.org/10.1145/3627703.3629553). It matches incidents to handlers, predicts the root-cause category and gives "an explanatory narrative," with RCA accuracy up to 0.766 on a year of Microsoft incidents. ([arXiv 2305.15778](https://arxiv.org/abs/2305.15778))
  - ATTACKDNA: these show that mitigation recommendation from historical incidents is mainstream in AIOps. ATTACKDNA brings the idea to security, using ATT&CK fingerprints and explicit provenance instead of generated text.

**How recommendation quality is evaluated**
- Observed metrics:
  - precision@1 and recall@3 against ground-truth playbook modules ([IC-SECURE](https://arxiv.org/abs/2311.03825))
  - macro-F1, precision and coverage, plus customer-feedback acceptance ([CGR](https://arxiv.org/html/2407.09017v4))
  - simulated recovery time, % ineffective actions and % failed recovery ([Hammar et al., §4](https://arxiv.org/html/2508.05188v1))
  - an LLM-as-judge cross-validated by experts ([Tellache et al.](https://arxiv.org/abs/2508.10677))
  - accuracy with inter-rater agreement: 93% / 64% ([LocalIntel](https://arxiv.org/abs/2401.10036))
  - lexical and semantic similarity to the actual mitigation, plus owner ratings ([Ahmed et al.](https://arxiv.org/abs/2301.03797))

### Inferences
- ATTACKDNA's "A's response is reused in 90% of pairs" is a coverage or recall-style metric. To be comparable with IC-SECURE or CGR, the report could add precision@k of recommended actions against the actions B actually took, or expert ratings.
- Labelling the source of each recommendation (memory, MITRE mitigation, or baseline control) is not reported by any system reviewed, so it can be claimed as a distinctive contribution. The claim should be worded as "not found in the reviewed literature."

### Gaps
- No peer-reviewed paper was found that empirically evaluates D3FEND- or ATT&CK-mitigation-based recommendations against real incident outcomes. D3FEND itself presents no quantitative evaluation.
- I found no study that tracks per-action *effectiveness* across past incidents to rank recommendations. CGR uses analyst actions but not their outcomes.
- CRUSOE's and Nespoli et al.'s specific recommendation mechanisms and results were not read.

## 4. LLM and RAG assistants for incident response and SOC triage (2023–2026): what they do, how they are evaluated, risks, and cross-organisation sharing

### Takeaway
Since 2023 the trend has been RAG or fine-tuned LLMs that ground answers in logs, CTI or documentation:
- retrieving log context for forensic questions (Cadet et al.)
- enriching alerts with CTI (Tellache et al.)
- organisation-specific threat intelligence (LocalIntel)
- multi-agent response simulation (AutoBnB-RAG)
- response planning with bounded hallucination (Hammar et al.)
- automated response pipelines (IRCopilot)

Evaluations are mostly on synthetic scenarios, public IDS datasets or LLM-judged outputs, with few real-SOC studies. One exception is Singh et al.'s 10-month field study, which found that analysts mainly use LLMs for sensemaking, not verdicts. The recurring risks are hallucination, context loss, privacy, and the lack of SOC-specific benchmarks. No system found shares a structured incident memory across organisations.

### Cited Findings
- R. Singh, S. Tariq, F. Jalalvand, M. B. Chhetri, S. Nepal, C. Paris and M. Lochner, "LLMs in the SOC: An Empirical Study of Human-AI Collaboration in Security Operations Centres," arXiv [2508.18947](https://arxiv.org/abs/2508.18947), 2025 (CSIRO Data61 with eSentire).
  - The study covers 3,090 GPT-4 queries by 45 SOC analysts over 10 months (May 2023 to March 2024).
  - Most queries concern interpreting low-level telemetry or refining communication, and only about 4% seek binary verdicts or recommendations.
  - The authors recommend an "evidence-first" mode that highlights log excerpts, command traces and ATT&CK linkages instead of prescriptive labels.
  - LLMs act as "on-demand cognitive aids that augment, rather than replace, SOC expertise."
  - Sources: [arXiv](https://arxiv.org/abs/2508.18947); details via [arXiv HTML](https://arxiv.org/html/2508.18947v2). **[the 4% and "evidence-first" details are from a search summary of the HTML – verify]**
  - ATTACKDNA: strong support for its design. It shows evidence (matched past incidents, shared techniques) rather than a verdict.
- X. Cadet, A. V. Singh, H. Mamania, E. Koh, A. Fitts, D. Van Bruggen, S. Boboila, P. Chin and A. Oprea, "Retrieval-Augmented LLMs for Security Incident Analysis," *ACM Conference on AI and Agentic Systems (CAIS 2026)*, San Jose; arXiv [2603.18196](https://arxiv.org/abs/2603.18196).
  - A RAG system uses a query library tagged with ATT&CK techniques to filter logs, then retrieves context to answer forensic questions.
  - Results: Claude Sonnet 4 reached 94% and DeepSeek V3 89% average recall over 17 malware scenarios, with DeepSeek about 15× cheaper; Llama 3.1 70B (local) reached 81%. On the Active Directory scenario, attack-step detection reached 100% precision and up to 96% recall.
  - Ablations confirm RAG retrieval is essential.
  - Source: [arXiv abstract](https://arxiv.org/abs/2603.18196).
  - ATTACKDNA: Cadet et al. retrieve *within one incident's logs*. ATTACKDNA retrieves *across past incidents*. The two are complementary.
- A. Tellache, A. Amara Korba, A. Mokhtari, H. Moldovan and Y. Ghamri-Doudane, "Advancing Autonomous Incident Response: Leveraging LLMs and Cyber Threat Intelligence," arXiv [2508.10677](https://arxiv.org/abs/2508.10677), 2025. Hybrid retrieval (a CTI vector database plus external CTI platform queries) enriches SIEM alerts, and an LLM generates mitigation strategies. Evaluation uses an auxiliary LLM judge cross-validated by experts, on real and simulated alerts. ([arXiv](https://arxiv.org/abs/2508.10677))
  - ATTACKDNA: retrieves past *incidents with outcomes* rather than generic CTI, and does not generate free text, so it has no hallucination surface for the recommendations themselves.
- K. Hammar, T. Alpcan and E. C. Lupu, "Incident Response Planning Using a Lightweight Large Language Model with Reduced Hallucination," *NDSS 2026*, San Diego. arXiv [2508.05188](https://arxiv.org/abs/2508.05188); [NDSS page](https://www.ndss-symposium.org/ndss-paper/incident-response-planning-using-a-lightweight-large-language-model-with-reduced-hallucination/).
  - Method: fine-tuning on logs from 68,000 incidents paired with response plans, RAG over threat-intelligence APIs (e.g., OTX), and lookahead planning.
  - It gives a provable bound on hallucination probability, defining a hallucinated action as one that makes no progress toward recovery.
  - Evaluation covers 25 incidents from 4 public datasets (CTU-Malware-2014, CIC-IDS-2017, AIT-IDS-V2-2022, CSLE-IDS-2024).
  - Recovery time was 13.46 versus 17.28 for OpenAI o3 (about 22% shorter). Ablations show fine-tuning matters most and RAG least.
  - Source: [arXiv HTML Table 4](https://arxiv.org/html/2508.05188v1).
  - A follow-up, "Hallucination-Resistant Security Planning with a Large Language Model," arXiv [2602.05279](https://arxiv.org/abs/2602.05279), is reported as accepted at NOMS 2026 with up to 30% shorter recovery times. **[from search summary – verify]**
  - ATTACKDNA: Hammar et al. learn from many past incidents but put that knowledge into model weights, which removes provenance. ATTACKDNA keeps incidents as retrievable, explainable cases.
- X. Lin, J. Zhang, G. Deng, T. Liu, T. Zhang, Q. Guo and R. Chen, "IRCopilot: Automated Incident Response with Large Language Models," arXiv [2505.20945](https://arxiv.org/abs/2505.20945), 2025.
  - The authors built an incremental benchmark from real IR tasks and identified "context loss, hallucinations, privacy protection concerns, and… limited ability to provide accurate, context-specific recommendations."
  - Four collaborating LLM sessions improve sub-task completion over baselines (reported as 150%, 138%, 136%, 119%, 114%, i.e. relative to baseline).
  - Source: [arXiv](https://arxiv.org/abs/2505.20945).
  - ATTACKDNA: IRCopilot's list of risks (hallucination, privacy, lack of context-specific advice) is a useful motivation paragraph for ATTACKDNA's non-generative, case-grounded recommendations.
- S. Mitra, S. Neupane, T. Chakraborty, S. Mittal, A. Piplai, M. Gaur and S. Rahimi, "LOCALINTEL: Generating Organizational Threat Intelligence from Global and Local Cyber Knowledge," arXiv [2401.10036](https://arxiv.org/abs/2401.10036), 2024. It retrieves global threat reports and contextualises them with a private local knowledge base to propose organisation-specific mitigations, reaching "up to 93% accurate" output with 64% inter-rater agreement. ([arXiv](https://arxiv.org/abs/2401.10036))
  - ATTACKDNA: LocalIntel combines *global public* knowledge with *one organisation's* private knowledge. ATTACKDNA's shared memory is a third option: *peer organisations'* incident experience.
- Z. Liu and A. Anwar, "AutoBnB-RAG: Enhancing Multi-Agent Incident Response with Retrieval-Augmented Generation," arXiv [2508.13118](https://arxiv.org/abs/2508.13118), 2025. Agents in a Backdoors & Breaches tabletop simulation retrieve either technical documentation (RAG-Wiki) or narrative incident reports (RAG-News). Retrieval "improves decision quality and success rates" across 8 team structures. ([arXiv](https://arxiv.org/abs/2508.13118))
  - ATTACKDNA: RAG-News, which retrieves past incident narratives, is the closest LLM analogue to recalling past incidents. ATTACKDNA does this with structured fingerprints and explicit match reasons.
- F. Y. Loumachi, M. C. Ghanem and M. A. Ferrag, "GenDFIR: Advancing Cyber Incident Timeline Analysis Through Retrieval Augmented Generation and Large Language Models," *Computers* 14(2), 67, 2025. DOI [10.3390/computers14020067](https://doi.org/10.3390/computers14020067); arXiv [2409.02572](https://arxiv.org/abs/2409.02572). It uses Llama 3.1 8B with RAG over a structured incident-event knowledge base and was tested on synthetic data. ([arXiv](https://arxiv.org/abs/2409.02572))
- Other LLM-for-IR and CTI work:
  - S. Hays and J. White, "Employing LLMs for Incident Response Planning and Review," arXiv [2403.01271](https://arxiv.org/abs/2403.01271), 2024. This is a position/qualitative paper that stresses "the need for human oversight."
  - P. Tseng, Z. Yeh, X. Dai and P. Liu, "Using LLMs to Automate Threat Intelligence Analysis Workflows in Security Operation Centers," arXiv [2407.13093](https://arxiv.org/abs/2407.13093), 2024.
  - R. Fieblinger, M. T. Alam and N. Rastogi, "Actionable Cyber Threat Intelligence using Knowledge Graphs and Large Language Models," 6th Workshop on Attackers and Cyber-Crime Operations (WACCO), arXiv [2407.02528](https://arxiv.org/abs/2407.02528), 2024. LLM triple extraction for a CTI knowledge graph works at small scale, but large-scale KG construction and link prediction "presents ongoing challenges."
  - M. H. Saju and A. Azim, "Toward Autonomous SOC Operations: End-to-End LLM Framework…," arXiv [2604.27321](https://arxiv.org/abs/2604.27321), 2026. Its ensemble detection reaches 82.8% accuracy with FPR 0.120. The RAG resolution reaches 90.0% accuracy and triage takes under 10 minutes. **[last two figures from search summary – verify]**
  - All via arXiv API.
- Benchmarks:
  - M. T. Alam, D. Bhusal, L. Nguyen and N. Rastogi, "CTIBench: A Benchmark for Evaluating LLMs in Cyber Threat Intelligence," arXiv [2406.07599](https://arxiv.org/abs/2406.07599), 2024. It is motivated by "concerns about their reliability, accuracy, and hallucinations." My recollection is that it includes ATT&CK-technique-extraction and threat-actor-attribution tasks and appeared at NeurIPS 2024 Datasets & Benchmarks. **[task list and venue from memory – verify]**
  - Y. Wu et al., "ExCyTIn-Bench: Evaluating LLM agents on Cyber Threat Investigation," arXiv [2507.14201](https://arxiv.org/abs/2507.14201) (comment: accepted at ICML 2026). It uses 57 Sentinel log tables and 7,542 questions, and the best model reaches a reward of 0.606.
  - L. Deason et al., "CyberSOCEval: Benchmarking LLMs Capabilities for Malware Analysis and Threat Intelligence Reasoning," arXiv [2509.20166](https://arxiv.org/abs/2509.20166), 2025 (part of CyberSecEval 4). Reasoning models "do not achieve the same boost as in coding and math."
- Surveys and risks:
  - S. Ndichu, T. Ban, S. Ozawa, T. Takahashi and D. Inoue, "AI-Driven Security Alert Screening and Alert Fatigue Mitigation in Security Operations Centers: A Survey," arXiv [2605.08316](https://arxiv.org/abs/2605.08316), 2026. It reviews 119 records (87 core studies, 2015–2026) and finds "persistent gaps in operational validation, adversarial robustness, cross-environment generalization, and evaluation practice."
  - R. Sleeba C and H. V. Nath, "Bridging the First-Hour Gap: Evaluating AI Reliability and Benchmarking Deficiencies in Cyber Incident Response for Law Enforcement," arXiv [2609.12681](https://arxiv.org/abs/2609.12681), 2026. It surveys playbooks, LLMs, RAG and agentic decision support and argues that current benchmarks are deficient.
- Data leakage and cross-organisation sharing:
  - CGR replicates across geographic regions to meet privacy regulations, and pseudo-anonymises GUIDE (SHA1 hashing, random IDs, timestamp noise). Similar-incident retrieval is restricted to the same organisation, while remediation and triage models are trained on pooled multi-organisation regional data. ([CGR arXiv HTML](https://arxiv.org/html/2407.09017v4))
  - Classic sharing infrastructure: C. Wagner, A. Dulaunoy, G. Wagener and A. Iklody, "MISP: The Design and Implementation of a Collaborative Threat Intelligence Sharing Platform," *ACM WISCS 2016*, DOI [10.1145/2994539.2994542](https://doi.org/10.1145/2994539.2994542).
  - Privacy-preserving sharing: J. M. de Fuentes, L. González-Manzano, J. Tapiador and P. Peris-Lopez, "PRACIS: Privacy-preserving and aggregatable cybersecurity information sharing," *Computers & Security* 69, 2017, pp. 127–141, DOI [10.1016/j.cose.2016.12.011](https://doi.org/10.1016/j.cose.2016.12.011).
  - Barriers: A. Zibak and A. Simpson, "Cyber Threat Information Sharing: Perceived Benefits and Barriers," *ARES 2019*, DOI [10.1145/3339252.3340528](https://doi.org/10.1145/3339252.3340528). This survey of practitioners finds a gap between the theorised benefits and the practice of sharing. ([abstract](https://doi.org/10.1145/3339252.3340528))
  - ATTACKDNA: MISP and STIX share indicators and CTI, not *what responders did and how well it worked*. ATTACKDNA's fingerprint, which omits hosts, users and raw logs, is a privacy-reducing representation for cross-organisation memory. The report should still discuss residual leakage, since CVEs, vectors and timing can identify victims.

### Inferences
- The LLM and RAG literature converges on *grounding* as the remedy for hallucination. ATTACKDNA grounds by construction: every recommended action points to a stored past incident or a named MITRE or baseline source, and nothing is generated.
- The closest LLM-era analogues to "recall past incidents" are AutoBnB-RAG's RAG-News, CGR's similar incidents, and Hammar et al.'s fine-tuning on 68k incidents. None offers explainable, structured, cross-organisation recall with response-effectiveness statistics.
- Singh et al.'s field evidence that analysts want sensemaking and evidence, not verdicts, is the best empirical justification for ATTACKDNA's "show why it matched" UX.

### Gaps
- I found no LLM or RAG IR system that builds a *shared, cross-organisation* incident memory. Federated or privacy-preserving RAG for SOCs was not found in my searches. Treat this as an absence in my searches, not proof.
- I found no study that quantifies hallucination rates of LLM IR recommendations in a production SOC.
- A Hungarian *National Security Review* article, "Utilizing Retrieval Augmented Generation in Incident Response" ([ojs.knbsz.gov.hu](https://ojs.knbsz.gov.hu/index.php/nsr/article/view/747)), appeared in search with organisation-specific hybrid-search RAG. Its authors and results were not verified.
- GenDFIR's "58% reduction in report time" appeared only in a secondary survey summary and was not verified.

## 5. Explainability in security retrieval and recommendation: do analysts need reasons?

### Takeaway
Qualitative SOC studies show that analysts distrust opaque alerts and need context. Alahmadi et al. list "Explainable" and "Contextual" among five required alarm properties, and Kokulu et al. document SOC tooling and process issues. The XAI SoK finds that security XAI is rarely evaluated with users (14% of studies). Deployed industrial systems such as CGR show recommendations without per-item rationale. CBR is repeatedly described as inherently explainable because the precedent *is* the explanation.

### Cited Findings
- B. A. Alahmadi, L. Axon and I. Martinovic, "99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms," *31st USENIX Security Symposium*, 2022. [USENIX page](https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi).
  - Method: a survey of 20 practitioners and a qualitative study with 21.
  - Many false positives are "benign triggers," alarm validation is tedious and leads to "alarm burnout," and alarms should be "interpretable and meaningful."
  - The authors propose five properties for alarms: Reliable, Explainable, Analytical, Contextual, Transferable.
  - ATTACKDNA: "Explainable," "Contextual" and "Transferable" map directly to per-match reasons, recalled context from similar incidents, and cross-organisation reuse.
- F. B. Kokulu, A. Soneji, T. Bao, Y. Shoshitaishvili, Z. Zhao, A. Doupé and G.-J. Ahn, "Matched and Mismatched SOCs: A Qualitative Study on Security Operations Center Issues," *ACM CCS 2019*. DOI [10.1145/3319535.3354239](https://doi.org/10.1145/3319535.3354239). Based on 18 semi-structured interviews, it identifies technical and non-technical SOC issues and analyst–manager disagreements. ([abstract](https://doi.org/10.1145/3319535.3354239))
- A. Nadeem, D. Vos, C. Cao, L. Pajola, S. Dieck, R. Baumgartner and S. Verwer, "SoK: Explainable Machine Learning for Computer Security Applications," *IEEE EuroS&P 2023*. DOI [10.1109/EuroSP57164.2023.00022](https://doi.org/10.1109/EuroSP57164.2023.00022).
  - Many XAI applications are "designed with little understanding of how they might be integrated into analyst workflows," and only 14% run user studies.
  - It suggests "interpretability by design may be a better alternative."
  - Source: [abstract](https://doi.org/10.1109/EuroSP57164.2023.00022).
  - ATTACKDNA: its structural-overlap re-rank is interpretable by design. The SoK suggests ATTACKDNA should validate its explanations with analysts, not just assert them.
- M. Nyre-Yu, E. Morris, M. Smith, B. Moss and C. Smutz, "Explainable AI in Cybersecurity Operations: Lessons Learned from xAI Tool Deployment," *Symposium on Usable Security (USEC) 2022*. DOI [10.14722/usec.2022.23014](https://doi.org/10.14722/usec.2022.23014). ([Crossref](https://doi.org/10.14722/usec.2022.23014)) **[findings not read – verify]**
- N. Capuano, G. Fenza, V. Loia and C. Stanzione, "Explainable Artificial Intelligence in CyberSecurity: A Survey," *IEEE Access* 10, 2022. DOI [10.1109/ACCESS.2022.3204171](https://doi.org/10.1109/ACCESS.2022.3204171). ([Crossref](https://doi.org/10.1109/ACCESS.2022.3204171))
- System-level evidence:
  - DeepCASE presents event context as an explanation of "why certain events are classified as malicious" ([abstract](https://doi.org/10.1109/SP46214.2022.9833671)).
  - RCACopilot outputs "an explanatory narrative" ([arXiv](https://arxiv.org/abs/2305.15778)).
  - CGR's paper does not describe showing analysts a rationale. Its expert reviewers judged relevance by shared attack patterns, IoCs and entity types, but these criteria are not shown in the product ([CGR arXiv HTML](https://arxiv.org/html/2407.09017v4)).
  - Singh et al. recommend "evidence-first" outputs with ATT&CK linkages ([arXiv](https://arxiv.org/abs/2508.18947)).
  - ATTACKDNA: CGR's expert criteria (shared attack patterns, IoCs, entity types) are essentially ATTACKDNA's explanation fields, made visible. This is a crisp positioning point.

### Inferences
- The argument "analysts need reasons" is well supported qualitatively (Alahmadi, Kokulu, Singh). Quantitative evidence that explanations improve SOC decisions is thin (SoK: 14% user studies). ATTACKDNA should present its explanations as aligned with stated analyst needs, not as proven to improve outcomes.
- Kitten-or-Panda's result implies explanations should also convey *strength* of evidence: rare shared techniques or CVEs are strong, generic ones are weak.

### Gaps
- I found no controlled user study that measures whether showing match reasons for similar-incident retrieval changes analyst accuracy or trust in a SOC.
- The specific lessons in Nyre-Yu et al. (USEC 2022) were not read.

## 6. Lessons learned and post-incident knowledge reuse (NIST SP 800-61r3; organisational learning from incidents)

### Takeaway
NIST SP 800-61r3 (April 2025) moves lessons learned from a final lifecycle phase to continuous improvement (CSF 2.0 ID.IM). It says lessons "should often be shared as soon as they are identified" and that reviews should cover "what actions were taken, and how effective those actions were." Empirical IS research (Ahmad et al.; Tøndel et al.; Patterson et al.) consistently finds that organisations under-invest in learning from incidents, so experience is lost. This is the gap ATTACKDNA's mitigation memory operationalises.

### Cited Findings
- A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, NIST SP 800-61 Rev. 3, April 2025 (supersedes Rev. 2, 2012). DOI [10.6028/NIST.SP.800-61r3](https://doi.org/10.6028/NIST.SP.800-61r3). The PDF was read in session. Key passages:
  - "The lessons learned during incident response should often be shared as soon as they are identified, not delayed until after recovery concludes. Continuous improvement is increasingly necessary…"
  - "Lessons learned from performing all activities in all Functions are fed into Improvement [ID.IM]…"
  - Lessons-learned meetings provide "an opportunity to review what happened, what actions were taken, and how effective those actions were."
  - Improvements include "identifying TTPs that are not currently being blocked by safeguards or flagged by detection technologies."
  - Sources: [CSRC page](https://csrc.nist.gov/pubs/sp/800/61/r3/final); [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf).
  - ATTACKDNA: maps almost word-for-word. Recording actions with their effectiveness, indexing them by TTPs, and making them recallable immediately match the r3 guidance. The report can position ATTACKDNA as tooling for CSF 2.0 ID.IM.
- C. M. Patterson, J. R. C. Nurse and V. N. L. Franqueira, "Learning from cyber security incidents: A systematic review and future research agenda," *Computers & Security* 132, 103309, 2023. DOI [10.1016/j.cose.2023.103309](https://doi.org/10.1016/j.cose.2023.103309). It reviews what research exists on learning from incidents, which organisational learning practices are found, and what further research is needed, concluding that more work is needed on which learning practices give the greatest impact. ([Crossref](https://doi.org/10.1016/j.cose.2023.103309); probable Kent repository record [kar.kent.ac.uk/101556](https://kar.kent.ac.uk/101556), mapping not verified) **[content from search summary]**
- C. M. Patterson, J. R. C. Nurse and V. N. L. Franqueira, "'I don't think we're there yet': The practices and challenges of organisational learning from cyber security incidents," *Computers & Security*, 2024. DOI [10.1016/j.cose.2023.103699](https://doi.org/10.1016/j.cose.2023.103699). It uses neo-institutional and organisational-learning theory and concludes that progress has been made but "further enhancements are needed." ([Crossref](https://doi.org/10.1016/j.cose.2023.103699); [AMiner](https://www.aminer.org/pub/656d9c47939a5f4082d33804/i-don-t-think-we-re-there-yet-the-practices-and-challenges)) **[content from search summary]**
- A. Ahmad, J. Hadgkiss and A. B. Ruighaver, "Incident response teams – Challenges in supporting the organisational security function," *Computers & Security*, 2012, DOI [10.1016/j.cose.2012.04.001](https://doi.org/10.1016/j.cose.2012.04.001). Also A. Ahmad, S. B. Maynard and G. Shanks, "A case analysis of information systems and security incident responses," *International Journal of Information Management*, 2015, DOI [10.1016/j.ijinfomgt.2015.08.001](https://doi.org/10.1016/j.ijinfomgt.2015.08.001). And A. Ahmad, S. B. Maynard, K. C. Desouza, J. Kotsias, M. T. Whitty and R. L. Baskerville, "How can organizations develop situation awareness for incident response: A case study of management practice," *Computers & Security*, 2021, DOI [10.1016/j.cose.2020.102122](https://doi.org/10.1016/j.cose.2020.102122). All via Crossref. **[findings not read in this session]**
- G. Grispos, W. B. Glisson and T. Storer, "Enhancing security incident response follow-up efforts with lightweight agile retrospectives," *Digital Investigation*, 2017. DOI [10.1016/j.diin.2017.07.006](https://doi.org/10.1016/j.diin.2017.07.006). ([Crossref](https://doi.org/10.1016/j.diin.2017.07.006)) **[findings not read]**
- I. A. Tøndel, M. B. Line and M. G. Jaatun, "Information security incident management: Current practice as reported in the literature," *Computers & Security*, 2014. DOI [10.1016/j.cose.2014.05.003](https://doi.org/10.1016/j.cose.2014.05.003). ([Crossref](https://doi.org/10.1016/j.cose.2014.05.003)) **[findings not read]**
- J. Shedden, A. Ahmad and A. B. Ruighaver, "Organisational learning and incident response: promoting effective learning through the incident response process," Australian Information Security Management Conference, 2010. **[bib unverified – Crossref returned no match; cited in search summary only]**
- CBR-side framing of the same problem: Nunes et al. (2019) note that resolution knowledge is "being under-used… sometimes even lost and not used at all" ([IJSEKE abstract](https://doi.org/10.1142/S021819401940014X)).
  - ATTACKDNA: turns lessons learned into a queryable, cross-organisation memory rather than a report that sits in a folder.

### Inferences
- NIST r3's explicit call to record "what actions were taken, and how effective those actions were" and to share lessons promptly gives ATTACKDNA's effectiveness-weighted response memory an authoritative normative anchor.
- The organisational-learning literature identifies cultural and process barriers, not just tooling gaps. ATTACKDNA addresses only the tooling and reuse side, and the report should say so.

### Gaps
- Full texts of Patterson et al. (2023, 2024), Ahmad et al., Grispos et al. and Tøndel et al. were not read, so specific empirical findings (e.g., the share of organisations holding lessons-learned meetings) are not reported here.
- I found no study that quantifies how often recorded lessons learned are *reused* in later incidents, which is exactly what ATTACKDNA's "response reused in 90% of pairs" measures in a simulated setting.
