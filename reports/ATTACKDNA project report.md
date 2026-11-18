# A shared memory of how attackers behave, not of who they hit

## 1. Abstract

Organisations keep facing attacks that another organisation has already contained, yet they rarely learn from each other, because incident reports reveal the victim and cannot be shared. ATTACKDNA is a cybersecurity platform that links organisations through a **shared memory of attacker behaviour**. Each organisation has its own private access. When one of them adds an incident report, the platform removes everything that identifies the victim and keeps only how the attack behaved, its **Attack DNA**: the type of attack, how the attacker got in, the MITRE ATT&CK techniques used, the vulnerabilities exploited and the response actions that stopped it. Other organisations can then recall that knowledge in two ways: **during an attack**, by asking the memory what attackers did next and what stopped them in similar incidents, and **after an attack**, by analysing their own report to find similar incidents and preventive measures. Every match and every recommendation shows its evidence and its source, and no organisation ever learns who another victim was. The long-term goal is a national, then regional, then global platform for defensive knowledge sharing.

## 2. Introduction

Security teams routinely handle attacks that someone, somewhere, has already handled. The first time is an incident; the second time should be a lookup. Today it rarely is.

Incident-response guidance already asks for this kind of learning. NIST SP 800-61 Rev. 3 (2025) treats lessons learned as part of continuous improvement, says they "should often be shared as soon as they are identified", and describes post-incident reviews as a chance to examine "what actions were taken, and how effective those actions were" [1]. In practice, that knowledge stays inside each organisation's reports.

The opportunity is large because attacker behaviour repeats. A 2026 study of MITRE ATT&CK found that only **34% of documented threat groups use any technique unique to them** [2]: most attackers reuse the same techniques. A response that stopped a chain of techniques in one organisation is therefore likely to matter in many others.

The idea also fits the Saudi context. The Saudi Central Bank's Cyber Threat Intelligence Principles define operational intelligence as "the modus operandi, behavior, and techniques used by threat actors" [3], which is exactly what ATTACKDNA calls Attack DNA, and the National Cybersecurity Authority already runs threat-information sharing for national entities [4].

## 3. Problem Statement

**Incident reports identify their victims.** Surveys of threat-intelligence sharing agree on why organisations hold back: confidentiality and privacy, legal liability, reputational damage, lack of trust, and free-riding [5][6]. Organisations fear "incidentally disclosing sensitive business data or personally identifiable information" and the penalties that follow [7].

**What is shared is mostly indicators, and indicators age fast.** Platforms such as MISP and government programmes such as CISA's Automated Indicator Sharing exchange IP addresses, domains and file hashes, and protect privacy by controlling who can see a record, not by removing the victim from it [8][9]. Indicators are the easiest thing for an attacker to change, which is why the Pyramid of Pain places them at the bottom and behaviour (TTPs) at the top [10]. Two leading commercial feeds tracking the same 22 threat actors overlapped by only **2.5–4.0%** [11], and indicator sharing through CISA's programme **fell by 93% between 2020 and 2022** [12]. None of these feeds carries what responders need most: what the attacker did and which actions stopped them.

**Deleting names is not enough.** Anonymised security data can still reveal its source by inference [13], and large language models can infer personal attributes from text with up to 85% accuracy even after anonymisation [14]. A safe sharing system must therefore share structured behaviour, not cleaned-up prose.

**The problem.** How can one organisation reuse another's incident experience, the attacker's behaviour and the response that worked, without learning, or being able to infer, who the victim was?

## 4. Objectives

1. **Share without exposure:** let organisations contribute incident knowledge while removing every identifier of the victim before anything leaves the organisation.
2. **Describe attacks by behaviour:** represent each incident as an Attack DNA mapped to MITRE ATT&CK [28], so different organisations' reports of the same attack can be matched even when they are written differently.
3. **Help during and after an attack:** let an organisation under attack recall what similar attackers did next and what stopped them, and let an organisation that has recovered find preventive measures.
4. **Earn the analyst's trust:** show, for every match and every recommendation, why it was made and where it came from.
5. **Scale safely:** grow from a pilot network of organisations to a national, regional and eventually global platform.

## 5. Proposed Solution: ATTACKDNA

### 5.1 The idea

ATTACKDNA separates the attack from the victim. Just as DNA identifies an organism wherever a sample is found, an Attack DNA identifies an attack pattern whichever organisation it hit. The platform keeps these fingerprints in a shared **memory**, which is why we describe it as a memory: it remembers how attacks behaved and how they were stopped, and it forgets who was attacked.

### 5.2 How organisations take part

Each organisation has its own private access to the platform. Its identity is stored only as a keyed pseudonym, used to tell it "this match is your own incident" and never shown to anyone else. Contributing is always the organisation's decision: nothing enters the shared memory without its security team's approval.

| Step | What happens |
|---|---|
| 1. Attach the report | The organisation uploads its incident report as written (PDF, Word or text). |
| 2. Remove the identity | A privacy layer removes names, hosts, IP addresses, accounts and other identifiers. When it is unsure whether a word is a name, it removes it. Attack evidence such as CVE numbers, ATT&CK technique IDs and malware hashes is kept. |
| 3. Extract the Attack DNA | The report becomes a structured fingerprint: attack type, how the attacker got in, ATT&CK techniques with the evidence for each, exploited vulnerabilities, impact and severity. The victim's industry is deliberately left out, because once names are removed the sector itself can reveal the victim. |
| 4. Add to memory | With the team's approval, the Attack DNA and the response actions the team took, with how well each worked, join the shared memory. The original report is never stored. |

### 5.3 Two ways to use the memory

| Mode | When | What the organisation provides | What it gets back |
|---|---|---|---|
| **Ask the memory** | During an ongoing attack | A description of what the attacker has done so far and how they got in | (1) What worked against similar attacks; (2) past attackers who got in the same way, and what they did; (3) what attackers did next in similar incidents, as a record of past incidents rather than a guess |
| **Analyze a report** | After the attack | Its incident report | Similar incidents in memory, why they match, what those organisations did and how well it worked, and what to do if the attack comes again |

### 5.4 Design principles

- **Privacy first.** Identity is removed before anything is stored or shared; only behaviour is kept; contributors are pseudonymous; the sector is not recorded.
- **Behaviour, not indicators.** Matching is based on ATT&CK techniques, tactics, attack type, entry point and vulnerabilities, which change far more slowly than IP addresses or domains.
- **Explainable.** Every match lists the reasons behind it (for example, "2 shared ATT&CK techniques, same entry: phishing"), and every recommended action carries its source and how often and how well it worked.
- **Two independent opinions, with a confidence.** The attack type and the entry vector are decided twice: once from the report's words, and once from the detected behaviour alone (the ATT&CK techniques and known-exploited vulnerabilities), without reading the words. When the two agree, the answer is marked high confidence; when they disagree, the analyst sees both instead of a confident label.
- **Resemblance, not attribution.** The platform says an attack resembles past ones; it never claims who the attacker is.

## 6. Related Work

### 6.1 Threat-intelligence sharing between organisations

MISP [8], the STIX 2.1 standard [15] and CISA's AIS [9] are the main ways organisations share threat intelligence today. They focus on indicators and protect privacy through access control: sharing groups, distribution levels and legal protection. Lincoln, Porras and Shmatikov [16] were among the first to sanitise security alerts before sharing them, and TRADE [17] lets contributors stay anonymous yet accountable. Other work protects shared data cryptographically: SEPIA aggregates network events across domains with secure multi-party computation [29], and PRACIS shares STIX incidents through an untrusted broker using homomorphic encryption [30].
**ATTACKDNA differs** by sharing the attacker's behaviour and the response that worked, rather than indicators, and by removing the victim from the content itself rather than only restricting who can read it.

### 6.2 Mapping incident reports to MITRE ATT&CK

Extracting attacker techniques from text has been studied since TTPDrill [18]. A 2025 systematisation of the field re-tested existing methods under one protocol and found that even the best fine-tuned models reach F1 scores of only about 71% and 63% on two public benchmarks, and that performance drops sharply in realistic settings, for example when every ATT&CK technique is a possible answer [19]. Orbinato et al. [20] showed that MITRE's own procedure examples can train such a mapper.
**ATTACKDNA builds on** this line, learning only from sentences MITRE publishes, but uses the mapping as a step towards sharing, not as an end in itself.

### 6.3 Retrieving similar incidents and recommending responses

Case-based reasoning systems record past incidents and reuse their resolutions [21][22], but each works inside a single organisation. Microsoft's Copilot Guided Response [23] recommends similar incidents and remediation actions to SOC analysts at scale; it matches incidents within one organisation's data and does not explain why a recommendation was made. Studies of SOC analysts show they need alerts and recommendations that are explainable and carry context [24].
**ATTACKDNA differs** by recalling incidents across organisations, explaining every match, and ranking actions by how often and how effectively they were used.

### 6.4 Predicting the attacker's next step

Researchers have learned which ATT&CK techniques tend to appear together [25] and predicted the next security event from sequences of alerts [26]. MITRE's Technique Inference Engine recommends techniques an attacker probably also used, but beats a simple "most common techniques" baseline by only a few points (recall@10 of 26.1% against 22.9%) [27].
**ATTACKDNA takes a cautious approach:** it shows what attackers actually did next in similar past incidents, as a record, until a prediction model clearly beats that baseline.

### 6.5 Comparison

| | Indicator sharing (MISP, AIS) | Incident recall in one organisation (CBR, Copilot Guided Response) | Next-technique inference (TIE) | **ATTACKDNA** |
|---|---|---|---|---|
| Removes the victim's identity from what is shared | No (access control instead) | Not applicable | Not applicable | **Yes** |
| Describes incidents by attacker behaviour (ATT&CK) | Partial | Partial | Yes | **Yes** |
| Recalls past incidents from other organisations | Indicators only | No | No | **Yes** |
| Explains why incidents match | No | Partial | No | **Yes** |
| Recalls what worked, with source and effectiveness | No | Partial | No | **Yes** |

## 7. Innovation and Added Value

To our knowledge, no existing system combines all of the following:

1. **Removing the victim's identity from free-text reports** and reducing each incident to structured attacker behaviour.
2. **Pseudonymous contribution** across organisations, so no organisation learns who another victim was.
3. **Cross-organisation recall of response actions**, ranked by how often and how effectively they were used, each labelled with its source.
4. **Explanations** for every match and every recommendation, and a **confidence** for every classification, from two independent opinions that must agree.
5. **Help during an attack**, not only after it.

For organisations, the value is practical: a repeat attack becomes a lookup, defenders reuse what already worked elsewhere, and smaller organisations without large security teams benefit from the experience of larger ones, without anyone exposing their identity.

## 8. Proof of Concept

A working prototype shows the idea is feasible. On test data it was not tuned on, it removed **98.6%** of hand-marked identifiers (275 of 279), named the attack type correctly in **85.7%** of 28 real incident summaries taken from Wikipedia, and, when two organisations reported the same attack in different words, found the first organisation's incident among the top five results in **95%** of cases (19 of 20) while revealing who it was on **0 of 20** screens. Its confidence levels are meaningful: when the words and the behaviour agreed on the attack type, the answer was right in **21 of 21** cases; when only one of them had an answer, in 33 of 37. The samples are small, so these figures are indicative rather than conclusive. The prototype runs on one machine; deploying it across organisations with separate accounts is the next step.

## 9. Challenges and Future Work

**Challenges.** Trust and governance between participating organisations; residual clues to identity, such as dates or unusual details; the quality and consistency of submitted reports; and incentives, so that organisations contribute as well as consume.

**Roadmap.**

1. **Pilot** with security operations centres on their own sanitised reports, with larger, independently labelled evaluation data.
2. **Multi-organisation deployment** with accounts, access control and governance rules.
3. **Interoperability:** export Attack DNA in STIX 2.1 so it can travel over existing sharing platforms.
4. **Arabic-language reports.**
5. **Predicting the attacker's next step**, once a model clearly beats the frequency baseline.
6. **Scale:** a national platform aligned with NCA and SAMA guidance, then the GCC, then a **global platform** for defensive knowledge sharing.

## 10. Conclusion

Organisations cannot share their incident reports, but they do not need to. What makes an incident reusable is how the attack behaved and what stopped it, not who was hit. ATTACKDNA keeps that behaviour as an Attack DNA in a shared memory, lets every organisation recall it during or after an attack with the evidence behind every answer, and never reveals the victim. The first time is an incident; with ATTACKDNA, the second time can be a lookup.

## 11. References

1. Nelson, A., Rekhi, S., Souppaya, M., & Scarfone, K. (2025). *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*. NIST SP 800-61 Rev. 3. https://doi.org/10.6028/NIST.SP.800-61r3
2. Saha, A., Lindorfer, M., & Caballero, J. (2026). Kitten or Panda? Measuring the Specificity of Threat Group Behaviors in Public CTI Knowledge Bases. *ACM ASIA CCS '26*. https://doi.org/10.1145/3779208.3786258
3. Saudi Central Bank (SAMA). Cyber Threat Intelligence Principles. https://rulebook.sama.gov.sa/en/entiresection/3087
4. National Cybersecurity Authority (NCA). Cyber Threats and Incidents – Information Sharing and Threat Monitoring. https://nca.gov.sa/en/cyber-operations/
5. Wagner, T. D., Mahbub, K., Palomar, E., & Abdallah, A. E. (2019). Cyber threat intelligence sharing: Survey and research directions. *Computers & Security*, 87, 101589. https://doi.org/10.1016/j.cose.2019.101589
6. Zibak, A., & Simpson, A. (2019). Cyber Threat Information Sharing: Perceived Benefits and Barriers. *ARES 2019*. https://doi.org/10.1145/3339252.3340528
7. Preuveneers, D., & Joosen, W. (2022). Privacy-Preserving Polyglot Sharing and Analysis of Confidential Cyber Threat Intelligence. *ARES 2022*. https://doi.org/10.1145/3538969.3538982
8. Wagner, C., Dulaunoy, A., Wagener, G., & Iklody, A. (2016). MISP: The Design and Implementation of a Collaborative Threat Intelligence Sharing Platform. *ACM WISCS '16*, 49–56. https://doi.org/10.1145/2994539.2994542
9. Cybersecurity and Infrastructure Security Agency (CISA). Automated Indicator Sharing (AIS). https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais
10. Bianco, D. J. (2013). The Pyramid of Pain. *Enterprise Detection & Response*. http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
11. Bouwman, X., Griffioen, H., Egbers, J., Doerr, C., Klievink, B., & van Eeten, M. (2020). A different cup of TI? The added value of commercial threat intelligence. *USENIX Security 2020*. https://www.usenix.org/conference/usenixsecurity20/presentation/bouwman
12. DHS Office of Inspector General. (2024). *OIG-24-60*: CISA's Automated Indicator Sharing program. https://oig.dhs.gov/sites/default/files/assets/2024-09/OIG-24-60-Sep24.pdf
13. Coull, S. E., Wright, C. V., Monrose, F., Collins, M. P., & Reiter, M. K. (2007). Playing Devil's Advocate: Inferring Sensitive Information from Anonymized Network Traces. *NDSS 2007*. https://www.ndss-symposium.org/ndss2007/playing-devils-advocate-inferring-sensitive-information-anonymized-network-traces/
14. Staab, R., Vero, M., Balunović, M., & Vechev, M. (2024). Beyond Memorization: Violating Privacy Via Inference with Large Language Models. *ICLR 2024*. https://arxiv.org/abs/2310.07298
15. OASIS. (2021). *STIX Version 2.1*. OASIS Standard. https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
16. Lincoln, P., Porras, P., & Shmatikov, V. (2004). Privacy-Preserving Sharing and Correlation of Security Alerts. *13th USENIX Security Symposium*. https://www.usenix.org/conference/13th-usenix-security-symposium/privacy-preserving-sharing-and-correlation-security-alerts
17. Allouche, Y., Tapas, N., Longo, F., Shabtai, A., & Wolfsthal, Y. (2021). TRADE: TRusted Anonymous Data Exchange: Threat Sharing Using Blockchain Technology. arXiv:2103.13158. https://arxiv.org/abs/2103.13158
18. Husari, G., Al-Shaer, E., Ahmed, M., Chu, B., & Niu, X. (2017). TTPDrill: Automatic and Accurate Extraction of Threat Actions from Unstructured Text of CTI Sources. *ACSAC 2017*, 103–115. https://doi.org/10.1145/3134600.3134646
19. Büchel, M., Paladini, T., Longari, S., Carminati, M., Zanero, S., et al. (2025). SoK: Automated TTP Extraction from CTI Reports – Are We There Yet? *34th USENIX Security Symposium*, 4621–4641. https://www.usenix.org/conference/usenixsecurity25/presentation/buechel
20. Orbinato, V., Barbaraci, M., Natella, R., & Cotroneo, D. (2022). Automatic Mapping of Unstructured Cyber Threat Intelligence: An Experimental Study. *IEEE ISSRE 2022*. https://doi.org/10.1109/ISSRE55969.2022.00027
21. Nunes, R. C., Colomé, M., Barcelos, F. A., Garbin, M., Paulus, G. B., & de Lima Silva, L. A. (2019). A Case-Based Reasoning Approach for the Cybersecurity Incident Recording and Resolution. *IJSEKE*, 29(11n12), 1607–1627. https://doi.org/10.1142/S021819401940014X
22. Guerra, P. A. C., Nunes, R. C., & de Lima Silva, L. A. (2025). A cases and clusters framework for recording, retrieving, and reusing response plans in structured cybersecurity incident management. *Engineering Applications of Artificial Intelligence*, 160, 111831. https://doi.org/10.1016/j.engappai.2025.111831
23. Freitas, S., Kalajdjieski, J., Gharib, A., & McCann, R. (2024). AI-Driven Guided Response for Security Operation Centers with Microsoft Copilot for Security. arXiv:2407.09017. https://arxiv.org/abs/2407.09017
24. Alahmadi, B. A., Axon, L., & Martinovic, I. (2022). 99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms. *USENIX Security 2022*. https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi
25. Al-Shaer, R., Spring, J. M., & Christou, E. (2020). Learning the Associations of MITRE ATT&CK Adversarial Techniques. *IEEE CNS 2020*, 1–9. https://doi.org/10.1109/CNS48642.2020.9162207
26. Shen, Y., Mariconti, E., Vervier, P.-A., & Stringhini, G. (2018). Tiresias: Predicting Security Events Through Deep Learning. *ACM CCS 2018*, 592–605. https://doi.org/10.1145/3243734.3243811
27. Turner, M. J., Carenzo, M., Lasky, J., Morris-King, J., & Ross, J. (2025). Technique Inference Engine: A Recommender Model to Support Cyber Threat Hunting. arXiv:2503.04819. https://arxiv.org/abs/2503.04819
28. Strom, B. E., Applebaum, A., Miller, D. P., Nickels, K. C., Pennington, A. G., & Thomas, C. B. (2018, rev. 2020). *MITRE ATT&CK: Design and Philosophy*. The MITRE Corporation. https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf
29. Burkhart, M., Strasser, M., Many, D., & Dimitropoulos, X. (2010). SEPIA: Privacy-Preserving Aggregation of Multi-Domain Network Events and Statistics. *USENIX Security 2010*. https://www.usenix.org/legacy/event/sec10/tech/full_papers/Burkhart.pdf
30. de Fuentes, J. M., González-Manzano, L., Tapiador, J., & Peris-Lopez, P. (2017). PRACIS: Privacy-preserving and aggregatable cybersecurity information sharing. *Computers & Security*, 69, 127–141. https://doi.org/10.1016/j.cose.2016.12.011
