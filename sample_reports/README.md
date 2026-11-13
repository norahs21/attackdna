# Sample incident reports

Reports to attach in the interface, as a security team would. Every
organisation, person, address and host in them is fabricated.

Files marked **A** and **B** are the same attack reported by two different
organisations, in different words:

1. Open **Add to memory**, attach the **A** report and add it.
2. Open **Analyze a report**, attach the matching **B** report and analyze it.
3. The top similar incident is A's, marked *shared by another organisation ·
   identity withheld*, with A's response recommended. Nothing names A.

| A (add to memory) | B (analyze) | Attack |
|---|---|---|
| 01 hospital | 02 logistics | Ransomware through a phishing link |
| 03 university (.docx) | 04 manufacturer (.pdf) | Ransomware through an unpatched VPN appliance |
| 05 contractor | 06 municipality (.docx) | Business email compromise, invoice fraud |
| 07 power company (.pdf) | 08 engineering firm | Web shell on an unpatched Exchange server |
| 09 bank | 10 government agency | Trojanised vendor update |

Files 11 to 14 are single reports for analysis on their own.

Regenerate with `python scripts/make_sample_reports.py`.
