"""Maps sanitized incident text to MITRE ATT&CK techniques and tactics.

Three complementary signals are combined:

1. **Explicit ids.** If the report already says "T1486", trust it.
2. **Behaviour phrases.** A curated alias table maps how analysts actually
   write ("files were encrypted", "malicious macro") to technique ids, and a
   generic pass matches official technique names verbatim.
3. **Resemblance to MITRE's examples.** Sentences the table has no phrase for
   are compared with the ~17,600 sentences MITRE has labelled (see
   `example_mapper`), which is where most of the recall comes from.

Nothing the report denies is mapped: "no lateral movement occurred" is not
lateral movement (see `negation`).

Every match carries the evidence phrase that produced it, so the UI can show
*why* a technique was assigned instead of asking the judges to take it on faith.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, List

from app.services import example_mapper
from app.services.knowledge_base import describe_technique, sort_tactics, technique_index
from app.services.negation import is_negated

# --------------------------------------------------------------------------
# Curated behaviour -> technique aliases. These carry most of the mapping
# quality: analysts describe behaviour, they rarely quote ATT&CK names.
# --------------------------------------------------------------------------
ALIASES: Dict[str, List[str]] = {
    # Initial access
    "T1566.001": ["malicious attachment", "attachment with malware", "weaponized document",
                  "macro-enabled document", "malicious macro", "infected attachment"],
    "T1566.002": ["phishing link", "spearphishing link", "credential harvesting page",
                  "fake login page", "malicious link", "phishing url"],
    "T1566": ["phishing", "spear phishing", "spearphishing", "phishing email", "phishing campaign"],
    "T1078": ["valid accounts", "compromised account", "stolen credentials", "legitimate credentials",
              "reused password", "account takeover", "credential stuffing",
              "valid account", "signed in with the valid account", "own valid credentials",
              "authenticated as the user", "used the stolen credentials",
              "logged in with the stolen", "harvested credentials"],
    "T1190": ["exploited a vulnerability", "public-facing application", "web application exploit",
              "unpatched server", "internet-facing", "sql injection", "remote code execution"],
    "T1133": ["external remote services", "vpn access", "exposed rdp", "remote desktop exposed"],
    # Narrative phrasing from published breach write-ups, which describe what
    # happened rather than naming the technique.
    "T1195": ["supply chain", "third-party vendor", "compromised update", "software supply chain",
              "trojanised update", "trojanized update", "malicious update",
              "compromised build environment", "signed updates containing",
              "pushed a malicious update", "vendor software update"],
    # Execution
    "T1059.001": ["powershell", "encoded powershell", "powershell script"],
    "T1059.003": ["cmd.exe", "command prompt", "batch script", "windows command shell"],
    "T1059.005": ["visual basic", "vbscript", "vba macro"],
    "T1059.006": ["python script", "malicious python"],
    "T1059": ["command and scripting", "script execution", "shell command", "arbitrary command"],
    "T1204": ["user execution", "user opened", "employee clicked", "user clicked", "double-clicked"],
    "T1053": ["scheduled task", "cron job", "at job", "task scheduler"],
    # Persistence / privilege escalation
    "T1136": ["created a new account", "rogue account", "new admin account", "account creation"],
    "T1547": ["registry run key", "startup folder", "autostart", "boot persistence"],
    "T1068": ["privilege escalation exploit", "local privilege escalation", "kernel exploit"],
    "T1548": ["bypassed uac", "sudo abuse", "elevation control"],
    # Defense evasion
    "T1027": ["obfuscated", "obfuscation", "packed binary", "base64 encoded payload",
              "encrypted payload", "encoded command", "steganography"],
    "T1070": ["cleared logs", "deleted logs", "log deletion", "anti-forensics", "wiped event log"],
    "T1562": ["disabled antivirus", "disabled edr", "impaired defenses", "turned off logging",
              "security tool disabled", "tampered with defenses"],
    "T1055": ["process injection", "injected into", "dll injection", "hollowing"],
    "T1218": ["living off the land", "lolbin", "signed binary proxy", "rundll32", "mshta", "regsvr32"],
    # Credential access
    "T1003": ["credential dumping", "lsass", "mimikatz", "ntds.dit", "sam hive", "hashdump"],
    "T1110": ["brute force", "password spraying", "password guessing", "login attempts"],
    "T1621": ["mfa fatigue", "push bombing", "mfa bombing", "multi-factor request generation",
              "mfa push prompts", "mfa prompts", "push prompts", "until a user approved",
              "repeatedly sent to one account"],
    "T1552": ["hardcoded credentials", "credentials in file", "plaintext password", "exposed secret",
              "unsecured credentials", "leaked api key", "hardcoded administrator credentials",
              "unencrypted credentials", "plaintext credentials", "credentials stored on",
              "password in a script", "credentials in a script"],
    "T1555": ["credential dump", "credential marketplace", "stolen password purchased",
              "password appeared in a credential dump", "credentials from password stores"],
    # Discovery
    "T1087": ["account discovery", "enumerated users", "user enumeration",
              "enumerated directory accounts", "directory enumeration",
              "enumerated accounts", "bulk directory enumeration"],
    "T1018": ["network scan", "scanned the network", "remote system discovery", "host discovery"],
    "T1082": ["system information discovery", "fingerprinted the host"],
    "T1046": ["port scan", "network service scanning", "service discovery", "port scanning",
              "advanced ip scanner", "angry ip scanner", "nmap", "netscan"],
    # Lateral movement
    "T1021.001": ["rdp", "remote desktop protocol", "lateral rdp"],
    "T1021.002": ["smb share", "admin share", "psexec", "smb lateral"],
    "T1021": ["lateral movement", "moved laterally", "pivoted to", "remote services"],
    "T1550": ["pass the hash", "pass the ticket", "token theft", "stolen session cookie"],
    # Collection / C2 / exfiltration
    "T1005": ["collected data", "staged files", "data from local system",
              "collected proprietary", "collected source code", "gathered files from the host",
              "copied files locally"],
    "T1114": ["mailbox access", "email collection", "read mailboxes", "inbox rule"],
    "T1071": ["command and control", "c2 channel", "c2 server", "beacon", "beaconing",
              "application layer protocol"],
    "T1573": ["encrypted channel", "tls c2", "encrypted c2"],
    "T1567": ["exfiltration to cloud", "uploaded to dropbox", "uploaded to mega", "cloud storage exfil",
              "exfiltrated to cloud storage", "uploaded to personal cloud storage",
              "uploaded to cloud storage", "personal cloud storage"],
    "T1041": ["exfiltrated over c2", "data exfiltration", "exfiltrated data", "data theft",
              "stole data", "data was stolen", "exfiltrated over an encrypted channel",
              "records were exfiltrated", "were exfiltrated over"],
    "T1048": ["exfiltration over alternative protocol", "dns tunneling", "ftp exfiltration"],
    # Impact
    "T1486": ["ransomware", "ransom note", "files were encrypted", "encrypted files",
              "data encrypted for impact", "encryption of files", "locked the files",
              "encrypted files on", "deploying ransomware", "deployed the ransomware",
              "deployed ransomware", "encrypted systems"],
    "T1490": ["deleted shadow copies", "vssadmin", "inhibit system recovery", "deleted backups"],
    "T1489": ["stopped services", "service stop", "killed processes"],
    "T1485": ["data destruction", "wiper", "wiped data", "destroyed data",
              "destructive by design", "could not be recovered by paying", "destroyed"],
    "T1505.003": ["web shell", "webshell", "deployed a web shell", "deployed web shells"],
    "T1078.002": ["domain administrator privileges", "domain admin privileges",
                  "obtained domain administrator"],
    "T1210": ["smb exploit", "exploit to spread", "spread using an exploit",
              "remote services exploitation"],
    "T1498": ["ddos", "denial of service", "traffic flood"],
    "T1657": ["financial theft", "fraudulent transfer", "business email compromise", "bec",
              "fraudulent payment", "changed the bank details", "payroll diversion",
              "direct-deposit details"],
    # T1556.006 is the adversary *changing* how MFA works. Its ATT&CK name is
    # "Multi-Factor Authentication", so matching the name mapped every report
    # that mentions MFA at all — including "was not protected by MFA", which
    # is the absence of a control, not a technique. Only tampering counts.
    "T1556.006": ["disabled mfa", "disabled multi-factor authentication", "mfa was disabled",
                  "removed the mfa requirement", "excluded from mfa", "turned off mfa"],
    "T1098.005": ["registered a new authenticator", "registered a new mfa device",
                  "enrolled their own device", "enrolled a new device", "added an mfa device",
                  "registered their own device"],
    "T1557": ["adversary-in-the-middle", "aitm", "man-in-the-middle", "evilginx"],
    "T1539": ["session token was stolen", "session token theft", "stole the session cookie",
              "session cookie was captured", "session token was captured", "hijack authenticated sessions",
              "session hijacking"],
    "T1110.003": ["password spraying", "password spray"],
    "T1110.004": ["credential stuffing"],
    # Tools whose use is itself the technique. This is what ATT&CK's own
    # software pages record, written the way an analyst names them.
    "T1003.001": ["dumped lsass", "lsass memory", "lsass dump", "procdump"],
    "T1003.003": ["ntdsutil", "ntds.dit"],
    "T1482": ["nltest", "domain trust discovery", "enumerated domain trusts"],
    "T1087.002": ["bloodhound", "sharphound", "adfind", "net group", "enumerated active directory"],
    "T1219": ["anydesk", "teamviewer", "screenconnect", "atera", "splashtop",
              "remote monitoring and management tool", "remote access software"],
    "T1572": ["ngrok", "chisel", "plink", "protocol tunneling", "tunnelled traffic", "tunneled traffic"],
    "T1496": ["xmrig", "cryptominer", "cryptocurrency miner", "mine cryptocurrency",
              "mining cryptocurrency", "cryptomining", "cryptojacking", "resource hijacking"],
    "T1070.001": ["wevtutil", "event logs were cleared", "cleared the event logs",
                  "cleared windows event logs", "windows event logs were cleared"],
    "T1105": ["certutil", "ingress tool transfer", "downloaded additional tools",
              "downloaded additional payloads"],
    "T1053.005": ["schtasks"],
    "T1547.001": ["run key", "registry run", "run keys"],
    "T1047": ["wmic", "wmi", "windows management instrumentation"],
    "T1218.005": ["mshta"],
    "T1218.010": ["regsvr32"],
    "T1218.011": ["rundll32"],
    "T1484.001": ["group policy object", "through group policy", "via group policy", "through a gpo",
                  "via a gpo", "group policy modification"],
    "T1567.002": ["rclone", "mega.nz", "megasync", "exfiltrated to mega"],
    "T1560.001": ["rar archive", "7-zip archive", "archived with", "compressed the data",
                  "staged in an archive", "zip archive"],
    "T1052.001": ["usb drive", "usb stick", "removable media", "external drive"],
    "T1195.001": ["typosquatted", "typosquatting", "malicious npm package", "malicious pypi package",
                  "dependency confusion", "malicious package"],
    "T1195.002": ["trojanised installer", "trojanized installer", "tampered installer",
                  "compromised build server", "compromised build servers", "software supply chain"],
    "T1552.001": ["access keys in a public repository", "keys to a public repository",
                  "credentials in a repository", "secrets in source code", "hardcoded access keys"],
    "T1552.005": ["metadata service", "instance metadata"],
    "T1530": ["storage bucket", "storage buckets", "s3 bucket", "blob container", "cloud storage object"],
    "T1610": ["privileged container", "deployed a container", "malicious container"],
    "T1611": ["escaped to the host", "container escape", "escape to host"],
    "T1098.004": ["added an ssh key", "ssh authorized_keys", "added their ssh key"],
    "T1561.002": ["master boot record", "overwrote the mbr", "disk wipe", "wiped the disks"],
    "T1056.001": ["keylogger", "keylogging", "keystroke logging"],
    "T1113": ["screen capture", "took screenshots", "captured screenshots"],
    "T1204.002": ["opened the attachment", "opened the malicious", "launched the lnk", "mounted the iso",
                  "opened a malicious", "malicious iso", "malicious lnk", "enabled macros",
                  "opened the document"],
    "T1204.001": ["clicked the link", "clicked a link", "clicked on the link", "clicked on a link"],
    "T1534": ["internal spearphishing", "internal phishing", "phishing from the compromised mailbox",
              "sent phishing from the compromised account"],
    "T1199": ["trusted relationship", "third-party access", "vendor access", "contractor access",
              "credentials belonging to a contractor", "supplier's access"],
}


TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Official technique names shorter than this are too generic to keyword-match
# safely (e.g. "Data", "Email"), so only aliases apply to them.
MIN_NAME_LENGTH = 8

# Some official ATT&CK names are ordinary security vocabulary. Matching them as
# technique names produces confident-looking nonsense — the word "credentials"
# in any report would otherwise map to T1589.001 (Reconnaissance: Credentials)
# and invent a reconnaissance phase that never happened. Aliases still cover
# these techniques where the surrounding phrasing is genuinely specific.
NAME_MATCH_STOPLIST = {
    "credentials", "domains", "databases", "malware", "software", "tool", "hardware",
    "firmware", "exploits", "vulnerabilities", "server", "serverless", "proxy",
    "compression", "scripting", "source", "impersonation", "botnet", "at", "trap",
    "dll", "dns", "ssh", "cdns", "whois", "add-ins", "confluence", "sharepoint",
    # The name of T1556.006. See the alias table.
    "multi-factor authentication",
}


@lru_cache(maxsize=4096)
def _phrase_pattern(phrase: str) -> "re.Pattern[str]":
    """A whole-phrase pattern that tolerates a simple plural.

    "smb share" has to match "SMB shares": an analyst writes whichever number
    the incident had, and the boundary that keeps "rdp" out of "wordpress"
    was also rejecting the plural of every phrase in the table.
    """
    return re.compile(rf"(?<![a-z0-9]){re.escape(phrase)}(?:e?s)?(?![a-z0-9])")


def _affirmed(phrase: str, text_lower: str) -> bool:
    """Whether the phrase occurs somewhere the report is not denying it."""
    return any(not is_negated(text_lower, match.start())
               for match in _phrase_pattern(phrase).finditer(text_lower))


def _alias_matches(text_lower: str) -> Dict[str, List[str]]:
    """technique id -> evidence phrases found in the text."""
    hits: Dict[str, List[str]] = {}
    for technique_id, phrases in ALIASES.items():
        for phrase in phrases:
            if _affirmed(phrase, text_lower):
                hits.setdefault(technique_id, []).append(phrase)
    return hits


@lru_cache(maxsize=1)
def _alias_phrase_owners() -> Dict[str, str]:
    """phrase -> the technique the curated table assigns it to."""
    return {phrase: technique_id
            for technique_id, phrases in ALIASES.items()
            for phrase in phrases}


def _name_matches(text_lower: str) -> Dict[str, List[str]]:
    """Match official ATT&CK technique names appearing verbatim in the text."""
    hits: Dict[str, List[str]] = {}
    owners = _alias_phrase_owners()
    for technique_id, record in technique_index().items():
        name = record.get("name", "")
        name_lower = name.lower()
        if len(name) < MIN_NAME_LENGTH or name_lower in NAME_MATCH_STOPLIST:
            continue
        # ATT&CK reuses names across tactics: "Spearphishing Link" is both
        # T1566.002 (initial access) and T1598.003 (reconnaissance). When the
        # curated alias table has already claimed a phrase for one technique,
        # that decision wins — otherwise every phishing report also reports a
        # reconnaissance phase that never happened.
        owner = owners.get(name_lower)
        if owner is not None and owner != technique_id:
            continue
        if _affirmed(name_lower, text_lower):
            hits.setdefault(technique_id, []).append(name)
    return hits


def map_to_attack(text: str, extra_technique_ids: List[str] | None = None) -> dict:
    """Map incident text to ATT&CK techniques and the tactics they cover.

    `extra_technique_ids` lets the LLM extractor contribute ids that the
    keyword layer could not see; they are merged and de-duplicated here so the
    two paths never disagree about the final shape of the output.
    """
    text_lower = (text or "").lower()

    evidence: Dict[str, List[str]] = {}
    sources: Dict[str, set] = {}

    for technique_id in TECHNIQUE_ID_RE.findall(text or ""):
        evidence.setdefault(technique_id, []).append(f"explicit id {technique_id}")
        sources.setdefault(technique_id, set()).add("explicit")

    for technique_id, phrases in _alias_matches(text_lower).items():
        evidence.setdefault(technique_id, []).extend(phrases)
        sources.setdefault(technique_id, set()).add("behaviour")

    for technique_id, names in _name_matches(text_lower).items():
        evidence.setdefault(technique_id, []).extend(names)
        sources.setdefault(technique_id, set()).add("attack-name")

    for technique_id in extra_technique_ids or []:
        technique_id = technique_id.strip().upper()
        if TECHNIQUE_ID_RE.fullmatch(technique_id):
            evidence.setdefault(technique_id, []).append("model inference")
            sources.setdefault(technique_id, set()).add("llm")

    # Sentences that read like the ones MITRE labelled. Added last and marked
    # as such: a rule match quotes the report, this quotes MITRE, and an
    # analyst weighing a mapping should know which kind they are looking at.
    for suggestion in example_mapper.suggest(text or ""):
        technique_id = suggestion["technique_id"]
        family = technique_id.split(".")[0]
        # A rule that already found this behaviour, at either level of detail,
        # has said it better; the suggestion would only add a second label.
        if any(known.split(".")[0] == family for known in evidence):
            if technique_id in evidence:
                sources[technique_id].add("example")
            continue
        evidence.setdefault(technique_id, []).append(suggestion["evidence"])
        sources.setdefault(technique_id, set()).add("example")

    # A sub-technique implies its parent, so reporting both is noise: keep the
    # specific one. The parent survives only when the report named it by id,
    # which means the analyst deliberately stayed at that level of detail.
    for sub in {t for t in evidence if "." in t}:
        parent = sub.split(".")[0]
        if parent in evidence and "explicit" not in sources.get(parent, set()):
            evidence.pop(parent, None)
            sources.pop(parent, None)

    techniques = []
    for technique_id, phrases in evidence.items():
        record = describe_technique(technique_id)
        unique_evidence = list(dict.fromkeys(phrases))
        techniques.append({
            "id": technique_id,
            "name": record["name"],
            "tactics": record["tactics"],
            "evidence": unique_evidence,
            "confidence": _confidence(sources.get(technique_id, set()), len(unique_evidence)),
        })

    # Strongest evidence first, then kill-chain order for a readable story.
    techniques.sort(key=lambda t: (-t["confidence"], t["id"]))

    tactics = sort_tactics([tactic for t in techniques for tactic in t["tactics"]])
    return {"techniques": techniques, "tactics": tactics}


def _confidence(sources: set, evidence_count: int) -> float:
    """Confidence in a mapping, from how it was found and how often."""
    base = 0.55
    if "explicit" in sources:
        base = 0.95
    elif "attack-name" in sources:
        base = 0.85
    elif "behaviour" in sources:
        base = 0.75
    independent = sources & {"llm", "example"}
    if independent and len(sources) > len(independent):
        base = min(0.98, base + 0.05)  # two independent paths agreed
    elif sources <= {"llm", "example"} and sources:
        # Inferred, not quoted: a lead for the analyst, weighted as one.
        base = 0.65 if sources == {"llm", "example"} else 0.6
    return round(min(0.98, base + 0.03 * (evidence_count - 1)), 2)
