"""What the Privacy Layer knows about words.

A regular expression can catch an identifier that has a *shape*: an address,
a mailbox, a host name. A person's or an organisation's name has no shape. The
only thing that marks "Aramco" or "Sara" as a name is that it is capitalised
and is not a word — so the layer has to know which capitalised tokens ARE
words, and which are public security vocabulary that describes the attack
rather than the victim ("PowerShell", "Mimikatz", "Citrix").

Three vocabularies answer that, all built from data the project already ships:

  ordinary words   an English word list (Webster's Second International, whose
                   copyright has lapsed) plus every lowercase word in the
                   ATT&CK and KEV text, which covers the modern terms a 1934
                   dictionary cannot know ("malware", "phishing")
  public terms     names that MITRE and CISA publish — techniques, tactics,
                   mitigations, malware, tools, threat groups, and the vendors
                   and products that have a known-exploited CVE — plus the
                   project's own classification vocabulary
  given names      a curated list, needed because some names are also words

Anything capitalised that is in none of them is treated as a name and removed.
That is the fail-closed direction: an unknown product name is lost, an unknown
person is not leaked.
"""
from __future__ import annotations

import gzip
import re
from functools import lru_cache
from typing import FrozenSet, Iterable, List

from app.config import DATA_DIR
from app.services import knowledge_base as kb

ENGLISH_WORDS_PATH = DATA_DIR / "processed" / "english_words.txt.gz"

_LOWER_WORD_RE = re.compile(r"(?<![A-Za-z0-9])[a-z][a-z]+(?![A-Za-z0-9])")
_NAME_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_ACRONYM_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z][A-Z0-9]{1,7}(?![A-Za-z0-9])")


def _words(block: str) -> FrozenSet[str]:
    return frozenset(block.split())


# --------------------------------------------------------------------------
# Security shorthand. These look like asset names (short, upper case) but are
# standard vocabulary; redacting them would make a sanitized report unreadable.
# --------------------------------------------------------------------------
SECURITY_ACRONYMS = _words("""
MITRE ATT CK ATT-CK CISA KEV NIST ISO SOC SIEM EDR XDR MDR NDR DLP MFA SSO VPN
RDP SMB DNS DHCP LDAP SAML OAUTH API URL URI PII IOC IOA TTP APT C2 TLS SSL
HTTP HTTPS FTP SSH WAF IDS IPS AV UEBA SOAR CVE CVSS NVD OWASP PDF EXE DLL PS1
VBA LOLBIN AD DC GPO PAM IAM T1486 T1059 T1027 US-CERT SANS FBI NSA GDPR PDPL
SLA RTO RPO IT OT ICS SCADA IOT SMS OTP CSV JSON XML SQL CPU RAM USB LAN WAN
NAC XSS CSRF SSRF IDOR LFI RFI XXE RCE BEC RAT POS MSP MSSP CI CD GPU HR CFO
CEO CISO CTO CIO COO PHI PCI DSS HIPAA NCA ECC SAMA SWIFT ATM GMT UTC AST AM PM
ID IDS OK FAQ SFTP TFTP SMTP IMAP POP3 SNMP ICMP VNC NFS WMI WINRM NTLM LSASS
NTDS SAM UAC COM DCOM RPC KDC TGT SPN OU LNK ISO CHM HTA MSI VBS JS JAR ZIP RAR
OS VM VPS CDN DGA P2P IRC TCP UDP IP MAC NAT ACL VLAN DMZ AWS GCP S3 EC2 ESXI
BIOS UEFI MBR IIS OWA ADFS JWT SIM DDOS DOS MITM AITM OSINT TI CTI DFIR IR BCP
DRP KPI ROI SaaS PaaS IaaS PLC HMI RTU SIS BMS ERP CRM EHR EMR PACS POC QA UAT
""".upper())

# Words that are capitalised because of what they are, not whose they are:
# roles, departments, the suffix that says what kind of body something is,
# document furniture, the calendar, units and currencies. "Bank" and
# "Hospital" stay readable on purpose — the sector classifier reads them.
STRUCTURE_WORDS = _words("""
inc llc ltd limited corp corporation company co gmbh plc llp bank group
holdings centre center hospital clinic authority ministry university college
institute agency foundation association council commission trust department
division unit office board committee team desk
chief information security officer incident commander crisis management
business continuity plan disaster recovery service help operations legal
finance financial accounting human resources procurement sales marketing
engineering development research compliance audit risk governance executive
director manager head lead senior junior analyst engineer administrator admin
architect consultant contractor vendor supplier partner customer client
employee staff user owner president vice deputy secretary treasurer
tier level phase stage step severity priority critical high medium low
table figure appendix section annex version day week month year quarter
internet intranet web cloud
january february march april may june july august september october november
december jan feb mar apr jun jul aug sep sept oct nov dec
monday tuesday wednesday thursday friday saturday sunday
gb mb kb tb gbps mbps kbps hz ghz ms usd sar eur gbp aed kwd qar bhd omr egp
jpy cny inr btc eth
mr mrs ms dr eng
""")

# Vendors, products and technology names that are not (or not reliably) in
# ATT&CK or the KEV catalog but appear constantly in incident reports.
TECH_EXTRAS = _words("""
microsoft windows linux unix macos mac ios android office outlook exchange
sharepoint onedrive teams azure entra defender sentinel intune bitlocker
powershell wmi kerberos ntlm active directory google chrome workspace gmail
amazon aws apple iphone ipad safari firefox mozilla edge oracle sap ibm cisco
citrix netscaler fortinet fortigate fortios palo alto vmware esxi vcenter
ivanti pulse sonicwall f5 okta duo crowdstrike sentinelone splunk
elastic qradar kubernetes docker github gitlab bitbucket jenkins jira
confluence slack zoom dropbox mega telegram whatsapp signal apache struts
log4j log4shell nginx tomcat mysql postgresql mongodb redis java javascript
python php dotnet npm pypi nuget maven rclone winrar 7zip anydesk teamviewer
screenconnect atera splashtop moveit goanywhere accellion kaseya solarwinds
orion veeam cobalt strike mimikatz psexec bloodhound impacket metasploit
ngrok xmrig qakbot emotet trickbot icedid lockbit conti ryuk akira blackcat
alphv revil darkside clop cl0p wannacry notpetya petya stuxnet shamoon triton
salesforce servicenow workday zendesk shopify wordpress drupal joomla
cloudflare akamai fastly zscaler proofpoint mimecast barracuda sophos
kaspersky symantec mcafee trellix bitdefender eset malwarebytes tenable
qualys rapid7 nessus wireshark nmap sysmon sysinternals procdump adfind
virustotal shodan tor onion bitcoin monero ethereum
""")

# Ordinary nouns that IT prose capitalises: "the Registry", "a Domain
# Controller", "Initial Access". Listed by hand rather than taken from ATT&CK
# technique names, because those names also contain "Target", "Mark", "Mail"
# and "Shell" — and each of those is somebody.
IT_WORDS = _words("""
domain controller directory registry kernel trojan worm virus backdoor rootkit
bootkit botnet firewall proxy gateway router switch appliance desktop remote
active server client workstation endpoint host tenant bucket vault certificate
token session cookie password credential credentials hash ticket policy object
forest schema catalog system guest default command prompt script macro
document folder share drive disk memory process thread driver module library
binary executable payload loader dropper stager beacon implant agent sensor
console portal dashboard panel device mobile wireless identity provider
authentication authorization patch update hotfix advisory bulletin alert
notice report summary timeline root cause lessons learned technical details
indicators compromise recommendations mitigations detection response
containment eradication recovery impact scope overview background
introduction conclusion initial access lateral movement privilege escalation
persistence defense defence evasion discovery collection exfiltration control
execution reconnaissance resource ransomware malware phishing spearphishing
email network event log logs task scheduler volume shadow copy safe mode
virtual private enterprise admins administrators users accounts account
services data database backup backups storage file files notes actions taken
""")

# Modern general vocabulary a 1934 word list does not carry.
MODERN_WORDS = _words("""
email emails online offline website websites login logins logon laptop laptops
smartphone app apps blog wifi username usernames password passwords passcode
database databases backup backups firewall firewalls download downloads
upload uploads ransomware malware spyware adware phish phished phishing spearphishing
smishing vishing cyber cybersecurity cyberattack healthcare payroll timeline
workflow onboarding helpdesk screenshot startup fintech ecommerce endpoint
endpoints hostname hostnames filename filenames workstation workstations
plaintext ciphertext encrypt encrypted encryption decrypt decrypted decryption
exfiltrate exfiltrated exfiltration dataset datasets metadata timestamp
timestamps runtime uptime downtime failover rollback hotfix changelog
checklist playbook playbooks runbook tabletop stakeholder stakeholders
outsourced outsourcing teleconference videoconference voicemail chatbot
""")

# --------------------------------------------------------------------------
# Given names. Needed because a name can also be a word ("Reem", "Mark"), and
# the only place a dictionary cannot tell them apart is the start of a
# sentence. A name in STRONG_NAMES is always removed when capitalised.
# --------------------------------------------------------------------------
STRONG_NAMES = _words("""
mohammed mohammad muhammad mohamed ahmad ahmed abdullah abdulla abdulaziz
abdulrahman abdulrhman abdulelah abdulmajeed abdulkarim abdulmohsen
abdulwahab ali omar umar othman uthman osama usama khalid khaled fahad fahd
faisal faysal saud sultan salman turki bandar nawaf nayef mishal meshal
mishaal majed majid mansour mansoor nasser nasir saleh salih saad saeed sami
samir tariq tarek talal thamer waleed walid yasser yasir yousef yusuf youssef
zaid zayed ziyad ibrahim ismail hamad hamza hani hassan hasan hussein hussain
husain hisham hatem jaber jamal jassim khalil mazen mohannad muath moath
musaed mustafa nabil nader naif rakan rashed rashid rayan sattam tamim wael
anas ammar amr ayman badr basel bilal emad essam fawaz firas ghassan haitham
jawad karim kareem luay maher marwan moayad munir murad omran qasim raed rami
sameer shadi suhail tamer wissam yahya younes zakaria zuhair amir
sara sarah noura nora norah nourah noor nour nouf reem rima lama maha hind
mona muna latifa lateefa layla laila leila lina lena dana dina deema dima
rana rania raneem rawan razan raghad reema rahaf shahad shahd shaikha sheikha
wafa abeer amal amani amira asma aseel atheer bashayer bushra dalal dalia
fatimah fatima fatma aisha aysha ayesha maryam mariam marwa arwa aryam hala
hana hanan haya hessa huda jawaher joud jood jana lulwa lujain manal manar
mashael nada nadia nahla najla najwa nawal nehal ohoud ola rasha sahar salma
samar samira sana shatha sultana tala thuraya wejdan wijdan yara yasmin
yasmeen zahra zainab zeinab ghada ghadeer ghaida hadeel hayat khadija khulood
kholoud lamya lamia maysa mayar modhi munirah muneera nouran renad ruba
sadeem shouq taghreed widad
james john robert michael william david richard joseph thomas charles
christopher daniel matthew anthony donald steven paul andrew joshua kenneth
kevin brian george edward ronald timothy jason jeffrey ryan jacob gary
nicholas eric jonathan stephen larry justin scott brandon benjamin samuel
gregory alexander patrick dennis jerry aaron jose adam henry nathan douglas
zachary peter kyle walter ethan jeremy harold keith arthur lawrence jesse
dylan bryan albert gabriel alan juan wayne ralph randy eugene vincent russell
elijah louis philip johnny
mary patricia jennifer linda elizabeth barbara susan jessica karen nancy lisa
betty margaret sandra ashley kimberly emily donna michelle dorothy amanda
melissa deborah stephanie rebecca sharon laura cynthia kathleen amy shirley
angela helen anna brenda pamela nicole emma samantha katherine christine
debra rachel catherine carolyn janet ruth maria diane julie joyce olivia
kelly christina lauren joan evelyn judith megan cheryl andrea hannah martha
jacqueline gloria teresa kathryn sophia isabella mia amelia liam oliver lucas
elena elise ivan sergei dmitri natalia olga pierre marie hans klaus giovanni
marco luca carlos miguel pedro pablo diego raj rahul amit priya anjali sanjay
vijay arjun deepak sunil anil ravi suresh ramesh ganesh lakshmi hiroshi kenji
takashi
""")

# Names that are everyday words too. Removed only where the sentence makes the
# reading as a person unavoidable — "Mark opened the attachment".
AMBIGUOUS_NAMES = _words("""
mark grant will bill rose hope faith joy grace dawn frank rich dean earl drew
chase wade lane miles hunter carter mason harper jack terry roger victor max
art ray bob rob pat sue don jay dale gene glen guy herb lance lee norm pierce
reed rod skip stan ted tony sam dan ben ken ron tom tim jim joe amber crystal
daisy ginger heather holly iris ivy jade jasmine lily olive pearl penny ruby
sandy violet angel christian jordan austin carol virginia georgia victoria
charlotte jean
""")

# What a person does in an incident report. Used to read an ambiguous name.
PERSON_VERBS = _words("""
clicked opened received reported entered noticed approved forwarded
downloaded said called confirmed logged signed replied sent submitted
provided shared ran executed installed accessed typed answered accepted
visited responded escalated authorised authorized contacted emailed
""")

# What an organisation does. A capitalised subject of one of these is the
# victim — including a vendor, which is a company as well as a product.
ORG_VERBS = _words("""
disclosed confirmed announced said stated acknowledged admitted revealed
notified paid declined refused hired engaged published warned apologised
apologized sued agreed reported detected discovered suffered experienced
learned
""")

# Sentence openers that are never the name of anything.
FUNCTION_WORDS = _words("""
the a an at in on after during when while since before by from to for with
and but or if as of this that these those our their its his her no not all
both each every some any several many most per via then once although
however meanwhile later initially subsequently finally also additionally
there here it they we he she i you who what which where why how within
without between among against under over into onto upon about above below
across around near until unless because so yet nor either neither once twice
approximately roughly nearly almost only just even still already further
moreover furthermore therefore thus hence next first second third last
one two three four five six seven eight nine ten
""")

# Plural and collective nouns that open sentences in every incident report and
# take the same verbs an organisation does ("Investigators confirmed ...").
GENERIC_SUBJECTS = _words("""
investigators analysts researchers attackers adversaries actors operators
criminals hackers intruders staff employees users customers clients patients
students officials authorities police regulators auditors responders
defenders administrators engineers developers vendors suppliers partners
executives management leadership forensics logs systems servers services
backups files data records alerts sensors tools controls teams hospitals
banks companies organisations organizations agencies operations production
sales payments monitoring telemetry logging analysis investigation review
testing detection response containment recovery encryption exfiltration
access email traffic authentication everything nothing someone nobody
""")


# --------------------------------------------------------------------------
# Vocabularies built from the knowledge bases
# --------------------------------------------------------------------------
def _name_tokens(names: Iterable[str]) -> List[str]:
    tokens: List[str] = []
    for name in names:
        tokens.extend(t.lower() for t in _NAME_TOKEN_RE.findall(name or "") if len(t) >= 2)
    return tokens


def _project_vocabulary() -> List[str]:
    """Every phrase the extractor and the mapper read as evidence.

    These must never be redacted, however they are capitalised: a report that
    writes "Business Email Compromise" in title case is still describing one.
    Imported lazily because those modules import the knowledge base too.
    """
    from app.services import dna_extractor, mitre_mapper

    phrases: List[str] = []
    for terms in dna_extractor.ATTACK_TYPES.values():
        phrases.extend(term for term, _weight in terms)
    for terms in dna_extractor.SECTORS.values():
        phrases.extend(terms)
    for terms in dna_extractor.IMPACTS.values():
        phrases.extend(terms)
    for _label, markers in dna_extractor.DECISIVE_MARKERS:
        phrases.extend(markers)
    for aliases in mitre_mapper.ALIASES.values():
        phrases.extend(aliases)
    return phrases


# Words in a vendor's name that say what kind of company it is, not which.
_COMPANY_FILLER = _words("""
software foundation project networks network systems system technologies
technology labs lab open source international communications solutions
security micro point alto check trend the and of for inc group corporation
enterprise community framework platforms platform professional electronics
electric
""")


@lru_cache(maxsize=1)
def company_names() -> FrozenSet[str]:
    """Vendors with a known-exploited CVE: companies that can be victims too."""
    vendors = (record.get("vendor", "") for record in _safe(kb.load_kev, {}).values())
    return frozenset(_name_tokens(vendors)) - _COMPANY_FILLER - STRUCTURE_WORDS - FUNCTION_WORDS


def _framework_names() -> List[str]:
    """Names of ATT&CK techniques, tactics and mitigations."""
    names = [t.get("name", "") for t in _safe(kb.load_techniques, [])]
    names.extend(kb.TACTIC_LABELS.values())
    names.extend(m.get("name", "") for m in _safe(kb.load_mitigations, {}).values())
    return [name for name in names if name]


def _all_public_names() -> List[str]:
    """Everything that may appear capitalised without being anyone's name."""
    try:
        own = _project_vocabulary()
    except Exception:  # noqa: BLE001 - a broken optional import must not stop redaction
        own = []
    return _framework_names() + _published_names() + own


def _published_names() -> List[str]:
    """Names of malware, tools, threat groups, vendors and products."""
    names: List[str] = []
    for record in _safe(kb.load_software, []):
        names.append(record.get("name", ""))
    for record in _safe(kb.load_groups, []):
        names.append(record.get("name", ""))
        names.extend(record.get("aliases", []))
    for record in _safe(kb.load_kev, {}).values():
        names.extend([record.get("vendor", ""), record.get("product", "")])
    return [name for name in names if name]


@lru_cache(maxsize=1)
def public_terms() -> FrozenSet[str]:
    """Lower-cased single tokens that are public security vocabulary.

    A published name counts word by word only where that is safe. "Stealth
    Falcon" is a threat group, but "Falcon" alone is as likely to be someone's
    project; "Drive-by Target" is a technique, but "Target" is a retailer
    before it is anything else. So a word from a published name stands on its
    own only if the name is that single word ("Mimikatz", "Conti") or the word
    is not English at all ("NetScaler"). The rest are recognised as whole
    phrases by `public_ngrams`, and the everyday IT nouns are listed by hand.
    """
    terms = set(TECH_EXTRAS) | set(STRUCTURE_WORDS) | set(IT_WORDS)
    terms.update(acronym.lower() for acronym in SECURITY_ACRONYMS)

    techniques = _safe(kb.load_techniques, [])
    mitigations = _safe(kb.load_mitigations, {})

    words = ordinary_words()
    for name in _all_public_names():
        tokens = _name_tokens([name])
        if len(tokens) == 1:
            terms.update(tokens)
        else:
            terms.update(token for token in tokens if token not in words)

    # Acronyms in the technique and mitigation text ("LSASS", "NTDS", "UAC").
    # Group and software descriptions are left out on purpose: they name victims.
    for record in list(techniques) + list(mitigations.values()):
        terms.update(a.lower() for a in _ACRONYM_RE.findall(record.get("description", "")))

    return frozenset(terms - STRONG_NAMES)


@lru_cache(maxsize=1)
def public_ngrams() -> FrozenSet[str]:
    """Runs of two to five words taken from published multi-word names.

    "Cobalt Strike", "Exchange Server", "Stealth Falcon": recognised together,
    where the words alone would not be.
    """
    grams = set()
    for name in _all_public_names():
        tokens = _name_tokens([name])
        for size in range(2, 6):
            for start in range(len(tokens) - size + 1):
                grams.add(" ".join(tokens[start:start + size]))
    return frozenset(grams)


@lru_cache(maxsize=1)
def ordinary_words() -> FrozenSet[str]:
    """Lower-cased English words, old and modern."""
    words = set(MODERN_WORDS) | set(FUNCTION_WORDS) | set(GENERIC_SUBJECTS)
    words |= PERSON_VERBS | ORG_VERBS

    if ENGLISH_WORDS_PATH.exists():
        try:
            with gzip.open(ENGLISH_WORDS_PATH, "rt", encoding="utf-8") as handle:
                words.update(line.strip() for line in handle if line.strip())
        except OSError:
            pass

    # Lower-case words in public knowledge-base prose. A proper noun is
    # capitalised there, so harvesting lower case only keeps names out.
    for record in _safe(kb.load_techniques, []):
        words.update(_LOWER_WORD_RE.findall(record.get("description", "")))
    for record in _safe(kb.load_mitigations, {}).values():
        words.update(_LOWER_WORD_RE.findall(record.get("description", "")))
    for record in _safe(kb.load_kev, {}).values():
        words.update(_LOWER_WORD_RE.findall(record.get("required_action", "")))

    return frozenset(words - STRONG_NAMES)


def _safe(loader, default):
    """A missing knowledge base shrinks the vocabulary; it must not stop redaction.

    A smaller vocabulary means more is redacted, which is the safe direction.
    """
    try:
        return loader()
    except Exception:  # noqa: BLE001
        return default


# --------------------------------------------------------------------------
# Questions the name detector asks
# --------------------------------------------------------------------------
# Three-letter stems are accepted only from this list. An unabridged dictionary
# has a three-letter entry for almost anything, and "ase" being a word is what
# made "Aseer" look like an inflection of one.
_SHORT_STEMS = _words("""
add aim ask act air arm bar bug buy cap cut dig end fit fix get hit job key
lay let log map mix net own pay put run say see set sit tag tap tie try use
win zip age aid bid box die dry due fly lie old new odd low big bad far few
hot ill ban bet bit can cop dam day ear eye fan fee gap gas hub jam kit lab
lap pad pan pen pin pop rid rip rob row sum tab tax tip top war way web wet
""")

_SUFFIXES = (
    ("ies", "y"), ("ied", "y"), ("es", ""), ("s", ""), ("ed", ""), ("ed", "e"),
    ("d", ""), ("ing", ""), ("ing", "e"), ("ly", ""), ("er", ""), ("er", "e"),
    ("est", ""), ("est", "e"), ("ment", ""), ("ness", ""), ("al", ""),
)


@lru_cache(maxsize=50_000)
def is_ordinary(word: str) -> bool:
    """Whether a token is an English word, allowing ordinary inflection."""
    lowered = word.lower().replace("’", "'")
    if lowered.endswith("'s"):
        lowered = lowered[:-2]
    lowered = lowered.strip("'")
    if not lowered:
        return False

    words = ordinary_words()
    if lowered in words:
        return True

    # "Internet-facing", "Double-extortion": a compound of words is a word.
    if "-" in lowered:
        parts = [part for part in lowered.split("-") if part]
        return bool(parts) and all(len(p) == 1 or is_ordinary(p) or is_public(p) for p in parts)

    if not lowered.isalpha():
        return False
    def known(stem: str) -> bool:
        return stem in words and (len(stem) >= 4 or stem in _SHORT_STEMS)

    for suffix, replacement in _SUFFIXES:
        if lowered.endswith(suffix) and len(lowered) - len(suffix) >= 3:
            stem = lowered[: len(lowered) - len(suffix)] + replacement
            if known(stem):
                return True
            # "stopped" -> "stop", "running" -> "run"
            if len(stem) >= 4 and stem[-1] == stem[-2] and known(stem[:-1]):
                return True
    return False


@lru_cache(maxsize=50_000)
def is_public(word: str) -> bool:
    """Whether a token is public security vocabulary rather than someone's name."""
    lowered = word.lower().replace("’", "'")
    if lowered.endswith("'s"):
        lowered = lowered[:-2]
    terms = public_terms()
    if lowered in terms:
        return True
    if lowered.endswith("s") and lowered[:-1] in terms:
        return True
    if "-" in lowered:
        parts = [part for part in lowered.split("-") if part]
        return bool(parts) and all(p in terms or p.isdigit() for p in parts)
    return False


@lru_cache(maxsize=1)
def sector_words() -> FrozenSet[str]:
    """Words the sector classifier reads: "bank", "pipeline", "healthcare"."""
    try:
        from app.services import dna_extractor
    except Exception:  # noqa: BLE001
        return frozenset()
    phrases: List[str] = []
    for terms in dna_extractor.SECTORS.values():
        phrases.extend(terms)
    return frozenset(_name_tokens(phrases)) - STRUCTURE_WORDS


def is_sector_word(word: str) -> bool:
    """A word that, capitalised next to a name, reads as part of a company's."""
    lowered = word.lower()
    words = sector_words()
    return lowered in words or (lowered.endswith("s") and lowered[:-1] in words)


# Prefixes of tokens that mix letters and digits without naming a machine:
# algorithms, protocol versions, product versions, threat-group designators.
TECH_PREFIXES = _words("""
sha md base aes rc des tdes utf ipv wpa oauth log win windows ios tls ssl
http https smb python java net dotnet esxi office port sql mssql rhel ubuntu
debian centos server exchange sharepoint vista cve ms kb apt unc ta
gmt utc tcp udp ntlm cis iso pci nist rsa ecc dh pbkdf crc blake hex
uint int amd arm intel core gen usb covid syswow advapi ntdll x509 type rule
event eventid code error status version ver rev build patch sp vlan
""")


def is_strong_name(word: str) -> bool:
    return word.lower() in STRONG_NAMES


def is_ambiguous_name(word: str) -> bool:
    return word.lower() in AMBIGUOUS_NAMES


def is_company(word: str) -> bool:
    return word.lower() in company_names()
