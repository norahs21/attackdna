"""The demo's visual language, in one place.

Two rules shape everything here.

**Colour carries meaning or it is not used.** Severity wears the status palette
because severity *is* a status; magnitude bars are one hue because length
already encodes magnitude and a second encoding would only add noise. Nothing
is coloured to look lively.

**The palette is validated, not chosen by eye.** These hues clear the
colour-vision-deficiency separation, chroma and contrast gates against the dark
surface they are drawn on, which is pinned in `.streamlit/config.toml` so the
demo cannot render on a surface the palette was never checked against. Every
status colour also ships with a written label, so a reader who cannot separate
the hues loses nothing.
"""
from __future__ import annotations

# --- Surfaces and ink ----------------------------------------------------
PLANE = "#0d0d0d"
SURFACE = "#1a1a19"
INK = "#ffffff"
INK_SECONDARY = "#c3c2b7"
INK_MUTED = "#898781"
GRIDLINE = "#2c2c2a"
BORDER = "rgba(255,255,255,0.10)"

# --- Categorical slots, in the order they must be assigned ---------------
ACCENT = "#3987e5"
SERIES = ("#3987e5", "#d95926", "#199e70")

# --- Status: reserved, never reused as a series colour -------------------
STATUS = {
    "good": "#0ca30c",
    "warning": "#fab219",
    "serious": "#ec835a",
    "critical": "#d03b3b",
}

# Severity is a status, so it draws from the status palette rather than from
# the series hues — and always beside its own written label.
SEVERITY_STATUS = {
    "low": "good",
    "medium": "warning",
    "high": "serious",
    "critical": "critical",
}

PROVENANCE_LABELS = {
    "public": ("Real breach", SERIES[2]),
    "synthetic": ("Synthetic", SERIES[1]),
    "internal": ("Your incident", SERIES[0]),
    "shared": ("Shared by a member", SERIES[0]),
}

STYLE = f"""
<style>
  .block-container {{ padding-top: 2rem; padding-bottom: 4rem; max-width: 1180px; }}

  /* --- Masthead ---
     A wordmark and a rule, not a logo and a pictogram. The name is set in
     tracked capitals because that is what reads as an instrument rather than
     an app, and it is the only place the accent appears at full strength. */
  .dna-hero {{
    border-top: 2px solid {ACCENT};
    border-bottom: 1px solid {BORDER};
    padding: 1.4rem 0 1.15rem;
    margin-bottom: 1.8rem;
  }}
  .dna-hero h1 {{
    margin: 0 0 .4rem 0; font-size: 2.1rem; font-weight: 600;
    letter-spacing: .16em; line-height: 1.1;
  }}
  .dna-hero p {{ color: {INK_SECONDARY}; font-size: 1rem; margin: 0; max-width: 62ch; }}
  .dna-hero .ar {{ color: {INK_MUTED}; font-size: .9rem; margin-top: .3rem; }}

  /* --- Sidebar section heading --- */
  .side-head {{
    font-size: .7rem; font-weight: 700; letter-spacing: .16em; text-transform: uppercase;
    color: {INK_MUTED}; padding-bottom: .4rem; margin-bottom: .6rem;
    border-bottom: 1px solid {BORDER};
  }}

  /* --- Legend row: a colour swatch that means what the charts mean --- */
  .legend {{ display: flex; align-items: center; gap: .5rem; font-size: .8rem;
             color: {INK_SECONDARY}; margin: .18rem 0; }}
  .legend .sw {{ width: 10px; height: 10px; border-radius: 2px; flex: none; }}
  .legend strong {{ color: {INK}; font-weight: 650; }}

  /* --- Stage heading: a numbered chip, so the journey is countable --- */
  .stage {{ display: flex; align-items: baseline; gap: .6rem; margin: .2rem 0 .1rem; }}
  .stage .n {{
    font-size: .74rem; font-weight: 700; letter-spacing: .04em;
    color: {ACCENT}; border: 1px solid rgba(57,135,229,.45);
    background: rgba(57,135,229,.12); border-radius: 6px; padding: .1rem .45rem;
  }}
  .stage .en {{
    font-size: .76rem; letter-spacing: .14em; text-transform: uppercase; color: {INK_MUTED};
  }}
  .stage .ar {{ font-size: .82rem; color: {INK_MUTED}; margin-inline-start: auto; }}

  /* --- Verdict card: the whole story, above the evidence --- */
  .verdict {{
    border: 1px solid rgba(57,135,229,.35); border-radius: 16px;
    background:
      linear-gradient(180deg, rgba(57,135,229,.10), rgba(57,135,229,.02)),
      {SURFACE};
    padding: 1.25rem 1.4rem; margin: .4rem 0 1.4rem;
  }}
  .verdict .headline {{
    font-size: 1.45rem; font-weight: 650; letter-spacing: -.015em; line-height: 1.25;
    margin-bottom: .15rem;
  }}
  .verdict .sub {{ color: {INK_MUTED}; font-size: .82rem; margin-bottom: 1rem; }}
  .verdict .row {{
    display: flex; gap: .8rem; align-items: stretch; padding: .55rem 0;
    border-top: 1px solid {BORDER}; font-size: .94rem; line-height: 1.5;
  }}
  .verdict .row:first-of-type {{ border-top: none; }}
  .verdict .row .rule {{ width: 3px; border-radius: 2px; flex: none; }}
  .verdict .row .k {{ color: {INK_MUTED}; font-size: .74rem; letter-spacing: .1em;
                      text-transform: uppercase; display: block; }}
  .verdict .row .v {{ color: {INK}; }}
  .verdict .row .v em {{ color: {INK_SECONDARY}; font-style: normal; }}

  /* --- Signature --- */
  .sig-box {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem;
    background: rgba(255,255,255,.04); border: 1px solid {BORDER};
    border-left: 3px solid {ACCENT};
    padding: .75rem .9rem; border-radius: 8px; word-break: break-word; line-height: 1.75;
    color: {INK_SECONDARY};
  }}

  /* --- Pills --- */
  .pill {{
    display: inline-block; padding: .16rem .58rem; border-radius: 999px;
    font-size: .73rem; font-weight: 600; margin: .12rem .25rem .12rem 0;
    border: 1px solid transparent; white-space: nowrap;
  }}
  .pill-critical {{ background: rgba(208,59,59,.18);  color: #ef8080; border-color: rgba(208,59,59,.5); }}
  .pill-high     {{ background: rgba(236,131,90,.16); color: #f0a184; border-color: rgba(236,131,90,.45); }}
  .pill-medium   {{ background: rgba(250,178,25,.16); color: #f5c65c; border-color: rgba(250,178,25,.45); }}
  .pill-low      {{ background: rgba(12,163,12,.16);  color: #4cc24c; border-color: rgba(12,163,12,.45); }}
  .pill-recalled {{ background: rgba(57,135,229,.16); color: #7fb1ef; border-color: rgba(57,135,229,.45); }}
  .pill-baseline {{ background: rgba(255,255,255,.06); color: {INK_MUTED}; border-color: {BORDER}; }}
  .pill-public   {{ background: rgba(25,158,112,.16); color: #4cc79a; border-color: rgba(25,158,112,.5); }}
  .pill-synthetic{{ background: rgba(217,89,38,.15);  color: #e8926f; border-color: rgba(217,89,38,.45); }}
  .pill-internal {{ background: rgba(57,135,229,.15); color: #7fb1ef; border-color: rgba(57,135,229,.45); }}

  .pill-shared   {{ background: rgba(57,135,229,.15); color: #7fb1ef; border-color: rgba(57,135,229,.45); }}
  .pill-yours    {{ background: rgba(255,255,255,.08); color: {INK}; border-color: rgba(255,255,255,.3); }}

  /* --- Journey: four steps, the current one lit --- */
  .journey {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: .5rem; margin: 0 0 1.4rem; }}
  .journey .step {{
    border: 1px solid {BORDER}; border-radius: 10px; padding: .55rem .7rem;
    background: rgba(255,255,255,.02); font-size: .8rem; color: {INK_MUTED}; line-height: 1.35;
  }}
  .journey .step b {{ display: block; color: {INK_SECONDARY}; font-size: .86rem; font-weight: 600; }}
  .journey .step .ar {{ display: block; font-size: .78rem; }}
  .journey .step.done {{ border-color: rgba(12,163,12,.45); }}
  .journey .step.done b {{ color: #4cc24c; }}
  .journey .step.now {{ border-color: rgba(57,135,229,.6); background: rgba(57,135,229,.10); }}
  .journey .step.now b {{ color: {INK}; }}
  @media (max-width: 720px) {{ .journey {{ grid-template-columns: repeat(2, 1fr); }} }}

  /* --- Privacy outcome: the first thing a team sees after attaching a report --- */
  .shield {{
    border-radius: 14px; padding: 1.1rem 1.25rem; margin: .3rem 0 1rem;
    border: 1px solid rgba(12,163,12,.5);
    background: linear-gradient(180deg, rgba(12,163,12,.14), rgba(12,163,12,.04)), {SURFACE};
  }}
  .shield.fail {{
    border-color: rgba(208,59,59,.6);
    background: linear-gradient(180deg, rgba(208,59,59,.16), rgba(208,59,59,.04)), {SURFACE};
  }}
  .shield .title {{ font-size: 1.3rem; font-weight: 650; letter-spacing: -.01em; }}
  .shield .title-ar {{ font-size: 1.05rem; color: {INK_SECONDARY}; margin-top: .1rem; direction: rtl; text-align: left; }}
  .shield .detail {{ color: {INK_SECONDARY}; font-size: .9rem; margin-top: .6rem; line-height: 1.55; }}
  .shield .chips {{ margin-top: .5rem; }}
  .chip {{
    display: inline-block; padding: .14rem .55rem; border-radius: 6px; margin: .15rem .3rem .15rem 0;
    font-size: .76rem; background: rgba(255,255,255,.06); border: 1px solid {BORDER}; color: {INK_SECONDARY};
  }}
  .chip strong {{ color: {INK}; }}

  /* --- Consent: what leaves, what stays --- */
  .consent {{ display: grid; grid-template-columns: 1fr 1fr; gap: .8rem; margin: .4rem 0 1rem; }}
  .consent .col {{ border: 1px solid {BORDER}; border-radius: 12px; padding: .8rem 1rem; background: {SURFACE}; }}
  .consent .col h4 {{ margin: 0 0 .45rem; font-size: .8rem; letter-spacing: .1em; text-transform: uppercase; }}
  .consent .col.share h4 {{ color: #7fb1ef; }}
  .consent .col.keep h4 {{ color: #4cc24c; }}
  .consent ul {{ margin: 0; padding-left: 1.1rem; font-size: .88rem; color: {INK_SECONDARY}; line-height: 1.6; }}
  @media (max-width: 720px) {{ .consent {{ grid-template-columns: 1fr; }} }}

  .redact {{ color: #ef8080; font-weight: 600; background: rgba(208,59,59,.12);
             border-radius: 4px; padding: 0 .2rem; }}

  /* --- Stat tile --- */
  .tile {{
    border: 1px solid {BORDER}; border-radius: 12px; background: {SURFACE};
    padding: .85rem 1rem; height: 100%;
  }}
  .tile .k {{ color: {INK_MUTED}; font-size: .72rem; letter-spacing: .09em;
              text-transform: uppercase; }}
  .tile .v {{ font-size: 1.85rem; font-weight: 650; letter-spacing: -.02em;
              line-height: 1.25; margin-top: .1rem; }}
  .tile .d {{ color: {INK_SECONDARY}; font-size: .78rem; }}

  /* --- Facts: short labelled values that wrap instead of truncating --- */
  .facts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: .6rem; margin: .3rem 0 1rem; }}
  .facts .f {{ border: 1px solid {BORDER}; border-radius: 10px; padding: .55rem .75rem;
               background: {SURFACE}; }}
  .facts .k {{ color: {INK_MUTED}; font-size: .7rem; letter-spacing: .09em; text-transform: uppercase; }}
  .facts .v {{ font-size: 1.12rem; font-weight: 620; margin-top: .15rem; line-height: 1.3; }}

  /* --- Streamlit chrome --- */
  div[data-testid="stExpander"] details {{
    border: 1px solid {BORDER}; border-radius: 12px; background: rgba(255,255,255,.02);
  }}
  div[data-testid="stExpander"] summary {{ font-size: .9rem; }}
  hr {{ border-color: {BORDER} !important; }}
  section[data-testid="stSidebar"] {{ border-right: 1px solid {BORDER}; }}
</style>
"""


def stage(number: str, english: str, arabic: str) -> str:
    """A numbered stage heading. The number is the point: six, always in order."""
    return (f'<div class="stage"><span class="n">{number}</span>'
            f'<span class="en">{english}</span>'
            f'<span class="ar">{arabic}</span></div>')


def side_head(title: str) -> str:
    """A sidebar section heading — a rule and tracked capitals, no pictogram."""
    return f'<div class="side-head">{title}</div>'


def legend_row(colour: str, count: int, label: str) -> str:
    """One provenance count, keyed by the same colour the charts use.

    The written label carries the meaning; the swatch only ties the row to the
    chart it corresponds to, so nothing here depends on telling hues apart.
    """
    return (f'<div class="legend"><span class="sw" style="background:{colour}"></span>'
            f'<span><strong>{count}</strong> {label}</span></div>')


def severity_pill(severity: str) -> str:
    label = (severity or "unknown").title()
    return f'<span class="pill pill-{(severity or "low").lower()}">{label}</span>'


def provenance_pill(provenance: str, yours: bool = False) -> str:
    """Where a recalled incident came from — never shown without this.

    A shared incident says only whether it is the viewer's own. Which other
    organisation contributed it is exactly what the system does not know how
    to say.
    """
    key = (provenance or "internal").lower()
    if yours:
        return '<span class="pill pill-yours">Your organisation\'s incident</span>'
    label = {"public": "Real documented breach",
             "synthetic": "Synthetic training incident",
             "internal": "Internal incident",
             "shared": "Shared by another organisation · identity withheld",
             }.get(key, key.title())
    return f'<span class="pill pill-{key}">{label}</span>'


def journey(current: int, done: int = 0) -> str:
    """The four steps a security team goes through, with the current one lit."""
    steps = [
        ("Attach report", "إرفاق التقرير"),
        ("Remove identity", "إزالة الهوية"),
        ("Attack DNA & matches", "البصمة والحوادث المشابهة"),
        ("Share (optional)", "المشاركة (اختياري)"),
    ]
    cells = []
    for index, (english, arabic) in enumerate(steps, start=1):
        state = "done" if index <= done else ("now" if index == current else "")
        cells.append(f'<div class="step {state}"><b>{index}. {english}</b>'
                     f'<span class="ar">{arabic}</span></div>')
    return f'<div class="journey">{"".join(cells)}</div>'


def chips(counts: dict) -> str:
    """Removed identifier categories, as countable chips."""
    labels = {
        "PERSON": ("person", "people"), "NAME": ("name", "names"),
        "ORG": ("organisation", "organisations"), "EMAIL": ("email", "emails"),
        "IP": ("IP address", "IP addresses"), "PHONE": ("phone number", "phone numbers"),
        "HOSTNAME": ("hostname", "hostnames"), "DOMAIN": ("domain", "domains"),
        "URL": ("URL", "URLs"), "ACCOUNT": ("account", "accounts"),
        "ARABIC_TEXT": ("Arabic passage", "Arabic passages"),
        "FOREIGN_TEXT": ("non-Latin passage", "non-Latin passages"),
        "NATIONAL_ID": ("national ID", "national IDs"), "IBAN": ("bank account", "bank accounts"),
        "CREDIT_CARD": ("card number", "card numbers"), "MAC": ("MAC address", "MAC addresses"),
        "SECRET": ("secret", "secrets"), "TOKEN": ("token", "tokens"),
        "REFERENCE": ("case reference", "case references"),
        "USER_PATH": ("user path", "user paths"),
    }

    def name(kind: str, count: int) -> str:
        singular, plural = labels.get(kind, (kind.replace("_", " ").lower(),) * 2)
        return singular if count == 1 else plural

    parts = [f'<span class="chip"><strong>{count}</strong> {name(kind, count)}</span>'
             for kind, count in sorted(counts.items(), key=lambda item: -item[1])]
    return f'<div class="chips">{"".join(parts)}</div>'


def facts(items) -> str:
    """A row of labelled values; long values wrap rather than being cut off."""
    cells = "".join(f'<div class="f"><div class="k">{label}</div><div class="v">{value}</div></div>'
                    for label, value in items)
    return f'<div class="facts">{cells}</div>'


def tile(label: str, value: str, detail: str = "") -> str:
    detail_html = f'<div class="d">{detail}</div>' if detail else ""
    return (f'<div class="tile"><div class="k">{label}</div>'
            f'<div class="v">{value}</div>{detail_html}</div>')
