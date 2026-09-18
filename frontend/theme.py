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
}

STYLE = f"""
<style>
  .block-container {{ padding-top: 2rem; padding-bottom: 4rem; max-width: 1180px; }}

  /* --- Hero --- */
  .dna-hero {{
    border: 1px solid {BORDER}; border-radius: 16px; padding: 1.5rem 1.7rem;
    background:
      radial-gradient(120% 140% at 0% 0%, rgba(57,135,229,.14), transparent 58%),
      {SURFACE};
    margin-bottom: 1.6rem;
  }}
  .dna-hero h1 {{
    margin: 0 0 .25rem 0; font-size: 2.35rem; letter-spacing: -.025em; line-height: 1.1;
  }}
  .dna-hero p {{ color: {INK_SECONDARY}; font-size: 1.02rem; margin: 0; }}
  .dna-hero .ar {{ color: {INK_MUTED}; font-size: .92rem; margin-top: .35rem; }}

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
    display: flex; gap: .7rem; align-items: flex-start; padding: .5rem 0;
    border-top: 1px solid {BORDER}; font-size: .94rem; line-height: 1.5;
  }}
  .verdict .row:first-of-type {{ border-top: none; }}
  .verdict .row .ico {{ font-size: 1.05rem; line-height: 1.4; width: 1.4rem; flex: none; }}
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


def severity_pill(severity: str) -> str:
    label = (severity or "unknown").title()
    return f'<span class="pill pill-{(severity or "low").lower()}">{label}</span>'


def provenance_pill(provenance: str) -> str:
    """Where a recalled incident came from — never shown without this."""
    key = (provenance or "internal").lower()
    label = {"public": "Real documented breach",
             "synthetic": "Synthetic training incident",
             "internal": "Your own incident"}.get(key, key.title())
    return f'<span class="pill pill-{key}">{label}</span>'


def tile(label: str, value: str, detail: str = "") -> str:
    detail_html = f'<div class="d">{detail}</div>' if detail else ""
    return (f'<div class="tile"><div class="k">{label}</div>'
            f'<div class="v">{value}</div>{detail_html}</div>')
