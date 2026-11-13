"""The interface's visual language, in one place, for day and night.

The layout follows an analytics console: a navigation rail, a page header,
a strip of key figures, then cards. Every colour on the page is a CSS variable,
so switching between day and night swaps one block of tokens and nothing else.
Charts are the exception, because Altair draws with concrete colours, so they
ask `palette(mode)` for the same tokens.

Two rules from the first version still hold.

**Colour carries meaning or it is not used.** Severity wears the status
palette because severity *is* a status; bars are one hue because length already
encodes magnitude.

**Every status colour ships with a written label**, so a reader who cannot
separate the hues loses nothing. The day palette uses darker variants of the
same hues so they keep their contrast on white.
"""
from __future__ import annotations

import html as _html
from typing import Dict, Iterable, List, Optional, Sequence

# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------
PALETTES: Dict[str, Dict[str, str]] = {
    "dark": {
        "bg": "#0b0b0c", "surface": "#151517", "surface2": "#1d1d20",
        "border": "rgba(255,255,255,0.08)", "border_strong": "rgba(255,255,255,0.16)",
        "ink": "#f4f4f5", "ink2": "#b9b9c0", "muted": "#80808a", "grid": "#26262a",
        "accent": "#3987e5", "accent_soft": "rgba(57,135,229,0.14)",
        "series1": "#3987e5", "series2": "#d95926", "series3": "#199e70",
        "series4": "#c45bd6", "series5": "#d6b23a", "series6": "#5bc0c4",
        "good": "#22b14c", "warning": "#fab219", "serious": "#ec835a", "critical": "#e05252",
        "good_ink": "#5fd17f", "warning_ink": "#f5c65c", "serious_ink": "#f0a184",
        "critical_ink": "#f08b8b", "accent_ink": "#86b6f0",
        "shadow": "none", "on_accent": "#ffffff",
    },
    "light": {
        "bg": "#eceef1", "surface": "#ffffff", "surface2": "#f5f6f8",
        "border": "#e2e5e9", "border_strong": "#cfd4da",
        "ink": "#15171c", "ink2": "#454a54", "muted": "#7d838d", "grid": "#eceef1",
        "accent": "#2563c9", "accent_soft": "rgba(37,99,201,0.09)",
        "series1": "#2563c9", "series2": "#c2491a", "series3": "#13805a",
        "series4": "#9b3fb0", "series5": "#a8820f", "series6": "#1f8a8e",
        "good": "#178a3a", "warning": "#c98a00", "serious": "#cf6234", "critical": "#c93434",
        "good_ink": "#146c2f", "warning_ink": "#8a5f00", "serious_ink": "#a54a22",
        "critical_ink": "#a82727", "accent_ink": "#1d4f9f",
        "shadow": "0 1px 2px rgba(16,24,40,.05), 0 1px 3px rgba(16,24,40,.06)",
        "on_accent": "#ffffff",
    },
}

SEVERITY_STATUS = {"low": "good", "medium": "warning", "high": "serious", "critical": "critical"}

PROVENANCE = {
    "shared": ("Shared by a member", "series1"),
    "public": ("Real breach", "series3"),
    "synthetic": ("Synthetic", "series2"),
    "internal": ("Internal", "muted"),
}


def palette(mode: str) -> Dict[str, str]:
    return PALETTES["light" if mode == "light" else "dark"]


def _variables(mode: str) -> str:
    tokens = palette(mode)
    return "".join(f"--{name.replace('_', '-')}: {value};" for name, value in tokens.items())


# --------------------------------------------------------------------------
# Stylesheet
# --------------------------------------------------------------------------
_CSS = """
/* ---------- Canvas and Streamlit chrome ---------- */
.stApp, [data-testid="stAppViewContainer"] { background: var(--bg) !important; color: var(--ink); }
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stAppDeployButton"], [data-testid="stDecoration"] { display: none !important; }
.block-container { padding-top: 1.6rem; padding-bottom: 4rem; max-width: 1240px; }
[data-testid="stSidebar"] { background: var(--surface) !important; border-right: 1px solid var(--border); }
[data-testid="stSidebar"] * { color: var(--ink2); }
.stApp p, .stApp li, .stApp label, .stApp span, .stApp div { color: inherit; }
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5 { color: var(--ink) !important; letter-spacing: -.01em; }
.stMarkdown, .stMarkdown p, .stMarkdown li { color: var(--ink2); }
.stMarkdown strong { color: var(--ink); }
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] * { color: var(--muted) !important; }
[data-testid="stWidgetLabel"] * { color: var(--ink2) !important; }
code { background: var(--surface2) !important; color: var(--accent-ink) !important; border-radius: 5px; }
hr { border-color: var(--border) !important; }
a { color: var(--accent) !important; }

/* inputs */
[data-baseweb="input"], [data-baseweb="base-input"], [data-baseweb="textarea"],
[data-baseweb="select"] > div, .stTextArea textarea, .stTextInput input {
  background: var(--surface2) !important; color: var(--ink) !important;
  border-color: var(--border) !important; }
.stTextArea textarea::placeholder, .stTextInput input::placeholder { color: var(--muted) !important; }
[data-baseweb="select"] * { color: var(--ink) !important; }
[data-baseweb="popover"] ul, [data-baseweb="menu"] { background: var(--surface) !important; }
[data-baseweb="popover"] li { color: var(--ink) !important; }
[data-testid="stFileUploaderDropzone"] {
  background: var(--surface) !important; border: 1.5px dashed var(--border-strong) !important;
  border-radius: 14px !important; padding: 1.6rem 1.2rem !important; }
[data-testid="stFileUploaderDropzone"] * { color: var(--ink2) !important; }
[data-testid="stFileUploaderFile"] * { color: var(--ink) !important; }

/* controls that take their colours from Streamlit's own theme, so they follow
   the night palette unless told otherwise */
[data-testid="stSelectbox"] [role="group"],
[data-testid="stSelectbox"] [data-baseweb="select"] > div,
[data-testid="stSelectbox"] [data-baseweb="select"] > div > div,
[data-testid="stNumberInputContainer"], [data-testid="stNumberInputContainer"] input,
[data-testid="stNumberInput"] button {
  background-color: var(--surface2) !important; color: var(--ink) !important;
  border-color: var(--border) !important; }
[data-testid="stSelectbox"] [role="group"] *, [data-testid="stSelectbox"] input {
  color: var(--ink) !important; -webkit-text-fill-color: var(--ink) !important; }
[data-testid="stNumberInput"] button svg, [data-testid="stSelectbox"] svg { color: var(--ink2) !important; fill: currentColor; }
[data-baseweb="popover"] [role="listbox"], [data-baseweb="popover"] ul,
[data-baseweb="popover"] li, [data-baseweb="popover"] [role="option"] {
  background-color: var(--surface) !important; color: var(--ink) !important; }
[data-baseweb="popover"] li:hover, [data-baseweb="popover"] [aria-selected="true"] {
  background-color: var(--surface2) !important; }
[data-testid="stSelectboxVirtualDropdown"] { background-color: var(--surface) !important;
  color: var(--ink) !important; border: 1px solid var(--border); border-radius: 10px; }
[data-testid="stSelectboxVirtualDropdown"] * { color: var(--ink) !important; }
[data-testid="stSelectboxVirtualDropdown"] [role="option"] > div { background-color: transparent !important; }
[data-testid="stSelectboxVirtualDropdown"] [role="option"]:hover > div,
[data-testid="stSelectboxVirtualDropdown"] [aria-selected="true"] > div { background-color: var(--surface2) !important; }
[data-testid="stFileChip"] { background: var(--surface2) !important; border: 1px solid var(--border);
  border-radius: 10px; }
[data-testid="stFileChip"] * { color: var(--ink) !important; background-color: transparent !important; }
[data-testid="stFileChip"] svg { fill: var(--ink2) !important; }
[data-baseweb="textarea"]:focus-within, [data-baseweb="input"]:focus-within,
[data-baseweb="base-input"]:focus-within { border-color: var(--accent) !important; }
[data-testid="stExpander"] summary:hover, [data-testid="stExpander"] details[open] > summary {
  background-color: var(--surface2) !important; }
[data-testid="stTooltipIcon"] svg, [data-testid="stSidebarCollapseButton"] svg,
[data-testid="stExpandedSidebarCollapseButton"] svg, [data-testid="stSidebarCollapsedControl"] svg,
[data-testid="stMainMenu"] svg { color: var(--ink2) !important; }

/* buttons */
.stButton > button, .stDownloadButton > button, [data-testid="stFileUploaderDropzone"] button {
  background: var(--surface) !important; color: var(--ink) !important;
  border: 1px solid var(--border-strong) !important; border-radius: 10px !important;
  box-shadow: var(--shadow); }
.stButton > button p, .stDownloadButton > button p { color: var(--ink) !important; }
.stButton > button[kind="primary"], [data-testid="stBaseButton-primary"] {
  background: var(--accent) !important; border-color: var(--accent) !important; }
.stButton > button[kind="primary"] p, [data-testid="stBaseButton-primary"] p { color: var(--on-accent) !important; }
.stButton > button:disabled { opacity: .45; }

/* expanders, tabs, alerts */
[data-testid="stExpander"] details { background: var(--surface) !important; border: 1px solid var(--border) !important;
  border-radius: 12px !important; box-shadow: var(--shadow); }
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary * { color: var(--ink) !important; }
[data-baseweb="tab-list"] { gap: .3rem; border-bottom: 1px solid var(--border); }
[data-baseweb="tab"] { color: var(--muted) !important; background: transparent !important; }
[data-baseweb="tab"] p { font-weight: 550; }
[data-baseweb="tab"][aria-selected="true"], [data-baseweb="tab"][aria-selected="true"] * { color: var(--ink) !important; }
[data-baseweb="tab-highlight"] { background: var(--accent) !important; }
[data-baseweb="tab-border"] { display: none; }
[data-testid="stAlertContainer"] { border-radius: 12px !important; }
[data-testid="stAlertContainer"] * { color: var(--ink) !important; }
[data-testid="stMetricValue"] { color: var(--ink) !important; }
[data-testid="stMetricLabel"] * { color: var(--muted) !important; }

/* ---------- Navigation rail ---------- */
.brand-logo { padding: .1rem 0 1.1rem; }
.brand-logo img { width: 100%; max-width: 210px; display: block; }
.brand { display: flex; align-items: center; gap: .6rem; padding: .2rem 0 1.1rem; }
.brand .mark { width: 30px; height: 30px; border-radius: 9px; background: var(--accent);
  display: grid; place-items: center; color: var(--on-accent) !important; font-weight: 800; font-size: .8rem; }
.brand .name { font-weight: 750; letter-spacing: .14em; color: var(--ink) !important; font-size: .95rem; }
.brand .brand-sub { display: block; font-size: .68rem; color: var(--muted) !important; letter-spacing: .02em; font-weight: 500; }
[data-testid="stSidebar"] [role="radiogroup"] { gap: .15rem; }
[data-testid="stSidebar"] [data-testid="stRadioOption"] {
  padding: .5rem .7rem; border-radius: 10px; margin: 0; width: 100%; cursor: pointer; }
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child { display: none; }
[data-testid="stSidebar"] [data-testid="stRadioOption"] p { font-size: .9rem; font-weight: 550; color: var(--ink2) !important; }
[data-testid="stSidebar"] [data-testid="stRadioOption"]:hover { background: var(--surface2); }
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] {
  background: var(--surface2); box-shadow: inset 3px 0 0 var(--accent), inset 0 0 0 1px var(--border); }
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] p { color: var(--ink) !important; }
/* switches: the track and knob follow the palette in both modes */
label:has(> span > input[role="switch"]) > div:first-of-type { background: var(--border-strong) !important; }
label:has(> span > input[role="switch"]:checked) > div:first-of-type { background: var(--accent) !important; }
label:has(> span > input[role="switch"]) > div:first-of-type > div { background: #ffffff !important; }
/* checkboxes */
label:has(> span > input[type="checkbox"]:not([role="switch"])) > div:first-of-type {
  background: var(--surface) !important; border: 1.5px solid var(--border-strong) !important; }
label:has(> span > input[type="checkbox"]:not([role="switch"]):checked) > div:first-of-type {
  background: var(--accent) !important; border-color: var(--accent) !important; }
.side-head { font-size: .66rem; font-weight: 700; letter-spacing: .16em; text-transform: uppercase;
  color: var(--muted) !important; margin: .2rem 0 .45rem; }
.mini { display: grid; grid-template-columns: 1fr 1fr; gap: .45rem; margin-bottom: .4rem; }
.mini .c { background: var(--surface2); border: 1px solid var(--border); border-radius: 10px; padding: .45rem .6rem; }
.mini .k { font-size: .66rem; color: var(--muted) !important; text-transform: uppercase; letter-spacing: .08em; }
.mini .v { font-size: 1.15rem; font-weight: 700; color: var(--ink) !important; }

/* ---------- Page header ---------- */
.pagehead { display: flex; justify-content: space-between; align-items: flex-end; gap: 1rem;
  flex-wrap: wrap; margin: 0 0 1.2rem; }
.pagehead h1 { font-size: 1.85rem !important; font-weight: 650 !important; margin: 0 !important; padding: 0 !important; }
.pagehead p { margin: .3rem 0 0; color: var(--ink2) !important; font-size: .95rem; max-width: 70ch; }
.pagehead .meta { display: flex; gap: .4rem; flex-wrap: wrap; }
.tag { display: inline-flex; align-items: center; gap: .35rem; padding: .28rem .65rem; border-radius: 999px;
  font-size: .75rem; font-weight: 600; background: var(--surface); border: 1px solid var(--border);
  color: var(--ink2) !important; box-shadow: var(--shadow); }
.tag .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--good); }

/* ---------- Cards and KPI strip ---------- */
[class*="st-key-card-"] { background: var(--surface) !important; border: 1px solid var(--border) !important;
  border-radius: 16px !important; box-shadow: var(--shadow); padding: 1rem 1.1rem .6rem !important; }
[data-testid="stVerticalBlockBorderWrapper"]:has(> [class*="st-key-card-"]) { border: none !important; padding: 0 !important; }
.cardhead h3 { font-size: .95rem !important; font-weight: 650 !important; margin: 0 !important; padding: 0 !important; }
.cardhead .sub { color: var(--muted) !important; font-size: .8rem; margin: .1rem 0 .2rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
  padding: 1rem 1.15rem; box-shadow: var(--shadow); margin-bottom: .9rem; }
.card h3 { font-size: .95rem !important; font-weight: 650 !important; margin: 0 0 .15rem !important; padding: 0 !important; }
.card .sub { color: var(--muted) !important; font-size: .8rem; margin-bottom: .6rem; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0;
  background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
  box-shadow: var(--shadow); margin-bottom: 1rem; overflow: hidden; }
.kpi { padding: .9rem 1.1rem; border-right: 1px solid var(--border); }
.kpi:last-child { border-right: none; }
.kpi .k { font-size: .76rem; color: var(--muted) !important; font-weight: 550; }
.kpi .v { font-size: 1.55rem; font-weight: 700; color: var(--ink) !important; letter-spacing: -.02em; line-height: 1.25; }
.kpi .d { font-size: .74rem; font-weight: 650; margin-left: .3rem; }
.kpi .n { font-size: .74rem; color: var(--muted) !important; }
.up { color: var(--good-ink) !important; } .down { color: var(--critical-ink) !important; }

/* ---------- Pills and chips ---------- */
.pill { display: inline-block; padding: .14rem .55rem; border-radius: 999px; font-size: .72rem;
  font-weight: 650; white-space: nowrap; border: 1px solid transparent; }
.pill-good { background: color-mix(in srgb, var(--good) 14%, transparent); color: var(--good-ink) !important; border-color: color-mix(in srgb, var(--good) 40%, transparent); }
.pill-warning { background: color-mix(in srgb, var(--warning) 16%, transparent); color: var(--warning-ink) !important; border-color: color-mix(in srgb, var(--warning) 45%, transparent); }
.pill-serious { background: color-mix(in srgb, var(--serious) 15%, transparent); color: var(--serious-ink) !important; border-color: color-mix(in srgb, var(--serious) 45%, transparent); }
.pill-critical { background: color-mix(in srgb, var(--critical) 14%, transparent); color: var(--critical-ink) !important; border-color: color-mix(in srgb, var(--critical) 45%, transparent); }
.pill-accent { background: var(--accent-soft); color: var(--accent-ink) !important; border-color: color-mix(in srgb, var(--accent) 40%, transparent); }
.pill-neutral { background: var(--surface2); color: var(--ink2) !important; border-color: var(--border); }
.chip { display: inline-block; padding: .16rem .55rem; border-radius: 7px; margin: .15rem .3rem .15rem 0;
  font-size: .76rem; background: var(--surface2); border: 1px solid var(--border); color: var(--ink2) !important; }
.chip strong { color: var(--ink) !important; }
.redact { color: var(--critical-ink) !important; font-weight: 650; background: color-mix(in srgb, var(--critical) 12%, transparent);
  border-radius: 4px; padding: 0 .2rem; }

/* ---------- Tables ---------- */
.tbl-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 12px; background: var(--surface); }
table.tbl { width: 100%; border-collapse: collapse; font-size: .84rem; }
table.tbl th { text-align: left; font-size: .7rem; letter-spacing: .07em; text-transform: uppercase;
  color: var(--muted) !important; font-weight: 650; padding: .6rem .8rem; background: var(--surface2);
  border-bottom: 1px solid var(--border); white-space: nowrap; }
table.tbl td { padding: .55rem .8rem; border-bottom: 1px solid var(--border); color: var(--ink2) !important; vertical-align: top; }
table.tbl tr:last-child td { border-bottom: none; }
table.tbl td.strong { color: var(--ink) !important; font-weight: 600; }
table.tbl td.num { text-align: right; font-variant-numeric: tabular-nums; }

/* ---------- Journey ---------- */
.journey { display: grid; grid-template-columns: repeat(4, 1fr); gap: .5rem; margin: 0 0 1.2rem; }
.journey .step { background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
  padding: .6rem .8rem; box-shadow: var(--shadow); }
.journey .step .i { font-size: .68rem; font-weight: 700; color: var(--muted) !important; letter-spacing: .08em; text-transform: uppercase; }
.journey .step b { display: block; color: var(--ink2) !important; font-size: .9rem; font-weight: 620; }
.journey .step.done { border-color: color-mix(in srgb, var(--good) 45%, transparent); }
.journey .step.done .i { color: var(--good-ink) !important; }
.journey .step.now { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
.journey .step.now b { color: var(--ink) !important; }
@media (max-width: 760px) { .journey { grid-template-columns: repeat(2, 1fr); } }

/* ---------- Section heading ---------- */
.stage { display: flex; align-items: center; gap: .6rem; margin: .5rem 0 .6rem; }
.stage .n { font-size: .74rem; font-weight: 750; color: var(--accent-ink) !important; background: var(--accent-soft);
  border-radius: 7px; padding: .12rem .5rem; }
.stage .t { font-size: 1.12rem; font-weight: 650; color: var(--ink) !important; }

/* ---------- Privacy outcome ---------- */
.shield { border-radius: 16px; padding: 1.1rem 1.25rem; margin: .2rem 0 .9rem; background: var(--surface);
  border: 1px solid color-mix(in srgb, var(--good) 50%, transparent);
  box-shadow: inset 4px 0 0 var(--good), var(--shadow); }
.shield.fail { border-color: color-mix(in srgb, var(--critical) 55%, transparent);
  box-shadow: inset 4px 0 0 var(--critical), var(--shadow); }
.shield .title { font-size: 1.25rem; font-weight: 700; color: var(--ink) !important; }
.shield .detail { color: var(--ink2) !important; font-size: .9rem; margin-top: .4rem; line-height: 1.55; }
.shield .detail strong { color: var(--ink) !important; }
.shield .chips { margin-top: .55rem; }

/* ---------- Verdict ---------- */
.verdict { background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
  padding: 1.15rem 1.3rem; margin: .2rem 0 1rem; box-shadow: var(--shadow); }
.verdict .headline { font-size: 1.4rem; font-weight: 700; color: var(--ink) !important; letter-spacing: -.015em; }
.verdict .sub { color: var(--muted) !important; font-size: .82rem; margin: .1rem 0 .8rem; }
.verdict .row { display: flex; gap: .8rem; padding: .55rem 0; border-top: 1px solid var(--border);
  font-size: .93rem; line-height: 1.5; }
.verdict .row .rule { width: 3px; border-radius: 2px; flex: none; }
.verdict .row .k { color: var(--muted) !important; font-size: .7rem; letter-spacing: .1em; text-transform: uppercase; display: block; }
.verdict .row .v { color: var(--ink) !important; }
.verdict .row .v em { color: var(--ink2) !important; font-style: normal; }

/* ---------- Facts, signature ---------- */
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .6rem; margin: .3rem 0 1rem; }
.facts .f { border: 1px solid var(--border); border-radius: 12px; padding: .6rem .8rem; background: var(--surface); box-shadow: var(--shadow); }
.facts .k { color: var(--muted) !important; font-size: .7rem; letter-spacing: .08em; text-transform: uppercase; }
.facts .v { font-size: 1.1rem; font-weight: 650; margin-top: .15rem; color: var(--ink) !important; }
.sig-box { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; background: var(--surface2);
  border: 1px solid var(--border); border-left: 3px solid var(--accent); padding: .75rem .9rem;
  border-radius: 10px; word-break: break-word; line-height: 1.75; color: var(--ink2) !important; }

/* ---------- Consent ---------- */
.consent { display: grid; grid-template-columns: 1fr 1fr; gap: .8rem; margin: .4rem 0 1rem; }
.consent .col { border: 1px solid var(--border); border-radius: 14px; padding: .85rem 1rem; background: var(--surface); box-shadow: var(--shadow); }
.consent .col h4 { margin: 0 0 .45rem !important; font-size: .74rem !important; letter-spacing: .1em; text-transform: uppercase; padding: 0 !important; }
.consent .col.share h4 { color: var(--accent-ink) !important; }
.consent .col.keep h4 { color: var(--good-ink) !important; }
.consent ul { margin: 0; padding-left: 1.1rem; font-size: .88rem; line-height: 1.6; }
.consent li { color: var(--ink2) !important; }
@media (max-width: 760px) { .consent { grid-template-columns: 1fr; } }

/* ---------- Stacked composition bar ---------- */
.stack { display: flex; height: 10px; border-radius: 999px; overflow: hidden; margin: .6rem 0 .7rem; gap: 2px; }
.legend3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: .4rem; }
.legend3 .l { font-size: .76rem; color: var(--muted) !important; }
.legend3 .l i { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: .35rem; }
.legend3 .l b { display: block; font-size: 1.15rem; color: var(--ink) !important; font-weight: 700; }
"""


def style(mode: str) -> str:
    """The full stylesheet for one mode."""
    return (f"<style>.stApp, [data-testid='stSidebar'], [data-baseweb='popover'], "
            f"[data-testid='stSelectboxVirtualDropdown'] {{{_variables(mode)}}}"
            f"{_CSS}</style>")


# --------------------------------------------------------------------------
# Components
# --------------------------------------------------------------------------
def esc(value) -> str:
    return _html.escape("" if value is None else str(value))


def brand() -> str:
    return ('<div class="brand"><div class="mark">DNA</div><div><span class="name">ATTACKDNA</span>'
            '<span class="brand-sub">Privacy-first incident memory</span></div></div>')


def side_head(title: str) -> str:
    return f'<div class="side-head">{esc(title)}</div>'


def mini_stats(items: Sequence[tuple]) -> str:
    cells = "".join(f'<div class="c"><div class="k">{esc(k)}</div><div class="v">{esc(v)}</div></div>'
                    for k, v in items)
    return f'<div class="mini">{cells}</div>'


def page_head(title: str, subtitle: str = "", tags: Sequence[str] = ()) -> str:
    tag_html = "".join(f'<span class="tag">{t}</span>' for t in tags)
    sub = f"<p>{esc(subtitle)}</p>" if subtitle else ""
    return (f'<div class="pagehead"><div><h1>{esc(title)}</h1>{sub}</div>'
            f'<div class="meta">{tag_html}</div></div>')


def status_tag(text: str) -> str:
    return f'<span class="dot"></span>{esc(text)}'


def kpis(items: Sequence[dict]) -> str:
    """The key-figure strip. Each item: label, value, optional delta (+/-) and note."""
    cells = []
    for item in items:
        delta = ""
        if item.get("delta"):
            cls = "down" if str(item["delta"]).startswith("-") else "up"
            delta = f'<span class="d {cls}">{esc(item["delta"])}</span>'
        note = f'<div class="n">{esc(item["note"])}</div>' if item.get("note") else ""
        cells.append(f'<div class="kpi"><div class="k">{esc(item["label"])}</div>'
                     f'<div class="v">{esc(item["value"])}{delta}</div>{note}</div>')
    return f'<div class="kpis">{"".join(cells)}</div>'


def card_open(title: str, subtitle: str = "") -> str:
    sub = f'<div class="sub">{esc(subtitle)}</div>' if subtitle else ""
    return f'<div class="card"><h3>{esc(title)}</h3>{sub}'


def card(title: str, subtitle: str, body_html: str) -> str:
    return card_open(title, subtitle) + body_html + "</div>"


def pill(text: str, kind: str = "neutral") -> str:
    return f'<span class="pill pill-{kind}">{esc(text)}</span>'


def severity_pill(severity: Optional[str]) -> str:
    key = (severity or "unknown").lower()
    return pill(key.title(), SEVERITY_STATUS.get(key, "neutral"))


def provenance_pill(provenance: Optional[str], yours: bool = False) -> str:
    """Where a recalled incident came from — never shown without this.

    A shared incident says only whether it is the viewer's own. Which other
    organisation contributed it is exactly what the system does not know how
    to say.
    """
    if yours:
        return pill("Your organisation's incident", "neutral")
    key = (provenance or "internal").lower()
    label = {"public": "Real documented breach",
             "synthetic": "Synthetic training incident",
             "internal": "Internal incident",
             "shared": "Shared by another organisation · identity withheld"}.get(key, key.title())
    kind = {"public": "good", "shared": "accent", "synthetic": "serious"}.get(key, "neutral")
    return pill(label, kind)


def table(rows: List[dict], columns: Optional[List[str]] = None, *, html_columns: Iterable[str] = (),
          strong: Iterable[str] = (), numeric: Iterable[str] = ()) -> str:
    """A themed HTML table. Values are escaped unless the column is in html_columns."""
    if not rows:
        return ""
    columns = columns or list(rows[0].keys())
    html_columns, strong, numeric = set(html_columns), set(strong), set(numeric)
    head = "".join(f"<th>{esc(c)}</th>" for c in columns)
    body = []
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column, "")
            content = str(value) if column in html_columns else esc(value)
            classes = " ".join(c for c, on in (("strong", column in strong),
                                               ("num", column in numeric)) if on)
            cells.append(f'<td class="{classes}">{content}</td>')
        body.append(f"<tr>{''.join(cells)}</tr>")
    return (f'<div class="tbl-wrap"><table class="tbl"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def stage(number: str, title: str) -> str:
    return f'<div class="stage"><span class="n">{esc(number)}</span><span class="t">{esc(title)}</span></div>'


def journey(current: int, done: int = 0) -> str:
    """The four steps a security team goes through, with the current one lit."""
    steps = ["Attach report", "Remove identity", "Attack DNA & matches", "Share (optional)"]
    cells = []
    for index, title in enumerate(steps, start=1):
        state = "done" if index <= done else ("now" if index == current else "")
        label = "Done" if index <= done else f"Step {index}"
        cells.append(f'<div class="step {state}"><span class="i">{label}</span><b>{title}</b></div>')
    return f'<div class="journey">{"".join(cells)}</div>'


_CHIP_LABELS = {
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
    "REFERENCE": ("case reference", "case references"), "USER_PATH": ("user path", "user paths"),
}


def chips(counts: dict) -> str:
    """Removed identifier categories, as countable chips."""
    def name(kind: str, count: int) -> str:
        singular, plural = _CHIP_LABELS.get(kind, (kind.replace("_", " ").lower(),) * 2)
        return singular if count == 1 else plural

    parts = [f'<span class="chip"><strong>{count}</strong> {esc(name(kind, count))}</span>'
             for kind, count in sorted(counts.items(), key=lambda item: -item[1])]
    return f'<div class="chips">{"".join(parts)}</div>'


def facts(items) -> str:
    """A row of labelled values; long values wrap rather than being cut off.

    Values are trusted HTML (callers pass pills); labels are escaped.
    """
    cells = "".join(f'<div class="f"><div class="k">{esc(label)}</div><div class="v">{value}</div></div>'
                    for label, value in items)
    return f'<div class="facts">{cells}</div>'


def composition(parts: Sequence[tuple], mode: str) -> str:
    """A segmented bar with a legend, like a budget split: (label, count, token)."""
    colours = palette(mode)
    total = sum(count for _, count, _ in parts) or 1
    bar = "".join(f'<span style="flex:{count};background:{colours[token]}"></span>'
                  for _, count, token in parts if count)
    legend = "".join(f'<div class="l"><i style="background:{colours[token]}"></i>{esc(label)}'
                     f'<b>{count}</b>{count / total:.0%}</div>' for label, count, token in parts)
    return f'<div class="stack">{bar}</div><div class="legend3">{legend}</div>'
