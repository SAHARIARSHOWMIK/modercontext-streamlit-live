from __future__ import annotations

import html
import time

import streamlit as st
from streamlit_ace import st_ace

from inference import MODEL_PATH, ModerContextScanner

st.set_page_config(
    page_title="ModerContext | Vulnerability Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.html(
    r'''
<style>
:root {
  --mc-navy: #0b1739;
  --mc-blue: #2f6cf6;
  --mc-blue-2: #4d8dff;
  --mc-text: #5f6f89;
  --mc-muted: #8b98ac;
  --mc-line: #e2e8f2;
  --mc-soft: #f7f9fd;
  --mc-white: #ffffff;
  --mc-green: #168553;
  --mc-red: #d93d4d;
}

#MainMenu, footer,
[data-testid="stToolbar"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"] { display: none !important; }
header[data-testid="stHeader"] { height: 0 !important; background: transparent !important; }
[data-testid="stSidebar"] { display: none !important; }

html { scroll-behavior: smooth; }
html, body, [class*="css"] {
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
}

.stApp {
  background:
    radial-gradient(circle at 50% -9%, rgba(84, 142, 255, .13) 0, rgba(84, 142, 255, 0) 34%),
    #f7f9fc;
  color: var(--mc-navy);
}

.block-container {
  max-width: 1240px;
  padding-top: 1.35rem;
  padding-bottom: 4.5rem;
}

/* Top navigation */
.st-key-topbar { margin-bottom: 48px; }
.st-key-topbar [data-testid="stVerticalBlockBorderWrapper"] {
  background: rgba(255,255,255,.96) !important;
  border: 1px solid #e2e8f2 !important;
  border-radius: 20px !important;
  box-shadow: 0 14px 42px rgba(24, 45, 86, .07) !important;
  padding: 10px 15px !important;
}
.mc-brand {
  display:flex; align-items:center; gap:12px;
  min-height:48px;
  color:var(--mc-navy); font-size:22px; font-weight:850;
  letter-spacing:-.02em;
}
.mc-mark {
  width:42px; height:46px; display:grid; place-items:center;
  color:white; font-size:18px; font-weight:900;
  background:linear-gradient(145deg,#1e5dea,#4a94ff);
  clip-path:polygon(50% 0%,94% 17%,88% 72%,50% 100%,12% 72%,6% 17%);
  filter:drop-shadow(0 8px 14px rgba(47,108,246,.22));
}
.mc-pill-wrap { display:flex; justify-content:flex-end; align-items:center; min-height:48px; }
.mc-pill {
  display:inline-flex; align-items:center; justify-content:center;
  padding:9px 14px; border-radius:999px;
  color:#2457d8; background:#eef4ff; border:1px solid #d7e4ff;
  font-size:12px; font-weight:850; white-space:nowrap;
}

.st-key-nav_scanner button,
.st-key-nav_how button,
.st-key-nav_about button {
  width:100% !important;
  min-height:40px !important;
  border:0 !important;
  border-radius:10px !important;
  background:transparent !important;
  box-shadow:none !important;
  color:#60708e !important;
  font-weight:800 !important;
  padding:0 8px !important;
}
.st-key-nav_scanner button:hover,
.st-key-nav_how button:hover,
.st-key-nav_about button:hover {
  color:var(--mc-blue) !important;
  background:#f4f7ff !important;
}
.st-key-nav_scanner button[kind="primary"],
.st-key-nav_how button[kind="primary"],
.st-key-nav_about button[kind="primary"] {
  color:var(--mc-blue) !important;
  background:#eef4ff !important;
}

/* Typography */
.mc-eyebrow {
  color:var(--mc-blue); font-size:11px; font-weight:900;
  letter-spacing:.13em; text-transform:uppercase; margin-bottom:10px;
}
.mc-hero-title {
  max-width:900px; color:var(--mc-navy);
  font-size:clamp(38px,5vw,58px); line-height:1.03;
  letter-spacing:-.052em; font-weight:850;
}
.mc-hero-title b { color:var(--mc-blue); }
.mc-hero-copy {
  max-width:815px; margin:18px 0 35px;
  color:#6c7890; font-size:17px; line-height:1.75;
}
.mc-section-head { margin:12px 0 26px; }
.mc-section-title {
  color:var(--mc-navy); font-size:clamp(31px,4vw,44px);
  line-height:1.08; letter-spacing:-.04em; font-weight:850;
}
.mc-section-copy {
  max-width:760px; margin-top:12px; color:#6c7890;
  font-size:16px; line-height:1.75;
}

/* Cards */
[data-testid="stVerticalBlockBorderWrapper"] {
  border-radius:19px !important;
  border-color:var(--mc-line) !important;
  background:#fff !important;
}
.st-key-scanner_input [data-testid="stVerticalBlockBorderWrapper"],
.st-key-scanner_output [data-testid="stVerticalBlockBorderWrapper"] {
  box-shadow:0 18px 55px rgba(25,42,78,.065) !important;
}
.panel-kicker {
  color:var(--mc-blue); font-size:10px; font-weight:900;
  letter-spacing:.11em; text-transform:uppercase;
}
.panel-title {
  margin-top:5px; color:var(--mc-navy); font-size:22px; font-weight:850;
  letter-spacing:-.02em;
}
.panel-copy { margin-top:5px; color:#7b879a; font-size:12px; line-height:1.6; }

/* Editor and action buttons */
iframe[title="streamlit_ace.st_ace"] { border-radius:14px !important; }
.st-key-analyze button {
  min-height:50px !important; border:0 !important; border-radius:12px !important;
  color:#fff !important;
  background:linear-gradient(135deg,#2b63ef,#3885ff) !important;
  box-shadow:0 11px 25px rgba(47,108,246,.22) !important;
  font-weight:850 !important;
}
.st-key-clear button, .st-key-another button {
  min-height:50px !important; border-radius:12px !important;
  border:1px solid #dce3ee !important; background:#fff !important;
  color:#43516b !important; box-shadow:none !important; font-weight:800 !important;
}
.st-key-clear button:hover, .st-key-another button:hover {
  border-color:#b9caea !important; color:var(--mc-blue) !important; background:#f8faff !important;
}
.mc-note { color:#7f8b9f; font-size:12px; margin-top:2px; }

/* Ready / progress */
.ready {
  min-height:468px; display:flex; flex-direction:column; align-items:center;
  justify-content:center; text-align:center; padding:36px;
}
.ready-icon {
  width:72px; height:72px; display:grid; place-items:center; border-radius:21px;
  background:#eef4ff; color:var(--mc-blue); font-size:29px; margin-bottom:18px;
}
.ready h2 { margin:6px 0 0; color:var(--mc-navy); font-size:27px; letter-spacing:-.03em; }
.ready p { max-width:390px; color:#6d7890; line-height:1.75; font-size:14px; }
.scan-title { color:var(--mc-navy); font-size:23px; font-weight:850; letter-spacing:-.02em; }
.scan-copy { color:#6d7890; font-size:13px; margin:5px 0 19px; line-height:1.6; }
div[data-testid="stProgress"] > div > div > div { background:linear-gradient(90deg,#2f6cf6,#63a3ff); }
.stage-row { display:flex; gap:13px; margin:17px 0; }
.stage-dot {
  width:28px; height:28px; flex:0 0 28px; display:grid; place-items:center;
  border-radius:50%; font-size:11px; font-weight:900;
}
.done { background:#dcfce7; color:#15803d; }
.active { background:#dbe7ff; color:#1e55d9; box-shadow:0 0 0 5px #f1f6ff; }
.wait { background:#f1f5f9; color:#94a3b8; }
.stage-name { color:#263650; font-size:14px; font-weight:800; }
.stage-desc { margin-top:2px; color:#8994a7; font-size:12px; }

/* Result */
.result { padding:18px 5px 8px; min-height:438px; }
.result-icon {
  width:68px; height:68px; display:grid; place-items:center;
  border-radius:20px; font-size:30px; font-weight:900; margin-bottom:20px;
}
.r-safe { background:#effcf4; color:var(--mc-green); }
.r-vuln { background:#fff1f2; color:var(--mc-red); }
.result-kicker { font-size:11px; font-weight:900; letter-spacing:.11em; text-transform:uppercase; }
.k-safe { color:var(--mc-green); }
.k-vuln { color:var(--mc-red); }
.result h2 {
  margin:7px 0 10px; color:var(--mc-navy); font-size:30px;
  line-height:1.12; letter-spacing:-.035em;
}
.result p { color:#6d7890; line-height:1.75; font-size:14px; max-width:500px; }
.meta {
  display:grid; grid-template-columns:repeat(3,1fr); gap:10px;
  margin-top:27px; padding-top:22px; border-top:1px solid #e4eaf2;
}
.meta-box { background:#f8faff; border-radius:12px; padding:13px; }
.meta-box span {
  display:block; color:#909caf; font-size:9px; font-weight:900;
  letter-spacing:.09em; text-transform:uppercase;
}
.meta-box b {
  display:block; margin-top:5px; color:#293750; font-size:12px;
  overflow-wrap:anywhere;
}

/* How to use */
.step-card { min-height:205px; padding:10px 4px 6px; }
.step-num {
  width:38px; height:38px; display:grid; place-items:center;
  border-radius:11px; background:#eef4ff; color:var(--mc-blue);
  font-size:11px; font-weight:900;
}
.step-title { margin-top:25px; color:var(--mc-navy); font-size:18px; font-weight:850; }
.step-copy { margin-top:8px; color:#6d7890; font-size:13px; line-height:1.75; }
.tip-card { padding:5px 4px; }
.tip-title { color:var(--mc-navy); font-size:16px; font-weight:850; }
.tip-copy { margin-top:7px; color:#6d7890; font-size:13px; line-height:1.75; }

/* About */
.about-card { padding:8px 4px; }
.about-card h3 { margin:0 0 10px; color:var(--mc-navy); font-size:22px; letter-spacing:-.02em; }
.about-card p { margin:0; color:#61708a; font-size:14px; line-height:1.85; }
.about-mini { min-height:170px; padding:7px 4px; }
.about-mini-icon {
  width:38px; height:38px; display:grid; place-items:center; border-radius:11px;
  background:#eef4ff; color:var(--mc-blue); font-weight:900; margin-bottom:18px;
}
.about-mini-title { color:var(--mc-navy); font-size:16px; font-weight:850; }
.about-mini-copy { margin-top:7px; color:#6d7890; font-size:13px; line-height:1.72; }

/* Footer */
.mc-footer {
  margin-top:72px; padding-top:22px; border-top:1px solid #e2e8f2;
  display:flex; justify-content:space-between; gap:20px;
  color:#8a96a9; font-size:11px;
}

@media(max-width: 900px) {
  .block-container { padding-left:1rem; padding-right:1rem; }
  .mc-pill-wrap { display:none; }
  .mc-hero-title { font-size:38px; }
  .meta { grid-template-columns:1fr; }
}

/* SENIOR_NAV_POLISH_V1 */

/* ---------- Streamlit chrome ---------- */
[data-testid="stToolbar"] {
    display: none !important;
}

#MainMenu {
    visibility: hidden !important;
}

footer {
    visibility: hidden !important;
}

/* ---------- Main navbar ---------- */
.st-key-mc_nav {
    margin-top: 4px !important;
    margin-bottom: 30px !important;
}

/* Border container */
.st-key-mc_nav [data-testid="stVerticalBlockBorderWrapper"] {
    background: rgba(255,255,255,0.98) !important;
    border: 1px solid #e5eaf2 !important;
    border-radius: 18px !important;

    padding: 8px 16px !important;

    box-shadow:
        0 1px 2px rgba(15,23,42,0.02),
        0 8px 24px rgba(15,23,42,0.045) !important;
}

/* Remove unnecessary vertical spacing */
.st-key-mc_nav [data-testid="stVerticalBlock"] {
    gap: 0 !important;
}

/* ---------- Brand ---------- */
.mc-brand {
    display: flex !important;
    align-items: center !important;
    gap: 12px !important;

    color: #0b1739 !important;
    font-size: 21px !important;
    font-weight: 800 !important;
    letter-spacing: -0.025em !important;
    white-space: nowrap !important;
}

.mc-mark {
    width: 36px !important;
    height: 40px !important;

    display: grid !important;
    place-items: center !important;

    font-size: 17px !important;
    font-weight: 850 !important;
}

/* ---------- Navigation ---------- */
.st-key-nav_scanner,
.st-key-nav_how,
.st-key-nav_about {
    display: flex !important;
    justify-content: center !important;
}

.st-key-nav_scanner button,
.st-key-nav_how button,
.st-key-nav_about button {
    min-height: 38px !important;
    height: 38px !important;

    width: auto !important;
    min-width: auto !important;

    padding: 0 14px !important;

    border: 0 !important;
    border-radius: 8px !important;

    background: transparent !important;

    color: #64748b !important;

    font-size: 14px !important;
    font-weight: 650 !important;
    letter-spacing: -0.01em !important;

    box-shadow: none !important;

    transition:
        background-color .16s ease,
        color .16s ease !important;
}

/* Hover */
.st-key-nav_scanner button:hover,
.st-key-nav_how button:hover,
.st-key-nav_about button:hover {
    background: #f6f8fc !important;
    color: #1e5fe5 !important;
}

/* Active page */
.st-key-nav_scanner button[kind="primary"],
.st-key-nav_how button[kind="primary"],
.st-key-nav_about button[kind="primary"] {
    background: transparent !important;
    color: #2563eb !important;

    border-radius: 0 !important;

    box-shadow:
        inset 0 -2px 0 #2563eb !important;

    font-weight: 750 !important;
}

/* Remove focus ring visual noise */
.st-key-nav_scanner button:focus,
.st-key-nav_how button:focus,
.st-key-nav_about button:focus {
    outline: none !important;
    box-shadow: none !important;
}

.st-key-nav_scanner button[kind="primary"]:focus,
.st-key-nav_how button[kind="primary"]:focus,
.st-key-nav_about button[kind="primary"]:focus {
    box-shadow:
        inset 0 -2px 0 #2563eb !important;
}

/* ---------- Research badge ---------- */
.mc-pill {
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;

    padding: 7px 12px !important;

    border: 1px solid #dce7fb !important;
    border-radius: 999px !important;

    background: #f7faff !important;

    color: #245bd7 !important;

    font-size: 11px !important;
    font-weight: 750 !important;
    letter-spacing: .01em !important;

    white-space: nowrap !important;
}

/* ---------- Mobile ---------- */
@media (max-width: 850px) {

    .st-key-mc_nav [data-testid="stVerticalBlockBorderWrapper"] {
        padding: 10px 12px !important;
    }

    .mc-brand {
        font-size: 18px !important;
    }

    .mc-mark {
        width: 32px !important;
        height: 36px !important;
    }

    .st-key-nav_scanner button,
    .st-key-nav_how button,
    .st-key-nav_about button {
        font-size: 13px !important;
        padding: 0 9px !important;
    }

    .mc-pill {
        font-size: 10px !important;
        padding: 6px 9px !important;
    }
}


/* MODERCONTEXT_HEADER_V2 */

/* =========================================
   HEADER CONTAINER
   ========================================= */

.st-key-mc_nav {
    width: calc(100% - 40px) !important;
    max-width: 1200px !important;

    margin-left: auto !important;
    margin-right: auto !important;
    margin-top: 8px !important;
    margin-bottom: 34px !important;
}

/* Main white navbar card */
.st-key-mc_nav [data-testid="stVerticalBlockBorderWrapper"] {
    width: 100% !important;

    background: rgba(255, 255, 255, 0.98) !important;

    border: 1px solid #e2e8f0 !important;
    border-radius: 18px !important;

    padding: 10px 18px !important;

    box-shadow:
        0 1px 2px rgba(15, 23, 42, 0.02),
        0 8px 28px rgba(15, 23, 42, 0.045) !important;
}


/* =========================================
   LOGO / BRAND
   ========================================= */

.mc-brand {
    display: flex !important;
    align-items: center !important;

    gap: 13px !important;

    font-size: 25px !important;
    line-height: 1 !important;

    font-weight: 800 !important;
    letter-spacing: -0.035em !important;

    color: #0b1739 !important;

    white-space: nowrap !important;
}

.mc-mark {
    width: 40px !important;
    height: 44px !important;

    display: grid !important;
    place-items: center !important;

    font-size: 19px !important;
    font-weight: 850 !important;
}


/* =========================================
   NAVIGATION
   ========================================= */

.st-key-nav_scanner,
.st-key-nav_how,
.st-key-nav_about {
    display: flex !important;
    justify-content: center !important;
    align-items: center !important;
}

/* Normal navigation item */
.st-key-nav_scanner button,
.st-key-nav_how button,
.st-key-nav_about button {
    width: auto !important;
    min-width: auto !important;

    height: 44px !important;
    min-height: 44px !important;

    padding: 0 16px !important;

    background: transparent !important;

    border: none !important;
    border-radius: 0 !important;

    color: #64748b !important;

    font-size: 17.5px !important;
    line-height: 1 !important;

    font-weight: 550 !important;
    letter-spacing: -0.015em !important;

    white-space: nowrap !important;

    box-shadow: none !important;

    transition:
        color 0.16s ease,
        background-color 0.16s ease !important;
}

/* Hover */
.st-key-nav_scanner button:hover,
.st-key-nav_how button:hover,
.st-key-nav_about button:hover {
    color: #2563eb !important;
    background: transparent !important;
}

/* Active navigation item */
.st-key-nav_scanner button[kind="primary"],
.st-key-nav_how button[kind="primary"],
.st-key-nav_about button[kind="primary"] {
    color: #2563eb !important;

    font-weight: 750 !important;

    background: transparent !important;

    border: none !important;

    box-shadow:
        inset 0 -3px 0 #2563eb !important;
}

/* Remove Streamlit focus decoration */
.st-key-nav_scanner button:focus,
.st-key-nav_how button:focus,
.st-key-nav_about button:focus {
    outline: none !important;
}

.st-key-nav_scanner button[kind="primary"]:focus,
.st-key-nav_how button[kind="primary"]:focus,
.st-key-nav_about button[kind="primary"]:focus {
    box-shadow:
        inset 0 -3px 0 #2563eb !important;
}


/* =========================================
   RESEARCH PROTOTYPE BADGE
   ========================================= */

.mc-pill {
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;

    padding: 9px 15px !important;

    border: 1px solid #d8e5ff !important;
    border-radius: 999px !important;

    background: #f4f8ff !important;

    color: #245bd7 !important;

    font-size: 13.5px !important;
    line-height: 1 !important;

    font-weight: 700 !important;
    letter-spacing: -0.005em !important;

    white-space: nowrap !important;
}


/* =========================================
   RESPONSIVENESS
   ========================================= */

@media (max-width: 1050px) {

    .st-key-mc_nav {
        width: calc(100% - 28px) !important;
    }

    .mc-brand {
        font-size: 22px !important;
    }

    .mc-mark {
        width: 37px !important;
        height: 41px !important;
        font-size: 17px !important;
    }

    .st-key-nav_scanner button,
    .st-key-nav_how button,
    .st-key-nav_about button {
        font-size: 16px !important;
        padding: 0 11px !important;
    }

    .mc-pill {
        font-size: 12px !important;
        padding: 8px 11px !important;
    }
}


@media (max-width: 800px) {

    .st-key-mc_nav {
        width: calc(100% - 20px) !important;
    }

    .st-key-mc_nav [data-testid="stVerticalBlockBorderWrapper"] {
        padding: 10px 12px !important;
    }

    /* Allow Streamlit header columns to wrap instead of overflow */
    .st-key-mc_nav [data-testid="stHorizontalBlock"] {
        flex-wrap: wrap !important;
        row-gap: 8px !important;
    }

    .mc-brand {
        font-size: 20px !important;
    }

    .st-key-nav_scanner button,
    .st-key-nav_how button,
    .st-key-nav_about button {
        height: 38px !important;
        min-height: 38px !important;

        font-size: 15px !important;
        padding: 0 9px !important;
    }

    .mc-pill {
        font-size: 11.5px !important;
    }
}


@media (max-width: 520px) {

    .st-key-mc_nav {
        width: calc(100% - 14px) !important;
    }

    .mc-brand {
        font-size: 19px !important;
    }

    .mc-mark {
        width: 34px !important;
        height: 38px !important;
    }

    .st-key-nav_scanner button,
    .st-key-nav_how button,
    .st-key-nav_about button {
        font-size: 14px !important;
        padding: 0 7px !important;
    }

    .mc-pill {
        font-size: 10.5px !important;
        padding: 7px 9px !important;
    }
}

</style>
'''
)

# ---------- State ----------
if "view" not in st.session_state:
    st.session_state.view = "Scanner"
if "code" not in st.session_state:
    st.session_state.code = r'''void process_input(const char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Processed: %s\n", buffer);
}'''
if "result" not in st.session_state:
    st.session_state.result = None
if "editor_key" not in st.session_state:
    st.session_state.editor_key = 0


def go_to(view: str) -> None:
    st.session_state.view = view


# ---------- Top bar ----------
with st.container(border=True, key="topbar"):
    brand_col, nav_col, pill_col = st.columns([1.55, 1.35, .75], vertical_alignment="center")

    with brand_col:
        st.html('<div class="mc-brand"><div class="mc-mark">M</div><span>ModerContext</span></div>')

    with nav_col:
        n1, n2, n3 = st.columns(3, gap="small")
        with n1:
            st.button(
                "Scanner",
                key="nav_scanner",
                type="primary" if st.session_state.view == "Scanner" else "tertiary",
                use_container_width=True,
                on_click=go_to,
                args=("Scanner",),
            )
        with n2:
            st.button(
                "How to use",
                key="nav_how",
                type="primary" if st.session_state.view == "How to use" else "tertiary",
                use_container_width=True,
                on_click=go_to,
                args=("How to use",),
            )
        with n3:
            st.button(
                "About",
                key="nav_about",
                type="primary" if st.session_state.view == "About" else "tertiary",
                use_container_width=True,
                on_click=go_to,
                args=("About",),
            )

    with pill_col:
        st.html('<div class="mc-pill-wrap"><div class="mc-pill">Research Prototype</div></div>')


@st.cache_resource(show_spinner=False)
def get_scanner():
    return ModerContextScanner()


STAGES = [
    ("validate", "Validating source code", "Checking the submitted function"),
    ("prepare", "Pre-processing code", "Preparing the function for analysis"),
    ("context", "Analyzing code context", "Examining security-relevant patterns"),
    ("detect", "Detecting vulnerabilities", "Running the trained detection system"),
    ("finalize", "Finalizing result", "Preparing the detection result"),
]
INDEX = {x[0]: i for i, x in enumerate(STAGES)}


def stages_html(current: str) -> str:
    cur = INDEX.get(current, 0)
    rows = []
    for i, (_, name, desc) in enumerate(STAGES):
        if i < cur:
            cls, mark = "done", "✓"
        elif i == cur:
            cls, mark = "active", "•"
        else:
            cls, mark = "wait", "•"
        rows.append(
            f'<div class="stage-row">'
            f'<div class="stage-dot {cls}">{mark}</div>'
            f'<div><div class="stage-name">{html.escape(name)}</div>'
            f'<div class="stage-desc">{html.escape(desc)}</div></div></div>'
        )
    return "".join(rows)


def friendly_language(value) -> str:
    v = str(value or "").lower()
    if v in {"cpp", "c++", "cplusplus"}:
        return "C++"
    if v == "c":
        return "C"
    return "C/C++"


def result_html(result: dict) -> str:
    vulnerable = result.get("prediction_label") == "VULNERABLE"
    if vulnerable:
        icon = "!"
        icon_class = "r-vuln"
        kicker_class = "k-vuln"
        kicker = "Vulnerability detected"
        title = "Potential vulnerability detected"
        copy = (
            "ModerContext detected patterns associated with vulnerable code in the submitted "
            "function. Review this function before deployment or use in a security-sensitive environment."
        )
    else:
        icon = "✓"
        icon_class = "r-safe"
        kicker_class = "k-safe"
        kicker = "Analysis complete"
        title = "No vulnerability detected"
        copy = (
            "ModerContext did not detect vulnerability-related patterns in the submitted function. "
            "This result supports secure code review and should not be interpreted as an absolute guarantee of security."
        )

    lang = html.escape(friendly_language(result.get("language_name")))
    fn = html.escape(str(result.get("function_name") or "Unknown"))
    sec = html.escape(str(result.get("analysis_seconds", "—")))

    return f'''
<div class="result">
  <div class="result-icon {icon_class}">{icon}</div>
  <div class="result-kicker {kicker_class}">{kicker}</div>
  <h2>{title}</h2>
  <p>{copy}</p>
  <div class="meta">
    <div class="meta-box"><span>Language</span><b>{lang}</b></div>
    <div class="meta-box"><span>Function</span><b>{fn}</b></div>
    <div class="meta-box"><span>Analysis time</span><b>{sec} sec</b></div>
  </div>
</div>
'''


# ---------- Scanner view ----------
if st.session_state.view == "Scanner":
    st.html(
        '''
<div class="mc-eyebrow">Source Code Security Scanner</div>
<div class="mc-hero-title">Analyze C/C++ code for <b>potential vulnerabilities</b></div>
<div class="mc-hero-copy">
  Submit one C or C++ function and ModerContext will process the source code,
  analyze its security-relevant context, and return a clear vulnerability detection result.
</div>
'''
    )

    left, right = st.columns([1.08, .92], gap="large")

    with left:
        with st.container(border=True, key="scanner_input"):
            st.html(
                '<div class="panel-kicker">Input</div>'
                '<div class="panel-title">Source code</div>'
                '<div class="panel-copy">Paste one C or C++ function at a time.</div>'
            )

            code_value = st_ace(
                value=st.session_state.code,
                language="c_cpp",
                theme="github",
                keybinding="vscode",
                font_size=14,
                tab_size=4,
                show_gutter=True,
                show_print_margin=False,
                wrap=False,
                auto_update=True,
                min_lines=22,
                max_lines=30,
                key=f"editor_{st.session_state.editor_key}",
            )
            if code_value is not None:
                st.session_state.code = code_value

            analyze_col, clear_col = st.columns([4, 1.15])
            with analyze_col:
                analyze = st.button(
                    "▶  Analyze code",
                    key="analyze",
                    type="primary",
                    use_container_width=True,
                )
            with clear_col:
                clear = st.button("Clear", key="clear", use_container_width=True)

            st.html('<div class="mc-note">Predictions are intended to support secure code review.</div>')

        if clear:
            st.session_state.code = ""
            st.session_state.result = None
            st.session_state.editor_key += 1
            st.rerun()

    with right:
        with st.container(border=True, key="scanner_output"):
            if not MODEL_PATH.exists():
                st.html(
                    '<div class="ready">'
                    '<div class="ready-icon">⚙</div>'
                    '<div class="panel-kicker">Setup required</div>'
                    '<h2>Model file required</h2>'
                    '<p>Place the trained checkpoint at <b>model/best_model.pt</b>. '
                    'ModerContext will use that file automatically.</p>'
                    '</div>'
                )
            elif analyze:
                source = (st.session_state.code or "").strip()
                if not source:
                    st.warning("Please paste a C or C++ function first.")
                else:
                    st.html(
                        '<div class="scan-title">Analyzing your function</div>'
                        '<div class="scan-copy">Please wait while ModerContext processes the submitted code.</div>'
                    )
                    progress = st.progress(3, text="Preparing the analyzer...")
                    stage_box = st.empty()
                    stage_box.html(stages_html("validate"))

                    try:
                        scanner = get_scanner()

                        def update(stage, percent, message):
                            progress.progress(int(percent), text=str(message))
                            if stage in INDEX:
                                stage_box.html(stages_html(stage))

                        st.session_state.result = scanner.analyze(source, progress_callback=update)
                        time.sleep(.2)
                        st.rerun()
                    except Exception as exc:
                        st.error("ModerContext could not analyze the submitted function.")
                        with st.expander("Technical details"):
                            st.exception(exc)

            elif st.session_state.result is not None:
                st.html(result_html(st.session_state.result))
                if st.button("↻  Analyze another function", key="another", use_container_width=True):
                    st.session_state.result = None
                    st.rerun()
            else:
                st.html(
                    '<div class="ready">'
                    '<div class="ready-icon">⌕</div>'
                    '<div class="panel-kicker">Scanner ready</div>'
                    '<h2>Ready to analyze</h2>'
                    '<p>Paste a C or C++ function in the editor and select '
                    '<b>Analyze code</b> to begin.</p>'
                    '</div>'
                )


# ---------- How-to view ----------
elif st.session_state.view == "How to use":
    st.html(
        '''
<div class="mc-section-head">
  <div class="mc-eyebrow">Simple workflow</div>
  <div class="mc-section-title">How to use ModerContext</div>
  <div class="mc-section-copy">
    The scanner keeps the research implementation behind a simple user-facing workflow.
    You only need to provide one C or C++ function and review the returned detection result.
  </div>
</div>
'''
    )

    steps = [
        ("01", "Paste your function", "Copy one complete C or C++ function into the source-code editor."),
        ("02", "Run the analysis", "Select Analyze code and allow ModerContext to process and evaluate the function."),
        ("03", "Review the result", "Review the vulnerability detection outcome together with the function and analysis details."),
    ]

    cols = st.columns(3, gap="medium")
    for col, (num, title, copy) in zip(cols, steps):
        with col:
            with st.container(border=True):
                st.html(
                    f'<div class="step-card"><div class="step-num">{num}</div>'
                    f'<div class="step-title">{html.escape(title)}</div>'
                    f'<div class="step-copy">{html.escape(copy)}</div></div>'
                )

    st.write("")
    info_left, info_right = st.columns(2, gap="medium")
    with info_left:
        with st.container(border=True):
            st.html(
                '<div class="tip-card"><div class="tip-title">What should I submit?</div>'
                '<div class="tip-copy">Submit one function rather than an entire project or source file. '
                'The prototype is designed for C/C++ function-level vulnerability detection.</div></div>'
            )
    with info_right:
        with st.container(border=True):
            st.html(
                '<div class="tip-card"><div class="tip-title">How should I interpret the result?</div>'
                '<div class="tip-copy">Use the prediction as decision support for secure code review. '
                'A SAFE result is not an absolute guarantee that the function contains no security issue.</div></div>'
            )

    st.write("")
    if st.button("Open scanner", type="primary", use_container_width=False):
        go_to("Scanner")
        st.rerun()


# ---------- About view ----------
else:
    st.html(
        '''
<div class="mc-section-head">
  <div class="mc-eyebrow">About the prototype</div>
  <div class="mc-section-title">ModerContext</div>
  <div class="mc-section-copy">
    A research prototype demonstrating practical source code vulnerability detection for C/C++ functions.
  </div>
</div>
'''
    )

    with st.container(border=True):
        st.html(
            '''
<div class="about-card">
  <h3>Research implementation</h3>
  <p>
    ModerContext is a master's research prototype for source code vulnerability detection.
    It applies the proposed context-aware processing methodology and a trained long-context
    classifier to C/C++ functions. The web application demonstrates how the research approach
    can be used as a practical input-to-prediction security analysis workflow.
  </p>
</div>
'''
        )

    st.write("")
    a1, a2, a3 = st.columns(3, gap="medium")
    about_items = [
        ("01", "Purpose", "Demonstrate the proposed vulnerability detection approach through a usable web interface."),
        ("02", "Scope", "Analyze one C or C++ function at a time and return a clear SAFE or VULNERABLE outcome."),
        ("03", "Use", "Support secure code review rather than replace professional security assessment or verification."),
    ]
    for col, (icon, title, copy) in zip((a1, a2, a3), about_items):
        with col:
            with st.container(border=True):
                st.html(
                    f'<div class="about-mini"><div class="about-mini-icon">{icon}</div>'
                    f'<div class="about-mini-title">{html.escape(title)}</div>'
                    f'<div class="about-mini-copy">{html.escape(copy)}</div></div>'
                )

    st.write("")
    if st.button("Open scanner", type="primary", use_container_width=False, key="about_open_scanner"):
        go_to("Scanner")
        st.rerun()


st.html(
    '<div class="mc-footer"><span>ModerContext · Source Code Vulnerability Detection</span>'
    '<span>Research Prototype</span></div>'
)
