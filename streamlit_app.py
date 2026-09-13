from __future__ import annotations

import html
import time

import streamlit as st
from streamlit_ace import st_ace

from inference import MODEL_PATH, ModerContextScanner

st.set_page_config(page_title="ModerContext | Vulnerability Detection", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

st.html('''
<style>
#MainMenu, footer { visibility: hidden; }
[data-testid="stSidebar"] { display: none; }
[data-testid="stHeader"] { background: transparent; }
.block-container { max-width: 1220px; padding-top: 1rem; padding-bottom: 5rem; }
.stApp { background: radial-gradient(circle at 50% -8%, #eef5ff 0, transparent 35%), #f7f9fc; color: #12203c; }
html, body, [class*="css"] { font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
.mc-nav { min-height:72px; display:flex; align-items:center; justify-content:space-between; padding:0 22px; margin-bottom:48px; border:1px solid #e3e9f2; border-radius:17px; background:rgba(255,255,255,.96); box-shadow:0 10px 34px rgba(25,42,78,.06); }
.mc-brand { display:flex; align-items:center; gap:11px; font-size:20px; font-weight:800; color:#0b1739; }
.mc-mark { width:38px; height:42px; display:grid; place-items:center; color:white; font-weight:850; background:linear-gradient(145deg,#1f5deb,#4992ff); clip-path:polygon(50% 0%,94% 17%,88% 72%,50% 100%,12% 72%,6% 17%); }
.mc-links { display:flex; gap:30px; font-size:14px; font-weight:700; color:#60708e; } .mc-links span:first-child { color:#2f6cf6; }
.mc-pill { padding:8px 13px; border-radius:999px; color:#1e55d9; background:#eef4ff; border:1px solid #d8e5ff; font-size:12px; font-weight:800; }
.eyebrow { color:#2f6cf6; font-size:11px; font-weight:850; letter-spacing:.12em; text-transform:uppercase; margin-bottom:10px; }
.hero-title { max-width:900px; color:#0b1739; font-size:clamp(38px,5vw,56px); line-height:1.04; letter-spacing:-.05em; font-weight:800; } .hero-title b { color:#2f6cf6; }
.hero-copy { max-width:790px; margin:18px 0 36px; color:#6d7890; font-size:17px; line-height:1.7; }
[data-testid="stVerticalBlockBorderWrapper"] { border-radius:18px!important; border-color:#e1e7f0!important; background:white!important; box-shadow:0 18px 55px rgba(25,42,78,.06); }
.panel-kicker { color:#2f6cf6; font-size:10px; font-weight:850; letter-spacing:.1em; text-transform:uppercase; } .panel-title { margin-top:5px; color:#0b1739; font-size:21px; font-weight:800; } .panel-copy { margin-top:5px; color:#7a869b; font-size:12px; }
.stButton>button { min-height:48px; border-radius:11px; font-weight:800; } .stButton>button[kind="primary"] { border:none; color:white; background:linear-gradient(135deg,#2c64ef,#3783ff); box-shadow:0 10px 24px rgba(47,108,246,.22); }
.ready { min-height:472px; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; padding:35px; } .ready-icon { width:72px; height:72px; display:grid; place-items:center; border-radius:20px; background:#eef4ff; color:#2f6cf6; font-size:31px; margin-bottom:18px; } .ready h2 { margin:0; color:#0b1739; font-size:26px; } .ready p { max-width:380px; color:#6d7890; line-height:1.7; font-size:14px; }
.scan-title { color:#0b1739; font-size:22px; font-weight:800; } .scan-copy { color:#6d7890; font-size:13px; margin:5px 0 20px; } div[data-testid="stProgress"] > div > div > div { background:linear-gradient(90deg,#2f6cf6,#63a3ff); }
.stage-row { display:flex; gap:13px; margin:17px 0; } .stage-dot { width:27px; height:27px; flex:0 0 27px; display:grid; place-items:center; border-radius:50%; font-size:11px; font-weight:900; } .done { background:#dcfce7; color:#15803d; } .active { background:#dbe7ff; color:#1e55d9; box-shadow:0 0 0 5px #f1f6ff; } .wait { background:#f1f5f9; color:#94a3b8; } .stage-name { color:#263650; font-size:14px; font-weight:750; } .stage-desc { margin-top:2px; color:#8994a7; font-size:12px; }
.result { padding:16px 5px 8px; min-height:440px; } .result-icon { width:68px; height:68px; display:grid; place-items:center; border-radius:19px; font-size:31px; font-weight:900; margin-bottom:20px; } .r-safe { background:#effcf4; color:#15803d; } .r-vuln { background:#fff1f2; color:#d62f3c; } .result-kicker { font-size:11px; font-weight:850; letter-spacing:.1em; text-transform:uppercase; } .k-safe { color:#15803d; } .k-vuln { color:#d62f3c; } .result h2 { margin:7px 0 10px; color:#0b1739; font-size:28px; letter-spacing:-.03em; } .result p { color:#6d7890; line-height:1.75; font-size:14px; max-width:500px; }
.meta { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-top:26px; padding-top:22px; border-top:1px solid #e4eaf2; } .meta-box { background:#f8faff; border-radius:11px; padding:13px; } .meta-box span { display:block; color:#909caf; font-size:9px; font-weight:850; letter-spacing:.08em; text-transform:uppercase; } .meta-box b { display:block; margin-top:5px; color:#293750; font-size:12px; overflow-wrap:anywhere; }
.lower { margin-top:88px; } .lower-title { text-align:center; color:#0b1739; font-size:31px; font-weight:800; letter-spacing:-.03em; } .guide-num { color:#2f6cf6; font-size:11px; font-weight:900; letter-spacing:.1em; } .guide-title { margin-top:18px; color:#0b1739; font-size:17px; font-weight:800; } .guide-copy { margin-top:7px; color:#6d7890; font-size:13px; line-height:1.7; } .about { color:#5c6a82; line-height:1.8; font-size:14px; }
@media(max-width:850px){ .mc-links{display:none}.mc-pill{display:none}.meta{grid-template-columns:1fr}.hero-title{font-size:36px} }
</style>
''')

st.html('''<div class="mc-nav"><div class="mc-brand"><div class="mc-mark">M</div><span>ModerContext</span></div><div class="mc-links"><span>Scanner</span><span>How to use</span><span>About</span></div><div class="mc-pill">Research Prototype</div></div><div class="eyebrow">Source Code Security Scanner</div><div class="hero-title">Analyze C/C++ code for <b>potential vulnerabilities</b></div><div class="hero-copy">Submit one C or C++ function and ModerContext will process the source code, analyze its security-relevant context, and return a clear vulnerability detection result.</div>''')

DEFAULT_CODE = '''void process_input(const char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Processed: %s\n", buffer);
}'''

if "code" not in st.session_state: st.session_state.code = DEFAULT_CODE
if "result" not in st.session_state: st.session_state.result = None
if "editor_key" not in st.session_state: st.session_state.editor_key = 0

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

def stages_html(current):
    cur = INDEX.get(current, 0)
    out = []
    for i, (_, name, desc) in enumerate(STAGES):
        cls, mark = ("done", "✓") if i < cur else (("active", "•") if i == cur else ("wait", "•"))
        out.append(f'<div class="stage-row"><div class="stage-dot {cls}">{mark}</div><div><div class="stage-name">{html.escape(name)}</div><div class="stage-desc">{html.escape(desc)}</div></div></div>')
    return "".join(out)

def friendly_language(value):
    v = str(value or "").lower()
    if v in {"cpp", "c++", "cplusplus"}: return "C++"
    if v == "c": return "C"
    return "C/C++"

def result_html(result):
    vuln = result["prediction_label"] == "VULNERABLE"
    if vuln:
        icon, icls, kcls, kicker, title = "!", "r-vuln", "k-vuln", "Vulnerability detected", "Potential vulnerability detected"
        copy = "ModerContext detected patterns associated with vulnerable code in the submitted function. Review this function before deployment or use in a security-sensitive environment."
    else:
        icon, icls, kcls, kicker, title = "✓", "r-safe", "k-safe", "Analysis complete", "No vulnerability detected"
        copy = "ModerContext did not detect vulnerability-related patterns in the submitted function. This result supports secure code review and should not be interpreted as an absolute guarantee of security."
    lang = html.escape(friendly_language(result.get("language_name")))
    fn = html.escape(str(result.get("function_name") or "Unknown"))
    sec = html.escape(str(result.get("analysis_seconds", "—")))
    return f'<div class="result"><div class="result-icon {icls}">{icon}</div><div class="result-kicker {kcls}">{kicker}</div><h2>{title}</h2><p>{copy}</p><div class="meta"><div class="meta-box"><span>Language</span><b>{lang}</b></div><div class="meta-box"><span>Function</span><b>{fn}</b></div><div class="meta-box"><span>Analysis time</span><b>{sec} sec</b></div></div></div>'

left, right = st.columns([1.08, .92], gap="large")
with left:
    with st.container(border=True):
        st.html('<div class="panel-kicker">Input</div><div class="panel-title">Source code</div><div class="panel-copy">One C or C++ function at a time.</div>')
        code_value = st_ace(value=st.session_state.code, language="c_cpp", theme="github", keybinding="vscode", font_size=14, tab_size=4, show_gutter=True, show_print_margin=False, wrap=False, auto_update=True, min_lines=22, max_lines=30, key=f"editor_{st.session_state.editor_key}")
        if code_value is not None: st.session_state.code = code_value
        a, c = st.columns([4, 1.15])
        with a: analyze = st.button("▶  Analyze code", type="primary", use_container_width=True)
        with c: clear = st.button("Clear", use_container_width=True)
        st.caption("Predictions are intended to support secure code review.")

if clear:
    st.session_state.code = ""
    st.session_state.result = None
    st.session_state.editor_key += 1
    st.rerun()

with right:
    with st.container(border=True):
        if not MODEL_PATH.exists():
            st.html('<div class="ready"><div class="ready-icon">⚙</div><h2>Model file required</h2><p>Place the trained checkpoint at <b>model/best_model.pt</b>. The app will use that file automatically.</p></div>')
        elif analyze:
            source = (st.session_state.code or "").strip()
            if not source:
                st.warning("Please paste a C or C++ function first.")
            else:
                st.html('<div class="scan-title">Analyzing your function</div><div class="scan-copy">Please wait while ModerContext processes the submitted code.</div>')
                bar = st.progress(3, text="Preparing the analyzer...")
                stage_box = st.empty(); stage_box.html(stages_html("validate"))
                try:
                    scanner = get_scanner()
                    def update(stage, percent, message):
                        bar.progress(int(percent), text=str(message))
                        if stage in INDEX: stage_box.html(stages_html(stage))
                    st.session_state.result = scanner.analyze(source, progress_callback=update)
                    time.sleep(.2)
                    st.rerun()
                except Exception as exc:
                    st.error("ModerContext could not analyze the submitted function.")
                    with st.expander("Technical details"): st.exception(exc)
        elif st.session_state.result is not None:
            st.html(result_html(st.session_state.result))
            if st.button("↻  Analyze another function", use_container_width=True):
                st.session_state.result = None; st.rerun()
        else:
            st.html('<div class="ready"><div class="ready-icon">⌕</div><div class="panel-kicker">Scanner ready</div><h2>Ready to analyze</h2><p>Paste a C or C++ function in the editor and select <b>Analyze code</b> to begin.</p></div>')

st.html('<div class="lower"><div class="eyebrow" style="text-align:center">Simple workflow</div><div class="lower-title">How to use ModerContext</div></div>')
cols = st.columns(3, gap="medium")
items = [("01", "Paste your function", "Copy one C or C++ function into the source-code editor."), ("02", "Run the analysis", "ModerContext pre-processes and evaluates the submitted source code."), ("03", "Review the result", "Receive a clear vulnerability detection outcome to support secure code review.")]
for col, (num, title, copy) in zip(cols, items):
    with col:
        with st.container(border=True): st.html(f'<div class="guide-num">{num}</div><div class="guide-title">{title}</div><div class="guide-copy">{copy}</div>')

st.html('<div class="lower"><div class="eyebrow" style="text-align:center">About the prototype</div><div class="lower-title">ModerContext</div></div>')
with st.container(border=True):
    st.html("""<div class="about"><b>ModerContext</b> is a master's research prototype for source code vulnerability detection. It applies the proposed context-aware processing methodology and a trained long-context classifier to C/C++ functions. The prototype demonstrates practical use of the research approach; its output should support, not replace, professional secure code review.</div>""")
