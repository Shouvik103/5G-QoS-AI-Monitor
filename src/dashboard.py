# dashboard.py — Private 5G Network QoS AI Monitor
# Industry-Grade Real-Time Telemetry Dashboard v3
import streamlit as st
import requests
import time
import random
import json
import pandas as pd
import altair as alt
import base64
import shutil
import subprocess
import math
from pathlib import Path
from statistics import pstdev
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent  # project root
QOS_HTTP_SOURCES = (
    "http://127.0.0.1:5050/",
    "http://localhost:5050/",
)
POLL_INTERVAL_SECONDS = 10


def _clamp(value, low, high):
    return max(low, min(high, value))


def _to_float(value, default):
    if value is None or pd.isna(value):
        return float(default)
    try:
        parsed = float(value)
        if math.isnan(parsed):
            return float(default)
        return parsed
    except (TypeError, ValueError):
        return float(default)


def _to_int(value, default):
    return int(round(_to_float(value, default)))


def _congestion_to_ai(value):
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"very low", "low"}:
            return 0
        if normalized == "medium":
            return 1
        if normalized in {"high", "very high"}:
            return 2

    numeric = _to_int(value, 1)
    return int(_clamp(numeric, 0, 2))


def _ai_to_congestion_ui(level):
    return {0: "Low", 1: "Medium", 2: "High"}.get(level, "Medium")


@st.cache_data(show_spinner=False)
def load_qos_stream(json_path: str):
    with open(json_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    sessions = payload.get("sessions", []) if isinstance(payload, dict) else []
    return _normalize_qos_sessions(sessions)


def fetch_qos_stream_http(api_url: str):
    response = requests.get(api_url, timeout=2.5)
    response.raise_for_status()
    payload = response.json()
    sessions = payload.get("sessions", []) if isinstance(payload, dict) else []
    return _normalize_qos_sessions(sessions)


def _normalize_qos_sessions(sessions):
    if not sessions:
        return []

    def _quantile_bounds(values, low_q=0.15, high_q=0.85):
        clean = sorted(float(v) for v in values if v is not None and not pd.isna(v))
        if not clean:
            return (0.0, 1.0)
        lo_idx = int((len(clean) - 1) * low_q)
        hi_idx = int((len(clean) - 1) * high_q)
        lo = clean[lo_idx]
        hi = clean[hi_idx]
        if hi <= lo:
            hi = lo + 1.0
        return lo, hi

    def _to_pct(value, lo, hi):
        return _clamp((value - lo) / (hi - lo), 0.0, 1.0)

    lat_lo, lat_hi = _quantile_bounds([_to_float(row.get("Latency_ms"), 500.0) for row in sessions])
    jit_lo, jit_hi = _quantile_bounds([_to_float(row.get("jitter_ms"), 1500.0) for row in sessions])
    loss_lo, loss_hi = _quantile_bounds([_to_float(row.get("loss_rate"), 0.35) for row in sessions])
    anm_lo, anm_hi = _quantile_bounds([abs(_to_float(row.get("Anomaly_Score"), 0.0)) for row in sessions], 0.2, 0.95)

    rows = []
    for row in sessions:
        latency = _to_float(row.get('Latency_ms'), 500.0)
        jitter = _to_float(row.get('jitter_ms'), 1500.0)
        signal = _to_float(row.get('Signal_Strength_dBm'), -75.0)

        # Use throughput values from the live backend payload.
        throughput_mbps = _to_float(row.get('throughput_mbps'), 0.001)
        download = throughput_mbps
        upload = max(throughput_mbps * 0.22, 0.0001)

        handovers = _to_int(row.get('User_ID'), 1) % 5
        data_usage = _clamp((throughput_mbps * 60.0), 0.5, 40.0)

        qos_status = str(row.get('QoS_Status', 'Normal')).lower()
        if 'degraded' in qos_status:
            congestion_ai = 2
            qos_status_tag = 'degraded'
        elif 'unusual' in qos_status:
            congestion_ai = 1
            qos_status_tag = 'unusual'
        else:
            congestion_ai = 0
            qos_status_tag = 'normal'

        burstiness = _to_float(row.get('burstiness'), 50.0)

        app_type = str(row.get('Application_Type', 'Other'))
        band = 'n78' if 'F1' in app_type else ('n41' if 'N2' in app_type else 'n28')

        bw_gap = _to_float(row.get('BW_Gap'), 0.0)
        resource_alloc = _to_float(row.get('Resource_Allocation_pct'), 100.0)
        loss_rate = _to_float(row.get('loss_rate'), 0.35)
        anomaly_score = _to_float(row.get('Anomaly_Score'), 0.0)

        risk_hint = (
            (_to_pct(latency, lat_lo, lat_hi) * 0.35)
            + (_to_pct(jitter, jit_lo, jit_hi) * 0.30)
            + (_to_pct(loss_rate, loss_lo, loss_hi) * 0.20)
            + (_to_pct(abs(anomaly_score), anm_lo, anm_hi) * 0.15)
        )
        risk_hint = _clamp(risk_hint, 0.0, 1.0)

        rows.append({
            'user_id': _to_int(row.get('User_ID'), 0),
            'latency': latency,
            'jitter': jitter,
            'signal': signal,
            'download': download,
            'upload': upload,
            'burstiness': burstiness,
            'app_type': app_type,
            'congestion_ai': congestion_ai,
            'band': band,
            'bw_gap': bw_gap,
            'loss_rate': loss_rate,
            'anomaly_score': anomaly_score,
            'resource_alloc_pct': resource_alloc,
            'qos_status_tag': qos_status_tag,
            'risk_hint': risk_hint,
        })
    return rows


@st.cache_data(show_spinner=False)
def load_pcap_stream(pcap_path: str):
    tshark = shutil.which("tshark")
    if not tshark:
        return []

    result = subprocess.run(
        [tshark, "-r", pcap_path, "-T", "fields", "-E", "separator=,", "-e", "frame.time_epoch", "-e", "frame.len"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []

    buckets = {}
    for line in result.stdout.splitlines():
        parts = line.split(',')
        if len(parts) < 2:
            continue
        try:
            ts = float(parts[0])
            frame_len = int(parts[1])
        except ValueError:
            continue
        sec = int(ts)
        buckets.setdefault(sec, []).append(frame_len)

    stream = []
    for sec in sorted(buckets.keys()):
        lengths = buckets[sec]
        if not lengths:
            continue
        bytes_total = sum(lengths)
        packet_rate = len(lengths)
        throughput_mbps = (bytes_total * 8.0) / 1_000_000.0
        jitter_hint = pstdev(lengths) if len(lengths) > 1 else 0.0

        if packet_rate > 350:
            congestion_hint = 2
        elif packet_rate > 150:
            congestion_hint = 1
        else:
            congestion_hint = 0

        stream.append({
            'packet_rate': packet_rate,
            'throughput_mbps': throughput_mbps,
            'jitter_hint': jitter_hint,
            'congestion_hint': congestion_hint,
        })

    return stream

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1. PAGE CONFIG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.set_page_config(
    page_title="5G AI Core — QoS Monitor",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2. PROFESSIONAL CSS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
    --bg-base: #060a13;
    --bg-surface: rgba(10, 15, 28, 0.92);
    --border-dim: rgba(56, 189, 248, 0.06);
    --border-glow: rgba(56, 189, 248, 0.18);
    --txt-1: #f1f5f9;
    --txt-2: #94a3b8;
    --txt-3: #64748b;
    --txt-4: #475569;
    --font: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --mono: 'JetBrains Mono', 'SF Mono', monospace;
}

.stApp {
    background: var(--bg-base);
    background-image:
        radial-gradient(ellipse 80% 60% at 5% -10%, rgba(56,189,248,0.06) 0%, transparent 60%),
        radial-gradient(ellipse 70% 50% at 95% 110%, rgba(139,92,246,0.04) 0%, transparent 60%);
    color: var(--txt-1);
    font-family: var(--font);
}

[data-testid="stHeader"] { display: none !important; }
#MainMenu { visibility: hidden !important; }
footer { visibility: hidden !important; }

.block-container {
    padding-top: 0.5rem !important;
    padding-bottom: 0.5rem !important;
    margin-top: 0 !important;
    max-width: 100% !important;
}

h1, h2, h3, h4 {
    font-family: var(--font) !important;
    padding-top: 0 !important;
    margin-top: 0 !important;
}

/* Metric Cards */
div[data-testid="metric-container"] {
    background: var(--bg-surface);
    border: 1px solid var(--border-dim);
    border-top: 2px solid rgba(56,189,248,0.15);
    border-radius: 12px;
    padding: 14px 16px;
    backdrop-filter: blur(24px) saturate(1.3);
    box-shadow: 0 2px 4px rgba(0,0,0,0.4), 0 8px 24px rgba(0,0,0,0.2);
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}
div[data-testid="metric-container"]:hover {
    border-color: var(--border-glow);
    transform: translateY(-2px);
    box-shadow: 0 2px 4px rgba(0,0,0,0.4), 0 12px 40px rgba(56,189,248,0.05);
}
div[data-testid="stMetricLabel"] p {
    font-family: var(--font) !important;
    font-size: 0.65rem !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: var(--txt-3) !important;
    margin-bottom: 2px !important;
}
div[data-testid="stMetricValue"] > div {
    font-family: var(--mono) !important;
    font-weight: 700 !important;
    font-size: 1.35rem !important;
    color: var(--txt-1) !important;
    letter-spacing: -0.5px;
}

/* Alert */
[data-testid="stAlert"] {
    border-radius: 10px !important;
    border: 1px solid var(--border-dim) !important;
}
[data-testid="stAlert"] p {
    font-size: 1rem !important;
    font-weight: 600 !important;
    font-family: var(--font) !important;
    letter-spacing: 0.5px;
}

/* Charts */
[data-testid="stArrowVegaLiteChart"],
[data-testid="stLineChart"] { border-radius: 8px; overflow: hidden; }
[data-testid="stArrowVegaLiteChart"] canvas { pointer-events: none; }

/* Graph Toolbar */
details, .vega-actions, summary { display: none !important; }
[data-testid="stElementToolbar"] button[title="More options"],
[data-testid="stElementToolbar"] button[aria-label="More options"],
[data-testid="stElementToolbar"] button[title="View more options"] { display: none !important; }

/* Button */
.stButton > button {
    background: linear-gradient(135deg, rgba(56,189,248,0.12), rgba(139,92,246,0.12)) !important;
    color: #38bdf8 !important;
    font-family: var(--font) !important;
    font-weight: 600 !important;
    font-size: 0.78rem !important;
    border: 1px solid rgba(56,189,248,0.2) !important;
    border-radius: 8px !important;
    padding: 0.5rem 1.6rem !important;
    letter-spacing: 1px;
    text-transform: uppercase;
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, rgba(56,189,248,0.22), rgba(139,92,246,0.22)) !important;
    border-color: rgba(56,189,248,0.4) !important;
    box-shadow: 0 0 24px rgba(56,189,248,0.12) !important;
    transform: translateY(-1px);
}

/* Dividers */
hr {
    border: none !important;
    height: 1px !important;
    background: linear-gradient(90deg, transparent, rgba(56,189,248,0.1) 25%, rgba(139,92,246,0.08) 75%, transparent) !important;
    margin: 0.6rem 0 !important;
}

[data-testid="stHorizontalBlock"] { gap: 0.6rem !important; }

::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }

@keyframes pulse-live {
    0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(52,211,153,0.5); }
    50% { opacity: 0.7; box-shadow: 0 0 0 6px rgba(52,211,153,0); }
}
.live-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #34d399; display: inline-block;
    animation: pulse-live 2s ease-in-out infinite;
    margin-right: 6px;
}

</style>
""", unsafe_allow_html=True)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3. TOP NAV BAR (via components.html for JS support)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
now_str = datetime.now().strftime("%b %d, %Y  ·  %H:%M:%S")
_title_text = "Private 5G Network QoS AI Monitor"
_char_spans = ''.join(
    f'<span class="rc">{c}</span>' if c != ' ' else '<span class="rc">&nbsp;</span>'
    for c in _title_text
)

import streamlit.components.v1 as components
components.html(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@800&display=swap');
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: transparent; overflow: hidden; }}
.bar {{
    background: rgba(10,15,28,0.95);
    border-bottom: 1px solid rgba(56,189,248,0.06);
    padding: 14px 24px;
    display: flex; justify-content: space-between; align-items: center;
    width: 100%;
}}
.title {{ display: inline-flex; cursor: default; }}
.rc {{
    font-size: 1.9rem; font-weight: 800;
    font-family: Inter, sans-serif; letter-spacing: -0.3px;
    color: #f1f5f9;
    display: inline-block;
    will-change: color;
}}
.right {{ display: flex; align-items: center; gap: 16px; }}
.ts {{ font-size: 0.7rem; color: #94a3b8; font-family: Inter, sans-serif; letter-spacing: 0.5px; }}
@keyframes pulse-live {{
    0%, 100% {{ opacity: 1; box-shadow: 0 0 0 0 rgba(52,211,153,0.5); }}
    50% {{ opacity: 0.7; box-shadow: 0 0 0 6px rgba(52,211,153,0); }}
}}
.live-badge {{
    display: flex; align-items: center; padding: 4px 10px;
    border-radius: 6px; background: rgba(52,211,153,0.08);
    border: 1px solid rgba(52,211,153,0.15);
}}
.live-dot {{
    width: 8px; height: 8px; border-radius: 50%;
    background: #34d399; display: inline-block;
    animation: pulse-live 2s ease-in-out infinite;
    margin-right: 6px;
}}
.live-txt {{
    font-size: 0.6rem; font-weight: 600; color: #34d399;
    font-family: Inter, sans-serif; text-transform: uppercase; letter-spacing: 1px;
}}
</style>

<div class="bar">
    <div class="title">{_char_spans}</div>
    <div class="right">
        <span class="ts" id="live-ts"></span>
        <div class="live-badge">
            <span class="live-dot"></span>
            <span class="live-txt">Live</span>
        </div>
    </div>
</div>

<script>
(function() {{
    /* ── Live clock ── */
    var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    function updateClock() {{
        var d = new Date();
        var mon = months[d.getMonth()];
        var day = String(d.getDate()).padStart(2, '0');
        var yr = d.getFullYear();
        var h = String(d.getHours()).padStart(2, '0');
        var m = String(d.getMinutes()).padStart(2, '0');
        var s = String(d.getSeconds()).padStart(2, '0');
        var el = document.getElementById('live-ts');
        if (el) el.textContent = mon + ' ' + day + ', ' + yr + '  \u00b7  ' + h + ':' + m + ':' + s;
    }}
    updateClock();
    setInterval(updateClock, 1000);

    /* ── RGB hover effect ── */
    var RADIUS = 200;
    var hueOffset = 0;
    var mx = -9999, my = -9999;
    var active = false;
    var chars = document.querySelectorAll('.rc');
    var positions = [];

    function cachePositions() {{
        positions = [];
        for (var i = 0; i < chars.length; i++) {{
            var r = chars[i].getBoundingClientRect();
            positions.push({{ x: r.left + r.width / 2, y: r.top + r.height / 2 }});
        }}
    }}
    cachePositions();
    window.addEventListener('resize', cachePositions);

    document.querySelector('.title').addEventListener('mouseenter', function() {{ active = true; }});
    document.querySelector('.title').addEventListener('mouseleave', function() {{
        active = false;
        for (var i = 0; i < chars.length; i++) {{ chars[i].style.color = '#f1f5f9'; }}
    }});
    document.querySelector('.title').addEventListener('mousemove', function(e) {{ mx = e.clientX; my = e.clientY; }});

    function frame() {{
        hueOffset = (hueOffset + 0.8) % 360;
        if (active) {{
            for (var i = 0; i < chars.length; i++) {{
                var dx = mx - positions[i].x;
                var dy = my - positions[i].y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < RADIUS) {{
                    var t = 1.0 - dist / RADIUS;
                    var hue = (hueOffset + i * 14) % 360;
                    var lit = 58 + (1 - t) * 38;
                    chars[i].style.color = 'hsl(' + hue + ',100%,' + lit + '%)';
                }} else {{
                    chars[i].style.color = '#f1f5f9';
                }}
            }}
        }}
        requestAnimationFrame(frame);
    }}
    requestAnimationFrame(frame);
}})();
</script>
""", height=60, scrolling=False)



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4. SESSION STATE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if 'history' not in st.session_state:
    st.session_state.history = pd.DataFrame(columns=[
        'Time', 'Latency', 'Jitter', 'Signal', 'Download', 'Upload', 'Burstiness', 'BW_Gap', 'Loss_Rate', 'Anomaly_Score'
    ])
    st.session_state.step = 0

if 'risk_trend' not in st.session_state:
    st.session_state.risk_trend = pd.DataFrame(columns=['Time', 'Risk'])


if 'risk_history' not in st.session_state:
    st.session_state.risk_history = []

if 'prediction_count' not in st.session_state:
    st.session_state.prediction_count = {'safe': 0, 'risk': 0}

if 'qos_index' not in st.session_state:
    st.session_state.qos_index = 0

if 'pcap_index' not in st.session_state:
    st.session_state.pcap_index = 0

if 'qos_api_url' not in st.session_state:
    st.session_state.qos_api_url = None

qos_stream = []

try:
    for api_url in QOS_HTTP_SOURCES:
        try:
            api_rows = fetch_qos_stream_http(api_url)
            qos_stream = api_rows
            st.session_state.qos_api_url = api_url
            break
        except Exception:
            continue
except Exception:
    st.session_state.qos_api_url = None

if st.session_state.qos_api_url is None:
    st.error("Live backend unavailable on port 5050. Start backend_5g_qos (3) and refresh the dashboard.")
    st.stop()

st.caption(f"Data source: backend_5g_qos (3) API ({st.session_state.qos_api_url})")
st.info("Connected to backend API. Waiting for live windows...")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5. STATUS BANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
status_banner = st.empty()
st.markdown("---")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 6. TELEMETRY PANELS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.markdown("""
<div style="display: flex; align-items: center; gap: 8px; margin: 2px 0 10px 0;">
    <div style="width: 3px; height: 14px; border-radius: 2px; background: linear-gradient(180deg, #38bdf8, #8b5cf6);"></div>
    <span style="font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.8px; color: #475569; font-family: Inter, sans-serif;">
        Live Telemetry Panels
    </span>
</div>
""", unsafe_allow_html=True)

col1, col2, col3, col4, col5 = st.columns(5)
box_lat  = col1.empty()
box_jit  = col2.empty()
box_sig  = col3.empty()
box_tp   = col4.empty()
box_burst = col5.empty()

st.markdown("---")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 7. QoS SIGNAL PANELS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.markdown("""
<div style="display: flex; align-items: center; gap: 8px; margin: 2px 0 10px 0;">
    <div style="width: 3px; height: 14px; border-radius: 2px; background: linear-gradient(180deg, #67e8f9, #22d3ee);"></div>
    <span style="font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.8px; color: #475569; font-family: Inter, sans-serif;">
        QoS Signal Panels
    </span>
</div>
""", unsafe_allow_html=True)

q1, q2, q3 = st.columns(3)
box_bw_gap = q1.empty()
box_loss = q2.empty()
box_anom = q3.empty()

st.markdown("---")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 8. NETWORK CONTEXT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.markdown("""
<div style="display: flex; align-items: center; gap: 8px; margin: 2px 0 10px 0;">
    <div style="width: 3px; height: 14px; border-radius: 2px; background: linear-gradient(180deg, #fbbf24, #fb923c);"></div>
    <span style="font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.8px; color: #475569; font-family: Inter, sans-serif;">
        Network Context Variables
    </span>
</div>
""", unsafe_allow_html=True)

m1, m2, m3 = st.columns(3)
with m1: met_band = st.empty()
with m2: met_app  = st.empty()
with m3: met_cong = st.empty()

st.markdown("---")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 9. AI INSIGHTS SECTION (bottom panels)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.markdown("""
<div style="display: flex; align-items: center; gap: 8px; margin: 2px 0 10px 0;">
    <div style="width: 3px; height: 14px; border-radius: 2px; background: linear-gradient(180deg, #34d399, #059669);"></div>
    <span style="font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.8px; color: #475569; font-family: Inter, sans-serif;">
        AI Prediction Analytics
    </span>
</div>
""", unsafe_allow_html=True)

ai_col1, ai_col2, ai_col3 = st.columns(3)
with ai_col1: ai_panel_predictions = st.empty()
with ai_col2: ai_panel_risk_chart  = st.empty()
with ai_col3: ai_panel_log         = st.empty()

st.markdown("---")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 10. KPI SUMMARY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.markdown("""
<div style="display: flex; align-items: center; gap: 8px; margin: 2px 0 10px 0;">
    <div style="width: 3px; height: 14px; border-radius: 2px; background: linear-gradient(180deg, #f87171, #dc2626);"></div>
    <span style="font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.8px; color: #475569; font-family: Inter, sans-serif;">
        Session KPI Summary
    </span>
</div>
""", unsafe_allow_html=True)

kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)
kpi_avg_lat = kpi1.empty()
kpi_avg_jit = kpi2.empty()
kpi_avg_sig = kpi3.empty()
kpi_avg_dl  = kpi4.empty()
kpi_avg_ul  = kpi5.empty()
kpi_avg_burst = kpi6.empty()

st.markdown("---")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 11. ACTION BUTTON
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if st.button("▶  INITIALIZE BACKEND AI STREAM"):
    for iteration in range(300):
        try:
            qos_stream = fetch_qos_stream_http(st.session_state.qos_api_url)
            if not qos_stream:
                status_banner.warning("Waiting for live datapoints from backend (5050)...")
                time.sleep(POLL_INTERVAL_SECONDS)
                continue
            st.session_state.qos_index %= len(qos_stream)
        except Exception as e:
            status_banner.error(f"⚠ Cannot reach backend API on 5050 ({e})")
            break

        qos_row = qos_stream[st.session_state.qos_index % len(qos_stream)]
        st.session_state.qos_index += 1

        sim_user_id = qos_row['user_id']
        sim_lat = qos_row['latency']
        sim_jit = qos_row['jitter']
        sim_sig = qos_row['signal']
        sim_dl = qos_row['download']
        sim_ul = qos_row['upload']
        sim_burst = qos_row['burstiness']
        sim_app_type = qos_row['app_type']
        sim_cong_ai = qos_row['congestion_ai']
        sim_loss_rate = qos_row.get('loss_rate', 0.35)
        sim_anomaly_score = qos_row.get('anomaly_score', 0.0)
        source_qos_tag = qos_row.get('qos_status_tag', 'normal')

        sim_cong_ui = _ai_to_congestion_ui(sim_cong_ai)
        sim_lat = _clamp(sim_lat, 1.0, 3000.0)
        sim_jit = _clamp(sim_jit, 0.1, 4000.0)
        sim_sig = _clamp(sim_sig, -125.0, -55.0)
        sim_burst = _clamp(sim_burst, 0.0, 500.0)

        dl_norm = _clamp(sim_dl / 1000.0, 0.0, 1.0)
        jit_norm = _clamp(sim_jit / 10.0, 0.0, 1.0)
        derived_bw_gap = _clamp(((1.0 - dl_norm) * 0.55) + (jit_norm * 0.18) + (sim_cong_ai * 0.12), 0.05, 5.0)
        derived_res_alloc = _clamp(90.0 - (sim_lat * 0.55) - (sim_jit * 1.8) - (sim_cong_ai * 5.0) + (dl_norm * 12.0), 25.0, 95.0)

        sim_bw_gap = _clamp(qos_row.get('bw_gap', derived_bw_gap), -1.0, 5.0) if qos_row else derived_bw_gap
        sim_res_alloc = _clamp(qos_row.get('resource_alloc_pct', derived_res_alloc), 25.0, 100.0) if qos_row else derived_res_alloc

        try:
            qos_tag = source_qos_tag if source_qos_tag is not None else 'normal'
            if qos_tag == 'degraded':
                verified_risk = 1
                verified_status = "QoS Degraded (from backend 5050)"
            elif qos_tag == 'unusual':
                verified_risk = 0
                verified_status = "Unusual but Acceptable (from backend 5050)"
            else:
                verified_risk = 0
                verified_status = "Network Healthy (from backend 5050)"

            # ── Stress ──
            risk_hint = float(qos_row.get('risk_hint', 0.5)) if qos_row else 0.5
            if verified_risk == 1:
                stress = 70.0 + (risk_hint * 30.0)
            else:
                stress = 12.0 + (risk_hint * 38.0)
            stress = _clamp(stress, 0.0, 100.0)

            if stress < 40:
                bar_color, status_text, status_icon = "#34d399", "NOMINAL", "●"
                bar_glow = "rgba(52,211,153,0.25)"
            elif stress < 70:
                bar_color, status_text, status_icon = "#fbbf24", "WARNING", "▲"
                bar_glow = "rgba(251,191,36,0.25)"
            elif stress < 90:
                bar_color, status_text, status_icon = "#fb923c", "HIGH RISK", "◆"
                bar_glow = "rgba(251,146,60,0.25)"
            else:
                bar_color, status_text, status_icon = "#f87171", "CRITICAL", "✖"
                bar_glow = "rgba(248,113,113,0.25)"

            # ── Track predictions ──
            if verified_risk == 1:
                st.session_state.prediction_count['risk'] += 1
            else:
                st.session_state.prediction_count['safe'] += 1

            # Keep last 8 risk events
            ts_now = datetime.now().strftime("%H:%M:%S")
            st.session_state.risk_history.append({
                'time': ts_now,
                'risk': verified_risk,
                'status': status_text,
                'lat': sim_lat,
                'sig': sim_sig,
                'color': bar_color
            })
            st.session_state.risk_history = st.session_state.risk_history[-8:]

            # ── Update history ──
            st.session_state.step += 1
            new_row = pd.DataFrame({
                'Time': [st.session_state.step], 'Latency': [sim_lat], 'Jitter': [sim_jit],
                'Signal': [sim_sig], 'Download': [sim_dl], 'Upload': [sim_ul], 'Burstiness': [sim_burst],
                'BW_Gap': [sim_bw_gap], 'Loss_Rate': [sim_loss_rate], 'Anomaly_Score': [sim_anomaly_score]
            })
            st.session_state.history = pd.concat([st.session_state.history, new_row]).tail(30)
            df_plot = st.session_state.history.set_index('Time')

            risk_row = pd.DataFrame({
                'Time': [st.session_state.step],
                'Risk': [float(min(100, max(0, stress)))],
            })
            st.session_state.risk_trend = pd.concat([st.session_state.risk_trend, risk_row]).tail(30)

            # ═══════════════════════════════════════
            # TELEMETRY PANELS
            # ═══════════════════════════════════════
            def _area_chart(data, col, color, h=140, flip=False):
                df_c = data[[col]].reset_index()
                encode_args = {
                    'x': alt.X('Time:Q', title=None, axis=alt.Axis(grid=False)),
                    'y': alt.Y(f'{col}:Q', title=None,
                         scale=alt.Scale(reverse=True) if flip else alt.Undefined,
                         axis=alt.Axis(grid=True, gridColor='rgba(148,163,184,0.1)'))
                }
                if flip:
                    encode_args['y2'] = alt.value(h)
                area = alt.Chart(df_c).mark_area(
                    interpolate='monotone', line={'color': color, 'strokeWidth': 2},
                    color=alt.Gradient(gradient='linear', stops=[
                        alt.GradientStop(color=color, offset=0),
                        alt.GradientStop(color='rgba(6,10,19,0)', offset=1)
                    ], x1=0, x2=0, y1=0, y2=1)
                ).encode(**encode_args).properties(height=h).configure_axis(
                    domain=False, labelColor='#475569', labelFont='Inter', labelFontSize=9, tickColor='#1e293b'
                ).configure_view(strokeOpacity=0)
                st.altair_chart(area, use_container_width=True)

            def _line_point_chart(data, col, color, h=140, point_size=22):
                df_c = data[[col]].reset_index()
                chart = alt.Chart(df_c).mark_line(
                    interpolate='monotone', strokeWidth=2.2, color=color
                ).encode(
                    x=alt.X('Time:Q', title=None, axis=alt.Axis(grid=False)),
                    y=alt.Y(f'{col}:Q', title=None, axis=alt.Axis(grid=True, gridColor='rgba(148,163,184,0.1)'))
                ) + alt.Chart(df_c).mark_circle(size=point_size, color=color, opacity=0.9).encode(
                    x='Time:Q',
                    y=f'{col}:Q'
                )
                chart = chart.properties(height=h).configure_axis(
                    domain=False, labelColor='#475569', labelFont='Inter', labelFontSize=9, tickColor='#1e293b'
                ).configure_view(strokeOpacity=0)
                st.altair_chart(chart, use_container_width=True)

            def _loss_rate_line_chart(data, col, color, h=140):
                df_c = data[[col]].reset_index()
                area = alt.Chart(df_c).mark_area(
                    color=alt.Gradient(
                        gradient='linear',
                        stops=[
                            alt.GradientStop(color=color, offset=0),
                            alt.GradientStop(color='rgba(6,10,19,0)', offset=1),
                        ],
                        x1=0,
                        x2=0,
                        y1=0,
                        y2=1,
                    ),
                    opacity=0.75
                ).encode(
                    x=alt.X('Time:Q', title=None, axis=alt.Axis(grid=False)),
                    y=alt.Y(f'{col}:Q', title=None, axis=alt.Axis(grid=True, gridColor='rgba(148,163,184,0.1)'))
                )
                line = alt.Chart(df_c).mark_line(
                    color=color, strokeWidth=2.1, interpolate='monotone'
                ).encode(
                    x='Time:Q',
                    y=f'{col}:Q'
                )
                points = alt.Chart(df_c).mark_circle(size=28, color=color, opacity=0.85).encode(
                    x='Time:Q',
                    y=f'{col}:Q'
                )
                chart = (area + line + points).properties(height=h).configure_axis(
                    domain=False, labelColor='#475569', labelFont='Inter', labelFontSize=9, tickColor='#1e293b'
                ).configure_view(strokeOpacity=0)
                st.altair_chart(chart, use_container_width=True)

            def _anomaly_chart(data, col, h=140):
                df_c = data[[col]].reset_index()
                extent = max(abs(float(df_c[col].min())), abs(float(df_c[col].max())), 0.05)
                points = alt.Chart(df_c).mark_circle(size=50, opacity=0.95).encode(
                    x=alt.X('Time:Q', title=None, axis=alt.Axis(grid=False)),
                    y=alt.Y(f'{col}:Q', title=None, scale=alt.Scale(domain=[-extent, extent]), axis=alt.Axis(grid=True, gridColor='rgba(148,163,184,0.1)')),
                    color=alt.condition(f'datum.{col} >= 0', alt.value('#a78bfa'), alt.value('#f472b6')),
                )
                zero_rule = alt.Chart(pd.DataFrame({'y': [0]})).mark_rule(color='rgba(148,163,184,0.35)', strokeDash=[4, 3]).encode(y='y:Q')
                line = alt.Chart(df_c).mark_line(color='#67e8f9', strokeWidth=1.8, interpolate='monotone').encode(
                    x='Time:Q',
                    y=alt.Y(f'{col}:Q', scale=alt.Scale(domain=[-extent, extent]))
                )
                chart = (zero_rule + line + points).properties(height=h).configure_axis(
                    domain=False, labelColor='#475569', labelFont='Inter', labelFontSize=9, tickColor='#1e293b'
                ).configure_view(strokeOpacity=0)
                st.altair_chart(chart, use_container_width=True)

            with box_lat.container():
                st.metric("Latency", f"{sim_lat:.1f} ms")
                _area_chart(df_plot, 'Latency', '#f87171')

            with box_jit.container():
                st.metric("Jitter", f"{sim_jit:.1f} ms")
                _area_chart(df_plot, 'Jitter', '#fbbf24')

            with box_sig.container():
                st.metric("Signal Strength", f"{sim_sig:.1f} dBm")
                _area_chart(df_plot, 'Signal', '#249E94', flip=True)

            with box_tp.container():
                if qos_row:
                    st.metric("Throughput (DL/UL)", f"{sim_dl:.4f} / {sim_ul:.4f} Mbps")
                else:
                    st.metric("Throughput (DL/UL)", f"{sim_dl:.0f} / {sim_ul:.0f} Mbps")
                df_tp = df_plot[['Download', 'Upload']].reset_index().melt(
                    'Time', var_name='Metric', value_name='Mbps'
                )
                tp_max = max(0.005, float(df_tp['Mbps'].max()) * 1.2)
                chart = alt.Chart(df_tp).mark_area(
                    interpolate='monotone', opacity=0.6, line=True
                ).encode(
                    x=alt.X('Time:Q', title=None, axis=alt.Axis(labels=False, ticks=False, grid=False)),
                    y=alt.Y('Mbps:Q', title=None, scale=alt.Scale(domain=[0, tp_max]),
                            axis=alt.Axis(grid=False, labels=False, ticks=False)),
                    color=alt.Color('Metric:N', title=None,
                        scale=alt.Scale(domain=['Download', 'Upload'], range=['#38bdf8', '#a78bfa']),
                        legend=alt.Legend(orient="bottom", labelColor="#64748b", labelFont="Inter", labelFontSize=9))
                ).properties(height=175).configure_axis(
                    domain=False, gridColor='rgba(148,163,184,0.04)',
                    labelColor='#475569', labelFont='Inter', labelFontSize=9
                ).configure_view(strokeOpacity=0)
                st.altair_chart(chart, use_container_width=True)

            with box_burst.container():
                st.metric("Burstiness", f"{sim_burst:.1f}")
                _area_chart(df_plot, 'Burstiness', '#DE1A58')

            with box_bw_gap.container():
                st.metric("Bandwidth Gap", f"{sim_bw_gap:.4f}")
                _line_point_chart(df_plot, 'BW_Gap', '#67e8f9', point_size=44)

            with box_loss.container():
                st.metric("Loss Rate", f"{sim_loss_rate:.4f}")
                _loss_rate_line_chart(df_plot, 'Loss_Rate', '#B6FF00')

            with box_anom.container():
                st.metric("Anomaly Score", f"{sim_anomaly_score:.4f}")
                _anomaly_chart(df_plot, 'Anomaly_Score')

            # ═══════════════════════════════════════
            # CONTEXT METRICS
            # ═══════════════════════════════════════
            def _card(label, value, value_color="#f1f5f9", accent=None, mono=True):
                font = "'JetBrains Mono', monospace" if mono else "Inter, sans-serif"
                border_top = f"border-top: 2px solid {accent};" if accent else ""
                return f'<div style="background: rgba(10,15,28,0.92); border: 1px solid rgba(56,189,248,0.06); {border_top} border-radius: 12px; padding: 14px 16px; backdrop-filter: blur(24px); box-shadow: 0 2px 4px rgba(0,0,0,0.4), 0 8px 24px rgba(0,0,0,0.2);"><p style="margin: 0 0 4px 0; font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.2px; color: #64748b; font-family: Inter, sans-serif;">{label}</p><p style="margin: 0; font-size: 1.35rem; font-weight: 700; color: {value_color}; font-family: {font}; letter-spacing: -0.5px;">{value}</p></div>'

            met_band.markdown(_card("User ID", str(sim_user_id)), unsafe_allow_html=True)
            met_app.markdown(_card("Application Type", sim_app_type, mono=False), unsafe_allow_html=True)

            cong_colors = {
                'Very Low': '#34d399', 'Low': '#6ee7b7',
                'Medium': '#fbbf24', 'High': '#fb923c', 'Very High': '#f87171'
            }
            cc = cong_colors.get(sim_cong_ui, '#94a3b8')
            met_cong.markdown(_card("Congestion Level", sim_cong_ui, value_color=cc, accent=cc), unsafe_allow_html=True)

            # ═══════════════════════════════════════
            # AI INSIGHTS PANELS
            # ═══════════════════════════════════════
            total_preds = st.session_state.prediction_count['safe'] + st.session_state.prediction_count['risk']
            safe_count = st.session_state.prediction_count['safe']
            risk_count = st.session_state.prediction_count['risk']
            safe_pct = (safe_count / total_preds * 100) if total_preds > 0 else 0
            risk_pct = (risk_count / total_preds * 100) if total_preds > 0 else 0

            # Panel 1: AI Prediction Summary
            pred_html = f'<div style="background: rgba(10,15,28,0.92); border: 1px solid rgba(56,189,248,0.06); border-radius: 12px; padding: 18px 20px; min-height: 180px; backdrop-filter: blur(24px); box-shadow: 0 2px 4px rgba(0,0,0,0.4), 0 8px 24px rgba(0,0,0,0.2);"><p style="margin: 0 0 14px 0; font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.2px; color: #64748b; font-family: Inter, sans-serif;">AI Prediction Summary</p><div style="display: flex; justify-content: space-between; margin-bottom: 16px;"><div style="text-align: center; flex: 1;"><p style="margin: 0; font-size: 1.8rem; font-weight: 800; color: #34d399; font-family: JetBrains Mono, monospace;">{safe_count}</p><p style="margin: 2px 0 0 0; font-size: 0.6rem; color: #475569; text-transform: uppercase; letter-spacing: 1px; font-family: Inter, sans-serif;">Safe</p></div><div style="width: 1px; background: rgba(56,189,248,0.08);"></div><div style="text-align: center; flex: 1;"><p style="margin: 0; font-size: 1.8rem; font-weight: 800; color: #f87171; font-family: JetBrains Mono, monospace;">{risk_count}</p><p style="margin: 2px 0 0 0; font-size: 0.6rem; color: #475569; text-transform: uppercase; letter-spacing: 1px; font-family: Inter, sans-serif;">At Risk</p></div><div style="width: 1px; background: rgba(56,189,248,0.08);"></div><div style="text-align: center; flex: 1;"><p style="margin: 0; font-size: 1.8rem; font-weight: 800; color: #f1f5f9; font-family: JetBrains Mono, monospace;">{total_preds}</p><p style="margin: 2px 0 0 0; font-size: 0.6rem; color: #475569; text-transform: uppercase; letter-spacing: 1px; font-family: Inter, sans-serif;">Total</p></div></div><div style="background: rgba(30,41,59,0.5); border-radius: 6px; width: 100%; height: 8px; overflow: hidden; display: flex;"><div style="background: #34d399; width: {safe_pct}%; height: 100%; transition: width 0.4s ease;"></div><div style="background: #f87171; width: {risk_pct}%; height: 100%; transition: width 0.4s ease;"></div></div><div style="display: flex; justify-content: space-between; margin-top: 4px;"><span style="font-size: 0.55rem; color: #34d399; font-family: JetBrains Mono, monospace;">{safe_pct:.1f}% Safe</span><span style="font-size: 0.55rem; color: #f87171; font-family: JetBrains Mono, monospace;">{risk_pct:.1f}% Risk</span></div></div>'
            ai_panel_predictions.markdown(pred_html, unsafe_allow_html=True)

            # Panel 2: Risk Score Trend
            with ai_panel_risk_chart.container():
                st.markdown('<p style="margin: 0 0 6px 0; font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.2px; color: #64748b; font-family: Inter, sans-serif;">Risk Score Trend</p>', unsafe_allow_html=True)
                if len(st.session_state.risk_trend) > 1:
                    df_risk = st.session_state.risk_trend.copy()
                    bars = alt.Chart(df_risk).mark_bar(
                        cornerRadiusTopLeft=3, cornerRadiusTopRight=3,
                        color='#d4789c', opacity=0.7
                    ).encode(
                        x=alt.X('Time:O', title=None, axis=alt.Axis(labels=False, ticks=False, grid=False)),
                        y=alt.Y('Risk:Q', title=None, scale=alt.Scale(domain=[0, 100]), axis=alt.Axis(grid=True, gridColor='rgba(148,163,184,0.1)'))
                    )
                    line = alt.Chart(df_risk).mark_line(
                        interpolate='monotone', strokeWidth=2, color='#67e8f9'
                    ).encode(
                        x=alt.X('Time:O', title=None),
                        y=alt.Y('Risk:Q', title=None)
                    )
                    r_chart = (bars + line).properties(height=160).configure_axis(
                        domain=False, labelColor='#475569', labelFont='Inter', labelFontSize=9, tickColor='#1e293b'
                    ).configure_view(strokeOpacity=0)
                    st.altair_chart(r_chart, use_container_width=True)

            # Panel 3: Recent Event Log
            log_rows = ""
            for evt in reversed(st.session_state.risk_history):
                log_rows += f'<div style="display: flex; justify-content: space-between; align-items: center; padding: 5px 0; border-bottom: 1px solid rgba(56,189,248,0.04);"><span style="font-size: 0.65rem; color: #475569; font-family: JetBrains Mono, monospace;">{evt["time"]}</span><span style="font-size: 0.6rem; font-weight: 600; color: {evt["color"]}; font-family: Inter, sans-serif; letter-spacing: 0.5px;">{evt["status"]}</span></div>'

            fallback = '<p style="font-size: 0.7rem; color: #334155; font-family: Inter, sans-serif;">Waiting for data...</p>'
            log_content = log_rows if log_rows else fallback

            # Build CSV data URI for last 25 events
            recent_25 = list(reversed(st.session_state.risk_history))[:25]
            csv_data = "Time,Status\n" + "".join(f'{e["time"]},{e["status"]}\n' for e in recent_25)
            b64_csv = base64.b64encode(csv_data.encode()).decode()
            dl_icon = f'<a href="data:text/csv;base64,{b64_csv}" download="recent_events.csv" style="text-decoration: none; font-size: 0.85rem; color: #64748b; cursor: pointer; transition: color 0.2s;" title="Download last 25 events">⬇</a>' if recent_25 else ''

            log_html = f'<div style="background: rgba(10,15,28,0.92); border: 1px solid rgba(56,189,248,0.06); border-radius: 12px; padding: 18px 20px; min-height: 180px; backdrop-filter: blur(24px); box-shadow: 0 2px 4px rgba(0,0,0,0.4), 0 8px 24px rgba(0,0,0,0.2);"><div style="display: flex; justify-content: space-between; align-items: center; margin: 0 0 10px 0;"><p style="margin: 0; font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.2px; color: #64748b; font-family: Inter, sans-serif;">Recent Events</p>{dl_icon}</div>{log_content}</div>'
            ai_panel_log.markdown(log_html, unsafe_allow_html=True)

            # ═══════════════════════════════════════
            # KPI SUMMARY
            # ═══════════════════════════════════════
            df_h = st.session_state.history
            kpi_avg_lat.metric("Avg Latency", f"{df_h['Latency'].mean():.1f} ms")
            kpi_avg_jit.metric("Avg Jitter", f"{df_h['Jitter'].mean():.1f} ms")
            kpi_avg_sig.metric("Avg Signal", f"{df_h['Signal'].mean():.1f} dBm")
            kpi_avg_dl.metric("Avg Download", f"{df_h['Download'].mean():.0f} Mbps")
            kpi_avg_ul.metric("Avg Upload", f"{df_h['Upload'].mean():.0f} Mbps")
            kpi_avg_burst.metric("Avg Burstiness", f"{df_h['Burstiness'].mean():.1f}")

            # ── Alert Banner ──
            if verified_risk == 1:
                status_banner.error(verified_status)
            else:
                status_banner.success(f"SYSTEM NOMINAL  ·  {verified_status}")

        except Exception as e:
            status_banner.error(f"⚠ Backend stream processing error ({e})")
            break

        time.sleep(POLL_INTERVAL_SECONDS)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 12. FOOTER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.markdown(f"""
<div style="
    margin-top: 8px; padding: 14px 0;
    border-top: 1px solid rgba(56,189,248,0.06);
    display: flex; justify-content: space-between; align-items: center;
">
    <span style="font-size: 0.6rem; color: #334155; font-family: Inter, sans-serif; letter-spacing: 0.5px;">
        5G QoS AI Monitor &nbsp;·&nbsp; Built with Streamlit + FastAPI + Scikit-Learn
    </span>
    <span style="font-size: 0.6rem; color: #334155; font-family: 'JetBrains Mono', monospace; letter-spacing: 0.5px;">
        {now_str}
    </span>
</div>
""", unsafe_allow_html=True)