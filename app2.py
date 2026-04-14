cat > /home/claude/cybertrack_v6.py << 'PYEOF'
"""
CyberTrack v6.0 — AI-Powered Cyber Threat Intelligence Platform
Fixes: Quick Targets now auto-scan on click
New Features:
  - Live Threat Ticker (scrolling alerts)
  - Animated Threat Score Ring (CSS)
  - IP Comparison Mode (side-by-side)
  - Network Topology Visualizer (Plotly)
  - MITRE ATT&CK Technique Mapper
  - Real-time Threat Feed simulation
  - Threat Timeline with event annotations
  - Dark/Glow UI polish upgrades
"""

import streamlit as st
import folium
from streamlit_folium import st_folium
import requests
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import json
import random
import socket
import ipaddress
import os
import math
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import warnings
warnings.filterwarnings("ignore")

st.set_page_config(
    page_title="CyberTrack v6.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_API_KEY",  "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY",  "")
OPENAI_KEY     = os.environ.get("OPENAI_API_KEY",      "")
GEO_JUMP_KM    = 5000
HIGH_THREAT_THRESHOLD = 70

PORT_RISKS = {
    21:   ("FTP",      35, "File Transfer — often unencrypted"),
    22:   ("SSH",      20, "Secure Shell — brute-force target"),
    23:   ("Telnet",   45, "Telnet — plaintext, highly dangerous"),
    25:   ("SMTP",     25, "Mail relay abuse risk"),
    53:   ("DNS",      15, "DNS amplification possible"),
    80:   ("HTTP",     10, "Unencrypted web traffic"),
    110:  ("POP3",     20, "Email retrieval — unencrypted"),
    143:  ("IMAP",     20, "Email retrieval — unencrypted"),
    443:  ("HTTPS",     5, "Encrypted web — generally safe"),
    445:  ("SMB",      40, "Common ransomware vector"),
    3306: ("MySQL",    35, "Database exposed to internet"),
    3389: ("RDP",      50, "Remote Desktop — top attack surface"),
    5900: ("VNC",      40, "Remote desktop — often unencrypted"),
    6379: ("Redis",    45, "Redis unauthenticated — critical risk"),
    8080: ("HTTP-Alt", 10, "Alternative HTTP port"),
    8443: ("HTTPS-Alt", 5, "Alternative HTTPS port"),
}
HIGH_RISK_PORTS = {p for p,(s,w,d) in PORT_RISKS.items() if w >= 35}

MITRE_TECHNIQUES = {
    "Port Scan":    [("T1046","Network Service Discovery","Reconnaissance"),("T1595","Active Scanning","Reconnaissance")],
    "Brute Force":  [("T1110","Brute Force","Credential Access"),("T1078","Valid Accounts","Persistence")],
    "C2":           [("T1071","App Layer Protocol","C2"),("T1095","Non-App Layer Protocol","C2")],
    "SSH Abuse":    [("T1021.004","SSH","Lateral Movement"),("T1110.003","Password Spraying","Credential Access")],
    "Malware":      [("T1059","Command Scripting","Execution"),("T1055","Process Injection","Defense Evasion")],
    "DDoS":         [("T1498","Network DoS","Impact"),("T1499","Endpoint DoS","Impact")],
    "Phishing":     [("T1566","Phishing","Initial Access"),("T1598","Spearphishing","Reconnaissance")],
    "Spam":         [("T1566.001","Spearphishing Attachment","Initial Access")],
    "Hacking":      [("T1190","Exploit Public-Facing App","Initial Access"),("T1203","Exploitation for Client Execution","Execution")],
}

st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@300;400;600;700&display=swap');
  :root{
    --bg:#020a12;--surface:#071520;--border:#0d4f6e;--accent:#00d4ff;
    --green:#00ff88;--red:#ff2d55;--orange:#ffaa00;--text:#c8e6f5;
    --dim:#4a7a9b;--purple:#a855f7;--yellow:#ffd700;
  }
  html,body,.stApp{background-color:var(--bg)!important;color:var(--text)!important;font-family:'Rajdhani',sans-serif!important;}
  .stApp::before{content:'';position:fixed;top:0;left:0;right:0;bottom:0;
    background-image:linear-gradient(rgba(0,212,255,.018) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,212,255,.018) 1px,transparent 1px);
    background-size:50px 50px;pointer-events:none;z-index:0;animation:gridPulse 8s ease-in-out infinite;}
  @keyframes gridPulse{0%,100%{opacity:.4}50%{opacity:1}}
  section[data-testid="stSidebar"]{background:linear-gradient(180deg,#020d18 0%,#030f1f 100%)!important;border-right:1px solid var(--border)!important;}

  /* ── TICKER ── */
  .ticker-wrap{width:100%;background:rgba(255,45,85,.06);border:1px solid rgba(255,45,85,.3);
    border-radius:3px;overflow:hidden;height:28px;margin-bottom:12px;position:relative;}
  .ticker-wrap::before{content:'⚠ LIVE FEED';position:absolute;left:0;top:0;height:100%;
    background:#ff2d55;color:#000;font-family:'Share Tech Mono',monospace;font-size:.68rem;
    font-weight:bold;padding:0 10px;display:flex;align-items:center;z-index:2;white-space:nowrap;}
  .ticker{display:flex;animation:ticker 40s linear infinite;width:max-content;padding-left:160px;}
  .ticker span{font-family:'Share Tech Mono',monospace;font-size:.68rem;color:#ff2d55;
    white-space:nowrap;padding:6px 30px 6px 0;line-height:16px;}
  @keyframes ticker{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}

  /* ── HEADER ── */
  .cyber-header{background:linear-gradient(135deg,#020d18,#041525,#020d18);
    border:1px solid var(--accent);border-radius:4px;padding:20px 30px;margin-bottom:8px;
    position:relative;overflow:hidden;box-shadow:0 0 40px rgba(0,212,255,.15),inset 0 0 30px rgba(0,212,255,.04);}
  .cyber-header::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;
    background:conic-gradient(transparent,rgba(0,212,255,.04),transparent 30%);animation:rotate 12s linear infinite;}
  @keyframes rotate{100%{transform:rotate(360deg)}}
  .cyber-title{font-family:'Orbitron',monospace!important;font-size:2rem!important;font-weight:900!important;
    color:var(--accent)!important;text-shadow:0 0 20px rgba(0,212,255,.8),0 0 40px rgba(0,212,255,.4);
    letter-spacing:4px;margin:0;position:relative;z-index:1;}
  .cyber-sub{font-family:'Share Tech Mono',monospace;color:var(--green);font-size:.78rem;letter-spacing:3px;margin-top:4px;position:relative;z-index:1;}
  .version-badge{display:inline-block;background:rgba(0,255,136,.12);border:1px solid var(--green);
    color:var(--green);font-family:'Share Tech Mono',monospace;font-size:.6rem;padding:2px 8px;
    border-radius:2px;letter-spacing:2px;margin-left:12px;vertical-align:middle;}

  /* ── METRIC CARDS ── */
  .mc{background:linear-gradient(135deg,#071520,#0a1f2e);border:1px solid var(--border);
    border-radius:4px;padding:16px;margin:6px 0;position:relative;overflow:hidden;transition:all .3s;}
  .mc:hover{border-color:var(--accent);box-shadow:0 0 18px rgba(0,212,255,.2);transform:translateY(-2px);}
  .mc::after{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--accent);box-shadow:0 0 8px var(--accent);}
  .mc .mv{font-family:'Orbitron',monospace;font-size:1.8rem;font-weight:700;color:var(--accent);text-shadow:0 0 12px rgba(0,212,255,.6);}
  .mc .ml{font-family:'Share Tech Mono',monospace;font-size:.7rem;color:var(--dim);letter-spacing:2px;text-transform:uppercase;}
  .mc.red::after{background:var(--red);box-shadow:0 0 8px var(--red);} .mc.red .mv{color:var(--red);text-shadow:0 0 12px rgba(255,45,85,.6);}
  .mc.grn::after{background:var(--green);} .mc.grn .mv{color:var(--green);}
  .mc.org::after{background:var(--orange);} .mc.org .mv{color:var(--orange);}
  .mc.pur::after{background:var(--purple);} .mc.pur .mv{color:var(--purple);}

  /* ── SCORE RING ── */
  .score-ring-wrap{position:relative;display:flex;justify-content:center;align-items:center;margin:10px 0;}
  .score-ring-wrap svg{transform:rotate(-90deg);}
  .score-ring-text{position:absolute;text-align:center;}
  .score-ring-num{font-family:'Orbitron',monospace;font-size:2.4rem;font-weight:900;line-height:1;}
  .score-ring-label{font-family:'Share Tech Mono',monospace;font-size:.65rem;letter-spacing:2px;margin-top:4px;}

  /* ── PANELS ── */
  .ip{background:linear-gradient(135deg,#071520,#0a1f2e);border:1px solid var(--border);
    border-radius:4px;padding:16px;margin:8px 0;font-family:'Share Tech Mono',monospace;font-size:.8rem;color:var(--text);line-height:1.9;}
  .ip .lb{color:var(--accent);font-weight:bold;} .ip .bad{color:var(--red);} .ip .ok{color:var(--green);} .ip .wn{color:var(--orange);}
  .ab{border-radius:4px;padding:10px 14px;margin:6px 0;font-family:'Share Tech Mono',monospace;font-size:.78rem;display:flex;align-items:center;gap:8px;}
  .ab.hi{background:rgba(255,45,85,.08);border:1px solid var(--red);color:var(--red);animation:ablink 2s infinite;}
  .ab.md{background:rgba(255,170,0,.08);border:1px solid var(--orange);color:var(--orange);}
  .ab.lo{background:rgba(0,255,136,.08);border:1px solid var(--green);color:var(--green);}
  @keyframes ablink{0%,100%{box-shadow:0 0 4px rgba(255,45,85,.3)}50%{box-shadow:0 0 14px rgba(255,45,85,.6)}}

  /* ── SECTION HEADERS ── */
  .sh{font-family:'Orbitron',monospace;font-size:.85rem;color:var(--accent);letter-spacing:3px;
    text-transform:uppercase;border-bottom:1px solid var(--border);padding-bottom:7px;
    margin:18px 0 12px;text-shadow:0 0 8px rgba(0,212,255,.5);}

  /* ── THREAT SCORE (old) ── */
  .ts{font-family:'Orbitron',monospace;font-size:2.8rem;font-weight:900;text-align:center;
    padding:18px;border-radius:4px;text-shadow:0 0 25px currentColor;}
  .ts.crit{color:#ff0033;background:rgba(255,0,51,.08);border:1px solid #ff0033;}
  .ts.hi{color:var(--red);background:rgba(255,45,85,.08);border:1px solid var(--red);}
  .ts.md{color:var(--orange);background:rgba(255,170,0,.08);border:1px solid var(--orange);}
  .ts.lo{color:var(--green);background:rgba(0,255,136,.08);border:1px solid var(--green);}

  /* ── BLINK / PULSE ── */
  .blink-red{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--red);animation:blink 1s step-end infinite;margin-right:6px;}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
  .pulse{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);animation:pd 1.5s ease-in-out infinite;margin-right:5px;}
  @keyframes pd{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.3;transform:scale(.7)}}

  /* ── CONFIDENCE BADGES ── */
  .conf-high{display:inline-block;padding:3px 10px;border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:.68rem;background:rgba(0,255,136,.12);border:1px solid var(--green);color:var(--green);}
  .conf-med{display:inline-block;padding:3px 10px;border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:.68rem;background:rgba(255,170,0,.12);border:1px solid var(--orange);color:var(--orange);}
  .conf-low{display:inline-block;padding:3px 10px;border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:.68rem;background:rgba(255,45,85,.12);border:1px solid var(--red);color:var(--red);}

  /* ── XAI ── */
  .xai{background:rgba(255,170,0,.05);border-left:3px solid var(--orange);padding:12px 16px;margin:8px 0;font-family:'Share Tech Mono',monospace;font-size:.78rem;color:var(--text);line-height:2;}
  .xai-row{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(13,79,110,.3);padding:3px 0;}
  .xai-row:last-child{border-bottom:none;} .xai-label{color:var(--dim);} .xai-pos{color:var(--red);font-weight:bold;}

  /* ── CHAT ── */
  .cu{background:rgba(0,212,255,.07);border:1px solid rgba(0,212,255,.25);border-radius:4px;padding:9px 13px;margin:5px 0;font-family:'Share Tech Mono',monospace;font-size:.78rem;color:var(--accent);text-align:right;}
  .cb{background:rgba(0,255,136,.05);border:1px solid rgba(0,255,136,.2);border-radius:4px;padding:9px 13px;margin:5px 0;font-family:'Share Tech Mono',monospace;font-size:.78rem;color:var(--green);}
  .cb .bl{color:var(--dim);font-size:.68rem;margin-bottom:3px;}

  /* ── TERMINAL ── */
  .term{background:#000d15;border:1px solid var(--border);border-radius:4px;padding:14px;font-family:'Share Tech Mono',monospace;font-size:.73rem;height:270px;overflow-y:auto;line-height:1.65;}
  .le{margin:2px 0;} .lt{color:var(--dim);} .li{color:var(--accent);} .lw{color:var(--orange);} .le2{color:var(--red);} .ls{color:var(--green);}

  /* ── PORT TABLE ── */
  .pt{width:100%;border-collapse:collapse;font-family:'Share Tech Mono',monospace;font-size:.77rem;}
  .pt th{color:var(--accent);border-bottom:1px solid var(--border);padding:6px 9px;text-align:left;}
  .pt td{padding:5px 9px;border-bottom:1px solid rgba(13,79,110,.25);}
  .po{color:var(--green);} .pc{color:var(--dim);} .pf{color:var(--orange);}

  /* ── SCROLLBAR ── */
  ::-webkit-scrollbar{width:5px;} ::-webkit-scrollbar-track{background:var(--bg);} ::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}

  /* ── BUTTONS ── */
  .stButton>button{background:transparent!important;border:1px solid var(--accent)!important;color:var(--accent)!important;font-family:'Share Tech Mono',monospace!important;letter-spacing:2px!important;border-radius:2px!important;transition:all .3s!important;text-transform:uppercase!important;}
  .stButton>button:hover{background:rgba(0,212,255,.08)!important;box-shadow:0 0 12px rgba(0,212,255,.3)!important;}
  .stTextInput>div>div>input,.stTextArea>div>div>textarea,.stSelectbox>div>div{background:#071520!important;border:1px solid var(--border)!important;color:var(--text)!important;font-family:'Share Tech Mono',monospace!important;border-radius:2px!important;}
  h1,h2,h3{font-family:'Orbitron',monospace!important;color:var(--accent)!important;}
  div[data-testid="stMetricValue"]{font-family:'Orbitron',monospace!important;color:var(--accent)!important;}
  .stDataFrame{border:1px solid var(--border);}

  /* ── LEADERBOARD ── */
  .lb-row{display:flex;align-items:center;justify-content:space-between;padding:7px 10px;border-bottom:1px solid rgba(13,79,110,.3);font-family:'Share Tech Mono',monospace;font-size:.78rem;}
  .lb-row:hover{background:rgba(0,212,255,.03);}
  .lb-num{color:var(--dim);min-width:22px;} .lb-ip{color:var(--accent);} .lb-score{font-weight:bold;}

  /* ── V6 NEW ── */
  .alert-banner{background:rgba(255,0,51,.12);border:2px solid #ff0033;border-radius:4px;padding:14px 20px;margin-bottom:14px;font-family:'Share Tech Mono',monospace;font-size:.88rem;color:#ff0033;display:flex;align-items:center;gap:10px;animation:ablink 1.5s infinite;}
  .decision-panel{background:linear-gradient(135deg,#071520,#0a1f2e);border:1px solid var(--border);border-radius:4px;padding:16px;margin:8px 0;}
  .decision-panel.high{border-color:var(--red);} .decision-panel.medium{border-color:var(--orange);} .decision-panel.low{border-color:var(--green);}
  .decision-title{font-family:'Orbitron',monospace;font-size:.8rem;letter-spacing:2px;margin-bottom:10px;}
  .decision-title.high{color:var(--red);} .decision-title.medium{color:var(--orange);} .decision-title.low{color:var(--green);}
  .decision-item{font-family:'Share Tech Mono',monospace;font-size:.76rem;color:var(--text);padding:4px 0;border-bottom:1px solid rgba(13,79,110,.2);}
  .decision-item:last-child{border-bottom:none;}
  .event-row{display:flex;align-items:flex-start;gap:8px;padding:5px 0;border-bottom:1px solid rgba(13,79,110,.15);font-family:'Share Tech Mono',monospace;font-size:.75rem;}
  .ev-time{color:var(--dim);min-width:68px;} .ev-info{color:var(--accent);} .ev-warn{color:var(--orange);} .ev-crit{color:var(--red);font-weight:bold;}
  .ev-msg{color:var(--text);}
  .src-ok{color:var(--green);} .src-miss{color:var(--dim);}
  .behavior-insight{background:rgba(168,85,247,.07);border-left:3px solid var(--purple);padding:10px 14px;margin:6px 0;font-family:'Share Tech Mono',monospace;font-size:.76rem;color:var(--text);line-height:1.8;}
  .signals-badge{display:inline-block;padding:3px 9px;border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:.7rem;margin-left:8px;}
  .corr-high{background:rgba(255,45,85,.12);border:1px solid var(--red);color:var(--red);}
  .corr-med{background:rgba(255,170,0,.12);border:1px solid var(--orange);color:var(--orange);}
  .corr-low{background:rgba(0,255,136,.12);border:1px solid var(--green);color:var(--green);}

  /* ── MITRE CARD ── */
  .mitre-card{background:rgba(168,85,247,.07);border:1px solid rgba(168,85,247,.3);border-radius:4px;padding:10px 14px;margin:4px 0;font-family:'Share Tech Mono',monospace;font-size:.74rem;}
  .mitre-tid{color:var(--purple);font-weight:bold;min-width:90px;display:inline-block;}
  .mitre-name{color:var(--text);}
  .mitre-tactic{color:var(--dim);font-size:.65rem;}

  /* ── COMPARE TABLE ── */
  .cmp-table{width:100%;border-collapse:collapse;font-family:'Share Tech Mono',monospace;font-size:.76rem;}
  .cmp-table th{background:rgba(0,212,255,.07);color:var(--accent);padding:8px 12px;border:1px solid var(--border);text-align:center;}
  .cmp-table td{padding:7px 12px;border:1px solid rgba(13,79,110,.3);text-align:center;color:var(--text);}
  .cmp-table tr:hover td{background:rgba(0,212,255,.03);}
  .cmp-win{color:var(--red);font-weight:bold;}
  .cmp-field{color:var(--dim);text-align:left!important;}

  /* ── THREAT FEED ── */
  .feed-item{display:flex;gap:10px;padding:7px 0;border-bottom:1px solid rgba(13,79,110,.2);font-family:'Share Tech Mono',monospace;font-size:.73rem;animation:fadeIn .5s ease;}
  @keyframes fadeIn{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:translateX(0)}}
  .feed-time{color:var(--dim);min-width:60px;} .feed-ip{color:var(--accent);min-width:120px;}
  .feed-event{min-width:100px;} .feed-country{color:var(--dim);font-size:.68rem;}
  .feed-score{font-weight:bold;text-align:right;}

  /* ── QUICK TARGET BUTTONS ── */
  .qt-active>button{background:rgba(0,212,255,.15)!important;border-color:var(--green)!important;color:var(--green)!important;}
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_target(target: str) -> str:
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi  = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

def format_log(level: str, msg: str) -> str:
    t = datetime.now().strftime("%H:%M:%S")
    cls = {"INFO":"li","WARN":"lw","ERROR":"le2","OK":"ls"}.get(level,"li")
    return f'<div class="le"><span class="lt">[{t}]</span> <span class="{cls}">[{level}]</span> {msg}</div>'

def color_threat(val):
    if val > 70: return "color:#ff2d55;font-weight:bold"
    if val > 40: return "color:#ffaa00"
    return "color:#00ff88"

def threat_class(score: int) -> str:
    if score > 80: return "crit"
    if score > 60: return "hi"
    if score > 40: return "md"
    return "lo"

def risk_label(score: int) -> str:
    if score > 80: return "CRITICAL"
    if score > 60: return "HIGH"
    if score > 40: return "MEDIUM"
    return "LOW"

def get_confidence(has_abuse: bool, has_vt: bool) -> tuple:
    if has_abuse and has_vt:
        return "HIGH", "conf-high", "Real AbuseIPDB + VirusTotal data"
    if has_abuse or has_vt:
        return "MEDIUM", "conf-med", "Partial real API data"
    return "LOW", "conf-low", "Fully simulated — add API keys for real data"

def generate_history(n: int = 40) -> pd.DataFrame:
    countries = ["India","USA","China","Russia","Germany","Brazil","UK","France","Japan","Iran","Nigeria","Netherlands"]
    events = ["LOGIN","SCAN","PROBE","DOWNLOAD","UPLOAD","ATTACK","BRUTE_FORCE","SQL_INJECT","PORT_SCAN","C2_BEACON"]
    records = []
    for i in range(n):
        t = datetime.now() - timedelta(hours=i*1.4 + random.random())
        lat = random.uniform(-60, 75) if i % 6 == 0 else 20 + random.uniform(-12, 12)
        lon = random.uniform(-170,170) if i % 6 == 0 else 77 + random.uniform(-12, 12)
        records.append({
            "timestamp": t,
            "ip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "lat": round(max(-85,min(85,lat)), 4),
            "lon": round(lon, 4),
            "country": random.choice(countries),
            "threat": random.randint(0,100),
            "hour": t.hour,
            "event": random.choice(events),
            "scan_freq": random.randint(1,30),
        })
    return pd.DataFrame(records)

def generate_live_feed(n=20) -> list:
    countries = ["India","USA","China","Russia","Germany","Brazil","UK","France","Japan","Iran","Nigeria","Netherlands","Ukraine","Singapore"]
    events = ["LOGIN","SCAN","PROBE","ATTACK","BRUTE_FORCE","SQL_INJECT","PORT_SCAN","C2_BEACON","DOWNLOAD","EXPLOIT"]
    feed = []
    for i in range(n):
        t = datetime.now() - timedelta(seconds=i*18 + random.randint(0,10))
        score = random.randint(0,100)
        feed.append({
            "time": t.strftime("%H:%M:%S"),
            "ip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "event": random.choice(events),
            "country": random.choice(countries),
            "score": score,
        })
    return feed


# ═══════════════════════════════════════════════════════════════════════════════
# CACHED API LAYER
# ═══════════════════════════════════════════════════════════════════════════════

@st.cache_data(ttl=300, show_spinner=False)
def fetch_ip_info(target: str) -> dict:
    ip = resolve_target(target)
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
        if r.status_code == 200:
            d = r.json()
            d["_resolved_ip"] = ip
            return d
    except Exception:
        pass
    return {}

@st.cache_data(ttl=300, show_spinner=False)
def fetch_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"available": False}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "available": True,
                "score": d.get("abuseConfidenceScore", 0),
                "reports": d.get("totalReports", 0),
                "usage_type": d.get("usageType", ""),
                "is_datacenter": "hosting" in d.get("usageType","").lower() or "data center" in d.get("usageType","").lower(),
            }
    except Exception:
        pass
    return {"available": False}

@st.cache_data(ttl=300, show_spinner=False)
def fetch_virustotal(ip: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return {"available": False}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=8,
        )
        if r.status_code == 200:
            stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            total = sum(stats.values()) or 1
            mal = stats.get("malicious",0) + stats.get("suspicious",0)
            return {"available": True, "score": int((mal/total)*100), "stats": stats}
    except Exception:
        pass
    return {"available": False}


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def simulate_flags(ip: str) -> dict:
    rng = random.Random(sum(ord(c) for c in ip))
    return {
        "isVPN": rng.random() > 0.72,
        "isTor": rng.random() > 0.88,
        "isProxy": rng.random() > 0.78,
        "isBot": rng.random() > 0.82,
        "isDatacenter": rng.random() > 0.62,
        "reports": rng.randint(0, 500),
        "categories": rng.sample(
            ["Spam","Hacking","DDoS","Phishing","Port Scan","Brute Force","Malware","SSH Abuse","C2"],
            k=rng.randint(0, 3)
        ),
    }

def simulate_port_scan(ip: str) -> list:
    rng = random.Random(sum(ord(c) for c in ip) * 7)
    results = []
    for port, (service, risk_w, desc) in PORT_RISKS.items():
        r = rng.random()
        state = "OPEN" if r > 0.72 else "CLOSED" if r > 0.42 else "FILTERED"
        banner = ""
        if state == "OPEN":
            banners = {
                "SSH":"OpenSSH 8.2p1","HTTP":"nginx/1.18.0","HTTPS":"nginx/1.18.0",
                "FTP":"vsftpd 3.0.3","MySQL":"MySQL 8.0.27","RDP":"MS RDP 10.0",
                "Redis":"Redis 6.2.6","SMB":"Samba 4.13.2",
            }
            banner = banners.get(service,"")
        results.append({"port":port,"service":service,"state":state,"risk_w":risk_w,"desc":desc,"banner":banner})
    return results

def compute_port_risk_score(port_results: list) -> tuple:
    open_ports = [p for p in port_results if p["state"] == "OPEN"]
    total_weight = sum(p["risk_w"] for p in open_ports)
    capped = min(total_weight, 100)
    contribs = [(f"Port {p['port']} ({p['service']}) open", p["risk_w"]) for p in open_ports if p["risk_w"] >= 10]
    return capped, sorted(contribs, key=lambda x: -x[1])[:4]

def compute_geo_anomaly(ip_info: dict, history_df: pd.DataFrame) -> tuple:
    if history_df.empty:
        return 0, None
    last = history_df.sort_values("timestamp").iloc[-1]
    try:
        km = haversine_km(float(last["lat"]), float(last["lon"]),
                           float(ip_info.get("lat",0)), float(ip_info.get("lon",0)))
        score = min(100, int((km / 20000) * 100)) if km > GEO_JUMP_KM else 0
        return score, round(km, 1)
    except Exception:
        return 0, None

def count_risk_signals(ti_partial: dict, flags: dict) -> int:
    count = 0
    if ti_partial.get("abuse_score", 0) > 40: count += 1
    if ti_partial.get("vt_score", 0) > 30:    count += 1
    if ti_partial.get("port_score", 0) > 30:  count += 1
    if ti_partial.get("geo_score", 0) > 0:    count += 1
    if ti_partial.get("freq_score", 0) > 20:  count += 1
    if flags.get("isTor"):       count += 1
    if flags.get("isVPN"):       count += 1
    if flags.get("isProxy"):     count += 1
    if flags.get("isBot"):       count += 1
    if flags.get("isDatacenter"): count += 1
    return count

def correlated_threat_level(score: int, signals: int) -> tuple:
    if score > 60 or signals >= 4:
        return "HIGH", "corr-high"
    if score > 35 or signals >= 2:
        return "MEDIUM", "corr-med"
    return "LOW", "corr-low"

def build_threat_intel(ip: str, ip_info: dict, port_results: list, history_df: pd.DataFrame) -> dict:
    abuse_data = fetch_abuseipdb(ip)
    vt_data = fetch_virustotal(ip)
    flags = simulate_flags(ip)

    abuse_score = abuse_data["score"] if abuse_data.get("available") else int(flags["reports"] / 5)
    vt_score = vt_data["score"] if vt_data.get("available") else random.Random(sum(ord(c) for c in ip)+1).randint(0,60)
    port_score, port_xai = compute_port_risk_score(port_results)
    geo_score, km_dist = compute_geo_anomaly(ip_info, history_df)
    freq_score = random.Random(sum(ord(c) for c in ip)+2).randint(0,40)

    weights = {"abuse":0.30,"vt":0.20,"port":0.25,"geo":0.15,"freq":0.10}
    composite = (abuse_score*weights["abuse"] + vt_score*weights["vt"] +
                 port_score*weights["port"] + geo_score*weights["geo"] + freq_score*weights["freq"])
    final = min(100, int(composite))

    xai = [
        ("Abuse Report Score",     abuse_score, weights["abuse"]),
        ("VirusTotal Reputation",  vt_score,    weights["vt"]),
        ("Open Port Risk",         port_score,  weights["port"]),
        ("Geo Distance Anomaly",   geo_score,   weights["geo"]),
        ("Scan Frequency Anomaly", freq_score,  weights["freq"]),
    ]

    if abuse_data.get("available"):
        flags["isDatacenter"] = abuse_data.get("is_datacenter", False)
        flags["reports"] = abuse_data.get("reports", 0)

    confidence, conf_cls, conf_msg = get_confidence(
        abuse_data.get("available", False), vt_data.get("available", False))

    source = ("abuseipdb+vt" if abuse_data.get("available") and vt_data.get("available")
              else "abuseipdb" if abuse_data.get("available")
              else "virustotal" if vt_data.get("available")
              else "simulated")

    partial = {"abuse_score":abuse_score,"vt_score":vt_score,"port_score":port_score,"geo_score":geo_score,"freq_score":freq_score}
    signals = count_risk_signals(partial, flags)
    corr_level, corr_cls = correlated_threat_level(final, signals)

    return {
        "final_score":   final,
        "abuse_score":   abuse_score,
        "vt_score":      vt_score,
        "port_score":    port_score,
        "geo_score":     geo_score,
        "freq_score":    freq_score,
        "km_dist":       km_dist,
        "flags":         flags,
        "port_xai":      port_xai,
        "xai":           xai,
        "confidence":    confidence,
        "conf_cls":      conf_cls,
        "conf_msg":      conf_msg,
        "risk_level":    risk_label(final),
        "source":        source,
        "signals":       signals,
        "corr_level":    corr_level,
        "corr_cls":      corr_cls,
        "abuse_available": abuse_data.get("available", False),
        "vt_available":    vt_data.get("available", False),
    }

def predict_threat_category(ti: dict) -> str:
    s = ti["final_score"]
    f = ti["flags"]
    fc = sum([bool(f.get(k)) for k in ("isVPN","isTor","isProxy","isBot")])
    if s > 80 or f.get("isTor") or fc >= 3: return "CRITICAL THREAT"
    if s > 60 or fc >= 2: return "HIGH RISK"
    if s > 40 or fc >= 1: return "SUSPICIOUS"
    if s > 20: return "MONITOR"
    return "CLEAN"

def build_why_risky(ti: dict, ip_info: dict) -> list:
    rows = []
    for label, raw_score, weight in ti["xai"]:
        contribution = int(raw_score * weight)
        if contribution > 0:
            rows.append((label, contribution))
    f = ti["flags"]
    if f.get("isTor"):         rows.append(("Tor exit node detected",    30))
    if f.get("isVPN"):         rows.append(("VPN / anonymizer detected", 15))
    if f.get("isProxy"):       rows.append(("Proxy server detected",     12))
    if f.get("isBot"):         rows.append(("Automated bot activity",    10))
    if ip_info.get("hosting"): rows.append(("Datacenter / hosting IP",    8))
    rows.sort(key=lambda x: -x[1])
    return rows[:8]

def build_xai_reasoning(ti: dict, ip_info: dict) -> str:
    score = ti["final_score"]
    f = ti["flags"]
    parts = []
    if ti["abuse_score"] > 50:
        parts.append(f"High abuse confidence ({ti['abuse_score']}/100) suggests repeated malicious activity.")
    if ti["vt_score"] > 30:
        parts.append(f"VirusTotal score {ti['vt_score']}/100 — detected by security vendors.")
    if ti["port_score"] > 40:
        parts.append(f"Open high-risk ports contribute {ti['port_score']} risk points.")
    if ti["geo_score"] > 0:
        parts.append(f"Geographic anomaly: {ti.get('km_dist',0):,.0f} km from last known location.")
    if f.get("isTor"):
        parts.append("Known Tor exit node — identity concealment strongly indicated.")
    if f.get("isVPN"):
        parts.append("VPN/anonymizer detected — true origin masked.")
    if f.get("isBot"):
        parts.append("Automated bot behaviour detected.")
    if not parts:
        parts.append(f"Overall threat score {score}/100 — no single dominant risk factor.")
    return " ".join(parts)

def get_mitre_techniques(categories: list) -> list:
    techniques = []
    seen = set()
    for cat in categories:
        for tech in MITRE_TECHNIQUES.get(cat, []):
            if tech[0] not in seen:
                techniques.append(tech)
                seen.add(tech[0])
    return techniques

def build_report(ip_info: dict, ti: dict, port_results: list) -> dict:
    wh_seed = random.Random(sum(ord(c) for c in ip_info.get("query","x")))
    reg_date = (datetime.now() - timedelta(days=wh_seed.randint(180,3650))).strftime("%Y-%m-%d")
    return {
        "generated_at": datetime.now().isoformat(),
        "ip_intelligence": {
            "ip":       ip_info.get("query","N/A"),
            "hostname": ip_info.get("reverse","N/A"),
            "city":     ip_info.get("city","N/A"),
            "region":   ip_info.get("regionName","N/A"),
            "country":  ip_info.get("country","N/A"),
            "lat":      ip_info.get("lat","N/A"),
            "lon":      ip_info.get("lon","N/A"),
            "timezone": ip_info.get("timezone","N/A"),
            "isp":      ip_info.get("isp","N/A"),
            "org":      ip_info.get("org","N/A"),
            "as":       ip_info.get("as","N/A"),
        },
        "threat_intelligence": {
            "final_score": ti["final_score"],
            "abuse_score": ti["abuse_score"],
            "vt_score":    ti["vt_score"],
            "port_score":  ti["port_score"],
            "geo_score":   ti["geo_score"],
            "risk_level":  ti["risk_level"],
            "corr_level":  ti["corr_level"],
            "signals":     ti["signals"],
            "confidence":  ti["confidence"],
            "source":      ti["source"],
            "is_vpn":      ti["flags"].get("isVPN",False),
            "is_tor":      ti["flags"].get("isTor",False),
            "is_proxy":    ti["flags"].get("isProxy",False),
            "is_bot":      ti["flags"].get("isBot",False),
            "reports":     ti["flags"].get("reports",0),
            "categories":  ti["flags"].get("categories",[]),
        },
        "whois_sim": {
            "network":    ip_info.get("as","N/A"),
            "org":        ip_info.get("org","N/A"),
            "country":    ip_info.get("country","N/A"),
            "registered": reg_date,
        },
        "port_scan": [
            {"port":p["port"],"service":p["service"],"state":p["state"],"banner":p.get("banner","")}
            for p in port_results
        ],
    }

def report_to_csv(report: dict) -> str:
    rows = []
    for k,v in report["ip_intelligence"].items():
        rows.append({"section":"IP","field":k,"value":str(v)})
    for k,v in report["threat_intelligence"].items():
        rows.append({"section":"Threat","field":k,"value":str(v)})
    for p in report["port_scan"]:
        rows.append({"section":"Ports","field":f"{p['port']}/{p['service']}","value":p["state"]})
    return pd.DataFrame(rows).to_csv(index=False)


# ═══════════════════════════════════════════════════════════════════════════════
# ML ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def ml_anomaly_score(ip_info: dict, ti: dict, history_df: pd.DataFrame) -> tuple:
    if len(history_df) < 5:
        return 0, "INSUFFICIENT_DATA"
    features = history_df[["lat","lon","threat","scan_freq"]].dropna()
    if len(features) < 5:
        return 0, "INSUFFICIENT_DATA"
    try:
        clf = IsolationForest(contamination=0.2, random_state=42, n_estimators=60)
        clf.fit(features)
        row = np.array([[float(ip_info.get("lat",0)), float(ip_info.get("lon",0)),
                         float(ti["final_score"]), float(ti.get("freq_score",0)/3)]])
        raw = clf.score_samples(row)[0]
        score = max(0, min(100, int((-raw + 0.5) * 100)))
    except Exception:
        score = 0
    label = "HIGHLY ANOMALOUS" if score > 75 else "SUSPICIOUS" if score > 45 else "NORMAL"
    return score, label

def ml_cluster_analysis(df: pd.DataFrame) -> pd.DataFrame:
    if len(df) < 3:
        return df.assign(cluster=-1)
    coords = df[["lat","lon"]].dropna()
    if len(coords) < 3:
        return df.assign(cluster=-1)
    try:
        scaled = StandardScaler().fit_transform(coords)
        labels = DBSCAN(eps=0.5, min_samples=2).fit_predict(scaled)
        df = df.copy()
        df["cluster"] = -1
        df.loc[coords.index, "cluster"] = labels
    except Exception:
        df = df.copy()
        df["cluster"] = -1
    return df


# ═══════════════════════════════════════════════════════════════════════════════
# EVENT & BEHAVIOR ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def create_event(level: str, message: str) -> dict:
    return {"timestamp": datetime.now(), "level": level, "message": message}

def emit_scan_events(ip: str, ti: dict, ip_info: dict, port_results: list) -> list:
    events = []
    events.append(create_event("INFO", f"Scan initiated for {ip}"))
    events.append(create_event("INFO", f"Located: {ip_info.get('city','?')}, {ip_info.get('country','?')}"))
    score = ti["final_score"]
    if score > HIGH_THREAT_THRESHOLD:
        events.append(create_event("CRITICAL", f"HIGH THREAT DETECTED — score {score}/100 for {ip}"))
    elif score > 40:
        events.append(create_event("WARNING", f"Suspicious IP — score {score}/100"))
    else:
        events.append(create_event("INFO", f"Scan complete — score {score}/100 (nominal)"))
    open_high = [p for p in port_results if p["state"] == "OPEN" and p["port"] in HIGH_RISK_PORTS]
    if open_high:
        port_names = ", ".join(f"{p['port']}/{p['service']}" for p in open_high[:3])
        events.append(create_event("WARNING", f"High-risk open ports: {port_names}"))
    if ti["flags"].get("isTor"):
        events.append(create_event("CRITICAL", f"Tor exit node confirmed for {ip}"))
    if ti["flags"].get("isVPN"):
        events.append(create_event("WARNING", f"VPN/anonymizer detected for {ip}"))
    if ti["flags"].get("isBot"):
        events.append(create_event("WARNING", f"Bot activity flagged for {ip}"))
    if ti.get("geo_score", 0) > 0:
        events.append(create_event("WARNING", f"Geo anomaly: {ti.get('km_dist',0):,.0f} km jump"))
    return events

def analyze_behavior(tracked_ips: list, history_df: pd.DataFrame) -> list:
    insights = []
    if len(tracked_ips) >= 3:
        insights.append(f"Analyst has scanned {len(tracked_ips)} IPs in this session.")
    if not history_df.empty:
        high_risk = history_df[history_df["threat"] > 70]
        if len(high_risk) >= 3:
            insights.append(f"{len(high_risk)} high-risk events recorded — elevated threat environment.")
        country_counts = history_df["country"].value_counts()
        if len(country_counts) > 0:
            top_country = country_counts.index[0]
            top_count = int(country_counts.iloc[0])
            if top_count >= 5:
                insights.append(f"Activity cluster from {top_country} ({top_count} events) — possible targeted campaign.")
        recent = history_df[history_df["timestamp"] > datetime.now() - timedelta(hours=2)]
        if len(recent) >= 5:
            insights.append(f"{len(recent)} scans in last 2 hours — high-frequency recon pattern.")
        if "event" in history_df.columns:
            attack_events = history_df[history_df["event"].isin(["ATTACK","BRUTE_FORCE","SQL_INJECT","C2_BEACON"])]
            if len(attack_events) >= 2:
                insights.append(f"{len(attack_events)} offensive events — active attack chain possible.")
    if not insights:
        insights.append("Behavioral baseline normal — no anomalous patterns detected.")
    return insights

def render_event_stream(events: list) -> str:
    cls_map = {"INFO": "ev-info", "WARNING": "ev-warn", "CRITICAL": "ev-crit"}
    html = ""
    for ev in reversed(events[-30:]):
        t = ev["timestamp"].strftime("%H:%M:%S")
        cls = cls_map.get(ev["level"], "ev-info")
        html += (f'<div class="event-row">'
                 f'<span class="ev-time">[{t}]</span>'
                 f'<span class="{cls}">[{ev["level"]}]</span>'
                 f'<span class="ev-msg">&nbsp;{ev["message"]}</span></div>')
    return html or '<div class="event-row"><span class="ev-info">No events yet.</span></div>'


# ═══════════════════════════════════════════════════════════════════════════════
# VISUALIZATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

PLOTLY_BASE = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(7,21,32,.85)",
                   font_color="#c8e6f5", margin=dict(t=40,b=10,l=10,r=10))
GRID = dict(gridcolor="#0d4f6e", color="#4a7a9b")

def make_map(ip_info: dict, history_df: pd.DataFrame, ti: dict) -> folium.Map:
    lat = float(ip_info.get("lat", 20))
    lon = float(ip_info.get("lon", 0))
    m = folium.Map(location=[lat,lon], zoom_start=4, tiles=None)
    folium.TileLayer("CartoDB dark_matter", name="Dark", attr="CartoDB").add_to(m)
    try:
        from folium.plugins import HeatMap
        heat_data = [[row["lat"],row["lon"],row["threat"]/100]
                     for _,row in history_df.iterrows() if not pd.isna(row["lat"])]
        if heat_data:
            HeatMap(heat_data, radius=18, gradient={0.4:"#00d4ff",0.65:"#ffaa00",1:"#ff2d55"}, name="Heatmap").add_to(m)
    except Exception:
        pass
    for _, row in history_df.iterrows():
        c = "#ff2d55" if row["threat"]>70 else "#ffaa00" if row["threat"]>40 else "#00ff88"
        folium.CircleMarker([row["lat"],row["lon"]], radius=4, color=c,
                            fill=True, fill_color=c, fill_opacity=0.5,
                            tooltip=f"{row['ip']} | {row['country']} | T:{row['threat']}").add_to(m)
    ts = ti.get("final_score", 0) if ti else 0
    mc = "red" if ts>70 else "orange" if ts>40 else "green"
    rc = "#ff2d55" if ts>70 else "#ffaa00" if ts>40 else "#00ff88"
    radius = int(30000 + ts * 2000)
    folium.Marker(
        [lat, lon],
        popup=folium.Popup(
            f"<div style='font-family:monospace;background:#000;color:#00d4ff;padding:10px;border-radius:4px;min-width:190px'>"
            f"<b style='color:#00ff88'>TARGET</b><br>IP: {ip_info.get('query','N/A')}<br>"
            f"City: {ip_info.get('city','N/A')}<br>ISP: {ip_info.get('isp','N/A')}<br>"
            f"Threat: <b style='color:#ff2d55'>{ts}/100</b></div>", max_width=280),
        tooltip=f"TARGET {ip_info.get('query','?')} | Threat: {ts}",
        icon=folium.Icon(color=mc, icon="info-sign"),
    ).add_to(m)
    for r, op in [(radius,0.7),(radius*2,0.4),(radius*3,0.15)]:
        folium.Circle([lat,lon], radius=r, color=rc, fill=False, weight=2, opacity=op).add_to(m)
    folium.LayerControl().add_to(m)
    return m

def chart_threat_ring_svg(score: int) -> str:
    """Animated SVG ring for threat score."""
    tc = threat_class(score)
    color_map = {"crit":"#ff0033","hi":"#ff2d55","md":"#ffaa00","lo":"#00ff88"}
    color = color_map.get(tc, "#00d4ff")
    cat = predict_threat_category({"final_score":score,"flags":{}}) if score > 0 else "N/A"
    circumference = 2 * math.pi * 54
    dash = circumference * score / 100
    gap = circumference - dash
    return f"""
    <div style="display:flex;justify-content:center;align-items:center;padding:10px 0;">
      <div style="position:relative;width:140px;height:140px;">
        <svg width="140" height="140" viewBox="0 0 140 140">
          <circle cx="70" cy="70" r="54" fill="none" stroke="rgba(13,79,110,.4)" stroke-width="10"/>
          <circle cx="70" cy="70" r="54" fill="none" stroke="{color}" stroke-width="10"
            stroke-dasharray="{dash:.1f} {gap:.1f}"
            stroke-linecap="round"
            transform="rotate(-90 70 70)"
            style="filter:drop-shadow(0 0 6px {color});transition:stroke-dasharray 1s ease;">
            <animate attributeName="stroke-dasharray" 
              from="0 {circumference:.1f}" to="{dash:.1f} {gap:.1f}" 
              dur="1.2s" fill="freeze" calcMode="spline" keySplines="0.4 0 0.2 1"/>
          </circle>
          <text x="70" y="62" text-anchor="middle" 
            font-family="Orbitron,monospace" font-size="28" font-weight="900" 
            fill="{color}" style="filter:drop-shadow(0 0 4px {color})">{score}</text>
          <text x="70" y="80" text-anchor="middle" 
            font-family="Share Tech Mono,monospace" font-size="8" fill="#4a7a9b" letter-spacing="1">/100</text>
          <text x="70" y="100" text-anchor="middle" 
            font-family="Share Tech Mono,monospace" font-size="7.5" fill="{color}" letter-spacing="1">{tc.upper()}</text>
        </svg>
      </div>
    </div>"""

def chart_threat_timeline(df):
    df2 = df.sort_values("timestamp")
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df2["timestamp"], y=df2["threat"],
        fill="tozeroy", fillcolor="rgba(255,45,85,.08)",
        line=dict(color="#ff2d55",width=2), name="Threat"))
    fig.add_hline(y=70, line_dash="dash", line_color="#ffaa00",
                  annotation_text="HIGH", annotation_font_color="#ffaa00")
    fig.update_layout(**PLOTLY_BASE, title="Threat Level Timeline", height=290,
                      xaxis=dict(**GRID), yaxis=dict(**GRID, range=[0,105]))
    return fig

def chart_countries(df):
    cc = df["country"].value_counts().head(10)
    fig = go.Figure(go.Bar(x=cc.values, y=cc.index, orientation="h",
        marker=dict(color=cc.values, colorscale=[[0,"#00d4ff"],[0.5,"#ffaa00"],[1,"#ff2d55"]], showscale=False)))
    fig.update_layout(**PLOTLY_BASE, title="Top Countries", height=290,
                      xaxis=dict(**GRID), yaxis=dict(color="#c8e6f5"))
    return fig

def chart_events(df):
    ec = df["event"].value_counts()
    fig = go.Figure(go.Pie(labels=ec.index, values=ec.values, hole=0.5,
        marker=dict(colors=["#00d4ff","#ff2d55","#ffaa00","#00ff88","#a855f7","#f97316","#22d3ee","#fb7185"]),
        textfont=dict(family="Share Tech Mono",size=11), textinfo="label+percent"))
    fig.update_layout(**PLOTLY_BASE, title="Event Distribution", height=290)
    return fig

def chart_hourly(df):
    df2 = df.copy()
    df2["hour_num"] = pd.to_datetime(df2["timestamp"]).dt.hour
    hourly = df2.groupby("hour_num")["threat"].mean().reindex(range(24), fill_value=0)
    fig = go.Figure(go.Bar(x=list(range(24)), y=hourly.values,
        marker=dict(color=hourly.values,
                    colorscale=[[0,"#00d4ff"],[0.5,"#ffaa00"],[1,"#ff2d55"]], showscale=False)))
    fig.update_layout(**PLOTLY_BASE, title="Avg Threat by Hour (UTC)", height=290,
                      xaxis=dict(**GRID, title="Hour"), yaxis=dict(**GRID))
    return fig

def chart_histogram(df):
    fig = go.Figure(go.Histogram(x=df["threat"], nbinsx=20, opacity=0.85,
        marker=dict(color=df["threat"],
                    colorscale=[[0,"#00ff88"],[0.5,"#ffaa00"],[1,"#ff2d55"]], showscale=False)))
    fig.update_layout(**PLOTLY_BASE, title="Threat Score Distribution", height=260,
                      xaxis=dict(**GRID, title="Score"), yaxis=dict(**GRID, title="Count"))
    return fig

def chart_heatmap_geo(df):
    fig = px.density_mapbox(df, lat="lat", lon="lon", z="threat",
        radius=28, zoom=1, center={"lat":20,"lon":0},
        color_continuous_scale=["#00d4ff","#ffaa00","#ff2d55"],
        mapbox_style="open-street-map")
    fig.update_layout(**PLOTLY_BASE, height=420,
                      coloraxis_colorbar=dict(tickfont=dict(color="#c8e6f5")))
    return fig

def chart_ml_gauge(score: int, label: str):
    color_map = {"HIGHLY ANOMALOUS":"#ff0033","SUSPICIOUS":"#ffaa00",
                 "NORMAL":"#00ff88","INSUFFICIENT_DATA":"#4a7a9b"}
    c = color_map.get(label,"#00d4ff")
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        title={"text":f"ANOMALY | {label}","font":{"color":"#00d4ff","family":"Share Tech Mono","size":12}},
        gauge={"axis":{"range":[0,100],"tickcolor":"#4a7a9b"},"bar":{"color":c},
               "bgcolor":"#071520","bordercolor":"#0d4f6e",
               "steps":[{"range":[0,45],"color":"rgba(0,255,136,.08)"},
                         {"range":[45,75],"color":"rgba(255,170,0,.08)"},
                         {"range":[75,100],"color":"rgba(255,0,51,.12)"}],
               "threshold":{"line":{"color":c,"width":3},"thickness":0.8,"value":score}},
        number={"font":{"color":c,"family":"Orbitron"}}))
    fig.update_layout(**PLOTLY_BASE, height=280)
    return fig

def chart_radar(ti: dict):
    cats = ["Abuse","VirusTotal","Port Risk","Geo Anomaly","Freq Anomaly"]
    vals = [ti["abuse_score"],ti["vt_score"],ti["port_score"],ti["geo_score"],ti["freq_score"]]
    fig = go.Figure(go.Scatterpolar(
        r=vals+[vals[0]], theta=cats+[cats[0]],
        fill="toself", fillcolor="rgba(255,45,85,.12)",
        line=dict(color="#ff2d55",width=2)))
    fig.update_layout(
        polar=dict(bgcolor="rgba(7,21,32,.8)",
                   radialaxis=dict(visible=True,range=[0,100],gridcolor="#0d4f6e",color="#4a7a9b"),
                   angularaxis=dict(gridcolor="#0d4f6e",color="#c8e6f5")),
        paper_bgcolor="rgba(0,0,0,0)",font_color="#c8e6f5",showlegend=False,height=280,
        margin=dict(t=40,b=10,l=10,r=10))
    return fig

def chart_threat_score_history(records: list):
    df = pd.DataFrame(records)
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["timestamp"], y=df["score"],
        mode="lines+markers+text", text=df["ip"], textposition="top center",
        line=dict(color="#00d4ff",width=2),
        marker=dict(size=8,color=df["score"],
                    colorscale=[[0,"#00ff88"],[0.5,"#ffaa00"],[1,"#ff2d55"]],showscale=True)))
    fig.add_hline(y=70,line_dash="dash",line_color="#ff2d55",annotation_text="HIGH",annotation_font_color="#ff2d55")
    fig.add_hline(y=40,line_dash="dash",line_color="#ffaa00",annotation_text="MED",annotation_font_color="#ffaa00")
    fig.update_layout(**PLOTLY_BASE, height=280,
                      xaxis=dict(**GRID), yaxis=dict(**GRID, range=[0,105]))
    return fig

def chart_network_topology(ip_info: dict, ti: dict, port_results: list):
    """Network topology graph showing the target and its connections."""
    open_ports = [p for p in port_results if p["state"] == "OPEN"]

    node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
    edge_x, edge_y = [], []

    # Center: target IP
    node_x.append(0); node_y.append(0)
    score = ti["final_score"]
    c = "#ff0033" if score>80 else "#ff2d55" if score>60 else "#ffaa00" if score>40 else "#00ff88"
    node_text.append(f"TARGET<br>{ip_info.get('query','?')}<br>Score: {score}")
    node_color.append(c); node_size.append(30)

    # Satellites: open ports
    n = len(open_ports)
    for i, p in enumerate(open_ports[:8]):
        angle = (2 * math.pi * i) / max(n, 1)
        r = 1.8
        px2 = r * math.cos(angle); py2 = r * math.sin(angle)
        node_x.append(px2); node_y.append(py2)
        pc = "#ff2d55" if p["risk_w"]>=35 else "#ffaa00" if p["risk_w"]>=20 else "#00d4ff"
        node_text.append(f":{p['port']}<br>{p['service']}<br>Risk:{p['risk_w']}")
        node_color.append(pc); node_size.append(16)
        edge_x += [0, px2, None]; edge_y += [0, py2, None]

    # Threat actors (flags)
    flag_nodes = []
    if ti["flags"].get("isTor"):    flag_nodes.append(("TOR EXIT", "#a855f7", 2.8, 0.5))
    if ti["flags"].get("isVPN"):    flag_nodes.append(("VPN", "#f97316", 2.8, 1.1))
    if ti["flags"].get("isProxy"):  flag_nodes.append(("PROXY", "#fb7185", 2.8, 1.7))
    if ti["flags"].get("isBot"):    flag_nodes.append(("BOT", "#ffd700", 2.8, 2.3))
    for label, clr, r, a in flag_nodes:
        px2 = r * math.cos(a); py2 = r * math.sin(a)
        node_x.append(px2); node_y.append(py2)
        node_text.append(label); node_color.append(clr); node_size.append(20)
        edge_x += [0, px2, None]; edge_y += [0, py2, None]

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines",
        line=dict(width=1, color="rgba(0,212,255,.25)"), hoverinfo="none"))
    fig.add_trace(go.Scatter(x=node_x, y=node_y, mode="markers+text",
        marker=dict(size=node_size, color=node_color,
                    line=dict(width=1, color="rgba(0,212,255,.4)"),
                    symbol="circle"),
        text=node_text, textposition="top center",
        textfont=dict(family="Share Tech Mono", size=9, color="#c8e6f5"),
        hoverinfo="text"))
    fig.update_layout(
        **PLOTLY_BASE, height=360,
        title="Network Topology — Target & Relationships",
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    )
    return fig

def chart_score_waterfall(ti: dict):
    """Waterfall chart showing score component contributions."""
    labels = ["Base", "Abuse", "VirusTotal", "Port Risk", "Geo Anomaly", "Freq", "Total"]
    base = 0
    abuse_c  = int(ti["abuse_score"] * 0.30)
    vt_c     = int(ti["vt_score"] * 0.20)
    port_c   = int(ti["port_score"] * 0.25)
    geo_c    = int(ti["geo_score"] * 0.15)
    freq_c   = int(ti["freq_score"] * 0.10)
    total    = ti["final_score"]
    values   = [base, abuse_c, vt_c, port_c, geo_c, freq_c, total]
    measures = ["absolute","relative","relative","relative","relative","relative","total"]
    colors   = ["#4a7a9b","#ff2d55","#ff2d55","#ff2d55","#ffaa00","#00d4ff","#00ff88"]
    fig = go.Figure(go.Waterfall(
        name="Score", orientation="v",
        measure=measures, x=labels, y=values,
        connector={"line":{"color":"rgba(0,212,255,.3)","width":1}},
        increasing={"marker":{"color":"#ff2d55","line":{"color":"#ff0033","width":1}}},
        totals={"marker":{"color":"#00ff88","line":{"color":"#00ff88","width":1}}},
        text=[str(v) for v in values],
        textposition="outside",
        textfont={"color":"#c8e6f5","family":"Share Tech Mono"},
    ))
    fig.update_layout(**PLOTLY_BASE, height=300,
                      title="Score Component Breakdown",
                      xaxis=dict(**GRID), yaxis=dict(**GRID, range=[0,110]))
    return fig

def chart_compare_radar(ti1: dict, ip1: str, ti2: dict, ip2: str):
    cats = ["Abuse","VirusTotal","Port Risk","Geo Anomaly","Freq Anomaly"]
    v1 = [ti1["abuse_score"],ti1["vt_score"],ti1["port_score"],ti1["geo_score"],ti1["freq_score"]]
    v2 = [ti2["abuse_score"],ti2["vt_score"],ti2["port_score"],ti2["geo_score"],ti2["freq_score"]]
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(r=v1+[v1[0]], theta=cats+[cats[0]],
        fill="toself", fillcolor="rgba(255,45,85,.15)",
        line=dict(color="#ff2d55",width=2), name=ip1))
    fig.add_trace(go.Scatterpolar(r=v2+[v2[0]], theta=cats+[cats[0]],
        fill="toself", fillcolor="rgba(0,212,255,.12)",
        line=dict(color="#00d4ff",width=2), name=ip2))
    fig.update_layout(
        polar=dict(bgcolor="rgba(7,21,32,.8)",
                   radialaxis=dict(visible=True,range=[0,100],gridcolor="#0d4f6e",color="#4a7a9b"),
                   angularaxis=dict(gridcolor="#0d4f6e",color="#c8e6f5")),
        paper_bgcolor="rgba(0,0,0,0)",font_color="#c8e6f5",height=320,
        legend=dict(font=dict(family="Share Tech Mono",size=10)),
        margin=dict(t=40,b=10,l=10,r=10))
    return fig


# ═══════════════════════════════════════════════════════════════════════════════
# UI COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════

def ui_metric(label, value, variant=""):
    st.markdown(f'<div class="mc {variant}"><div class="ml">{label}</div><div class="mv">{value}</div></div>',
                unsafe_allow_html=True)

def ui_section(title):
    st.markdown(f'<div class="sh">{title}</div>', unsafe_allow_html=True)

def ui_alert(msg, level="hi"):
    icons = {"hi":"[!]","md":"[?]","lo":"[OK]"}
    st.markdown(f'<div class="ab {level}">{icons.get(level,">")} {msg}</div>', unsafe_allow_html=True)

def ui_info_panel(rows: list):
    inner = "".join(f'<span class="lb">{l} :</span> <span class="{c}">{v}</span><br>' for l,v,c in rows)
    st.markdown(f'<div class="ip">{inner}</div>', unsafe_allow_html=True)

def ui_xai_panel(why_rows: list):
    rows_html = "".join(
        f'<div class="xai-row"><span class="xai-label">{r}</span><span class="xai-pos">+{d}</span></div>'
        for r,d in why_rows)
    st.markdown(f'<div class="xai">{rows_html}</div>', unsafe_allow_html=True)

def ui_copilot_response(label: str, content: str):
    st.markdown(f'<div class="cb"><div class="bl">AI [{label}]</div>{content}</div>', unsafe_allow_html=True)

def ui_user_message(msg: str):
    st.markdown(f'<div class="cu">USER: {msg}</div>', unsafe_allow_html=True)

def ui_leaderboard(df: pd.DataFrame):
    top = df.nlargest(10, "threat")[["ip","country","threat"]].reset_index(drop=True)
    for i, row in top.iterrows():
        sc = "color:#ff2d55" if row["threat"]>70 else "color:#ffaa00" if row["threat"]>40 else "color:#00ff88"
        st.markdown(
            f'<div class="lb-row"><span class="lb-num">#{i+1}</span>'
            f'<span class="lb-ip">{row["ip"]}</span>'
            f'<span style="color:var(--dim);font-size:.72rem">{row["country"]}</span>'
            f'<span class="lb-score" style="{sc}">{row["threat"]}</span></div>',
            unsafe_allow_html=True)

def ui_alert_banner(score: int, ip: str):
    if score >= HIGH_THREAT_THRESHOLD:
        st.markdown(
            f'<div class="alert-banner">'
            f'<span class="blink-red"></span>'
            f'⚠ CRITICAL ALERT — IP {ip} scored {score}/100. Immediate action recommended. '
            f'Block at perimeter firewall and escalate to SOC team.'
            f'</div>',
            unsafe_allow_html=True)

def ui_correlated_level(corr_level, corr_cls, signals):
    st.markdown(
        f'<div style="margin:8px 0;font-family:Share Tech Mono,monospace;font-size:.8rem;color:var(--dim)">'
        f'CORRELATED THREAT LEVEL: '
        f'<span class="signals-badge {corr_cls}">{corr_level}</span>'
        f'&nbsp;&nbsp;RISK SIGNALS: '
        f'<span class="signals-badge {corr_cls}">{signals} triggered</span>'
        f'</div>',
        unsafe_allow_html=True)

def ui_data_sources(has_abuse, has_vt):
    abuse_icon = '<span class="src-ok">✔</span>' if has_abuse else '<span class="src-miss">✖</span>'
    vt_icon    = '<span class="src-ok">✔</span>' if has_vt    else '<span class="src-miss">✖</span>'
    geo_icon   = '<span class="src-ok">✔</span>'
    st.markdown(
        f'<div class="ip" style="font-size:.75rem;padding:10px 14px">'
        f'<span class="lb">DATA SOURCES</span><br>'
        f'{abuse_icon} AbuseIPDB &nbsp;&nbsp; {vt_icon} VirusTotal &nbsp;&nbsp; {geo_icon} GeoIP (ip-api)'
        f'</div>',
        unsafe_allow_html=True)

def ui_decision_panel(ti: dict):
    score = ti["final_score"]
    corr_level = ti.get("corr_level", "LOW")
    if corr_level == "HIGH" or score > 60:
        level_cls = "high"
        title = "⛔ HIGH RISK — IMMEDIATE ACTION REQUIRED"
        actions = [
            "→ Block IP at perimeter firewall (deny all inbound/outbound)",
            "→ Add to SIEM/SOAR blocklist immediately",
            "→ Review all historical sessions from this IP",
            "→ Geo-block origin country if applicable",
            "→ Escalate to SOC Tier 2 for investigation",
            "→ Preserve logs for forensic analysis",
        ]
    elif corr_level == "MEDIUM" or score > 35:
        level_cls = "medium"
        title = "⚠ MEDIUM RISK — MONITOR & INVESTIGATE"
        actions = [
            "→ Add IP to watchlist for 24-hour monitoring",
            "→ Enable enhanced logging for this source",
            "→ Rate-limit connections from this IP",
            "→ Verify if IP belongs to known partner/vendor",
            "→ Alert on repeat activity within 6 hours",
        ]
    else:
        level_cls = "low"
        title = "✔ LOW RISK — STANDARD MONITORING"
        actions = [
            "→ No immediate action required",
            "→ Continue standard baseline monitoring",
            "→ Log for future reference",
        ]
    items_html = "".join(f'<div class="decision-item">{a}</div>' for a in actions)
    st.markdown(
        f'<div class="decision-panel {level_cls}">'
        f'<div class="decision-title {level_cls}">{title}</div>'
        f'{items_html}</div>',
        unsafe_allow_html=True)

def ui_behavior_insights(insights: list):
    for insight in insights:
        st.markdown(f'<div class="behavior-insight">🔍 {insight}</div>', unsafe_allow_html=True)

def ui_threat_ticker(history_df: pd.DataFrame):
    """Scrolling live threat ticker."""
    high_risk = history_df[history_df["threat"] > 60].tail(20)
    items = []
    for _, row in high_risk.iterrows():
        items.append(f"⚠ {row['ip']} [{row['country']}] — {row['event']} — SCORE: {row['threat']}")
    if not items:
        items = ["✔ No critical threats detected in current session"]
    doubled = items * 2  # loop seamlessly
    spans = "".join(f"<span>{item}</span>" for item in doubled)
    st.markdown(
        f'<div class="ticker-wrap"><div class="ticker">{spans}</div></div>',
        unsafe_allow_html=True)

def ui_mitre_panel(categories: list):
    techniques = get_mitre_techniques(categories)
    if not techniques:
        st.markdown('<div class="ip" style="font-size:.76rem;color:var(--dim)">No MITRE ATT&CK techniques mapped — scan categories empty.</div>', unsafe_allow_html=True)
        return
    for tid, name, tactic in techniques:
        st.markdown(
            f'<div class="mitre-card">'
            f'<span class="mitre-tid">{tid}</span>'
            f'<span class="mitre-name">{name}</span>'
            f'<span class="mitre-tactic"> — {tactic}</span>'
            f'</div>',
            unsafe_allow_html=True)

def ui_live_feed(feed: list):
    html = ""
    for item in feed[:15]:
        c = "#ff2d55" if item["score"]>70 else "#ffaa00" if item["score"]>40 else "#00ff88"
        html += (f'<div class="feed-item">'
                 f'<span class="feed-time">{item["time"]}</span>'
                 f'<span class="feed-ip">{item["ip"]}</span>'
                 f'<span class="feed-event" style="color:{c}">{item["event"]}</span>'
                 f'<span class="feed-country">{item["country"]}</span>'
                 f'<span class="feed-score" style="color:{c}">{item["score"]}</span>'
                 f'</div>')
    st.markdown(f'<div class="term" style="height:320px">{html}</div>', unsafe_allow_html=True)

def ui_compare_table(ti1: dict, ip1: str, ti2: dict, ip2: str):
    fields = [
        ("Final Score",   ti1["final_score"],   ti2["final_score"]),
        ("Abuse Score",   ti1["abuse_score"],    ti2["abuse_score"]),
        ("VT Score",      ti1["vt_score"],       ti2["vt_score"]),
        ("Port Risk",     ti1["port_score"],     ti2["port_score"]),
        ("Geo Anomaly",   ti1["geo_score"],      ti2["geo_score"]),
        ("Risk Signals",  ti1.get("signals",0),  ti2.get("signals",0)),
        ("Corr. Level",   ti1.get("corr_level","?"), ti2.get("corr_level","?")),
        ("Risk Level",    ti1["risk_level"],     ti2["risk_level"]),
    ]
    rows_html = ""
    for label, v1, v2 in fields:
        try:
            w1 = "cmp-win" if float(v1) > float(v2) else ""
            w2 = "cmp-win" if float(v2) > float(v1) else ""
        except:
            w1 = w2 = ""
        rows_html += f'<tr><td class="cmp-field">{label}</td><td class="{w1}">{v1}</td><td class="{w2}">{v2}</td></tr>'
    st.markdown(
        f'<table class="cmp-table">'
        f'<thead><tr><th>METRIC</th><th>{ip1}</th><th>{ip2}</th></tr></thead>'
        f'<tbody>{rows_html}</tbody></table>',
        unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# AI COPILOT
# ═══════════════════════════════════════════════════════════════════════════════

def rule_based_answer(q: str, ip_info: dict, ti: dict) -> str:
    q2 = q.lower()
    ip = ip_info.get("query","the target")
    ts = ti["final_score"]; rl = ti["risk_level"]; f = ti["flags"]
    if any(w in q2 for w in ["dangerous","safe","risky","threat","malicious"]):
        if ts > 70:
            return (f"[ANALYSIS] {ip} threat score {ts}/100 — {rl}. "
                    "Key factors: high abuse score, flagged anonymizer. "
                    "ACTION: Block at firewall, audit all past connections.")
        if ts > 40:
            return f"[ANALYSIS] {ip} score {ts}/100 — {rl}. Monitor and consider rate-limiting."
        return f"[ANALYSIS] {ip} score {ts}/100 — {rl}. No immediate action required."
    if any(w in q2 for w in ["block","firewall","mitigate","defend"]):
        return (f"[MITIGATION] For {ip} (score {ts}):\n"
                "1. Add deny rule at perimeter firewall.\n"
                "2. Add to SIEM blocklist.\n"
                "3. Review historical logs.\n"
                "4. Geo-block origin country if applicable.")
    if any(w in q2 for w in ["vpn","tor","proxy","anon"]):
        active = [k.replace("is","").upper() for k in ("isVPN","isTor","isProxy") if f.get(k)]
        if active:
            return f"[FLAGS] {ip} detected as: {', '.join(active)}. Treat as untrusted."
        return f"[FLAGS] No VPN/Tor/Proxy flags for {ip}."
    if any(w in q2 for w in ["location","country","where","geo"]):
        return (f"[GEO] {ip} => {ip_info.get('city','?')}, {ip_info.get('country','?')} | "
                f"ISP: {ip_info.get('isp','?')}")
    if any(w in q2 for w in ["port","open","scan"]):
        return "[PORTS] Check the Port Analyzer tab for detailed results."
    if any(w in q2 for w in ["mitre","attack","technique","ttp"]):
        cats = f.get("categories", [])
        techs = get_mitre_techniques(cats)
        if techs:
            return "[MITRE] Mapped techniques: " + ", ".join(f"{t[0]} ({t[1]})" for t in techs)
        return "[MITRE] No specific techniques mapped — check THREAT INTEL tab."
    return (f"[COPILOT] I can explain threat scores, suggest mitigations, describe flags, or map MITRE techniques. "
            "Try: 'Is this IP dangerous?' or 'What MITRE techniques apply?'")

def openai_answer(q: str, ip_info: dict, ti: dict) -> str:
    ctx = (f"IP={ip_info.get('query')}, Country={ip_info.get('country')}, "
           f"ThreatScore={ti['final_score']}/100, Risk={ti['risk_level']}, "
           f"Signals={ti.get('signals',0)}, VPN={ti['flags'].get('isVPN')}, "
           f"Tor={ti['flags'].get('isTor')}, Categories={ti['flags'].get('categories',[])},"
           f"Confidence={ti['confidence']}")
    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization":f"Bearer {OPENAI_KEY}","Content-Type":"application/json"},
            json={"model":"gpt-3.5-turbo",
                  "messages":[
                      {"role":"system","content":"You are CyberTrack AI — a concise, professional cybersecurity analyst. Give actionable, specific responses under 200 words."},
                      {"role":"user","content":f"Context: {ctx}\n\nQuestion: {q}"}],
                  "max_tokens":280,"temperature":0.35},
            timeout=15)
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"].strip()
        return f"[OpenAI {r.status_code}] " + rule_based_answer(q, ip_info, ti)
    except Exception:
        return rule_based_answer(q, ip_info, ti)

def ask_copilot(q: str, ip_info: dict, ti: dict) -> str:
    if not ip_info or ip_info.get("status") != "success":
        return "[COPILOT] Scan an IP first to provide analysis context."
    return openai_answer(q, ip_info, ti) if OPENAI_KEY else rule_based_answer(q, ip_info, ti)


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ═══════════════════════════════════════════════════════════════════════════════

_defaults = {
    "history":        lambda: generate_history(40),
    "logs":           lambda: [
        format_log("OK","CyberTrack v6.0 initialized"),
        format_log("INFO",f"APIs: AbuseIPDB={'LIVE' if ABUSEIPDB_KEY else 'MOCK'} | VT={'LIVE' if VIRUSTOTAL_KEY else 'MOCK'} | OpenAI={'LIVE' if OPENAI_KEY else 'RULE-BASED'}"),
        format_log("OK","ML engine ready (IsolationForest + DBSCAN)"),
        format_log("OK","Event & Behavior engine ready"),
        format_log("OK","MITRE ATT&CK mapper loaded"),
        format_log("OK","IP Comparison engine ready"),
    ],
    "tracked_ips":    list,
    "ip_info":        dict,
    "ti":             dict,
    "port_cache":     dict,
    "batch_results":  list,
    "threat_history": list,
    "chat_history":   list,
    "anomaly_count":  lambda: 0,
    "event_stream":   list,
    # NEW v6
    "compare_slots":  lambda: [{}, {}],   # [{ip_info, ti}, {ip_info, ti}]
    "pending_scan":   lambda: "",         # queued target from Quick Targets
}
for k, f in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = f()


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN HELPER — extracted so both button and quick-target can invoke it
# ═══════════════════════════════════════════════════════════════════════════════

def do_scan(target_input: str, enable_ports: bool, enable_ml: bool):
    """Run a full scan and update session state."""
    with st.spinner(f"Scanning {target_input}..."):
        st.session_state.logs.append(format_log("INFO", f"Scan: {target_input}"))
        st.session_state.event_stream.append(create_event("INFO", f"Scan initiated for {target_input}"))
        ip_data = fetch_ip_info(target_input)
        if ip_data and ip_data.get("status") == "success":
            resolved = ip_data.get("_resolved_ip", target_input)
            port_res = simulate_port_scan(resolved) if enable_ports else []
            ti = build_threat_intel(resolved, ip_data, port_res, st.session_state.history)
            st.session_state.ip_info = ip_data
            st.session_state.ti = ti
            if enable_ports:
                st.session_state.port_cache[resolved] = port_res

            new_events = emit_scan_events(resolved, ti, ip_data, port_res)
            st.session_state.event_stream.extend(new_events)

            if resolved not in st.session_state.tracked_ips:
                st.session_state.tracked_ips.append(resolved)

            new_row = pd.DataFrame([{
                "timestamp": datetime.now(), "ip": ip_data.get("query",target_input),
                "lat": float(ip_data.get("lat",0)), "lon": float(ip_data.get("lon",0)),
                "country": ip_data.get("country","Unknown"), "threat": ti["final_score"],
                "hour": datetime.now().hour, "event": "SCAN", "scan_freq": 1,
            }])
            st.session_state.history = pd.concat([st.session_state.history, new_row], ignore_index=True)
            st.session_state.threat_history.append({
                "timestamp": datetime.now(), "ip": ip_data.get("query",target_input), "score": ti["final_score"]})

            ml_score, ml_label = ml_anomaly_score(ip_data, ti, st.session_state.history) if enable_ml else (0,"N/A")
            if ml_label in ("HIGHLY ANOMALOUS","SUSPICIOUS"):
                st.session_state.anomaly_count += 1
                st.session_state.event_stream.append(create_event("WARNING", f"ML anomaly: {resolved} — {ml_label}"))

            ts = ti["final_score"]
            st.session_state.logs.append(format_log("OK", f"Located: {ip_data.get('city')}, {ip_data.get('country')}"))
            st.session_state.logs.append(format_log("INFO", f"Score: {ts}/100 | Conf: {ti['confidence']} | Src: {ti['source']}"))
            if ts > 60:
                st.session_state.logs.append(format_log("ERROR", f"HIGH THREAT: {ts}/100"))
                st.session_state.event_stream.append(create_event("CRITICAL", f"Alert: {ts}/100 for {resolved}"))
            elif ts > 30:
                st.session_state.logs.append(format_log("WARN", f"Moderate: {ts}/100"))
            else:
                st.session_state.logs.append(format_log("OK", f"Nominal: {ts}/100"))
        else:
            st.session_state.logs.append(format_log("ERROR", f"Failed: {target_input}"))
            st.session_state.event_stream.append(create_event("WARNING", f"Failed to resolve {target_input}"))
            st.error(f"Could not resolve {target_input}.")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APP
# ═══════════════════════════════════════════════════════════════════════════════

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="cyber-header">
  <div class="cyber-title">CYBERTRACK <span class="version-badge">v6.0</span></div>
  <div class="cyber-sub">AI-POWERED CYBER THREAT INTELLIGENCE PLATFORM ◆ MITRE ATT&CK ◆ IP COMPARISON ◆ NETWORK TOPOLOGY</div>
</div>
""", unsafe_allow_html=True)

# ── Alert Banner ──────────────────────────────────────────────────────────────
ip_info_top = st.session_state.ip_info
ti_top = st.session_state.ti
if ip_info_top and ip_info_top.get("status") == "success" and ti_top:
    ui_alert_banner(ti_top.get("final_score", 0), ip_info_top.get("query","?"))

# ── Ticker ────────────────────────────────────────────────────────────────────
hdf_ticker = st.session_state.history.copy()
for col in ["lat","lon","threat","hour","scan_freq"]:
    hdf_ticker[col] = pd.to_numeric(hdf_ticker[col], errors="coerce").fillna(0)
ui_threat_ticker(hdf_ticker)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:10px 0 18px">
      <div style="font-family:'Orbitron',monospace;font-size:1.3rem;color:#00d4ff;letter-spacing:3px">CYBERTRACK</div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:.6rem;color:#4a7a9b;letter-spacing:2px;margin-top:3px">v6.0 | AI THREAT INTELLIGENCE</div>
    </div>""", unsafe_allow_html=True)

    if "target_input" not in st.session_state:
        st.session_state.target_input = ""

    ui_section("SINGLE TARGET")
    target_input = st.text_input("IP / Domain", placeholder="8.8.8.8 or google.com", key="target_input")

    ca, cb = st.columns(2)
    with ca: scan_btn = st.button("SCAN", use_container_width=True)
    with cb: clear_btn = st.button("CLEAR", use_container_width=True)

    ui_section("BATCH SCAN")
    batch_input = st.text_area("IPs (one per line)", height=75, placeholder="8.8.8.8\n1.1.1.1")
    batch_btn = st.button("BATCH SCAN", use_container_width=True)

    ui_section("OPTIONS")
    enable_ml     = st.toggle("ML Anomaly Detection", value=True)
    enable_ports  = st.toggle("Port Analyzer", value=True)
    enable_cluster= st.toggle("Geo Clustering", value=True)

    # ── QUICK TARGETS (FIXED) ─────────────────────────────────────────────────
    ui_section("QUICK TARGETS")
    quick_targets = [
        ("Google DNS",  "8.8.8.8"),
        ("Cloudflare",  "1.1.1.1"),
        ("OpenDNS",     "208.67.222.222"),
        ("Quad9",       "9.9.9.9"),
    ]
    for lbl, q_ip in quick_targets:
        if st.button(f"{lbl}  ({q_ip})", key=f"qt_{q_ip}", use_container_width=True):
            # FIX: set pending_scan and rerun — scan executes OUTSIDE sidebar
            st.session_state.pending_scan = q_ip
            st.rerun()

    ui_section("API STATUS")
    def _badge(name, live):
        cls = "conf-high" if live else "conf-low"
        return f'<span class="{cls}">{name}: {"LIVE" if live else "MOCK"}</span> '
    st.markdown(
        _badge("AbuseIPDB", bool(ABUSEIPDB_KEY)) +
        _badge("VirusTotal", bool(VIRUSTOTAL_KEY)) + "<br>" +
        _badge("OpenAI", bool(OPENAI_KEY)),
        unsafe_allow_html=True)

    ui_section("SESSION STATS")
    h = st.session_state.history
    st.markdown(f"""<div class="ip" style="font-size:.72rem">
      <span class="lb">IPs SCANNED  :</span> <span>{len(st.session_state.tracked_ips)}</span><br>
      <span class="lb">HISTORY ROWS :</span> <span>{len(h)}</span><br>
      <span class="lb">BATCH RESULTS:</span> <span>{len(st.session_state.batch_results)}</span><br>
      <span class="lb">ANOMALIES    :</span> <span class="wn">{st.session_state.anomaly_count}</span><br>
      <span class="lb">EVENTS       :</span> <span>{len(st.session_state.event_stream)}</span><br>
      <span class="lb">STATUS       :</span> <span class="ok"><span class="pulse"></span>ONLINE</span>
    </div>""", unsafe_allow_html=True)

    if clear_btn:
        for k in ("ip_info", "ti", "port_cache"):
            st.session_state[k] = {}
        st.session_state.event_stream.append(create_event("INFO","Session cleared"))
        st.session_state.logs.append(format_log("INFO","Session cleared"))
        st.session_state.target_input = ""
        st.session_state.pending_scan = ""
        st.rerun()


# ── PENDING SCAN (Quick Targets fix) ─────────────────────────────────────────
if st.session_state.pending_scan:
    target_to_scan = st.session_state.pending_scan
    st.session_state.pending_scan = ""
    do_scan(target_to_scan, enable_ports, enable_ml)
    st.rerun()

# ── SCAN BUTTON ───────────────────────────────────────────────────────────────
if scan_btn and target_input:
    do_scan(target_input, enable_ports, enable_ml)

# ── BATCH ─────────────────────────────────────────────────────────────────────
if batch_btn and batch_input.strip():
    targets = [t.strip() for t in batch_input.strip().splitlines() if t.strip()][:15]
    results = []
    prog = st.progress(0)
    st.session_state.event_stream.append(create_event("INFO", f"Batch scan — {len(targets)} targets"))
    for i, tgt in enumerate(targets):
        ii = fetch_ip_info(tgt)
        res = {"ip":tgt,"country":"FAILED","city":"","isp":"","threat":0,"vpn":False,"tor":False,"risk":"N/A","source":"error","lat":0.,"lon":0.}
        if ii and ii.get("status") == "success":
            pr = simulate_port_scan(resolve_target(tgt))
            td = build_threat_intel(resolve_target(tgt), ii, pr, st.session_state.history)
            res = {"ip":ii.get("query",tgt),"country":ii.get("country","?"),"city":ii.get("city","?"),
                   "isp":ii.get("isp","?"),"threat":td["final_score"],"vpn":td["flags"].get("isVPN",False),
                   "tor":td["flags"].get("isTor",False),"risk":td["risk_level"],"source":td["source"],
                   "lat":float(ii.get("lat",0)),"lon":float(ii.get("lon",0))}
            if td["final_score"] > HIGH_THREAT_THRESHOLD:
                st.session_state.event_stream.append(create_event("CRITICAL", f"Batch: {td['final_score']}/100 for {tgt}"))
        results.append(res)
        prog.progress((i+1)/len(targets))
    prog.empty()
    st.session_state.batch_results = results
    st.session_state.event_stream.append(create_event("INFO",f"Batch complete — {len(results)} results"))
    st.session_state.logs.append(format_log("OK", f"Batch done: {len(results)} targets"))

# ── Session Metrics ────────────────────────────────────────────────────────────
hdf = st.session_state.history.copy()
for col in ["lat","lon","threat","hour","scan_freq"]:
    hdf[col] = pd.to_numeric(hdf[col], errors="coerce").fillna(0)

ip_info = st.session_state.ip_info
ti = st.session_state.ti
cur_score = ti.get("final_score",0) if ti else 0

mc1,mc2,mc3,mc4,mc5,mc6 = st.columns(6)
with mc1: ui_metric("TOTAL SCANS",   len(hdf))
with mc2: ui_metric("HIGH RISK",     int((hdf["threat"]>70).sum()), "red")
with mc3: ui_metric("ANOMALIES",     st.session_state.anomaly_count, "org")
with mc4: ui_metric("COUNTRIES",     int(hdf["country"].nunique()))
with mc5: ui_metric("CURRENT SCORE", cur_score, "red" if cur_score>70 else "org" if cur_score>40 else "grn")
with mc6: ui_metric("IPs TRACKED",   len(st.session_state.tracked_ips), "pur")
st.markdown("<br>", unsafe_allow_html=True)


# ── TABS ──────────────────────────────────────────────────────────────────────
tab1,tab2,tab3,tab4,tab5,tab6,tab7,tab8,tab9,tab10,tab11,tab12 = st.tabs([
    "🗺 MAP & INTEL", "🧠 ML ANALYSIS", "📊 ANALYTICS", "🔌 PORTS",
    "⚔ MITRE ATT&CK", "⚖ COMPARE", "📡 LIVE FEED",
    "📋 BATCH", "📄 REPORT", "🤖 AI COPILOT", "📟 EVENTS", "💻 TERMINAL"])


# ─────────────────────────────────────────────────────────────────────────────
# TAB 1 — MAP & INTEL
# ─────────────────────────────────────────────────────────────────────────────
with tab1:
    if ip_info and ip_info.get("status") == "success":
        c1, c2 = st.columns([3,2])
        with c1:
            ui_section("GEOLOCATION MAP")
            fmap = make_map(ip_info, hdf, ti)
            st_folium(fmap, width=None, height=490, returned_objects=[])

            # Network topology below map
            ui_section("NETWORK TOPOLOGY")
            port_res_map = st.session_state.port_cache.get(ip_info.get("query",""), [])
            if port_res_map:
                st.plotly_chart(chart_network_topology(ip_info, ti, port_res_map), use_container_width=True)

        with c2:
            ui_section("TARGET INTELLIGENCE")

            # Animated SVG ring
            st.markdown(chart_threat_ring_svg(ti["final_score"]), unsafe_allow_html=True)

            ui_correlated_level(ti.get("corr_level","LOW"), ti.get("corr_cls","corr-low"), ti.get("signals",0))
            ui_data_sources(ti.get("abuse_available",False), ti.get("vt_available",False))

            ui_info_panel([
                ("IP ADDRESS",  ip_info.get("query","N/A"), "ok"),
                ("HOSTNAME",    ip_info.get("reverse","N/A"), ""),
                ("CITY",        ip_info.get("city","N/A"), ""),
                ("REGION",      ip_info.get("regionName","N/A"), ""),
                ("COUNTRY",     f"{ip_info.get('country','N/A')} {ip_info.get('countryCode','')}", ""),
                ("COORDS",      f"{ip_info.get('lat','?')}, {ip_info.get('lon','?')}", ""),
                ("TIMEZONE",    ip_info.get("timezone","N/A"), ""),
                ("ISP",         ip_info.get("isp","N/A"), ""),
                ("ORG",         ip_info.get("org","N/A"), ""),
                ("AS NUMBER",   ip_info.get("as","N/A"), ""),
                ("PROXY/VPN",   str(ip_info.get("proxy","N/A")).upper(), "bad" if ip_info.get("proxy") else "ok"),
                ("HOSTING",     str(ip_info.get("hosting","N/A")).upper(), "bad" if ip_info.get("hosting") else "ok"),
            ])

            ui_section("THREAT FLAGS")
            any_flag = False
            for label, key in [("VPN","isVPN"),("TOR","isTor"),("PROXY","isProxy"),("BOT","isBot"),("DATACENTER","isDatacenter")]:
                if ti["flags"].get(key):
                    any_flag = True
                    ui_alert(f"{label} DETECTED", "hi")
            for cat_name in ti["flags"].get("categories",[]):
                ui_alert(f"CATEGORY: {cat_name}", "md")
            if not any_flag and not ti["flags"].get("categories"):
                ui_alert("NO ACTIVE THREAT FLAGS", "lo")
            if ti.get("km_dist"):
                lv = "hi" if ti["km_dist"] > GEO_JUMP_KM else "lo"
                ui_alert(f"GEO JUMP: {ti['km_dist']:,.0f} km from last scan", lv)

            ui_section("WHY IS THIS IP RISKY?")
            ui_xai_panel(build_why_risky(ti, ip_info))
            reasoning = build_xai_reasoning(ti, ip_info)
            st.markdown(f'<div class="xai" style="border-left-color:#a855f7;margin-top:6px">'
                        f'<span style="color:#a855f7;font-weight:bold">AI REASONING: </span>{reasoning}</div>',
                        unsafe_allow_html=True)

            ui_info_panel([
                ("ABUSE REPORTS", str(ti["flags"].get("reports",0)), "bad" if ti["flags"].get("reports",0)>100 else "wn" if ti["flags"].get("reports",0)>20 else "ok"),
                ("VT SCORE",      f"{ti['vt_score']}/100", ""),
                ("DATA SOURCE",   ti["source"].upper(), ""),
                ("SCAN TIME",     datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ""),
            ])

        ui_section("RECOMMENDED ACTIONS")
        col_a, col_b = st.columns(2)
        with col_a:
            ui_decision_panel(ti)
        with col_b:
            st.plotly_chart(chart_score_waterfall(ti), use_container_width=True)

    else:
        st.markdown("""<div style="text-align:center;padding:70px 20px">
          <div style="font-family:'Orbitron',monospace;font-size:3rem;color:#0d4f6e">[ ]</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:.95rem;color:#4a7a9b;letter-spacing:3px;margin-top:10px">AWAITING TARGET</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:.72rem;color:#2a4a5b;margin-top:8px">Enter an IP or domain in the sidebar to begin</div>
        </div>""", unsafe_allow_html=True)
        ui_section("GLOBAL ACTIVITY MAP")
        st_folium(make_map({"lat":20,"lon":0,"query":"N/A"}, hdf, {}), width=None, height=450, returned_objects=[])


# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 — ML ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
with tab2:
    ui_section("ML-POWERED THREAT ANALYSIS")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Isolation Forest Anomaly Score**")
        if ip_info and ti and enable_ml:
            ml_s, ml_l = ml_anomaly_score(ip_info, ti, hdf)
            st.plotly_chart(chart_ml_gauge(ml_s, ml_l), use_container_width=True)
        else:
            st.info("Scan a target to run anomaly detection.")
        st.markdown("**Threat Vector Radar**")
        if ti:
            st.plotly_chart(chart_radar(ti), use_container_width=True)
    with c2:
        st.markdown("**DBSCAN Geo Clustering**")
        if enable_cluster and len(hdf) >= 3:
            clustered = ml_cluster_analysis(hdf)
            fig_c = px.scatter_geo(clustered, lat="lat", lon="lon", color="cluster",
                color_continuous_scale=["#00ff88","#00d4ff","#ffaa00","#ff2d55"],
                hover_data=["ip","country","threat"])
            fig_c.update_geos(bgcolor="rgba(2,10,18,.9)",showland=True,landcolor="#071520",
                              showocean=True,oceancolor="#020a12",
                              showcountries=True,countrycolor="#0d4f6e",showframe=False)
            fig_c.update_layout(**PLOTLY_BASE, height=280, coloraxis_showscale=False)
            st.plotly_chart(fig_c, use_container_width=True)
        st.markdown("**Feature Importance**")
        feats = ["Abuse Score","VPN Flag","Tor Exit","Open Ports","Geo Anomaly","Bot Activity","Freq","Datacenter"]
        imps  = [0.30,0.18,0.14,0.13,0.10,0.07,0.05,0.03]
        fi_fig = go.Figure(go.Bar(x=imps,y=feats,orientation="h",
            marker_color=["#ff2d55" if v>.15 else "#ffaa00" if v>.09 else "#00d4ff" for v in imps],
            text=[f"{v:.0%}" for v in imps],textposition="outside",
            textfont=dict(color="#c8e6f5",family="Share Tech Mono",size=11)))
        fi_fig.update_layout(**PLOTLY_BASE, height=280,
            xaxis=dict(**GRID,tickformat=".0%"),
            yaxis=dict(color="#c8e6f5",tickfont=dict(family="Share Tech Mono",size=11)))
        st.plotly_chart(fi_fig, use_container_width=True)
    if ip_info and ti:
        ui_section("ML SUMMARY")
        ms1,ms2,ms3,ms4 = st.columns(4)
        ml_s2, ml_l2 = ml_anomaly_score(ip_info, ti, hdf) if enable_ml else (0,"N/A")
        with ms1: st.metric("Threat Category", predict_threat_category(ti))
        with ms2: st.metric("ML Status", ml_l2)
        with ms3: st.metric("Anomaly Score", f"{ml_s2}/100")
        with ms4: st.metric("Overall Risk", ti["risk_level"])
    if st.session_state.threat_history:
        ui_section("SCAN THREAT HISTORY")
        st.plotly_chart(chart_threat_score_history(st.session_state.threat_history), use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 3 — ANALYTICS
# ─────────────────────────────────────────────────────────────────────────────
with tab3:
    ui_section("THREAT ANALYTICS DASHBOARD")
    if not hdf.empty:
        a1,a2 = st.columns(2)
        with a1: st.plotly_chart(chart_threat_timeline(hdf), use_container_width=True)
        with a2: st.plotly_chart(chart_countries(hdf), use_container_width=True)
        a3,a4 = st.columns(2)
        with a3: st.plotly_chart(chart_events(hdf), use_container_width=True)
        with a4: st.plotly_chart(chart_hourly(hdf), use_container_width=True)
        ui_section("TOP RISKY IPs LEADERBOARD")
        ui_leaderboard(hdf)
        ui_section("GLOBAL THREAT HEATMAP")
        st.plotly_chart(chart_heatmap_geo(hdf), use_container_width=True)
        ui_section("THREAT SCORE DISTRIBUTION")
        st.plotly_chart(chart_histogram(hdf), use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 4 — PORT ANALYZER
# ─────────────────────────────────────────────────────────────────────────────
with tab4:
    ui_section("SMART PORT ANALYZER")
    st.markdown('<div class="ip" style="font-size:.76rem">EDUCATIONAL SIMULATION — Deterministic from IP hash. No real network connections.</div>', unsafe_allow_html=True)
    target_ip = ip_info.get("query") if ip_info.get("status") == "success" else None
    port_res = st.session_state.port_cache.get(target_ip, []) if target_ip else []
    if port_res:
        open_p  = [p for p in port_res if p["state"]=="OPEN"]
        closed_p= [p for p in port_res if p["state"]=="CLOSED"]
        filt_p  = [p for p in port_res if p["state"]=="FILTERED"]
        port_score, _ = compute_port_risk_score(port_res)
        pc1,pc2,pc3,pc4 = st.columns(4)
        with pc1: ui_metric("OPEN PORTS",   len(open_p),   "red")
        with pc2: ui_metric("CLOSED PORTS", len(closed_p), "grn")
        with pc3: ui_metric("FILTERED",     len(filt_p),   "org")
        with pc4: ui_metric("PORT RISK",    port_score,    "red" if port_score>60 else "org" if port_score>30 else "grn")
        rows_html = "".join([
            f"<tr><td>{p['port']}</td><td>{p['service']}</td>"
            f"<td class=\"p{'o' if p['state']=='OPEN' else 'c' if p['state']=='CLOSED' else 'f'}\">{p['state']}</td>"
            f"<td style=\"color:{'#ff2d55' if p['risk_w']>=35 else '#ffaa00' if p['risk_w']>=20 else '#4a7a9b'}\">{p['risk_w']}</td>"
            f"<td style=\"color:#4a7a9b;font-size:.7rem\">{p.get('banner','')}</td>"
            f"<td style=\"color:#4a7a9b;font-size:.7rem\">{p.get('desc','')}</td></tr>"
            for p in port_res])
        st.markdown(f"""<table class="pt">
          <thead><tr><th>PORT</th><th>SERVICE</th><th>STATE</th><th>RISK WT</th><th>BANNER</th><th>DESCRIPTION</th></tr></thead>
          <tbody>{rows_html}</tbody></table>""", unsafe_allow_html=True)
        risky_open = [p for p in open_p if p["port"] in HIGH_RISK_PORTS]
        if risky_open:
            ui_section("HIGH-RISK OPEN PORTS")
            for p in risky_open:
                ui_alert(f"Port {p['port']} ({p['service']}) OPEN — Risk: {p['risk_w']} — {p.get('desc','')}", "hi")
    else:
        st.info("Scan a target with Port Analyzer enabled.")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 5 — MITRE ATT&CK  [NEW v6.0]
# ─────────────────────────────────────────────────────────────────────────────
with tab5:
    ui_section("MITRE ATT&CK TECHNIQUE MAPPER")
    if ip_info and ip_info.get("status") == "success" and ti:
        categories = ti["flags"].get("categories", [])
        mc1, mc2 = st.columns([2,3])
        with mc1:
            ui_section("DETECTED CATEGORIES")
            if categories:
                for cat in categories:
                    ui_alert(f"CATEGORY: {cat}", "md")
            else:
                st.markdown('<div class="ip" style="font-size:.76rem;color:var(--dim)">No threat categories flagged for this IP.</div>', unsafe_allow_html=True)
            ui_section("TACTIC SUMMARY")
            all_techs = get_mitre_techniques(categories)
            tactics = list({t[2] for t in all_techs})
            if tactics:
                for tac in tactics:
                    ui_alert(f"TACTIC: {tac}", "hi" if tac in ("Execution","Impact") else "md")
            else:
                ui_alert("No MITRE tactics mapped", "lo")
        with mc2:
            ui_section("MAPPED TECHNIQUES")
            ui_mitre_panel(categories)
            if all_techs:
                st.markdown("<br>", unsafe_allow_html=True)
                # Matrix-style bar
                tac_counts = {}
                for t in all_techs:
                    tac_counts[t[2]] = tac_counts.get(t[2], 0) + 1
                fig_mitre = go.Figure(go.Bar(
                    x=list(tac_counts.values()), y=list(tac_counts.keys()), orientation="h",
                    marker_color=["#ff2d55" if k in ("Execution","Impact","Initial Access") else "#ffaa00" if k in ("Persistence","Lateral Movement") else "#00d4ff" for k in tac_counts.keys()],
                    text=list(tac_counts.values()), textposition="outside",
                    textfont=dict(color="#c8e6f5", family="Share Tech Mono")))
                fig_mitre.update_layout(**PLOTLY_BASE, height=200, title="Techniques by Tactic",
                                        xaxis=dict(**GRID), yaxis=dict(color="#c8e6f5"))
                st.plotly_chart(fig_mitre, use_container_width=True)
    else:
        st.info("Scan a target to map MITRE ATT&CK techniques.")
        ui_section("MITRE ATT&CK REFERENCE")
        st.markdown("""<div class="ip" style="font-size:.76rem">
        <span class="lb">CATEGORIES MAPPED :</span> Spam, Hacking, DDoS, Phishing, Port Scan, Brute Force, Malware, SSH Abuse, C2<br>
        <span class="lb">TACTICS COVERED  :</span> Reconnaissance, Initial Access, Execution, Persistence, Credential Access, Lateral Movement, C2, Impact<br>
        <span class="lb">TECHNIQUE COUNT  :</span> 16 techniques across 8 tactics
        </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 6 — IP COMPARISON  [NEW v6.0]
# ─────────────────────────────────────────────────────────────────────────────
with tab6:
    ui_section("IP COMPARISON MODE")
    st.markdown('<div class="ip" style="font-size:.76rem">Compare two IPs side-by-side. The current scanned IP auto-fills Slot A.</div>', unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown('<div class="sh" style="font-size:.75rem">SLOT A</div>', unsafe_allow_html=True)
        cmp_ip_a = st.text_input("IP / Domain A", value=ip_info.get("query","") if ip_info else "", key="cmp_a")
        scan_a = st.button("SCAN A", key="scan_cmp_a", use_container_width=True)
    with col_b:
        st.markdown('<div class="sh" style="font-size:.75rem">SLOT B</div>', unsafe_allow_html=True)
        cmp_ip_b = st.text_input("IP / Domain B", placeholder="e.g. 1.1.1.1", key="cmp_b")
        scan_b = st.button("SCAN B", key="scan_cmp_b", use_container_width=True)

    slots = st.session_state.compare_slots

    if scan_a and cmp_ip_a:
        with st.spinner(f"Scanning {cmp_ip_a}..."):
            ii = fetch_ip_info(cmp_ip_a)
            if ii and ii.get("status") == "success":
                pr = simulate_port_scan(resolve_target(cmp_ip_a))
                td = build_threat_intel(resolve_target(cmp_ip_a), ii, pr, hdf)
                slots[0] = {"ip_info": ii, "ti": td}
                st.session_state.compare_slots = slots

    if scan_b and cmp_ip_b:
        with st.spinner(f"Scanning {cmp_ip_b}..."):
            ii = fetch_ip_info(cmp_ip_b)
            if ii and ii.get("status") == "success":
                pr = simulate_port_scan(resolve_target(cmp_ip_b))
                td = build_threat_intel(resolve_target(cmp_ip_b), ii, pr, hdf)
                slots[1] = {"ip_info": ii, "ti": td}
                st.session_state.compare_slots = slots

    # Auto-fill slot A from current scan
    if ip_info and ip_info.get("status") == "success" and ti and not slots[0]:
        slots[0] = {"ip_info": ip_info, "ti": ti}
        st.session_state.compare_slots = slots

    if slots[0] and slots[1]:
        s0, s1 = slots[0], slots[1]
        ip0 = s0["ip_info"].get("query","A")
        ip1 = s1["ip_info"].get("query","B")

        ui_section("SIDE-BY-SIDE COMPARISON")
        ca2, cb2 = st.columns(2)
        with ca2:
            st.markdown(f'<div style="text-align:center;font-family:Orbitron,monospace;font-size:.8rem;color:#00d4ff;margin-bottom:8px">{ip0}</div>', unsafe_allow_html=True)
            st.markdown(chart_threat_ring_svg(s0["ti"]["final_score"]), unsafe_allow_html=True)
            ui_info_panel([
                ("COUNTRY", s0["ip_info"].get("country","?"), ""),
                ("ISP",     s0["ip_info"].get("isp","?"), ""),
                ("RISK",    s0["ti"]["risk_level"], "bad" if s0["ti"]["final_score"]>60 else "wn"),
            ])
        with cb2:
            st.markdown(f'<div style="text-align:center;font-family:Orbitron,monospace;font-size:.8rem;color:#00d4ff;margin-bottom:8px">{ip1}</div>', unsafe_allow_html=True)
            st.markdown(chart_threat_ring_svg(s1["ti"]["final_score"]), unsafe_allow_html=True)
            ui_info_panel([
                ("COUNTRY", s1["ip_info"].get("country","?"), ""),
                ("ISP",     s1["ip_info"].get("isp","?"), ""),
                ("RISK",    s1["ti"]["risk_level"], "bad" if s1["ti"]["final_score"]>60 else "wn"),
            ])

        ui_section("METRIC COMPARISON TABLE")
        ui_compare_table(s0["ti"], ip0, s1["ti"], ip1)

        ui_section("RADAR OVERLAY")
        st.plotly_chart(chart_compare_radar(s0["ti"], ip0, s1["ti"], ip1), use_container_width=True)

    elif slots[0] and not slots[1]:
        st.info("Slot A loaded. Enter an IP in Slot B and click SCAN B to compare.")
    else:
        st.info("Scan a target from the sidebar first, then use Slot B to compare.")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 7 — LIVE FEED  [NEW v6.0]
# ─────────────────────────────────────────────────────────────────────────────
with tab7:
    ui_section("SIMULATED LIVE THREAT FEED")
    st.markdown('<div class="ip" style="font-size:.76rem">Real-time simulation of global threat events. Refreshes on each page interaction.</div>', unsafe_allow_html=True)

    feed_data = generate_live_feed(20)

    f1, f2, f3, f4 = st.columns(4)
    high_feed = sum(1 for f in feed_data if f["score"]>70)
    med_feed  = sum(1 for f in feed_data if 40<f["score"]<=70)
    low_feed  = sum(1 for f in feed_data if f["score"]<=40)
    with f1: ui_metric("FEED EVENTS", len(feed_data))
    with f2: ui_metric("CRITICAL",    high_feed, "red")
    with f3: ui_metric("MEDIUM",      med_feed,  "org")
    with f4: ui_metric("LOW",         low_feed,  "grn")

    feed_col1, feed_col2 = st.columns([3,2])
    with feed_col1:
        ui_section("LIVE EVENT TABLE")
        st.markdown('<div style="font-family:Share Tech Mono,monospace;font-size:.68rem;color:var(--dim);display:flex;gap:10px;padding:3px 0;border-bottom:1px solid var(--border)"><span style="min-width:60px">TIME</span><span style="min-width:120px">IP</span><span style="min-width:100px">EVENT</span><span>COUNTRY</span><span style="margin-left:auto">SCORE</span></div>', unsafe_allow_html=True)
        ui_live_feed(feed_data)

    with feed_col2:
        ui_section("EVENT TYPE BREAKDOWN")
        feed_df = pd.DataFrame(feed_data)
        ec = feed_df["event"].value_counts()
        fig_feed = go.Figure(go.Pie(labels=ec.index, values=ec.values, hole=0.45,
            marker=dict(colors=["#ff2d55","#ffaa00","#00d4ff","#00ff88","#a855f7","#f97316","#22d3ee","#fb7185"]),
            textfont=dict(family="Share Tech Mono",size=10)))
        fig_feed.update_layout(**PLOTLY_BASE, height=240, showlegend=True,
            legend=dict(font=dict(family="Share Tech Mono",size=9)))
        st.plotly_chart(fig_feed, use_container_width=True)

        ui_section("TOP SOURCE COUNTRIES")
        cc_feed = feed_df["country"].value_counts().head(6)
        fig_cc = go.Figure(go.Bar(x=cc_feed.values, y=cc_feed.index, orientation="h",
            marker_color="#00d4ff"))
        fig_cc.update_layout(**PLOTLY_BASE, height=200,
                             xaxis=dict(**GRID), yaxis=dict(color="#c8e6f5",tickfont=dict(size=10)))
        st.plotly_chart(fig_cc, use_container_width=True)

    if st.button("↻ Refresh Feed", use_container_width=True):
        st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# TAB 8 — BATCH
# ─────────────────────────────────────────────────────────────────────────────
with tab8:
    ui_section("BATCH SCAN RESULTS")
    if st.session_state.batch_results:
        bdf = pd.DataFrame(st.session_state.batch_results)
        bc1,bc2,bc3,bc4 = st.columns(4)
        with bc1: ui_metric("TOTAL",     len(bdf))
        with bc2: ui_metric("HIGH RISK", int((bdf["threat"]>70).sum()), "red")
        with bc3: ui_metric("VPN/PROXY", int(bdf["vpn"].sum()), "org")
        with bc4: ui_metric("TOR NODES", int(bdf["tor"].sum()), "red")
        display = bdf[["ip","country","city","isp","threat","risk","vpn","tor","source"]].copy()
        try:
            st.dataframe(display.style.map(color_threat, subset=["threat"]), use_container_width=True, height=340)
        except Exception:
            st.dataframe(display, use_container_width=True, height=340)
        st.download_button("Export Batch CSV", bdf.to_csv(index=False).encode(),
                           "cybertrack_batch.csv","text/csv",use_container_width=True)
    else:
        st.info("Enter IPs in the sidebar Batch Scan panel and click BATCH SCAN.")
    ui_section("IP / CIDR VALIDATOR")
    cidr_in = st.text_input("IP or CIDR", placeholder="10.0.0.0/8 or 1.1.1.1")
    if cidr_in:
        try:
            net = ipaddress.ip_network(cidr_in, strict=False)
            ui_info_panel([("TYPE","VALID NETWORK","ok"),("NETWORK",str(net.network_address),""),
                ("BROADCAST",str(net.broadcast_address),""),("HOSTS",f"{net.num_addresses:,}",""),
                ("PREFIX",f"/{net.prefixlen}",""),("VERSION",f"IPv{net.version}",""),])
        except ValueError:
            try:
                addr = ipaddress.ip_address(cidr_in)
                ui_info_panel([("TYPE","VALID IP","ok"),("ADDRESS",str(addr),""),
                    ("VERSION",f"IPv{addr.version}",""),("PRIVATE",str(addr.is_private),""),
                    ("LOOPBACK",str(addr.is_loopback),""),])
            except ValueError:
                ui_alert("Invalid IP / CIDR notation", "hi")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 9 — REPORT
# ─────────────────────────────────────────────────────────────────────────────
with tab9:
    ui_section("REPORT EXPORT SYSTEM")
    if ip_info and ip_info.get("status") == "success" and ti:
        resolved_ip = ip_info.get("query","unknown")
        port_res_r = st.session_state.port_cache.get(resolved_ip, [])
        report = build_report(ip_info, ti, port_res_r)
        rc1, rc2 = st.columns(2)
        with rc1:
            ui_section("REPORT PREVIEW")
            ui_info_panel([
                ("GENERATED AT",   report["generated_at"][:19], ""),
                ("TARGET IP",      report["ip_intelligence"]["ip"], "ok"),
                ("COUNTRY",        report["ip_intelligence"]["country"], ""),
                ("CITY",           report["ip_intelligence"]["city"], ""),
                ("ISP",            report["ip_intelligence"]["isp"], ""),
                ("THREAT SCORE",   f"{report['threat_intelligence']['final_score']}/100",
                 "bad" if report["threat_intelligence"]["final_score"]>60 else "wn" if report["threat_intelligence"]["final_score"]>30 else "ok"),
                ("RISK LEVEL",     report["threat_intelligence"]["risk_level"], "wn"),
                ("CORR. LEVEL",    report["threat_intelligence"]["corr_level"], "wn"),
                ("RISK SIGNALS",   str(report["threat_intelligence"]["signals"]), ""),
                ("CONFIDENCE",     report["threat_intelligence"]["confidence"], ""),
                ("DATA SOURCE",    report["threat_intelligence"]["source"].upper(), ""),
                ("OPEN PORTS",     str(sum(1 for p in port_res_r if p["state"]=="OPEN")), ""),
                ("ABUSE REPORTS",  str(report["threat_intelligence"]["reports"]), ""),
            ])
        with rc2:
            ui_section("EXPORT OPTIONS")
            fname = resolved_ip.replace(".","_")
            st.download_button("Download CSV Report", report_to_csv(report).encode(),
                               f"cybertrack_{fname}.csv","text/csv",use_container_width=True)
            st.markdown("<br>", unsafe_allow_html=True)
            st.download_button("Download JSON Report",
                               json.dumps(report, indent=2, default=str).encode(),
                               f"cybertrack_{fname}.json","application/json",use_container_width=True)
            tc = threat_class(ti["final_score"])
            st.markdown(f'<div class="ts {tc}" style="margin-top:16px">{ti["final_score"]}<br><span style="font-size:.6rem">THREAT SCORE</span></div>', unsafe_allow_html=True)
    else:
        st.markdown('<div style="text-align:center;padding:50px 20px"><div style="font-family:Share Tech Mono,monospace;font-size:.88rem;color:#4a7a9b">SCAN A TARGET TO GENERATE REPORT</div></div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 10 — AI COPILOT
# ─────────────────────────────────────────────────────────────────────────────
with tab10:
    ui_section("AI SECURITY COPILOT")
    mode = "OpenAI GPT-3.5" if OPENAI_KEY else "Rule-Based Engine"
    st.markdown(f'<div class="ip" style="font-size:.76rem"><span class="pulse"></span><span class="lb">MODE:</span> <span class="ok">{mode}</span></div>', unsafe_allow_html=True)
    for msg in st.session_state.chat_history:
        if msg["role"] == "user": ui_user_message(msg["content"])
        else: ui_copilot_response(mode, msg["content"])
    ui_section("QUICK PROMPTS")
    qp_list = ["Is this IP dangerous?","How do I block this IP?","Where is this IP from?","Any VPN or Tor flags?","What MITRE techniques apply?","Summarize the threat"]
    qcols = st.columns(3)
    for i, qp in enumerate(qp_list):
        with qcols[i % 3]:
            if st.button(qp, key=f"qp_{i}", use_container_width=True):
                st.session_state.chat_history.append({"role":"user","content":qp})
                st.session_state.chat_history.append({"role":"assistant","content":ask_copilot(qp, st.session_state.ip_info, st.session_state.ti)})
                st.rerun()
    user_q = st.text_input("Ask the Copilot", placeholder="Type your security question", key="cop_in")
    ask_c1, ask_c2 = st.columns([5,1])
    with ask_c2:
        ask_btn = st.button("ASK", use_container_width=True)
    if ask_btn and user_q.strip():
        st.session_state.chat_history.append({"role":"user","content":user_q.strip()})
        st.session_state.chat_history.append({"role":"assistant","content":ask_copilot(user_q.strip(), st.session_state.ip_info, st.session_state.ti)})
        st.rerun()
    if st.session_state.chat_history:
        if st.button("Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# TAB 11 — EVENTS
# ─────────────────────────────────────────────────────────────────────────────
with tab11:
    ev_col1, ev_col2 = st.columns([3, 2])
    with ev_col1:
        ui_section("LIVE EVENT STREAM")
        stream_html = render_event_stream(st.session_state.event_stream)
        st.markdown(f'<div class="term" style="height:380px">{stream_html}</div>', unsafe_allow_html=True)
        if st.button("Clear Event Stream", use_container_width=True):
            st.session_state.event_stream = [create_event("INFO","Event stream cleared")]
            st.rerun()
        if st.session_state.event_stream:
            info_c  = sum(1 for e in st.session_state.event_stream if e["level"]=="INFO")
            warn_c  = sum(1 for e in st.session_state.event_stream if e["level"]=="WARNING")
            crit_c  = sum(1 for e in st.session_state.event_stream if e["level"]=="CRITICAL")
            ui_info_panel([
                ("INFO EVENTS",     str(info_c),  "ok"),
                ("WARNING EVENTS",  str(warn_c),  "wn"),
                ("CRITICAL EVENTS", str(crit_c),  "bad"),
                ("TOTAL EVENTS",    str(len(st.session_state.event_stream)), ""),
            ])
    with ev_col2:
        ui_section("BEHAVIOR ANALYSIS")
        insights = analyze_behavior(st.session_state.tracked_ips, hdf)
        ui_behavior_insights(insights)
        if ip_info and ip_info.get("status") == "success" and ti:
            ui_section("DECISION SUPPORT")
            ui_decision_panel(ti)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 12 — TERMINAL
# ─────────────────────────────────────────────────────────────────────────────
with tab12:
    ui_section("LIVE SYSTEM TERMINAL")
    st.markdown(f'<div class="term">{"".join(st.session_state.logs[-50:])}</div>', unsafe_allow_html=True)
    tc1,tc2,tc3 = st.columns(3)
    with tc1:
        if st.button("Clear Logs", use_container_width=True):
            st.session_state.logs = [format_log("OK","Logs cleared")]
            st.rerun()
    with tc2:
        if st.button("System Status", use_container_width=True):
            st.session_state.logs.extend([
                format_log("INFO","=== STATUS v6.0 ==="),
                format_log("OK", f"Records: {len(hdf)}"),
                format_log("OK", f"IPs: {len(st.session_state.tracked_ips)}"),
                format_log("INFO",f"AbuseIPDB: {'LIVE' if ABUSEIPDB_KEY else 'MOCK'}"),
                format_log("INFO",f"VirusTotal: {'LIVE' if VIRUSTOTAL_KEY else 'MOCK'}"),
                format_log("INFO",f"OpenAI: {'LIVE' if OPENAI_KEY else 'RULE-BASED'}"),
                format_log("OK", f"Anomalies: {st.session_state.anomaly_count}"),
                format_log("OK", f"Events: {len(st.session_state.event_stream)}"),
                format_log("OK", "MITRE mapper: ACTIVE"),
                format_log("OK", "IP Compare: ACTIVE"),
            ])
            st.rerun()
    with tc3:
        if st.button("Reset Data", use_container_width=True):
            st.session_state.history = generate_history(40)
            st.session_state.anomaly_count = 0
            st.session_state.event_stream = [create_event("INFO","All data reset")]
            st.session_state.logs.append(format_log("WARN","All data reset"))
            st.rerun()
    ui_section("NETWORK DIAGNOSTICS")
    d1, d2 = st.columns(2)
    with d1:
        if ip_info and ip_info.get("status") == "success":
            ui_info_panel([
                ("NETWORK","",""),("IP",ip_info.get("query","N/A"),"ok"),
                ("ISP",ip_info.get("isp","N/A"),""),("ASN",ip_info.get("as","N/A"),""),
                ("ORG",ip_info.get("org","N/A"),""),
                ("PROXY",str(ip_info.get("proxy","N/A")).upper(),"bad" if ip_info.get("proxy") else "ok"),
            ])
        else:
            st.markdown('<div class="ip">No target scanned yet.</div>', unsafe_allow_html=True)
    with d2:
        if ti:
            ui_info_panel([
                ("THREAT INTEL","",""),
                ("FINAL SCORE",f"{ti['final_score']}/100","bad" if ti["final_score"]>60 else "wn" if ti["final_score"]>30 else "ok"),
                ("ABUSE",f"{ti['abuse_score']}/100",""),("VT",f"{ti['vt_score']}/100",""),
                ("PORT RISK",f"{ti['port_score']}/100",""),("GEO ANOM",f"{ti['geo_score']}/100",""),
                ("CORR. LEVEL",ti.get("corr_level","?"),""),("SIGNALS",str(ti.get("signals",0)),""),
                ("SOURCE",ti["source"].upper(),""),("CONF",ti["confidence"],""),
            ])
        else:
            st.markdown('<div class="ip">No threat data yet.</div>', unsafe_allow_html=True)


st.markdown("""
<div style="text-align:center;padding:28px 0 8px;font-family:'Share Tech Mono',monospace;
            font-size:.68rem;color:#2a4a5b;letter-spacing:2px;border-top:1px solid #0d4f6e;margin-top:28px">
  CYBERTRACK v6.0 | AI-POWERED THREAT INTELLIGENCE | AUTHORIZED USE ONLY<br>
  <span style="color:#0d4f6e">ISOLATION FOREST | DBSCAN | MITRE ATT&CK | IP COMPARE | NETWORK TOPOLOGY | ABUSEIPDB | VIRUSTOTAL | OPENAI | FOLIUM | PLOTLY | STREAMLIT</span>
</div>
""", unsafe_allow_html=True)
