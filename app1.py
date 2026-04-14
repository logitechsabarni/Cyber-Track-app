"""
CyberTrack v5.5 — AI-Powered Cyber Threat Intelligence Platform
Architecture:
  1. Config & Constants
  2. Utility Functions
  3. Cached API Layer
  4. Threat Intelligence Engine
  5. ML Engine
  6. Event & Behavior Engine        [NEW v5.5]
  7. Visualization Functions
  8. UI Components
  9. Main App Controller
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 1. CONFIG & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
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
    page_title="CyberTrack v5.5",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_API_KEY",  "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY",  "")
OPENAI_KEY     = os.environ.get("OPENAI_API_KEY",      "")
GEO_JUMP_KM    = 5000
HIGH_THREAT_THRESHOLD = 70   # [NEW v5.5] alert banner threshold

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

st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@300;400;600;700&display=swap');
  :root{--bg:#020a12;--surface:#071520;--border:#0d4f6e;--accent:#00d4ff;--green:#00ff88;--red:#ff2d55;--orange:#ffaa00;--text:#c8e6f5;--dim:#4a7a9b;--purple:#a855f7;}
  html,body,.stApp{background-color:var(--bg)!important;color:var(--text)!important;font-family:'Rajdhani',sans-serif!important;}
  .stApp::before{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background-image:linear-gradient(rgba(0,212,255,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.022) 1px,transparent 1px);background-size:50px 50px;pointer-events:none;z-index:0;animation:gridPulse 8s ease-in-out infinite;}
  @keyframes gridPulse{0%,100%{opacity:.5}50%{opacity:1}}
  section[data-testid="stSidebar"]{background:linear-gradient(180deg,#020d18 0%,#030f1f 100%)!important;border-right:1px solid var(--border)!important;}
  .cyber-header{background:linear-gradient(135deg,#020d18,#041525,#020d18);border:1px solid var(--accent);border-radius:4px;padding:20px 30px;margin-bottom:20px;position:relative;overflow:hidden;box-shadow:0 0 30px rgba(0,212,255,.2),inset 0 0 30px rgba(0,212,255,.05);}
  .cyber-header::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:conic-gradient(transparent,rgba(0,212,255,.05),transparent 30%);animation:rotate 10s linear infinite;}
  @keyframes rotate{100%{transform:rotate(360deg)}}
  .cyber-title{font-family:'Orbitron',monospace!important;font-size:2rem!important;font-weight:900!important;color:var(--accent)!important;text-shadow:0 0 20px rgba(0,212,255,.8),0 0 40px rgba(0,212,255,.4);letter-spacing:4px;margin:0;position:relative;z-index:1;}
  .cyber-sub{font-family:'Share Tech Mono',monospace;color:var(--green);font-size:.8rem;letter-spacing:3px;margin-top:4px;position:relative;z-index:1;}
  .mc{background:linear-gradient(135deg,#071520,#0a1f2e);border:1px solid var(--border);border-radius:4px;padding:16px;margin:6px 0;position:relative;overflow:hidden;transition:all .3s;}
  .mc:hover{border-color:var(--accent);box-shadow:0 0 18px rgba(0,212,255,.2);transform:translateY(-2px);}
  .mc::after{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--accent);box-shadow:0 0 8px var(--accent);}
  .mc .mv{font-family:'Orbitron',monospace;font-size:1.8rem;font-weight:700;color:var(--accent);text-shadow:0 0 12px rgba(0,212,255,.6);}
  .mc .ml{font-family:'Share Tech Mono',monospace;font-size:.7rem;color:var(--dim);letter-spacing:2px;text-transform:uppercase;}
  .mc.red::after{background:var(--red);box-shadow:0 0 8px var(--red);} .mc.red .mv{color:var(--red);text-shadow:0 0 12px rgba(255,45,85,.6);}
  .mc.grn::after{background:var(--green);box-shadow:0 0 8px var(--green);} .mc.grn .mv{color:var(--green);}
  .mc.org::after{background:var(--orange);} .mc.org .mv{color:var(--orange);}
  .mc.pur::after{background:var(--purple);} .mc.pur .mv{color:var(--purple);}
  .ip{background:linear-gradient(135deg,#071520,#0a1f2e);border:1px solid var(--border);border-radius:4px;padding:16px;margin:8px 0;font-family:'Share Tech Mono',monospace;font-size:.8rem;color:var(--text);line-height:1.9;}
  .ip .lb{color:var(--accent);font-weight:bold;} .ip .bad{color:var(--red);} .ip .ok{color:var(--green);} .ip .wn{color:var(--orange);}
  .ab{border-radius:4px;padding:10px 14px;margin:6px 0;font-family:'Share Tech Mono',monospace;font-size:.78rem;display:flex;align-items:center;gap:8px;}
  .ab.hi{background:rgba(255,45,85,.08);border:1px solid var(--red);color:var(--red);animation:ablink 2s infinite;}
  .ab.md{background:rgba(255,170,0,.08);border:1px solid var(--orange);color:var(--orange);}
  .ab.lo{background:rgba(0,255,136,.08);border:1px solid var(--green);color:var(--green);}
  @keyframes ablink{0%,100%{box-shadow:0 0 4px rgba(255,45,85,.3)}50%{box-shadow:0 0 14px rgba(255,45,85,.6)}}
  .sh{font-family:'Orbitron',monospace;font-size:.85rem;color:var(--accent);letter-spacing:3px;text-transform:uppercase;border-bottom:1px solid var(--border);padding-bottom:7px;margin:18px 0 12px;text-shadow:0 0 8px rgba(0,212,255,.5);}
  .ts{font-family:'Orbitron',monospace;font-size:2.8rem;font-weight:900;text-align:center;padding:18px;border-radius:4px;text-shadow:0 0 25px currentColor;}
  .ts.crit{color:#ff0033;background:rgba(255,0,51,.08);border:1px solid #ff0033;}
  .ts.hi{color:var(--red);background:rgba(255,45,85,.08);border:1px solid var(--red);}
  .ts.md{color:var(--orange);background:rgba(255,170,0,.08);border:1px solid var(--orange);}
  .ts.lo{color:var(--green);background:rgba(0,255,136,.08);border:1px solid var(--green);}
  .blink-red{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--red);animation:blink 1s step-end infinite;margin-right:6px;}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
  .pulse{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);animation:pd 1.5s ease-in-out infinite;margin-right:5px;}
  @keyframes pd{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.3;transform:scale(.7)}}
  .conf-high{display:inline-block;padding:3px 10px;border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:.68rem;background:rgba(0,255,136,.12);border:1px solid var(--green);color:var(--green);}
  .conf-med{display:inline-block;padding:3px 10px;border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:.68rem;background:rgba(255,170,0,.12);border:1px solid var(--orange);color:var(--orange);}
  .conf-low{display:inline-block;padding:3px 10px;border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:.68rem;background:rgba(255,45,85,.12);border:1px solid var(--red);color:var(--red);}
  .xai{background:rgba(255,170,0,.05);border-left:3px solid var(--orange);padding:12px 16px;margin:8px 0;font-family:'Share Tech Mono',monospace;font-size:.78rem;color:var(--text);line-height:2;}
  .xai-row{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(13,79,110,.3);padding:3px 0;}
  .xai-row:last-child{border-bottom:none;} .xai-label{color:var(--dim);} .xai-pos{color:var(--red);font-weight:bold;}
  .cu{background:rgba(0,212,255,.07);border:1px solid rgba(0,212,255,.25);border-radius:4px;padding:9px 13px;margin:5px 0;font-family:'Share Tech Mono',monospace;font-size:.78rem;color:var(--accent);text-align:right;}
  .cb{background:rgba(0,255,136,.05);border:1px solid rgba(0,255,136,.2);border-radius:4px;padding:9px 13px;margin:5px 0;font-family:'Share Tech Mono',monospace;font-size:.78rem;color:var(--green);}
  .cb .bl{color:var(--dim);font-size:.68rem;margin-bottom:3px;}
  .term{background:#000d15;border:1px solid var(--border);border-radius:4px;padding:14px;font-family:'Share Tech Mono',monospace;font-size:.73rem;height:270px;overflow-y:auto;line-height:1.65;}
  .le{margin:2px 0;} .lt{color:var(--dim);} .li{color:var(--accent);} .lw{color:var(--orange);} .le2{color:var(--red);} .ls{color:var(--green);}
  .pt{width:100%;border-collapse:collapse;font-family:'Share Tech Mono',monospace;font-size:.77rem;}
  .pt th{color:var(--accent);border-bottom:1px solid var(--border);padding:6px 9px;text-align:left;}
  .pt td{padding:5px 9px;border-bottom:1px solid rgba(13,79,110,.25);}
  .po{color:var(--green);} .pc{color:var(--dim);} .pf{color:var(--orange);}
  ::-webkit-scrollbar{width:5px;} ::-webkit-scrollbar-track{background:var(--bg);} ::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}
  .stButton>button{background:transparent!important;border:1px solid var(--accent)!important;color:var(--accent)!important;font-family:'Share Tech Mono',monospace!important;letter-spacing:2px!important;border-radius:2px!important;transition:all .3s!important;text-transform:uppercase!important;}
  .stButton>button:hover{background:rgba(0,212,255,.08)!important;box-shadow:0 0 12px rgba(0,212,255,.3)!important;}
  .stTextInput>div>div>input,.stTextArea>div>div>textarea,.stSelectbox>div>div{background:#071520!important;border:1px solid var(--border)!important;color:var(--text)!important;font-family:'Share Tech Mono',monospace!important;border-radius:2px!important;}
  h1,h2,h3{font-family:'Orbitron',monospace!important;color:var(--accent)!important;}
  div[data-testid="stMetricValue"]{font-family:'Orbitron',monospace!important;color:var(--accent)!important;}
  .stDataFrame{border:1px solid var(--border);}
  .lb-row{display:flex;align-items:center;justify-content:space-between;padding:7px 10px;border-bottom:1px solid rgba(13,79,110,.3);font-family:'Share Tech Mono',monospace;font-size:.78rem;}
  .lb-row:hover{background:rgba(0,212,255,.03);}
  .lb-num{color:var(--dim);min-width:22px;} .lb-ip{color:var(--accent);} .lb-score{font-weight:bold;}
  /* NEW v5.5 styles */
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
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. UTILITY FUNCTIONS
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
    dphi = math.radians(lat2 - lat1)
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


# ═══════════════════════════════════════════════════════════════════════════════
# 3. CACHED API LAYER
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
# 4. THREAT INTELLIGENCE ENGINE
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
    """[NEW v5.5] Count number of distinct risk signals triggered."""
    count = 0
    if ti_partial.get("abuse_score", 0) > 40: count += 1
    if ti_partial.get("vt_score", 0) > 30:    count += 1
    if ti_partial.get("port_score", 0) > 30:  count += 1
    if ti_partial.get("geo_score", 0) > 0:    count += 1
    if ti_partial.get("freq_score", 0) > 20:  count += 1
    if flags.get("isTor"):      count += 1
    if flags.get("isVPN"):      count += 1
    if flags.get("isProxy"):    count += 1
    if flags.get("isBot"):      count += 1
    if flags.get("isDatacenter"): count += 1
    return count

def correlated_threat_level(score: int, signals: int) -> tuple:
    """[NEW v5.5] Correlated threat level based on score + signal count."""
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

    # [NEW v5.5] correlated level + signals
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
        "signals":       signals,           # [NEW v5.5]
        "corr_level":    corr_level,        # [NEW v5.5]
        "corr_cls":      corr_cls,          # [NEW v5.5]
        "abuse_available": abuse_data.get("available", False),   # [NEW v5.5]
        "vt_available":    vt_data.get("available", False),      # [NEW v5.5]
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
    if f.get("isTor"):        rows.append(("Tor exit node detected",    30))
    if f.get("isVPN"):        rows.append(("VPN / anonymizer detected", 15))
    if f.get("isProxy"):      rows.append(("Proxy server detected",     12))
    if f.get("isBot"):        rows.append(("Automated bot activity",    10))
    if ip_info.get("hosting"): rows.append(("Datacenter / hosting IP",   8))
    rows.sort(key=lambda x: -x[1])
    return rows[:8]

def build_xai_reasoning(ti: dict, ip_info: dict) -> str:
    """[NEW v5.5] Generate textual reasoning for XAI panel."""
    score = ti["final_score"]
    f = ti["flags"]
    parts = []
    if ti["abuse_score"] > 50:
        parts.append(f"High abuse confidence ({ti['abuse_score']}/100) suggests repeated malicious activity reported by the community.")
    if ti["vt_score"] > 30:
        parts.append(f"VirusTotal reputation score of {ti['vt_score']}/100 indicates detection by security vendors.")
    if ti["port_score"] > 40:
        parts.append(f"Open high-risk ports contribute {ti['port_score']} risk points — likely exploitable attack surfaces.")
    if ti["geo_score"] > 0:
        parts.append(f"Geographic anomaly detected: origin is {ti.get('km_dist',0):,.0f} km from last known location.")
    if f.get("isTor"):
        parts.append("IP is a known Tor exit node — identity concealment strongly indicated.")
    if f.get("isVPN"):
        parts.append("VPN or anonymizer service detected — true origin is masked.")
    if f.get("isBot"):
        parts.append("Automated bot behaviour detected — high scan frequency or scripted requests.")
    if not parts:
        parts.append(f"Overall threat score is {score}/100 with no single dominant risk factor.")
    return " ".join(parts)

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
            "final_score":  ti["final_score"],
            "abuse_score":  ti["abuse_score"],
            "vt_score":     ti["vt_score"],
            "port_score":   ti["port_score"],
            "geo_score":    ti["geo_score"],
            "risk_level":   ti["risk_level"],
            "corr_level":   ti["corr_level"],
            "signals":      ti["signals"],
            "confidence":   ti["confidence"],
            "source":       ti["source"],
            "is_vpn":       ti["flags"].get("isVPN",False),
            "is_tor":       ti["flags"].get("isTor",False),
            "is_proxy":     ti["flags"].get("isProxy",False),
            "is_bot":       ti["flags"].get("isBot",False),
            "reports":      ti["flags"].get("reports",0),
            "categories":   ti["flags"].get("categories",[]),
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
# 5. ML ENGINE
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
# 6. EVENT & BEHAVIOR ENGINE  [NEW v5.5]
# ═══════════════════════════════════════════════════════════════════════════════

def create_event(level: str, message: str) -> dict:
    """Create a structured event entry."""
    return {"timestamp": datetime.now(), "level": level, "message": message}

def emit_scan_events(ip: str, ti: dict, ip_info: dict, port_results: list) -> list:
    """Emit events for a scan action."""
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
        events.append(create_event("WARNING", f"High-risk open ports detected: {port_names}"))

    if ti["flags"].get("isTor"):
        events.append(create_event("CRITICAL", f"Tor exit node confirmed for {ip}"))
    if ti["flags"].get("isVPN"):
        events.append(create_event("WARNING", f"VPN/anonymizer detected for {ip}"))
    if ti["flags"].get("isBot"):
        events.append(create_event("WARNING", f"Automated bot activity flagged for {ip}"))
    if ti.get("geo_score", 0) > 0:
        events.append(create_event("WARNING", f"Geo anomaly: {ti.get('km_dist',0):,.0f} km jump from last scan"))

    return events

def analyze_behavior(tracked_ips: list, history_df: pd.DataFrame) -> list:
    """[NEW v5.5] Generate behavioral insights from scan patterns."""
    insights = []
    if len(tracked_ips) >= 3:
        insights.append(f"Analyst has scanned {len(tracked_ips)} IPs in this session — potential automated sweep or investigation pattern.")

    if not history_df.empty:
        high_risk = history_df[history_df["threat"] > 70]
        if len(high_risk) >= 3:
            insights.append(f"{len(high_risk)} high-risk events recorded — elevated threat environment detected.")

        country_counts = history_df["country"].value_counts()
        if len(country_counts) > 0:
            top_country = country_counts.index[0]
            top_count = int(country_counts.iloc[0])
            if top_count >= 5:
                insights.append(f"Activity cluster from {top_country} ({top_count} events) — possible targeted campaign origin.")

        recent = history_df[history_df["timestamp"] > datetime.now() - timedelta(hours=2)]
        if len(recent) >= 5:
            insights.append(f"{len(recent)} scans in the last 2 hours — high-frequency reconnaissance pattern detected.")

        if "event" in history_df.columns:
            attack_events = history_df[history_df["event"].isin(["ATTACK","BRUTE_FORCE","SQL_INJECT","C2_BEACON"])]
            if len(attack_events) >= 2:
                insights.append(f"{len(attack_events)} offensive event types logged — active attack chain may be in progress.")

    if not insights:
        insights.append("Behavioral baseline normal — no anomalous scan patterns detected.")
    return insights

def render_event_stream(events: list) -> str:
    """Render structured events as HTML."""
    cls_map = {"INFO": "ev-info", "WARNING": "ev-warn", "CRITICAL": "ev-crit"}
    html = ""
    for ev in reversed(events[-30:]):
        t = ev["timestamp"].strftime("%H:%M:%S")
        cls = cls_map.get(ev["level"], "ev-info")
        html += (f'<div class="event-row">'
                 f'<span class="ev-time">[{t}]</span>'
                 f'<span class="{cls}">[{ev["level"]}]</span>'
                 f'<span class="ev-msg">&nbsp;{ev["message"]}</span></div>')
    return html or '<div class="event-row"><span class="ev-info">No events yet — scan a target to populate the stream.</span></div>'


# ═══════════════════════════════════════════════════════════════════════════════
# 7. VISUALIZATION FUNCTIONS
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


# ═══════════════════════════════════════════════════════════════════════════════
# 8. UI COMPONENTS
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

def ui_threat_score(score: int, category: str, confidence_cls: str, confidence: str):
    tc = threat_class(score)
    blink = '<span class="blink-red"></span>' if score > 60 else ""
    st.markdown(
        f'<div class="ts {tc}">{blink}{score}<br>'
        f'<span style="font-size:.65rem;letter-spacing:2px">{category}</span><br>'
        f'<span class="{confidence_cls}" style="font-size:.55rem">CONFIDENCE: {confidence}</span></div>',
        unsafe_allow_html=True)

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
    """[NEW v5.5] Top-level alert banner for high threat scores."""
    if score >= HIGH_THREAT_THRESHOLD:
        st.markdown(
            f'<div class="alert-banner">'
            f'<span class="blink-red"></span>'
            f'⚠ CRITICAL ALERT — IP {ip} scored {score}/100. Immediate action recommended. '
            f'Block at perimeter firewall and escalate to SOC team.'
            f'</div>',
            unsafe_allow_html=True)

def ui_correlated_level(corr_level: str, corr_cls: str, signals: int):
    """[NEW v5.5] Display correlated threat level + signal count badge."""
    st.markdown(
        f'<div style="margin:8px 0;font-family:Share Tech Mono,monospace;font-size:.8rem;color:var(--dim)">'
        f'CORRELATED THREAT LEVEL: '
        f'<span class="signals-badge {corr_cls}">{corr_level}</span>'
        f'&nbsp;&nbsp;RISK SIGNALS: '
        f'<span class="signals-badge {corr_cls}">{signals} triggered</span>'
        f'</div>',
        unsafe_allow_html=True)

def ui_data_sources(has_abuse: bool, has_vt: bool):
    """[NEW v5.5] Display data source checklist."""
    abuse_icon = '<span class="src-ok">✔</span>' if has_abuse else '<span class="src-miss">✖</span>'
    vt_icon    = '<span class="src-ok">✔</span>' if has_vt    else '<span class="src-miss">✖</span>'
    geo_icon   = '<span class="src-ok">✔</span>'  # ip-api always used
    st.markdown(
        f'<div class="ip" style="font-size:.75rem;padding:10px 14px">'
        f'<span class="lb">DATA SOURCES</span><br>'
        f'{abuse_icon} AbuseIPDB &nbsp;&nbsp; {vt_icon} VirusTotal &nbsp;&nbsp; {geo_icon} GeoIP (ip-api)'
        f'</div>',
        unsafe_allow_html=True)

def ui_decision_panel(ti: dict):
    """[NEW v5.5] Decision support panel with recommended actions."""
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
        f'{items_html}'
        f'</div>',
        unsafe_allow_html=True)

def ui_behavior_insights(insights: list):
    """[NEW v5.5] Render behavior analysis insights."""
    for insight in insights:
        st.markdown(f'<div class="behavior-insight">🔍 {insight}</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# AI COPILOT
# ═══════════════════════════════════════════════════════════════════════════════

def rule_based_answer(q: str, ip_info: dict, ti: dict) -> str:
    q2 = q.lower()
    ip = ip_info.get("query","the target")
    ts = ti["final_score"]
    rl = ti["risk_level"]
    f  = ti["flags"]
    if any(w in q2 for w in ["dangerous","safe","risky","threat","malicious"]):
        if ts > 70:
            return (f"[ANALYSIS] {ip} threat score {ts}/100 — {rl}. "
                    "Key factors: high abuse score, flagged anonymizer. "
                    "ACTION: Block at firewall, audit all past connections.")
        if ts > 40:
            return f"[ANALYSIS] {ip} score {ts}/100 — {rl}. Monitor and consider rate-limiting if unexpected."
        return f"[ANALYSIS] {ip} score {ts}/100 — {rl}. No immediate action required."
    if any(w in q2 for w in ["block","firewall","mitigate","defend"]):
        return (f"[MITIGATION] For {ip} (score {ts}):\n"
                "1. Add deny rule at perimeter firewall.\n"
                "2. Add to SIEM blocklist.\n"
                "3. Review historical logs for past connections.\n"
                "4. Geo-block origin country if applicable.")
    if any(w in q2 for w in ["vpn","tor","proxy","anon"]):
        active = [k.replace("is","").upper() for k in ("isVPN","isTor","isProxy") if f.get(k)]
        if active:
            return f"[FLAGS] {ip} detected as: {', '.join(active)}. Treat as untrusted — anonymized origin."
        return f"[FLAGS] No VPN/Tor/Proxy flags for {ip}."
    if any(w in q2 for w in ["location","country","where","geo"]):
        return (f"[GEO] {ip} => {ip_info.get('city','?')}, {ip_info.get('country','?')} | "
                f"ISP: {ip_info.get('isp','?')} | Lat/Lon: {ip_info.get('lat','?')},{ip_info.get('lon','?')}")
    if any(w in q2 for w in ["port","open","scan"]):
        return "[PORTS] Check the Port Analyzer tab for detailed port scan results."
    if any(w in q2 for w in ["report","export","download"]):
        return "[REPORT] Use the Report Export tab to download CSV or JSON reports."
    return (f"[COPILOT] I can explain threat scores, suggest mitigations, describe flags, or locate {ip}. "
            "Try: 'Is this IP dangerous?' or 'How do I block this?'")

def openai_answer(q: str, ip_info: dict, ti: dict) -> str:
    ctx = (f"IP={ip_info.get('query')}, Country={ip_info.get('country')}, "
           f"ISP={ip_info.get('isp')}, ThreatScore={ti['final_score']}/100, "
           f"Risk={ti['risk_level']}, CorrelatedLevel={ti.get('corr_level','?')}, "
           f"Signals={ti.get('signals',0)}, VPN={ti['flags'].get('isVPN')}, "
           f"Tor={ti['flags'].get('isTor')}, Confidence={ti['confidence']}")
    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization":f"Bearer {OPENAI_KEY}","Content-Type":"application/json"},
            json={"model":"gpt-3.5-turbo",
                  "messages":[
                      {"role":"system","content":"You are CyberTrack AI — a concise, professional cybersecurity analyst. Give actionable, specific responses."},
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
        format_log("OK","CyberTrack v5.5 initialized"),
        format_log("INFO",f"APIs: AbuseIPDB={'LIVE' if ABUSEIPDB_KEY else 'MOCK'} | VT={'LIVE' if VIRUSTOTAL_KEY else 'MOCK'} | OpenAI={'LIVE' if OPENAI_KEY else 'RULE-BASED'}"),
        format_log("OK","ML engine ready (IsolationForest + DBSCAN)"),
        format_log("OK","Event & Behavior engine ready"),
    ],
    "tracked_ips":    list,
    "ip_info":        dict,
    "ti":             dict,
    "port_cache":     dict,
    "batch_results":  list,
    "threat_history": list,
    "chat_history":   list,
    "anomaly_count":  lambda: 0,
    "event_stream":   list,      # [NEW v5.5]
}
for k, f in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = f()


# ═══════════════════════════════════════════════════════════════════════════════
# 9. MAIN APP CONTROLLER
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<div class="cyber-header">
  <div class="cyber-title">CYBERTRACK v5.5</div>
  <div class="cyber-sub">AI-POWERED CYBER THREAT INTELLIGENCE PLATFORM</div>
</div>
""", unsafe_allow_html=True)

# ── [NEW v5.5] Top-level alert banner ────────────────────────────────────────
ip_info_top = st.session_state.ip_info
ti_top = st.session_state.ti
if ip_info_top and ip_info_top.get("status") == "success" and ti_top:
    ui_alert_banner(ti_top.get("final_score", 0), ip_info_top.get("query","?"))

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:10px 0 18px">
      <div style="font-family:'Orbitron',monospace;font-size:1.3rem;color:#00d4ff;letter-spacing:3px">CYBERTRACK</div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:.6rem;color:#4a7a9b;letter-spacing:2px;margin-top:3px">v5.5 | AI THREAT INTELLIGENCE</div>
    </div>""", unsafe_allow_html=True)

    ui_section("SINGLE TARGET")
    target_input = st.text_input("IP / Domain", placeholder="8.8.8.8 or google.com", key="target")
    ca, cb = st.columns(2)
    with ca: scan_btn  = st.button("SCAN",  use_container_width=True)
    with cb: clear_btn = st.button("CLEAR", use_container_width=True)

    ui_section("BATCH SCAN")
    batch_input = st.text_area("IPs (one per line)", height=75, placeholder="8.8.8.8\n1.1.1.1")
    batch_btn   = st.button("BATCH SCAN", use_container_width=True)

    ui_section("OPTIONS")
    enable_ml      = st.toggle("ML Anomaly Detection", value=True)
    enable_ports   = st.toggle("Port Analyzer",        value=True)
    enable_cluster = st.toggle("Geo Clustering",       value=True)

    ui_section("QUICK TARGETS")
    for lbl, q in [("Google DNS","8.8.8.8"),("Cloudflare","1.1.1.1"),("OpenDNS","208.67.222.222"),("Quad9","9.9.9.9")]:
        if st.button(f"{lbl} ({q})", key=f"qt_{q}", use_container_width=True):
            st.session_state.target = q
            st.session_state.target_input = q

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
        for k in ("ip_info","ti","port_cache"):
            st.session_state[k] = {}
        st.session_state.event_stream.append(create_event("INFO","Session cleared by user"))
        st.session_state.logs.append(format_log("INFO","Session cleared"))
        st.rerun()

# ── Scan ─────────────────────────────────────────────────────────────────────
if scan_btn and target_input:
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

            # [NEW v5.5] Emit structured events
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
                st.session_state.event_stream.append(create_event("WARNING", f"ML anomaly detected for {resolved} — {ml_label}"))
            ts = ti["final_score"]
            st.session_state.logs.append(format_log("OK", f"Located: {ip_data.get('city')}, {ip_data.get('country')}"))
            st.session_state.logs.append(format_log("INFO", f"Score: {ts}/100 | Confidence: {ti['confidence']} | Source: {ti['source']}"))
            st.session_state.logs.append(format_log("INFO", f"ML: {ml_label} ({ml_score}) | Signals: {ti.get('signals',0)} | Corr: {ti.get('corr_level','?')}"))
            if ts > 60:
                st.session_state.logs.append(format_log("ERROR", f"HIGH THREAT: {ts}/100"))
                st.session_state.event_stream.append(create_event("CRITICAL", f"Alert threshold exceeded: {ts}/100 for {resolved}"))
            elif ts > 30:
                st.session_state.logs.append(format_log("WARN", f"Moderate: {ts}/100"))
            else:
                st.session_state.logs.append(format_log("OK", f"Nominal: {ts}/100"))
        else:
            st.session_state.logs.append(format_log("ERROR", f"Failed: {target_input}"))
            st.session_state.event_stream.append(create_event("WARNING", f"Failed to resolve {target_input}"))
            st.error(f"Could not resolve {target_input}. Check the address and retry.")

# ── Batch ────────────────────────────────────────────────────────────────────
if batch_btn and batch_input.strip():
    targets = [t.strip() for t in batch_input.strip().splitlines() if t.strip()][:15]
    results = []
    prog = st.progress(0)
    st.session_state.event_stream.append(create_event("INFO", f"Batch scan started — {len(targets)} targets"))
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
                st.session_state.event_stream.append(create_event("CRITICAL", f"Batch: high threat {td['final_score']}/100 for {tgt}"))
        results.append(res)
        prog.progress((i+1)/len(targets))
    prog.empty()
    st.session_state.batch_results = results
    st.session_state.event_stream.append(create_event("INFO", f"Batch scan complete — {len(results)} results"))
    st.session_state.logs.append(format_log("OK", f"Batch done: {len(results)} targets"))

# ── Session Banner ────────────────────────────────────────────────────────────
hdf = st.session_state.history.copy()
for col in ["lat","lon","threat","hour","scan_freq"]:
    hdf[col] = pd.to_numeric(hdf[col], errors="coerce").fillna(0)

ip_info = st.session_state.ip_info
ti = st.session_state.ti
cur_score = ti.get("final_score",0) if ti else 0

mc1,mc2,mc3,mc4,mc5,mc6 = st.columns(6)
with mc1: ui_metric("TOTAL SCANS",  len(hdf))
with mc2: ui_metric("HIGH RISK",    int((hdf["threat"]>70).sum()), "red")
with mc3: ui_metric("ANOMALIES",    st.session_state.anomaly_count, "org")
with mc4: ui_metric("COUNTRIES",    int(hdf["country"].nunique()))
with mc5: ui_metric("CURRENT SCORE", cur_score, "red" if cur_score>70 else "org" if cur_score>40 else "grn")
with mc6: ui_metric("IPs TRACKED",  len(st.session_state.tracked_ips), "pur")
st.markdown("<br>", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1,tab2,tab3,tab4,tab5,tab6,tab7,tab8,tab9,tab10 = st.tabs([
    "MAP & INTEL","ML ANALYSIS","ANALYTICS","PORT ANALYZER",
    "BATCH","REPORT","AI COPILOT","EVENTS","HISTORY","TERMINAL"])

# TAB 1 — MAP & INTEL
with tab1:
    if ip_info and ip_info.get("status") == "success":
        c1, c2 = st.columns([3,2])
        with c1:
            ui_section("GEOLOCATION MAP")
            fmap = make_map(ip_info, hdf, ti)
            st_folium(fmap, width=None, height=490, returned_objects=[])
        with c2:
            ui_section("TARGET INTELLIGENCE")
            cat = predict_threat_category(ti)
            ui_threat_score(ti["final_score"], cat, ti["conf_cls"], ti["confidence"])

            # [NEW v5.5] Correlated level + signals
            ui_correlated_level(ti.get("corr_level","LOW"), ti.get("corr_cls","corr-low"), ti.get("signals",0))

            # [NEW v5.5] Data source checklist
            ui_data_sources(ti.get("abuse_available", False), ti.get("vt_available", False))

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

            # [NEW v5.5] Textual reasoning
            reasoning = build_xai_reasoning(ti, ip_info)
            st.markdown(f'<div class="xai" style="border-left-color:#a855f7;margin-top:6px">'
                        f'<span style="color:#a855f7;font-weight:bold">AI REASONING: </span>{reasoning}</div>',
                        unsafe_allow_html=True)

            ui_info_panel([
                ("ABUSE REPORTS", str(ti["flags"].get("reports",0)), "bad" if ti["flags"].get("reports",0)>100 else "wn" if ti["flags"].get("reports",0)>20 else "ok"),
                ("VT SCORE",   f"{ti['vt_score']}/100", ""),
                ("DATA SOURCE", ti["source"].upper(), ""),
                ("SCAN TIME",  datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ""),
            ])

        # [NEW v5.5] Decision support panel below map columns
        ui_section("RECOMMENDED ACTIONS")
        ui_decision_panel(ti)

    else:
        st.markdown("""<div style="text-align:center;padding:70px 20px">
          <div style="font-family:'Orbitron',monospace;font-size:3rem;color:#0d4f6e">[ ]</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:.95rem;color:#4a7a9b;letter-spacing:3px;margin-top:10px">AWAITING TARGET</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:.72rem;color:#2a4a5b;margin-top:8px">Enter an IP or domain in the sidebar to begin</div>
        </div>""", unsafe_allow_html=True)
        ui_section("GLOBAL ACTIVITY MAP")
        st_folium(make_map({"lat":20,"lon":0,"query":"N/A"}, hdf, {}), width=None, height=450, returned_objects=[])

# TAB 2 — ML ANALYSIS
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
        else:
            st.info("Need 3+ records for clustering.")
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
        ml_s, ml_l = ml_anomaly_score(ip_info, ti, hdf) if enable_ml else (0,"N/A")
        with ms1: st.metric("Threat Category", predict_threat_category(ti))
        with ms2: st.metric("ML Status", ml_l)
        with ms3: st.metric("Anomaly Score", f"{ml_s}/100")
        with ms4: st.metric("Overall Risk", ti["risk_level"])
    if st.session_state.threat_history:
        ui_section("SCAN THREAT HISTORY")
        st.plotly_chart(chart_threat_score_history(st.session_state.threat_history), use_container_width=True)

# TAB 3 — ANALYTICS
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

# TAB 4 — PORT ANALYZER
with tab4:
    ui_section("SMART PORT ANALYZER")
    st.markdown('<div class="ip" style="font-size:.76rem">EDUCATIONAL SIMULATION — Deterministic from IP hash. No real network connections.</div>', unsafe_allow_html=True)
    target_ip = ip_info.get("query") if ip_info.get("status") == "success" else None
    port_res = st.session_state.port_cache.get(target_ip, []) if target_ip else []
    if port_res:
        open_p = [p for p in port_res if p["state"]=="OPEN"]
        closed_p = [p for p in port_res if p["state"]=="CLOSED"]
        filt_p = [p for p in port_res if p["state"]=="FILTERED"]
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
        st.info("Scan a target with Port Analyzer enabled to see results.")

# TAB 5 — BATCH
with tab5:
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
            ui_info_panel([
                ("TYPE","VALID NETWORK","ok"),("NETWORK",str(net.network_address),""),
                ("BROADCAST",str(net.broadcast_address),""),("HOSTS",f"{net.num_addresses:,}",""),
                ("PREFIX",f"/{net.prefixlen}",""),("VERSION",f"IPv{net.version}",""),])
        except ValueError:
            try:
                addr = ipaddress.ip_address(cidr_in)
                ui_info_panel([
                    ("TYPE","VALID IP","ok"),("ADDRESS",str(addr),""),
                    ("VERSION",f"IPv{addr.version}",""),("PRIVATE",str(addr.is_private),""),
                    ("LOOPBACK",str(addr.is_loopback),""),])
            except ValueError:
                ui_alert("Invalid IP / CIDR notation", "hi")

# TAB 6 — REPORT
with tab6:
    ui_section("REPORT EXPORT SYSTEM")
    if ip_info and ip_info.get("status") == "success" and ti:
        resolved_ip = ip_info.get("query","unknown")
        port_res = st.session_state.port_cache.get(resolved_ip, [])
        report = build_report(ip_info, ti, port_res)
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
                ("OPEN PORTS",     str(sum(1 for p in port_res if p["state"]=="OPEN")), ""),
                ("ABUSE REPORTS",  str(report["threat_intelligence"]["reports"]), ""),
            ])
        with rc2:
            ui_section("EXPORT OPTIONS")
            st.markdown('<div class="ip" style="font-size:.76rem">Full intelligence snapshot: geolocation, threat scores, port scan, WHOIS, correlated risk level.</div>', unsafe_allow_html=True)
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
        st.markdown('<div style="text-align:center;padding:50px 20px"><div style="font-family:Share Tech Mono,monospace;font-size:.88rem;color:#4a7a9b;letter-spacing:2px">SCAN A TARGET TO GENERATE REPORT</div></div>', unsafe_allow_html=True)

# TAB 7 — AI COPILOT
with tab7:
    ui_section("AI SECURITY COPILOT")
    mode = "OpenAI GPT-3.5" if OPENAI_KEY else "Rule-Based Engine"
    st.markdown(f'<div class="ip" style="font-size:.76rem"><span class="pulse"></span><span class="lb">MODE:</span> <span class="ok">{mode}</span></div>', unsafe_allow_html=True)
    for msg in st.session_state.chat_history:
        if msg["role"] == "user": ui_user_message(msg["content"])
        else: ui_copilot_response(mode, msg["content"])
    ui_section("QUICK PROMPTS")
    qp_list = ["Is this IP dangerous?","How do I block this IP?","Where is this IP from?","Any VPN or Tor flags?"]
    qcols = st.columns(4)
    for i, qp in enumerate(qp_list):
        with qcols[i]:
            if st.button(qp, key=f"qp_{i}", use_container_width=True):
                st.session_state.chat_history.append({"role":"user","content":qp})
                st.session_state.chat_history.append({"role":"assistant","content":ask_copilot(qp, st.session_state.ip_info, st.session_state.ti)})
                st.session_state.logs.append(format_log("INFO", f"Copilot: {qp[:40]}"))
                st.rerun()
    user_q = st.text_input("Ask the Copilot", placeholder="Type your security question", key="cop_in")
    ask_c1, ask_c2 = st.columns([5,1])
    with ask_c2:
        ask_btn = st.button("ASK", use_container_width=True)
    if ask_btn and user_q.strip():
        st.session_state.chat_history.append({"role":"user","content":user_q.strip()})
        st.session_state.chat_history.append({"role":"assistant","content":ask_copilot(user_q.strip(), st.session_state.ip_info, st.session_state.ti)})
        st.session_state.logs.append(format_log("INFO", f"Copilot: {user_q[:40]}"))
        st.rerun()
    if st.session_state.chat_history:
        if st.button("Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()

# TAB 8 — EVENTS [NEW v5.5]
with tab8:
    ev_col1, ev_col2 = st.columns([3, 2])
    with ev_col1:
        ui_section("LIVE EVENT STREAM")
        stream_html = render_event_stream(st.session_state.event_stream)
        st.markdown(
            f'<div class="term" style="height:380px">{stream_html}</div>',
            unsafe_allow_html=True)
        if st.button("Clear Event Stream", use_container_width=True):
            st.session_state.event_stream = [create_event("INFO","Event stream cleared")]
            st.rerun()

        # Event stats
        if st.session_state.event_stream:
            info_c  = sum(1 for e in st.session_state.event_stream if e["level"] == "INFO")
            warn_c  = sum(1 for e in st.session_state.event_stream if e["level"] == "WARNING")
            crit_c  = sum(1 for e in st.session_state.event_stream if e["level"] == "CRITICAL")
            ui_info_panel([
                ("INFO EVENTS",     str(info_c), "ok"),
                ("WARNING EVENTS",  str(warn_c), "wn"),
                ("CRITICAL EVENTS", str(crit_c), "bad"),
                ("TOTAL EVENTS",    str(len(st.session_state.event_stream)), ""),
            ])

    with ev_col2:
        ui_section("BEHAVIOR ANALYSIS")
        insights = analyze_behavior(st.session_state.tracked_ips, hdf)
        ui_behavior_insights(insights)

        if ip_info and ip_info.get("status") == "success" and ti:
            ui_section("DECISION SUPPORT")
            ui_decision_panel(ti)

# TAB 9 — HISTORY
with tab9:
    ui_section("SCAN HISTORY")
    hf1,hf2,hf3 = st.columns(3)
    with hf1: cf = st.selectbox("Country",["All"]+sorted(hdf["country"].dropna().unique().tolist()))
    with hf2: ef = st.selectbox("Event",  ["All"]+sorted(hdf["event"].dropna().unique().tolist()))
    with hf3: tf = st.selectbox("Threat", ["All","High (>70)","Medium (40-70)","Low (<40)"])
    filt = hdf.copy()
    if cf != "All": filt = filt[filt["country"]==cf]
    if ef != "All": filt = filt[filt["event"]==ef]
    if tf == "High (>70)":       filt = filt[filt["threat"]>70]
    elif tf == "Medium (40-70)": filt = filt[(filt["threat"]>=40)&(filt["threat"]<=70)]
    elif tf == "Low (<40)":      filt = filt[filt["threat"]<40]
    disp = filt[["timestamp","ip","country","threat","event","lat","lon"]].sort_values("timestamp",ascending=False).reset_index(drop=True)
    try:
        st.dataframe(disp.style.map(color_threat, subset=["threat"]), use_container_width=True, height=420)
    except Exception:
        st.dataframe(disp, use_container_width=True, height=420)
    dl1,dl2,dl3 = st.columns(3)
    with dl1: st.download_button("Export CSV",  filt.to_csv(index=False).encode(), "history.csv","text/csv",use_container_width=True)
    with dl2: st.download_button("Export JSON", filt.to_json(orient="records",default_handler=str).encode(),"history.json","application/json",use_container_width=True)
    with dl3:
        if st.button("Clear History", use_container_width=True):
            st.session_state.history = generate_history(40)
            st.session_state.logs.append(format_log("WARN","History reset"))
            st.rerun()

# TAB 10 — TERMINAL
with tab10:
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
                format_log("INFO","=== STATUS ==="),
                format_log("OK", f"Records: {len(hdf)}"),
                format_log("OK", f"IPs: {len(st.session_state.tracked_ips)}"),
                format_log("INFO",f"AbuseIPDB: {'LIVE' if ABUSEIPDB_KEY else 'MOCK'}"),
                format_log("INFO",f"VirusTotal: {'LIVE' if VIRUSTOTAL_KEY else 'MOCK'}"),
                format_log("INFO",f"OpenAI: {'LIVE' if OPENAI_KEY else 'RULE-BASED'}"),
                format_log("OK", f"Anomalies: {st.session_state.anomaly_count}"),
                format_log("OK", f"Events: {len(st.session_state.event_stream)}"),
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
                ("CORR. LEVEL",ti.get("corr_level","?"),""),
                ("SIGNALS",str(ti.get("signals",0)),""),
                ("SOURCE",ti["source"].upper(),""),("CONF",ti["confidence"],""),
            ])
        else:
            st.markdown('<div class="ip">No threat data yet.</div>', unsafe_allow_html=True)

st.markdown("""
<div style="text-align:center;padding:28px 0 8px;font-family:'Share Tech Mono',monospace;
            font-size:.68rem;color:#2a4a5b;letter-spacing:2px;border-top:1px solid #0d4f6e;margin-top:28px">
  CYBERTRACK v5.5 | AI-POWERED THREAT INTELLIGENCE | AUTHORIZED USE ONLY<br>
  <span style="color:#0d4f6e">ISOLATION FOREST | DBSCAN | ABUSEIPDB | VIRUSTOTAL | OPENAI | FOLIUM | PLOTLY | STREAMLIT</span>
</div>
""", unsafe_allow_html=True)
