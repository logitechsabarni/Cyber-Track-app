"""
CyberTrack v4.0 — Real-Time Threat Intelligence Platform
Upgrades from v3.0:
  - Real AbuseIPDB + VirusTotal API integration (with mock fallback)
  - AI Security Copilot (OpenAI if key present, else rule-based)
  - Report Generator (CSV + JSON export)
  - @st.cache_data on API calls (Streamlit Cloud optimized)
  - No blocking time.sleep() anywhere
  - New tab layout: Scanner | Map | ML Analysis | Analytics | Port Scanner |
                     WHOIS/Batch | History | Copilot | Logs
All v3.0 features preserved unchanged.
"""

import streamlit as st
import folium
from streamlit_folium import st_folium
import requests
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import random
import math
import socket
import ipaddress
import os
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import warnings
warnings.filterwarnings("ignore")

# ─── PAGE CONFIG ────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberTrack | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CSS (v3.0 preserved + minor additions) ──────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@300;400;600;700&display=swap');

  :root {
    --cyber-bg: #020a12;
    --cyber-surface: #071520;
    --cyber-border: #0d4f6e;
    --cyber-accent: #00d4ff;
    --cyber-accent2: #00ff88;
    --cyber-danger: #ff2d55;
    --cyber-warn: #ffaa00;
    --cyber-text: #c8e6f5;
    --cyber-dim: #4a7a9b;
    --cyber-purple: #a855f7;
  }
  html, body, .stApp {
    background-color: var(--cyber-bg) !important;
    color: var(--cyber-text) !important;
    font-family: 'Rajdhani', sans-serif !important;
  }
  .stApp::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px);
    background-size: 50px 50px;
    pointer-events: none;
    z-index: 0;
    animation: gridPulse 8s ease-in-out infinite;
  }
  @keyframes gridPulse { 0%,100%{opacity:.5} 50%{opacity:1} }
  section[data-testid="stSidebar"] {
    background: linear-gradient(180deg,#020d18 0%,#030f1f 100%) !important;
    border-right: 1px solid var(--cyber-border) !important;
  }
  .cyber-header {
    background: linear-gradient(135deg,#020d18 0%,#041525 50%,#020d18 100%);
    border: 1px solid var(--cyber-accent);
    border-radius: 4px;
    padding: 20px 30px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
    box-shadow: 0 0 30px rgba(0,212,255,.2), inset 0 0 30px rgba(0,212,255,.05);
  }
  .cyber-header::before {
    content:'';
    position:absolute;top:-50%;left:-50%;width:200%;height:200%;
    background: conic-gradient(transparent,rgba(0,212,255,.05),transparent 30%);
    animation: rotate 10s linear infinite;
  }
  @keyframes rotate { 100%{transform:rotate(360deg)} }
  .cyber-title {
    font-family: 'Orbitron', monospace !important;
    font-size: 2.2rem !important;
    font-weight: 900 !important;
    color: var(--cyber-accent) !important;
    text-shadow: 0 0 20px rgba(0,212,255,.8), 0 0 40px rgba(0,212,255,.4);
    letter-spacing: 4px;
    margin: 0;
    position: relative;
    z-index: 1;
  }
  .cyber-subtitle {
    font-family: 'Share Tech Mono', monospace;
    color: var(--cyber-accent2);
    font-size: .85rem;
    letter-spacing: 3px;
    margin-top: 4px;
    position: relative;
    z-index: 1;
  }
  .metric-card {
    background: linear-gradient(135deg,#071520 0%,#0a1f2e 100%);
    border: 1px solid var(--cyber-border);
    border-radius: 4px;
    padding: 18px;
    margin: 8px 0;
    position: relative;
    overflow: hidden;
    transition: all .3s ease;
  }
  .metric-card:hover { border-color:var(--cyber-accent); box-shadow:0 0 20px rgba(0,212,255,.2); transform:translateY(-2px); }
  .metric-card::after { content:''; position:absolute; top:0;left:0; width:3px;height:100%; background:var(--cyber-accent); box-shadow:0 0 10px var(--cyber-accent); }
  .metric-value { font-family:'Orbitron',monospace; font-size:2rem; font-weight:700; color:var(--cyber-accent); text-shadow:0 0 15px rgba(0,212,255,.6); }
  .metric-label { font-family:'Share Tech Mono',monospace; font-size:.75rem; color:var(--cyber-dim); letter-spacing:2px; text-transform:uppercase; }
  .metric-card.danger::after { background:var(--cyber-danger); box-shadow:0 0 10px var(--cyber-danger); }
  .metric-card.danger .metric-value { color:var(--cyber-danger); text-shadow:0 0 15px rgba(255,45,85,.6); }
  .metric-card.success::after { background:var(--cyber-accent2); box-shadow:0 0 10px var(--cyber-accent2); }
  .metric-card.success .metric-value { color:var(--cyber-accent2); text-shadow:0 0 15px rgba(0,255,136,.6); }
  .metric-card.warn::after { background:var(--cyber-warn); box-shadow:0 0 10px var(--cyber-warn); }
  .metric-card.warn .metric-value { color:var(--cyber-warn); text-shadow:0 0 15px rgba(255,170,0,.6); }
  .metric-card.purple::after { background:var(--cyber-purple); box-shadow:0 0 10px var(--cyber-purple); }
  .metric-card.purple .metric-value { color:var(--cyber-purple); text-shadow:0 0 15px rgba(168,85,247,.6); }
  .info-panel {
    background: linear-gradient(135deg,#071520 0%,#0a1f2e 100%);
    border: 1px solid var(--cyber-border);
    border-radius: 4px;
    padding: 20px;
    margin: 10px 0;
    font-family: 'Share Tech Mono', monospace;
    font-size: .82rem;
    color: var(--cyber-text);
    line-height: 1.8;
  }
  .info-panel .label { color:var(--cyber-accent); font-weight:bold; }
  .info-panel .value { color:var(--cyber-text); }
  .info-panel .bad   { color:var(--cyber-danger); }
  .info-panel .good  { color:var(--cyber-accent2); }
  .info-panel .warn  { color:var(--cyber-warn); }
  .alert-box {
    border-radius: 4px; padding: 12px 16px; margin: 8px 0;
    font-family:'Share Tech Mono',monospace; font-size:.8rem;
    display:flex; align-items:center; gap:10px;
    animation: alertPulse 2s ease-in-out infinite;
  }
  @keyframes alertPulse { 0%,100%{box-shadow:0 0 5px rgba(255,45,85,.3)} 50%{box-shadow:0 0 15px rgba(255,45,85,.6)} }
  .alert-high   { background:rgba(255,45,85,.1);  border:1px solid var(--cyber-danger); color:var(--cyber-danger); }
  .alert-medium { background:rgba(255,170,0,.1);  border:1px solid var(--cyber-warn);   color:var(--cyber-warn); }
  .alert-low    { background:rgba(0,255,136,.1);  border:1px solid var(--cyber-accent2);color:var(--cyber-accent2); }
  .section-header {
    font-family:'Orbitron',monospace; font-size:.9rem; color:var(--cyber-accent);
    letter-spacing:3px; text-transform:uppercase;
    border-bottom:1px solid var(--cyber-border); padding-bottom:8px; margin:20px 0 15px 0;
    text-shadow:0 0 10px rgba(0,212,255,.5);
  }
  .threat-score { font-family:'Orbitron',monospace; font-size:3rem; font-weight:900; text-align:center; padding:20px; border-radius:4px; text-shadow:0 0 30px currentColor; }
  .threat-critical { color:#ff0033; background:rgba(255,0,51,.1);   border:1px solid #ff0033; }
  .threat-high     { color:var(--cyber-danger); background:rgba(255,45,85,.1);  border:1px solid var(--cyber-danger); }
  .threat-medium   { color:var(--cyber-warn);   background:rgba(255,170,0,.1);  border:1px solid var(--cyber-warn); }
  .threat-low      { color:var(--cyber-accent2);background:rgba(0,255,136,.1);  border:1px solid var(--cyber-accent2); }
  .stButton > button {
    background:transparent !important; border:1px solid var(--cyber-accent) !important;
    color:var(--cyber-accent) !important; font-family:'Share Tech Mono',monospace !important;
    letter-spacing:2px !important; border-radius:2px !important;
    transition:all .3s ease !important; text-transform:uppercase !important;
  }
  .stButton > button:hover { background:rgba(0,212,255,.1) !important; box-shadow:0 0 15px rgba(0,212,255,.3) !important; transform:translateY(-1px) !important; }
  .stTextInput > div > div > input,
  .stSelectbox > div > div,
  .stNumberInput > div > div > input,
  .stTextArea > div > div > textarea {
    background:#071520 !important; border:1px solid var(--cyber-border) !important;
    color:var(--cyber-text) !important; font-family:'Share Tech Mono',monospace !important; border-radius:2px !important;
  }
  .stTextInput > div > div > input:focus { border-color:var(--cyber-accent) !important; box-shadow:0 0 10px rgba(0,212,255,.3) !important; }
  div[data-testid="stMetricValue"] { font-family:'Orbitron',monospace !important; color:var(--cyber-accent) !important; }
  .stDataFrame { border:1px solid var(--cyber-border); }
  h1, h2, h3 { font-family:'Orbitron',monospace !important; color:var(--cyber-accent) !important; }
  .log-terminal {
    background:#000d15; border:1px solid var(--cyber-border); border-radius:4px;
    padding:15px; font-family:'Share Tech Mono',monospace; font-size:.75rem;
    height:260px; overflow-y:auto; line-height:1.6;
  }
  .log-entry { margin:2px 0; }
  .log-time { color:var(--cyber-dim); }
  .log-info { color:var(--cyber-accent); }
  .log-warn { color:var(--cyber-warn); }
  .log-error { color:var(--cyber-danger); }
  .log-success { color:var(--cyber-accent2); }
  .port-table { width:100%; border-collapse:collapse; font-family:'Share Tech Mono',monospace; font-size:.78rem; }
  .port-table th { color:var(--cyber-accent); border-bottom:1px solid var(--cyber-border); padding:6px 10px; text-align:left; }
  .port-table td { padding:5px 10px; border-bottom:1px solid rgba(13,79,110,.3); }
  .port-open   { color:var(--cyber-accent2); }
  .port-closed { color:var(--cyber-dim); }
  .port-filtered { color:var(--cyber-warn); }
  ::-webkit-scrollbar { width:6px; }
  ::-webkit-scrollbar-track { background:var(--cyber-bg); }
  ::-webkit-scrollbar-thumb { background:var(--cyber-border); border-radius:3px; }
  ::-webkit-scrollbar-thumb:hover { background:var(--cyber-accent); }
  .pulse-dot {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: var(--cyber-accent2);
    animation: pulseDot 1.5s ease-in-out infinite;
    margin-right: 6px;
  }
  @keyframes pulseDot { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.3;transform:scale(.7)} }
  /* Copilot chat bubbles */
  .chat-user {
    background: rgba(0,212,255,.08); border:1px solid rgba(0,212,255,.3);
    border-radius:4px; padding:10px 14px; margin:6px 0;
    font-family:'Share Tech Mono',monospace; font-size:.8rem; color:var(--cyber-accent);
    text-align:right;
  }
  .chat-bot {
    background: rgba(0,255,136,.06); border:1px solid rgba(0,255,136,.25);
    border-radius:4px; padding:10px 14px; margin:6px 0;
    font-family:'Share Tech Mono',monospace; font-size:.8rem; color:var(--cyber-accent2);
  }
  .chat-bot .bot-label { color:var(--cyber-dim); font-size:.7rem; margin-bottom:4px; }
  /* Why risky panel */
  .why-risky {
    background: rgba(255,170,0,.06); border-left:3px solid var(--cyber-warn);
    padding:12px 16px; margin:8px 0; font-family:'Share Tech Mono',monospace;
    font-size:.78rem; color:var(--cyber-text); line-height:1.8;
  }
  .badge {
    display:inline-block; padding:2px 8px; border-radius:2px;
    font-family:'Share Tech Mono',monospace; font-size:.65rem; letter-spacing:1px;
  }
  .badge-red    { background:rgba(255,45,85,.15);  border:1px solid var(--cyber-danger); color:var(--cyber-danger); }
  .badge-green  { background:rgba(0,255,136,.15);  border:1px solid var(--cyber-accent2);color:var(--cyber-accent2); }
  .badge-yellow { background:rgba(255,170,0,.15);  border:1px solid var(--cyber-warn);   color:var(--cyber-warn); }
  .badge-blue   { background:rgba(0,212,255,.15);  border:1px solid var(--cyber-accent); color:var(--cyber-accent); }
</style>
""", unsafe_allow_html=True)


# ─── ENV / API KEYS ──────────────────────────────────────────────────────────
ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_API_KEY",  "")
VIRUSTOTAL_KEY  = os.environ.get("VIRUSTOTAL_API_KEY", "")
OPENAI_KEY      = os.environ.get("OPENAI_API_KEY",     "")


# ─── HELPER FUNCTIONS (v3.0 preserved) ──────────────────────────────────────

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


@st.cache_data(ttl=300, show_spinner=False)
def get_ip_info(target: str) -> dict:
    ip = resolve_target(target)
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
        if r.status_code == 200:
            data = r.json()
            data["_resolved_ip"] = ip
            return data
    except Exception:
        pass
    return {}


@st.cache_data(ttl=300, show_spinner=False)
def get_threat_intel(ip: str) -> dict:
    """Real AbuseIPDB + VirusTotal with mock fallback."""
    result = {
        "abuseScore":   0,
        "vtScore":      0,
        "isVPN":        False,
        "isTor":        False,
        "isProxy":      False,
        "isBot":        False,
        "isDatacenter": False,
        "reports":      0,
        "categories":   [],
        "source":       "mock",
    }

    # ── AbuseIPDB ──
    if ABUSEIPDB_KEY:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=8,
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                result["abuseScore"]   = d.get("abuseConfidenceScore", 0)
                result["reports"]      = d.get("totalReports", 0)
                result["isVPN"]        = d.get("isPublic", True) and d.get("usageType","") in ("VPN","Hosting","Data Center/Web Hosting/Transit")
                result["isDatacenter"] = "hosting" in d.get("usageType","").lower() or "data center" in d.get("usageType","").lower()
                result["source"]       = "abuseipdb"
        except Exception:
            pass

    # ── VirusTotal ──
    if VIRUSTOTAL_KEY:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=8,
            )
            if r.status_code == 200:
                stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                malicious  = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total      = sum(stats.values()) or 1
                result["vtScore"]   = int(((malicious + suspicious) / total) * 100)
                result["abuseScore"] = max(result["abuseScore"], result["vtScore"])
                if result["source"] == "mock":
                    result["source"] = "virustotal"
                else:
                    result["source"] = "abuseipdb+virustotal"
        except Exception:
            pass

    # ── Mock fallback ──
    if result["source"] == "mock":
        seed = sum(ord(c) for c in ip)
        rng  = random.Random(seed)
        result["abuseScore"]   = rng.randint(0, 100)
        result["isVPN"]        = rng.random() > 0.70
        result["isTor"]        = rng.random() > 0.85
        result["isProxy"]      = rng.random() > 0.75
        result["isBot"]        = rng.random() > 0.80
        result["isDatacenter"] = rng.random() > 0.60
        result["reports"]      = rng.randint(0, 500)
        result["categories"]   = rng.sample(
            ["Spam","Hacking","DDoS","Phishing","Port Scan","Brute Force","Malware","SSH Abuse"],
            k=rng.randint(0, 3)
        )

    return result


def build_why_risky(threat_data: dict, ip_info: dict) -> str:
    """Generate a human-readable 'Why risky?' explanation."""
    reasons = []
    ts = threat_data.get("abuseScore", 0)
    if ts > 80:
        reasons.append(f"Abuse confidence score is critically high ({ts}/100).")
    elif ts > 50:
        reasons.append(f"Abuse confidence score is elevated ({ts}/100).")
    if threat_data.get("isTor"):
        reasons.append("IP is a known Tor exit node — anonymized traffic source.")
    if threat_data.get("isVPN"):
        reasons.append("IP is associated with a VPN or anonymization service.")
    if threat_data.get("isProxy"):
        reasons.append("IP is flagged as a proxy server.")
    if threat_data.get("isBot"):
        reasons.append("IP has been identified performing automated/bot activity.")
    if threat_data.get("isDatacenter"):
        reasons.append("IP originates from a datacenter/hosting provider (not residential).")
    rpt = threat_data.get("reports", 0)
    if rpt > 100:
        reasons.append(f"High volume of abuse reports: {rpt} reports on record.")
    elif rpt > 20:
        reasons.append(f"Moderate abuse report volume: {rpt} reports.")
    for cat in threat_data.get("categories", []):
        reasons.append(f"Abuse category on record: {cat}.")
    hosting = ip_info.get("hosting", False)
    if hosting:
        reasons.append("IP is flagged as hosted infrastructure.")
    if not reasons:
        reasons.append("No significant threat indicators detected for this IP.")
    return "<br>".join(f"▸ {r}" for r in reasons)


def simulated_whois(ip: str, ip_info: dict) -> dict:
    seed = sum(ord(c) for c in ip)
    rng  = random.Random(seed)
    reg_date = datetime.now() - timedelta(days=rng.randint(180, 3650))
    return {
        "Network":     ip_info.get("as", "N/A"),
        "Org":         ip_info.get("org", "N/A"),
        "Country":     ip_info.get("country", "N/A"),
        "CIDR":        f"{'.'.join(ip.split('.')[:2])}.0.0/16",
        "Registered":  reg_date.strftime("%Y-%m-%d"),
        "Updated":     (reg_date + timedelta(days=rng.randint(30, 365))).strftime("%Y-%m-%d"),
        "Abuse Email": f"abuse@{ip_info.get('isp','unknown').lower().replace(' ','-')}.com",
        "Netname":     f"NET-{'-'.join(ip.split('.')[:2])}-0-0",
    }


def simulate_port_scan(ip: str) -> list:
    seed = sum(ord(c) for c in ip)
    rng  = random.Random(seed)
    common_ports = [
        (21,"FTP"),(22,"SSH"),(23,"Telnet"),(25,"SMTP"),(53,"DNS"),
        (80,"HTTP"),(110,"POP3"),(143,"IMAP"),(443,"HTTPS"),(445,"SMB"),
        (3306,"MySQL"),(3389,"RDP"),(5900,"VNC"),(8080,"HTTP-Alt"),
        (8443,"HTTPS-Alt"),(6379,"Redis"),
    ]
    results = []
    for port, service in common_ports:
        r = rng.random()
        state = "OPEN" if r > 0.75 else "CLOSED" if r > 0.45 else "FILTERED"
        banner = ""
        if state == "OPEN":
            banners = {
                "SSH":"OpenSSH 8.2p1 Ubuntu","HTTP":"nginx/1.18.0",
                "HTTPS":"nginx/1.18.0","FTP":"vsftpd 3.0.3",
                "MySQL":"MySQL 8.0.27","RDP":"MS RDP 10.0","Redis":"Redis 6.2.6",
            }
            banner = banners.get(service, "")
        results.append({"port":port,"service":service,"state":state,"banner":banner})
    return results


def ml_anomaly_score(ip_info: dict, history_df: pd.DataFrame):
    if history_df.empty or len(history_df) < 5:
        return 0.0, "INSUFFICIENT_DATA"
    features = history_df[["lat","lon","threat"]].dropna()
    if len(features) < 5:
        return 0.0, "INSUFFICIENT_DATA"
    try:
        clf = IsolationForest(contamination=0.2, random_state=42, n_estimators=50)
        clf.fit(features)
        cur = np.array([[float(ip_info.get("lat",0)), float(ip_info.get("lon",0)), 0.0]])
        raw = clf.score_samples(cur)[0]
        normalized = max(0, min(100, int((-raw + 0.5) * 100)))
    except Exception:
        normalized = 0
    label = ("CRITICAL" if normalized > 80 else "HIGH" if normalized > 60 else
              "MEDIUM"   if normalized > 40 else "LOW")
    return normalized, label


def ml_cluster_analysis(df: pd.DataFrame) -> pd.DataFrame:
    if len(df) < 3:
        return df.assign(cluster=-1)
    coords = df[["lat","lon"]].dropna()
    if len(coords) < 3:
        return df.assign(cluster=-1)
    try:
        scaler = StandardScaler()
        scaled = scaler.fit_transform(coords)
        labels = DBSCAN(eps=0.5, min_samples=2).fit_predict(scaled)
        df = df.copy()
        df["cluster"] = -1
        df.loc[coords.index, "cluster"] = labels
    except Exception:
        df = df.copy()
        df["cluster"] = -1
    return df


def ml_predict_threat_category(threat_data: dict) -> str:
    score = threat_data.get("abuseScore", 0)
    flags = sum([bool(threat_data.get(k)) for k in ("isVPN","isTor","isProxy","isBot")])
    if score > 80 or threat_data.get("isTor") or flags >= 3:
        return "⚠️ CRITICAL THREAT"
    elif score > 60 or flags >= 2:
        return "🔴 HIGH RISK"
    elif score > 40 or flags >= 1:
        return "🟡 SUSPICIOUS"
    elif score > 20:
        return "🔵 MONITOR"
    return "🟢 CLEAN"


def generate_scan_history(n: int = 35) -> pd.DataFrame:
    base_lat, base_lon = 20.0, 77.0
    records = []
    countries = ["India","USA","China","Russia","Germany","Brazil","UK","France","Japan","Iran"]
    events    = ["LOGIN","SCAN","PROBE","DOWNLOAD","UPLOAD","ATTACK","BRUTE_FORCE","SQL_INJECT"]
    for i in range(n):
        t   = datetime.now() - timedelta(hours=i * 1.5 + random.random())
        lat = base_lat + (random.uniform(-45,45) if i % 7 == 0 else random.uniform(-10,10))
        lon = base_lon + (random.uniform(-90,90) if i % 7 == 0 else random.uniform(-10,10))
        lat = max(-85.0, min(85.0, lat))
        records.append({
            "timestamp": t,
            "ip":        f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "lat":       round(lat, 4),
            "lon":       round(lon, 4),
            "country":   random.choice(countries),
            "threat":    random.randint(0, 100),
            "hour":      t.hour,
            "event":     random.choice(events),
        })
    return pd.DataFrame(records)


def make_folium_map(ip_info: dict, history_df: pd.DataFrame, threat_data: dict) -> folium.Map:
    lat = float(ip_info.get("lat", 20.5937))
    lon = float(ip_info.get("lon", 78.9629))
    m   = folium.Map(location=[lat, lon], zoom_start=4, tiles=None)
    folium.TileLayer("CartoDB dark_matter", name="Dark Matter", attr="CartoDB").add_to(m)
    for _, row in history_df.iterrows():
        color = "#ff2d55" if row["threat"] > 70 else "#ffaa00" if row["threat"] > 40 else "#00ff88"
        folium.CircleMarker(
            location=[row["lat"], row["lon"]], radius=4,
            color=color, fill=True, fill_color=color, fill_opacity=0.55,
            popup=f"{row['ip']} | {row['country']} | Threat: {row['threat']}",
            tooltip=row["ip"],
        ).add_to(m)
    ts = threat_data.get("abuseScore", 0)
    marker_color = "red" if ts > 70 else "orange" if ts > 40 else "green"
    folium.Marker(
        location=[lat, lon],
        popup=folium.Popup(f"""
            <div style='font-family:monospace;background:#000;color:#00d4ff;
                        padding:10px;border-radius:4px;min-width:200px'>
            <b style='color:#00ff88'>🎯 TARGET IP</b><br>
            IP: {ip_info.get('query','N/A')}<br>
            City: {ip_info.get('city','N/A')}<br>
            ISP: {ip_info.get('isp','N/A')}<br>
            Threat: <b style='color:#ff2d55'>{ts}/100</b>
            </div>""", max_width=300),
        tooltip=f"🎯 {ip_info.get('query','Target')}",
        icon=folium.Icon(color=marker_color, icon="info-sign"),
    ).add_to(m)
    ring_color = "#ff2d55" if ts > 70 else "#ffaa00" if ts > 40 else "#00ff88"
    for radius, opacity in [(50000,0.7),(100000,0.4),(180000,0.15)]:
        folium.Circle(location=[lat,lon], radius=radius,
                      color=ring_color, fill=False, weight=2, opacity=opacity).add_to(m)
    folium.LayerControl().add_to(m)
    return m


def format_log_entry(level: str, msg: str) -> str:
    t   = datetime.now().strftime("%H:%M:%S")
    cls = {"INFO":"log-info","WARN":"log-warn","ERROR":"log-error","OK":"log-success"}.get(level,"log-info")
    return f'<div class="log-entry"><span class="log-time">[{t}]</span> <span class="{cls}">[{level}]</span> {msg}</div>'


def color_threat_cell(val):
    if val > 70: return "color: #ff2d55; font-weight: bold"
    elif val > 40: return "color: #ffaa00"
    return "color: #00ff88"


# ─── REPORT GENERATOR ────────────────────────────────────────────────────────

def build_report(ip_info: dict, threat_data: dict, port_results: list, whois_data: dict) -> dict:
    """Assemble a full report dict for export."""
    return {
        "generated_at":  datetime.now().isoformat(),
        "ip_intelligence": {
            "ip":        ip_info.get("query","N/A"),
            "hostname":  ip_info.get("reverse","N/A"),
            "city":      ip_info.get("city","N/A"),
            "region":    ip_info.get("regionName","N/A"),
            "country":   ip_info.get("country","N/A"),
            "lat":       ip_info.get("lat","N/A"),
            "lon":       ip_info.get("lon","N/A"),
            "timezone":  ip_info.get("timezone","N/A"),
            "isp":       ip_info.get("isp","N/A"),
            "org":       ip_info.get("org","N/A"),
            "as":        ip_info.get("as","N/A"),
            "proxy":     ip_info.get("proxy","N/A"),
            "hosting":   ip_info.get("hosting","N/A"),
            "mobile":    ip_info.get("mobile","N/A"),
        },
        "threat_intelligence": {
            "abuse_score":   threat_data.get("abuseScore", 0),
            "vt_score":      threat_data.get("vtScore", 0),
            "reports":       threat_data.get("reports", 0),
            "is_vpn":        threat_data.get("isVPN", False),
            "is_tor":        threat_data.get("isTor", False),
            "is_proxy":      threat_data.get("isProxy", False),
            "is_bot":        threat_data.get("isBot", False),
            "is_datacenter": threat_data.get("isDatacenter", False),
            "categories":    threat_data.get("categories", []),
            "risk_level":    ml_predict_threat_category(threat_data),
            "data_source":   threat_data.get("source","mock"),
        },
        "whois":       whois_data,
        "port_scan":   port_results,
    }


def report_to_csv(report: dict) -> str:
    rows = []
    for k, v in report["ip_intelligence"].items():
        rows.append({"section":"IP Intelligence","field":k,"value":str(v)})
    for k, v in report["threat_intelligence"].items():
        rows.append({"section":"Threat Intel","field":k,"value":str(v)})
    for k, v in report.get("whois",{}).items():
        rows.append({"section":"WHOIS","field":k,"value":str(v)})
    for p in report.get("port_scan",[]):
        rows.append({"section":"Port Scan","field":f"port_{p['port']}_{p['service']}","value":p["state"]})
    return pd.DataFrame(rows).to_csv(index=False)


# ─── AI COPILOT ──────────────────────────────────────────────────────────────

def rule_based_copilot(question: str, ip_info: dict, threat_data: dict) -> str:
    """Rule-based fallback when no OpenAI key is present."""
    q    = question.lower()
    ip   = ip_info.get("query", "the target IP")
    ts   = threat_data.get("abuseScore", 0)
    risk = ml_predict_threat_category(threat_data)

    if any(w in q for w in ["dangerous","risky","threat","safe","malicious"]):
        if ts > 70:
            return (f"[ANALYSIS] {ip} has a high abuse score of {ts}/100. "
                    f"Risk level: {risk}. "
                    "Recommended action: Block this IP at your firewall immediately. "
                    "Check your logs for past connections from this address.")
        elif ts > 40:
            return (f"[ANALYSIS] {ip} has a moderate abuse score of {ts}/100. "
                    f"Risk level: {risk}. "
                    "Monitor traffic from this IP. Consider rate-limiting or geo-blocking if not expected.")
        else:
            return (f"[ANALYSIS] {ip} has a low abuse score of {ts}/100. "
                    f"Risk level: {risk}. "
                    "No immediate action required. Continue standard monitoring.")

    if any(w in q for w in ["block","firewall","mitigate","defend","protect"]):
        return (f"[MITIGATION] For {ip} (score {ts}/100):\n"
                "1. Add to firewall deny list if score > 60.\n"
                "2. Enable geo-blocking for high-risk regions.\n"
                "3. Alert your SOC team if this IP has active connections.\n"
                "4. Check SIEM for historical activity from this address.")

    if any(w in q for w in ["vpn","tor","proxy"]):
        flags = []
        if threat_data.get("isVPN"):  flags.append("VPN")
        if threat_data.get("isTor"):  flags.append("Tor exit node")
        if threat_data.get("isProxy"): flags.append("Proxy")
        if flags:
            return f"[FLAGS] {ip} is identified as: {', '.join(flags)}. Anonymized traffic sources are higher risk — treat as untrusted by default."
        return f"[FLAGS] No VPN, Tor, or Proxy flags detected for {ip}."

    if any(w in q for w in ["location","country","where","geo"]):
        return (f"[GEO] {ip} is located in {ip_info.get('city','Unknown')}, "
                f"{ip_info.get('country','Unknown')}. "
                f"ISP: {ip_info.get('isp','Unknown')}. "
                f"Coordinates: {ip_info.get('lat','?')}, {ip_info.get('lon','?')}.")

    if any(w in q for w in ["report","export","download"]):
        return "[REPORT] Use the 'Report Generator' tab to export a full JSON or CSV report for this IP."

    if any(w in q for w in ["port","scan","open"]):
        return "[PORTS] Check the Port Scanner tab for a simulated port analysis of this IP."

    return (f"[COPILOT] I can help with: threat analysis, risk assessment, mitigation steps, "
            f"geo info, VPN/Tor/Proxy flags, and report generation for {ip}. "
            "Try asking: 'Is this IP dangerous?' or 'How do I block this IP?'")


def openai_copilot(question: str, ip_info: dict, threat_data: dict) -> str:
    """Call OpenAI API for AI-powered analysis."""
    context = (
        f"IP: {ip_info.get('query','N/A')}, "
        f"Country: {ip_info.get('country','N/A')}, "
        f"ISP: {ip_info.get('isp','N/A')}, "
        f"Abuse Score: {threat_data.get('abuseScore',0)}/100, "
        f"VPN: {threat_data.get('isVPN',False)}, "
        f"Tor: {threat_data.get('isTor',False)}, "
        f"Risk: {ml_predict_threat_category(threat_data)}"
    )
    system_prompt = (
        "You are CyberTrack AI — a cybersecurity analyst assistant. "
        "Answer concisely and professionally. Focus on threat analysis, mitigation, "
        "and actionable recommendations. Use the IP context provided."
    )
    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type": "application/json"},
            json={
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Context: {context}\n\nQuestion: {question}"},
                ],
                "max_tokens": 300,
                "temperature": 0.4,
            },
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"].strip()
        return f"[OpenAI Error {r.status_code}] Falling back to rule-based response.\n\n" + rule_based_copilot(question, ip_info, threat_data)
    except Exception as e:
        return f"[OpenAI unavailable] {e}\n\n" + rule_based_copilot(question, ip_info, threat_data)


def ask_copilot(question: str, ip_info: dict, threat_data: dict) -> str:
    if not ip_info or ip_info.get("status") != "success":
        return "[COPILOT] Please scan an IP first so I have context to analyze."
    if OPENAI_KEY:
        return openai_copilot(question, ip_info, threat_data)
    return rule_based_copilot(question, ip_info, threat_data)


# ─── SESSION STATE ────────────────────────────────────────────────────────────
defaults = {
    "history":          lambda: generate_scan_history(35),
    "logs":             lambda: [
        format_log_entry("OK",   "CyberTrack v4.0 initialized"),
        format_log_entry("INFO", f"API keys loaded: AbuseIPDB={'YES' if ABUSEIPDB_KEY else 'NO'}, VT={'YES' if VIRUSTOTAL_KEY else 'NO'}, OpenAI={'YES' if OPENAI_KEY else 'NO'}"),
        format_log_entry("INFO", "ML anomaly engine loaded (IsolationForest + DBSCAN)"),
        format_log_entry("OK",   "All systems operational"),
    ],
    "tracked_ips":      list,
    "ip_info":          dict,
    "threat_data":      dict,
    "port_scan_cache":  dict,
    "whois_cache":      dict,
    "batch_results":    list,
    "threat_history":   list,
    "chat_history":     list,
}
for key, factory in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = factory()


# ─── SIDEBAR ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:15px 0 20px 0">
      <div style="font-family:'Orbitron',monospace;font-size:1.4rem;color:#00d4ff;
                  text-shadow:0 0 15px rgba(0,212,255,.8);letter-spacing:3px">🛡️ CYBERTRACK</div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:.65rem;
                  color:#4a7a9b;letter-spacing:2px;margin-top:4px">v4.0 · THREAT INTELLIGENCE</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-header">⚙ SINGLE TARGET</div>', unsafe_allow_html=True)
    target_input = st.text_input("🎯 IP / Domain", placeholder="e.g. 8.8.8.8 or google.com", key="target")
    col_a, col_b = st.columns(2)
    with col_a: scan_btn  = st.button("⚡ SCAN",  use_container_width=True)
    with col_b: clear_btn = st.button("🗑 CLEAR", use_container_width=True)

    st.markdown('<div class="section-header">📦 BATCH SCAN</div>', unsafe_allow_html=True)
    batch_input = st.text_area("IPs (one per line)", height=80, placeholder="8.8.8.8\n1.1.1.1\n...")
    batch_btn   = st.button("⚡ BATCH SCAN", use_container_width=True)

    st.markdown('<div class="section-header">🔧 OPTIONS</div>', unsafe_allow_html=True)
    enable_ml      = st.toggle("ML Anomaly Detection", value=True)
    enable_threat  = st.toggle("Threat Intelligence",  value=True)
    enable_cluster = st.toggle("Geo Clustering",       value=True)
    enable_ports   = st.toggle("Port Scanner (sim)",   value=True)

    st.markdown('<div class="section-header">📡 QUICK TARGETS</div>', unsafe_allow_html=True)
    for label, q in {"Google DNS":"8.8.8.8","Cloudflare":"1.1.1.1","OpenDNS":"208.67.222.222","Quad9":"9.9.9.9"}.items():
        if st.button(f"▸ {label} ({q})", key=f"q_{q}", use_container_width=True):
            st.session_state["target"] = q
            st.rerun()

    # API status indicators
    st.markdown('<div class="section-header">🔑 API STATUS</div>', unsafe_allow_html=True)
    def api_badge(name, present):
        cls = "badge-green" if present else "badge-yellow"
        status = "LIVE" if present else "MOCK"
        return f'<span class="badge {cls}">{name}: {status}</span> '
    st.markdown(
        api_badge("AbuseIPDB", bool(ABUSEIPDB_KEY)) +
        api_badge("VirusTotal", bool(VIRUSTOTAL_KEY)) + "<br>" +
        api_badge("OpenAI", bool(OPENAI_KEY)),
        unsafe_allow_html=True
    )

    st.markdown('<div class="section-header">📊 SESSION STATS</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="info-panel" style="font-size:.75rem">
      <span class="label">SCANNED IPs:</span>    <span class="value">{len(st.session_state.tracked_ips)}</span><br>
      <span class="label">HISTORY:</span>         <span class="value">{len(st.session_state.history)} records</span><br>
      <span class="label">BATCH RESULTS:</span>   <span class="value">{len(st.session_state.batch_results)}</span><br>
      <span class="label">CHAT MESSAGES:</span>   <span class="value">{len(st.session_state.chat_history)}</span><br>
      <span class="label">STATUS:</span>          <span class="good"><span class="pulse-dot"></span>ONLINE</span>
    </div>
    """, unsafe_allow_html=True)

    if clear_btn:
        for k in ("ip_info","threat_data","port_scan_cache","whois_cache"):
            st.session_state[k] = {}
        st.session_state.logs.append(format_log_entry("INFO","Session cleared"))
        st.rerun()


# ─── SCAN LOGIC ───────────────────────────────────────────────────────────────
if scan_btn and target_input:
    with st.spinner(f"🔍 Scanning {target_input} ..."):
        st.session_state.logs.append(format_log_entry("INFO", f"Initiating scan: {target_input}"))
        ip_info    = get_ip_info(target_input)
        threat_data = get_threat_intel(resolve_target(target_input)) if enable_threat else {}

        if ip_info and ip_info.get("status") == "success":
            st.session_state.ip_info     = ip_info
            st.session_state.threat_data = threat_data
            resolved_ip = ip_info.get("_resolved_ip", target_input)
            if resolved_ip not in st.session_state.tracked_ips:
                st.session_state.tracked_ips.append(resolved_ip)
            if enable_ports:
                st.session_state.port_scan_cache[resolved_ip] = simulate_port_scan(resolved_ip)
            st.session_state.whois_cache[resolved_ip] = simulated_whois(resolved_ip, ip_info)
            new_row = pd.DataFrame([{
                "timestamp": datetime.now(),
                "ip":        ip_info.get("query", target_input),
                "lat":       float(ip_info.get("lat",0)),
                "lon":       float(ip_info.get("lon",0)),
                "country":   ip_info.get("country","Unknown"),
                "threat":    threat_data.get("abuseScore",0),
                "hour":      datetime.now().hour,
                "event":     "SCAN",
            }])
            st.session_state.history = pd.concat(
                [st.session_state.history, new_row], ignore_index=True
            )
            st.session_state.threat_history.append({
                "timestamp": datetime.now(),
                "ip":        ip_info.get("query", target_input),
                "score":     threat_data.get("abuseScore",0),
            })
            ts = threat_data.get("abuseScore",0)
            src = threat_data.get("source","mock")
            st.session_state.logs.append(format_log_entry("OK",   f"Located: {ip_info.get('city')}, {ip_info.get('country')}"))
            st.session_state.logs.append(format_log_entry("INFO", f"Threat source: {src.upper()}"))
            if ts > 60:
                st.session_state.logs.append(format_log_entry("ERROR", f"HIGH THREAT: {ts}/100"))
            elif ts > 30:
                st.session_state.logs.append(format_log_entry("WARN",  f"Moderate threat: {ts}/100"))
            else:
                st.session_state.logs.append(format_log_entry("OK",    f"Threat nominal: {ts}/100"))
        else:
            st.session_state.logs.append(format_log_entry("ERROR", f"Failed to resolve: {target_input}"))
            st.error(f"⚠️ Could not resolve **{target_input}**. Check the address and try again.")


# ─── BATCH SCAN ───────────────────────────────────────────────────────────────
if batch_btn and batch_input.strip():
    targets = [t.strip() for t in batch_input.strip().splitlines() if t.strip()]
    results = []
    prog = st.progress(0)
    for i, tgt in enumerate(targets[:15]):
        ii = get_ip_info(tgt)
        td = get_threat_intel(resolve_target(tgt)) if enable_threat else {}
        if ii and ii.get("status") == "success":
            results.append({
                "ip":      ii.get("query", tgt),
                "country": ii.get("country","Unknown"),
                "city":    ii.get("city","Unknown"),
                "isp":     ii.get("isp","Unknown"),
                "threat":  td.get("abuseScore",0),
                "vpn":     td.get("isVPN",False),
                "tor":     td.get("isTor",False),
                "source":  td.get("source","mock"),
                "lat":     float(ii.get("lat",0)),
                "lon":     float(ii.get("lon",0)),
            })
        else:
            results.append({"ip":tgt,"country":"FAILED","city":"","isp":"","threat":0,
                             "vpn":False,"tor":False,"source":"error","lat":0.0,"lon":0.0})
        prog.progress((i+1)/len(targets))
    prog.empty()
    st.session_state.batch_results = results
    st.session_state.logs.append(format_log_entry("OK", f"Batch scan complete: {len(results)} targets"))


# ─── MAIN CONTENT ─────────────────────────────────────────────────────────────
st.markdown("""
<div class="cyber-header">
  <div class="cyber-title">🛡️ CYBERTRACK</div>
  <div class="cyber-subtitle">REAL-TIME LOCATION INTELLIGENCE & THREAT ANALYSIS PLATFORM v4.0</div>
</div>
""", unsafe_allow_html=True)

ip_info     = st.session_state.ip_info
threat_data = st.session_state.threat_data
history_df  = st.session_state.history.copy()

for col in ["lat","lon","threat","hour"]:
    history_df[col] = pd.to_numeric(history_df[col], errors="coerce").fillna(0)

# ─── TOP METRICS ──────────────────────────────────────────────────────────────
mc1,mc2,mc3,mc4,mc5,mc6 = st.columns(6)
total_scans      = len(history_df)
high_threats     = int((history_df["threat"] > 70).sum())
unique_countries = int(history_df["country"].nunique())
avg_threat       = int(history_df["threat"].mean()) if len(history_df) else 0
current_threat   = threat_data.get("abuseScore",0) if threat_data else 0
tracked_count    = len(st.session_state.tracked_ips)

with mc1:
    st.markdown(f"""<div class="metric-card"><div class="metric-label">TOTAL SCANS</div><div class="metric-value">{total_scans}</div></div>""", unsafe_allow_html=True)
with mc2:
    st.markdown(f"""<div class="metric-card danger"><div class="metric-label">HIGH THREATS</div><div class="metric-value">{high_threats}</div></div>""", unsafe_allow_html=True)
with mc3:
    st.markdown(f"""<div class="metric-card"><div class="metric-label">COUNTRIES</div><div class="metric-value">{unique_countries}</div></div>""", unsafe_allow_html=True)
with mc4:
    st.markdown(f"""<div class="metric-card warn"><div class="metric-label">AVG THREAT %</div><div class="metric-value">{avg_threat}</div></div>""", unsafe_allow_html=True)
with mc5:
    cls = "danger" if current_threat > 70 else "warn" if current_threat > 40 else "success"
    st.markdown(f"""<div class="metric-card {cls}"><div class="metric-label">CURRENT TARGET</div><div class="metric-value">{current_threat}</div></div>""", unsafe_allow_html=True)
with mc6:
    st.markdown(f"""<div class="metric-card purple"><div class="metric-label">IPs TRACKED</div><div class="metric-value">{tracked_count}</div></div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ─── TABS ─────────────────────────────────────────────────────────────────────
tab1,tab2,tab3,tab4,tab5,tab6,tab7,tab8,tab9 = st.tabs([
    "🗺️  MAP & INTEL",
    "🤖  ML ANALYSIS",
    "📈  ANALYTICS",
    "🔌  PORT SCANNER",
    "🌐  WHOIS / BATCH",
    "📋  HISTORY",
    "📄  REPORT",
    "💬  AI COPILOT",
    "🖥️  TERMINAL",
])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — MAP & INTEL (v3.0 preserved + why risky panel)
# ═══════════════════════════════════════════════════════════════════════════════
with tab1:
    if ip_info and ip_info.get("status") == "success":
        map_col, info_col = st.columns([3, 2])
        with map_col:
            st.markdown('<div class="section-header">🗺️ GEOLOCATION MAP</div>', unsafe_allow_html=True)
            fmap = make_folium_map(ip_info, history_df, threat_data)
            st_folium(fmap, width=None, height=490, returned_objects=[])

        with info_col:
            st.markdown('<div class="section-header">📍 TARGET INTELLIGENCE</div>', unsafe_allow_html=True)
            threat_cat = ml_predict_threat_category(threat_data)
            ts = threat_data.get("abuseScore", 0)
            tc = ("threat-critical" if ts > 80 else "threat-high" if ts > 60 else
                  "threat-medium"   if ts > 40 else "threat-low")
            src_badge = threat_data.get("source","mock").upper()
            st.markdown(
                f'<div class="threat-score {tc}">{ts}<br>'
                f'<span style="font-size:.7rem;letter-spacing:2px">{threat_cat}</span><br>'
                f'<span style="font-size:.55rem;color:var(--cyber-dim)">SOURCE: {src_badge}</span></div>',
                unsafe_allow_html=True
            )

            proxy_class = "bad" if ip_info.get("proxy") else "good"
            host_class  = "bad" if ip_info.get("hosting") else "good"
            st.markdown(f"""
            <div class="info-panel">
              <span class="label">◈ IP ADDRESS  :</span> <span class="value">{ip_info.get('query','N/A')}</span><br>
              <span class="label">◈ HOSTNAME    :</span> <span class="value">{ip_info.get('reverse','N/A')}</span><br>
              <span class="label">◈ CITY        :</span> <span class="value">{ip_info.get('city','N/A')}</span><br>
              <span class="label">◈ REGION      :</span> <span class="value">{ip_info.get('regionName','N/A')}</span><br>
              <span class="label">◈ COUNTRY     :</span> <span class="value">{ip_info.get('country','N/A')} {ip_info.get('countryCode','')}</span><br>
              <span class="label">◈ COORDINATES :</span> <span class="value">{ip_info.get('lat','N/A')}, {ip_info.get('lon','N/A')}</span><br>
              <span class="label">◈ TIMEZONE    :</span> <span class="value">{ip_info.get('timezone','N/A')}</span><br>
              <span class="label">◈ ISP         :</span> <span class="value">{ip_info.get('isp','N/A')}</span><br>
              <span class="label">◈ ORG         :</span> <span class="value">{ip_info.get('org','N/A')}</span><br>
              <span class="label">◈ AS NUMBER   :</span> <span class="value">{ip_info.get('as','N/A')}</span><br>
              <span class="label">◈ PROXY/VPN   :</span> <span class="{proxy_class}">{str(ip_info.get('proxy','N/A')).upper()}</span><br>
              <span class="label">◈ HOSTING     :</span> <span class="{host_class}">{str(ip_info.get('hosting','N/A')).upper()}</span><br>
              <span class="label">◈ MOBILE      :</span> <span class="value">{str(ip_info.get('mobile','N/A')).upper()}</span>
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="section-header">🚨 THREAT FLAGS</div>', unsafe_allow_html=True)
            flags = {"VPN":threat_data.get("isVPN"),"TOR":threat_data.get("isTor"),
                     "PROXY":threat_data.get("isProxy"),"BOT":threat_data.get("isBot"),
                     "DATACENTER":threat_data.get("isDatacenter")}
            any_flag = False
            for flag, val in flags.items():
                if val:
                    any_flag = True
                    st.markdown(f'<div class="alert-box alert-high">🔴 {flag} DETECTED</div>', unsafe_allow_html=True)
            for cat in threat_data.get("categories",[]):
                st.markdown(f'<div class="alert-box alert-medium">⚠️ CATEGORY: {cat}</div>', unsafe_allow_html=True)
            if not any_flag and not threat_data.get("categories"):
                st.markdown('<div class="alert-box alert-low">✅ NO ACTIVE THREAT FLAGS</div>', unsafe_allow_html=True)

            # Why risky panel (v4.0 new)
            st.markdown('<div class="section-header">❓ WHY RISKY?</div>', unsafe_allow_html=True)
            why = build_why_risky(threat_data, ip_info)
            st.markdown(f'<div class="why-risky">{why}</div>', unsafe_allow_html=True)

            rpt = threat_data.get("reports",0)
            rpt_cls = "bad" if rpt > 100 else "warn" if rpt > 20 else "good"
            st.markdown(f"""
            <div class="info-panel">
              <span class="label">ABUSE REPORTS :</span> <span class="{rpt_cls}">{rpt}</span><br>
              <span class="label">VT SCORE      :</span> <span class="value">{threat_data.get('vtScore',0)}/100</span><br>
              <span class="label">SCAN TIME     :</span> <span class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="text-align:center;padding:80px 20px">
          <div style="font-family:'Orbitron',monospace;font-size:3rem;color:#0d4f6e;margin-bottom:20px">🛡️</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:1rem;color:#4a7a9b;letter-spacing:3px">AWAITING TARGET</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:.75rem;color:#2a4a5b;margin-top:10px">
            Enter an IP address or domain in the sidebar to begin tracking
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('<div class="section-header">🗺️ GLOBAL ACTIVITY MAP</div>', unsafe_allow_html=True)
        fmap = make_folium_map({"lat":20,"lon":0,"query":"N/A"}, history_df, {})
        st_folium(fmap, width=None, height=450, returned_objects=[])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — ML ANALYSIS (v3.0 preserved)
# ═══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown('<div class="section-header">🤖 ML-POWERED THREAT ANALYSIS</div>', unsafe_allow_html=True)
    ml_col1, ml_col2 = st.columns(2)

    with ml_col1:
        st.markdown("**Anomaly Detection — Isolation Forest**")
        if ip_info and enable_ml and ip_info.get("status") == "success":
            score, label = ml_anomaly_score(ip_info, history_df)
            color_map = {"CRITICAL":"#ff0033","HIGH":"#ff2d55","MEDIUM":"#ffaa00",
                         "LOW":"#00ff88","INSUFFICIENT_DATA":"#4a7a9b"}
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                domain={"x":[0,1],"y":[0,1]},
                title={"text":f"ANOMALY SCORE | {label}",
                       "font":{"color":"#00d4ff","family":"Share Tech Mono","size":13}},
                gauge={"axis":{"range":[0,100],"tickcolor":"#4a7a9b"},
                       "bar":{"color":color_map.get(label,"#00d4ff")},
                       "bgcolor":"#071520","bordercolor":"#0d4f6e",
                       "steps":[{"range":[0,40],"color":"rgba(0,255,136,.1)"},
                                 {"range":[40,60],"color":"rgba(255,170,0,.1)"},
                                 {"range":[60,80],"color":"rgba(255,45,85,.1)"},
                                 {"range":[80,100],"color":"rgba(255,0,51,.15)"}],
                       "threshold":{"line":{"color":color_map.get(label,"#00d4ff"),"width":3},
                                    "thickness":0.8,"value":score}},
                number={"font":{"color":color_map.get(label,"#00d4ff"),"family":"Orbitron"}}
            ))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
                              font_color="#c8e6f5",height=280,margin=dict(t=30,b=10))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Scan a target to see ML anomaly score.")

        st.markdown("**Threat Vector Radar**")
        if threat_data:
            categories = ["Abuse Score","VPN Risk","Tor Risk","Proxy Risk","Bot Risk","Datacenter"]
            values = [threat_data.get("abuseScore",0),
                      100 if threat_data.get("isVPN") else 0,
                      100 if threat_data.get("isTor") else 0,
                      100 if threat_data.get("isProxy") else 0,
                      100 if threat_data.get("isBot") else 0,
                      100 if threat_data.get("isDatacenter") else 0]
            fig2 = go.Figure(go.Scatterpolar(
                r=values+[values[0]], theta=categories+[categories[0]],
                fill="toself", fillcolor="rgba(255,45,85,.15)",
                line=dict(color="#ff2d55",width=2)
            ))
            fig2.update_layout(
                polar=dict(bgcolor="rgba(7,21,32,.8)",
                           radialaxis=dict(visible=True,range=[0,100],gridcolor="#0d4f6e",color="#4a7a9b"),
                           angularaxis=dict(gridcolor="#0d4f6e",color="#c8e6f5")),
                paper_bgcolor="rgba(0,0,0,0)",font_color="#c8e6f5",
                showlegend=False,height=280,margin=dict(t=30,b=10)
            )
            st.plotly_chart(fig2, use_container_width=True)

    with ml_col2:
        st.markdown("**Geo Clustering — DBSCAN**")
        if enable_cluster and len(history_df) >= 3:
            clustered_df = ml_cluster_analysis(history_df)
            fig3 = px.scatter_geo(
                clustered_df, lat="lat", lon="lon", color="cluster",
                color_continuous_scale=["#00ff88","#00d4ff","#ffaa00","#ff2d55"],
                hover_data=["ip","country","threat"], title="Geographic Clusters"
            )
            fig3.update_geos(bgcolor="rgba(2,10,18,.9)",showland=True,landcolor="#071520",
                             showocean=True,oceancolor="#020a12",
                             showcountries=True,countrycolor="#0d4f6e",showframe=False)
            fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)",font_color="#c8e6f5",
                               height=280,margin=dict(t=40,b=0,l=0,r=0),coloraxis_showscale=False)
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("Need ≥3 records for clustering.")

        st.markdown("**ML Feature Importance (Threat Prediction)**")
        features    = ["Abuse Score","VPN Flag","Tor Exit","Proxy","Bot","Reports","Datacenter","Hour"]
        importances = [0.31,0.18,0.15,0.12,0.09,0.07,0.05,0.03]
        colors_bar  = ["#ff2d55" if v>.2 else "#ffaa00" if v>.1 else "#00d4ff" for v in importances]
        fig4 = go.Figure(go.Bar(
            x=importances, y=features, orientation="h",
            marker_color=colors_bar,
            text=[f"{v:.0%}" for v in importances], textposition="outside",
            textfont=dict(color="#c8e6f5",family="Share Tech Mono",size=11)
        ))
        fig4.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
                           font_color="#c8e6f5",height=280,
                           xaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b",tickformat=".0%"),
                           yaxis=dict(color="#c8e6f5",tickfont=dict(family="Share Tech Mono",size=11)),
                           margin=dict(t=20,b=10))
        st.plotly_chart(fig4, use_container_width=True)

    st.markdown('<div class="section-header">🧠 ML THREAT SUMMARY</div>', unsafe_allow_html=True)
    if ip_info and threat_data and ip_info.get("status") == "success":
        s1,s2,s3,s4 = st.columns(4)
        threat_cat   = ml_predict_threat_category(threat_data)
        score, label = ml_anomaly_score(ip_info, history_df)
        with s1: st.metric("Threat Category", threat_cat)
        with s2: st.metric("Anomaly Level",   label)
        with s3: st.metric("Anomaly Score",   f"{score}/100")
        with s4:
            risk = ("CRITICAL" if threat_data.get("isTor") or threat_data.get("abuseScore",0)>80 else
                    "HIGH"     if threat_data.get("abuseScore",0)>60 else
                    "MEDIUM"   if threat_data.get("abuseScore",0)>40 else "LOW")
            st.metric("Overall Risk", risk)

    if st.session_state.threat_history:
        st.markdown('<div class="section-header">📉 SCAN THREAT SCORE TIMELINE</div>', unsafe_allow_html=True)
        th_df = pd.DataFrame(st.session_state.threat_history)
        fig_th = go.Figure()
        fig_th.add_trace(go.Scatter(
            x=th_df["timestamp"], y=th_df["score"],
            mode="lines+markers+text", text=th_df["ip"],
            textposition="top center",
            line=dict(color="#00d4ff",width=2),
            marker=dict(size=8,color=th_df["score"],
                        colorscale=[[0,"#00ff88"],[0.5,"#ffaa00"],[1,"#ff2d55"]],
                        showscale=True)
        ))
        fig_th.add_hline(y=70,line_dash="dash",line_color="#ff2d55",annotation_text="HIGH",annotation_font_color="#ff2d55")
        fig_th.add_hline(y=40,line_dash="dash",line_color="#ffaa00",annotation_text="MED",annotation_font_color="#ffaa00")
        fig_th.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(7,21,32,.8)",
                              font_color="#c8e6f5",height=280,
                              xaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b"),
                              yaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b",range=[0,105]),
                              margin=dict(t=20,b=10))
        st.plotly_chart(fig_th, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — ANALYTICS (v3.0 preserved)
# ═══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown('<div class="section-header">📈 THREAT ANALYTICS DASHBOARD</div>', unsafe_allow_html=True)
    if not history_df.empty:
        a1, a2 = st.columns(2)
        with a1:
            df_sorted = history_df.sort_values("timestamp")
            fig5 = go.Figure()
            fig5.add_trace(go.Scatter(x=df_sorted["timestamp"],y=df_sorted["threat"],
                fill="tozeroy",fillcolor="rgba(255,45,85,.1)",
                line=dict(color="#ff2d55",width=2),name="Threat Level"))
            fig5.add_hline(y=70,line_dash="dash",line_color="#ffaa00",
                           annotation_text="HIGH THRESHOLD",annotation_font_color="#ffaa00")
            fig5.update_layout(title="Threat Level Over Time",
                paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(7,21,32,.8)",
                font_color="#c8e6f5",height=300,
                xaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b"),
                yaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b",range=[0,100]),
                margin=dict(t=40,b=10))
            st.plotly_chart(fig5, use_container_width=True)
        with a2:
            country_counts = history_df["country"].value_counts().head(8)
            fig6 = go.Figure(go.Bar(x=country_counts.values,y=country_counts.index,orientation="h",
                marker=dict(color=country_counts.values,
                            colorscale=[[0,"#00d4ff"],[0.5,"#ffaa00"],[1,"#ff2d55"]],showscale=False)))
            fig6.update_layout(title="Top Threat Countries",
                paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(7,21,32,.8)",
                font_color="#c8e6f5",height=300,
                xaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b"),
                yaxis=dict(color="#c8e6f5",tickfont=dict(family="Share Tech Mono",size=11)),
                margin=dict(t=40,b=10))
            st.plotly_chart(fig6, use_container_width=True)

        a3, a4 = st.columns(2)
        with a3:
            event_counts = history_df["event"].value_counts()
            fig7 = go.Figure(go.Pie(labels=event_counts.index,values=event_counts.values,hole=0.5,
                marker=dict(colors=["#00d4ff","#ff2d55","#ffaa00","#00ff88","#a855f7","#f97316"]),
                textfont=dict(family="Share Tech Mono",size=11),textinfo="label+percent"))
            fig7.update_layout(title="Event Type Distribution",paper_bgcolor="rgba(0,0,0,0)",
                               font_color="#c8e6f5",height=300,margin=dict(t=40,b=10))
            st.plotly_chart(fig7, use_container_width=True)
        with a4:
            if len(history_df) > 5:
                history_df["hour_num"] = pd.to_datetime(history_df["timestamp"]).dt.hour
                hourly = history_df.groupby("hour_num")["threat"].mean().reindex(range(24),fill_value=0)
                fig8 = go.Figure(go.Bar(x=list(range(24)),y=hourly.values,
                    marker=dict(color=hourly.values,
                                colorscale=[[0,"#00d4ff"],[0.5,"#ffaa00"],[1,"#ff2d55"]],showscale=False)))
                fig8.update_layout(title="Avg Threat by Hour (UTC)",
                    paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(7,21,32,.8)",
                    font_color="#c8e6f5",height=300,
                    xaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b",title="Hour"),
                    yaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b",title="Avg Threat"),
                    margin=dict(t=40,b=10))
                st.plotly_chart(fig8, use_container_width=True)

        st.markdown('<div class="section-header">🌍 GLOBAL THREAT HEATMAP</div>', unsafe_allow_html=True)
        fig9 = px.density_mapbox(history_df,lat="lat",lon="lon",z="threat",
            radius=30,zoom=1,center={"lat":20,"lon":0},
            color_continuous_scale=["#00d4ff","#ffaa00","#ff2d55"],mapbox_style="open-street-map")
        fig9.update_layout(paper_bgcolor="rgba(0,0,0,0)",font_color="#c8e6f5",
                           height=420,margin=dict(t=20,b=10),
                           coloraxis_colorbar=dict(tickfont=dict(color="#c8e6f5")))
        st.plotly_chart(fig9, use_container_width=True)

        st.markdown('<div class="section-header">📊 THREAT SCORE DISTRIBUTION</div>', unsafe_allow_html=True)
        fig10 = go.Figure(go.Histogram(x=history_df["threat"],nbinsx=20,
            marker=dict(color=history_df["threat"],
                        colorscale=[[0,"#00ff88"],[0.5,"#ffaa00"],[1,"#ff2d55"]],showscale=False),
            opacity=0.8))
        fig10.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(7,21,32,.8)",
            font_color="#c8e6f5",height=250,
            xaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b",title="Threat Score"),
            yaxis=dict(gridcolor="#0d4f6e",color="#4a7a9b",title="Count"),
            margin=dict(t=20,b=10))
        st.plotly_chart(fig10, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 — PORT SCANNER (v3.0 preserved)
# ═══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown('<div class="section-header">🔌 SIMULATED PORT SCANNER</div>', unsafe_allow_html=True)
    st.markdown("""<div class="info-panel" style="font-size:.78rem">
      ⚠️ <span class="warn">EDUCATIONAL SIMULATION ONLY</span> — Results are deterministically
      simulated from the IP hash. No real network connections are made.
    </div>""", unsafe_allow_html=True)

    target_ip_for_ports = ip_info.get("query") if ip_info.get("status") == "success" else None
    if target_ip_for_ports and target_ip_for_ports in st.session_state.port_scan_cache:
        port_results = st.session_state.port_scan_cache[target_ip_for_ports]
        open_ports   = [p for p in port_results if p["state"] == "OPEN"]
        closed_ports = [p for p in port_results if p["state"] == "CLOSED"]
        filt_ports   = [p for p in port_results if p["state"] == "FILTERED"]
        pc1,pc2,pc3 = st.columns(3)
        with pc1:
            st.markdown(f"""<div class="metric-card danger"><div class="metric-label">OPEN PORTS</div><div class="metric-value">{len(open_ports)}</div></div>""", unsafe_allow_html=True)
        with pc2:
            st.markdown(f"""<div class="metric-card success"><div class="metric-label">CLOSED PORTS</div><div class="metric-value">{len(closed_ports)}</div></div>""", unsafe_allow_html=True)
        with pc3:
            st.markdown(f"""<div class="metric-card warn"><div class="metric-label">FILTERED PORTS</div><div class="metric-value">{len(filt_ports)}</div></div>""", unsafe_allow_html=True)

        rows = "".join([
            f"""<tr><td>{p['port']}</td><td>{p['service']}</td>
            <td class="port-{'open' if p['state']=='OPEN' else 'closed' if p['state']=='CLOSED' else 'filtered'}">{p['state']}</td>
            <td style="color:#4a7a9b">{p.get('banner','')}</td></tr>"""
            for p in port_results
        ])
        st.markdown(f"""<table class="port-table">
          <thead><tr><th>PORT</th><th>SERVICE</th><th>STATE</th><th>BANNER</th></tr></thead>
          <tbody>{rows}</tbody></table>""", unsafe_allow_html=True)

        risky = ["SSH","RDP","FTP","Telnet","VNC","SMB","Redis","MySQL"]
        risky_open = [p for p in open_ports if p["service"] in risky]
        if risky_open:
            st.markdown('<div class="section-header">⚠️ HIGH-RISK OPEN PORTS</div>', unsafe_allow_html=True)
            for p in risky_open:
                st.markdown(f'<div class="alert-box alert-high">🔴 Port {p["port"]} ({p["service"]}) OPEN — {p.get("banner","")}</div>', unsafe_allow_html=True)
    else:
        if not target_ip_for_ports:
            st.info("Scan a target IP first (enable Port Scanner in sidebar options).")
        else:
            st.info("Re-scan with 'Port Scanner (sim)' toggle ON to see results.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5 — WHOIS / BATCH (v3.0 preserved)
# ═══════════════════════════════════════════════════════════════════════════════
with tab5:
    w_col1, w_col2 = st.columns(2)
    with w_col1:
        st.markdown('<div class="section-header">🌐 WHOIS INFORMATION</div>', unsafe_allow_html=True)
        target_ip_for_whois = ip_info.get("query") if ip_info.get("status") == "success" else None
        if target_ip_for_whois and target_ip_for_whois in st.session_state.whois_cache:
            wh = st.session_state.whois_cache[target_ip_for_whois]
            rows_w = "".join([
                f'<span class="label">{k:12}:</span> <span class="value">{v}</span><br>'
                for k, v in wh.items()
            ])
            st.markdown(f'<div class="info-panel">{rows_w}</div>', unsafe_allow_html=True)
        else:
            st.info("Scan a target to see WHOIS data.")

    with w_col2:
        st.markdown('<div class="section-header">🔍 IP VALIDATOR / CIDR</div>', unsafe_allow_html=True)
        cidr_input = st.text_input("Check IP / CIDR", placeholder="192.168.1.0/24 or 8.8.8.8")
        if cidr_input:
            try:
                net = ipaddress.ip_network(cidr_input, strict=False)
                st.markdown(f"""<div class="info-panel">
                  <span class="label">TYPE      :</span> <span class="good">VALID NETWORK</span><br>
                  <span class="label">NETWORK   :</span> <span class="value">{net.network_address}</span><br>
                  <span class="label">BROADCAST :</span> <span class="value">{net.broadcast_address}</span><br>
                  <span class="label">HOSTS     :</span> <span class="value">{net.num_addresses:,}</span><br>
                  <span class="label">PREFIXLEN :</span> <span class="value">/{net.prefixlen}</span><br>
                  <span class="label">VERSION   :</span> <span class="value">IPv{net.version}</span>
                </div>""", unsafe_allow_html=True)
            except ValueError:
                try:
                    addr = ipaddress.ip_address(cidr_input)
                    st.markdown(f"""<div class="info-panel">
                      <span class="label">TYPE      :</span> <span class="good">VALID IP</span><br>
                      <span class="label">ADDRESS   :</span> <span class="value">{addr}</span><br>
                      <span class="label">VERSION   :</span> <span class="value">IPv{addr.version}</span><br>
                      <span class="label">PRIVATE   :</span> <span class="value">{addr.is_private}</span><br>
                      <span class="label">LOOPBACK  :</span> <span class="value">{addr.is_loopback}</span>
                    </div>""", unsafe_allow_html=True)
                except ValueError:
                    st.markdown('<div class="alert-box alert-high">❌ Invalid IP / CIDR notation</div>', unsafe_allow_html=True)

    st.markdown('<div class="section-header">📦 BATCH SCAN RESULTS</div>', unsafe_allow_html=True)
    if st.session_state.batch_results:
        batch_df = pd.DataFrame(st.session_state.batch_results)
        bc1,bc2,bc3,bc4 = st.columns(4)
        with bc1: st.markdown(f"""<div class="metric-card"><div class="metric-label">TOTAL</div><div class="metric-value">{len(batch_df)}</div></div>""", unsafe_allow_html=True)
        with bc2:
            high = int((batch_df["threat"]>70).sum())
            st.markdown(f"""<div class="metric-card danger"><div class="metric-label">HIGH THREAT</div><div class="metric-value">{high}</div></div>""", unsafe_allow_html=True)
        with bc3:
            st.markdown(f"""<div class="metric-card warn"><div class="metric-label">VPN/PROXY</div><div class="metric-value">{int(batch_df['vpn'].sum())}</div></div>""", unsafe_allow_html=True)
        with bc4:
            st.markdown(f"""<div class="metric-card danger"><div class="metric-label">TOR NODES</div><div class="metric-value">{int(batch_df['tor'].sum())}</div></div>""", unsafe_allow_html=True)
        display_batch = batch_df[["ip","country","city","isp","threat","vpn","tor","source"]].copy()
        try:
            styled = display_batch.style.map(color_threat_cell, subset=["threat"])
            st.dataframe(styled, use_container_width=True, height=320)
        except Exception:
            st.dataframe(display_batch, use_container_width=True, height=320)
        csv_batch = batch_df.to_csv(index=False).encode()
        st.download_button("⬇️ Export Batch Results CSV", csv_batch, "cybertrack_batch.csv","text/csv", use_container_width=True)
    else:
        st.info("Use the Batch Scan panel in the sidebar to scan multiple IPs at once.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 6 — HISTORY (v3.0 preserved)
# ═══════════════════════════════════════════════════════════════════════════════
with tab6:
    st.markdown('<div class="section-header">📋 SCAN HISTORY</div>', unsafe_allow_html=True)
    cf1,cf2,cf3 = st.columns(3)
    with cf1:
        country_filter = st.selectbox("Filter by Country",["All"]+sorted(history_df["country"].dropna().unique().tolist()))
    with cf2:
        event_filter = st.selectbox("Filter by Event",["All"]+sorted(history_df["event"].dropna().unique().tolist()))
    with cf3:
        threat_filter = st.selectbox("Threat Level",["All","High (>70)","Medium (40-70)","Low (<40)"])

    filtered = history_df.copy()
    if country_filter != "All": filtered = filtered[filtered["country"]==country_filter]
    if event_filter   != "All": filtered = filtered[filtered["event"]==event_filter]
    if threat_filter == "High (>70)":      filtered = filtered[filtered["threat"]>70]
    elif threat_filter == "Medium (40-70)": filtered = filtered[(filtered["threat"]>=40)&(filtered["threat"]<=70)]
    elif threat_filter == "Low (<40)":      filtered = filtered[filtered["threat"]<40]

    display_df = (filtered[["timestamp","ip","country","threat","event","lat","lon"]]
                  .sort_values("timestamp",ascending=False).reset_index(drop=True))
    try:
        styled_df = display_df.style.map(color_threat_cell, subset=["threat"])
        st.dataframe(styled_df, use_container_width=True, height=420)
    except Exception:
        st.dataframe(display_df, use_container_width=True, height=420)

    dl1,dl2,dl3 = st.columns(3)
    with dl1:
        st.download_button("⬇️ Export CSV",  filtered.to_csv(index=False).encode(), "cybertrack_history.csv","text/csv",use_container_width=True)
    with dl2:
        st.download_button("⬇️ Export JSON", filtered.to_json(orient="records",default_handler=str).encode(), "cybertrack_history.json","application/json",use_container_width=True)
    with dl3:
        if st.button("🗑️ Clear History", use_container_width=True):
            st.session_state.history = generate_scan_history(35)
            st.session_state.logs.append(format_log_entry("WARN","History reset"))
            st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 7 — REPORT GENERATOR (v4.0 new)
# ═══════════════════════════════════════════════════════════════════════════════
with tab7:
    st.markdown('<div class="section-header">📄 REPORT GENERATOR</div>', unsafe_allow_html=True)
    if ip_info and ip_info.get("status") == "success":
        resolved_ip   = ip_info.get("query","")
        port_results  = st.session_state.port_scan_cache.get(resolved_ip, [])
        whois_data    = st.session_state.whois_cache.get(resolved_ip, {})
        report        = build_report(ip_info, threat_data, port_results, whois_data)

        r1, r2 = st.columns(2)
        with r1:
            st.markdown('<div class="section-header">📋 REPORT PREVIEW</div>', unsafe_allow_html=True)
            ts_label = ml_predict_threat_category(threat_data)
            st.markdown(f"""
            <div class="info-panel">
              <span class="label">GENERATED AT  :</span> <span class="value">{report['generated_at']}</span><br>
              <span class="label">TARGET IP     :</span> <span class="value">{report['ip_intelligence']['ip']}</span><br>
              <span class="label">COUNTRY       :</span> <span class="value">{report['ip_intelligence']['country']}</span><br>
              <span class="label">CITY          :</span> <span class="value">{report['ip_intelligence']['city']}</span><br>
              <span class="label">ISP           :</span> <span class="value">{report['ip_intelligence']['isp']}</span><br>
              <span class="label">ABUSE SCORE   :</span> <span class="{'bad' if report['threat_intelligence']['abuse_score']>60 else 'warn' if report['threat_intelligence']['abuse_score']>30 else 'good'}">{report['threat_intelligence']['abuse_score']}/100</span><br>
              <span class="label">VT SCORE      :</span> <span class="value">{report['threat_intelligence']['vt_score']}/100</span><br>
              <span class="label">RISK LEVEL    :</span> <span class="warn">{ts_label}</span><br>
              <span class="label">DATA SOURCE   :</span> <span class="value">{report['threat_intelligence']['data_source'].upper()}</span><br>
              <span class="label">OPEN PORTS    :</span> <span class="value">{sum(1 for p in port_results if p['state']=='OPEN')}</span><br>
              <span class="label">WHOIS ORG     :</span> <span class="value">{whois_data.get('Org','N/A')}</span>
            </div>
            """, unsafe_allow_html=True)

        with r2:
            st.markdown('<div class="section-header">⬇️ EXPORT OPTIONS</div>', unsafe_allow_html=True)
            st.markdown("""<div class="info-panel" style="font-size:.78rem">
              Export a complete intelligence report for this IP including geolocation,
              threat scores, port scan results, and WHOIS data.<br><br>
              <span class="warn">⚠️ Reports are point-in-time snapshots.</span>
            </div>""", unsafe_allow_html=True)

            csv_report  = report_to_csv(report).encode()
            json_report = json.dumps(report, indent=2, default=str).encode()

            st.download_button(
                "⬇️ Download CSV Report",
                csv_report,
                f"cybertrack_report_{resolved_ip.replace('.','_')}.csv",
                "text/csv",
                use_container_width=True
            )
            st.markdown("<br>", unsafe_allow_html=True)
            st.download_button(
                "⬇️ Download JSON Report",
                json_report,
                f"cybertrack_report_{resolved_ip.replace('.','_')}.json",
                "application/json",
                use_container_width=True
            )

            # Threat summary card
            score_val = report["threat_intelligence"]["abuse_score"]
            score_cls = ("threat-critical" if score_val > 80 else "threat-high" if score_val > 60 else
                         "threat-medium"   if score_val > 40 else "threat-low")
            st.markdown(f"""
            <div style="margin-top:20px">
              <div class="threat-score {score_cls}">{score_val}
                <br><span style="font-size:.65rem;letter-spacing:2px">THREAT SCORE</span>
              </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="text-align:center;padding:60px 20px">
          <div style="font-family:'Share Tech Mono',monospace;font-size:.9rem;color:#4a7a9b;letter-spacing:2px">
            SCAN A TARGET TO GENERATE A REPORT
          </div>
        </div>
        """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 8 — AI COPILOT (v4.0 new)
# ═══════════════════════════════════════════════════════════════════════════════
with tab8:
    st.markdown('<div class="section-header">💬 AI SECURITY COPILOT</div>', unsafe_allow_html=True)

    mode_label = "OpenAI GPT-3.5" if OPENAI_KEY else "Rule-Based Engine"
    st.markdown(f"""<div class="info-panel" style="font-size:.78rem">
      <span class="pulse-dot"></span>
      <span class="label">COPILOT MODE:</span> <span class="good">{mode_label}</span><br>
      <span class="warn">▸</span> Ask about the currently scanned IP — threat level, mitigation, geo info, flags.<br>
      <span class="warn">▸</span> Examples: "Is this IP dangerous?" · "How do I block this?" · "Where is this IP from?"
    </div>""", unsafe_allow_html=True)

    # Render chat history
    for msg in st.session_state.chat_history:
        if msg["role"] == "user":
            st.markdown(f'<div class="chat-user">🧑 {msg["content"]}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="chat-bot"><div class="bot-label">🤖 CYBERTRACK AI [{mode_label}]</div>{msg["content"]}</div>', unsafe_allow_html=True)

    # Quick prompts
    st.markdown('<div class="section-header">⚡ QUICK PROMPTS</div>', unsafe_allow_html=True)
    qp_cols = st.columns(4)
    quick_prompts = [
        "Is this IP dangerous?",
        "How do I block this IP?",
        "What country is this from?",
        "Any VPN or Tor flags?",
    ]
    for i, qp in enumerate(quick_prompts):
        with qp_cols[i]:
            if st.button(qp, key=f"qp_{i}", use_container_width=True):
                st.session_state.chat_history.append({"role":"user","content":qp})
                reply = ask_copilot(qp, st.session_state.ip_info, st.session_state.threat_data)
                st.session_state.chat_history.append({"role":"assistant","content":reply})
                st.session_state.logs.append(format_log_entry("INFO",f"Copilot query: {qp[:40]}"))
                st.rerun()

    # Free-form input
    user_q = st.text_input("Ask the AI Copilot...", placeholder="Type your security question here", key="copilot_input")
    ask_cols = st.columns([4,1])
    with ask_cols[1]:
        ask_btn = st.button("ASK ▶", use_container_width=True)
    if ask_btn and user_q.strip():
        st.session_state.chat_history.append({"role":"user","content":user_q.strip()})
        reply = ask_copilot(user_q.strip(), st.session_state.ip_info, st.session_state.threat_data)
        st.session_state.chat_history.append({"role":"assistant","content":reply})
        st.session_state.logs.append(format_log_entry("INFO",f"Copilot query: {user_q[:40]}"))
        st.rerun()

    if st.session_state.chat_history:
        if st.button("🗑️ Clear Chat", use_container_width=False):
            st.session_state.chat_history = []
            st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 9 — TERMINAL (v3.0 preserved)
# ═══════════════════════════════════════════════════════════════════════════════
with tab9:
    st.markdown('<div class="section-header">🖥️ LIVE SYSTEM TERMINAL</div>', unsafe_allow_html=True)
    logs_html = "".join(st.session_state.logs[-50:])
    st.markdown(f'<div class="log-terminal">{logs_html}</div>', unsafe_allow_html=True)

    t1,t2,t3 = st.columns(3)
    with t1:
        if st.button("🧹 Clear Logs", use_container_width=True):
            st.session_state.logs = [format_log_entry("OK","Logs cleared")]
            st.rerun()
    with t2:
        if st.button("📊 System Status", use_container_width=True):
            st.session_state.logs.extend([
                format_log_entry("INFO","=== SYSTEM STATUS CHECK ==="),
                format_log_entry("OK",  "ML Engine: ONLINE"),
                format_log_entry("OK",  "Geo API: ONLINE"),
                format_log_entry("OK",  f"Records in DB: {len(history_df)}"),
                format_log_entry("INFO",f"Memory: {len(st.session_state.tracked_ips)} IPs tracked"),
                format_log_entry("OK",  f"Batch results: {len(st.session_state.batch_results)}"),
                format_log_entry("INFO",f"AbuseIPDB: {'LIVE' if ABUSEIPDB_KEY else 'MOCK'}"),
                format_log_entry("INFO",f"VirusTotal: {'LIVE' if VIRUSTOTAL_KEY else 'MOCK'}"),
                format_log_entry("INFO",f"OpenAI: {'LIVE' if OPENAI_KEY else 'RULE-BASED'}"),
            ])
            st.rerun()
    with t3:
        if st.button("🔄 Reset Data", use_container_width=True):
            st.session_state.history = generate_scan_history(35)
            st.session_state.logs.append(format_log_entry("WARN","History reset with fresh simulation data"))
            st.rerun()

    st.markdown('<div class="section-header">💻 NETWORK DIAGNOSTICS</div>', unsafe_allow_html=True)
    diag_col1, diag_col2 = st.columns(2)
    with diag_col1:
        if ip_info and ip_info.get("status") == "success":
            proxy_cls = "bad" if ip_info.get("proxy") else "good"
            st.markdown(f"""<div class="info-panel">
              <span class="label">=== NETWORK INFO ===</span><br>
              <span class="label">IP   :</span> <span class="value">{ip_info.get('query','N/A')}</span><br>
              <span class="label">ISP  :</span> <span class="value">{ip_info.get('isp','N/A')}</span><br>
              <span class="label">ASN  :</span> <span class="value">{ip_info.get('as','N/A')}</span><br>
              <span class="label">ORG  :</span> <span class="value">{ip_info.get('org','N/A')}</span><br>
              <span class="label">PROXY:</span> <span class="{proxy_cls}">{str(ip_info.get('proxy','N/A')).upper()}</span>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div class="info-panel"><span class="label">No target scanned yet.</span></div>', unsafe_allow_html=True)
    with diag_col2:
        if threat_data:
            cats = ", ".join(threat_data.get("categories",[])) or "None"
            sc   = threat_data.get("abuseScore",0)
            sc_c = "bad" if sc>60 else "warn" if sc>30 else "good"
            st.markdown(f"""<div class="info-panel">
              <span class="label">=== THREAT INTEL ===</span><br>
              <span class="label">SCORE  :</span> <span class="{sc_c}">{sc}/100</span><br>
              <span class="label">VT     :</span> <span class="value">{threat_data.get('vtScore',0)}/100</span><br>
              <span class="label">SOURCE :</span> <span class="value">{threat_data.get('source','mock').upper()}</span><br>
              <span class="label">REPORTS:</span> <span class="value">{threat_data.get('reports',0)}</span><br>
              <span class="label">CATS   :</span> <span class="value">{cats}</span><br>
              <span class="label">VPN    :</span> <span class="{'bad' if threat_data.get('isVPN') else 'good'}">{str(threat_data.get('isVPN','N/A')).upper()}</span><br>
              <span class="label">TOR    :</span> <span class="{'bad' if threat_data.get('isTor') else 'good'}">{str(threat_data.get('isTor','N/A')).upper()}</span>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div class="info-panel"><span class="label">No threat data yet.</span></div>', unsafe_allow_html=True)


# ─── FOOTER ───────────────────────────────────────────────────────────────────
st.markdown("""
<div style="text-align:center;padding:30px 0 10px;font-family:'Share Tech Mono',monospace;
            font-size:.7rem;color:#2a4a5b;letter-spacing:2px;border-top:1px solid #0d4f6e;margin-top:30px">
  🛡️ CYBERTRACK v4.0 · REAL-TIME LOCATION INTELLIGENCE · FOR AUTHORIZED USE ONLY<br>
  <span style="color:#0d4f6e">ISOLATION FOREST · DBSCAN · ABUSEIPDB · VIRUSTOTAL · OPENAI · FOLIUM · PLOTLY · STREAMLIT</span>
</div>
""", unsafe_allow_html=True)
