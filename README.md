# 🛡️ CyberTrack v4.0
### Real-Time Threat Intelligence Platform

Upgrades v3.0 with real API support, AI Security Copilot, Report Generator, and full Streamlit Cloud compatibility.

---

## 🚀 Quick Start

```bash
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows

pip install -r requirements.txt
streamlit run cybertrack_app.py
```

Open your browser at **http://localhost:8501**

---

## 🔑 Optional API Keys (set as environment variables or Streamlit secrets)

| Variable | Service | Effect |
|---|---|---|
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Real abuse reports & confidence score |
| `VIRUSTOTAL_API_KEY` | VirusTotal | Malware / phishing reputation score |
| `OPENAI_API_KEY` | OpenAI GPT-3.5 | AI-powered copilot responses |

**Without keys:** app runs fully in mock/simulation mode — no crashes, no errors.

### Streamlit Cloud secrets setup:
```toml
# .streamlit/secrets.toml
ABUSEIPDB_API_KEY = "your_key_here"
VIRUSTOTAL_API_KEY = "your_key_here"
OPENAI_API_KEY = "your_key_here"
```

---

## ✨ What's New in v4.0 vs v3.0

| Feature | v3.0 | v4.0 |
|---|---|---|
| AbuseIPDB integration | Mock only | ✅ Real API + mock fallback |
| VirusTotal integration | Mock only | ✅ Real API + mock fallback |
| VT score display | ❌ | ✅ Shown in UI + report |
| AI Security Copilot | ❌ | ✅ OpenAI GPT-3.5 or rule-based |
| Report Generator tab | ❌ | ✅ CSV + JSON export |
| "Why Risky?" panel | ❌ | ✅ Human-readable explanation |
| Data source indicator | ❌ | ✅ Shows mock/abuseipdb/virustotal |
| API key status sidebar | ❌ | ✅ Live/Mock badges |
| @st.cache_data | ❌ | ✅ All API calls cached 5 min |
| Mapbox dependency | ❌ uses density_mapbox | ✅ open-street-map (no token needed) |
| Batch scan cap | 20 IPs | 15 IPs (Cloud-safe) |
| time.sleep blocking | ❌ present | ✅ removed entirely |

---

## 📋 Requirements

| Package | Version | Purpose |
|---|---|---|
| streamlit | ≥1.35.0 | Web app framework |
| folium | ≥0.16.0 | Interactive maps |
| streamlit-folium | ≥0.20.0 | Folium ↔ Streamlit bridge |
| requests | ≥2.31.0 | HTTP API calls |
| pandas | ≥2.0.0 | Data wrangling |
| numpy | ≥1.24.0 | Numerical ops |
| plotly | ≥5.20.0 | Interactive charts |
| scikit-learn | ≥1.3.0 | IsolationForest, DBSCAN |

**Python:** 3.9 – 3.12 | **OS:** Windows / macOS / Linux

---

## 🔒 Legal Notice

For **authorized security research and educational use only**.
The port scanner makes **no real network connections** — simulation only.

---

## 📁 File Structure

```
cybertrack_app.py    ← Main application (single file)
requirements.txt     ← Python dependencies
README.md            ← This file
```
https://cyber-track-app-ewwnzjpr3fgynhvejrivcc.streamlit.app/
