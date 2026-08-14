# PhishGuard AI — Enterprise SOC Security & Threat Intelligence Platform

PhishGuard AI is an open-source, SOC-grade phishing analysis platform that inspects `.eml` files using a multi-engine hybrid architecture (Header Analysis, URL Matrix, Attachment Sandbox, NLP Social Engineering, and ML Classification) with Explainable AI (XAI) scoring and MITRE ATT&CK technique mapping.

---

## 🚀 Features

- **Enterprise Dark Interface**: Modern glassmorphism UI with Three.js 3D WebGL cyber threat shield.
- **Drag & Drop .eml Analyzer**: Interactive real-time pipeline flow visualization.
- **5-Pillar Hybrid Engine**:
  - **Header Engine**: SPF / DKIM / DMARC verification, Return-Path mismatch, Display Name Brand Spoofing.
  - **URL Matrix**: Anchor text deception detection, Punycode homographs, shorteners, high-risk TLDs.
  - **Attachment Sandbox**: Double extensions, macro-enabled office docs, executable detection, SHA-256 hashes.
  - **NLP Detector**: Keyword pattern matching for urgency, fear tactics, credential harvesting, wire transfers.
  - **ML Classifier**: TF-IDF + Random Forest model with dynamic probability boosting.
- **Explainable AI (XAI)**: Detailed breakdown of score additions and actionable SOC recommendations.
- **Threat Intelligence & MITRE ATT&CK**: Maps threat vectors directly to MITRE tactics (T1566.001, T1566.002, T1056.001, T1036.007).
- **Report Exports**: Instant exports in JSON, HTML, or TXT formats.

---

## ⚡ Quick Start

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the Enterprise Web Application
python web_server.py
```

Access the Web Platform at: `http://127.0.0.1:5000`

---

## 🛠 Project Structure

```
PhishGuardAI/
├── core/
│   ├── ai/               # Random Forest ML Classifier
│   ├── attachment_analysis/ # Attachment Sandbox
│   ├── database/         # SQLite Historical Log Storage
│   ├── email_parser/     # MIME Email Parser
│   ├── header_analysis/   # Header & Auth Analyzer
│   ├── nlp/              # Social Engineering Detector
│   ├── reports/          # Report Generator (JSON/HTML/TXT)
│   ├── url_analysis/     # URL Security Matrix
│   └── hybrid_engine.py  # Hybrid XAI Aggregator
├── services/
│   └── threat_intel.py   # IOC Extraction & MITRE ATT&CK Mapping
├── web/
│   ├── static/
│   │   ├── css/style.css            # Dark Glassmorphism SOC Theme
│   │   └── js/
│   │       ├── app.js               # Application & Pipeline Controller
│   │       └── three_cyber_globe.js # Three.js 3D WebGL Visualizer
│   └── templates/
│       └── index.html               # Enterprise Web Dashboard
├── fastapi_app.py        # FastAPI REST API Server
├── web_server.py         # Application Entry Point
├── requirements.txt      # Python Dependencies
└── samples/              # Sample .eml Test Files
```

---

## 📄 License
MIT License
