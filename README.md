# PhishGuard AI

A standalone Windows desktop application that detects phishing emails by analysing `.eml` files. It provides a rich, explainable report, stores scan history locally and can export results as PDF, HTML or JSON.

## Features
- Drag‑and‑drop or browse for `.eml` files
- Hybrid detection engine (rule‑based + header + URL + attachment + NLP + ML)
- Explainable AI – list reasons for each finding
- Scan history stored in SQLite
- Export reports (PDF/HTML/JSON)
- Offline‑first (all analysis runs locally)

## Quick Start (developer)
```powershell
# Install dependencies
pip install -r requirements.txt

# Run the app (development mode)
python -m app.main_window
```

## Building the Windows executable
```powershell
# Using PyInstaller
pyinstaller installer/build.spec
```

## License
MIT

## Project Structure

```
PhishGuardAI/
├─ app/
│   └─ main_window.py
├─ controllers/
├─ services/
├─ email_parser/
├─ header_analysis/
├─ url_analysis/
├─ attachment_analysis/
├─ nlp/
├─ ai/
├─ database/
├─ reports/
├─ resources/
│   ├─ icons/
│   └─ theme.qss
├─ tests/
├─ installer/
│   └─ build.spec
├─ requirements.txt
└─ README.md
```

## Development Workflow

```bash
# Clone the repository
git clone <repo_url>
cd PhishGuardAI

# Install dependencies
pip install -r requirements.txt

# Run the application in development mode
python -m app.main_window

# Run the test suite
pytest
```

## Testing

- Unit tests cover each analysis module (header, URL, attachment, NLP, ML).
- Integration tests run the full pipeline on a set of benign and phishing `.eml` samples.
- CI is configured with GitHub Actions to run on every push.

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Write tests for your changes.
4. Submit a Pull Request.

## Roadmap

- Outlook / Gmail plugin integration.
- Real‑time email monitoring.
- Online threat‑intel enrichment (VirusTotal, Safe Browsing).
- Advanced ML models (MiniLM, RoBERTa).

---
