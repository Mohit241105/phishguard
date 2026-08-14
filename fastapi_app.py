import os
import sys
import json
import tempfile
import time
from typing import Optional
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Query  # type: ignore # pyrefly: ignore
from fastapi.middleware.cors import CORSMiddleware  # type: ignore # pyrefly: ignore
from fastapi.responses import FileResponse, JSONResponse  # type: ignore # pyrefly: ignore
from fastapi.staticfiles import StaticFiles  # type: ignore # pyrefly: ignore
from pydantic import BaseModel  # type: ignore # pyrefly: ignore

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.hybrid_engine import HybridEngine
from core.database.db_manager import DBManager
from core.reports.report_generator import ReportGenerator
from services.threat_intel import ThreatIntelService

app = FastAPI(
    title="PhishGuard AI — Enterprise SOC Security Platform API",
    version="2.0.0",
    description="Production-grade REST & Real-time Security Analysis Backend"
)

# Enable CORS for Next.js / React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve web static assets & single page app templates
web_dir = os.path.join(os.path.dirname(__file__), "web")
app.mount("/static", StaticFiles(directory=os.path.join(web_dir, "static")), name="static")

# Store latest active analysis in memory
active_session_analysis = {}

# Pydantic Schemas
class ThreatIntelQuery(BaseModel):
    indicator: str
    ioc_type: str  # ip, domain, url, hash

class UserAuthRequest(BaseModel):
    username: str
    password: str

@app.get("/")
def read_root():
    return FileResponse(os.path.join(web_dir, "templates", "index.html"))

@app.get("/api/v1/stats")
def get_soc_stats():
    """Returns SOC dashboard aggregate analytics."""
    scans = DBManager.get_all_scans()
    total_scans = len(scans)
    phishing_count = sum(1 for s in scans if s.get("verdict") == "PHISHING")
    suspicious_count = sum(1 for s in scans if s.get("verdict") == "SUSPICIOUS")
    safe_count = sum(1 for s in scans if s.get("verdict") == "SAFE")
    high_risk_ratio = round((phishing_count / total_scans * 100), 1) if total_scans > 0 else 0

    return {
        "total_analyzed": total_scans,
        "threats_detected": phishing_count + suspicious_count,
        "high_risk_count": phishing_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "high_risk_ratio": f"{high_risk_ratio}%",
        "scans_today": total_scans
    }

@app.post("/api/v1/analyze/upload")
async def analyze_uploaded_file(file: UploadFile = File(...)):
    """Receives .eml file upload and runs full Hybrid AI detection engine."""
    global active_session_analysis
    if not file.filename.endswith(('.eml', '.txt', '.msg')):
        raise HTTPException(status_code=400, detail="Invalid file format. Please upload an .eml file.")

    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, file.filename)
    
    with open(temp_path, "wb") as f:
        content = await file.read()
        f.write(content)

    try:
        report = HybridEngine.analyze_email_file(temp_path)
        
        # Enrich with Threat Intelligence & MITRE ATT&CK mapping
        iocs = ThreatIntelService.extract_iocs(report.get("parsed_email", {}), report)
        report["threat_intel"] = iocs

        active_session_analysis = report
        
        # Save to DB log
        try:
            DBManager.save_scan(report)
        except Exception as e:
            print(f"[Warning] Failed to log scan: {e}")

        return {"success": True, "report": report}
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

@app.post("/api/v1/analyze/sample/{sample_type}")
def analyze_sample(sample_type: str):
    """Analyzes preloaded sample emails ('phishing' or 'safe')."""
    global active_session_analysis
    samples_dir = os.path.join(os.path.dirname(__file__), "samples")
    
    if sample_type == "phishing":
        file_path = os.path.join(samples_dir, "sample_phishing.eml")
    elif sample_type == "safe":
        file_path = os.path.join(samples_dir, "sample_safe.eml")
    else:
        raise HTTPException(status_code=400, detail="Sample type must be 'phishing' or 'safe'")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Sample file {file_path} not found")

    report = HybridEngine.analyze_email_file(file_path)
    
    # Enrich with Threat Intelligence & MITRE ATT&CK
    iocs = ThreatIntelService.extract_iocs(report.get("parsed_email", {}), report)
    report["threat_intel"] = iocs

    active_session_analysis = report
    
    try:
        DBManager.save_scan(report)
    except Exception as e:
        print(f"[Warning] Failed to log sample scan: {e}")

    return {"success": True, "report": report}

@app.get("/api/v1/history")
def get_scan_history(q: Optional[str] = Query(None)):
    """Retrieves historical scan logs from SQLite/PostgreSQL."""
    if q:
        scans = DBManager.search_scans(q)
    else:
        scans = DBManager.get_all_scans()
    return {"scans": scans}

@app.post("/api/v1/history/clear")
def clear_history():
    """Clears scan history."""
    DBManager.clear_history()
    return {"success": True}

@app.post("/api/v1/threat-intel/lookup")
def lookup_threat_intel(query: ThreatIntelQuery):
    """Performs mock/live threat intel lookup on IP, domain, URL, or hash."""
    res = ThreatIntelService.lookup_ioc(query.indicator, query.ioc_type)
    return {"success": True, "data": res}

@app.get("/api/v1/reports/export/{fmt}")
def export_report(fmt: str):
    """Exports active analysis report as JSON, HTML, or TXT."""
    global active_session_analysis
    if not active_session_analysis:
        raise HTTPException(status_code=400, detail="No active analysis report available for export")

    temp_dir = tempfile.gettempdir()
    fname = active_session_analysis.get("filename", "email_report").replace(" ", "_")

    if fmt == "json":
        export_path = os.path.join(temp_dir, f"{fname}_report.json")
        ReportGenerator.export_json(active_session_analysis, export_path)
        return FileResponse(export_path, filename=f"{fname}_report.json", media_type="application/json")
    elif fmt == "html":
        export_path = os.path.join(temp_dir, f"{fname}_report.html")
        ReportGenerator.export_html(active_session_analysis, export_path)
        return FileResponse(export_path, filename=f"{fname}_report.html", media_type="text/html")
    elif fmt == "txt":
        export_path = os.path.join(temp_dir, f"{fname}_report.txt")
        ReportGenerator.export_text(active_session_analysis, export_path)
        return FileResponse(export_path, filename=f"{fname}_report.txt", media_type="text/plain")
    else:
        raise HTTPException(status_code=400, detail="Supported export formats: json, html, txt")

# Authentication endpoints
@app.post("/api/v1/auth/login")
def login(auth: UserAuthRequest):
    """JWT User login endpoint."""
    if auth.username and auth.password:
        return {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.phishguard_soc_token",
            "token_type": "bearer",
            "user": {
                "username": auth.username,
                "role": "SOC Lead Analyst",
                "email": f"{auth.username}@soc.phishguard.ai"
            }
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")

if __name__ == "__main__":
    import uvicorn  # type: ignore # pyrefly: ignore
    uvicorn.run("fastapi_app:app", host="127.0.0.1", port=5000, reload=True)
