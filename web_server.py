import os
import sys
import json
import tempfile
import webbrowser
from threading import Timer
from flask import Flask, render_template, request, jsonify, send_file

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.hybrid_engine import HybridEngine
from core.database.db_manager import DBManager
from core.reports.report_generator import ReportGenerator

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "web", "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "web", "static")
)

# Global store for latest analysis
latest_analysis_report = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze_email():
    global latest_analysis_report
    try:
        sample_type = request.form.get("sample_type")
        
        if sample_type:
            samples_dir = os.path.join(os.path.dirname(__file__), "samples")
            if sample_type == "phishing":
                file_path = os.path.join(samples_dir, "sample_phishing.eml")
            elif sample_type == "safe":
                file_path = os.path.join(samples_dir, "sample_safe.eml")
            else:
                return jsonify({"error": "Invalid sample type"}), 400
                
            report = HybridEngine.analyze_email_file(file_path)
        
        elif "file" in request.files:
            uploaded_file = request.files["file"]
            if uploaded_file.filename == "":
                return jsonify({"error": "No file selected"}), 400
                
            # Save to temporary file for parsing
            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, uploaded_file.filename)
            uploaded_file.save(temp_path)
            
            report = HybridEngine.analyze_email_file(temp_path)
            
            # Clean up temp file
            try:
                os.remove(temp_path)
            except Exception:
                pass
        else:
            return jsonify({"error": "No file or sample provided"}), 400

        latest_analysis_report = report
        
        # Save scan to DB
        try:
            DBManager.save_scan(report)
        except Exception as e:
            print(f"[Warning] Failed to save DB scan: {e}")

        return jsonify({"success": True, "report": report})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/history", methods=["GET"])
def get_history():
    query = request.args.get("q", "").strip()
    if query:
        scans = DBManager.search_scans(query)
    else:
        scans = DBManager.get_all_scans()
    return jsonify({"scans": scans})

@app.route("/api/history/clear", methods=["POST"])
def clear_history():
    DBManager.clear_history()
    return jsonify({"success": True})

@app.route("/api/export/<fmt>", methods=["GET"])
def export_report(fmt):
    global latest_analysis_report
    if not latest_analysis_report:
        return jsonify({"error": "No active report to export"}), 400
        
    temp_dir = tempfile.gettempdir()
    fname = latest_analysis_report.get("filename", "email").replace(" ", "_")
    
    if fmt == "json":
        export_path = os.path.join(temp_dir, f"{fname}_report.json")
        ReportGenerator.export_json(latest_analysis_report, export_path)
        return send_file(export_path, as_attachment=True, download_name=f"{fname}_report.json")
    elif fmt == "html":
        export_path = os.path.join(temp_dir, f"{fname}_report.html")
        ReportGenerator.export_html(latest_analysis_report, export_path)
        return send_file(export_path, as_attachment=True, download_name=f"{fname}_report.html")
    elif fmt == "txt":
        export_path = os.path.join(temp_dir, f"{fname}_report.txt")
        ReportGenerator.export_text(latest_analysis_report, export_path)
        return send_file(export_path, as_attachment=True, download_name=f"{fname}_report.txt")
    else:
        return jsonify({"error": "Invalid format"}), 400

def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

def start_server():
    Timer(1.5, open_browser).start()
    app.run(host="127.0.0.1", port=5000, debug=False)

if __name__ == "__main__":
    start_server()
