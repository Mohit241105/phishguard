import json
import html

class ReportGenerator:
    """Generates HTML, JSON, and Text reports for PhishGuard AI analysis results."""

    @staticmethod
    def export_json(report: dict, file_path: str):
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

    @staticmethod
    def export_text(report: dict, file_path: str):
        lines = []
        lines.append("==========================================================")
        lines.append("           PHISHGUARD AI - ANALYSIS REPORT               ")
        lines.append("==========================================================")
        lines.append(f"Scan Date:    {report.get('scan_timestamp')}")
        lines.append(f"Filename:     {report.get('filename')}")
        lines.append(f"Sender:       {report.get('sender')}")
        lines.append(f"Subject:      {report.get('subject')}")
        lines.append(f"Final Risk:   {report.get('final_risk_score')}/100")
        lines.append(f"Verdict:      {report.get('verdict')} ({report.get('risk_level')})")
        lines.append("\n----------------------------------------------------------")
        lines.append("SECURITY SCORE BREAKDOWN")
        lines.append("----------------------------------------------------------")
        scores = report.get('scores', {})
        lines.append(f"  Header Score:     {scores.get('header_score')}/100")
        lines.append(f"  URL Score:        {scores.get('url_score')}/100")
        lines.append(f"  Attachment Score: {scores.get('attachment_score')}/100")
        lines.append(f"  NLP Tactic Score: {scores.get('nlp_score')}/100")
        lines.append(f"  ML Model Score:   {scores.get('ml_score')}/100")
        lines.append("\n----------------------------------------------------------")
        lines.append("EXPLAINABLE AI REASONS & EVIDENCE")
        lines.append("----------------------------------------------------------")
        for i, exp in enumerate(report.get('explanations', []), 1):
            lines.append(f" [{i}] {exp}")
        lines.append("\n----------------------------------------------------------")
        lines.append("RECOMMENDATIONS")
        lines.append("----------------------------------------------------------")
        for rec in report.get('recommendations', []):
            lines.append(f" - {rec}")
        lines.append("==========================================================\n")

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

    @staticmethod
    def export_html(report: dict, file_path: str):
        scores = report.get('scores', {})
        explanations_html = "".join([f"<li>{html.escape(e)}</li>" for e in report.get('explanations', [])])
        recs_html = "".join([f"<li>{html.escape(r)}</li>" for r in report.get('recommendations', [])])
        
        urls_rows = ""
        for u in report.get('url_details', {}).get('urls', []):
            urls_rows += f"""
            <tr>
                <td style="word-break: break-all;">{html.escape(u['url'])}</td>
                <td>{html.escape(u['domain'])}</td>
                <td><span class="badge {u['risk_level'].lower()}">{u['risk_level']}</span></td>
                <td>{u['score']}/100</td>
            </tr>
            """
            
        att_rows = ""
        for a in report.get('attachment_details', {}).get('analyzed_attachments', []):
            att_rows += f"""
            <tr>
                <td>{html.escape(a['filename'])}</td>
                <td>{a['size']} bytes</td>
                <td><span class="badge {a['risk_level'].lower()}">{a['risk_level']}</span></td>
                <td>{a['score']}/100</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PhishGuard AI Report - {html.escape(report.get('subject', ''))}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2e; color: #cdd6f4; margin: 0; padding: 20px; }}
        .container {{ max-width: 950px; margin: 0 auto; background-color: #181825; border-radius: 12px; padding: 30px; border: 1px solid #313244; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }}
        h1, h2, h3 {{ color: #89b4fa; border-bottom: 1px solid #313244; padding-bottom: 8px; }}
        .verdict-box {{ text-align: center; padding: 20px; border-radius: 8px; margin-bottom: 25px; border: 2px solid {report.get('badge_color', '#89b4fa')}; }}
        .score {{ font-size: 48px; font-weight: bold; color: {report.get('badge_color', '#89b4fa')}; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 13px; text-transform: uppercase; }}
        .phishing, .dangerous, .malicious {{ background-color: #f38ba8; color: #11111b; }}
        .suspicious {{ background-color: #f9e2af; color: #11111b; }}
        .safe, .clean {{ background-color: #a6e3a1; color: #11111b; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 25px; }}
        .card {{ background-color: #1e1e2e; padding: 15px; border-radius: 8px; border: 1px solid #313244; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #313244; }}
        th {{ background-color: #313244; color: #89b4fa; }}
        ul {{ padding-left: 20px; line-height: 1.6; }}
        .footer {{ text-align: center; font-size: 12px; color: #6c7086; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ PhishGuard AI - Security Analysis Report</h1>
        <p><strong>Scan Timestamp:</strong> {report.get('scan_timestamp')} | <strong>Filename:</strong> {html.escape(report.get('filename', ''))}</p>
        
        <div class="verdict-box">
            <div>VERDICT</div>
            <div class="score">{report.get('verdict')}</div>
            <div>Risk Score: <strong>{report.get('final_risk_score')}/100</strong> ({report.get('risk_level')})</div>
        </div>

        <div class="grid">
            <div class="card">
                <h3>📧 Email Overview</h3>
                <p><strong>Subject:</strong> {html.escape(report.get('subject', ''))}</p>
                <p><strong>Sender:</strong> {html.escape(report.get('sender', ''))}</p>
                <p><strong>Recipient:</strong> {html.escape(report.get('recipient', ''))}</p>
                <p><strong>Date:</strong> {html.escape(report.get('date', ''))}</p>
            </div>
            <div class="card">
                <h3>📊 Score Breakdown</h3>
                <p>Header Risk: <strong>{scores.get('header_score')}/100</strong></p>
                <p>URL Risk: <strong>{scores.get('url_score')}/100</strong></p>
                <p>Attachment Risk: <strong>{scores.get('attachment_score')}/100</strong></p>
                <p>NLP Social Eng: <strong>{scores.get('nlp_score')}/100</strong></p>
                <p>Machine Learning: <strong>{scores.get('ml_score')}/100</strong></p>
            </div>
        </div>

        <h2>🧠 Explainable AI Evidence</h2>
        <ul>{explanations_html}</ul>

        <h2>🛡️ Recommended Actions</h2>
        <ul>{recs_html}</ul>

        <h2>🔗 Extracted URLs ({report.get('url_details', {}).get('total_urls', 0)})</h2>
        <table>
            <thead><tr><th>URL</th><th>Domain</th><th>Risk</th><th>Score</th></tr></thead>
            <tbody>{urls_rows if urls_rows else '<tr><td colspan="4">No URLs detected.</td></tr>'}</tbody>
        </table>

        <h2>📎 Attachments ({report.get('attachment_details', {}).get('total_attachments', 0)})</h2>
        <table>
            <thead><tr><th>Filename</th><th>Size</th><th>Risk</th><th>Score</th></tr></thead>
            <tbody>{att_rows if att_rows else '<tr><td colspan="4">No attachments detected.</td></tr>'}</tbody>
        </table>

        <div class="footer">
            Generated by PhishGuard AI - Standalone SOC Email Security Suite
        </div>
    </div>
</body>
</html>
"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
