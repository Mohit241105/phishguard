import os
import re

class AttachmentAnalyzer:
    """Safely inspects email attachment metadata for high-risk extensions, double extensions, and macros."""

    EXECUTABLE_EXTS = {'.exe', '.bat', '.cmd', '.vbs', '.ps1', '.js', '.hta', '.cpl', '.pif', '.dll', '.scr', '.com'}
    SCRIPT_EXTS = {'.vbe', '.jse', '.wsf', '.jar', '.py', '.sh'}
    MACRO_EXTS = {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.doc', '.xls'}
    ARCHIVE_EXTS = {'.zip', '.rar', '.7z', '.iso', '.img', '.cab', '.tar', '.gz'}

    @staticmethod
    def analyze(parsed_email: dict) -> dict:
        attachments = parsed_email.get("attachments", [])
        if not attachments:
            return {
                "attachment_risk_score": 0,
                "total_attachments": 0,
                "analyzed_attachments": [],
                "findings": []
            }

        analyzed_attachments = []
        max_score = 0
        total_points = 0
        findings = []

        for att in attachments:
            fname = att.get("filename", "")
            size = att.get("size", 0)
            c_type = att.get("content_type", "")
            sha256 = att.get("sha256", "")

            att_res = AttachmentAnalyzer._analyze_single(fname, size, c_type, sha256)
            analyzed_attachments.append(att_res)

            total_points += att_res["score"]
            if att_res["score"] > max_score:
                max_score = att_res["score"]

            for flag in att_res["flags"]:
                findings.append(f"Attachment Warning [{fname}]: {flag}")

        final_score = min(max_score + (len(attachments) - 1) * 10, 100)

        return {
            "attachment_risk_score": final_score,
            "total_attachments": len(attachments),
            "analyzed_attachments": analyzed_attachments,
            "findings": findings
        }

    @staticmethod
    def _analyze_single(filename: str, size: int, content_type: str, sha256: str) -> dict:
        score = 0
        flags = []
        ext = os.path.splitext(filename)[1].lower()

        # 1. Check Double Extensions (e.g. invoice.pdf.exe)
        parts = filename.split('.')
        if len(parts) > 2:
            second_last = '.' + parts[-2].lower()
            last = '.' + parts[-1].lower()
            if last in AttachmentAnalyzer.EXECUTABLE_EXTS or last in AttachmentAnalyzer.SCRIPT_EXTS:
                score += 50
                flags.append(f"Double extension anomaly detected: '{second_last}{last}'. Common malware masquerading technique.")

        # 2. Executable Extension Check
        if ext in AttachmentAnalyzer.EXECUTABLE_EXTS:
            score += 50
            flags.append(f"High-Risk Executable attachment ('{ext}'). Direct threat vector.")

        # 3. Script Extension Check
        elif ext in AttachmentAnalyzer.SCRIPT_EXTS:
            score += 40
            flags.append(f"Script file attachment ('{ext}'). Potential execution risk.")

        # 4. Macro-enabled Office Document Check
        elif ext in AttachmentAnalyzer.MACRO_EXTS:
            score += 35
            flags.append(f"Legacy or Macro-Enabled Office document ('{ext}'). May contain malicious VBA macros.")

        # 5. Archive Files
        elif ext in AttachmentAnalyzer.ARCHIVE_EXTS:
            score += 20
            flags.append(f"Compressed archive attachment ('{ext}'). Used to bypass perimeter scanner inspection.")

        risk_level = "CLEAN"
        if score >= 45:
            risk_level = "MALICIOUS"
        elif score >= 20:
            risk_level = "SUSPICIOUS"

        return {
            "filename": filename,
            "extension": ext,
            "size": size,
            "content_type": content_type,
            "sha256": sha256,
            "score": min(score, 100),
            "risk_level": risk_level,
            "flags": flags
        }
