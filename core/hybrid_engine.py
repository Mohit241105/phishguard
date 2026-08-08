import datetime
from core.email_parser.parser import EmailParser
from core.header_analysis.header_analyzer import HeaderAnalyzer
from core.url_analysis.url_analyzer import URLAnalyzer
from core.attachment_analysis.attachment_analyzer import AttachmentAnalyzer
from core.nlp.nlp_analyzer import NLPAnalyzer
from core.ai.ml_engine import MLEngine

class HybridEngine:
    """Combines Rule-based, Header, URL, Attachment, NLP, and Machine Learning engines into unified Explainable AI verdict."""

    @staticmethod
    def analyze_email_file(file_path: str) -> dict:
        parsed_email = EmailParser.parse_file(file_path)
        return HybridEngine.analyze_parsed(parsed_email)

    @staticmethod
    def analyze_parsed(parsed_email: dict) -> dict:
        # Run individual sub-analyzers
        header_res = HeaderAnalyzer.analyze(parsed_email)
        url_res = URLAnalyzer.analyze(parsed_email)
        att_res = AttachmentAnalyzer.analyze(parsed_email)
        nlp_res = NLPAnalyzer.analyze(parsed_email)

        # Run ML engine
        ml_engine = MLEngine.get_instance()
        ml_res = ml_engine.predict(
            parsed_email,
            header_score=header_res["header_risk_score"],
            url_score=url_res["url_risk_score"]
        )

        # Calculate weighted Hybrid Final Risk Score
        h_score = header_res["header_risk_score"]
        u_score = url_res["url_risk_score"]
        a_score = att_res["attachment_risk_score"]
        n_score = nlp_res["nlp_risk_score"]
        m_score = ml_res["ml_risk_score"]

        raw_final = (
            0.25 * h_score +
            0.25 * u_score +
            0.20 * a_score +
            0.15 * n_score +
            0.15 * m_score
        )

        final_risk_score = min(int(round(raw_final)), 100)

        # Assign verdict & color badge
        if final_risk_score >= 65:
            verdict = "PHISHING"
            risk_level = "HIGH RISK"
            badge_color = "#F38BA8"  # Soft Red
        elif final_risk_score >= 35:
            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM RISK"
            badge_color = "#F9E2AF"  # Soft Yellow
        else:
            verdict = "SAFE"
            risk_level = "LOW RISK"
            badge_color = "#A6E3A1"  # Soft Green

        # Collect Explainable AI reasons
        explanations = []
        
        # Header reasons
        for finding in header_res["findings"]:
            explanations.append(f"Header Anomaly: {finding}")
            
        # URL reasons
        for finding in url_res["findings"]:
            explanations.append(f"URL Threat: {finding}")

        # Attachment reasons
        for finding in att_res["findings"]:
            explanations.append(f"Attachment Threat: {finding}")

        # NLP reasons
        for finding in nlp_res["findings"]:
            explanations.append(f"Social Engineering Tactic: {finding}")

        # ML model reason
        explanations.append(
            f"Machine Learning Classifier: Predicted '{ml_res['classification']}' with {ml_res['confidence']}% confidence."
        )

        if not explanations:
            explanations.append("No suspicious indicators or security policy violations detected in this email.")

        # Recommendations
        recommendations = []
        if verdict == "PHISHING":
            recommendations.append("DO NOT click any embedded links or open any attached files.")
            recommendations.append("Report this email immediately to your Security Operations Center (SOC) or IT Admin.")
            recommendations.append("Block the sender address and domain at the email gateway level.")
        elif verdict == "SUSPICIOUS":
            recommendations.append("Exercise caution. Verify the sender's identity through an out-of-band communication channel.")
            recommendations.append("Hover over links to verify destination domains before clicking.")
            recommendations.append("Do not enter login credentials or financial information on linked web pages.")
        else:
            recommendations.append("Email appears safe, but maintain standard security awareness.")
            recommendations.append("Always verify unexpected requests for sensitive data.")

        scan_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return {
            "scan_timestamp": scan_timestamp,
            "filename": parsed_email.get("filename", "email.eml"),
            "subject": parsed_email.get("subject", ""),
            "sender": parsed_email.get("from", ""),
            "sender_email": parsed_email.get("from_email", ""),
            "sender_domain": parsed_email.get("from_domain", ""),
            "recipient": parsed_email.get("to", ""),
            "date": parsed_email.get("date", ""),
            "final_risk_score": final_risk_score,
            "verdict": verdict,
            "risk_level": risk_level,
            "badge_color": badge_color,
            "scores": {
                "header_score": h_score,
                "url_score": u_score,
                "attachment_score": a_score,
                "nlp_score": n_score,
                "ml_score": m_score
            },
            "header_details": header_res,
            "url_details": url_res,
            "attachment_details": att_res,
            "nlp_details": nlp_res,
            "ml_details": ml_res,
            "explanations": explanations,
            "recommendations": recommendations,
            "parsed_email": parsed_email
        }
