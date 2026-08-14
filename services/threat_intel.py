import re
import hashlib

class ThreatIntelService:
    """Enterprise Threat Intelligence & IOC Extraction Service mapped to MITRE ATT&CK Framework."""

    MITRE_ATTACK_MAPPING = {
        "T1566.001": {
            "name": "Spearphishing Attachment",
            "tactics": ["Initial Access"],
            "description": "Malicious file attachment delivered via targeted email."
        },
        "T1566.002": {
            "name": "Spearphishing Link",
            "tactics": ["Initial Access"],
            "description": "Hyperlink directing victim to malicious payload or credential harvester."
        },
        "T1056.001": {
            "name": "Credential Harvesting",
            "tactics": ["Credential Access"],
            "description": "Social engineering prompt attempting to capture user credentials."
        },
        "T1036.007": {
            "name": "Brand Masquerading / Display Name Spoofing",
            "tactics": ["Defense Evasion"],
            "description": "Spoofing trusted enterprise names to bypass email filter heuristics."
        },
        "T1568": {
            "name": "Dynamic DNS & High-Risk TLD Infrastructure",
            "tactics": ["Command and Control"],
            "description": "Use of shorteners or disposable TLDs to conceal malicious landing infrastructure."
        }
    }

    @staticmethod
    def extract_iocs(parsed_email: dict, analysis_report: dict) -> dict:
        """Extract Indicators of Compromise (IOCs) from parsed email and analysis details."""
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "mitre_techniques": []
        }

        # IP Addresses
        header_details = analysis_report.get("header_details", {})
        origin_ip = header_details.get("originating_ip")
        if origin_ip and origin_ip != "Unknown":
            iocs["ip_addresses"].append({
                "ip": origin_ip,
                "type": "Originating Mail Server",
                "reputation": "Suspicious" if header_details.get("spf_status") == "FAIL" else "Neutral"
            })

        # Domains & URLs
        url_details = analysis_report.get("url_details", {})
        for u in url_details.get("urls", []):
            iocs["urls"].append({
                "url": u.get("url"),
                "score": u.get("score", 0),
                "risk_level": u.get("risk_level", "SAFE")
            })
            if u.get("domain") and u.get("domain") not in [d["domain"] for d in iocs["domains"]]:
                iocs["domains"].append({
                    "domain": u.get("domain"),
                    "category": "Suspicious TLD" if any("TLD" in f for f in u.get("flags", [])) else "Target Host"
                })

        # Sender Domain
        sender_domain = parsed_email.get("from_domain")
        if sender_domain and sender_domain not in [d["domain"] for d in iocs["domains"]]:
            iocs["domains"].append({
                "domain": sender_domain,
                "category": "Sender Domain"
            })

        # Attachment Hashes
        att_details = analysis_report.get("attachment_details", {})
        for att in att_details.get("analyzed_attachments", []):
            if att.get("sha256"):
                iocs["hashes"].append({
                    "filename": att.get("filename"),
                    "sha256": att.get("sha256"),
                    "risk_level": att.get("risk_level", "CLEAN")
                })

        # Map MITRE ATT&CK
        techniques = []
        if att_details.get("attachment_risk_score", 0) > 20:
            techniques.append(ThreatIntelService.MITRE_ATTACK_MAPPING["T1566.001"])
        if url_details.get("url_risk_score", 0) > 20:
            techniques.append(ThreatIntelService.MITRE_ATTACK_MAPPING["T1566.002"])
        nlp_details = analysis_report.get("nlp_details", {})
        if "Credential Harvesting" in nlp_details.get("detected_categories", {}):
            techniques.append(ThreatIntelService.MITRE_ATTACK_MAPPING["T1056.001"])
        if header_details.get("brand_spoofing"):
            techniques.append(ThreatIntelService.MITRE_ATTACK_MAPPING["T1036.007"])

        iocs["mitre_techniques"] = techniques
        return iocs

    @staticmethod
    def lookup_ioc(indicator: str, ioc_type: str) -> dict:
        """Mock/Live Threat Intel Sandbox Lookup for IOCs."""
        indicator_clean = indicator.strip().lower()
        
        return {
            "indicator": indicator_clean,
            "type": ioc_type,
            "virustotal": {
                "malicious_votes": 14 if "test" in indicator_clean or "malicious" in indicator_clean else 0,
                "total_engines": 72,
                "status": "FLAGGED" if "test" in indicator_clean or "malicious" in indicator_clean else "CLEAN"
            },
            "abuseipdb": {
                "abuse_confidence_score": 85 if ioc_type == "ip" and "192" not in indicator_clean else 0,
                "country": "US",
                "isp": "Cloud Security Corp"
            },
            "whois": {
                "registrar": "NameCheap Inc",
                "created_date": "2026-01-15",
                "domain_age_days": 210,
                "privacy_enabled": True
            }
        }
