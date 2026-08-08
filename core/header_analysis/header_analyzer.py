import re

class HeaderAnalyzer:
    """Analyzes email headers for SPF/DKIM/DMARC status, domain mismatches, routing, and spoofing indicators."""

    @staticmethod
    def analyze(parsed_email: dict) -> dict:
        risk_score = 0
        findings = []
        anomalies = []
        
        from_domain = parsed_email.get("from_domain", "")
        reply_to_domain = parsed_email.get("reply_to_domain", "")
        return_path_domain = parsed_email.get("return_path_domain", "")
        from_header = parsed_email.get("from", "")
        auth_results = parsed_email.get("auth_results", "").lower()
        received_spf = parsed_email.get("received_spf", "").lower()
        dkim_sig = parsed_email.get("dkim_signature", "")

        # 1. SPF Check
        spf_status = "UNKNOWN"
        if "spf=pass" in auth_results or "pass" in received_spf:
            spf_status = "PASS"
        elif "spf=fail" in auth_results or "fail" in received_spf or "softfail" in received_spf:
            spf_status = "FAIL"
            risk_score += 25
            findings.append("SPF Validation Failed: Sender IP is not authorized for the domain.")
        elif "spf=none" in auth_results or not received_spf:
            spf_status = "NONE"
            findings.append("No SPF authentication result found in headers.")

        # 2. DKIM Check
        dkim_status = "UNKNOWN"
        if "dkim=pass" in auth_results:
            dkim_status = "PASS"
        elif "dkim=fail" in auth_results:
            dkim_status = "FAIL"
            risk_score += 20
            findings.append("DKIM Signature Validation Failed: Email content may have been tampered with.")
        elif dkim_sig:
            dkim_status = "PRESENT"
        else:
            dkim_status = "NONE"
            anomalies.append("Missing DKIM cryptographic signature.")

        # 3. DMARC Check
        dmarc_status = "UNKNOWN"
        if "dmarc=pass" in auth_results:
            dmarc_status = "PASS"
        elif "dmarc=fail" in auth_results:
            dmarc_status = "FAIL"
            risk_score += 25
            findings.append("DMARC Validation Failed: Email violates domain policy.")

        # 4. Reply-To Domain Mismatch
        reply_mismatch = False
        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            reply_mismatch = True
            risk_score += 25
            findings.append(f"Reply-To Mismatch: Replies directed to '{reply_to_domain}' instead of sender domain '{from_domain}'.")

        # 5. Return-Path Domain Mismatch
        return_mismatch = False
        if return_path_domain and from_domain and return_path_domain != from_domain:
            return_mismatch = True
            risk_score += 20
            findings.append(f"Return-Path Mismatch: Bounce messages sent to '{return_path_domain}' instead of '{from_domain}'.")

        # 6. Display Name Brand Spoofing Check
        # Example: From: "PayPal Customer Support" <user@generic-web-host.com>
        brand_spoofing = False
        known_brands = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "bankofamerica", "chase", "wellsfargo", "docusign", "dropbox"]
        display_name_match = re.match(r'^["\']?([^"\']+)["\']?\s*<', from_header)
        display_name = display_name_match.group(1).lower() if display_name_match else ""
        
        if display_name:
            for brand in known_brands:
                if brand in display_name and brand not in from_domain:
                    brand_spoofing = True
                    risk_score += 30
                    findings.append(f"Display Name Spoofing Detected: Friendly name claims to be '{brand.title()}' but actual domain is '{from_domain}'.")
                    break

        # 7. Missing Core Headers
        if not parsed_email.get("message_id"):
            risk_score += 10
            anomalies.append("Missing Message-ID header (atypical for legitimate mail servers).")
            
        if not parsed_email.get("date"):
            risk_score += 10
            anomalies.append("Missing Date header.")

        # Extract Originating IP from Received Headers
        originating_ip = "Unknown"
        received_headers = parsed_email.get("received_headers", [])
        for rec in reversed(received_headers):
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', rec)
            if ip_match:
                originating_ip = ip_match.group(1)
                break

        final_score = min(risk_score, 100)

        return {
            "header_risk_score": final_score,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "reply_mismatch": reply_mismatch,
            "return_mismatch": return_mismatch,
            "brand_spoofing": brand_spoofing,
            "originating_ip": originating_ip,
            "findings": findings,
            "anomalies": anomalies
        }
