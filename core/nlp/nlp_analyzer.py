import re

class NLPAnalyzer:
    """Analyzes email text content for social engineering tactics, urgency language, and phishing intent."""

    PHISHING_PATTERNS = {
        "Urgency & Pressure": [
            r"\burgent(?:ly)?\b", r"\baction required\b", r"\bimmediately\b",
            r"\bwithin 24 hours\b", r"\bwithin 12 hours\b", r"\baccount (?:will be )?suspended\b",
            r"\baccount (?:will be )?terminated\b", r"\bexpiring soon\b", r"\bact now\b", r"\bfinal notice\b"
        ],
        "Fear & Threat Tactics": [
            r"\bunauthorized (?:access|login|activity)\b", r"\bsecurity (?:alert|breach|warning)\b",
            r"\bsuspicious activity\b", r"\baccount (?:locked|compromised)\b",
            r"\bverify your identity\b", r"\bprevent account closure\b"
        ],
        "Credential Harvesting": [
            r"\bclick (?:here|below)? (?:to|and) (?:login|verify|update|restore)\b", r"\bconfirm your password\b",
            r"\bupdate (?:your )?payment (?:details|method|info)\b", r"\bverify (?:your )?(?:account|identity)\b",
            r"\bre-authenticate\b", r"\bsign in to continue\b", r"\bvalidate credentials\b", r"\brestore (?:your )?access\b"
        ],
        "Financial & BEC Scams": [
            r"\bwire transfer\b", r"\bunpaid invoice\b", r"\bpayroll (?:change|update)\b",
            r"\bpayment confirmation\b", r"\bgift cards?\b", r"\bconfidential task\b",
            r"\bare you available\b", r"\bdirect deposit update\b", r"\bbank account details\b"
        ]
    }

    @staticmethod
    def analyze(parsed_email: dict) -> dict:
        combined_body = parsed_email.get("combined_body", "")
        subject = parsed_email.get("subject", "")
        full_text = (subject + " " + combined_body).lower()

        detected_categories = {}
        total_hits = 0
        findings = []
        risk_score = 0

        for category, patterns in NLPAnalyzer.PHISHING_PATTERNS.items():
            category_hits = []
            for pattern in patterns:
                matches = re.findall(pattern, full_text, re.IGNORECASE)
                if matches:
                    category_hits.extend(matches)
            
            if category_hits:
                detected_categories[category] = list(set(category_hits))
                hit_count = len(category_hits)
                total_hits += hit_count
                
                # Category specific scoring
                if category == "Credential Harvesting":
                    risk_score += hit_count * 25
                elif category == "Fear & Threat Tactics":
                    risk_score += hit_count * 20
                elif category == "Urgency & Pressure":
                    risk_score += hit_count * 15
                elif category == "Financial & BEC Scams":
                    risk_score += hit_count * 20
                
                matched_str = ", ".join([f"'{m}'" for m in set(category_hits)])
                findings.append(f"Social Engineering Tactic [{category}]: Detected keywords {matched_str}.")

        # Check for generic suspicious greetings (e.g., "Dear Customer", "Dear User")
        if re.search(r'\bdear (?:customer|user|account holder|client|sir/madam)\b', full_text):
            risk_score += 15
            findings.append("Generic Greeting Detected: 'Dear Customer/User' instead of recipient name.")

        final_risk_score = min(risk_score, 100)

        return {
            "nlp_risk_score": final_risk_score,
            "total_tactic_hits": total_hits,
            "detected_categories": detected_categories,
            "findings": findings
        }
