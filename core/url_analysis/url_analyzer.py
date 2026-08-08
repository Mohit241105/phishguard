import re
import urllib.parse

class URLAnalyzer:
    """Extracts, decodes, and evaluates URLs in email content for security risks."""

    URL_REGEX = re.compile(r'(?:https?://|ftp://)[^\s"\'<>]+', re.IGNORECASE)
    IP_HOST_REGEX = re.compile(r'^(?:https?://|ftp://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE)
    
    SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 'rb.gy', 'tiny.cc'}
    SUSPICIOUS_TLDS = {'.xyz', '.top', '.zip', '.club', '.work', '.online', '.site', '.vip', '.icu', '.cam', '.monster', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq'}

    @staticmethod
    def analyze(parsed_email: dict) -> dict:
        text_body = parsed_email.get("text_body", "")
        html_body = parsed_email.get("html_body", "")
        sender_domain = parsed_email.get("from_domain", "")

        extracted_urls = set()
        anchor_mismatches = []

        # Extract plain URLs from text body
        for match in URLAnalyzer.URL_REGEX.findall(text_body):
            extracted_urls.add(URLAnalyzer._clean_url(match))

        # Extract URLs and check href vs anchor text mismatch in HTML
        if html_body:
            # Match <a ... href="URL">TEXT</a>
            html_links = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_body, re.IGNORECASE | re.DOTALL)
            for href, anchor_text in html_links:
                clean_href = URLAnalyzer._clean_url(href)
                extracted_urls.add(clean_href)
                
                # Strip inner HTML tags from anchor text
                clean_anchor = re.sub(r'<[^>]+>', '', anchor_text).strip()
                # If anchor text looks like a domain or URL, compare with href target
                if re.search(r'https?://|www\.|\w+\.\w+', clean_anchor):
                    anchor_domain = URLAnalyzer._extract_domain(clean_anchor)
                    href_domain = URLAnalyzer._extract_domain(clean_href)
                    if anchor_domain and href_domain and anchor_domain != href_domain:
                        anchor_mismatches.append({
                            "displayed_text": clean_anchor,
                            "actual_destination": clean_href,
                            "display_domain": anchor_domain,
                            "actual_domain": href_domain
                        })

        analyzed_urls = []
        max_url_score = 0
        total_risk_points = 0
        findings = []

        for url in extracted_urls:
            url_res = URLAnalyzer._analyze_single_url(url, sender_domain)
            analyzed_urls.append(url_res)
            total_risk_points += url_res["score"]
            if url_res["score"] > max_url_score:
                max_url_score = url_res["score"]

        # If anchor text mismatches detected
        if anchor_mismatches:
            total_risk_points += len(anchor_mismatches) * 35
            for am in anchor_mismatches:
                findings.append(
                    f"Deceptive Link Detected: Anchor text displays '{am['displayed_text']}' but links to '{am['actual_destination']}'."
                )

        # Summarize URL risk score
        url_count = len(analyzed_urls)
        if url_count == 0:
            final_risk_score = 0
        else:
            # Average score + max score boost
            calculated = (total_risk_points / url_count) * 0.5 + max_url_score * 0.5
            final_risk_score = min(int(calculated), 100)

        # High risk findings from URLs
        for u in analyzed_urls:
            for flag in u["flags"]:
                if flag not in findings:
                    findings.append(f"Suspicious URL [{u['url']}]: {flag}")

        return {
            "url_risk_score": final_risk_score,
            "total_urls": url_count,
            "urls": analyzed_urls,
            "anchor_mismatches": anchor_mismatches,
            "findings": findings
        }

    @staticmethod
    def _analyze_single_url(url: str, sender_domain: str = "") -> dict:
        score = 0
        flags = []
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc.lower().split(':')[0]
        
        # 1. IP Host Check
        if URLAnalyzer.IP_HOST_REGEX.match(url):
            score += 40
            flags.append("URL uses raw IP address instead of domain name.")

        # 2. Shortener Check
        if hostname in URLAnalyzer.SHORTENERS:
            score += 30
            flags.append("URL uses a shortening service to conceal target domain.")

        # 3. Punycode / Homograph Check
        if hostname.startswith("xn--"):
            score += 45
            flags.append("URL uses Punycode (possible Internationalized Domain Name homograph attack).")

        # 4. Suspicious TLD
        for tld in URLAnalyzer.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                score += 25
                flags.append(f"Domain uses high-risk suspicious TLD '{tld}'.")
                break

        # 5. Non-HTTPS
        if parsed.scheme.lower() == 'http':
            score += 15
            flags.append("URL uses unencrypted HTTP protocol.")

        # 6. Length Check
        if len(url) > 100:
            score += 15
            flags.append("Excessively long URL (frequently used for obfuscation).")

        # 7. Domain Mismatch with Sender
        if sender_domain and hostname and sender_domain not in hostname:
            score += 15

        risk_level = "SAFE"
        if score >= 50:
            risk_level = "DANGEROUS"
        elif score >= 25:
            risk_level = "SUSPICIOUS"

        return {
            "url": url,
            "domain": hostname,
            "score": min(score, 100),
            "risk_level": risk_level,
            "flags": flags
        }

    @staticmethod
    def _clean_url(url: str) -> str:
        # Decode percent-encoding
        url = urllib.parse.unquote(url)
        # Clean trailing punctuation
        url = url.rstrip('.,;)\'">')
        return url

    @staticmethod
    def _extract_domain(text_or_url: str) -> str:
        if not text_or_url.startswith(('http://', 'https://')):
            text_or_url = 'http://' + text_or_url
        parsed = urllib.parse.urlparse(text_or_url)
        return parsed.netloc.lower().split(':')[0]
