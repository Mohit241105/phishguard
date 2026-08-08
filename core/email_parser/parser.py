import os
import re
import hashlib
from email import policy
from email.parser import BytesParser
import urllib.parse

class EmailParser:
    """Parses RFC-822 (.eml) files into clean structured email metadata and content."""

    @staticmethod
    def parse_file(file_path: str) -> dict:
        with open(file_path, 'rb') as f:
            raw_bytes = f.read()
        return EmailParser.parse_bytes(raw_bytes, filename=os.path.basename(file_path))

    @staticmethod
    def parse_bytes(raw_bytes: bytes, filename: str = "uploaded.eml") -> dict:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        
        # Extract headers dictionary
        headers_raw = dict(msg.items())
        
        subject = msg.get('Subject', '(No Subject)')
        from_header = msg.get('From', '')
        to_header = msg.get('To', '')
        reply_to = msg.get('Reply-To', '')
        return_path = msg.get('Return-Path', '')
        date_header = msg.get('Date', '')
        message_id = msg.get('Message-ID', '')
        
        # All received headers
        received_list = msg.get_all('Received', [])
        auth_results = msg.get('Authentication-Results', '')
        dkim_sig = msg.get('DKIM-Signature', '')
        received_spf = msg.get('Received-SPF', '')

        # Extract domains from sender addresses
        from_email, from_domain = EmailParser._extract_email_and_domain(from_header)
        reply_to_email, reply_to_domain = EmailParser._extract_email_and_domain(reply_to)
        return_path_email, return_path_domain = EmailParser._extract_email_and_domain(return_path)

        # Extract body text and HTML
        text_body = ""
        html_body = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                # Check attachment
                if 'attachment' in content_disposition or part.get_filename():
                    att_name = part.get_filename() or "unnamed_attachment"
                    att_bytes = part.get_payload(decode=True) or b""
                    att_sha256 = hashlib.sha256(att_bytes).hexdigest()
                    attachments.append({
                        "filename": att_name,
                        "content_type": content_type,
                        "size": len(att_bytes),
                        "sha256": att_sha256
                    })
                elif content_type == 'text/plain' and 'attachment' not in content_disposition:
                    try:
                        text_body += part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            text_body += payload.decode('utf-8', errors='ignore')
                elif content_type == 'text/html' and 'attachment' not in content_disposition:
                    try:
                        html_body += part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_body += payload.decode('utf-8', errors='ignore')
        else:
            content_type = msg.get_content_type()
            try:
                content_str = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True)
                content_str = payload.decode('utf-8', errors='ignore') if payload else ""
                
            if content_type == 'text/html':
                html_body = content_str
            else:
                text_body = content_str

        # If no plain text, extract text from HTML roughly
        combined_body = text_body
        if not combined_body and html_body:
            combined_body = re.sub(r'<[^>]+>', ' ', html_body)

        return {
            "filename": filename,
            "subject": subject,
            "from": from_header,
            "from_email": from_email,
            "from_domain": from_domain,
            "to": to_header,
            "reply_to": reply_to,
            "reply_to_email": reply_to_email,
            "reply_to_domain": reply_to_domain,
            "return_path": return_path,
            "return_path_email": return_path_email,
            "return_path_domain": return_path_domain,
            "date": date_header,
            "message_id": message_id,
            "auth_results": auth_results,
            "dkim_signature": dkim_sig,
            "received_spf": received_spf,
            "received_headers": received_list,
            "text_body": text_body,
            "html_body": html_body,
            "combined_body": combined_body,
            "attachments": attachments,
            "raw_headers": headers_raw
        }

    @staticmethod
    def _extract_email_and_domain(header_val: str) -> tuple:
        if not header_val:
            return "", ""
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_val)
        if match:
            email_addr = match.group(0).lower()
            domain = email_addr.split('@')[-1]
            return email_addr, domain
        return "", ""
