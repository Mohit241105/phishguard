import os
import unittest
import sys

# Ensure root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.email_parser.parser import EmailParser
from core.header_analysis.header_analyzer import HeaderAnalyzer
from core.url_analysis.url_analyzer import URLAnalyzer
from core.attachment_analysis.attachment_analyzer import AttachmentAnalyzer
from core.nlp.nlp_analyzer import NLPAnalyzer
from core.ai.ml_engine import MLEngine
from core.hybrid_engine import HybridEngine
from core.database.db_manager import DBManager

class TestPhishGuardAI(unittest.TestCase):

    def setUp(self):
        self.samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))
        self.phishing_file = os.path.join(self.samples_dir, "sample_phishing.eml")
        self.safe_file = os.path.join(self.samples_dir, "sample_safe.eml")

    def test_01_email_parser(self):
        parsed_phish = EmailParser.parse_file(self.phishing_file)
        self.assertEqual(parsed_phish["subject"], "URGENT: Your PayPal Account Has Been Suspended!")
        self.assertEqual(parsed_phish["from_domain"], "mail-server-9821.xyz")
        self.assertEqual(len(parsed_phish["attachments"]), 1)
        self.assertEqual(parsed_phish["attachments"][0]["filename"], "Account_Verification_Form.docm.exe")

        parsed_safe = EmailParser.parse_file(self.safe_file)
        self.assertEqual(parsed_safe["from_domain"], "company.com")
        self.assertEqual(len(parsed_safe["attachments"]), 0)

    def test_02_header_analyzer(self):
        parsed_phish = EmailParser.parse_file(self.phishing_file)
        res_phish = HeaderAnalyzer.analyze(parsed_phish)
        self.assertTrue(res_phish["reply_mismatch"])
        self.assertTrue(res_phish["return_mismatch"])
        self.assertTrue(res_phish["brand_spoofing"])
        self.assertGreaterEqual(res_phish["header_risk_score"], 50)

    def test_03_url_analyzer(self):
        parsed_phish = EmailParser.parse_file(self.phishing_file)
        res_url = URLAnalyzer.analyze(parsed_phish)
        self.assertGreater(res_url["total_urls"], 0)
        self.assertGreaterEqual(len(res_url["anchor_mismatches"]), 1)
        self.assertGreaterEqual(res_url["url_risk_score"], 40)

    def test_04_attachment_analyzer(self):
        parsed_phish = EmailParser.parse_file(self.phishing_file)
        res_att = AttachmentAnalyzer.analyze(parsed_phish)
        self.assertEqual(res_att["total_attachments"], 1)
        self.assertGreaterEqual(res_att["attachment_risk_score"], 50)

    def test_05_nlp_analyzer(self):
        parsed_phish = EmailParser.parse_file(self.phishing_file)
        res_nlp = NLPAnalyzer.analyze(parsed_phish)
        self.assertIn("Urgency & Pressure", res_nlp["detected_categories"])
        self.assertIn("Credential Harvesting", res_nlp["detected_categories"])

    def test_06_ml_engine(self):
        parsed_phish = EmailParser.parse_file(self.phishing_file)
        ml = MLEngine.get_instance()
        res_ml = ml.predict(parsed_phish)
        self.assertGreaterEqual(res_ml["ml_risk_score"], 50)

    def test_07_hybrid_engine(self):
        report_phish = HybridEngine.analyze_email_file(self.phishing_file)
        self.assertEqual(report_phish["verdict"], "PHISHING")
        self.assertGreaterEqual(report_phish["final_risk_score"], 65)

        report_safe = HybridEngine.analyze_email_file(self.safe_file)
        self.assertEqual(report_safe["verdict"], "SAFE")
        self.assertLess(report_safe["final_risk_score"], 35)

    def test_08_db_manager(self):
        report_phish = HybridEngine.analyze_email_file(self.phishing_file)
        scan_id = DBManager.save_scan(report_phish)
        self.assertIsInstance(scan_id, int)
        scans = DBManager.get_all_scans()
        self.assertGreater(len(scans), 0)

if __name__ == "__main__":
    unittest.main()
