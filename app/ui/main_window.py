import sys
import os
import json
from qt_compat import QtWidgets, QtCore, QtGui, Signal, Slot
from app.ui.theme import SIMPLE_DARK_QSS
from app.controllers.analysis_controller import AnalysisWorker
from core.database.db_manager import DBManager
from core.reports.report_generator import ReportGenerator

class SimpleDropZone(QtWidgets.QFrame):
    """Simple Drag & Drop box for .eml files."""
    file_dropped_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        self.label = QtWidgets.QLabel("📁 Drag & Drop .eml Email File Here\nor Click to Browse")
        self.label.setObjectName("DropLabel")
        self.label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.label)

    def mousePressEvent(self, event: QtGui.QMouseEvent):
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "Select Email File", "", "Email Files (*.eml *.msg *.txt);;All Files (*)"
            )
            if file_path:
                self.file_dropped_signal.emit(file_path)

    def dragEnterEvent(self, event: QtGui.QDragEnterEvent):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and urls[0].toLocalFile().lower().endswith(('.eml', '.msg', '.txt')):
                event.acceptProposedAction()
                return
        event.ignore()

    def dropEvent(self, event: QtGui.QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_dropped_signal.emit(file_path)
            event.acceptProposedAction()


class HistoryDialog(QtWidgets.QDialog):
    """Simple History Dialog."""
    report_selected_signal = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan History - PhishGuard AI")
        self.resize(750, 450)
        
        layout = QtWidgets.QVBoxLayout(self)

        search_row = QtWidgets.QHBoxLayout()
        self.txt_search = QtWidgets.QLineEdit()
        self.txt_search.setPlaceholderText("Search history by sender, subject, or filename...")
        self.txt_search.textChanged.connect(self._filter_history)

        btn_clear = QtWidgets.QPushButton("Clear History")
        btn_clear.setStyleSheet("background-color: #EF4444; color: white; font-weight: bold;")
        btn_clear.clicked.connect(self._clear_history)

        search_row.addWidget(self.txt_search, stretch=1)
        search_row.addWidget(btn_clear)
        layout.addLayout(search_row)

        self.tbl_history = QtWidgets.QTableWidget()
        self.tbl_history.setColumnCount(6)
        self.tbl_history.setHorizontalHeaderLabels(["ID", "Date", "Filename", "Sender", "Subject", "Verdict"])
        self.tbl_history.horizontalHeader().setStretchLastSection(True)
        self.tbl_history.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self.tbl_history)

        self._load_data()

    def _load_data(self, query=""):
        scans = DBManager.search_scans(query) if query else DBManager.get_all_scans()
        self.tbl_history.setRowCount(len(scans))
        for row, s in enumerate(scans):
            self.tbl_history.setItem(row, 0, QtWidgets.QTableWidgetItem(str(s["id"])))
            self.tbl_history.setItem(row, 1, QtWidgets.QTableWidgetItem(s["scan_date"]))
            self.tbl_history.setItem(row, 2, QtWidgets.QTableWidgetItem(s["filename"]))
            self.tbl_history.setItem(row, 3, QtWidgets.QTableWidgetItem(s["sender"]))
            self.tbl_history.setItem(row, 4, QtWidgets.QTableWidgetItem(s["subject"]))
            
            verdict_item = QtWidgets.QTableWidgetItem(f"{s['verdict']} ({s['risk_score']})")
            if s['verdict'] == 'PHISHING':
                verdict_item.setForeground(QtGui.QColor("#EF4444"))
            elif s['verdict'] == 'SUSPICIOUS':
                verdict_item.setForeground(QtGui.QColor("#F59E0B"))
            else:
                verdict_item.setForeground(QtGui.QColor("#10B981"))
            self.tbl_history.setItem(row, 5, verdict_item)

    def _filter_history(self, text: str):
        self._load_data(text.strip())

    def _on_double_click(self, index):
        row = index.row()
        scan_id_item = self.tbl_history.item(row, 0)
        if scan_id_item:
            scan_id = int(scan_id_item.text())
            scans = DBManager.get_all_scans()
            for s in scans:
                if s["id"] == scan_id:
                    report = json.loads(s["report_json"])
                    self.report_selected_signal.emit(report)
                    self.accept()
                    break

    def _clear_history(self):
        if QtWidgets.QMessageBox.question(self, "Clear History", "Delete all saved scan history?") == QtWidgets.QMessageBox.StandardButton.Yes:
            DBManager.clear_history()
            self._load_data()


class MainWindow(QtWidgets.QMainWindow):
    """Simple & Clean Native Desktop Application."""

    def __init__(self):
        super().__init__()
        self.current_file_path = None
        self.current_report = None
        self.worker = None

        self.setWindowTitle("PhishGuard AI - Email Security Analyzer")
        self.resize(1050, 720)
        self.setStyleSheet(SIMPLE_DARK_QSS)

        self._init_ui()

    def _init_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header Bar
        header = QtWidgets.QFrame()
        header.setObjectName("HeaderBar")
        h_layout = QtWidgets.QHBoxLayout(header)

        title_box = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel("🛡️ PhishGuard AI")
        title.setObjectName("HeaderTitle")
        sub = QtWidgets.QLabel("AI-Powered Phishing Detection & Analysis Engine")
        sub.setObjectName("HeaderSubtitle")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        h_layout.addLayout(title_box)

        h_layout.addStretch()

        btn_history = QtWidgets.QPushButton("📜 History")
        btn_history.clicked.connect(self._open_history)

        btn_export = QtWidgets.QPushButton("💾 Export")
        btn_export.clicked.connect(self._open_export)

        h_layout.addWidget(btn_history)
        h_layout.addWidget(btn_export)

        main_layout.addWidget(header)

        # Body Content
        body = QtWidgets.QWidget()
        b_layout = QtWidgets.QHBoxLayout(body)
        b_layout.setContentsMargins(20, 20, 20, 20)
        b_layout.setSpacing(20)

        # LEFT CARD: Input
        left_card = QtWidgets.QFrame()
        left_card.setObjectName("SimpleCard")
        left_card.setFixedWidth(400)
        l_layout = QtWidgets.QVBoxLayout(left_card)
        l_layout.setSpacing(16)

        l_title = QtWidgets.QLabel("1. Select Email File")
        l_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #38BDF8;")
        l_layout.addWidget(l_title)

        # Drop Zone
        self.drop_zone = SimpleDropZone()
        self.drop_zone.file_dropped_signal.connect(self._on_file_selected)
        l_layout.addWidget(self.drop_zone, stretch=1)

        # Sample Buttons
        sample_label = QtWidgets.QLabel("Or test with quick sample:")
        sample_label.setStyleSheet("color: #94A3B8; font-size: 11px;")
        l_layout.addWidget(sample_label)

        sample_row = QtWidgets.QHBoxLayout()
        self.btn_sample_phish = QtWidgets.QPushButton("⚠️ Phishing Sample")
        self.btn_sample_phish.setObjectName("SamplePhishBtn")
        self.btn_sample_phish.clicked.connect(lambda: self._analyze_sample("phishing"))

        self.btn_sample_safe = QtWidgets.QPushButton("🛡️ Safe Sample")
        self.btn_sample_safe.setObjectName("SampleSafeBtn")
        self.btn_sample_safe.clicked.connect(lambda: self._analyze_sample("safe"))

        sample_row.addWidget(self.btn_sample_phish)
        sample_row.addWidget(self.btn_sample_safe)
        l_layout.addLayout(sample_row)

        # Primary Analyze Button
        self.btn_analyze = QtWidgets.QPushButton("🚀 Analyze Email")
        self.btn_analyze.setObjectName("PrimaryScanBtn")
        self.btn_analyze.clicked.connect(self._run_analysis)
        l_layout.addWidget(self.btn_analyze)

        b_layout.addWidget(left_card)

        # RIGHT CARD: Results
        right_card = QtWidgets.QFrame()
        right_card.setObjectName("SimpleCard")
        r_layout = QtWidgets.QVBoxLayout(right_card)
        r_layout.setSpacing(14)

        # Verdict Banner
        self.banner = QtWidgets.QFrame()
        self.banner.setStyleSheet("background-color: #0F172A; border-radius: 8px; border: 2px solid #38BDF8; padding: 14px;")
        banner_layout = QtWidgets.QHBoxLayout(self.banner)

        banner_box = QtWidgets.QVBoxLayout()
        self.lbl_verdict = QtWidgets.QLabel("READY TO ANALYZE")
        self.lbl_verdict.setStyleSheet("font-size: 22px; font-weight: bold; color: #38BDF8;")
        
        self.lbl_score = QtWidgets.QLabel("Select an email file on the left and click Analyze.")
        self.lbl_score.setStyleSheet("color: #94A3B8; font-size: 13px;")

        banner_box.addWidget(self.lbl_verdict)
        banner_box.addWidget(self.lbl_score)
        banner_layout.addLayout(banner_box)
        banner_layout.addStretch()

        r_layout.addWidget(self.banner)

        # Sub-score Progress Bars
        sub_group = QtWidgets.QGroupBox("Security Engine Breakdown")
        sub_group.setStyleSheet("font-weight: bold; color: #38BDF8;")
        sub_lay = QtWidgets.QFormLayout(sub_group)
        sub_lay.setSpacing(6)

        self.bar_header = QtWidgets.QProgressBar()
        self.bar_url = QtWidgets.QProgressBar()
        self.bar_att = QtWidgets.QProgressBar()
        self.bar_nlp = QtWidgets.QProgressBar()
        self.bar_ml = QtWidgets.QProgressBar()

        sub_lay.addRow("Header Integrity:", self.bar_header)
        sub_lay.addRow("URL Security:", self.bar_url)
        sub_lay.addRow("Attachment Risk:", self.bar_att)
        sub_lay.addRow("NLP Social Eng:", self.bar_nlp)
        sub_lay.addRow("AI ML Confidence:", self.bar_ml)

        r_layout.addWidget(sub_group)

        # Tabs
        self.tabs = QtWidgets.QTabWidget()
        r_layout.addWidget(self.tabs, stretch=1)

        # Tab 1: AI Evidence
        t_exp = QtWidgets.QWidget()
        l_exp = QtWidgets.QVBoxLayout(t_exp)
        self.txt_evidence = QtWidgets.QTextEdit()
        self.txt_evidence.setReadOnly(True)
        l_exp.addWidget(self.txt_evidence)
        self.tabs.addTab(t_exp, "🧠 AI Evidence & Recommendations")

        # Tab 2: URLs
        t_url = QtWidgets.QWidget()
        l_url = QtWidgets.QVBoxLayout(t_url)
        self.tbl_urls = QtWidgets.QTableWidget()
        self.tbl_urls.setColumnCount(4)
        self.tbl_urls.setHorizontalHeaderLabels(["URL Target", "Domain Host", "Risk Level", "Score"])
        self.tbl_urls.horizontalHeader().setStretchLastSection(True)
        l_url.addWidget(self.tbl_urls)
        self.tabs.addTab(t_url, "🔗 URLs")

        # Tab 3: Attachments
        t_att = QtWidgets.QWidget()
        l_att = QtWidgets.QVBoxLayout(t_att)
        self.tbl_atts = QtWidgets.QTableWidget()
        self.tbl_atts.setColumnCount(4)
        self.tbl_atts.setHorizontalHeaderLabels(["Filename", "Extension", "Size (Bytes)", "Risk Level"])
        self.tbl_atts.horizontalHeader().setStretchLastSection(True)
        l_att.addWidget(self.tbl_atts)
        self.tabs.addTab(t_att, "📎 Attachments")

        # Tab 4: Raw Headers
        t_auth = QtWidgets.QWidget()
        l_auth = QtWidgets.QVBoxLayout(t_auth)
        self.txt_auth = QtWidgets.QTextEdit()
        self.txt_auth.setReadOnly(True)
        l_auth.addWidget(self.txt_auth)
        self.tabs.addTab(t_auth, "📧 Headers")

        b_layout.addWidget(right_card, stretch=1)
        main_layout.addWidget(body, stretch=1)

        self.statusBar().showMessage("Ready.")

    # =================================================================
    # ACTIONS
    # =================================================================
    def _on_file_selected(self, file_path: str):
        self.current_file_path = file_path
        fname = os.path.basename(file_path)
        self.drop_zone.label.setText(f"📄 Selected File:\n{fname}")
        self.statusBar().showMessage(f"Selected: {fname}")

    def _analyze_sample(self, sample_type: str):
        samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "samples"))
        file_path = os.path.join(samples_dir, "sample_phishing.eml" if sample_type == "phishing" else "sample_safe.eml")
        self._on_file_selected(file_path)
        self._run_analysis()

    def _run_analysis(self):
        if not self.current_file_path or not os.path.exists(self.current_file_path):
            QtWidgets.QMessageBox.warning(self, "Warning", "Please select an .eml email file first!")
            return

        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Analyzing...")
        self.statusBar().showMessage("Running security inspection...")

        self.worker = AnalysisWorker(self.current_file_path)
        self.worker.finished_signal.connect(self._on_analysis_finished)
        self.worker.error_signal.connect(self._on_analysis_error)
        self.worker.start()

    @Slot(dict)
    def _on_analysis_finished(self, report: dict):
        self.current_report = report
        self.btn_analyze.setEnabled(True)
        self.btn_analyze.setText("🚀 Analyze Email")
        self.statusBar().showMessage(f"Analysis complete. Verdict: {report.get('verdict')}")
        self._update_results(report)

    @Slot(str)
    def _on_analysis_error(self, err: str):
        self.btn_analyze.setEnabled(True)
        self.btn_analyze.setText("🚀 Analyze Email")
        QtWidgets.QMessageBox.critical(self, "Error", err)

    def _update_results(self, r: dict):
        verdict = r.get("verdict", "UNKNOWN")
        score = r.get("final_risk_score", 0)
        badge_color = r.get("badge_color", "#38BDF8")

        self.lbl_verdict.setText(f"VERDICT: {verdict}")
        self.lbl_verdict.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {badge_color};")
        self.lbl_score.setText(f"Risk Score: {score}/100 ({r.get('risk_level')})")
        self.banner.setStyleSheet(f"background-color: #0F172A; border-radius: 8px; border: 2px solid {badge_color}; padding: 14px;")

        # Progress bars
        scores = r.get("scores", {})
        self.bar_header.setValue(scores.get("header_score", 0))
        self.bar_url.setValue(scores.get("url_score", 0))
        self.bar_att.setValue(scores.get("attachment_score", 0))
        self.bar_nlp.setValue(scores.get("nlp_score", 0))
        self.bar_ml.setValue(scores.get("ml_score", 0))

        # Tab 1: AI Evidence & Recommendations
        lines = ["🧠 EXPLAINABLE AI EVIDENCE:"] + [f"• {e}" for e in r.get("explanations", [])]
        lines += ["\n🛡️ RECOMMENDED ACTIONS:"] + [f"✔ {rec}" for rec in r.get("recommendations", [])]
        self.txt_evidence.setPlainText("\n".join(lines))

        # Tab 2: URLs Table
        urls = r.get("url_details", {}).get("urls", [])
        self.tbl_urls.setRowCount(len(urls))
        for r_idx, u in enumerate(urls):
            self.tbl_urls.setItem(r_idx, 0, QtWidgets.QTableWidgetItem(u.get("url", "")))
            self.tbl_urls.setItem(r_idx, 1, QtWidgets.QTableWidgetItem(u.get("domain", "")))
            self.tbl_urls.setItem(r_idx, 2, QtWidgets.QTableWidgetItem(u.get("risk_level", "")))
            self.tbl_urls.setItem(r_idx, 3, QtWidgets.QTableWidgetItem(str(u.get("score", 0))))

        # Tab 3: Attachments Table
        atts = r.get("attachment_details", {}).get("analyzed_attachments", [])
        self.tbl_atts.setRowCount(len(atts))
        for r_idx, a in enumerate(atts):
            self.tbl_atts.setItem(r_idx, 0, QtWidgets.QTableWidgetItem(a.get("filename", "")))
            self.tbl_atts.setItem(r_idx, 1, QtWidgets.QTableWidgetItem(a.get("extension", "")))
            self.tbl_atts.setItem(r_idx, 2, QtWidgets.QTableWidgetItem(str(a.get("size", 0))))
            self.tbl_atts.setItem(r_idx, 3, QtWidgets.QTableWidgetItem(a.get("risk_level", "")))

        # Tab 4: Raw Headers
        h = r.get("header_details", {})
        auth_text = f"Subject: {r.get('subject')}\nSender: {r.get('sender')}\nRecipient: {r.get('recipient')}\nDate: {r.get('date')}\n\nSPF Status: {h.get('spf_status')}\nDKIM Status: {h.get('dkim_status')}\nDMARC Status: {h.get('dmarc_status')}\nOriginating IP: {h.get('originating_ip')}\nReply-To Mismatch: {h.get('reply_mismatch')}\nReturn-Path Mismatch: {h.get('return_mismatch')}\nBrand Spoofing: {h.get('brand_spoofing')}"
        self.txt_auth.setPlainText(auth_text)

    def _open_history(self):
        dlg = HistoryDialog(self)
        dlg.report_selected_signal.connect(self._update_results)
        dlg.exec()

    def _open_export(self):
        if not self.current_report:
            QtWidgets.QMessageBox.warning(self, "Warning", "No active report to export.")
            return

        fmt, ok = QtWidgets.QInputDialog.getItem(
            self, "Export Report", "Select Format:", ["HTML Report", "JSON Data", "Text Summary"], 0, False
        )
        if ok and fmt:
            fname = f"PhishGuard_Report_{self.current_report.get('filename', 'email')}"
            if "HTML" in fmt:
                path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save HTML Report", f"{fname}.html", "HTML Files (*.html)")
                if path: ReportGenerator.export_html(self.current_report, path)
            elif "JSON" in fmt:
                path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save JSON Data", f"{fname}.json", "JSON Files (*.json)")
                if path: ReportGenerator.export_json(self.current_report, path)
            elif "Text" in fmt:
                path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Text Summary", f"{fname}.txt", "Text Files (*.txt)")
                if path: ReportGenerator.export_text(self.current_report, path)
