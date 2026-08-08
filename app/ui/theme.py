"""
Simple, Clean, Minimalist UI Theme for PhishGuard AI.
"""

SIMPLE_DARK_QSS = """
QMainWindow {
    background-color: #0F172A;
    color: #F8FAFC;
}

QWidget {
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
    color: #F8FAFC;
}

/* Header Bar */
QFrame#HeaderBar {
    background-color: #1E293B;
    border-bottom: 1px solid #334155;
    padding: 14px 24px;
}

QLabel#HeaderTitle {
    font-size: 22px;
    font-weight: bold;
    color: #38BDF8;
}

QLabel#HeaderSubtitle {
    font-size: 12px;
    color: #94A3B8;
}

/* Main Cards */
QFrame#SimpleCard {
    background-color: #1E293B;
    border-radius: 12px;
    border: 1px solid #334155;
    padding: 20px;
}

/* Drop Zone Frame */
QFrame#DropZone {
    background-color: #0F172A;
    border: 2px dashed #38BDF8;
    border-radius: 12px;
    padding: 24px;
}

QFrame#DropZone:hover {
    background-color: #1E293B;
    border-color: #7DD3FC;
}

QLabel#DropLabel {
    color: #E2E8F0;
    font-weight: 600;
    font-size: 14px;
}

/* Buttons */
QPushButton {
    background-color: #334155;
    color: #F8FAFC;
    border-radius: 8px;
    padding: 10px 18px;
    font-weight: bold;
    border: none;
}

QPushButton:hover {
    background-color: #475569;
}

QPushButton#PrimaryScanBtn {
    background-color: #0284C7;
    color: #FFFFFF;
    font-size: 15px;
    font-weight: bold;
    border-radius: 10px;
    padding: 14px;
}

QPushButton#PrimaryScanBtn:hover {
    background-color: #0369A1;
}

QPushButton#SamplePhishBtn {
    background-color: #451A03;
    color: #FDBA74;
    border: 1px solid #7C2D12;
}

QPushButton#SamplePhishBtn:hover {
    background-color: #7C2D12;
}

QPushButton#SampleSafeBtn {
    background-color: #064E3B;
    color: #6EE7B7;
    border: 1px solid #047857;
}

QPushButton#SampleSafeBtn:hover {
    background-color: #047857;
}

/* Progress Bars */
QProgressBar {
    border: 1px solid #334155;
    background-color: #0F172A;
    border-radius: 6px;
    height: 16px;
    text-align: center;
    color: #F8FAFC;
    font-size: 11px;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: #38BDF8;
    border-radius: 5px;
}

/* Tabs & Tables */
QTabWidget::pane {
    border: 1px solid #334155;
    background-color: #1E293B;
    border-radius: 8px;
}

QTabBar::tab {
    background-color: #0F172A;
    color: #94A3B8;
    padding: 8px 16px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: bold;
}

QTabBar::tab:selected {
    background-color: #1E293B;
    color: #38BDF8;
    border-bottom: 2px solid #38BDF8;
}

QTableWidget {
    background-color: #0F172A;
    gridline-color: #334155;
    border: 1px solid #334155;
    border-radius: 6px;
}

QHeaderView::section {
    background-color: #1E293B;
    color: #38BDF8;
    padding: 6px;
    font-weight: bold;
    border: 1px solid #334155;
}

QTextEdit {
    background-color: #0F172A;
    border: 1px solid #334155;
    border-radius: 6px;
    color: #F8FAFC;
    font-family: 'Consolas', monospace;
    font-size: 12px;
}
"""
