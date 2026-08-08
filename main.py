"""
PhishGuard AI - Standalone SOC Email Security Suite
Native Windows Desktop Application Entry Point
"""

import sys
import os
import io

# Ensure UTF-8 output encoding for standard output
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add root directory to python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from qt_compat import QtWidgets
from app.ui.main_window import MainWindow

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("PhishGuard AI")
    app.setOrganizationName("Security SOC")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
