"""
Qt Compatibility Abstraction Layer for PhishGuard AI.
Supports PySide6, PyQt6, and PyQt5 seamlessly.
"""

import sys

QT_API = None

try:
    from PyQt6 import QtWidgets, QtCore, QtGui
    from PyQt6.QtCore import pyqtSignal as Signal, pyqtSlot as Slot
    QT_API = "PyQt6"
except ImportError:
    try:
        from PySide6 import QtWidgets, QtCore, QtGui
        from PySide6.QtCore import Signal, Slot
        QT_API = "PySide6"
    except ImportError:
        try:
            from PyQt5 import QtWidgets, QtCore, QtGui
            from PyQt5.QtCore import pyqtSignal as Signal, pyqtSlot as Slot
            QT_API = "PyQt5"
        except ImportError:
            raise ImportError(
                "No compatible Qt library found. Please install PyQt6, PySide6, or PyQt5."
            )

__all__ = ["QtWidgets", "QtCore", "QtGui", "Signal", "Slot", "QT_API"]
