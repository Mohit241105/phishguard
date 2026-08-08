from qt_compat import QtCore, Signal
from core.hybrid_engine import HybridEngine
from core.database.db_manager import DBManager

class AnalysisWorker(QtCore.QThread):
    """Background worker thread for processing .eml analysis without blocking the UI main loop."""

    progress_signal = Signal(int)
    finished_signal = Signal(dict)
    error_signal = Signal(str)

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            self.progress_signal.emit(10)
            # Step 1: Parse email
            self.progress_signal.emit(30)
            
            # Step 2: Hybrid Engine Analysis
            report = HybridEngine.analyze_email_file(self.file_path)
            self.progress_signal.emit(80)

            # Step 3: Save to SQLite database
            try:
                DBManager.save_scan(report)
            except Exception as db_err:
                print(f"[Warning] Failed to save scan history to DB: {db_err}")

            self.progress_signal.emit(100)
            self.finished_signal.emit(report)

        except Exception as e:
            import traceback
            traceback.print_exc()
            self.error_signal.emit(str(e))
