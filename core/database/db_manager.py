import sqlite3
import json
import os

class DBManager:
    """SQLite Database Manager for local scan history storage and retrieval."""

    DB_FILE = os.path.join(os.path.dirname(__file__), "phishguard_history.db")

    @classmethod
    def init_db(cls):
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date TEXT NOT NULL,
                filename TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                risk_score INTEGER,
                verdict TEXT,
                report_json TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    @classmethod
    def save_scan(cls, report: dict) -> int:
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        
        # Serialize report for storage (excluding heavy raw html body if needed)
        json_data = json.dumps(report, default=str)
        
        cursor.execute("""
            INSERT INTO scan_history (scan_date, filename, sender, subject, risk_score, verdict, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            report.get("scan_timestamp", ""),
            report.get("filename", ""),
            report.get("sender", ""),
            report.get("subject", ""),
            report.get("final_risk_score", 0),
            report.get("verdict", "UNKNOWN"),
            json_data
        ))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    @classmethod
    def get_all_scans(cls) -> list:
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, scan_date, filename, sender, subject, risk_score, verdict, report_json
            FROM scan_history
            ORDER BY id DESC
        """)
        rows = cursor.fetchall()
        conn.close()

        scans = []
        for r in rows:
            scans.append({
                "id": r[0],
                "scan_date": r[1],
                "filename": r[2],
                "sender": r[3],
                "subject": r[4],
                "risk_score": r[5],
                "verdict": r[6],
                "report_json": r[7]
            })
        return scans

    @classmethod
    def search_scans(cls, query: str) -> list:
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        like_query = f"%{query}%"
        cursor.execute("""
            SELECT id, scan_date, filename, sender, subject, risk_score, verdict, report_json
            FROM scan_history
            WHERE filename LIKE ? OR sender LIKE ? OR subject LIKE ? OR verdict LIKE ?
            ORDER BY id DESC
        """, (like_query, like_query, like_query, like_query))
        rows = cursor.fetchall()
        conn.close()

        scans = []
        for r in rows:
            scans.append({
                "id": r[0],
                "scan_date": r[1],
                "filename": r[2],
                "sender": r[3],
                "subject": r[4],
                "risk_score": r[5],
                "verdict": r[6],
                "report_json": r[7]
            })
        return scans

    @classmethod
    def delete_scan(cls, scan_id: int):
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()

    @classmethod
    def clear_history(cls):
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history")
        conn.commit()
        conn.close()
