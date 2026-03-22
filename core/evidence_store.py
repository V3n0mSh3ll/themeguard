import os
import json
import time
import sqlite3
import hashlib


_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".evidence.db")


class EvidenceStore:

    def __init__(self, db_path=None):
        self.db_path = db_path or _DB_PATH
        self._conn = None
        self._init_db()

    def _init_db(self):
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                files_scanned INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                scan_type TEXT,
                status TEXT DEFAULT 'running'
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                file TEXT NOT NULL,
                line INTEGER DEFAULT 0,
                type TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                confidence REAL DEFAULT 0.5,
                message TEXT,
                match_text TEXT,
                evidence_count INTEGER DEFAULT 1,
                action TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );
            CREATE TABLE IF NOT EXISTS file_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                file TEXT NOT NULL,
                file_hash TEXT,
                size INTEGER,
                risk_score REAL DEFAULT 0.0,
                findings_count INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        """)
        self._conn.commit()

    def start_scan(self, target, scan_type="theme"):
        scan_id = hashlib.md5(f"{target}{time.time()}".encode()).hexdigest()[:12]
        self._conn.execute(
            "INSERT INTO scans (scan_id, target, started_at, scan_type) VALUES (?, ?, ?, ?)",
            (scan_id, target, time.strftime("%Y-%m-%d %H:%M:%S"), scan_type),
        )
        self._conn.commit()
        return scan_id

    def finish_scan(self, scan_id, files_scanned, findings_count):
        self._conn.execute(
            "UPDATE scans SET finished_at=?, files_scanned=?, findings_count=?, status='done' WHERE scan_id=?",
            (time.strftime("%Y-%m-%d %H:%M:%S"), files_scanned, findings_count, scan_id),
        )
        self._conn.commit()

    def store_findings(self, scan_id, findings):
        rows = []
        for f in findings:
            rows.append((
                scan_id,
                f.get("file", ""),
                f.get("line", 0),
                f.get("type", ""),
                f.get("severity", "medium"),
                f.get("confidence", 0.5),
                f.get("message", ""),
                f.get("match", "")[:200],
                f.get("evidence_count", 1),
                f.get("action", ""),
                time.strftime("%Y-%m-%d %H:%M:%S"),
            ))
        self._conn.executemany(
            "INSERT INTO findings (scan_id, file, line, type, severity, confidence, message, match_text, evidence_count, action, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()

    def get_scan_history(self, limit=10):
        cur = self._conn.execute(
            "SELECT scan_id, target, started_at, finished_at, files_scanned, findings_count, status "
            "FROM scans ORDER BY started_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(zip(["scan_id", "target", "started_at", "finished_at", "files_scanned", "findings_count", "status"], row)) for row in cur.fetchall()]

    def get_findings_by_scan(self, scan_id):
        cur = self._conn.execute(
            "SELECT file, line, type, severity, confidence, message, action FROM findings WHERE scan_id=? ORDER BY severity DESC",
            (scan_id,),
        )
        return [dict(zip(["file", "line", "type", "severity", "confidence", "message", "action"], row)) for row in cur.fetchall()]

    def get_diff(self, scan_id_old, scan_id_new):
        old = set()
        cur = self._conn.execute("SELECT file, type, line FROM findings WHERE scan_id=?", (scan_id_old,))
        for row in cur.fetchall():
            old.add((row[0], row[1], row[2]))

        new_findings = []
        resolved = []

        cur = self._conn.execute("SELECT file, type, line, severity, message FROM findings WHERE scan_id=?", (scan_id_new,))
        new_set = set()
        for row in cur.fetchall():
            key = (row[0], row[1], row[2])
            new_set.add(key)
            if key not in old:
                new_findings.append({"file": row[0], "type": row[1], "line": row[2], "severity": row[3], "message": row[4]})

        for key in old:
            if key not in new_set:
                resolved.append({"file": key[0], "type": key[1], "line": key[2]})

        return {"new": new_findings, "resolved": resolved}

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
