"""
========================================================================================
x1vart Persistent Database Manager (SQLite3)
========================================================================================
Provides zero-dependency persistent storage for:
- Historical Scan Results (Attack Surface History)
- Risk Scores, Grades, and OWASP Threat Findings
- Comparison and Diff Tracking between Scans
- Scan Management (List, View, Delete)
========================================================================================
"""

import json
import os
import sys
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

if getattr(sys, 'frozen', False):
    DB_DIR = os.path.dirname(sys.executable)
else:
    DB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILE_PATH = os.path.join(DB_DIR, "x1vart.db")


class DatabaseManager:
    def __init__(self, db_path: str = DB_FILE_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes SQLite schema if not exists."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    status TEXT NOT NULL, -- RUNNING, COMPLETED, FAILED
                    progress INTEGER DEFAULT 0,
                    current_stage TEXT DEFAULT 'Initializing',
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    risk_score INTEGER DEFAULT 0,
                    risk_grade TEXT DEFAULT '-',
                    execution_mode TEXT NOT NULL,
                    worker_ip TEXT,
                    summary_json TEXT,
                    results_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_id ON scans(scan_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON scans(domain)")

            # Schedules table for Continuous Recon (EASM)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    schedule_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    interval_hours INTEGER NOT NULL DEFAULT 24,
                    use_kali INTEGER NOT NULL DEFAULT 1,
                    worker_ip TEXT DEFAULT '192.168.1.100:22',
                    discord_webhook TEXT DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_run_at TEXT,
                    next_run_at TEXT,
                    last_scan_id TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sched_next ON schedules(enabled, next_run_at)")

            # Diff history table for Asset changes
            conn.execute("""
                CREATE TABLE IF NOT EXISTS diff_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    old_scan_id TEXT NOT NULL,
                    new_scan_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    diff_json TEXT NOT NULL,
                    alert_sent INTEGER DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_diff_domain ON diff_history(domain)")

            # General settings (e.g. default discord webhook)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.commit()

    def create_scan(self, target: str, domain: str, execution_mode: str, worker_ip: Optional[str] = None) -> str:
        """Creates a new scan record and returns unique scan_id."""
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO scans (
                    scan_id, target, domain, status, progress, current_stage,
                    created_at, execution_mode, worker_ip
                ) VALUES (?, ?, ?, 'RUNNING', 5, 'Stage 1: OSINT & Passive Recon', ?, ?, ?)
            """, (scan_id, target, domain, now, execution_mode, worker_ip))
            conn.commit()
        return scan_id

    def update_scan_progress(self, scan_id: str, progress: int, stage_name: str):
        """Updates progress percentage (0-100) and stage description."""
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE scans
                SET progress = ?, current_stage = ?
                WHERE scan_id = ?
            """, (progress, stage_name, scan_id))
            conn.commit()

    def complete_scan(self, scan_id: str, results: Dict[str, Any]):
        """Marks scan as COMPLETED and stores summary + full JSON payload."""
        now = datetime.now().isoformat()
        summary = results.get("summary", {})
        owasp = results.get("owasp_analysis", {})
        risk_score = owasp.get("exposure_score", 0)
        risk_grade = owasp.get("security_grade", "C")
        exec_mode = results.get("execution_mode")

        with self._get_connection() as conn:
            if exec_mode:
                conn.execute("""
                    UPDATE scans
                    SET status = 'COMPLETED', progress = 100, current_stage = 'Scan Completed',
                        completed_at = ?, risk_score = ?, risk_grade = ?, execution_mode = ?,
                        summary_json = ?, results_json = ?
                    WHERE scan_id = ?
                """, (
                    now,
                    risk_score,
                    risk_grade,
                    exec_mode,
                    json.dumps(summary, ensure_ascii=False, default=str),
                    json.dumps(results, ensure_ascii=False, default=str),
                    scan_id
                ))
            else:
                conn.execute("""
                    UPDATE scans
                    SET status = 'COMPLETED', progress = 100, current_stage = 'Scan Completed',
                        completed_at = ?, risk_score = ?, risk_grade = ?,
                        summary_json = ?, results_json = ?
                    WHERE scan_id = ?
                """, (
                    now,
                    risk_score,
                    risk_grade,
                    json.dumps(summary, ensure_ascii=False, default=str),
                    json.dumps(results, ensure_ascii=False, default=str),
                    scan_id
                ))
            conn.commit()

    def fail_scan(self, scan_id: str, error_message: str):
        """Marks scan as FAILED with error message."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE scans
                SET status = 'FAILED', current_stage = ?, completed_at = ?
                WHERE scan_id = ?
            """, (f"Error: {error_message}", now, scan_id))
            conn.commit()

    
    def save_scan_result(self, scan_id: str, target: str = None, domain: str = None, status: str = "COMPLETED", result_data: Dict[str, Any] = None, exposure_score: int = 0, security_grade: str = "C"):
        """Helper alias for complete_scan to ensure API compatibility."""
        self.complete_scan(scan_id, result_data or {})

    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Returns scan status, progress, and stage."""
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT scan_id, target, domain, status, progress, current_stage,
                       created_at, completed_at, risk_score, risk_grade, execution_mode
                FROM scans WHERE scan_id = ?
            """, (scan_id,))
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Returns the full scan results payload for a completed scan."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT results_json FROM scans WHERE scan_id = ?", (scan_id,))
            row = cur.fetchone()
            if not row or not row["results_json"]:
                return None
            return json.loads(row["results_json"])

    def list_history(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Lists scan history records for UI Dashboard."""
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT id, scan_id, target, domain, status, created_at, completed_at,
                       risk_score, risk_grade, execution_mode, summary_json
                FROM scans
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            history = []
            for r in rows:
                item = dict(r)
                if item.get("summary_json"):
                    try:
                        item["summary"] = json.loads(item["summary_json"])
                    except Exception:
                        item["summary"] = {}
                else:
                    item["summary"] = {}
                item.pop("summary_json", None)
                history.append(item)
            return history

    def delete_scan(self, scan_id: str) -> bool:
        """Deletes a scan record from database."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cur.rowcount > 0

    # =========================================================================
    # EASM: SCHEDULES & CONTINUOUS MONITORING
    # =========================================================================
    def create_schedule(
        self,
        target: str,
        domain: str,
        interval_hours: int = 24,
        use_kali: bool = True,
        worker_ip: str = "192.168.1.100:22",
        discord_webhook: str = ""
    ) -> str:
        """Registers a recurring recon schedule."""
        sched_id = f"sched_{uuid.uuid4().hex[:10]}"
        now = datetime.now()
        next_run = now.isoformat()  # Run immediately or on next tick
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO schedules (
                    schedule_id, target, domain, interval_hours, use_kali,
                    worker_ip, discord_webhook, enabled, next_run_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """, (
                sched_id, target, domain, interval_hours, 1 if use_kali else 0,
                worker_ip, discord_webhook, next_run, now.isoformat()
            ))
            conn.commit()
        return sched_id

    def list_schedules(self) -> List[Dict[str, Any]]:
        """Lists all active and paused schedules."""
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT id, schedule_id, target, domain, interval_hours, use_kali,
                       worker_ip, discord_webhook, enabled, last_run_at, next_run_at,
                       last_scan_id, created_at
                FROM schedules
                ORDER BY id DESC
            """)
            return [dict(r) for r in cur.fetchall()]

    def get_due_schedules(self) -> List[Dict[str, Any]]:
        """Finds schedules whose next_run_at is past or due now."""
        now_iso = datetime.now().isoformat()
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT id, schedule_id, target, domain, interval_hours, use_kali,
                       worker_ip, discord_webhook, enabled, last_run_at, next_run_at
                FROM schedules
                WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?)
            """, (now_iso,))
            return [dict(r) for r in cur.fetchall()]

    def update_schedule_after_run(self, schedule_id: str, scan_id: str, interval_hours: int):
        """Updates last_run_at and computes next_run_at."""
        now = datetime.now()
        from datetime import timedelta
        next_run = (now + timedelta(hours=interval_hours)).isoformat()
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE schedules
                SET last_run_at = ?, next_run_at = ?, last_scan_id = ?
                WHERE schedule_id = ?
            """, (now.isoformat(), next_run, scan_id, schedule_id))
            conn.commit()

    def toggle_schedule(self, schedule_id: str, enabled: bool) -> bool:
        """Enables or disables recurring execution for schedule."""
        with self._get_connection() as conn:
            cur = conn.execute("""
                UPDATE schedules SET enabled = ? WHERE schedule_id = ?
            """, (1 if enabled else 0, schedule_id))
            conn.commit()
            return cur.rowcount > 0

    def delete_schedule(self, schedule_id: str) -> bool:
        """Deletes a schedule record."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM schedules WHERE schedule_id = ?", (schedule_id,))
            conn.commit()
            return cur.rowcount > 0

    # =========================================================================
    # EASM: DIFFING & CHANGE DETECTION
    # =========================================================================
    def get_previous_completed_scan(self, domain: str, exclude_scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Returns the most recent completed scan result for comparison."""
        with self._get_connection() as conn:
            if exclude_scan_id:
                cur = conn.execute("""
                    SELECT scan_id, results_json, completed_at
                    FROM scans
                    WHERE domain = ? AND status = 'COMPLETED' AND scan_id != ? AND results_json IS NOT NULL
                    ORDER BY id DESC LIMIT 1
                """, (domain, exclude_scan_id))
            else:
                cur = conn.execute("""
                    SELECT scan_id, results_json, completed_at
                    FROM scans
                    WHERE domain = ? AND status = 'COMPLETED' AND results_json IS NOT NULL
                    ORDER BY id DESC LIMIT 1
                """, (domain,))
            row = cur.fetchone()
            if not row or not row["results_json"]:
                return None
            try:
                res = json.loads(row["results_json"])
                res["_scan_id"] = row["scan_id"]
                res["_completed_at"] = row["completed_at"]
                return res
            except Exception:
                return None

    def save_diff(self, domain: str, old_scan_id: str, new_scan_id: str, diff_payload: Dict[str, Any], alert_sent: bool = False):
        """Persists detected changes between two scan runs."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO diff_history (
                    domain, old_scan_id, new_scan_id, created_at, diff_json, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                domain, old_scan_id, new_scan_id, now,
                json.dumps(diff_payload, ensure_ascii=False), 1 if alert_sent else 0
            ))
            conn.commit()

    def list_diff_history(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Lists recent diff events for UI."""
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT id, domain, old_scan_id, new_scan_id, created_at, diff_json, alert_sent
                FROM diff_history
                ORDER BY id DESC LIMIT ?
            """, (limit,))
            rows = []
            for r in cur.fetchall():
                item = dict(r)
                try:
                    item["diff"] = json.loads(item["diff_json"])
                except Exception:
                    item["diff"] = {}
                item.pop("diff_json", None)
                rows.append(item)
            return rows

    # =========================================================================
    # SETTINGS (Discord Webhook, API keys, etc.)
    # =========================================================================
    def get_setting(self, key: str, default: Any = "") -> str:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cur.fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (key, value))
            conn.commit()


# Singleton instance
db_manager = DatabaseManager()
