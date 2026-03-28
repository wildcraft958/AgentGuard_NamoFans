"""
AgentGuard – SQLite Audit Log (agentguard.observability.audit).

Persistent, queryable record of every Guardian decision.
Extended with a `layer` column to match AgentGuard's layered architecture.

Usage:
    from agentguard.observability.audit import AuditLog

    log = AuditLog("~/.agentguard/audit.db")
    log.record("validate_input", "l1_input", is_safe=False, reason="Injection detected")
    print(log.recent(10))
    print(log.blocked_count())
    print(f"24h pass rate: {log.pass_rate():.0%}")
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    """
    SQLite-backed audit log for AgentGuard Guardian decisions.

    Schema:
        id       INTEGER PRIMARY KEY AUTOINCREMENT
        ts       TEXT    ISO-8601 timestamp (UTC)
        action   TEXT    e.g. 'validate_input', 'validate_output', 'validate_tool_call'
        layer    TEXT    e.g. 'l1_input', 'l2_output', 'tool_firewall'
        safe     INTEGER 1 = allowed, 0 = blocked
        reason   TEXT    human-readable block reason (NULL if safe)
        metadata TEXT    JSON: blocked_by, params_hash, etc.
    """

    _CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS audit_log (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        ts                TEXT    NOT NULL,
        action            TEXT    NOT NULL,
        layer             TEXT,
        safe              INTEGER NOT NULL,
        reason            TEXT,
        metadata          TEXT,
        l4_rbac_decision  TEXT    DEFAULT '',
        l4_signals        TEXT    DEFAULT '[]',
        l4_composite      REAL    DEFAULT 0.0,
        l4_action         TEXT    DEFAULT ''
    )
    """

    _CREATE_IDX_TS = "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)"
    _CREATE_IDX_ACTION = "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)"

    def __init__(self, db_path: str | Path | None = None):
        """
        Initialize the audit log.

        Args:
            db_path: Path to the SQLite database file.
                     Defaults to ~/.agentguard/audit.db.
                     Pass ':memory:' for an in-memory database (useful in tests).
        """
        if db_path is None:
            db_path = Path.home() / ".agentguard" / "audit.db"

        self._db_path = Path(db_path).expanduser()

        if str(self._db_path) != ":memory:":
            self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist, migrate L4 columns if missing."""
        with self._conn:
            self._conn.execute(self._CREATE_TABLE)
            self._conn.execute(self._CREATE_IDX_TS)
            self._conn.execute(self._CREATE_IDX_ACTION)
            # Migrate: add L4 columns to existing databases that pre-date this schema
            existing = {
                row[1] for row in self._conn.execute("PRAGMA table_info(audit_log)").fetchall()
            }
            migrations = [
                ("l4_rbac_decision", "TEXT DEFAULT ''"),
                ("l4_signals", "TEXT DEFAULT '[]'"),
                ("l4_composite", "REAL DEFAULT 0.0"),
                ("l4_action", "TEXT DEFAULT ''"),
            ]
            for col, col_def in migrations:
                if col not in existing:
                    self._conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col} {col_def}")

    def record(
        self,
        action: str,
        layer: str,
        is_safe: bool,
        reason: str | None = None,
        metadata: dict | None = None,
        l4_rbac_decision: str = "",
        l4_signals: str = "[]",
        l4_composite: float = 0.0,
        l4_action: str = "",
    ) -> int:
        """
        Insert one audit row.

        Args:
            action:           High-level action name.
            layer:            Security layer (l1_input, l2_output, tool_firewall, etc.)
            is_safe:          True if allowed, False if blocked.
            reason:           Human-readable block reason.
            metadata:         Optional dict for extra context.
            l4_rbac_decision: ALLOW | DENY | ELEVATE from L4a RBAC engine.
            l4_signals:       JSON list of L4b anomaly signals.
            l4_composite:     L4b composite anomaly score (0.0–1.0).
            l4_action:        L4b action: ALLOW | WARN | ELEVATE | BLOCK.

        Returns:
            Row id of the inserted record.
        """
        ts = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata) if metadata else None

        cursor = self._conn.execute(
            "INSERT INTO audit_log "
            "(ts, action, layer, safe, reason, metadata, "
            " l4_rbac_decision, l4_signals, l4_composite, l4_action) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ts,
                action,
                layer,
                int(is_safe),
                reason,
                meta_json,
                l4_rbac_decision,
                l4_signals,
                l4_composite,
                l4_action,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid

    def recent(self, limit: int = 50) -> list[dict]:
        """
        Return the most recent audit records.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of dicts, newest first.
        """
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def blocked_count(self, action: str | None = None) -> int:
        """
        Count blocked (is_safe=False) records.

        Args:
            action: Optional filter by action name.

        Returns:
            Count of blocked records.
        """
        if action:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE safe = 0 AND action = ?", (action,)
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM audit_log WHERE safe = 0").fetchone()
        return row[0]

    def pass_rate(self, since_hours: int = 24) -> float:
        """
        Calculate the pass rate (safe / total) over the last N hours.

        Args:
            since_hours: Look-back window in hours.

        Returns:
            Float between 0.0 and 1.0. Returns 1.0 if no records exist.
        """
        from datetime import timedelta

        since_ts = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        since_str = since_ts.isoformat()

        row = self._conn.execute(
            "SELECT COUNT(*), SUM(safe) FROM audit_log WHERE ts >= ?", (since_str,)
        ).fetchone()

        total, safe_count = row[0], row[1] or 0
        if total == 0:
            return 1.0
        return safe_count / total

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def hash_params(params: dict) -> str:
    """SHA-256 hash of a params dict for deduplication / privacy."""
    serialized = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]
