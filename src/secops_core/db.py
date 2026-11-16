import os
import sqlite3
from datetime import datetime
from pathlib import Path

from secops_core.alert import Alert
from secops_core.parser import LogEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    user TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    action TEXT NOT NULL,
    success INTEGER NOT NULL,
    is_anomaly INTEGER NOT NULL,
    UNIQUE (timestamp, user, source_ip, action)
);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    detector TEXT NOT NULL,
    severity TEXT NOT NULL,
    user TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    description TEXT NOT NULL,
    rule TEXT,
    score REAL,
    explanation TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
"""


def default_path() -> Path:
    return Path(os.environ.get("SECOPS_DATA_DIR", "data")) / "secops.db"


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Abre (e cria, se preciso) o banco. Use ':memory:' nos testes."""
    path = str(path or default_path())
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    if "rule" not in {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}:
        conn.execute("ALTER TABLE alerts ADD COLUMN rule TEXT")  # banco criado antes da coluna
    return conn


def insert_logs(conn: sqlite3.Connection, events: list[LogEvent]) -> int:
    """Grava os eventos, ignorando duplicados. Devolve quantos eram novos."""
    before = conn.total_changes
    with conn:
        conn.executemany(
            "INSERT OR IGNORE INTO logs (timestamp, user, source_ip, action, success, is_anomaly)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [
                (e.timestamp.isoformat(), e.user, e.source_ip, e.action, e.success, e.is_anomaly)
                for e in events
            ],
        )
    return conn.total_changes - before


def get_logs(
    conn: sqlite3.Connection, user: str | None = None, limit: int = 1000
) -> list[LogEvent]:
    sql, args = "SELECT * FROM logs", []
    if user:
        sql, args = sql + " WHERE user = ?", [user]
    rows = conn.execute(sql + " ORDER BY timestamp LIMIT ?", [*args, limit])
    return [
        LogEvent(
            datetime.fromisoformat(r["timestamp"]),
            r["user"],
            r["source_ip"],
            r["action"],
            bool(r["success"]),
            bool(r["is_anomaly"]),
        )
        for r in rows
    ]


def insert_alerts(conn: sqlite3.Connection, alerts: list[Alert]) -> None:
    with conn:
        conn.executemany(
            "INSERT INTO alerts (detector, severity, user, timestamp, description, score,"
            " explanation, rule) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    a.detector,
                    a.severity,
                    a.user,
                    a.timestamp.isoformat(),
                    a.description,
                    a.score,
                    a.explanation,
                    a.rule,
                )
                for a in alerts
            ],
        )


def _alert(row: sqlite3.Row) -> Alert:
    return Alert(
        detector=row["detector"],
        severity=row["severity"],
        user=row["user"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        description=row["description"],
        score=row["score"],
        explanation=row["explanation"],
        rule=row["rule"],
        id=row["id"],
    )


def get_alerts(
    conn: sqlite3.Connection,
    severity: str | None = None,
    detector: str | None = None,
    limit: int = 1000,
) -> list[Alert]:
    filters = {"severity": severity, "detector": detector}
    where = [f"{col} = ?" for col, value in filters.items() if value]
    sql = "SELECT * FROM alerts" + (f" WHERE {' AND '.join(where)}" if where else "")
    args = [value for value in filters.values() if value]
    return [
        _alert(r) for r in conn.execute(sql + " ORDER BY timestamp, id LIMIT ?", [*args, limit])
    ]


def get_alert(conn: sqlite3.Connection, alert_id: int) -> Alert | None:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", [alert_id]).fetchone()
    return _alert(row) if row else None


def set_explanation(conn: sqlite3.Connection, alert_id: int, explanation: str) -> None:
    with conn:
        conn.execute("UPDATE alerts SET explanation = ? WHERE id = ?", [explanation, alert_id])


def clear_alerts(conn: sqlite3.Connection) -> None:
    """Apaga os alertas, para o pipeline poder reprocessar sem duplicar."""
    with conn:
        conn.execute("DELETE FROM alerts")
