import os
import sqlite3
from datetime import UTC, datetime
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
    conn = sqlite3.connect(path, check_same_thread=False)  # uma conexão por requisição da API
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    if "rule" not in {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}:
        conn.execute("ALTER TABLE alerts ADD COLUMN rule TEXT")  # banco criado antes da coluna
    return conn


def _utc(when: datetime | None) -> str | None:
    """Horários ficam no banco sempre em UTC, para a comparação de texto bater com a de datas."""
    return when.astimezone(UTC).isoformat() if when else None


def insert_logs(conn: sqlite3.Connection, events: list[LogEvent]) -> int:
    """Grava os eventos, ignorando duplicados. Devolve quantos eram novos."""
    before = conn.total_changes
    with conn:
        conn.executemany(
            "INSERT OR IGNORE INTO logs (timestamp, user, source_ip, action, success, is_anomaly)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [
                (_utc(e.timestamp), e.user, e.source_ip, e.action, e.success, e.is_anomaly)
                for e in events
            ],
        )
    return conn.total_changes - before


def get_logs(
    conn: sqlite3.Connection,
    user: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = 1000,
) -> list[LogEvent]:
    """Logs em ordem de horário; `start` é inclusivo e `end` exclusivo."""
    filters = {"user = ?": user, "timestamp >= ?": _utc(start), "timestamp < ?": _utc(end)}
    where = [clause for clause, value in filters.items() if value]
    sql = "SELECT * FROM logs" + (f" WHERE {' AND '.join(where)}" if where else "")
    args = [value for value in filters.values() if value]
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
                    _utc(a.timestamp),
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


def _count_by(conn: sqlite3.Connection, table: str, column: str) -> dict[str, int]:
    rows = conn.execute(
        f"SELECT {column}, COUNT(*) n FROM {table} GROUP BY {column} ORDER BY n DESC"
    )
    return {row[column]: row["n"] for row in rows}


def metrics(conn: sqlite3.Connection) -> dict:
    """Números para o painel: totais e quebras dos alertas por gravidade, detector e usuário."""
    return {
        "logs": conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "alerts_by_severity": _count_by(conn, "alerts", "severity"),
        "alerts_by_detector": _count_by(conn, "alerts", "detector"),
        "alerts_by_user": _count_by(conn, "alerts", "user"),
    }
