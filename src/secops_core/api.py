import os
import sqlite3
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query

from secops_core import db, llm, pipeline
from secops_core.alert import Alert
from secops_core.explain import explain
from secops_core.parser import LogEvent, LogParseError, load_jsonl

app = FastAPI(title="SecOps Assistido")

Limit = Annotated[int, Query(ge=1, le=5000)]


def get_conn() -> Iterator[sqlite3.Connection]:
    conn = db.connect()
    try:
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/logs")
def logs(
    conn: Conn,
    user: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: Limit = 1000,
) -> list[LogEvent]:
    return db.get_logs(conn, user.lower() if user else None, start, end, limit)


@app.get("/alerts")
def alerts(
    conn: Conn,
    severity: Literal["low", "medium", "high"] | None = None,
    detector: Literal["rules", "zscore", "iforest"] | None = None,
    limit: Limit = 1000,
) -> list[Alert]:
    return db.get_alerts(conn, severity, detector, limit)


def _alert_or_404(conn: sqlite3.Connection, alert_id: int) -> Alert:
    alert = db.get_alert(conn, alert_id)
    if alert is None:
        raise HTTPException(404, f"alerta {alert_id} não existe")
    return alert


@app.get("/alerts/{alert_id}")
def alert(alert_id: int, conn: Conn) -> Alert:
    return _alert_or_404(conn, alert_id)


@app.get("/alerts/{alert_id}/explanation")
def explanation(alert_id: int, conn: Conn, ai: bool = False) -> dict:
    """Explicação do alerta. O template responde na hora; `ai=true` pede também o resumo do
    modelo local, que leva de 20 a 90 s e cai no template se o Ollama não responder."""
    found = _alert_or_404(conn, alert_id)
    if not ai:
        return {"id": alert_id, "explanation": found.explanation or explain(found), "ai": False}
    text = llm.enhance(conn, alert_id)
    return {"id": alert_id, "explanation": text, "ai": llm.MARKER in text}


@app.get("/metrics")
def metrics(conn: Conn) -> dict:
    return db.metrics(conn)


@app.post("/run")
def run(conn: Conn) -> dict[str, int]:
    """Lê data/logs_simulados.jsonl, roda os detectores e substitui os alertas."""
    path = Path(os.environ.get("SECOPS_DATA_DIR", "data")) / "logs_simulados.jsonl"
    if not path.exists():
        raise HTTPException(404, f"{path} não existe; rode `make generate`")
    try:
        events = load_jsonl(path)
    except LogParseError as exc:
        raise HTTPException(422, str(exc)) from exc
    return pipeline.run(conn, events)


# Demonstração do hot reload: tire o "# " das linhas abaixo, salve e abra /ola
# @app.get("/ola")
# def ola() -> dict[str, str]:
#     return {"mensagem": "ola, turma"}
