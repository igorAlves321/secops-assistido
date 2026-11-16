import os
import sqlite3
from collections import defaultdict
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from secops_core import db
from secops_core.alert import Alert
from secops_core.detectors import iforest, rules, zscore
from secops_core.explain import explain
from secops_core.parser import LogEvent, load_jsonl

DETECTORS = [rules, zscore, iforest]
SEVERITY = {"low": 0, "medium": 1, "high": 2}
TRUST = {"rules": 2, "iforest": 1, "zscore": 0}  # desempate: regra explícita vale mais
WINDOW = timedelta(minutes=5)
SPAN = {"zscore": timedelta(hours=1)}  # o alerta do Z-Score cobre a hora inteira


def _end(alert: Alert):
    return alert.timestamp + SPAN.get(alert.detector, WINDOW)


def merge(alerts: list[Alert]) -> list[Alert]:
    """Junta alertas do mesmo usuário cujas janelas se sobrepõem. Fica o mais grave,
    com a lista de quem mais o confirmou na descrição."""
    by_user = defaultdict(list)
    for alert in alerts:
        by_user[alert.user].append(alert)

    merged = []
    for group in by_user.values():
        group.sort(key=lambda a: a.timestamp)
        cluster, end = [group[0]], _end(group[0])
        for alert in [*group[1:], None]:  # None fecha o último grupo
            if alert and alert.timestamp < end:
                cluster.append(alert)
                end = max(end, _end(alert))
                continue
            merged.append(_pick(cluster))
            cluster, end = ([alert], _end(alert)) if alert else ([], None)
    return sorted(merged, key=lambda a: (a.timestamp, a.user))


def _pick(cluster: list[Alert]) -> Alert:
    best = max(cluster, key=lambda a: (SEVERITY[a.severity], TRUST[a.detector]))
    others = sorted({a.detector for a in cluster if a is not best} - {best.detector})
    if others:
        best = replace(best, description=f"{best.description} (também: {', '.join(others)})")
    return best


def run(conn: sqlite3.Connection, events: list[LogEvent]) -> dict[str, int]:
    """Grava os logs, roda os detectores e substitui os alertas do banco."""
    new_logs = db.insert_logs(conn, events)
    raw = [alert for detector in DETECTORS for alert in detector.detect(events)]
    alerts = merge(raw)
    db.clear_alerts(conn)
    db.insert_alerts(conn, alerts)
    for saved in db.get_alerts(conn):
        db.set_explanation(conn, saved.id, explain(saved))
    return {
        "logs": len(events),
        "novos": new_logs,
        "alertas_brutos": len(raw),
        "alertas": len(alerts),
    }


def main() -> None:
    path = Path(os.environ.get("SECOPS_DATA_DIR", "data")) / "logs_simulados.jsonl"
    conn = db.connect()
    print(run(conn, load_jsonl(path)))


if __name__ == "__main__":
    main()
