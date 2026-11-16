"""Ponta a ponta: gerador -> JSONL -> parser -> detectores -> SQLite -> API.

ATENÇÃO: os dados são sintéticos e o gerador planta justamente os padrões que as regras conhecem
(rajada de logins falhos e ações sensíveis). Estes números provam que o pipeline funciona de
ponta a ponta, não que ele detecta ataques reais.
"""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from secops_core import db, generator, pipeline
from secops_core.api import app
from secops_core.parser import parse_event


def covers(alert, event):
    return (
        alert.user == event.user
        and alert.timestamp <= event.timestamp < alert.timestamp + timedelta(hours=1)
    )


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_pipeline_finds_every_planted_anomaly_without_false_high_alerts(seed):
    events = [parse_event(raw) for raw in generator.generate(1000, seed=seed)]
    conn = db.connect(":memory:")

    pipeline.run(conn, events)

    alerts = db.get_alerts(conn)
    anomalies = [e for e in events if e.is_anomaly]
    high = [a for a in alerts if a.severity == "high"]
    assert all(any(covers(a, e) for a in alerts) for e in anomalies)  # recall de 100%
    assert high and all(any(covers(a, e) for e in anomalies) for a in high)  # precisão dos "high"
    assert len(alerts) <= 15  # o ruído (medium) fica limitado


def test_full_flow_through_the_api(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    client = TestClient(app)

    generator.main(["--events", "500"])
    summary = client.post("/run").json()
    high = client.get("/alerts", params={"severity": "high"}).json()
    explanation = client.get(f"/alerts/{high[0]['id']}/explanation").json()

    assert summary["logs"] > 500 and summary["alertas"] >= 4
    assert {a["rule"] for a in high} == {"adulteracao_log", "escalada_privilegio", "login_falho"}
    assert explanation["ai"] is False and "O que fazer:" in explanation["explanation"]
    assert client.get("/metrics").json()["alerts_by_severity"]["high"] == len(high)
