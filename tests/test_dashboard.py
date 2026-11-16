import io
import json
import re
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest
from streamlit.testing.v1 import AppTest

DASHBOARD = str(Path(__file__).parents[1] / "src/secops_core/dashboard.py")

ALERTS = [
    {"id": 1, "detector": "rules", "severity": "high", "user": "diego", "rule": "login_falho",
     "timestamp": "2026-01-07T17:00:00+00:00", "description": "20 logins falhos de diego",
     "score": 20.0, "explanation": None},
    {"id": 2, "detector": "iforest", "severity": "medium", "user": "alice", "rule": "atipico",
     "timestamp": "2026-01-06T10:00:00+00:00", "description": "1 evento atípico de alice",
     "score": 0.6, "explanation": None},
]  # fmt: skip
LOGS = [
    {"timestamp": f"2026-01-07T{h:02d}:00:00+00:00", "user": "diego", "source_ip": "10.0.1.14",
     "action": "GetObject", "success": True, "is_anomaly": False}
    for h in range(9, 18)
]  # fmt: skip
METRICS = {
    "logs": 9, "alerts": 2,
    "alerts_by_severity": {"high": 1, "medium": 1},
    "alerts_by_detector": {"rules": 1, "iforest": 1},
    "alerts_by_user": {"diego": 1, "alice": 1},
}  # fmt: skip


def explanation(at):
    """Texto da explicação na tela (o fake da API devolve 'Explicação do alerta N')."""
    [found] = [
        m.value for m in at.markdown if re.fullmatch(r"Explicação do alerta \d+( \+ IA)?", m.value)
    ]
    return found


class FakeApi:
    """Responde no lugar da API e guarda o que foi pedido."""

    def __init__(self, metrics=METRICS, down=False, ai=False, run_error=None):
        self.metrics, self.down, self.ai, self.run_error = metrics, down, ai, run_error
        self.requests = []

    def __call__(self, request, timeout=None):
        if self.down:
            raise URLError("fora do ar")
        path, method = request.full_url.split("8080", 1)[1], request.get_method()
        self.requests.append((method, path))
        route = path.split("?")[0]
        if route == "/health":
            body = {"status": "ok"}
        elif route == "/metrics":
            body = self.metrics
        elif route == "/logs":
            body = LOGS
        elif route == "/alerts":
            body = ALERTS
        elif route == "/run" and self.run_error:
            raise HTTPError(
                request.full_url,
                422,
                "x",
                {},
                io.BytesIO(json.dumps({"detail": self.run_error}).encode()),
            )
        elif route == "/run":
            body = {"logs": 9, "novos": 9, "alertas_brutos": 3, "alertas": 2}
        else:  # /alerts/{id}/explanation
            alert_id = int(route.split("/")[2])
            text = f"Explicação do alerta {alert_id}"
            body = {"id": alert_id, "explanation": text, "ai": False}
            if "ai=True" in path:
                body = {
                    "id": alert_id,
                    "explanation": text + (" + IA" if self.ai else ""),
                    "ai": self.ai,
                }
        return io.BytesIO(json.dumps(body).encode())


@pytest.fixture
def app(monkeypatch):
    def start(**kwargs):
        api = FakeApi(**kwargs)
        monkeypatch.setattr("urllib.request.urlopen", api)
        monkeypatch.setenv("SECOPS_API_URL", "http://api:8080")
        at = AppTest.from_file(DASHBOARD, default_timeout=30).run()
        return at, api

    return start


def test_shows_error_when_api_is_down(app):
    at, _ = app(down=True)

    assert [e.value for e in at.error] == ["API indisponível"]
    assert not at.exception


def test_shows_hint_when_there_is_no_data(app):
    at, _ = app(metrics={**METRICS, "logs": 0})

    assert "make generate" in at.info[0].value
    assert not at.exception


def test_shows_kpis_and_charts(app):
    at, _ = app()

    assert not at.exception
    assert {m.label: m.value for m in at.metric} == {
        "Logs analisados": "9", "Alertas": "2", "Alertas altos": "1", "Usuários com alerta": "2",
    }  # fmt: skip


def test_shows_template_explanation_of_the_first_alert_by_time(app):
    at, api = app()

    assert at.selectbox[1].value == 2  # ordenado por horário: o da alice (06/01) vem antes
    assert explanation(at) == "Explicação do alerta 2"
    assert ("GET", "/alerts/2/explanation") in api.requests


def test_selecting_another_alert_changes_the_explanation(app):
    at, _ = app()

    at.selectbox[1].select(1).run()

    assert explanation(at) == "Explicação do alerta 1"


def test_filters_narrow_the_alerts(app):
    at, _ = app()

    at.checkbox(key="sev-medium").uncheck().run()

    assert at.selectbox[1].options == ["Nº 1 · alta · diego · 07/01/2026 17:00"]
    at.checkbox(key="sev-high").uncheck().run()
    assert "Nenhum alerta" in at.info[0].value


def test_user_filter_narrows_the_alerts(app):
    at, _ = app()

    at.selectbox[0].select("alice").run()

    assert at.selectbox[1].options == ["Nº 2 · média · alice · 06/01/2026 10:00"]


def test_ai_button_shows_model_summary(app):
    at, api = app(ai=True)

    at.button(key="ai").click().run()

    assert explanation(at).endswith("+ IA")
    assert not at.warning
    assert any("ai=True" in path for _, path in api.requests)


def test_ai_button_warns_when_model_is_off(app):
    at, _ = app(ai=False)

    at.button(key="ai").click().run()

    assert "make llm" in at.warning[0].value
    assert explanation(at) == "Explicação do alerta 2"  # o template continua na tela


def test_run_button_posts_and_reports(app):
    at, api = app()

    at.sidebar.button(key="run").click().run()

    assert ("POST", "/run") in api.requests
    assert at.sidebar.success[0].value == "2 alertas em 9 logs"


def test_run_button_shows_api_error_detail(app):
    at, _ = app(run_error="linha 3: campo ausente")

    at.sidebar.button(key="run").click().run()

    assert at.sidebar.error[0].value == "linha 3: campo ausente"
