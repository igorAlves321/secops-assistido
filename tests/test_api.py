import pytest
from fastapi.testclient import TestClient

from secops_core import generator, llm
from secops_core.api import app


def test_health():
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("OLLAMA_URL", raising=False)  # nenhum teste fala com o Ollama de verdade
    return TestClient(app)


@pytest.fixture
def loaded(client):
    generator.main(["--events", "300"])
    assert client.post("/run").status_code == 200
    return client


def test_endpoints_are_empty_before_the_first_run(client):
    assert client.get("/alerts").json() == []
    assert client.get("/logs").json() == []
    assert client.get("/metrics").json()["alerts"] == 0


def test_run_without_logs_file_is_404(client):
    response = client.post("/run")

    assert response.status_code == 404
    assert "make generate" in response.json()["detail"]


def test_run_with_corrupt_file_is_422(client, tmp_path):
    (tmp_path / "logs_simulados.jsonl").write_text("{ruim\n")

    response = client.post("/run")

    assert response.status_code == 422
    assert "linha 1" in response.json()["detail"]


def test_run_fills_logs_alerts_and_metrics(loaded):
    metrics = loaded.get("/metrics").json()

    assert metrics["logs"] == len(loaded.get("/logs", params={"limit": 5000}).json()) > 300
    assert metrics["alerts"] == len(loaded.get("/alerts").json()) > 0
    assert metrics["alerts_by_severity"]["high"] == 4
    assert sum(metrics["alerts_by_user"].values()) == metrics["alerts"]


def test_run_twice_keeps_the_same_alerts(loaded):
    before = loaded.get("/metrics").json()

    assert loaded.post("/run").json()["novos"] == 0
    assert loaded.get("/metrics").json() == before


def test_alerts_filters_and_validation(loaded):
    high = loaded.get("/alerts", params={"severity": "high"}).json()

    assert high and {a["severity"] for a in high} == {"high"}
    assert {a["detector"] for a in loaded.get("/alerts", params={"detector": "rules"}).json()} == {
        "rules"
    }
    assert loaded.get("/alerts", params={"severity": "critico"}).status_code == 422
    assert loaded.get("/alerts", params={"limit": 0}).status_code == 422
    assert len(loaded.get("/alerts", params={"limit": 2}).json()) == 2


def test_logs_filters_by_user_case_insensitive_and_time(loaded):
    rows = loaded.get("/logs", params={"user": "ALICE", "limit": 5000}).json()

    assert rows and {r["user"] for r in rows} == {"alice"}
    start = rows[10]["timestamp"]
    later = loaded.get("/logs", params={"user": "alice", "start": start, "limit": 5000}).json()
    assert later[0]["timestamp"] == start and len(later) < len(rows)


def test_alerts_pagination_and_extra_filters(loaded):
    everything = loaded.get("/alerts").json()

    page = loaded.get("/alerts", params={"limit": 2, "offset": 1}).json()
    assert page == everything[1:3]
    assert loaded.get("/alerts", params={"offset": -1}).status_code == 422

    first = everything[0]
    mine = loaded.get("/alerts", params={"user": first["user"].upper()}).json()
    assert mine and {a["user"] for a in mine} == {first["user"]}
    by_rule = loaded.get("/alerts", params={"rule": "login_falho"}).json()
    assert by_rule and {a["rule"] for a in by_rule} == {"login_falho"}


def test_logs_pagination_and_action_filter(loaded):
    everything = loaded.get("/logs", params={"limit": 5000}).json()

    page = loaded.get("/logs", params={"limit": 3, "offset": 2}).json()
    assert page == everything[2:5]
    stops = loaded.get("/logs", params={"action": "StopLogging"}).json()
    assert stops and {r["action"] for r in stops} == {"StopLogging"}


def test_alert_by_id_and_404(loaded):
    first = loaded.get("/alerts").json()[0]

    assert loaded.get(f"/alerts/{first['id']}").json() == first
    assert loaded.get("/alerts/99999").status_code == 404
    assert loaded.get("/alerts/abc").status_code == 422


def test_explanation_defaults_to_template(loaded):
    first = loaded.get("/alerts", params={"severity": "high"}).json()[0]

    body = loaded.get(f"/alerts/{first['id']}/explanation").json()

    assert body["ai"] is False
    assert "O que fazer:" in body["explanation"]


def test_explanation_ai_falls_back_when_ollama_is_off(loaded):
    first = loaded.get("/alerts").json()[0]

    body = loaded.get(f"/alerts/{first['id']}/explanation", params={"ai": True}).json()

    assert body["ai"] is False
    assert "O que fazer:" in body["explanation"]


def test_explanation_ai_uses_the_model_when_it_answers(loaded, monkeypatch):
    monkeypatch.setattr(llm, "ask_ollama", lambda prompt: "resumo falso")
    first = loaded.get("/alerts").json()[0]

    body = loaded.get(f"/alerts/{first['id']}/explanation", params={"ai": True}).json()

    assert body["ai"] is True
    assert body["explanation"].endswith("resumo falso")


def test_explanation_of_unknown_alert_is_404(loaded):
    assert loaded.get("/alerts/99999/explanation").status_code == 404
