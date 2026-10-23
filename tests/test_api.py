from fastapi.testclient import TestClient

from secops_core.api import app


def test_health():
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
