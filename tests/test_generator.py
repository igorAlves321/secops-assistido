import json

from secops_core.generator import generate, main


def test_generate_is_reproducible():
    assert generate(100, seed=1) == generate(100, seed=1)


def test_generate_labels_anomalies_and_sorts():
    logs = generate(200, seed=1)

    assert sum(not log["is_anomaly"] for log in logs) == 200
    assert 0 < sum(log["is_anomaly"] for log in logs) < 200
    assert [log["timestamp"] for log in logs] == sorted(log["timestamp"] for log in logs)


def test_main_writes_jsonl(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPS_DATA_DIR", str(tmp_path))

    main(["--events", "50"])

    lines = (tmp_path / "logs_simulados.jsonl").read_text().splitlines()
    assert len(lines) > 50
    assert {"timestamp", "user", "source_ip", "action", "success", "is_anomaly"} == set(
        json.loads(lines[0])
    )
