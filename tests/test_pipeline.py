from datetime import UTC, datetime, timedelta

import pytest

from secops_core import db, pipeline
from secops_core.alert import Alert
from secops_core.generator import generate, main
from secops_core.parser import load_jsonl, parse_event

T0 = datetime(2026, 1, 5, 10, 0, tzinfo=UTC)


def alert(detector, severity="medium", user="alice", minutes=0, description="x"):
    return Alert(detector, severity, user, T0 + timedelta(minutes=minutes), description)


def test_overlapping_alerts_of_same_user_become_one():
    [result] = pipeline.merge(
        [
            alert("zscore", minutes=-30),
            alert("rules", "high", minutes=0),
            alert("iforest", minutes=2),
        ]
    )

    assert result.detector == "rules"
    assert result.severity == "high"
    assert "iforest" in result.description and "zscore" in result.description


def test_most_severe_wins_then_most_trusted():
    [result] = pipeline.merge([alert("iforest", "medium"), alert("rules", "medium")])

    assert result.detector == "rules"


def test_different_users_stay_separate():
    assert len(pipeline.merge([alert("rules", user="alice"), alert("rules", user="bruno")])) == 2


def test_distant_alerts_stay_separate():
    assert len(pipeline.merge([alert("rules", minutes=0), alert("rules", minutes=30)])) == 2


def test_zscore_covers_its_whole_hour():
    zs = alert("zscore", minutes=-10)  # hora cheia: cobre até 10h50

    assert len(pipeline.merge([zs, alert("rules", minutes=40)])) == 1
    assert len(pipeline.merge([zs, alert("rules", minutes=55)])) == 2


def test_merge_of_nothing():
    assert pipeline.merge([]) == []


@pytest.fixture
def events():
    return [parse_event(raw) for raw in generate(1000, seed=42)]


def test_run_stores_logs_and_alerts(events):
    conn = db.connect(":memory:")

    summary = pipeline.run(conn, events)

    assert summary["logs"] == len(events)
    assert summary["alertas"] == len(db.get_alerts(conn)) < summary["alertas_brutos"]
    assert len(db.get_logs(conn, limit=10_000)) == summary["novos"]


def test_run_twice_does_not_duplicate(events):
    conn = db.connect(":memory:")
    first = pipeline.run(conn, events)

    second = pipeline.run(conn, events)

    assert second["novos"] == 0
    assert second["alertas"] == first["alertas"] == len(db.get_alerts(conn))


def test_every_generated_anomaly_is_covered(events):
    conn = db.connect(":memory:")
    pipeline.run(conn, events)
    alerts = db.get_alerts(conn)

    for e in (e for e in events if e.is_anomaly):
        assert any(
            a.user == e.user and a.timestamp <= e.timestamp < a.timestamp + timedelta(hours=1)
            for a in alerts
        )


def test_main_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SECOPS_DATA_DIR", str(tmp_path))
    main(["--events", "200"])

    pipeline.main()

    assert "alertas" in capsys.readouterr().out
    assert (tmp_path / "secops.db").exists()
    assert load_jsonl(tmp_path / "logs_simulados.jsonl")
