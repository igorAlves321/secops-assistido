from datetime import UTC, datetime, timedelta, timezone

import pytest

from secops_core import db
from secops_core.alert import Alert
from secops_core.parser import LogEvent

WHEN = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)


@pytest.fixture
def conn():
    return db.connect(":memory:")


def event(user="alice", action="GetObject", minute=0, anomaly=False):
    return LogEvent(WHEN.replace(minute=minute), user, "10.0.1.11", action, True, anomaly)


def alert(detector="rules", severity="high", user="alice"):
    return Alert(detector, severity, user, WHEN, "login suspeito", score=0.9)


def test_logs_roundtrip(conn):
    events = [event(minute=1), event(minute=2, anomaly=True)]

    assert db.insert_logs(conn, events) == 2
    assert db.get_logs(conn) == events


def test_insert_logs_ignores_duplicates(conn):
    db.insert_logs(conn, [event()])

    assert db.insert_logs(conn, [event(), event(minute=5)]) == 1
    assert len(db.get_logs(conn)) == 2


def test_get_logs_filters_by_user_and_limit(conn):
    db.insert_logs(conn, [event("alice", minute=1), event("bruno", minute=2), event("bruno")])

    assert {e.user for e in db.get_logs(conn, user="bruno")} == {"bruno"}
    assert len(db.get_logs(conn, limit=1)) == 1


def test_get_logs_filters_by_time_range(conn):
    db.insert_logs(conn, [event(minute=m) for m in (0, 10, 20, 30)])

    got = db.get_logs(conn, start=WHEN.replace(minute=10), end=WHEN.replace(minute=30))

    assert [e.timestamp.minute for e in got] == [10, 20]  # início inclusivo, fim exclusivo


def test_timestamps_are_stored_in_utc(conn):
    brt = datetime(2026, 1, 5, 6, 0, tzinfo=timezone(timedelta(hours=-3)))  # 09:00 UTC
    db.insert_logs(conn, [LogEvent(brt, "alice", "10.0.1.11", "GetObject", True)])

    [got] = db.get_logs(conn, start=WHEN, end=WHEN + timedelta(minutes=1))

    assert got.timestamp == brt


def test_alerts_roundtrip_gets_id(conn):
    db.insert_alerts(conn, [alert()])

    [saved] = db.get_alerts(conn)
    assert saved.id is not None
    assert saved == Alert("rules", "high", "alice", WHEN, "login suspeito", 0.9, id=saved.id)


def test_get_alerts_filters(conn):
    db.insert_alerts(
        conn, [alert("rules", "high"), alert("zscore", "low"), alert("zscore", "high")]
    )

    assert len(db.get_alerts(conn, severity="high")) == 2
    assert len(db.get_alerts(conn, detector="zscore")) == 2
    assert len(db.get_alerts(conn, severity="high", detector="zscore")) == 1


def test_get_alert_and_set_explanation(conn):
    db.insert_alerts(conn, [alert()])
    [saved] = db.get_alerts(conn)

    db.set_explanation(conn, saved.id, "Muitas falhas de login.")

    assert db.get_alert(conn, saved.id).explanation == "Muitas falhas de login."
    assert db.get_alert(conn, 999) is None


def test_clear_alerts(conn):
    db.insert_alerts(conn, [alert(), alert()])

    db.clear_alerts(conn)

    assert db.get_alerts(conn) == []


def test_connect_creates_file_in_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPS_DATA_DIR", str(tmp_path / "novo"))

    db.connect().close()

    assert (tmp_path / "novo" / "secops.db").exists()
