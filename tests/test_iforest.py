from datetime import UTC, datetime, timedelta

from secops_core.detectors.iforest import detect
from secops_core.generator import generate
from secops_core.parser import LogEvent, parse_event

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)


def normal(count=200):
    return [
        LogEvent(T0 + timedelta(minutes=7 * i), "alice", "10.0.1.11", "GetObject", True)
        for i in range(count)
    ]


def test_too_few_events_return_nothing():
    assert detect(normal(10)) == []


def test_is_reproducible():
    events = [parse_event(raw) for raw in generate(300, seed=1)]

    assert detect(events) == detect(events)


def test_odd_event_among_normal_ones_is_flagged():
    odd = LogEvent(T0 + timedelta(hours=3, minutes=1), "alice", "198.51.100.9", "DeleteTrail", True)

    alerts = detect(sorted([*normal(), odd], key=lambda e: e.timestamp))

    assert any(a.timestamp == odd.timestamp and a.detector == "iforest" for a in alerts)


def test_generated_attack_and_sensitive_actions_are_found():
    events = [parse_event(raw) for raw in generate(1000, seed=42)]
    anomalies = [e for e in events if e.is_anomaly]

    alerts = detect(events)

    def covered(e):
        return any(
            a.user == e.user and a.timestamp <= e.timestamp <= a.timestamp + timedelta(minutes=5)
            for a in alerts
        )

    assert all(covered(e) for e in anomalies)
    assert len(alerts) <= 15  # falsos positivos limitados pela contaminação


def test_flagged_burst_becomes_one_alert():
    events = [parse_event(raw) for raw in generate(1000, seed=42)]

    alerts = detect(events)

    assert sum("20 evento(s)" in a.description for a in alerts) == 1
