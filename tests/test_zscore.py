from datetime import UTC, datetime, timedelta

from secops_core.detectors.zscore import detect
from secops_core.generator import generate
from secops_core.parser import LogEvent, parse_event

T0 = datetime(2026, 1, 5, 0, 0, tzinfo=UTC)


def hours(user, counts):
    """Um evento por contagem, espalhados em horas consecutivas: counts[i] eventos na hora i."""
    return [
        LogEvent(T0 + timedelta(hours=h, seconds=i), user, "10.0.1.11", "GetObject", True)
        for h, count in enumerate(counts)
        for i in range(count)
    ]


def test_spike_is_flagged():
    [alert] = detect(hours("alice", [3, 4, 3, 5, 4] * 6 + [40]))

    assert alert.detector == "zscore"
    assert alert.severity == "high"
    assert alert.user == "alice"
    assert alert.timestamp == T0 + timedelta(hours=30)
    assert alert.score >= 5


def test_steady_traffic_has_no_alerts():
    assert detect(hours("alice", [4, 5, 4, 5, 4, 5, 4, 5, 4, 5, 4, 5])) == []


def test_constant_traffic_does_not_divide_by_zero():
    assert detect(hours("alice", [4] * 12)) == []


def test_too_little_history_is_ignored():
    assert detect(hours("alice", [3, 3, 3, 40])) == []


def test_users_are_compared_only_with_themselves():
    quiet = hours("alice", [3, 4, 3, 5, 4, 3, 4, 3, 5, 4, 3, 4])
    busy = hours("bruno", [30, 31, 29, 30, 32, 30, 31, 29, 30, 31, 30, 29])

    assert detect(quiet + busy) == []


def test_generated_burst_is_flagged_for_its_victim():
    events = [parse_event(raw) for raw in generate(1000, seed=42)]

    alerts = detect(events)

    burst = [e for e in events if e.source_ip == "203.0.113.50"]
    assert any(
        a.user == burst[0].user and a.timestamp.hour == burst[0].timestamp.hour for a in alerts
    )
    assert len(alerts) <= 3  # poucos falsos positivos no tráfego normal
