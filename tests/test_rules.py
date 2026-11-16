from datetime import UTC, datetime, timedelta

import pytest

from secops_core.detectors.rules import detect
from secops_core.generator import generate
from secops_core.parser import LogEvent, parse_event

T0 = datetime(2026, 1, 5, 10, 0, tzinfo=UTC)


def ev(seconds=0, user="alice", ip="10.0.1.11", action="GetObject", success=True):
    return LogEvent(T0 + timedelta(seconds=seconds), user, ip, action, success)


def failures(count, step=6, user="alice", start=0):
    return [ev(start + i * step, user, "203.0.113.50", "ConsoleLogin", False) for i in range(count)]


def test_normal_traffic_has_no_alerts():
    assert detect([ev(0), ev(60, action="PutObject"), ev(120, success=False)]) == []


def test_sensitive_action_is_high():
    [alert] = detect([ev(action="StopLogging")])

    assert (alert.detector, alert.severity, alert.user) == ("rules", "high", "alice")
    assert "StopLogging" in alert.description


@pytest.mark.parametrize(
    ("action", "rule"),
    [
        ("UpdateTrail", "adulteracao_log"),
        ("CreateAccessKey", "escalada_privilegio"),
        ("PutRolePolicy", "escalada_privilegio"),
        ("DeletePublicAccessBlock", "s3_publico"),
        ("PutBucketPolicy", "s3_publico"),
    ],
)
def test_sensitive_actions_pick_the_rule_of_their_risk(action, rule):
    [alert] = detect([ev(action=action)])

    assert (alert.rule, alert.severity) == (rule, "high")


def test_any_root_activity_is_high():
    [alert] = detect([ev(user="root", action="ListBuckets")])

    assert (alert.rule, alert.severity, alert.user) == ("atividade_root", "high", "root")
    assert "ListBuckets" in alert.description


def test_root_doing_a_sensitive_action_raises_both_rules():
    alerts = detect([ev(user="root", action="StopLogging")])

    assert {a.rule for a in alerts} == {"adulteracao_log", "atividade_root"}


def test_failed_login_burst_is_one_alert():
    [alert] = detect(failures(20))

    assert alert.severity == "high"
    assert alert.score == 20
    assert alert.timestamp == T0
    assert "203.0.113.50" in alert.description


def test_few_failures_do_not_alert():
    assert detect(failures(4)) == []


def test_failures_split_by_long_pause_do_not_add_up():
    events = failures(3) + failures(3, start=3600)

    assert detect(events) == []


def test_two_bursts_two_alerts():
    assert len(detect(failures(5) + failures(5, start=3600))) == 2


def test_bursts_are_counted_per_user():
    assert detect(failures(3, user="alice") + failures(3, user="bruno")) == []


def test_unsorted_input_is_handled():
    assert len(detect(list(reversed(failures(6))))) == 1


def test_successful_login_from_public_ip_is_medium():
    [alert] = detect([ev(ip="8.8.8.8", action="ConsoleLogin")])

    assert alert.severity == "medium"
    assert "8.8.8.8" in alert.description


def test_failed_event_from_public_ip_is_not_external_alert():
    assert detect([ev(ip="8.8.8.8", success=False)]) == []


def test_catches_every_generated_anomaly():
    events = [parse_event(raw) for raw in generate(1000, seed=42)]

    alerts = detect(events)

    assert len(alerts) == 4  # 1 rajada de logins + 3 ações sensíveis
    assert sum(a.score == 20 for a in alerts) == 1
    assert sum(e.is_anomaly for e in events) == 23
