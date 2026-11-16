from datetime import UTC

import pytest

from secops_core.generator import generate, main
from secops_core.parser import LogParseError, load_jsonl, parse_event, parse_lines

VALID = {
    "timestamp": "2026-01-05T09:09:21+00:00",
    "user": " Alice ",
    "source_ip": "10.0.1.11",
    "action": "PutObject",
    "success": True,
    "is_anomaly": False,
}


def test_parse_event_normalizes():
    event = parse_event(VALID)

    assert event.user == "alice"
    assert event.timestamp.tzinfo is not None
    assert event.success is True


def test_naive_timestamp_becomes_utc():
    event = parse_event({**VALID, "timestamp": "2026-01-05T09:09:21"})

    assert event.timestamp.tzinfo == UTC


def test_missing_is_anomaly_defaults_to_false():
    raw = {k: v for k, v in VALID.items() if k != "is_anomaly"}

    assert parse_event(raw).is_anomaly is False


@pytest.mark.parametrize(
    "change",
    [
        {"timestamp": "ontem"},
        {"source_ip": "999.1.1.1"},
        {"success": "true"},
        {"user": "  "},
        {"action": ""},
    ],
)
def test_parse_event_rejects_invalid(change):
    with pytest.raises(LogParseError):
        parse_event({**VALID, **change})


def test_parse_event_rejects_missing_field():
    with pytest.raises(LogParseError):
        parse_event({k: v for k, v in VALID.items() if k != "action"})


def test_parse_lines_reports_line_number():
    with pytest.raises(LogParseError, match="linha 1"):
        parse_lines(["{ruim\n"])


def test_parse_lines_skips_blank_lines():
    assert parse_lines(["\n", "   \n"]) == []


def test_generated_logs_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPS_DATA_DIR", str(tmp_path))
    main(["--events", "50"])

    events = load_jsonl(tmp_path / "logs_simulados.jsonl")

    assert len(events) == len(generate(50, seed=42))
    assert any(e.is_anomaly for e in events)
