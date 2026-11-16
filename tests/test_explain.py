from datetime import UTC, datetime

import pytest

from secops_core import db, pipeline
from secops_core.alert import Alert
from secops_core.explain import explain
from secops_core.generator import generate
from secops_core.parser import parse_event

WHEN = datetime(2026, 1, 5, 3, 30, tzinfo=UTC)


def make(rule, detector="rules", severity="high", score=None):
    return Alert(detector, severity, "alice", WHEN, "descrição do alerta", score=score, rule=rule)


RULES = [
    "adulteracao_log",
    "escalada_privilegio",
    "s3_publico",
    "atividade_root",
    "login_falho",
    "ip_externo",
    "volume",
    "atipico",
]


@pytest.mark.parametrize("rule", [*RULES, None, "desconhecida"])
def test_every_rule_renders_all_sections(rule):
    text = explain(make(rule, score=12.0))

    assert "descrição do alerta" in text
    assert "Por que importa:" in text
    assert "O que fazer:" in text
    assert "05/01/2026 03:30 UTC" in text


def test_text_mentions_user_severity_and_detector():
    text = explain(make("adulteracao_log"))

    assert "alice" in text
    assert "Gravidade: alta" in text
    assert "Detector: rules" in text


def test_login_falho_shows_attempts_as_integer():
    assert "12 tentativas" in explain(make("login_falho", score=12.0))


def test_unknown_rule_uses_default_template():
    assert "marcou esse comportamento" in explain(make("desconhecida", "zscore", "low"))


def test_pipeline_stores_an_explanation_for_every_alert():
    conn = db.connect(":memory:")
    pipeline.run(conn, [parse_event(raw) for raw in generate(1000, seed=42)])

    alerts = db.get_alerts(conn)

    assert alerts and all(a.explanation for a in alerts)
    assert {a.rule for a in alerts} <= set(RULES)


def test_old_database_gets_rule_column(tmp_path):
    import sqlite3

    path = tmp_path / "velho.db"
    old = sqlite3.connect(path)
    old.executescript(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY, detector TEXT, severity TEXT, user TEXT,"
        " timestamp TEXT, description TEXT, score REAL, explanation TEXT);"
    )
    old.close()

    conn = db.connect(path)

    assert "rule" in {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}
