import json
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from secops_core import db, llm
from secops_core.alert import Alert
from secops_core.parser import LogEvent

T0 = datetime(2026, 1, 5, 17, 0, tzinfo=UTC)


@pytest.fixture
def ollama(monkeypatch):
    """Ollama falso: responde com `server.reply` (ou dorme `server.delay` s) e guarda o pedido."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            server.requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            time.sleep(server.delay)
            data = (
                server.reply
                if isinstance(server.reply, bytes)
                else json.dumps(server.reply).encode()
            )
            self.send_response(200)
            self.end_headers()
            try:
                self.wfile.write(data)
            except OSError:  # o cliente desistiu por timeout
                pass

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.requests, server.delay, server.reply = [], 0, {"response": " Parece força bruta. "}
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("OLLAMA_URL", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("OLLAMA_MODEL", "modelo-teste")
    yield server
    server.shutdown()


def test_ask_returns_stripped_answer(ollama):
    assert llm.ask("oi") == "Parece força bruta."
    assert ollama.requests[0]["model"] == "modelo-teste"
    assert ollama.requests[0]["stream"] is False


def test_ask_without_config_returns_none(monkeypatch):
    monkeypatch.delenv("OLLAMA_URL", raising=False)

    assert llm.ask("oi") is None


def test_ask_unreachable_returns_none(monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("OLLAMA_MODEL", "m")

    assert llm.ask("oi") is None


def test_ask_timeout_returns_none(ollama, monkeypatch):
    ollama.delay = 1
    monkeypatch.setenv("OLLAMA_TIMEOUT", "0.2")

    assert llm.ask("oi") is None


@pytest.mark.parametrize("reply", [b"isso nao e json", {"outro": 1}, {"response": "  "}, [1, 2]])
def test_ask_bad_reply_returns_none(ollama, reply):
    ollama.reply = reply

    assert llm.ask("oi") is None


def make_db():
    conn = db.connect(":memory:")
    events = [
        LogEvent(T0 + timedelta(seconds=6 * i), "diego", "203.0.113.50", "ConsoleLogin", False)
        for i in range(20)
    ]
    events += [LogEvent(T0 + timedelta(hours=3), "diego", "10.0.1.14", "GetObject", True)]
    events += [LogEvent(T0, "alice", "10.0.1.11", "GetObject", True)]
    db.insert_logs(conn, events)
    alert = Alert("rules", "high", "diego", T0, "20 logins falhos de diego", rule="login_falho")
    db.insert_alerts(conn, [alert])
    return conn, db.get_alerts(conn)[0]


def test_prompt_has_alert_and_only_nearby_logs_of_the_user():
    conn, alert = make_db()
    context = db.get_logs(conn, "diego", T0 - llm.CONTEXT, T0 + llm.CONTEXT)

    prompt = llm.build_prompt(alert, context)

    assert "20 logins falhos de diego" in prompt
    assert "(20 eventos)" in prompt  # sem o GetObject de 3h depois nem os logs da alice
    assert "17:00:00–17:01:54 ConsoleLogin de 203.0.113.50 (FALHOU) ×20" in prompt
    assert prompt.count("ConsoleLogin") == 1  # as 20 linhas viraram uma
    assert "... e mais" not in prompt


def test_prompt_truncates_long_context(monkeypatch):
    _, alert = make_db()
    monkeypatch.setattr(llm, "MAX_CONTEXT_LINES", 3)
    alternating = [  # ações diferentes em sequência: nada se agrupa
        LogEvent(T0 + timedelta(seconds=i), "diego", "10.0.1.14", f"Acao{i}", True)
        for i in range(10)
    ]

    prompt = llm.build_prompt(alert, alternating)

    assert "Acao2" in prompt and "Acao3" not in prompt
    assert "... e mais 7 trechos" in prompt


def test_enhance_adds_model_analysis_and_stores_it():
    conn, alert = make_db()
    prompts = []

    def fake(prompt):
        prompts.append(prompt)
        return "Força bruta clássica."

    text = llm.enhance(conn, alert.id, ask=fake)

    assert "Por que importa:" in text  # o template continua lá
    assert text.endswith(f"{llm.MARKER}\nForça bruta clássica.")
    assert "(20 eventos)" in prompts[0]
    assert db.get_alert(conn, alert.id).explanation == text


def test_enhance_is_cached_after_success():
    conn, alert = make_db()
    llm.enhance(conn, alert.id, ask=lambda p: "primeira")

    def must_not_be_called(prompt):
        raise AssertionError("não devia perguntar de novo")

    assert "primeira" in llm.enhance(conn, alert.id, ask=must_not_be_called)


def test_enhance_falls_back_to_template_and_retries_later():
    conn, alert = make_db()

    text = llm.enhance(conn, alert.id, ask=lambda p: None)

    assert "Por que importa:" in text and llm.MARKER not in text
    assert db.get_alert(conn, alert.id).explanation is None  # nada guardado: tenta de novo
    assert llm.MARKER in llm.enhance(conn, alert.id, ask=lambda p: "agora foi")


def test_enhance_unknown_alert():
    assert llm.enhance(db.connect(":memory:"), 999, ask=lambda p: "x") is None


def test_enhance_end_to_end_with_fake_ollama(ollama):
    conn, alert = make_db()

    assert llm.enhance(conn, alert.id).endswith("Parece força bruta.")
    assert "20 logins falhos de diego" in ollama.requests[0]["prompt"]
