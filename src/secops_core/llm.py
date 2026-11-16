import json
import os
import sqlite3
from collections.abc import Callable
from datetime import timedelta
from itertools import groupby
from urllib.request import Request, urlopen

from secops_core import db
from secops_core.alert import Alert
from secops_core.explain import explain
from secops_core.parser import LogEvent

MARKER = "Atividade em volta do alerta (resumo do modelo local, pode conter erros):"
CONTEXT = timedelta(minutes=30)  # logs do usuário antes e depois do alerta
MAX_CONTEXT_LINES = 25
MAX_TOKENS = 150  # a CPU gera ~5 tokens/s; limita a espera


def ask_ollama(prompt: str) -> str | None:
    """Pergunta ao Ollama. Devolve None se ele não estiver configurado, não responder a
    tempo ou responder algo inútil: quem chama cai no template."""
    url, model = os.environ.get("OLLAMA_URL"), os.environ.get("OLLAMA_MODEL")
    if not url or not model:
        return None
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": "30m",  # evita recarregar o modelo (~30 s) a cada pedido
            "options": {"num_predict": MAX_TOKENS, "temperature": 0.2},
        }
    ).encode()
    request = Request(f"{url}/api/generate", body, {"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=float(os.environ.get("OLLAMA_TIMEOUT", "120"))) as response:
            answer = json.load(response)["response"].strip()
    except (OSError, ValueError, KeyError, TypeError, AttributeError):  # rede, JSON ou formato
        return None
    return answer or None


def _lines(context: list[LogEvent]) -> list[str]:
    """Uma linha por trecho; eventos seguidos iguais viram uma linha com a contagem."""
    lines = []
    for (action, ip, success), group in groupby(
        context, lambda e: (e.action, e.source_ip, e.success)
    ):
        events = list(group)
        result = "ok" if success else "FALHOU"
        when = f"{events[0].timestamp:%H:%M:%S}"
        if len(events) > 1:
            when += f"–{events[-1].timestamp:%H:%M:%S}"
        count = f" ×{len(events)}" if len(events) > 1 else ""
        lines.append(f"{when} {action} de {ip} ({result}){count}")
    return lines


def build_prompt(alert: Alert, context: list[LogEvent]) -> str:
    all_lines = _lines(context)
    lines = "\n".join(all_lines[:MAX_CONTEXT_LINES]) or "(sem logs no período)"
    hidden = len(all_lines) - MAX_CONTEXT_LINES
    more = f"\n... e mais {hidden} trechos" if hidden > 0 else ""
    return (
        "Você é um analista de SecOps. Descreva em português, em no máximo 3 linhas, apenas O QUE "
        "o usuário fez em volta do horário do alerta, usando só os dados abaixo (ações, IPs, "
        "horários, falhas e sucessos). NÃO diga se é ataque ou uso normal, NÃO faça contas e "
        "NÃO invente nada.\n\n"
        f"Alerta ({alert.severity}, detector {alert.detector}): {alert.description}\n"
        f"Usuário: {alert.user}\n\n"
        f"Atividade do usuário em volta do alerta ({len(context)} eventos):\n{lines}{more}"
    )


def enhance(
    conn: sqlite3.Connection, alert_id: int, ask: Callable[[str], str | None] | None = None
) -> str | None:
    """Explicação do alerta: template e, se o modelo responder, a análise dele. A versão
    com análise é guardada no banco; se o modelo falhar, devolve só o template e tenta
    de novo no próximo pedido. None se o alerta não existe."""
    alert = db.get_alert(conn, alert_id)
    if alert is None:
        return None
    if alert.explanation and MARKER in alert.explanation:
        return alert.explanation

    context = db.get_logs(
        conn, alert.user, alert.timestamp - CONTEXT, alert.timestamp + CONTEXT, limit=500
    )
    answer = (ask or ask_ollama)(build_prompt(alert, context))
    base = alert.explanation or explain(alert)
    if answer is None:
        return base
    text = f"{base}\n\n{MARKER}\n{answer}"
    db.set_explanation(conn, alert_id, text)
    return text
