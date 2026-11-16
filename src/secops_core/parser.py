import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class LogParseError(ValueError):
    """Linha de log inválida; a mensagem diz qual linha e por quê."""


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime  # sempre com fuso (UTC se a origem vier sem)
    user: str
    source_ip: str
    action: str
    success: bool
    is_anomaly: bool = False  # gabarito do gerador; logs reais não têm


def parse_event(raw: dict) -> LogEvent:
    try:
        when = datetime.fromisoformat(raw["timestamp"])
        user = str(raw["user"]).strip().lower()
        action = str(raw["action"]).strip()
        ip = str(ipaddress.ip_address(raw["source_ip"]))
        success = raw["success"]
    except (KeyError, ValueError, TypeError) as exc:
        raise LogParseError(f"campo ausente ou inválido: {exc!r}") from exc
    if not user or not action:
        raise LogParseError("user e action não podem ser vazios")
    if not isinstance(success, bool):
        raise LogParseError(f"success deve ser booleano, veio {success!r}")
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return LogEvent(when, user, ip, action, success, bool(raw.get("is_anomaly", False)))


def parse_lines(lines) -> list[LogEvent]:
    events = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            events.append(parse_event(json.loads(line)))
        except (json.JSONDecodeError, LogParseError) as exc:
            raise LogParseError(f"linha {number}: {exc}") from exc
    return events


def load_jsonl(path: str | Path) -> list[LogEvent]:
    with Path(path).open(encoding="utf-8") as file:
        return parse_lines(file)
