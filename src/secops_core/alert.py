from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Alert:
    detector: str  # "zscore", "rules" ou "iforest"
    severity: str  # "low", "medium" ou "high"
    user: str
    timestamp: datetime  # início do comportamento suspeito
    description: str
    score: float | None = None
    explanation: str | None = None
    rule: str | None = None  # qual regra gerou o alerta; escolhe o template de explicação
    id: int | None = None  # preenchido pelo banco
