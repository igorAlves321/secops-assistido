from collections import Counter, defaultdict
from statistics import mean, pstdev

from secops_core.alert import Alert
from secops_core.parser import LogEvent

THRESHOLD = 3.0  # desvios-padrão acima da média que viram alerta
HIGH_THRESHOLD = 5.0
MIN_BUCKETS = 10  # com menos horas de histórico a média não é confiável


def detect(events: list[LogEvent]) -> list[Alert]:
    """Z-Score do volume de eventos por usuário e por hora, contra o histórico do próprio usuário."""
    buckets = defaultdict(Counter)
    for e in events:
        buckets[e.user][e.timestamp.replace(minute=0, second=0, microsecond=0)] += 1

    alerts = []
    for user, counts in buckets.items():
        if len(counts) < MIN_BUCKETS:
            continue
        avg, std = mean(counts.values()), pstdev(counts.values())
        if std == 0:
            continue
        for hour, count in sorted(counts.items()):
            z = (count - avg) / std
            if z >= THRESHOLD:
                alerts.append(
                    Alert(
                        "zscore",
                        "high" if z >= HIGH_THRESHOLD else "medium",
                        user,
                        hour,
                        f"{count} eventos de {user} em uma hora (média {avg:.1f}, z={z:.1f})",
                        score=round(z, 2),
                    )
                )
    return sorted(alerts, key=lambda a: (a.timestamp, a.user))
