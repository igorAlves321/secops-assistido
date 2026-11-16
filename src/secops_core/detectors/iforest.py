import math
from bisect import bisect_left
from collections import Counter, defaultdict
from datetime import timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

from secops_core.alert import Alert
from secops_core.parser import LogEvent

CONTAMINATION = 0.03  # fração dos eventos que o modelo considera anômala
GROUP_GAP = timedelta(
    minutes=5
)  # eventos suspeitos do mesmo usuário até esse intervalo viram um alerta
MIN_EVENTS = 50


def _features(events: list[LogEvent]) -> np.ndarray:
    """Uma linha por evento, na ordem recebida."""
    action_freq = Counter(e.action for e in events)
    usual_ip = {
        user: Counter(e.source_ip for e in events if e.user == user).most_common(1)[0][0]
        for user in {e.user for e in events}
    }
    by_user = defaultdict(list)  # user -> [(segundos, falhou)], ordenado
    for e in sorted(events, key=lambda e: e.timestamp):
        by_user[e.user].append((e.timestamp.timestamp(), not e.success))
    times = {user: [t for t, _ in rows] for user, rows in by_user.items()}
    fails = {user: np.cumsum([int(f) for _, f in rows]) for user, rows in by_user.items()}

    rows = []
    for e in events:
        t, ts = e.timestamp.timestamp(), times[e.user]
        end = bisect_left(ts, t + 1e-6)  # inclui o próprio evento
        last_minute = end - bisect_left(ts, t - 60)
        start5 = bisect_left(ts, t - 300)
        failed_5min = fails[e.user][end - 1] - (fails[e.user][start5 - 1] if start5 else 0)
        rows.append(
            [
                e.timestamp.hour,
                e.timestamp.hour < 6 or e.timestamp.hour >= 22,
                not e.success,
                e.source_ip != usual_ip[e.user],
                -math.log(action_freq[e.action] / len(events)),
                last_minute,
                failed_5min,
            ]
        )
    return np.array(rows, dtype=float)


def detect(events: list[LogEvent]) -> list[Alert]:
    """Isolation Forest sobre o comportamento de cada evento. Eventos suspeitos
    seguidos do mesmo usuário viram um alerta só."""
    if len(events) < MIN_EVENTS:
        return []
    features = _features(events)
    model = IsolationForest(contamination=CONTAMINATION, random_state=42).fit(features)
    flags = model.predict(features)
    scores = -model.score_samples(features)  # maior = mais anômalo

    flagged = defaultdict(list)
    for e, flag, score in zip(events, flags, scores, strict=True):
        if flag == -1:
            flagged[e.user].append((e, score))

    alerts = []
    for user, rows in flagged.items():
        rows.sort(key=lambda row: row[0].timestamp)
        group = [rows[0]]
        for row in [*rows[1:], None]:  # None fecha o último grupo
            if row and row[0].timestamp - group[-1][0].timestamp <= GROUP_GAP:
                group.append(row)
                continue
            first = group[0][0]
            actions = ", ".join(sorted({e.action for e, _ in group}))
            alerts.append(
                Alert(
                    "iforest",
                    "medium",
                    user,
                    first.timestamp,
                    f"{len(group)} evento(s) atípico(s) de {user}: {actions}",
                    score=round(max(s for _, s in group), 3),
                    rule="atipico",
                )
            )
            group = [row] if row else []
    return sorted(alerts, key=lambda a: (a.timestamp, a.user))
