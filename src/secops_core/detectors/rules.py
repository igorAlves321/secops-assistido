import ipaddress
from collections import defaultdict
from datetime import timedelta

from secops_core.alert import Alert
from secops_core.parser import LogEvent

# Ações da API da AWS que mexem na própria segurança da conta, por tipo de risco.
# Cada tipo vira uma regra, com o seu texto de explicação.
SENSITIVE_RULES = {
    "adulteracao_log": ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"),
    "escalada_privilegio": (
        "AttachUserPolicy",
        "PutUserPolicy",
        "AttachRolePolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "AddUserToGroup",
        "UpdateAssumeRolePolicy",
    ),
    "s3_publico": (
        "PutBucketAcl",
        "PutBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeletePublicAccessBlock",
    ),
}
RULE_OF_ACTION = {a: rule for rule, actions in SENSITIVE_RULES.items() for a in actions}
ROOT_USER = "root"
FAILED_LOGIN_LIMIT = 5  # falhas seguidas que viram alerta
FAILED_LOGIN_GAP = timedelta(minutes=5)  # pausa maior que isso encerra a sequência


def detect(events: list[LogEvent]) -> list[Alert]:
    """Regras determinísticas de CloudTrail. Devolve os alertas em ordem de horário."""
    alerts = [
        *_sensitive_actions(events),
        *_root_activity(events),
        *_failed_logins(events),
        *_external_ips(events),
    ]
    return sorted(alerts, key=lambda a: (a.timestamp, a.user))


def _sensitive_actions(events: list[LogEvent]) -> list[Alert]:
    return [
        Alert(
            "rules",
            "high",
            e.user,
            e.timestamp,
            f"Ação sensível {e.action} por {e.user}",
            rule=RULE_OF_ACTION[e.action],
        )
        for e in events
        if e.action in RULE_OF_ACTION
    ]


def _root_activity(events: list[LogEvent]) -> list[Alert]:
    """Qualquer uso do root é alerta: a conta root não deveria fazer o trabalho do dia a dia."""
    return [
        Alert(
            "rules",
            "high",
            e.user,
            e.timestamp,
            f"Atividade do usuário root: {e.action} de {e.source_ip}",
            rule="atividade_root",
        )
        for e in events
        if e.user == ROOT_USER
    ]


def _failed_logins(events: list[LogEvent]) -> list[Alert]:
    failures = defaultdict(list)
    for e in sorted(events, key=lambda e: e.timestamp):
        if e.action == "ConsoleLogin" and not e.success:
            failures[e.user].append(e)

    alerts = []
    for user, user_failures in failures.items():
        run = [user_failures[0]]
        for e in [*user_failures[1:], None]:  # None fecha a última sequência
            if e and e.timestamp - run[-1].timestamp <= FAILED_LOGIN_GAP:
                run.append(e)
                continue
            if len(run) >= FAILED_LOGIN_LIMIT:
                ips = ", ".join(sorted({r.source_ip for r in run}))
                alerts.append(
                    Alert(
                        "rules",
                        "high",
                        user,
                        run[0].timestamp,
                        f"{len(run)} logins falhos seguidos de {user} (IP {ips})",
                        score=float(len(run)),
                        rule="login_falho",
                    )
                )
            run = [e] if e else []
    return alerts


def _external_ips(events: list[LogEvent]) -> list[Alert]:
    return [
        Alert(
            "rules",
            "medium",
            e.user,
            e.timestamp,
            f"{e.action} com sucesso de IP externo {e.source_ip}",
            rule="ip_externo",
        )
        for e in events
        if e.success and ipaddress.ip_address(e.source_ip).is_global
    ]
