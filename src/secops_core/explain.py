from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateNotFound

from secops_core.alert import Alert

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,  # variável faltando é bug, não texto em branco
    trim_blocks=True,
    keep_trailing_newline=False,
)
SEVERITY = {"high": "alta", "medium": "média", "low": "baixa"}


def explain(alert: Alert) -> str:
    """Explicação em português para um alerta, a partir do template da sua regra."""
    try:
        template = _env.get_template(f"{alert.rule}.j2")
    except TemplateNotFound:
        template = _env.get_template("padrao.j2")
    return template.render(
        alert=alert,
        severity=SEVERITY.get(alert.severity, alert.severity),
        quando=alert.timestamp.strftime("%d/%m/%Y %H:%M UTC"),
    ).strip()
