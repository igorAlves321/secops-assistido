import json
import os
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from secops_core import charts

API_URL = os.environ.get("SECOPS_API_URL", "http://localhost:8080")
SEVERITIES = ["high", "medium", "low"]
DETECTORS = ["rules", "iforest", "zscore"]
SEVERITY_PT = {"high": "alta", "medium": "média", "low": "baixa"}
MAX_TABLE_ROWS = 200  # a tabela é HTML de verdade (boa para leitor de tela), então fica limitada


def call(path: str, method: str = "GET", timeout: float = 10, **params):
    query = urlencode({k: v for k, v in params.items() if v})
    url = f"{API_URL}{path}{'?' + query if query else ''}"
    with urlopen(Request(url, method=method), timeout=timeout) as response:
        return json.load(response)


def when(value) -> pd.Series:
    """Horário legível em português, em vez do ISO cru."""
    return pd.to_datetime(value).dt.strftime("%d/%m/%Y %H:%M")


def api_error(exc: HTTPError) -> str:
    try:
        return json.load(exc)["detail"]
    except (ValueError, KeyError, TypeError):
        return str(exc)


st.set_page_config(page_title="SecOps Assistido", layout="wide")
# O Streamlit fixa <html lang="en">, e leitores de tela trocam a pronúncia pelo idioma da página.
# O conteúdo é em português, então corrigimos o atributo (WCAG 3.1.1). O script roda num iframe;
# depois de agir, o iframe se esconde para não virar uma parada de Tab nem um "frame" mudo.
components.html(
    "<script>parent.document.documentElement.lang = 'pt-BR';"
    "window.frameElement.style.display = 'none';</script>",
    height=0,
)
st.html(charts.CSS)
st.title("SecOps Assistido", anchor=False)

try:
    call("/health", timeout=3)
except OSError:
    st.error("API indisponível")
    st.stop()

with st.sidebar:
    st.header("Detecção", anchor=False)
    if st.button("Rodar detecção", key="run", use_container_width=True):
        try:
            summary = call("/run", "POST", timeout=180)
            st.success(f"{summary['alertas']} alertas em {summary['logs']} logs")
        except HTTPError as exc:
            st.error(api_error(exc))
        except OSError:
            st.error("A API não respondeu")

metrics = call("/metrics")
if not metrics["logs"]:
    st.info("Ainda não há dados. Gere os logs (`make generate`) e clique em **Rodar detecção**.")
    st.stop()

cols = st.columns(4)
cols[0].metric("Logs analisados", metrics["logs"])
cols[1].metric("Alertas", metrics["alerts"])
cols[2].metric("Alertas altos", metrics["alerts_by_severity"].get("high", 0))
cols[3].metric("Usuários com alerta", len(metrics["alerts_by_user"]))

overview, investigation = st.tabs(["Visão geral", "Investigação"])

with overview:
    logs = pd.DataFrame(call("/logs", limit=5000))
    logs["timestamp"] = pd.to_datetime(logs["timestamp"])
    hourly = logs.set_index("timestamp").resample("h").size().rename("Eventos").rename_axis("Hora")
    peak = hourly.idxmax()
    st.header("Eventos por hora", anchor=False)
    st.markdown(
        f"Pico de **{hourly.max()} eventos** em {peak:%d/%m/%Y às %H:%M} (UTC). "
        "A tabela por dia, abaixo, traz os mesmos dados em texto."
    )
    st.html(
        charts.timeseries_html(
            list(hourly.items()),
            f"Linha com o número de eventos em cada hora, de {hourly.index[0]:%d/%m/%Y} a "
            f"{hourly.index[-1]:%d/%m/%Y}. Pico de {hourly.max()} eventos em {peak:%d/%m/%Y %H:%M}. "
            "Os valores por dia estão na tabela abaixo.",
            "Eventos",
        )
    )
    left, middle, right = st.columns(3)
    with left:
        st.header("Alertas por gravidade", anchor=False)
        st.html(
            charts.bars_html(
                "Alertas por gravidade",
                "Gravidade",
                {SEVERITY_PT[k]: v for k, v in metrics["alerts_by_severity"].items()},
            )
        )
    with middle:
        st.header("Alertas por detector", anchor=False)
        st.html(charts.bars_html("Alertas por detector", "Detector", metrics["alerts_by_detector"]))
    with right:
        st.header("Alertas por usuário", anchor=False)
        st.html(charts.bars_html("Alertas por usuário", "Usuário", metrics["alerts_by_user"]))
    st.header("Eventos por dia", anchor=False)
    daily = hourly.groupby(hourly.index.date).agg(["sum", "max"])
    st.html(
        charts.table_html(
            "Eventos por dia (horário UTC)",
            ["Dia", "Eventos no dia", "Máximo em uma hora"],
            [[f"{day:%d/%m/%Y}", total, top] for day, (total, top) in daily.iterrows()],
            "dias",
        )
    )

with investigation:
    alerts = pd.DataFrame(call("/alerts", limit=5000))
    st.header("Alertas", anchor=False)
    left, middle, right = st.columns(3)
    # Checkboxes nativos em vez de multiselect: sem chips, e cada rótulo se explica sozinho.
    with left:
        severity = [
            s
            for s in SEVERITIES
            if st.checkbox(f"Gravidade {SEVERITY_PT[s]}", True, key=f"sev-{s}")
        ]
    with middle:
        detector = [d for d in DETECTORS if st.checkbox(f"Detector {d}", True, key=f"det-{d}")]
    user = right.selectbox("Usuário", ["Todos", *sorted(alerts["user"].unique())])
    shown = alerts[alerts["severity"].isin(severity) & alerts["detector"].isin(detector)]
    if user != "Todos":
        shown = shown[shown["user"] == user]
    shown = shown.sort_values("timestamp")

    if shown.empty:
        st.info("Nenhum alerta com esses filtros.")
    else:
        st.caption(f"{len(shown)} alertas, do mais antigo para o mais recente. Horários em UTC.")
        table = [
            [
                row.id,
                when(pd.Series([row.timestamp])).iloc[0],
                SEVERITY_PT[row.severity],
                row.user,
                row.detector,
                row.description,
            ]
            for row in shown.head(MAX_TABLE_ROWS).itertuples()
        ]
        st.html(
            charts.table_html(
                "Alertas encontrados",
                ["Nº", "Horário (UTC)", "Gravidade", "Usuário", "Detector", "Descrição"],
                table,
                "alertas",
            )
        )
        if len(shown) > MAX_TABLE_ROWS:
            st.caption(
                f"Mostrando os {MAX_TABLE_ROWS} primeiros; use os filtros para ver os demais."
            )

        rows = shown.set_index("id")
        labels = (
            rows["severity"].map(SEVERITY_PT)
            + " · "
            + rows["user"]
            + " · "
            + when(rows["timestamp"])
        )
        alert_id = st.selectbox(
            "Escolha um alerta para ver a explicação",
            rows.index,
            format_func=lambda i: f"Nº {i} · {labels[i]}",
        )
        st.header(f"Explicação do alerta nº {alert_id}", anchor=False)
        result = call(f"/alerts/{alert_id}/explanation")
        if st.button("Pedir resumo da IA (pode levar até 2 min)", key="ai"):
            with st.spinner("O modelo local está lendo os logs em volta do alerta..."):
                try:
                    result = call(f"/alerts/{alert_id}/explanation", timeout=180, ai=True)
                except OSError:
                    st.error("A API não respondeu a tempo")
            if not result["ai"]:
                st.warning(
                    "O Ollama não respondeu; mostrando só a explicação padrão. Rode `make llm`."
                )
        st.markdown(result["explanation"])
