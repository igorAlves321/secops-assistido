import json
import os
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pandas as pd
import streamlit as st

API_URL = os.environ.get("SECOPS_API_URL", "http://localhost:8080")
SEVERITIES = ["high", "medium", "low"]
DETECTORS = ["rules", "iforest", "zscore"]


def call(path: str, method: str = "GET", timeout: float = 10, **params):
    query = urlencode({k: v for k, v in params.items() if v})
    url = f"{API_URL}{path}{'?' + query if query else ''}"
    with urlopen(Request(url, method=method), timeout=timeout) as response:
        return json.load(response)


def api_error(exc: HTTPError) -> str:
    try:
        return json.load(exc)["detail"]
    except (ValueError, KeyError, TypeError):
        return str(exc)


st.set_page_config(page_title="SecOps Assistido", layout="wide")
st.title("SecOps Assistido")

try:
    call("/health", timeout=3)
except OSError:
    st.error("API indisponível")
    st.stop()

with st.sidebar:
    st.header("Detecção")
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
    st.subheader("Eventos por hora")
    st.line_chart(logs.set_index("timestamp").resample("h").size())
    left, middle, right = st.columns(3)
    left.subheader("Por gravidade")
    left.bar_chart(pd.Series(metrics["alerts_by_severity"]))
    middle.subheader("Por detector")
    middle.bar_chart(pd.Series(metrics["alerts_by_detector"]))
    right.subheader("Por usuário")
    right.bar_chart(pd.Series(metrics["alerts_by_user"]))

with investigation:
    alerts = pd.DataFrame(call("/alerts", limit=5000))
    left, middle, right = st.columns(3)
    severity = left.multiselect("Gravidade", SEVERITIES, default=SEVERITIES)
    detector = middle.multiselect("Detector", DETECTORS, default=DETECTORS)
    user = right.multiselect("Usuário", sorted(alerts["user"].unique()))
    shown = alerts[alerts["severity"].isin(severity) & alerts["detector"].isin(detector)]
    if user:
        shown = shown[shown["user"].isin(user)]
    shown = shown.sort_values("timestamp")
    st.dataframe(
        shown[["id", "timestamp", "severity", "user", "detector", "description"]],
        hide_index=True,
        use_container_width=True,
    )

    if shown.empty:
        st.info("Nenhum alerta com esses filtros.")
    else:
        rows = shown.set_index("id")
        alert_id = st.selectbox(
            "Alerta",
            rows.index,
            format_func=lambda i: (
                f"#{i} · {rows.loc[i, 'severity']} · {rows.loc[i, 'user']} · "
                f"{rows.loc[i, 'timestamp'][:16]}"
            ),
        )
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
        st.text(result["explanation"])
