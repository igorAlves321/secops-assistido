import json
import os
from urllib.request import urlopen

import streamlit as st

API_URL = os.environ.get("SECOPS_API_URL", "http://localhost:8000")

st.title("SecOps Assistido")

try:
    with urlopen(f"{API_URL}/health", timeout=3) as response:
        st.success(f"API: {json.load(response)['status']}")
except OSError:
    st.error("API indisponível")
