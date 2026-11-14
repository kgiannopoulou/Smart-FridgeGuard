"""Streamlit SOC dashboard (placeholder for Phase 1, Step 4).

Run with:  streamlit run dashboard/app.py
"""

import pandas as pd
import plotly.express as px
import streamlit as st

from fridgeguard import __version__

st.set_page_config(page_title="Smart-FridgeGuard SOC", layout="wide")
st.title("Smart-FridgeGuard SOC dashboard")
st.caption(f"v{__version__} · development environment check")

st.info(
    "The event generator and database are not built yet. "
    "This page only confirms that Streamlit, pandas and Plotly work together."
)

# Static sample shape only; real data will come from SQLite (docs/architecture.md, 3.5).
sample = pd.DataFrame(
    {
        "minute": list(range(10)) * 3,
        "device_id": ["FRIDGE-001"] * 10 + ["FRIDGE-002"] * 10 + ["FRIDGE-003"] * 10,
        "temperature_c": [4.0] * 10 + [-18.0] * 10 + [5.0] * 10,
    }
)
fig = px.line(
    sample, x="minute", y="temperature_c", color="device_id", title="Chart rendering test"
)
st.plotly_chart(fig, width="stretch")
