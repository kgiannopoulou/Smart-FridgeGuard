"""Smart-FridgeGuard SOC dashboard (Phase 3, Step 11).

Run with:  streamlit run dashboard/app.py
Database:  data/fridgeguard.db, or set FRIDGEGUARD_DB to another file.
"""

from pathlib import Path

import streamlit as st

PAGES = Path(__file__).parent / "views"  # not "pages/": that name triggers auto-discovery

st.set_page_config(
    page_title="Smart-FridgeGuard SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

navigation = st.navigation(
    {
        "Monitoring": [
            st.Page(PAGES / "overview.py", title="Overview", icon="🛡️", default=True),
            st.Page(PAGES / "temperature.py", title="Temperature monitoring", icon="🌡️"),
            st.Page(PAGES / "security.py", title="Security monitoring", icon="🔐"),
        ],
        "Response": [
            st.Page(PAGES / "alerts.py", title="Alert management", icon="🚨"),
            st.Page(PAGES / "investigation.py", title="Alert investigation", icon="🕵️"),
            st.Page(PAGES / "incidents.py", title="Incident investigation", icon="🔎"),
        ],
    }
)
navigation.run()
