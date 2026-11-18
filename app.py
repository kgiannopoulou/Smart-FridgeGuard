"""Smart-FridgeGuard SOC dashboard (Phase 3, Step 11).

Run with:  streamlit run app.py
Database:  data/fridgeguard.db, or set FRIDGEGUARD_DB to another file.
Pages:     dashboard/views/ (one file per page); data layer in fridgeguard/dashboard/.
"""

from pathlib import Path

import streamlit as st

# not "pages/": that folder name would trigger Streamlit's page auto-discovery
PAGES = Path(__file__).parent / "dashboard" / "views"

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
