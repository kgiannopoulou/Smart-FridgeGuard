"""Overview: fleet status, open alerts and open incidents at a glance."""

import plotly.graph_objects as go
import streamlit as st

from fridgeguard.dashboard import ui
from fridgeguard.dashboard.theme import SEVERITY_COLORS, SEVERITY_ORDER, device_colors, style

ctx = ui.page("Security operations overview", "Smart-FridgeGuard SOC · refrigerator fleet")
if ctx is None:
    st.stop()

devs = ctx.get("devices")
tel = ctx.get("telemetry", ctx.since, ctx.until)
sec = ctx.get("security_events", ctx.since, ctx.until)
alerts = ctx.get("alerts")
incidents = ctx.get("incidents")
colors = device_colors(list(devs["device_id"]), ctx.pal)

open_alerts = alerts[alerts["status"].isin(["new", "under_investigation"])]
open_alerts = open_alerts[open_alerts["severity"] != "INFO"]
open_inc = incidents[incidents["status"] != "closed"] if not incidents.empty else incidents
latest = tel.sort_values("ts").groupby("device_id").tail(1) if not tel.empty else tel
in_range = int((~latest["out_of_range"]).sum()) if not latest.empty else 0
failed = int((sec["event_type"] == "LOGIN_FAILURE").sum()) if not sec.empty else 0
urgent = int(open_alerts["severity"].isin(["CRITICAL", "HIGH"]).sum())

c = st.columns(5)
c[0].metric("In range", f"{in_range} / {len(devs)}", border=True)
c[1].metric("Open alerts", len(open_alerts), border=True, help="new or under investigation")
c[2].metric("Crit. + high", urgent, border=True)
c[3].metric("Incidents", len(open_inc), border=True, help="not closed")
c[4].metric("Failed logins", failed, border=True, help="in the selected time range")

st.subheader("Fleet status")
cols = st.columns(max(len(devs), 1))
for col, (_, d) in zip(cols, devs.iterrows(), strict=False):
    with col.container(border=True):
        row = latest[latest["device_id"] == d["device_id"]]
        st.markdown(f"**{d['device_id']}** · {d['name']}")
        if row.empty:
            st.caption("No readings in this time range")
            continue
        r = row.iloc[0]
        state = "⚠️ out of range" if r["out_of_range"] else "✅ in range"
        st.metric(
            "Latest temperature",
            f"{r['temperature_c']:.1f} °C",
            help=f"expected {r['expected_min_c']:.1f} .. {r['expected_max_c']:.1f} °C",
        )
        st.caption(
            f"{state} · expected {r['expected_min_c']:.1f}..{r['expected_max_c']:.1f} °C · "
            f"{r['device_status']} · {ui.fmt_ts(r['ts'])} UTC"
        )
        spark = tel[tel["device_id"] == d["device_id"]].tail(360)
        fig = go.Figure(
            go.Scatter(
                x=spark["ts"],
                y=spark["temperature_c"],
                mode="lines",
                line={"color": colors[d["device_id"]], "width": 2},
                hovertemplate="%{x|%H:%M} · %{y:.1f} °C<extra></extra>",
            )
        )
        fig.add_hrect(
            y0=r["expected_min_c"], y1=r["expected_max_c"], fillcolor=ctx.pal.band, line_width=0
        )
        style(fig, ctx.pal, height=110, legend=False)
        fig.update_layout(margin={"l": 0, "r": 0, "t": 4, "b": 0})
        fig.update_xaxes(visible=False)
        fig.update_yaxes(visible=False)
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False}, theme=None)

left, right = st.columns([2, 3])
with left:
    st.subheader("Open alerts by severity")
    counts = open_alerts["severity"].value_counts()
    levels = [s for s in SEVERITY_ORDER if s != "INFO"]
    fig = go.Figure(
        go.Bar(
            x=[int(counts.get(s, 0)) for s in levels],
            y=[ui.severity_label(s) for s in levels],
            orientation="h",
            marker={"color": [SEVERITY_COLORS[s] for s in levels], "cornerradius": 4},
            text=[int(counts.get(s, 0)) for s in levels],
            textposition="outside",
            hovertemplate="%{y}: %{x} open<extra></extra>",
        )
    )
    style(fig, ctx.pal, height=230, legend=False)
    fig.update_traces(cliponaxis=False)
    fig.update_yaxes(autorange="reversed", showgrid=False, automargin=True)
    fig.update_xaxes(
        showgrid=False, visible=False, range=[0, max(1, counts.max() if len(counts) else 1) * 1.2]
    )
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False}, theme=None)
    st.page_link("views/alerts.py", label="Open the alert queue", icon="🚨")

with right:
    st.subheader("Open incidents")
    if open_inc.empty:
        st.info("No open incidents. Correlation groups related alerts into incidents.")
    else:
        view = open_inc.assign(
            severity=open_inc["severity"].map(ui.severity_label),
            status=open_inc["status"].map(ui.status_label),
        )[["incident_id", "first_seen", "severity", "confidence", "status", "title"]]
        st.dataframe(
            view.head(8),
            hide_index=True,
            width="stretch",
            column_config={
                "incident_id": "Incident",
                "first_seen": st.column_config.DatetimeColumn(
                    "First seen (UTC)", format="YYYY-MM-DD HH:mm"
                ),
                "severity": "Severity",
                "confidence": st.column_config.ProgressColumn(
                    "Confidence", min_value=0, max_value=100, format="%d"
                ),
                "status": "Status",
                "title": "Title",
            },
        )
        st.page_link("views/incidents.py", label="Investigate incidents", icon="🔎")

st.subheader("Latest alerts")
recent = alerts.sort_values("first_seen", ascending=False).head(8)
if recent.empty:
    st.info("No alerts yet.")
else:
    st.dataframe(
        recent.assign(
            severity=recent["severity"].map(ui.severity_label),
            status=recent["status"].map(ui.status_label),
        )[
            [
                "alert_id",
                "first_seen",
                "severity",
                "rule_id",
                "device_id",
                "user",
                "status",
                "title",
            ]
        ],
        hide_index=True,
        width="stretch",
        column_config={
            "alert_id": "Alert",
            "first_seen": st.column_config.DatetimeColumn("Time (UTC)", format="YYYY-MM-DD HH:mm"),
            "severity": "Severity",
            "rule_id": "Rule",
            "device_id": "Fridge",
            "user": "Associated user",
            "status": "Status",
            "title": "Title",
        },
    )
