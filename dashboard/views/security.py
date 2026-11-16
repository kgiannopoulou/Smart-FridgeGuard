"""Security monitoring: logins, configuration changes, suspicious IPs, unusual access times."""

import plotly.graph_objects as go
import streamlit as st

from fridgeguard.dashboard import data, ui
from fridgeguard.dashboard.theme import style

ctx = ui.page(
    "Security monitoring",
    "Authentication and configuration audit trail from the refrigerator controllers",
)
if ctx is None:
    st.stop()

sec = ctx.get("security_events", ctx.since, ctx.until)
if sec.empty:
    st.info("No security events in this time range.")
    st.stop()

failed = sec[sec["event_type"] == "LOGIN_FAILURE"]
ok = sec[sec["event_type"] == "LOGIN_SUCCESS"]
changes = sec[sec["category"] == "configuration"]
ips = data.suspicious_ips(sec)
unusual = data.unusual_access(sec)

c = st.columns(5)
c[0].metric("Failed logins", len(failed), border=True)
c[1].metric("Successful logins", len(ok), border=True)
c[2].metric("Configuration changes", len(changes), border=True)
c[3].metric(
    "Suspicious source IPs", len(ips), border=True, help="off the allow-list or with failed logins"
)
c[4].metric(
    "Unusual-time access",
    len(unusual),
    border=True,
    help="store closed, or privileged outside maintenance",
)

COMMON = {
    "event_id": "Event",
    "ts": st.column_config.DatetimeColumn("Time (UTC)", format="YYYY-MM-DD HH:mm:ss"),
    "device_id": "Fridge",
    "event_type": "Type",
    "user": "User",
    "role": "Role",
    "source_ip": "Source IP",
    "status": "Status",
}


def status_view(df):
    icons = {"normal": "· normal", "suspicious": "⚠️ suspicious", "malicious": "⛔ malicious"}
    return df.assign(status=df["status"].map(icons))


# ---- authentication activity per hour -------------------------------------------------
st.subheader("Authentication activity")
span = (ctx.until - (ctx.since or ctx.bounds[0])).total_seconds() / 3600
bucket, bucket_text = ("h", "hour") if span <= 48 else ("6h", "6 hours")
per_hour = data.auth_per_hour(sec, bucket)
fig = go.Figure()
for outcome, color in (("Successful", ctx.pal.series[0]), ("Failed", ctx.pal.series[1])):
    g = per_hour[per_hour["outcome"] == outcome]
    fig.add_trace(
        go.Bar(
            x=g["hour"],
            y=g["count"],
            name=f"{outcome} logins",
            marker={
                "color": color,
                "cornerradius": 4,
                "line": {"color": ctx.pal.surface, "width": 2},
            },
            hovertemplate=f"%{{x|%Y-%m-%d %H:00}}<br>%{{y}} {outcome.lower()}<extra></extra>",
        )
    )
style(fig, ctx.pal, height=280)
fig.update_layout(barmode="group", title_text=f"Logins per {bucket_text} (UTC)")
fig.update_yaxes(title_text="logins")
st.plotly_chart(fig, width="stretch", theme=None)

tab_fail, tab_ok, tab_cfg = st.tabs(
    [
        f"Failed logins ({len(failed)})",
        f"Successful logins ({len(ok)})",
        f"Configuration changes ({len(changes)})",
    ]
)
with tab_fail:
    if failed.empty:
        st.success("No failed logins in this time range.")
    else:
        st.dataframe(
            status_view(failed.sort_values("ts", ascending=False))[
                [
                    "event_id",
                    "ts",
                    "device_id",
                    "user",
                    "source_ip",
                    "reason",
                    "allowed_ip",
                    "status",
                ]
            ],
            hide_index=True,
            width="stretch",
            column_config={
                **COMMON,
                "user": "Username tried",
                "reason": "Reason",
                "allowed_ip": st.column_config.CheckboxColumn("On allow-list"),
            },
        )
with tab_ok:
    st.dataframe(
        status_view(ok.sort_values("ts", ascending=False))[
            [
                "event_id",
                "ts",
                "device_id",
                "user",
                "role",
                "source_ip",
                "session_id",
                "within_maintenance_window",
                "allowed_ip",
                "status",
            ]
        ],
        hide_index=True,
        width="stretch",
        column_config={
            **COMMON,
            "session_id": "Session",
            "within_maintenance_window": st.column_config.CheckboxColumn("In maintenance window"),
            "allowed_ip": st.column_config.CheckboxColumn("On allow-list"),
        },
    )
with tab_cfg:
    view = changes.assign(
        change=changes["previous_value"].astype(str)
        + " → "
        + changes["new_value"].astype(str)
        + " "
        + changes["unit"].fillna("")
    )
    st.dataframe(
        status_view(view.sort_values("ts", ascending=False))[
            [
                "event_id",
                "ts",
                "device_id",
                "user",
                "role",
                "parameter",
                "change",
                "result",
                "authorized",
                "within_maintenance_window",
                "source_ip",
                "status",
            ]
        ],
        hide_index=True,
        width="stretch",
        column_config={
            **COMMON,
            "parameter": "Setting",
            "change": "Previous → new",
            "result": "Result",
            "authorized": st.column_config.CheckboxColumn("Authorized"),
            "within_maintenance_window": st.column_config.CheckboxColumn("In maintenance window"),
        },
    )

# ---- suspicious IPs -------------------------------------------------------------------------
st.subheader("Suspicious IP addresses")
if ips.empty:
    st.success("Every source IP is on the allow-list and none produced failed logins.")
else:
    st.dataframe(
        ips,
        hide_index=True,
        width="stretch",
        column_config={
            "source_ip": "Source IP",
            "on_allow_list": st.column_config.CheckboxColumn("On allow-list"),
            "failed": "Failed",
            "successful": "Successful",
            "changes": "Changes",
            "usernames_tried": "Usernames tried",
            "devices": "Fridges",
            "first_seen": st.column_config.DatetimeColumn(
                "First seen (UTC)", format="YYYY-MM-DD HH:mm"
            ),
            "last_seen": st.column_config.DatetimeColumn(
                "Last seen (UTC)", format="YYYY-MM-DD HH:mm"
            ),
            "suspicious_events": "Suspicious events",
        },
    )

# ---- unusual access times -------------------------------------------------------------------
st.subheader("Unusual access times")
st.caption(
    f"Successful logins and configuration changes by local time ({ctx.site.tz.key}). "
    f"Store opening hours {ctx.site.opening_start}-{ctx.site.opening_end}; "
    f"maintenance window {ctx.site.maintenance_text}."
)
grid = data.access_heatmap(sec)
ramp = ctx.pal.ramp
heat = go.Figure(
    go.Heatmap(
        z=grid.values,
        x=[f"{h:02d}" for h in grid.columns],
        y=list(grid.index),
        colorscale=[[i / (len(ramp) - 1), c] for i, c in enumerate(ramp)],
        xgap=2,
        ygap=2,
        colorbar={"title": {"text": "events"}, "thickness": 10},
        hovertemplate="%{y} %{x}:00 local<br>%{z} logins/changes<extra></extra>",
    )
)
opening = int(ctx.site.opening_start[:2]), int(ctx.site.opening_end[:2])
for x0, x1 in ((-0.5, opening[0] - 0.5), (opening[1] - 0.5, 23.5)):
    heat.add_vrect(
        x0=x0,
        x1=x1,
        line={"color": ctx.pal.muted, "width": 1, "dash": "dot"},
        fillcolor="rgba(0,0,0,0)",
    )
style(heat, ctx.pal, height=300, legend=False)
heat.update_layout(title_text="Access by weekday and hour (dotted = store closed)")
heat.update_yaxes(autorange="reversed", showgrid=False)
heat.update_xaxes(showgrid=False, title_text="local hour")
st.plotly_chart(heat, width="stretch", theme=None)

if unusual.empty:
    st.success("No logins or changes at unusual times.")
else:
    st.dataframe(
        status_view(unusual)[
            [
                "event_id",
                "local_ts",
                "device_id",
                "event_type",
                "user",
                "role",
                "source_ip",
                "why",
                "status",
            ]
        ].assign(local_ts=unusual["local_ts"].dt.strftime("%a %Y-%m-%d %H:%M")),
        hide_index=True,
        width="stretch",
        column_config={**COMMON, "local_ts": "Local time", "why": "Why unusual"},
    )
