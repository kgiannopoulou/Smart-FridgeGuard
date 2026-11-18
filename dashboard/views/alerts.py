"""Alert management: severity, timestamps, affected fridge, associated user, status and
the triage workflow (every action is written to alert_history)."""

import plotly.graph_objects as go
import streamlit as st

from fridgeguard.dashboard import ui
from fridgeguard.dashboard.theme import SEVERITY_COLORS, SEVERITY_ORDER, style
from fridgeguard.storage.store import ALERT_STATUSES, ALERT_TRANSITIONS

ctx = ui.page("Alert management", "Triage queue: most severe open alerts first")
if ctx is None:
    st.stop()

alerts = ctx.get("alerts")
if alerts.empty:
    st.info("No alerts yet. Run `python -m fridgeguard detect`.")
    st.stop()

# ---- filters (one row) ------------------------------------------------------------------
f = st.columns([3, 3, 2, 2])
sev = f[0].multiselect(
    "Severity", SEVERITY_ORDER, default=[s for s in SEVERITY_ORDER if s != "INFO"]
)
status = f[1].multiselect(
    "Status", ALERT_STATUSES, default=["new", "under_investigation"], format_func=ui.status_label
)
fridge = f[2].selectbox("Fridge", ["All", *sorted(alerts["device_id"].dropna().unique())])
in_range = f[3].toggle("Only selected time range", value=False)

view = alerts[alerts["severity"].isin(sev) & alerts["status"].isin(status)]
if fridge != "All":
    view = view[view["device_id"] == fridge]
if in_range and ctx.since is not None:
    view = view[view["first_seen"] >= ctx.since]
view = view.sort_values(["severity_rank", "first_seen"], ascending=[False, True])

counts = view["severity"].value_counts()
c = st.columns(5)
for col, s in zip(c, SEVERITY_ORDER, strict=True):
    col.metric(ui.severity_label(s), int(counts.get(s, 0)), border=True)

# ---- alerts over time by severity -----------------------------------------------------------
per_day = alerts.assign(day=alerts["first_seen"].dt.floor("D")).groupby(["day", "severity"]).size()
fig = go.Figure()
for s in reversed(SEVERITY_ORDER):
    if s not in sev:
        continue
    series = per_day.xs(s, level="severity") if s in per_day.index.get_level_values(1) else None
    if series is None:
        continue
    fig.add_trace(
        go.Bar(
            x=series.index,
            y=series.values,
            name=ui.severity_label(s),
            marker={"color": SEVERITY_COLORS[s], "line": {"color": ctx.pal.surface, "width": 2}},
            hovertemplate=f"%{{x|%Y-%m-%d}}<br>%{{y}} {s} alerts<extra></extra>",
        )
    )
style(fig, ctx.pal, height=240)
fig.update_layout(barmode="stack", title_text="Alerts raised per day (all statuses)")
st.plotly_chart(fig, width="stretch", theme=None)

# ---- queue ------------------------------------------------------------------------------
st.subheader(f"Alerts ({len(view)})")
table = view.assign(
    severity_label=view["severity"].map(ui.severity_label),
    status_label=view["status"].map(ui.status_label),
)[
    [
        "alert_id",
        "first_seen",
        "last_seen",
        "severity_label",
        "rule_id",
        "device_id",
        "user",
        "status_label",
        "assigned_to",
        "incident_id",
        "title",
    ]
]
picked = st.dataframe(
    table,
    hide_index=True,
    width="stretch",
    on_select="rerun",
    selection_mode="single-row",
    key="alert_table",
    column_config={
        "alert_id": "Alert",
        "first_seen": st.column_config.DatetimeColumn(
            "First seen (UTC)", format="YYYY-MM-DD HH:mm"
        ),
        "last_seen": st.column_config.DatetimeColumn("Last seen (UTC)", format="YYYY-MM-DD HH:mm"),
        "severity_label": "Severity",
        "rule_id": "Rule",
        "device_id": "Affected fridge",
        "user": "Associated user",
        "status_label": "Investigation status",
        "assigned_to": "Assigned to",
        "incident_id": "Incident",
        "title": "Title",
    },
)
rows = picked.selection.rows if picked else []
if not rows:
    st.caption("Select an alert to see its evidence and to triage it.")
    st.stop()

alert = view.iloc[rows[0]]
alert_id = alert["alert_id"]
with ui.reader(ctx.db) as store:
    evidence = store.alert_evidence(alert_id)
    history = store.alert_history(alert_id)
    current = store.alert(alert_id)
    notes = store.notifications(alert_id=alert_id)

st.divider()
st.markdown(
    f"### {alert_id} {ui.severity_chip(current['severity'])}",
    unsafe_allow_html=True,
)
st.markdown(f"**{current['title']}**")
st.write(current["description"])
info = st.columns(4)
info[0].markdown(f"**Rule**  \n{current['rule_id']} {current['rule_name']}")
info[1].markdown(f"**Affected fridge**  \n{current['device_id'] or '-'}")
info[2].markdown(f"**Associated user**  \n{alert['user']}")
info[3].markdown(
    f"**Status**  \n{ui.status_label(current['status'])} · {current['assigned_to'] or 'unassigned'}"
)
locked = " (set by an analyst)" if current["severity_locked"] else ""
st.caption(
    f"Severity {current['severity']}{locked}, base {current['base_severity']}: "
    f"{current['severity_reason'] or '-'}"
)
if alert["incident_id"]:
    st.caption(f"Part of incident **{alert['incident_id']}**: see Incident investigation.")
st.page_link(
    "dashboard/views/investigation.py",
    label="Investigate this alert (L1 workflow and incident report)",
    icon="🕵️",
    query_params={"alert": alert_id},
)

sent = sum(n["status"] == "sent" for n in notes)
ev_tab, hist_tab, ntf_tab, act_tab = st.tabs(
    [
        f"Evidence ({len(evidence)})",
        f"History ({len(history)})",
        f"Notifications ({sent} sent / {len(notes)})",
        "Triage",
    ]
)
with ev_tab:
    st.dataframe(evidence, hide_index=True, width="stretch")
with hist_tab:
    if history:
        st.dataframe(history, hide_index=True, width="stretch")
    else:
        st.caption("No changes yet.")
with ntf_tab:
    if notes:
        st.dataframe(
            [
                {
                    k: n[k]
                    for k in (
                        "notification_id",
                        "ts",
                        "channel",
                        "kind",
                        "severity",
                        "status",
                        "held_back",
                        "dedup_key",
                        "reason",
                    )
                }
                for n in notes
            ],
            hide_index=True,
            width="stretch",
            column_config={
                "notification_id": "ID",
                "ts": "Activity (UTC)",
                "held_back": "Summarizes held back",
                "dedup_key": "Dedup key",
                "channel": "Channel",
                "kind": "Kind",
                "severity": "Severity",
                "status": "Status",
                "reason": "Reason",
            },
        )
        st.caption(
            "Suppressed rows are duplicates held back during the cooldown or by the rate "
            "limit; escalations are always sent (config/notifications.yaml)."
        )
    else:
        st.caption(
            "No notifications for this alert: below the channels' minimum severity, or "
            "notifications were off. `python -m fridgeguard notify run` notifies stored alerts."
        )
with act_tab:
    analyst = ui.analyst_name()
    options = ALERT_TRANSITIONS[current["status"]]
    with st.form(f"status_{alert_id}", clear_on_submit=True):
        st.markdown("**Change status**")
        new_status = st.selectbox(
            "New status",
            list(options),
            format_func=lambda s: ui.status_label(s) + (" (note required)" if options[s] else ""),
        )
        note = st.text_area("Note", placeholder="What did you check? What did you find?")
        if st.form_submit_button("Update status", type="primary"):
            if not analyst:
                st.error("Enter your analyst name in the sidebar first.")
            else:
                try:
                    ui.write(lambda s: s.set_alert_status(alert_id, new_status, analyst, note))
                    st.toast(f"{alert_id} is now {new_status}")
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
    with st.form(f"severity_{alert_id}", clear_on_submit=True):
        st.markdown("**Override severity** (stops automatic re-prioritization)")
        new_sev = st.selectbox(
            "Severity", SEVERITY_ORDER, index=SEVERITY_ORDER.index(current["severity"])
        )
        sev_note = st.text_input("Reason")
        if st.form_submit_button("Set severity"):
            if not analyst:
                st.error("Enter your analyst name in the sidebar first.")
            else:
                try:
                    ui.write(lambda s: s.set_alert_severity(alert_id, new_sev, analyst, sev_note))
                    st.toast(f"{alert_id} severity {new_sev}")
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
