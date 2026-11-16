"""Incident investigation: event timeline, related alerts, evidence collected, analyst
findings and recommended response for one correlated incident."""

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from fridgeguard.dashboard import data, ui
from fridgeguard.dashboard.theme import SEVERITY_COLORS, device_colors, style
from fridgeguard.storage.store import INCIDENT_STATUSES, INCIDENT_VERDICTS

ctx = ui.page(
    "Incident investigation",
    "Correlated incidents: related alerts and events grouped for one investigation",
)
if ctx is None:
    st.stop()

incidents = ctx.get("incidents")
if incidents.empty:
    st.info(
        "No incidents. Correlation groups related alerts into incidents: "
        "`python -m fridgeguard correlate`."
    )
    st.stop()

f = st.columns([2, 2, 5])
show_closed = f[0].toggle("Include closed", value=False)
pool = incidents if show_closed else incidents[incidents["status"] != "closed"]
if pool.empty:
    st.success("Every incident is closed.")
    st.stop()
labels = {
    r["incident_id"]: f"{ui.severity_label(r['severity'])} · {r['incident_id']} · {r['title']}"
    for _, r in pool.iterrows()
}
wanted = st.query_params.get("incident")
ids = list(labels)
incident_id = f[2].selectbox(
    "Incident",
    ids,
    index=ids.index(wanted) if wanted in ids else 0,
    format_func=labels.get,
)
st.query_params["incident"] = incident_id

with ui.reader(ctx.db) as store:
    inc = data.incident_detail(store, incident_id)
    context = data.incident_context(store, inc)

st.markdown(f"## {inc['incident_id']} {ui.severity_chip(inc['severity'])}", unsafe_allow_html=True)
st.markdown(f"**{inc['title']}**")
st.write(inc["description"])

c = st.columns(3)
c[0].metric(
    "Confidence",
    f"{inc['confidence']} / 100",
    f"{inc['confidence_level']} confidence",
    delta_color="off",
    delta_arrow="off",
    border=True,
    help="How strongly the evidence supports a real attack (not how bad it would be)",
)
c[1].metric(
    "Status",
    inc["status"],
    f"verdict: {inc['verdict'].replace('_', ' ')}",
    delta_color="off",
    delta_arrow="off",
    border=True,
)
c[2].metric("Alerts · records", f"{inc['alert_count']} · {inc['record_count']}", border=True)
st.caption(f"Pattern **{inc['pattern_id']}** {inc['pattern_name']}")
ent = inc["entities"]
st.caption(
    f"First seen {inc['first_seen']} · last seen {inc['last_seen']} · "
    f"fridges {', '.join(ent.get('devices', [])) or '-'} · "
    f"users {', '.join(ent.get('users', [])) or '-'} · "
    f"source IPs {', '.join(ent.get('source_ips', [])) or '-'}"
)

tl, rel, evid, find, resp = st.tabs(
    [
        "Event timeline",
        f"Related alerts ({len(inc['alerts'])})",
        "Evidence collected",
        f"Analyst findings ({len(inc['reviews'])})",
        "Recommended response",
    ]
)

members: pd.DataFrame = inc["members"]

# ---- 1. event timeline ------------------------------------------------------------------
with tl:
    lanes = {"Alert": 2, "Security event": 1, "Telemetry": 0}
    fig = go.Figure()
    for lane in lanes:
        g = members[members["type"] == lane]
        if g.empty:
            continue
        if lane == "Alert":
            colors = [SEVERITY_COLORS.get(s, ctx.pal.muted) for s in g["state"]]
            symbol = "diamond"
        elif lane == "Security event":
            colors = [
                SEVERITY_COLORS["HIGH"] if s in ("suspicious", "malicious") else ctx.pal.series[0]
                for s in g["state"]
            ]
            symbol = "circle"
        else:
            colors = ctx.pal.series[2]
            symbol = "square"
        fig.add_trace(
            go.Scatter(
                x=g["ts"],
                y=[lane] * len(g),
                mode="markers",
                name=lane,
                marker={
                    "size": 13,
                    "color": colors,
                    "symbol": symbol,
                    "line": {"color": ctx.pal.surface, "width": 2},
                },
                customdata=g[["record_id", "what", "note"]],
                hovertemplate="<b>%{customdata[0]}</b> %{x|%H:%M:%S}<br>%{customdata[1]}"
                "<br><i>%{customdata[2]}</i><extra></extra>",
            )
        )
    for st_ in inc["steps"]:
        if st_["ts"]:
            fig.add_vline(
                x=pd.Timestamp(st_["ts"]), line={"color": ctx.pal.axis, "width": 1, "dash": "dot"}
            )
    style(fig, ctx.pal, height=240, legend=False)
    fig.update_layout(title_text="Records in time order")
    fig.update_yaxes(categoryorder="array", categoryarray=list(reversed(lanes)), showgrid=False)
    st.plotly_chart(fig, width="stretch", theme=None)
    st.caption(
        "◆ alert (severity colour) · ● security event (orange = suspicious) · ■ reading · "
        "dotted lines = matched sequence steps"
    )

    if not context.empty:
        tcolors = device_colors(sorted(context["device_id"].unique()), ctx.pal)
        temp = go.Figure()
        for device, g in context.groupby("device_id"):
            temp.add_hrect(
                y0=g["expected_min_c"].iloc[-1],
                y1=g["expected_max_c"].iloc[-1],
                fillcolor=ctx.pal.band,
                line_width=0,
            )
            temp.add_trace(
                go.Scatter(
                    x=g["ts"],
                    y=g["temperature_c"],
                    mode="lines",
                    name=device,
                    line={"color": tcolors[device], "width": 2},
                    hovertemplate=f"{device} %{{x|%H:%M}} · %{{y:.2f}} °C<extra></extra>",
                )
            )
        changes = members[
            (members["type"] == "Security event") & members["what"].str.contains("->", regex=False)
        ]
        for _, ch in changes.iterrows():
            temp.add_vline(
                x=ch["ts"], line={"color": SEVERITY_COLORS["HIGH"], "width": 1.5, "dash": "dash"}
            )
        style(temp, ctx.pal, height=260, legend=context["device_id"].nunique() > 1)
        temp.update_layout(
            title_text="Temperature around the incident (dashed = configuration change)",
            hovermode="x unified",
        )
        temp.update_yaxes(title_text="°C")
        st.plotly_chart(temp, width="stretch", theme=None)

    if inc["steps"]:
        st.markdown("**Attack sequence**")
        for s in inc["steps"]:
            mark = "✅" if s["record_id"] else ("➖" if s["optional"] else "❌")
            when = (
                f" · {s['ts']}" if s["ts"] else (" · not seen (optional)" if s["optional"] else "")
            )
            st.markdown(
                f"{mark} {s['label']} {f'`{rid}`' if (rid := s['record_id']) else ''}{when}"
            )

    st.dataframe(
        members[
            ["ts", "record_id", "type", "device_id", "user", "source_ip", "what", "state", "note"]
        ],
        hide_index=True,
        width="stretch",
        column_config={
            "ts": st.column_config.DatetimeColumn("Time (UTC)", format="YYYY-MM-DD HH:mm:ss"),
            "record_id": "Record",
            "type": "Type",
            "device_id": "Fridge",
            "user": "User",
            "source_ip": "Source IP",
            "what": "Detail",
            "state": "Status",
            "note": "Why it belongs to the incident",
        },
    )

# ---- 2. related alerts -----------------------------------------------------------------
with rel:
    al = pd.DataFrame(inc["alerts"])
    if al.empty:
        st.caption("No alerts.")
    else:
        al = al.assign(
            severity=al["severity"].map(ui.severity_label), status=al["status"].map(ui.status_label)
        )
        st.dataframe(
            al[
                [
                    "alert_id",
                    "first_seen",
                    "severity",
                    "rule_id",
                    "rule_name",
                    "device_id",
                    "status",
                    "assigned_to",
                    "title",
                ]
            ],
            hide_index=True,
            width="stretch",
            column_config={
                "alert_id": "Alert",
                "first_seen": "First seen (UTC)",
                "rule_id": "Rule",
                "rule_name": "Rule name",
                "device_id": "Fridge",
                "assigned_to": "Assigned to",
            },
        )
        st.page_link("views/alerts.py", label="Triage these alerts in Alert management", icon="🚨")

# ---- 3. evidence collected ---------------------------------------------------------------
with evid:
    left, right = st.columns(2)
    with left:
        st.markdown("**Why the confidence is what it is**")
        factors = pd.DataFrame(inc["confidence_factors"], columns=["points", "reason"])
        st.dataframe(factors, hide_index=True, width="stretch")
        st.caption(
            "Confidence says how strongly the evidence supports a real attack; "
            "severity says how bad it would be."
        )
    with right:
        st.markdown("**Entities involved**")
        st.dataframe(
            pd.DataFrame(
                [(k.replace("_", " "), ", ".join(v)) for k, v in ent.items() if v],
                columns=["entity", "values"],
            ),
            hide_index=True,
            width="stretch",
        )
        st.markdown(
            f"**MITRE ATT&CK:** {', '.join(inc['attack_ids']) or '-'}  \n"
            f"**Requirements:** {', '.join(inc['implements']) or '-'}"
        )
    st.markdown("**How the records are connected**")
    st.dataframe(
        pd.DataFrame(inc["links"], columns=["from", "to", "link"]), hide_index=True, width="stretch"
    )
    counts = members["type"].value_counts()
    st.caption(" · ".join(f"{n} {t.lower()}s" for t, n in counts.items()))

# ---- 4. analyst findings -----------------------------------------------------------------
with find:
    if inc["reviews"]:
        st.dataframe(pd.DataFrame(inc["reviews"]), hide_index=True, width="stretch")
    else:
        st.info("No analyst review yet: verdict **unverified**.")
    analyst = ui.analyst_name()
    with st.form(f"review_{incident_id}", clear_on_submit=True):
        st.markdown("**Record findings**")
        cols = st.columns(2)
        status = cols[0].selectbox(
            "Status", INCIDENT_STATUSES, index=INCIDENT_STATUSES.index(inc["status"])
        )
        verdict = cols[1].selectbox(
            "Verdict",
            INCIDENT_VERDICTS,
            index=INCIDENT_VERDICTS.index(inc["verdict"]),
            format_func=lambda v: v.replace("_", " "),
        )
        note = st.text_area(
            "Findings", placeholder="What was verified, with whom, and the conclusion"
        )
        if st.form_submit_button("Save review", type="primary"):
            if not analyst:
                st.error("Enter your analyst name in the sidebar first.")
            elif not note.strip():
                st.error("Findings are required.")
            else:
                ui.write(
                    lambda s: s.add_incident_review(
                        incident_id, analyst, status, verdict, note.strip()
                    )
                )
                st.toast(f"{incident_id}: {status}, {verdict}")
                st.rerun()

# ---- 5. recommended response ----------------------------------------------------------------
with resp:
    left, right = st.columns(2)
    with left:
        st.markdown("**Recommended response**")
        for i, r in enumerate(inc["response"], start=1):
            st.markdown(f"{i}. {r}")
    with right:
        st.markdown("**Verify before acting**")
        for i, q in enumerate(inc["questions"]):
            st.checkbox(q, key=f"q_{incident_id}_{i}")
    st.download_button(
        "Download investigation report (Markdown)",
        data=data.incident_report(inc),
        file_name=f"{incident_id}.md",
        mime="text/markdown",
        icon="📄",
    )
