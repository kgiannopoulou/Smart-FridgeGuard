"""Alert investigation (Phase 3, Step 12): the L1 analyst workflow for one alert, step by
step, ending in a downloadable incident report (Markdown or PDF).

Every step shows the facts gathered from the database and, for decision steps, a
rule-based suggestion with its reasons. Only what the analyst records counts; answers
are append-only and can be revised by recording the step again."""

from datetime import UTC, datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from fridgeguard.dashboard import data, ui
from fridgeguard.dashboard.theme import SEVERITY_COLORS, style
from fridgeguard.investigation import STEP_LABELS, Settings, build_case, record, render, start
from fridgeguard.investigation.workflow import FINAL_TO_ALERT, REQUIRED_BEFORE_DOCUMENTATION
from fridgeguard.storage.store import INVESTIGATION_STEPS

ctx = ui.page(
    "Alert investigation",
    "L1 workflow: review the alert, investigate, decide, escalate and document",
)
if ctx is None:
    st.stop()


@st.cache_resource
def settings() -> Settings:
    return Settings.from_config()


alerts = ctx.get("alerts")
if alerts.empty:
    st.info("No alerts to investigate. Run `python -m fridgeguard detect`.")
    st.stop()

with ui.reader(ctx.db) as store:
    cases = {r["alert_id"]: r for r in store.investigations()}

f = st.columns([2, 6])
include_closed = f[0].toggle("Include closed alerts", value=False)
pool = (
    alerts
    if include_closed
    else alerts[alerts["status"].isin(data.OPEN_ALERT_STATUSES) | alerts["alert_id"].isin(cases)]
)
pool = pool.sort_values(["severity_rank", "first_seen"], ascending=[False, True])
if pool.empty:
    st.success("No open alerts.")
    st.stop()


def label(alert_id: str) -> str:
    r = pool.set_index("alert_id").loc[alert_id]
    case = cases.get(alert_id)
    progress = f" · {case['investigation_id']} {case['steps_done']}/8" if case else ""
    return f"{ui.severity_label(r['severity'])} · {alert_id} · {r['title']}{progress}"


ids = list(pool["alert_id"])
wanted = st.query_params.get("alert")
alert_id = f[1].selectbox(
    "Alert", ids, index=ids.index(wanted) if wanted in ids else 0, format_func=label
)
st.query_params["alert"] = alert_id

with ui.reader(ctx.db) as store:
    case = build_case(store, alert_id, settings())
a, dev = case.alert, case.device
analyst = ui.analyst_name()

st.markdown(f"## {alert_id} {ui.severity_chip(a['severity'])}", unsafe_allow_html=True)
st.markdown(f"**{a['title']}**")
inc_text = f" · part of incident **{case.incident['incident_id']}**" if case.incident else ""
st.caption(
    f"{a['rule_id']} {a['rule_name']} · detected {ui.fmt_ts(a['first_seen'])} UTC · "
    f"{ui.status_label(a['status'])} · assigned to {a['assigned_to'] or 'nobody'}{inc_text}"
)

# ---- not opened yet -------------------------------------------------------------------------
if case.investigation is None:
    st.info(
        "No investigation yet. Starting one assigns the alert to you and moves it to "
        "**under investigation**."
    )
    if st.button("Start investigation", type="primary", icon="🕵️"):
        if not analyst:
            st.error("Enter your analyst name in the sidebar first.")
        else:
            ui.write(lambda s: start(s, alert_id, analyst))
            st.rerun()

# ---- progress and the three decisions ----------------------------------------------------
done = case.steps_done
if case.investigation:
    st.progress(
        len(done) / len(INVESTIGATION_STEPS),
        text=f"{case.investigation_id}: {len(done)} of {len(INVESTIGATION_STEPS)} steps recorded"
        f" · final status **{case.final_status.replace('_', ' ')}**",
    )
m = st.columns(3)
for col, step, title in zip(
    m,
    ("authorization", "impact", "escalation"),
    ("Authorized?", "Impact", "Escalation"),
    strict=True,
):
    value, confirmed = case.decision(step)
    col.metric(
        title,
        value.replace("_", " "),
        "recorded by analyst" if confirmed else "suggested, not confirmed",
        delta_color="off",
        delta_arrow="off",
        border=True,
    )


def step_form(step: str, *, help_text: str = "", options_help: dict | None = None) -> None:
    """Record (or revise) one workflow step."""
    if case.investigation is None:
        st.caption("Start the investigation to record this step.")
        return
    entry = case.latest(step)
    if entry:
        st.success(
            f"Recorded by {entry['analyst']} at {ui.fmt_ts(entry['ts'])}"
            + (f": **{entry['decision']}**" if entry["decision"] else "")
            + f"  \n{entry['note']}"
        )
    with st.form(f"{step}_{case.investigation_id}", clear_on_submit=True):
        options = INVESTIGATION_STEPS[step]
        decision = None
        if options:
            current, _ = case.decision(step)
            decision = st.selectbox(
                "Decision",
                options,
                index=options.index(current) if current in options else 0,
                format_func=lambda o: (
                    o.replace("_", " ")
                    + (f" - {options_help[o]}" if options_help and o in options_help else "")
                ),
            )
        note = st.text_area("Notes", placeholder=help_text)
        verb = "Revise" if entry else "Record"
        if st.form_submit_button(f"{verb}: {STEP_LABELS[step]}", type="primary"):
            if not analyst:
                st.error("Enter your analyst name in the sidebar first.")
                return
            try:
                moved = ui.write(
                    lambda s: record(s, case.investigation_id, step, analyst, note, decision)
                )
            except ValueError as exc:
                st.error(str(exc))
                return
            if moved:
                st.toast(f"{alert_id} moved to {' -> '.join(moved)}")
            st.rerun()


def reasons(items: list[str]) -> None:
    st.markdown("\n".join(f"- {r}" for r in items))


def mark(step: str) -> str:
    return "✅" if step in done else "⬜"


TAB_NAMES = {
    "review_alert": "Review",
    "affected_device": "Fridge",
    "related_events": "Related events",
    "user_and_ip": "User & IP",
    "authorization": "Authorized?",
    "impact": "Impact",
    "escalation": "Escalation",
    "documentation": "Document",
}
tabs = st.tabs([f"{mark(s)} {i}. {TAB_NAMES[s]}" for i, s in enumerate(STEP_LABELS, 1)])

# 1. review the alert
with tabs[0]:
    st.markdown(f"#### 1. {STEP_LABELS['review_alert']}")
    st.write(a["description"])
    st.caption(f"Severity {a['severity']} (base {a['base_severity']}): {a['severity_reason']}")
    ev = pd.DataFrame(
        [{k: e[k] for k in ("record_id", "kind", "ts", "detail", "note")} for e in case.evidence]
    )
    st.markdown(f"**Evidence ({len(ev)})**")
    st.dataframe(
        ev,
        hide_index=True,
        width="stretch",
        column_config={
            "record_id": "Record",
            "kind": "Type",
            "ts": "Time (UTC)",
            "detail": "Detail",
            "note": "Why it is evidence",
        },
    )
    if case.alert_history:
        with st.expander(f"Triage history ({len(case.alert_history)})"):
            st.dataframe(pd.DataFrame(case.alert_history), hide_index=True, width="stretch")
    st.markdown("**Questions to answer during the investigation**")
    reasons(case.playbook.get("verify", []))
    step_form("review_alert", help_text="Is the alert valid? What exactly triggered it?")

# 2. affected refrigerator
with tabs[1]:
    st.markdown(f"#### 2. {STEP_LABELS['affected_device']}")
    if dev is None:
        st.caption("The alert is not tied to one refrigerator.")
    else:
        c = st.columns(4)
        c[0].metric("Fridge", dev["device_id"], dev["name"], delta_color="off", delta_arrow="off")
        c[1].metric("Expected range", dev["expected_range"])
        c[2].metric("Minutes out of range", dev["minutes_out"])
        c[3].metric("Longest telemetry gap", f"{dev['longest_gap_min']} min")
        st.caption(
            f"{dev['location']} · type {dev['device_type']}"
            + (" · **safety-critical stock**" if dev["critical"] else "")
            + f" · allowed source IPs {', '.join(dev['allowed_ips'])}"
        )
        with ui.reader(ctx.db) as store:
            tel = data.telemetry(
                store,
                pd.Timestamp(dev["window"][0]).to_pydatetime(),
                pd.Timestamp(dev["window"][1]).to_pydatetime(),
                [dev["device_id"]],
            )
        if not tel.empty:
            fig = go.Figure()
            fig.add_hrect(
                y0=tel["expected_min_c"].iloc[-1],
                y1=tel["expected_max_c"].iloc[-1],
                fillcolor=ctx.pal.band,
                line_width=0,
            )
            fig.add_trace(
                go.Scatter(
                    x=tel["ts"],
                    y=tel["temperature_c"],
                    mode="lines",
                    name=dev["device_id"],
                    line={"color": ctx.pal.series[0], "width": 2},
                    hovertemplate="%{x|%H:%M} · %{y:.2f} °C<extra></extra>",
                )
            )
            fig.add_vline(
                x=pd.Timestamp(a["first_seen"]),
                line={"color": SEVERITY_COLORS.get(a["severity"]), "width": 1.5, "dash": "dash"},
            )
            style(fig, ctx.pal, height=260, legend=False)
            fig.update_layout(title_text="Temperature around the alert (dashed = alert raised)")
            fig.update_yaxes(title_text="°C")
            st.plotly_chart(fig, width="stretch", theme=None)
    step_form(
        "affected_device",
        help_text="Which fridge, what does it hold, what state is it in now?",
    )

# 3. related events
with tabs[2]:
    st.markdown(f"#### 3. {STEP_LABELS['related_events']}")
    if case.related_events:
        rel = pd.DataFrame(case.related_events)[
            [
                "ts_device",
                "event_id",
                "event_type",
                "user",
                "source_ip",
                "detail",
                "status",
                "in_evidence",
            ]
        ]
        st.dataframe(
            rel,
            hide_index=True,
            width="stretch",
            column_config={
                "ts_device": "Time (UTC)",
                "event_id": "Event",
                "event_type": "Type",
                "source_ip": "Source IP",
                "in_evidence": st.column_config.CheckboxColumn("Evidence"),
            },
        )
    else:
        st.caption("No security events on the device or from the same sources in the window.")
    if case.related_alerts:
        st.markdown("**Other alerts on the fridge in the window**")
        st.dataframe(
            pd.DataFrame(case.related_alerts)[
                ["alert_id", "first_seen", "severity", "rule_id", "status", "title"]
            ],
            hide_index=True,
            width="stretch",
        )
    if dev:
        st.caption(f"Window: {dev['window'][0]} to {dev['window'][1]} (UTC)")
    step_form(
        "related_events",
        help_text="What happened before and after? Same session, same IP, other alerts?",
    )

# 4. user and source IP
with tabs[3]:
    st.markdown(f"#### 4. {STEP_LABELS['user_and_ip']}")
    if case.users:
        st.markdown(f"**Users** (activity in the last {settings().history.days} days)")
        st.dataframe(pd.DataFrame(case.users), hide_index=True, width="stretch")
    if case.source_ips:
        st.markdown("**Source IPs**")
        st.dataframe(pd.DataFrame(case.source_ips), hide_index=True, width="stretch")
    if not case.users and not case.source_ips:
        st.caption("No user or source IP behind this alert.")
    step_form(
        "user_and_ip",
        help_text="Is the account real and used as usual? Is the IP known? Did you contact "
        "the account owner?",
    )

# 5. authorization
with tabs[4]:
    st.markdown(f"#### 5. {STEP_LABELS['authorization']}")
    st.markdown(f"**Suggested: {case.authorization.decision.replace('_', ' ')}**, because:")
    reasons(case.authorization.reasons)
    step_form(
        "authorization",
        help_text="Your conclusion and how you verified it (work order, call with the owner...)",
    )

# 6. impact
with tabs[5]:
    st.markdown(f"#### 6. {STEP_LABELS['impact']}")
    st.markdown(f"**Suggested: {case.impact.decision}**, because:")
    reasons(case.impact.reasons)
    step_form(
        "impact",
        help_text="What could this have affected: settings, temperature, stock, other fridges?",
        options_help=settings().impact_levels,
    )

# 7. escalation
with tabs[6]:
    st.markdown(f"#### 7. {STEP_LABELS['escalation']}")
    st.markdown(f"**Suggested: {case.escalation.decision.replace('_', ' ')}**, because:")
    reasons(case.escalation.reasons)
    st.dataframe(
        pd.DataFrame(
            [{"team": k, "name": v["name"], "when": v["when"]} for k, v in settings().teams.items()]
        ),
        hide_index=True,
        width="stretch",
    )
    step_form("escalation", help_text="Who did you hand it to, when, and with what request?")

# 8. documentation
with tabs[7]:
    st.markdown(f"#### 8. {STEP_LABELS['documentation']}")
    missing = [s for s in REQUIRED_BEFORE_DOCUMENTATION if s not in done]
    if missing:
        st.warning("Record these decisions first: " + ", ".join(STEP_LABELS[s] for s in missing))
    st.markdown("**What the final status does to the alert**")
    st.dataframe(
        pd.DataFrame(
            [
                {"final status": k, "alert moves to": " -> ".join(v) or "(stays open)"}
                for k, v in FINAL_TO_ALERT.items()
            ]
        ),
        hide_index=True,
        width="stretch",
    )
    step_form("documentation", help_text="Summary of the investigation and its conclusion")

# ---- timeline and report ------------------------------------------------------------------
st.divider()
st.subheader("Event timeline")
st.dataframe(
    pd.DataFrame(case.timeline),
    hide_index=True,
    width="stretch",
    column_config={
        "ts": "Time (UTC)",
        "source": "Source",
        "record": "Record",
        "detail": "What happened",
        "status": "Status",
    },
)

st.subheader("Incident report")
st.caption(
    "Fills the SOC template: initial alert, investigation performed, evidence, timeline, "
    "findings, impact, recommended response, escalation and final status. Decisions not yet "
    "recorded appear as *suggested, not confirmed*."
)
now = datetime.now(UTC)
name = case.investigation_id or alert_id
d = st.columns([1, 1, 4])
d[0].download_button(
    "Markdown",
    data=render(case, "md", now),
    file_name=f"{name}.md",
    mime="text/markdown",
    icon="📄",
    width="stretch",
)
d[1].download_button(
    "PDF",
    data=render(case, "pdf", now),
    file_name=f"{name}.pdf",
    mime="application/pdf",
    icon="📕",
    width="stretch",
)
with st.expander("Preview (Markdown)"):
    st.markdown(render(case, "md", now).decode("utf-8"))
