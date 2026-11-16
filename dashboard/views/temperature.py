"""Temperature monitoring: history, expected ranges, abnormal readings, device comparison."""

import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

from fridgeguard.dashboard import ui
from fridgeguard.dashboard.theme import SEVERITY_COLORS, device_colors, style

ctx = ui.page(
    "Temperature monitoring",
    "Temperature history against each fridge's expected operating range",
)
if ctx is None:
    st.stop()

devs = ctx.get("devices")
all_ids = list(devs["device_id"])
colors = device_colors(all_ids, ctx.pal)
names = dict(zip(devs["device_id"], devs["name"], strict=True))

chosen = st.pills(
    "Fridges",
    all_ids,
    selection_mode="multi",
    default=all_ids,
    format_func=lambda d: f"{d} · {names[d]}",
    key="temp_devices",
)
chosen = sorted(chosen or [])
if not chosen:
    st.info("Select at least one fridge.")
    st.stop()

tel = ctx.get("telemetry", ctx.since, ctx.until, chosen)
if tel.empty:
    st.info("No readings in this time range.")
    st.stop()

# ---- 1. temperature history (small multiples: fridges and freezers have different ranges)
st.subheader("Temperature history")
st.caption(
    "Shaded band = expected operating range · dotted line = setpoint · "
    "red markers = readings outside the range"
)
fig = make_subplots(
    rows=len(chosen),
    cols=1,
    shared_xaxes=True,
    vertical_spacing=0.06,
    subplot_titles=[f"{d} · {names[d]}" for d in chosen],
)
step = max(1, len(tel) // (4000 * len(chosen)))  # keep the browser responsive on long ranges
for i, device in enumerate(chosen, start=1):
    g = tel[tel["device_id"] == device]
    if g.empty:
        continue
    shown = g.iloc[::step]
    low, high = g["expected_min_c"].iloc[-1], g["expected_max_c"].iloc[-1]
    fig.add_hrect(y0=low, y1=high, fillcolor=ctx.pal.band, line_width=0, row=i, col=1)
    fig.add_trace(
        go.Scatter(
            x=shown["ts"],
            y=shown["setpoint_c"],
            mode="lines",
            name="Setpoint",
            line={"color": ctx.pal.muted, "width": 1, "dash": "dot"},
            showlegend=i == 1,
            legendgroup="setpoint",
            hovertemplate="setpoint %{y:.1f} °C<extra></extra>",
        ),
        row=i,
        col=1,
    )
    fig.add_trace(
        go.Scatter(
            x=shown["ts"],
            y=shown["temperature_c"],
            mode="lines",
            name=device,
            line={"color": colors[device], "width": 2},
            hovertemplate=f"{device}<br>%{{x|%Y-%m-%d %H:%M}}<br>%{{y:.2f}} °C<extra></extra>",
        ),
        row=i,
        col=1,
    )
    bad = g[g["out_of_range"]]
    if not bad.empty:
        fig.add_trace(
            go.Scatter(
                x=bad["ts"],
                y=bad["temperature_c"],
                mode="markers",
                name="Out of range",
                marker={
                    "color": SEVERITY_COLORS["CRITICAL"],
                    "size": 8,
                    "line": {"color": ctx.pal.surface, "width": 2},
                },
                showlegend=i == 1,
                legendgroup="bad",
                customdata=bad[["deviation_c"]],
                hovertemplate="%{x|%Y-%m-%d %H:%M}<br>%{y:.2f} °C, %{customdata[0]:.2f} °C "
                "outside the range<extra>abnormal</extra>",
            ),
            row=i,
            col=1,
        )
    fig.update_yaxes(title_text="°C", row=i, col=1)
style(fig, ctx.pal, height=230 * len(chosen) + 40)
fig.update_annotations(font={"color": ctx.pal.ink, "size": 13}, x=0, xanchor="left")
fig.update_layout(
    hovermode="x unified",
    margin={"t": 70, "l": 64, "r": 16, "b": 40},
    legend={"yref": "container", "y": 0.995, "yanchor": "top"},
)
st.plotly_chart(fig, width="stretch", theme=None)

# ---- 2. expected operating ranges and device comparison ---------------------------------
st.subheader("Device comparison")
comparison = ctx.get("device_comparison_frame", ctx.since, ctx.until, tuple(chosen))
st.dataframe(
    comparison,
    hide_index=True,
    width="stretch",
    column_config={
        "device_id": "Fridge",
        "name": "Name",
        "expected_range": "Expected range",
        "readings": "Readings",
        "min_c": st.column_config.NumberColumn("Min °C", format="%.1f"),
        "mean_c": st.column_config.NumberColumn("Mean °C", format="%.1f"),
        "max_c": st.column_config.NumberColumn("Max °C", format="%.1f"),
        "in_range_pct": st.column_config.ProgressColumn(
            "Time in range", min_value=0, max_value=100, format="%.1f %%"
        ),
        "minutes_out": "Minutes out of range",
        "excursions": "Excursions",
        "latest_c": st.column_config.NumberColumn("Latest °C", format="%.1f"),
        "latest_status": "Status",
    },
)

dist = go.Figure()
for device in chosen:
    g = tel[tel["device_id"] == device]
    if g.empty:
        continue
    low, high = g["expected_min_c"].iloc[-1], g["expected_max_c"].iloc[-1]
    # position within the expected range: 0 % = lower limit, 100 % = upper limit
    dist.add_trace(
        go.Box(
            x=100 * (g["temperature_c"] - low) / (high - low),
            name=device,
            marker_color=colors[device],
            line={"width": 1.5},
            boxpoints=False,
            hovertemplate=f"{device}<br>%{{x:.0f}} %% of the range<extra></extra>",
        )
    )
dist.add_vrect(x0=0, x1=100, fillcolor=ctx.pal.band, line_width=0)
style(dist, ctx.pal, height=90 + 45 * len(chosen), legend=False)
dist.update_layout(title_text="Position within the expected range")
dist.update_xaxes(title_text="0 % = lower limit · 100 % = upper limit", ticksuffix=" %")
st.plotly_chart(dist, width="stretch", theme=None)

# ---- 3. abnormal readings ---------------------------------------------------------------------
st.subheader("Abnormal temperature readings")
exc = ctx.get("excursions_frame", ctx.since, ctx.until, tuple(chosen))
if exc.empty:
    st.success("No readings outside the expected range in this time range.")
else:
    st.caption(
        f"{len(exc)} excursions (continuous runs outside the range). Short ones are usually "
        "door openings; DET-003 alerts after 15 minutes."
    )
    st.dataframe(
        exc.sort_values("start", ascending=False),
        hide_index=True,
        width="stretch",
        column_config={
            "device_id": "Fridge",
            "start": st.column_config.DatetimeColumn("Start (UTC)", format="YYYY-MM-DD HH:mm"),
            "end": st.column_config.DatetimeColumn("End (UTC)", format="YYYY-MM-DD HH:mm"),
            "minutes": "Minutes",
            "readings": "Readings",
            "worst_c": st.column_config.NumberColumn("Worst °C", format="%.1f"),
            "max_deviation_c": st.column_config.NumberColumn("Beyond range °C", format="%.2f"),
        },
    )
    with st.expander("All abnormal readings"):
        bad = tel[tel["out_of_range"]].sort_values("ts", ascending=False)
        st.dataframe(
            bad[
                [
                    "reading_id",
                    "ts",
                    "device_id",
                    "temperature_c",
                    "expected_min_c",
                    "expected_max_c",
                    "deviation_c",
                    "device_status",
                    "door_open",
                ]
            ],
            hide_index=True,
            width="stretch",
        )
