"""Colours and chart styling for the SOC dashboard.

Colour roles follow one rule each:

* **device identity** (categorical): a fixed hue per refrigerator, in a fixed order, so a
  filter never repaints a device;
* **severity** (state): reserved status colours, always shown with the severity name;
* **magnitude** (sequential): one blue ramp, light to dark (access heatmap).

Every chart uses one y-axis; devices with different ranges get small multiples.
"""

from __future__ import annotations

from dataclasses import dataclass

import plotly.graph_objects as go


@dataclass(frozen=True)
class Palette:
    surface: str
    page: str
    ink: str
    ink2: str
    muted: str
    grid: str
    axis: str
    band: str
    series: tuple[str, ...]
    ramp: tuple[str, ...]


DARK = Palette(
    surface="#1a1a19",
    page="#0d0d0d",
    ink="#f0efec",
    ink2="#c3c2b7",
    muted="#898781",
    grid="#2c2c2a",
    axis="#383835",
    band="rgba(57,135,229,0.10)",
    series=("#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c"),
    ramp=("#1a1a19", "#104281", "#1c5cab", "#2a78d6", "#5598e7", "#9ec5f4"),
)
LIGHT = Palette(
    surface="#fcfcfb",
    page="#f9f9f7",
    ink="#0b0b0b",
    ink2="#52514e",
    muted="#898781",
    grid="#e1e0d9",
    axis="#c3c2b7",
    band="rgba(42,120,214,0.08)",
    series=("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"),
    ramp=("#fcfcfb", "#cde2fb", "#9ec5f4", "#5598e7", "#2a78d6", "#184f95"),
)

# Status colours are fixed in both themes and never used for a series.
SEVERITY_COLORS = {
    "CRITICAL": "#d03b3b",
    "HIGH": "#ec835a",
    "MEDIUM": "#fab219",
    "LOW": "#5598e7",
    "INFO": "#898781",
}
SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
STATUS_ICONS = {
    "new": "🆕",
    "under_investigation": "🔎",
    "confirmed": "❗",
    "false_positive": "✖",
    "resolved": "✔",
    "open": "🆕",
    "investigating": "🔎",
    "closed": "✔",
}


def palette(theme_type: str | None) -> Palette:
    return LIGHT if theme_type == "light" else DARK


def device_colors(device_ids: list[str], pal: Palette) -> dict[str, str]:
    """Fixed colour per device: sorted device IDs take the categorical slots in order."""
    return {d: pal.series[i % len(pal.series)] for i, d in enumerate(sorted(device_ids))}


def style(fig: go.Figure, pal: Palette, *, height: int = 320, legend: bool = True) -> go.Figure:
    """Recessive grid and axes, surface background, hover in the theme's ink."""
    fig.update_layout(
        height=height,
        margin={"l": 64, "r": 16, "t": 48, "b": 40},
        paper_bgcolor=pal.surface,
        plot_bgcolor=pal.surface,
        font={"color": pal.ink2, "size": 12},
        title_font={"color": pal.ink, "size": 14},
        title_x=0,
        title_xanchor="left",
        hoverlabel={"bgcolor": pal.surface, "font_color": pal.ink, "bordercolor": pal.axis},
        showlegend=legend,
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.02,
            "xanchor": "right",
            "x": 1,
            "bgcolor": "rgba(0,0,0,0)",
        },
        bargap=0.25,
    )
    axis = {
        "gridcolor": pal.grid,
        "linecolor": pal.axis,
        "zerolinecolor": pal.axis,
        "tickfont": {"color": pal.muted},
        "title_font": {"color": pal.muted},
        "automargin": True,
    }
    fig.update_xaxes(**axis)
    fig.update_yaxes(**axis)
    return fig
