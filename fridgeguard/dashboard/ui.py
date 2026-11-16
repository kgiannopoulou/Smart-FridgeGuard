"""Streamlit helpers shared by the dashboard pages: database choice, sidebar filters,
cached data loading, severity labels and the audited write actions."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

from fridgeguard.config import PROJECT_ROOT
from fridgeguard.dashboard import data
from fridgeguard.dashboard.theme import (
    SEVERITY_COLORS,
    SEVERITY_ICONS,
    STATUS_ICONS,
    Palette,
    palette,
)
from fridgeguard.storage import EventStore

DEFAULT_DB = PROJECT_ROOT / "data" / "fridgeguard.db"
RANGES = {
    "Last 6 hours": timedelta(hours=6),
    "Last 24 hours": timedelta(hours=24),
    "Last 3 days": timedelta(days=3),
    "Last 7 days": timedelta(days=7),
    "All data": None,
}


def db_path() -> Path:
    return Path(os.environ.get("FRIDGEGUARD_DB") or DEFAULT_DB)


def _version(path: Path) -> float:
    """Changes whenever the database (or its WAL) is written: the cache key."""
    stamps = [p.stat().st_mtime for p in (path, Path(f"{path}-wal")) if p.exists()]
    return max(stamps, default=0.0)


@contextmanager
def reader(path: Path) -> Iterator[EventStore]:
    store = EventStore(path, read_only=True)
    try:
        yield store
    finally:
        store.close()


# ---- cached loaders (keyed on path + database version) -------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def load(name: str, path: str, version: float, *args) -> object:
    """Run ``fridgeguard.dashboard.data.<name>(store, *args)`` with caching."""
    with reader(Path(path)) as store:
        if name in ("security_events",):
            return getattr(data, name)(store, site(), *args)
        return getattr(data, name)(store, *args)


@st.cache_resource
def site() -> data.Site:
    return data.Site.from_config()


@dataclass
class Context:
    db: Path
    version: float
    site: data.Site
    pal: Palette
    since: datetime | None
    until: datetime | None
    bounds: tuple[datetime, datetime]

    def get(self, name: str, *args):
        return load(name, str(self.db), self.version, *args)


def page(title: str, caption: str) -> Context | None:
    """Page header + sidebar. Returns None (after explaining) when there is no data."""
    pal = palette(getattr(st.context.theme, "type", None))
    st.markdown(_CSS, unsafe_allow_html=True)
    st.title(title)
    st.caption(caption)
    path = db_path()
    if not path.exists():
        st.warning(
            f"No event database at `{path}`. Generate data first:\n\n"
            "```\npython -m fridgeguard simulate --duration 3d --faults-per-day 0.5"
            " --show none\n```"
        )
        return None
    version = _version(path)
    bounds = load("data_bounds", str(path), version)
    if bounds is None:
        st.info("The event database is empty. Run the simulation to generate events.")
        return None
    s = site()
    with st.sidebar:
        st.markdown(f"**{s.name}**")
        st.caption(f"Database: `{path.name}`  \nMaintenance window: {s.maintenance_text}")
        choice = st.selectbox("Time range", list(RANGES), index=1, key="time_range")
        st.caption(
            f"Data from {bounds[0]:%Y-%m-%d %H:%M} to {bounds[1]:%Y-%m-%d %H:%M} UTC. "
            "Ranges count back from the newest record."
        )
        if st.button("Refresh data", width="stretch"):
            st.cache_data.clear()
            st.rerun()
    span = RANGES[choice]
    since = bounds[1] - span if span else None
    return Context(path, version, s, pal, since, bounds[1], bounds)


# ---- labels -----------------------------------------------------------------------------
def severity_label(sev: str) -> str:
    return f"{SEVERITY_ICONS.get(sev, '')} {sev}"


def status_label(status: str) -> str:
    return f"{STATUS_ICONS.get(status, '')} {status.replace('_', ' ')}"


def severity_chip(sev: str) -> str:
    """Inline HTML chip: status colour + icon + name (never colour alone)."""
    color = SEVERITY_COLORS.get(sev, "#898781")
    ink = "#0b0b0b" if sev in ("MEDIUM", "HIGH") else "#ffffff"
    return (
        f'<span class="fg-chip" style="background:{color};color:{ink}">'
        f"{SEVERITY_ICONS.get(sev, '')} {sev}</span>"
    )


def fmt_ts(ts) -> str:
    if ts is None or (isinstance(ts, float) and pd.isna(ts)):
        return "-"
    return pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def analyst_name() -> str:
    default = os.environ.get("FRIDGEGUARD_ANALYST", "")
    return st.sidebar.text_input("Analyst name", value=default, key="analyst").strip()


# ---- audited writes ---------------------------------------------------------------------
def write(action, *args, **kwargs):
    """Open the database for writing just for this action, then refresh cached data."""
    store = EventStore(db_path())
    try:
        return action(store, *args, **kwargs)
    finally:
        store.close()
        st.cache_data.clear()


_CSS = """
<style>
.fg-chip { display:inline-block; padding:2px 10px; border-radius:999px; font-weight:600;
           font-size:0.85rem; letter-spacing:0.02em; }
.fg-kv { color: var(--fg-muted, #898781); font-size:0.85rem; }
div[data-testid="stMetric"] { border-radius: 10px; }
</style>
"""
