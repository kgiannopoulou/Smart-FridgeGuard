"""Smoke tests for the development environment (Phase 1, Step 4)."""

import sqlite3

import pandas as pd
import plotly.express as px
import pytest

from fridgeguard import __version__, envcheck
from fridgeguard.__main__ import main


def test_package_version():
    assert __version__ == "0.1.0"


def test_python_version():
    ok, _ = envcheck.check_python()
    assert ok


@pytest.mark.parametrize("name", envcheck.PACKAGES)
def test_required_package_importable(name):
    ok, message = envcheck.check_package(name)
    assert ok, message


def test_sqlite_supports_json_and_append_only_triggers():
    ok, message = envcheck.check_sqlite()
    assert ok, message


def test_sqlite_wal_mode(tmp_path):
    con = sqlite3.connect(tmp_path / "test.db")
    mode = con.execute("PRAGMA journal_mode = WAL").fetchone()[0]
    con.close()
    assert mode == "wal"


def test_project_folders_exist():
    ok, message = envcheck.check_folders()
    assert ok, message


def test_pandas_and_plotly_work_together():
    df = pd.DataFrame({"device_id": ["FRIDGE-001", "FRIDGE-002"], "temperature_c": [4.1, -18.2]})
    fig = px.bar(df, x="device_id", y="temperature_c")
    assert len(fig.data) == 1


def test_cli_check_env_passes(capsys):
    assert main(["check-env"]) == 0
    assert "checks passed" in capsys.readouterr().out


def test_dashboard_renders_without_errors():
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file("../dashboard/app.py", default_timeout=30).run()
    assert not app.exception
    assert app.title[0].value == "Smart-FridgeGuard SOC dashboard"
