"""Root-level entry points (Step 16) and the operational log in logs/."""

import importlib
import logging
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

SCRIPTS = {
    "simulator": ("simulate", ["Simulation", "SimulationSettings"]),
    "detector": ("detect", ["Detector", "Alert", "Prioritizer", "load_rules"]),
    "correlation": ("correlate", ["Correlator", "build_case"]),
    "database": ("events", ["EventStore", "import_jsonl"]),
    "notifications": ("notify", ["Notifier", "build_channels"]),
}


@pytest.mark.parametrize("name", sorted(SCRIPTS))
def test_entry_point_exports_package_api(name):
    module = importlib.import_module(name)
    for attr in SCRIPTS[name][1]:
        assert getattr(module, attr) is not None
    assert callable(module.run)


@pytest.mark.parametrize("name", sorted(SCRIPTS))
def test_entry_point_maps_to_cli_command(name, monkeypatch):
    module = importlib.import_module(name)
    seen = []
    monkeypatch.setattr(module, "main", lambda argv: seen.append(argv) or 0)
    assert module.run([]) == 0
    assert seen[0][0] == SCRIPTS[name][0]


def test_group_commands_pass_through(monkeypatch):
    import correlation
    import database
    import detector

    seen = []
    for module in (detector, correlation, database):
        monkeypatch.setattr(module, "main", lambda argv: seen.append(argv) or 0)
    detector.run(["alerts", "queue"])
    detector.run(["--db", "x.db"])
    correlation.run(["incidents", "list"])
    database.run(["list", "--status", "suspicious"])
    assert seen == [
        ["alerts", "queue"],
        ["detect", "--db", "x.db"],
        ["incidents", "list"],
        ["events", "list", "--status", "suspicious"],
    ]


def test_script_runs_from_repository_root():
    result = subprocess.run(
        [sys.executable, "simulator.py", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "--duration" in result.stdout


def test_cli_writes_operational_log(tmp_path, monkeypatch):
    from fridgeguard.__main__ import main

    monkeypatch.setenv("FRIDGEGUARD_LOG_DIR", str(tmp_path / "logs"))
    db = tmp_path / "events.db"
    assert main(["events", "--db", str(db), "stats"]) == 2  # no database yet
    for handler in logging.getLogger("fridgeguard").handlers:
        handler.flush()
    text = (tmp_path / "logs" / "fridgeguard.log").read_text(encoding="utf-8")
    assert "command='events stats' exit=2" in text
    assert str(db) not in text  # arguments are not logged


def test_log_can_be_disabled(tmp_path, monkeypatch):
    from fridgeguard.logs import setup_logging

    monkeypatch.setenv("FRIDGEGUARD_LOG_DIR", "")
    assert not [h for h in setup_logging().handlers if hasattr(h, "_fridgeguard")]
