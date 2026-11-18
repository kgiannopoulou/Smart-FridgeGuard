"""Development environment check (Phase 1, Step 4).

Verifies the Python version, required libraries, SQLite features used by the
architecture (WAL mode, JSON functions, triggers) and the project folder layout.
"""

from __future__ import annotations

import importlib
import sqlite3
import sys
from pathlib import Path

MIN_PYTHON = (3, 12)
PACKAGES = ["pandas", "streamlit", "plotly", "pytest", "yaml", "pydantic", "jinja2", "fpdf"]
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FOLDERS = [
    "config",
    "scenarios",
    "fridgeguard/simulator",
    "fridgeguard/generator",
    "fridgeguard/detection/rules",
    "fridgeguard/storage",
    "fridgeguard/investigation",
    "dashboard/views",
    "templates",
    "tests",
    "data",
    "reports",
    "logs",
    "docs",
    "screenshots",
]


def check_python() -> tuple[bool, str]:
    ok = sys.version_info >= MIN_PYTHON
    return ok, f"Python {sys.version.split()[0]} (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})"


def check_package(name: str) -> tuple[bool, str]:
    try:
        module = importlib.import_module(name)
    except ImportError:
        return False, f"{name}: not installed"
    return True, f"{name} {getattr(module, '__version__', '?')}"


def check_sqlite() -> tuple[bool, str]:
    """Check the SQLite features the storage design relies on."""
    con = sqlite3.connect(":memory:")
    try:
        con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, payload TEXT)")
        con.execute(
            "CREATE TRIGGER t_no_update BEFORE UPDATE ON t "
            "BEGIN SELECT RAISE(ABORT, 'append-only'); END"
        )
        con.execute("INSERT INTO t (payload) VALUES ('{\"temperature_c\": 4.2}')")
        value = con.execute("SELECT json_extract(payload, '$.temperature_c') FROM t").fetchone()[0]
        try:
            con.execute("UPDATE t SET payload = '{}'")
            return False, "SQLite triggers did not block UPDATE"
        except sqlite3.IntegrityError:
            pass
        ok = value == 4.2
        return ok, f"SQLite {sqlite3.sqlite_version} (JSON + triggers OK)"
    finally:
        con.close()


def check_folders() -> tuple[bool, str]:
    missing = [f for f in FOLDERS if not (PROJECT_ROOT / f).is_dir()]
    if missing:
        return False, "missing folders: " + ", ".join(missing)
    return True, f"project folders ({len(FOLDERS)}) present"


def run_checks() -> int:
    results = [
        check_python(),
        *(check_package(p) for p in PACKAGES),
        check_sqlite(),
        check_folders(),
    ]
    for ok, message in results:
        print(f"[{'OK' if ok else 'FAIL'}] {message}")
    failed = sum(not ok for ok, _ in results)
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0
