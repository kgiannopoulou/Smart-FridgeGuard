"""Centralized SQLite event database (append-only telemetry and security events).

Shortcut for ``python -m fridgeguard events``; the code lives in ``fridgeguard/storage/``
(schema.sql, normalize.py, store.py).

    python database.py                          # counts per table and type
    python database.py list --status suspicious
    python database.py import data/events.jsonl
    python database.py verify                   # re-check every SHA-256 hash
"""

import sys

from fridgeguard.__main__ import main
from fridgeguard.storage import EventStore, import_jsonl

__all__ = ["EventStore", "import_jsonl", "run"]


def run(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    return main(["events", *(args or ["stats"])])


if __name__ == "__main__":
    sys.exit(run())
