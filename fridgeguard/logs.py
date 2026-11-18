"""Operational log: one line per CLI command in ``logs/fridgeguard.log``.

The event database is the security record (append-only, hashed). This log is for the
operator: which command ran, how long it took, its exit code, and the traceback if it
crashed. Arguments are not logged (notes and usernames stay in the database, secrets never
reach the command line). ``FRIDGEGUARD_LOG_DIR`` moves the log; an empty value disables it.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fridgeguard.config import PROJECT_ROOT

LOG_FILE = "fridgeguard.log"
_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def log_dir() -> Path | None:
    value = os.environ.get("FRIDGEGUARD_LOG_DIR")
    if value is None:
        return PROJECT_ROOT / "logs"
    return Path(value) if value.strip() else None


def setup_logging() -> logging.Logger:
    """Attach a rotating file handler (1 MB x 3) to the ``fridgeguard`` logger once."""
    logger = logging.getLogger("fridgeguard")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    directory = log_dir()
    target = str((directory / LOG_FILE).resolve()) if directory else None
    ours = [h for h in logger.handlers if hasattr(h, "_fridgeguard")]
    for handler in ours:
        if handler._fridgeguard != target:  # type: ignore[attr-defined]
            logger.removeHandler(handler)
            handler.close()
    if target and not any(getattr(h, "_fridgeguard", None) == target for h in logger.handlers):
        try:
            directory.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                target, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
            )
        except OSError:
            return logger  # logging must never stop the monitoring commands
        handler.setFormatter(logging.Formatter(_FORMAT))
        handler._fridgeguard = target  # type: ignore[attr-defined]
        logger.addHandler(handler)
    return logger
