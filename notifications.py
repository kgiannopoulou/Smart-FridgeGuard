"""Deduplicated alert notifications: console, email and Telegram.

Shortcut for ``python -m fridgeguard notify``; the code lives in
``fridgeguard/notifications/`` and is configured in ``config/notifications.yaml``.

    python notifications.py                 # counts per channel and status
    python notifications.py channels        # configured channels (secrets never shown)
    python notifications.py run             # notify stored alerts not handled yet
"""

import sys

from fridgeguard.__main__ import main
from fridgeguard.notifications import Notifier, build_channels

__all__ = ["Notifier", "build_channels", "run"]


def run(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    return main(["notify", *(args or ["stats"])])


if __name__ == "__main__":
    sys.exit(run())
