"""Detection engine: rules DET-001..DET-007 and alert prioritization.

Shortcut for ``python -m fridgeguard detect`` and ``alerts``; the code lives in
``fridgeguard/detection/`` (detector.py, rules/, prioritizer.py), the rules are configured
in ``config/detection.yaml`` and ``config/prioritization.yaml``.

    python detector.py                  # re-run the rules over the stored events
    python detector.py alerts queue     # open alerts, most severe first
"""

import sys

from fridgeguard.__main__ import main
from fridgeguard.detection import Alert, Detector, Prioritizer, load_rules

__all__ = ["Alert", "Detector", "Prioritizer", "load_rules", "run"]

GROUPS = {"detect", "alerts"}


def run(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    return main(args if args[:1] and args[0] in GROUPS else ["detect", *args])


if __name__ == "__main__":
    sys.exit(run())
