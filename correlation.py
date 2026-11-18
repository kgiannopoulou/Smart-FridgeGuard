"""Event correlation (COR-001..004), incidents and the L1 investigation workflow.

Shortcut for ``python -m fridgeguard correlate``, ``incidents`` and ``investigate``; the
code lives in ``fridgeguard/detection/correlator.py`` and ``fridgeguard/investigation/``.

    python correlation.py                               # correlate alerts into incidents
    python correlation.py incidents list
    python correlation.py investigate start ALR-000025
"""

import sys

from fridgeguard.__main__ import main
from fridgeguard.detection import Correlator
from fridgeguard.investigation import build_case

__all__ = ["Correlator", "build_case", "run"]

GROUPS = {"correlate", "incidents", "investigate"}


def run(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    return main(args if args[:1] and args[0] in GROUPS else ["correlate", *args])


if __name__ == "__main__":
    sys.exit(run())
