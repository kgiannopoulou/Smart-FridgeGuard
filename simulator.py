"""Refrigerator and user-activity simulator.

Shortcut for ``python -m fridgeguard simulate``; the code lives in
``fridgeguard/simulator/`` (thermal model, fleet, faults), ``fridgeguard/generator/``
(users, RBAC, activity) and ``fridgeguard/simulation.py`` (runner).

    python simulator.py --duration 1d --show activity
    python simulator.py --realtime --speed 60
"""

import sys

from fridgeguard.__main__ import main
from fridgeguard.simulation import Simulation, SimulationSettings

__all__ = ["Simulation", "SimulationSettings", "run"]


def run(argv: list[str] | None = None) -> int:
    return main(["simulate", *(sys.argv[1:] if argv is None else argv)])


if __name__ == "__main__":
    sys.exit(run())
