"""Command-line entry point: ``python -m fridgeguard``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fridgeguard import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fridgeguard",
        description="Smart-FridgeGuard security monitoring lab",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check-env", help="verify that the development environment is ready")

    sim = sub.add_parser(
        "simulate",
        help="simulate refrigerators and user activity",
        description=(
            "Simulate the refrigerator fleet and user activity. Without --duration the "
            "simulation runs continuously until Ctrl+C."
        ),
    )
    sim.add_argument("--duration", help="simulated time to run, e.g. 30m, 12h, 3d")
    sim.add_argument(
        "--realtime",
        action="store_true",
        help="wait between readings (live mode); default runs as fast as possible",
    )
    sim.add_argument(
        "--speed", type=float, default=1.0, help="real-time speed-up factor (with --realtime)"
    )
    sim.add_argument("--seed", type=int, help="random seed (default from config)")
    sim.add_argument("--start", help="simulated start time, ISO 8601 (default from config)")
    sim.add_argument("--interval", type=float, help="seconds between readings (default 60)")
    sim.add_argument(
        "--out",
        type=Path,
        default=Path("data/events.jsonl"),
        help="JSON Lines event log (appended); use '-' to disable",
    )
    sim.add_argument(
        "--show",
        choices=["all", "activity", "none"],
        default="all",
        help="console output: all events, only user activity, or nothing",
    )
    sim.add_argument("--no-activity", action="store_true", help="simulate fridges only")
    sim.add_argument("--anomalies-per-day", type=float, help="suspicious activities per day")
    sim.add_argument("--config-dir", type=Path, help="alternative config directory")
    return parser


def run_simulate(args: argparse.Namespace) -> int:
    from fridgeguard.simulation import Simulation, SimulationSettings, parse_duration
    from fridgeguard.sinks import ConsoleSink, JsonlSink
    from fridgeguard.timeutil import parse_utc

    try:
        duration = parse_duration(args.duration) if args.duration else None
        if args.speed <= 0:
            raise ValueError("--speed must be positive")
        settings = SimulationSettings.from_config(
            args.config_dir,
            seed=args.seed,
            start=parse_utc(args.start) if args.start else None,
            interval_s=args.interval,
            activity=False if args.no_activity else None,
            anomalies_per_day=args.anomalies_per_day,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    sinks = [ConsoleSink(sys.stdout, args.show)]
    log = None
    if str(args.out) != "-":
        log = JsonlSink(args.out)
        sinks.append(log)

    sim = Simulation(settings, sinks, args.config_dir)
    mode = f"real time x{args.speed:g}" if args.realtime else "fast"
    span = args.duration or "continuous (Ctrl+C to stop)"
    print(
        f"# Smart-FridgeGuard simulation | {len(sim.fleet.device_ids)} fridges | "
        f"start {settings.start.isoformat()} | {span} | {mode} | seed {settings.seed}",
        file=sys.stderr,
    )
    try:
        ticks = sim.run(duration, realtime=args.realtime, speed=args.speed)
    except KeyboardInterrupt:
        ticks = None
    where = f" -> {log.path}" if log else ""
    done = f"{ticks} ticks, " if ticks is not None else "stopped, "
    print(f"# {done}{sim.events_emitted} events{where}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check-env":
        from fridgeguard.envcheck import run_checks

        return run_checks()
    if args.command == "simulate":
        return run_simulate(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
