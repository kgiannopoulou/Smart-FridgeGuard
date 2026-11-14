"""Command-line entry point: ``python -m fridgeguard``."""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from fridgeguard import __version__

DEFAULT_DB = Path("data/fridgeguard.db")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fridgeguard",
        description="Smart-FridgeGuard security monitoring lab",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check-env", help="verify that the development environment is ready")

    # ---- simulate ----
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
        "--db",
        type=Path,
        default=DEFAULT_DB,
        help="SQLite event database (appended); use '-' to disable",
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

    # ---- events ----
    ev = sub.add_parser("events", help="query the centralized event database")
    ev.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite event database")
    ev_sub = ev.add_subparsers(dest="events_command", required=True)

    imp = ev_sub.add_parser("import", help="load a JSON Lines event log into the database")
    imp.add_argument("jsonl", type=Path)
    imp.add_argument("--config-dir", type=Path, help="config directory for the device list")

    lst = ev_sub.add_parser("list", help="list security events (newest last)")
    lst.add_argument("--device")
    lst.add_argument("--type", dest="event_type", help="e.g. SETPOINT_CHANGE, LOGIN_FAILURE")
    lst.add_argument("--user")
    lst.add_argument("--status", choices=["normal", "suspicious", "malicious"])
    lst.add_argument("--since", help="ISO 8601 UTC, e.g. 2026-11-17T00:00")
    lst.add_argument("--until", help="ISO 8601 UTC")
    lst.add_argument("--limit", type=int, default=50, help="number of events (0 = all)")

    tel = ev_sub.add_parser("telemetry", help="list temperature readings (newest last)")
    tel.add_argument("--device")
    tel.add_argument("--since")
    tel.add_argument("--until")
    tel.add_argument("--limit", type=int, default=20, help="number of readings (0 = all)")

    hist = ev_sub.add_parser("history", help="status history of one security event")
    hist.add_argument("event_id", help="e.g. EVT-000012")

    ev_sub.add_parser("stats", help="counts by table, type and status")
    ev_sub.add_parser("verify", help="re-check every stored event against its hash")
    return parser


def _utf8_stdout() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ---- simulate ----------------------------------------------------------------------------
def run_simulate(args: argparse.Namespace) -> int:
    from fridgeguard.simulation import Simulation, SimulationSettings, parse_duration
    from fridgeguard.sinks import ConsoleSink, JsonlSink, SQLiteSink
    from fridgeguard.storage import EventStore
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

    _utf8_stdout()
    sinks = [ConsoleSink(sys.stdout, args.show)]
    log = None
    if str(args.out) != "-":
        log = JsonlSink(args.out)
        sinks.append(log)

    sim = Simulation(settings, sinks, args.config_dir)
    db_sink = None
    if str(args.db) != "-":
        store = EventStore(args.db)
        store.register_devices(sim.fleet)
        db_sink = SQLiteSink(store)
        sim.sinks.append(db_sink)

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
    if db_sink:
        db_sink.store.close()

    targets = [str(log.path)] if log else []
    if db_sink:
        targets.append(str(args.db))
    where = f" -> {', '.join(targets)}" if targets else ""
    done = f"{ticks} ticks, " if ticks is not None else "stopped, "
    print(f"# {done}{sim.events_emitted} events{where}", file=sys.stderr)
    if db_sink and db_sink.rejected:
        print(f"# warning: {db_sink.rejected} events rejected by the database", file=sys.stderr)
    return 0


# ---- events ------------------------------------------------------------------------------
def run_events(args: argparse.Namespace) -> int:
    from fridgeguard.storage import EventStore, import_jsonl

    _utf8_stdout()
    cmd = args.events_command

    if cmd == "import":
        from fridgeguard.simulator.fleet import Fleet

        if not args.jsonl.exists():
            print(f"error: {args.jsonl} not found", file=sys.stderr)
            return 2
        store = EventStore(args.db)
        store.register_devices(Fleet.from_config(random.Random(0), args.config_dir))
        with args.jsonl.open(encoding="utf-8") as fh:
            counts = import_jsonl(store, fh)
        store.close()
        print(
            f"imported {counts['telemetry']} telemetry readings and "
            f"{counts['security_events']} security events into {args.db} "
            f"({counts['duplicates']} duplicates skipped, {counts['rejected']} rejected)"
        )
        return 0

    if not Path(args.db).exists():
        print(f"error: {args.db} not found; run 'fridgeguard simulate' first", file=sys.stderr)
        return 2

    store = EventStore(args.db, read_only=True)
    try:
        if cmd == "list":
            rows = store.security_events(
                limit=args.limit or None,
                newest_first=True,
                device=args.device,
                event_type=args.event_type.upper() if args.event_type else None,
                user=args.user,
                status=args.status,
                since=args.since,
                until=args.until,
            )
            print(format_security_table(list(reversed(rows))))
        elif cmd == "telemetry":
            rows = store.telemetry(
                limit=args.limit or None,
                newest_first=True,
                device=args.device,
                since=args.since,
                until=args.until,
            )
            print(format_telemetry_table(list(reversed(rows))))
        elif cmd == "history":
            history = store.status_history(args.event_id)
            if not history:
                print(f"error: no event {args.event_id}", file=sys.stderr)
                return 2
            for h in history:
                print(f"{h['ts']}  {h['status']:<10}  set by {h['set_by']:<8}  {h['reason']}")
        elif cmd == "stats":
            s = store.stats()
            print(f"database          {args.db}")
            print(f"devices           {s['devices']}")
            print(f"telemetry         {s['telemetry']}")
            print(f"security events   {s['security_events']}")
            print(f"rejected events   {s['rejected']}")
            print(f"time range (UTC)  {s['time_range'][0]} .. {s['time_range'][1]}")
            print("by type:    " + ", ".join(f"{k} {v}" for k, v in s["by_type"].items()))
            print("by status:  " + ", ".join(f"{k} {v}" for k, v in s["by_status"].items()))
        elif cmd == "verify":
            problems = store.verify_integrity()
            s = store.stats()
            checked = s["telemetry"] + s["security_events"]
            if problems:
                print("\n".join(problems))
                print(f"FAILED: {len(problems)} of {checked} events do not match their hash")
                return 1
            print(f"OK: all {checked} stored events match their SHA-256 hash")
    finally:
        store.close()
    return 0


def _fmt_ts(ts: str) -> str:
    return ts.replace("T", " ")[:16]


def format_security_table(rows: list[dict]) -> str:
    header = (
        f"{'Event ID':<11} {'Timestamp (UTC)':<16}  {'Device':<10}  {'Event type':<22} "
        f"{'User':<16} {'Previous':>9} {'New':>9}  {'Result':<8} {'Source IP':<15} Status"
    )
    lines = [header, "-" * (len(header) + 10)]
    for r in rows:
        lines.append(
            f"{r['event_id']:<11} {_fmt_ts(r['timestamp']):<16}  {r['device']:<10}  "
            f"{r['event_type']:<22} {r['user']:<16} {r['previous_value'] or '':>9} "
            f"{r['new_value'] or '':>9}  {r['result'] or '':<8} {r['source_ip']:<15} "
            f"{r['status'].capitalize()}"
        )
    lines.append(f"({len(rows)} events)")
    return "\n".join(lines)


def format_telemetry_table(rows: list[dict]) -> str:
    header = (
        f"{'Reading ID':<11} {'Timestamp (UTC)':<16}  {'Device':<10}  {'Temp':>8}  "
        f"{'Setpoint':>8}  {'Expected range':<17} Status"
    )
    lines = [header, "-" * len(header)]
    for r in rows:
        expected = f"{r['expected_min_c']:.1f}..{r['expected_max_c']:.1f} °C"
        lines.append(
            f"{r['reading_id']:<11} {_fmt_ts(r['ts_device']):<16}  {r['device_id']:<10}  "
            f"{r['temperature_c']:>5.1f} °C  {r['setpoint_c']:>5.1f} °C  {expected:<17} "
            f"{r['device_status']}"
        )
    lines.append(f"({len(rows)} readings)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check-env":
        from fridgeguard.envcheck import run_checks

        return run_checks()
    if args.command == "simulate":
        return run_simulate(args)
    if args.command == "events":
        return run_events(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
