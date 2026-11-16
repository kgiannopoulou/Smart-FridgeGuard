"""Command-line entry point: ``python -m fridgeguard``."""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from fridgeguard import __version__

DEFAULT_DB = Path("data/fridgeguard.db")
SEVERITY_CHOICES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUS_CHOICES = ["new", "under_investigation", "confirmed", "false_positive", "resolved"]
INCIDENT_STATUS_CHOICES = ["open", "investigating", "closed"]
VERDICT_CHOICES = ["unverified", "true_positive", "benign", "false_positive", "undetermined"]


def _default_analyst() -> str:
    import getpass
    import os

    try:
        return os.environ.get("FRIDGEGUARD_ANALYST") or getpass.getuser()
    except OSError:
        return "analyst"


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
    sim.add_argument(
        "--faults-per-day",
        type=float,
        help="device faults (compressor failure, offline) per day (default 0)",
    )
    sim.add_argument(
        "--no-detect", action="store_true", help="store events without running detection"
    )
    sim.add_argument("--config-dir", type=Path, help="alternative config directory")

    # ---- detect ----
    det = sub.add_parser(
        "detect",
        help="run the detection rules over all stored events",
        description="Run config/detection.yaml over every stored event. Safe to repeat: "
        "existing alerts are found again, not duplicated.",
    )
    det.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite event database")
    det.add_argument("--config-dir", type=Path, help="alternative config directory")

    # ---- correlate / incidents ----
    cor = sub.add_parser(
        "correlate",
        help="group related alerts and events into incidents",
        description="Run config/correlation.yaml over the stored alerts and events. Safe to "
        "repeat: existing incidents are refreshed, not duplicated.",
    )
    cor.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite event database")
    cor.add_argument("--config-dir", type=Path, help="alternative config directory")

    inc = sub.add_parser("incidents", help="list, investigate and review incidents")
    inc.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite event database")
    inc_sub = inc.add_subparsers(dest="incidents_command", required=True)
    inc_list = inc_sub.add_parser("list", help="incidents, most severe first")
    inc_list.add_argument("--pattern", dest="pattern_id", help="e.g. COR-001")
    inc_list.add_argument("--min-severity", choices=SEVERITY_CHOICES)
    inc_list.add_argument("--status", choices=INCIDENT_STATUS_CHOICES)
    inc_list.add_argument("--verdict", choices=VERDICT_CHOICES)
    inc_show = inc_sub.add_parser("show", help="one incident: steps, confidence, timeline")
    inc_show.add_argument("incident_id", help="e.g. INC-20261117-001")
    inc_rev = inc_sub.add_parser(
        "review",
        help="record an analyst review (status and verdict)",
        description="Append a review: status open / investigating / closed and a verdict. "
        "A note is always required.",
    )
    inc_rev.add_argument("incident_id")
    inc_rev.add_argument("status", choices=INCIDENT_STATUS_CHOICES)
    inc_rev.add_argument(
        "--verdict", choices=VERDICT_CHOICES, default=None, help="default: keep the current one"
    )
    inc_rev.add_argument("--note", required=True, help="findings behind the review")
    inc_rev.add_argument("--analyst", default=None)

    # ---- alerts ----
    al = sub.add_parser("alerts", help="list, prioritize and manage security alerts")
    al.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite event database")
    al_sub = al.add_subparsers(dest="alerts_command", required=True)
    al_list = al_sub.add_parser("list", help="list alerts (oldest first)")
    al_list.add_argument("--rule", dest="rule_id", help="e.g. DET-002")
    al_list.add_argument("--severity", choices=SEVERITY_CHOICES)
    al_list.add_argument("--min-severity", choices=SEVERITY_CHOICES)
    al_list.add_argument("--device")
    al_list.add_argument("--status", choices=STATUS_CHOICES)
    al_list.add_argument("--assigned", dest="assigned_to", help="analyst name")
    al_list.add_argument("--limit", type=int, default=0, help="number of alerts (0 = all)")
    al_queue = al_sub.add_parser(
        "queue", help="triage queue: open alerts, most severe first, then oldest first"
    )
    al_queue.add_argument(
        "--min-severity", choices=SEVERITY_CHOICES, default="LOW", help="default LOW (hides INFO)"
    )
    al_queue.add_argument("--device")
    al_queue.add_argument("--assigned", dest="assigned_to", help="analyst name")
    al_queue.add_argument("--limit", type=int, default=0, help="number of alerts (0 = all)")
    al_show = al_sub.add_parser("show", help="one alert with its evidence and history")
    al_show.add_argument("alert_id", help="e.g. ALR-000001")
    al_status = al_sub.add_parser(
        "status",
        help="move an alert through the workflow",
        description="new -> under_investigation -> confirmed / false_positive / resolved. "
        "A note is required for every step except starting an investigation.",
    )
    al_status.add_argument("alert_id")
    al_status.add_argument("status", choices=STATUS_CHOICES)
    al_status.add_argument("--note", default="", help="why (required except for investigating)")
    al_status.add_argument(
        "--analyst", default=None, help="default: $FRIDGEGUARD_ANALYST or the OS user"
    )
    al_sev = al_sub.add_parser(
        "severity", help="override an alert's severity (stops automatic re-prioritization)"
    )
    al_sev.add_argument("alert_id")
    al_sev.add_argument("severity", choices=SEVERITY_CHOICES)
    al_sev.add_argument("--note", required=True, help="why the severity is changed")
    al_sev.add_argument("--analyst", default=None)
    al_sub.add_parser("prioritize", help="re-classify every alert (config/prioritization.yaml)")
    al_sub.add_parser("stats", help="alert counts by severity and status")
    al_sub.add_parser("rules", help="show the configured detection rules")
    al.add_argument("--config-dir", type=Path, help="alternative config directory")

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
            faults_per_day=args.faults_per_day,
        )
        if settings.faults_per_day < 0:
            raise ValueError("--faults-per-day must be >= 0")
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
    db_sink = detector = None
    if str(args.db) != "-":
        store = EventStore(args.db)
        store.register_devices(sim.fleet)
        db_sink = SQLiteSink(store)
        sim.sinks.append(db_sink)
        if not args.no_detect:
            from fridgeguard.detection import Detector

            try:
                detector = Detector.from_config(
                    store, args.config_dir, on_alert=_alert_printer(args.show)
                )
            except ValueError as exc:
                print(f"error in detection config: {exc}", file=sys.stderr)
                return 2

            def detect_stored(result) -> None:
                kind = "telemetry" if result.table == "telemetry" else "security"
                detector.process_row(kind, store.record_row(kind, result.ref))

            db_sink.on_stored = detect_stored

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
    correlation = None
    if detector:
        detector.finish(sim.now)
        correlation = _correlate(db_sink.store, args.config_dir)
    if db_sink:
        db_sink.store.close()

    targets = [str(log.path)] if log else []
    if db_sink:
        targets.append(str(args.db))
    where = f" -> {', '.join(targets)}" if targets else ""
    done = f"{ticks} ticks, " if ticks is not None else "stopped, "
    print(f"# {done}{sim.events_emitted} events{where}", file=sys.stderr)
    if detector:
        s = detector.summary
        rules = ", ".join(f"{k} {v}" for k, v in sorted(s.by_rule.items())) or "none"
        print(
            f"# detection: {len(s.new_alerts)} new alerts from {s.hits} rule hits ({rules})",
            file=sys.stderr,
        )
    if correlation:
        print(f"# correlation: {_correlation_text(correlation)}", file=sys.stderr)
    if db_sink and db_sink.rejected:
        print(f"# warning: {db_sink.rejected} events rejected by the database", file=sys.stderr)
    return 0


def _alert_printer(show: str):
    def print_alert(alert) -> None:
        if show == "none" or not alert.new:
            return
        ts = alert.ts.strftime("%Y-%m-%d %H:%M:%SZ")
        print(
            f"{ts}  ALERT {alert.alert_id} {alert.severity:<8} {alert.rule_id}  {alert.title}",
            flush=True,
        )

    return print_alert


# ---- detect / alerts ----------------------------------------------------------------------
def run_detect(args: argparse.Namespace) -> int:
    from fridgeguard.detection import Detector
    from fridgeguard.storage import EventStore

    _utf8_stdout()
    if not Path(args.db).exists():
        print(f"error: {args.db} not found; run 'fridgeguard simulate' first", file=sys.stderr)
        return 2
    store = EventStore(args.db)
    try:
        detector = Detector.from_config(store, args.config_dir)
    except ValueError as exc:
        print(f"error in detection config: {exc}", file=sys.stderr)
        store.close()
        return 2
    summary = detector.run()
    correlation = _correlate(store, args.config_dir)
    total = store.stats()["alerts"]
    store.close()
    rules = ", ".join(f"{r.rule_id}" for r in detector.rules)
    print(f"rules:      {rules}")
    print(f"records:    {summary.records} scanned")
    hits = ", ".join(f"{k} {v}" for k, v in sorted(summary.by_rule.items())) or "none"
    print(f"rule hits:  {summary.hits} ({hits})")
    print(f"alerts:     {len(summary.new_alerts)} new, {total} in the database")
    for a in summary.new_alerts:
        print(f"  {a.alert_id}  {a.severity:<8} {a.rule_id}  {a.title}")
    if correlation:
        print(f"incidents:  {_correlation_text(correlation)}")
    return 0


# ---- correlate / incidents ------------------------------------------------------------------
def _correlate(store, config_dir):
    from fridgeguard.detection import Correlator

    try:
        return Correlator.from_config(store, config_dir).run()
    except (ValueError, KeyError) as exc:
        print(f"error in correlation config: {exc}", file=sys.stderr)
        return None


def _correlation_text(summary) -> str:
    text = (
        f"{len(summary.created)} new, {len(summary.updated)} updated "
        f"from {summary.alerts} alerts ({summary.candidates} connected groups)"
    )
    if summary.merged:
        text += "; merged " + ", ".join(f"{a} into {b}" for a, b in summary.merged)
    return text


def run_correlate(args: argparse.Namespace) -> int:
    from fridgeguard.storage import EventStore

    _utf8_stdout()
    if not Path(args.db).exists():
        print(f"error: {args.db} not found; run 'fridgeguard simulate' first", file=sys.stderr)
        return 2
    store = EventStore(args.db)
    try:
        summary = _correlate(store, args.config_dir)
        if summary is None:
            return 2
        print(f"incidents:  {_correlation_text(summary)}")
        for inc in store.incidents():
            if inc["incident_id"] in summary.created:
                print(f"  {inc['incident_id']}  {inc['severity']:<8} {inc['title']}")
    finally:
        store.close()
    return 0


def run_incidents(args: argparse.Namespace) -> int:
    from fridgeguard.storage import EventStore

    _utf8_stdout()
    if not Path(args.db).exists():
        print(f"error: {args.db} not found; run 'fridgeguard simulate' first", file=sys.stderr)
        return 2
    if args.incidents_command == "review":
        store = EventStore(args.db)
        try:
            current = store.incident(args.incident_id)
            if current is None:
                print(f"error: no incident {args.incident_id}", file=sys.stderr)
                return 2
            if not args.note.strip():
                print("error: a note is required", file=sys.stderr)
                return 2
            verdict = args.verdict or current["verdict"]
            store.add_incident_review(
                args.incident_id,
                args.analyst or _default_analyst(),
                args.status,
                verdict,
                args.note.strip(),
            )
            print(f"{args.incident_id}  now {args.status}, verdict {verdict}")
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        finally:
            store.close()
        return 0

    store = EventStore(args.db, read_only=True)
    try:
        if args.incidents_command == "list":
            return _list_incidents(store, args)
        return _show_incident(store, args.incident_id)
    finally:
        store.close()


def _list_incidents(store, args) -> int:
    from fridgeguard.storage.store import SEVERITY_LEVELS

    rows = store.incidents(
        pattern_id=args.pattern_id,
        min_severity=SEVERITY_LEVELS.index(args.min_severity) if args.min_severity else None,
        status=args.status,
        verdict=args.verdict,
    )
    rows.sort(key=lambda r: (-r["severity_rank"], r["first_seen"]))
    print(format_incident_table(rows))
    return 0


def _show_incident(store, incident_id: str) -> int:
    import json

    inc = store.incident(incident_id)
    if inc is None:
        print(f"error: no incident {incident_id}", file=sys.stderr)
        return 2
    print(f"{inc['incident_id']}  {inc['severity']}  {inc['pattern_id']} {inc['pattern_name']}")
    if inc["merged_into"]:
        print(f"merged into: {inc['merged_into']}")
    print(f"title:       {inc['title']}")
    print(f"description: {inc['description']}")
    print(f"first seen:  {inc['first_seen']}   last seen: {inc['last_seen']}")
    print(f"status:      {inc['status']}   verdict: {inc['verdict']}")
    print(f"confidence:  {inc['confidence']} ({inc['confidence_level']})")
    for points, reason in json.loads(inc["confidence_factors"]):
        print(f"  {points:+4d}  {reason}")
    ent = json.loads(inc["entities"])
    for key in ("devices", "users", "claimed_users", "source_ips", "sessions"):
        if ent.get(key):
            print(f"{key + ':':<13}{', '.join(ent[key])}")
    print(f"ATT&CK:      {', '.join(json.loads(inc['attack_ids']))}")
    print(f"implements:  {', '.join(json.loads(inc['implements']))}")
    steps = json.loads(inc["steps"])
    if steps:
        print("sequence:")
        for st in steps:
            mark = st["record_id"] or ("not seen (optional)" if st["optional"] else "-")
            print(f"  {st['label']:<45} {mark}")
    members = store.incident_members(incident_id)
    print(f"timeline ({len(members)} records):")
    for m in members:
        print(f"  {_fmt_ts(m['ts'])}  {m['record_id']:<11} {m['note']}")
    print("analyst must verify:")
    for q in json.loads(inc["questions"]):
        print(f"  - {q}")
    print("recommended response:")
    for r in json.loads(inc["response"]):
        print(f"  - {r}")
    reviews = store.incident_reviews(incident_id)
    print(f"reviews ({len(reviews)}):")
    for r in reviews:
        print(
            f"  {_fmt_ts(r['ts'])}  {r['analyst']:<12} {r['status']:<13} "
            f"{r['verdict']:<15} {r['note']}"
        )
    return 0


def format_incident_table(rows: list[dict]) -> str:
    header = (
        f"{'Incident ID':<17} {'First seen (UTC)':<16}  {'Severity':<8} {'Pattern':<8} "
        f"{'Conf.':>5}  {'Alerts':>6} {'Records':>7}  {'Status':<13} {'Verdict':<14} Title"
    )
    lines = [header, "-" * 140]
    for r in rows:
        lines.append(
            f"{r['incident_id']:<17} {_fmt_ts(r['first_seen']):<16}  {r['severity']:<8} "
            f"{r['pattern_id']:<8} {r['confidence']:>5}  {r['alert_count']:>6} "
            f"{r['record_count']:>7}  {r['status']:<13} {r['verdict']:<14} {r['title']}"
        )
    lines.append(f"({len(rows)} incidents)")
    return "\n".join(lines)


def _print_counts(store) -> None:
    from fridgeguard.storage.store import ALERT_STATUSES, SEVERITY_LEVELS

    counts = store.alert_counts()
    sev, st = counts["by_severity"], counts["by_status"]
    print("by severity: " + ", ".join(f"{k} {sev.get(k, 0)}" for k in reversed(SEVERITY_LEVELS)))
    print("by status:   " + ", ".join(f"{k} {st.get(k, 0)}" for k in ALERT_STATUSES))


def run_alerts(args: argparse.Namespace) -> int:
    import json

    from fridgeguard.storage import EventStore

    _utf8_stdout()
    if args.alerts_command == "rules":
        from fridgeguard.detection import load_rules

        rules, dedup = load_rules(args.config_dir)
        for r in rules:
            params = ", ".join(f"{k}={v}" for k, v in r.params.items())
            print(f"{r.rule_id}  {r.severity:<8} {r.name}  [{r.type_name}]")
            print(f"          implements {', '.join(r.implements)}; ATT&CK {', '.join(r.attack)}")
            print(f"          {params}")
        print(f"(alerts for the same rule and subject within {dedup:g} s are grouped)")
        return 0
    if not Path(args.db).exists():
        print(f"error: {args.db} not found; run 'fridgeguard simulate' first", file=sys.stderr)
        return 2
    if args.alerts_command in ("status", "severity", "prioritize"):
        return _manage_alert(args)
    from fridgeguard.storage.store import SEVERITY_LEVELS

    store = EventStore(args.db, read_only=True)
    try:
        if args.alerts_command == "list":
            min_rank = SEVERITY_LEVELS.index(args.min_severity) if args.min_severity else None
            rows = store.alerts(
                limit=args.limit or None,
                rule_id=args.rule_id,
                severity=args.severity,
                min_severity=min_rank,
                device=args.device,
                status=args.status,
                assigned_to=args.assigned_to,
            )
            print(format_alert_table(rows))
        elif args.alerts_command == "queue":
            rows = store.alert_queue(
                args.min_severity,
                limit=args.limit or None,
                device=args.device,
                assigned_to=args.assigned_to,
            )
            print(format_alert_table(rows, queue=True))
        elif args.alerts_command == "stats":
            _print_counts(store)
        else:
            alert = store.alert(args.alert_id)
            if alert is None:
                print(f"error: no alert {args.alert_id}", file=sys.stderr)
                return 2
            print(
                f"{alert['alert_id']}  {alert['severity']}  {alert['rule_id']} {alert['rule_name']}"
            )
            print(f"title:       {alert['title']}")
            print(f"description: {alert['description']}")
            print(f"device:      {alert['device_id']}   subject: {alert['subject']}")
            print(f"first seen:  {alert['first_seen']}   last seen: {alert['last_seen']}")
            locked = " (set by analyst)" if alert["severity_locked"] else ""
            print(f"severity:    {alert['severity']}{locked}   base: {alert['base_severity']}")
            print(f"why:         {alert['severity_reason'] or '-'}")
            print(f"status:      {alert['status']}   assigned to: {alert['assigned_to'] or '-'}")
            print(f"ATT&CK:      {', '.join(json.loads(alert['attack_ids']))}")
            print(f"implements:  {', '.join(json.loads(alert['implements']))}")
            print(f"evidence ({alert['evidence_count']}):")
            for ev in store.alert_evidence(args.alert_id):
                print(f"  {ev['record_id']:<11} {_fmt_ts(ev['ts'])}  {ev['note']}")
            history = store.alert_history(args.alert_id)
            print(f"history ({len(history)}):")
            for h in history:
                change = f"{h['field']} {h['old_value'] or '-'} -> {h['new_value']}"
                print(f"  {_fmt_ts(h['ts'])}  {h['actor']:<12} {change:<40} {h['note']}")
    finally:
        store.close()
    return 0


def _manage_alert(args: argparse.Namespace) -> int:
    from fridgeguard.detection import Prioritizer
    from fridgeguard.storage import EventStore

    store = EventStore(args.db)
    try:
        if args.alerts_command == "prioritize":
            try:
                summary = Prioritizer.from_config(store, args.config_dir).run()
            except ValueError as exc:
                print(f"error in prioritization config: {exc}", file=sys.stderr)
                return 2
            print(f"alerts:     {summary.alerts} classified, {len(summary.changed)} changed")
            for alert_id, old, new in summary.changed:
                print(f"  {alert_id}  {old} -> {new}")
            _print_counts(store)
            return 0
        analyst = args.analyst or _default_analyst()
        try:
            if args.alerts_command == "status":
                alert = store.set_alert_status(args.alert_id, args.status, analyst, args.note)
                print(
                    f"{alert['alert_id']}  {alert['severity']}  now {alert['status']}"
                    f" (assigned to {alert['assigned_to'] or '-'})"
                )
            else:
                store.set_alert_severity(args.alert_id, args.severity, analyst, args.note)
                print(f"{args.alert_id}  severity {args.severity} (set by {analyst})")
        except KeyError as exc:
            print(f"error: {exc.args[0]}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    finally:
        store.close()
    return 0


def format_alert_table(rows: list[dict], queue: bool = False) -> str:
    header = (
        f"{'Alert ID':<11} {'First seen (UTC)':<16}  {'Severity':<8} {'Rule':<8} "
        f"{'Device':<10}  {'Ev.':>3}  {'Status':<19} {'Assigned':<10} Title"
    )
    lines = [header, "-" * 130]
    for r in rows:
        lines.append(
            f"{r['alert_id']:<11} {_fmt_ts(r['first_seen']):<16}  {r['severity']:<8} "
            f"{r['rule_id']:<8} {r['device_id'] or '-':<10}  {r['evidence_count']:>3}  "
            f"{r['status']:<19} {r['assigned_to'] or '-':<10} {r['title']}"
        )
    lines.append(f"({len(rows)} {'open alerts in the queue' if queue else 'alerts'})")
    return "\n".join(lines)


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
            print(f"alerts            {s['alerts']}")
            print(f"incidents         {s['incidents']}")
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
    if args.command == "detect":
        return run_detect(args)
    if args.command == "alerts":
        return run_alerts(args)
    if args.command == "correlate":
        return run_correlate(args)
    if args.command == "incidents":
        return run_incidents(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
