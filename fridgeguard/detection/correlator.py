"""Event correlation (Phase 2, Step 9).

The :class:`Correlator` connects alerts with the events around them and groups related
activity into **incidents** (``config/correlation.yaml``). It works in four stages:

1. **evidence:** every alert (except INFO) and the records it is based on;
2. **pivots:** the follow-up lookups an analyst would do by hand: successful logins from
   a source that just failed, everything else in a login session, what was changed on a
   device before it went out of range, and whether the temperature reacted to a change;
3. **linking:** records that share a session, source IP, user or device and are close in
   time are connected (union-find); each connected group is a candidate incident;
4. **patterns:** ordered attack sequences (COR-001 ... COR-004) name the incident, set its
   severity and say what the analyst must verify. Connected alerts of several rules that
   match no pattern become a "related alerts" incident (COR-000).

Each incident gets a confidence score (0-100) with the reasons behind it. Correlation
shows that events are *related*; it does not prove an attack. Every incident starts as
verdict ``unverified`` and an analyst decides.

Re-running is safe: an incident is found again through its members, refreshed, and gains
any new members; when new activity joins two existing incidents, the newer one is marked
``merged_into`` the older one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fridgeguard.config import load_yaml
from fridgeguard.models import iso_utc
from fridgeguard.storage import EventStore
from fridgeguard.storage.store import SEVERITY_LEVELS
from fridgeguard.timeutil import parse_utc

RELATED_PATTERN = "COR-000"
MATCH_FIELDS = {
    "kind",
    "rule",
    "stage",
    "event_type",
    "category",
    "result",
    "status",
    "parameter",
}
LINK_FIELDS = ("session_id", "source_ip", "user", "device_id")
AUTHENTICATED = {"LOGIN_SUCCESS", "LOGOUT"}  # plus every configuration event


# ---- settings ---------------------------------------------------------------------------
@dataclass
class Step:
    id: str
    label: str
    match: dict[str, set[str]]
    same: dict[str, str] = field(default_factory=dict)
    within: timedelta | None = None
    optional: bool = False


@dataclass
class Pattern:
    id: str
    name: str
    severity: str
    confidence_base: int
    steps: list[Step]
    implements: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    questions: list[str] = field(default_factory=list)
    response: list[str] = field(default_factory=list)


@dataclass
class CorrelationSettings:
    rule_stages: dict[str, str]
    event_stages: dict[str, str]
    pivots: dict[str, dict[str, Any]]
    link_on: dict[str, timedelta]
    patterns: list[Pattern]
    related: dict[str, Any]
    confidence: dict[str, Any]
    allowed_ips: dict[str, set[str]]
    safe_ranges: dict[str, tuple[float, float]]

    @classmethod
    def from_config(cls, config_dir: Path | None = None) -> CorrelationSettings:
        cfg = load_yaml("correlation.yaml", config_dir)
        devices = load_yaml("devices.yaml", config_dir)["devices"]
        stages = cfg.get("stages") or {}
        patterns = []
        for pid, spec in (cfg.get("patterns") or {}).items():
            steps = []
            for raw in spec.get("steps") or []:
                match = {
                    k: {str(x) for x in (v if isinstance(v, list) else [v])}
                    for k, v in (raw.get("match") or {}).items()
                }
                unknown = set(match) - MATCH_FIELDS
                if unknown:
                    raise ValueError(f"{pid}.{raw.get('id')}: unknown match fields {unknown}")
                same = dict(raw.get("same") or {})
                if set(same) - set(LINK_FIELDS):
                    raise ValueError(f"{pid}.{raw.get('id')}: 'same' supports {LINK_FIELDS}")
                within = raw.get("within_s")
                steps.append(
                    Step(
                        id=raw["id"],
                        label=raw.get("label", raw["id"]),
                        match=match,
                        same=same,
                        within=timedelta(seconds=float(within)) if within else None,
                        optional=bool(raw.get("optional", False)),
                    )
                )
            known = {s.id for s in steps}
            for s in steps:
                if set(s.same.values()) - known:
                    raise ValueError(f"{pid}.{s.id}: 'same' refers to an unknown step")
            if not any(not s.optional for s in steps):
                raise ValueError(f"{pid}: a pattern needs at least one required step")
            severity = str(spec.get("severity", "MEDIUM")).upper()
            if severity not in SEVERITY_LEVELS:
                raise ValueError(f"{pid}: severity must be one of {SEVERITY_LEVELS}")
            patterns.append(
                Pattern(
                    id=pid,
                    name=spec["name"],
                    severity=severity,
                    confidence_base=int(spec.get("confidence_base", 30)),
                    steps=steps,
                    implements=list(spec.get("implements") or []),
                    attack=list(spec.get("attack") or []),
                    questions=list(spec.get("questions") or []),
                    response=list(spec.get("response") or []),
                )
            )
        link_on = {k: timedelta(seconds=float(v)) for k, v in (cfg.get("link_on") or {}).items()}
        if set(link_on) - set(LINK_FIELDS):
            raise ValueError(f"link_on supports {LINK_FIELDS}")
        return cls(
            rule_stages=dict(stages.get("rules") or {}),
            event_stages=dict(stages.get("events") or {}),
            pivots=dict(cfg.get("pivots") or {}),
            link_on=link_on,
            patterns=patterns,
            related=dict(cfg.get("related_alerts") or {}),
            confidence=dict(cfg.get("confidence") or {}),
            allowed_ips={d["device_id"]: set(d.get("allowed_ips") or []) for d in devices},
            safe_ranges={d["device_id"]: (d["safe_min_c"], d["safe_max_c"]) for d in devices},
        )


# ---- the items being correlated -------------------------------------------------------
@dataclass
class Item:
    """An alert, security event or reading taking part in correlation."""

    record_id: str
    kind: str  # alert | security | telemetry
    ts: datetime
    fields: dict[str, Any]  # matchable and linkable values
    row: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def get(self, key: str) -> Any:
        return self.fields.get(key)


@dataclass
class CorrelationSummary:
    alerts: int = 0
    candidates: int = 0
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    merged: list[tuple[str, str]] = field(default_factory=list)  # (merged, into)


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


# ---- correlator ---------------------------------------------------------------------------
class Correlator:
    def __init__(self, store: EventStore, settings: CorrelationSettings):
        self.store = store
        self.s = settings
        self.items: dict[str, Item] = {}
        self.edges: list[tuple[str, str, str]] = []  # (a, b, reason)
        self.effects: dict[str, str] = {}  # change event -> telemetry reading showing effect

    @classmethod
    def from_config(cls, store: EventStore, config_dir: Path | None = None) -> Correlator:
        return cls(store, CorrelationSettings.from_config(config_dir))

    # ---- stage 1: evidence -------------------------------------------------------------
    def _security_item(self, row: dict[str, Any]) -> Item:
        rid = row["event_id"]
        if rid not in self.items:
            fields = {
                "kind": "security",
                "stage": self.s.event_stages.get(row["event_type"]),
                **{
                    k: row.get(k)
                    for k in (
                        "event_type",
                        "category",
                        "result",
                        "status",
                        "parameter",
                        "device_id",
                        "source_ip",
                        "session_id",
                    )
                },
                # a failed login's username is only a claim
                "user": row["user"]
                if row["event_type"] in AUTHENTICATED or row["category"] == "configuration"
                else None,
            }
            self.items[rid] = Item(rid, "security", parse_utc(row["ts_device"]), fields, row)
        return self.items[rid]

    def _telemetry_item(self, row: dict[str, Any], stage: str | None = None) -> Item:
        rid = row["reading_id"]
        if rid not in self.items:
            fields = {"kind": "telemetry", "stage": stage, "device_id": row["device_id"]}
            self.items[rid] = Item(rid, "telemetry", parse_utc(row["ts_device"]), fields, row)
        elif stage:
            self.items[rid].fields["stage"] = stage
        return self.items[rid]

    def _load_alerts(self) -> list[Item]:
        alerts = [
            a
            for a in self.store.alerts()
            if a["severity"] != "INFO" and a["rule_id"] in self.s.rule_stages
        ]
        evidence: dict[str, list[dict[str, Any]]] = {
            a["alert_id"]: self.store.alert_evidence(a["alert_id"]) for a in alerts
        }
        sec_ids = [
            e["record_id"] for ev in evidence.values() for e in ev if e["kind"] == "security"
        ]
        tel_ids = [
            e["record_id"] for ev in evidence.values() for e in ev if e["kind"] == "telemetry"
        ]
        sec_rows = self.store.security_rows_with_status(sec_ids)
        tel_rows = self.store.telemetry_rows(tel_ids)

        items = []
        for a in alerts:
            members = []
            for e in evidence[a["alert_id"]]:
                row = (sec_rows if e["kind"] == "security" else tel_rows).get(e["record_id"])
                if row is None:
                    continue
                if e["kind"] == "security":
                    item = self._security_item(row)
                else:
                    stage = self.s.rule_stages.get(a["rule_id"])
                    item = self._telemetry_item(row, stage if stage == "impact" else None)
                item.notes.append(f"evidence of {a['alert_id']} ({a['rule_id']}): {e['note']}")
                members.append(item)
            sec = [m for m in members if m.kind == "security"]

            def single(key: str, sec=sec) -> Any:
                values = {m.get(key) for m in sec} - {None}
                return values.pop() if len(values) == 1 else None

            fields = {
                "kind": "alert",
                "rule": a["rule_id"],
                "stage": self.s.rule_stages.get(a["rule_id"]),
                "device_id": a["device_id"],
                "source_ip": single("source_ip"),
                "session_id": single("session_id"),
                "user": single("user"),
            }
            item = Item(a["alert_id"], "alert", parse_utc(a["first_seen"]), fields, a)
            item.notes.append(f"{a['rule_id']} {a['severity']}: {a['title']}")
            self.items[a["alert_id"]] = item
            for m in members:
                self.edges.append((item.record_id, m.record_id, "alert evidence"))
            items.append(item)
        return items

    # ---- stage 2: pivots ------------------------------------------------------------------
    def _pivots(self, alerts: list[Item]) -> None:
        p = self.s.pivots
        laf = p.get("login_after_failures") or {}
        if laf.get("enabled", True):
            window = timedelta(seconds=float(laf.get("window_s", 1800)))
            for a in alerts:
                ip = a.get("source_ip")
                if a.get("rule") not in set(laf.get("rules", ["DET-002"])) or not ip:
                    continue
                last = parse_utc(a.row["last_seen"])
                for row in self.store.logins_from(ip, iso_utc(a.ts), iso_utc(last + window)):
                    item = self._security_item(row)
                    item.notes.append(
                        f"successful login from {ip} after the failures of {a.record_id}"
                    )
                    self.edges.append((a.record_id, item.record_id, f"same source IP {ip}"))

        if (p.get("session_activity") or {}).get("enabled", True):
            sessions = {
                i.get("session_id")
                for i in self.items.values()
                if i.kind == "security" and i.get("session_id")
            }
            for sid in sorted(sessions):
                rows = self.store.session_events(sid)
                for row in rows:
                    item = self._security_item(row)
                    if not item.notes:
                        item.notes.append(f"activity in session {sid}")

        cbi = p.get("changes_before_impact") or {}
        if cbi.get("enabled", True):
            lookback = timedelta(seconds=float(cbi.get("lookback_s", 7200)))
            for a in alerts:
                if a.get("rule") not in set(cbi.get("rules", ["DET-003"])) or not a.get(
                    "device_id"
                ):
                    continue
                for row in self.store.applied_changes(
                    a.get("device_id"), iso_utc(a.ts - lookback), iso_utc(a.ts)
                ):
                    item = self._security_item(row)
                    item.notes.append(
                        f"change applied on {a.get('device_id')} before {a.record_id}"
                    )
                    self.edges.append((a.record_id, item.record_id, "change before excursion"))

        tac = p.get("temperature_after_change") or {}
        if tac.get("enabled", True):
            window = timedelta(seconds=float(tac.get("window_s", 3600)))
            rise = float(tac.get("rise_c", 1.5))
            changes = [
                i
                for i in list(self.items.values())
                if i.kind == "security"
                and i.get("parameter") == "setpoint_c"
                and i.get("result") == "applied"
            ]
            for ch in changes:
                device = ch.get("device_id")
                before = self.store.reading_before(device, iso_utc(ch.ts))
                if before is None:
                    continue
                try:
                    direction = float(ch.row["new_value"]) - float(ch.row["previous_value"])
                except (TypeError, ValueError):
                    continue
                if direction == 0:
                    continue
                base = before["temperature_c"]
                for row in self.store.readings_between(
                    device, iso_utc(ch.ts), iso_utc(ch.ts + window)
                ):
                    # only a move towards the new setpoint counts as the device reacting
                    moved = row["temperature_c"] - base
                    if moved * direction > 0 and abs(moved) >= rise:
                        item = self._telemetry_item(row, "impact")
                        mins = (parse_utc(row["ts_device"]) - ch.ts).total_seconds() / 60
                        item.notes.append(
                            f"temperature {base:.1f} -> {row['temperature_c']:.1f} °C "
                            f"{mins:.0f} min after {ch.record_id} (independent sensor check)"
                        )
                        self.edges.append((ch.record_id, item.record_id, "temperature reacted"))
                        self.effects[ch.record_id] = item.record_id
                        break

    # ---- stage 3: linking ---------------------------------------------------------------
    def _clusters(self) -> list[list[Item]]:
        uf = _UnionFind()
        for rid in self.items:
            uf.find(rid)
        for a, b, _ in self.edges:
            uf.union(a, b)
        for key, gap in self.s.link_on.items():
            groups: dict[Any, list[Item]] = {}
            for item in self.items.values():
                if item.kind == "telemetry" and key != "device_id":
                    continue
                value = item.get(key)
                if value is not None:
                    groups.setdefault(value, []).append(item)
            for value, group in groups.items():
                group.sort(key=lambda i: (i.ts, i.record_id))
                for prev, cur in zip(group, group[1:], strict=False):
                    if cur.ts - prev.ts <= gap and (prev.kind, cur.kind) != (
                        "telemetry",
                        "telemetry",
                    ):
                        uf.union(prev.record_id, cur.record_id)
                        self.edges.append((prev.record_id, cur.record_id, f"same {key} {value}"))
        clusters: dict[str, list[Item]] = {}
        for rid, item in self.items.items():
            clusters.setdefault(uf.find(rid), []).append(item)
        result = [
            sorted(c, key=lambda i: (i.ts, i.kind != "alert", i.record_id))
            for c in clusters.values()
            if any(i.kind == "alert" for i in c)
        ]
        return sorted(result, key=lambda c: (c[0].ts, c[0].record_id))

    # ---- stage 4: patterns --------------------------------------------------------------
    @staticmethod
    def _matches(item: Item, step: Step) -> bool:
        for key, wanted in step.match.items():
            value = item.get(key)
            if value is None or str(value) not in wanted:
                return False
        return True

    def match_pattern(self, pattern: Pattern, items: list[Item]) -> dict[str, Item] | None:
        """Earliest assignment of items to the pattern's steps, in order, or None."""

        def search(index: int, prev: Item | None, chosen: dict[str, Item]):
            if index == len(pattern.steps):
                return dict(chosen)
            step = pattern.steps[index]
            for item in items:
                if item.record_id in {c.record_id for c in chosen.values()}:
                    continue
                if prev is not None and item.ts < prev.ts:
                    continue
                if step.within and prev is not None and item.ts - prev.ts > step.within:
                    continue
                if not self._matches(item, step):
                    continue
                if any(
                    chosen.get(ref) is None or item.get(key) != chosen[ref].get(key)
                    for key, ref in step.same.items()
                ):
                    continue
                chosen[step.id] = item
                found = search(index + 1, item, chosen)
                if found is not None:
                    return found
                del chosen[step.id]
            if step.optional:
                return search(index + 1, prev, chosen)
            return None

        return search(0, None, {})

    def _confidence(self, base: int, items: list[Item]) -> tuple[int, list[tuple[int, str]]]:
        pts = self.s.confidence
        factors: list[tuple[int, str]] = [(base, "pattern base")]
        sec = [i for i in items if i.kind == "security"]
        sources = {(i.get("device_id"), i.get("source_ip")) for i in sec}
        outside = sorted(
            {ip for dev, ip in sources if ip not in self.s.allowed_ips.get(dev, set())}
        )
        if outside and "external_source" in pts:
            factors.append(
                (pts["external_source"], f"source not on allow-list: {', '.join(outside)}")
            )
        elif sources and "allowed_source" in pts:
            factors.append((pts["allowed_source"], "every source IP is on the device allow-list"))
        acted = [
            i
            for i in sec
            if (i.get("event_type") == "LOGIN_SUCCESS" or i.get("category") == "configuration")
            and i.row.get("role") in ("technician", "admin")
        ]
        windows = {i.row.get("within_maintenance_window") for i in acted} - {None}
        if 0 in windows and "outside_maintenance" in pts:
            factors.append(
                (pts["outside_maintenance"], "privileged activity outside the maintenance window")
            )
        elif windows == {1} and "inside_maintenance" in pts:
            factors.append(
                (pts["inside_maintenance"], "all privileged activity inside the maintenance window")
            )
        failures = [i for i in sec if i.get("event_type") == "LOGIN_FAILURE"]
        names = {i.row["user"] for i in failures}
        if len(names) >= 3 and "many_usernames" in pts:
            factors.append((pts["many_usernames"], f"failed logins tried {len(names)} usernames"))
        if (
            any(i.row.get("reason") == "unknown_user" for i in failures)
            and "unknown_accounts" in pts
        ):
            factors.append(
                (pts["unknown_accounts"], "failed logins for accounts that do not exist")
            )
        effects = [i.record_id for i in sec if i.record_id in self.effects]
        if effects and "physical_effect" in pts:
            factors.append(
                (pts["physical_effect"], "sensor shows the device reacting to the change")
            )
        for i in sec:
            if i.get("parameter") != "setpoint_c" or i.get("result") != "applied":
                continue
            low, high = self.s.safe_ranges.get(i.get("device_id"), (None, None))
            try:
                value = float(i.row.get("new_value"))
            except (TypeError, ValueError):
                continue
            if low is not None and not low <= value <= high and "unsafe_value" in pts:
                factors.append(
                    (pts["unsafe_value"], f"setpoint {value:g} °C outside the safe range")
                )
                break
        score = max(0, min(100, sum(p for p, _ in factors)))
        return score, factors

    def _level(self, score: int) -> str:
        levels = self.s.confidence.get("levels") or {"medium": 40, "high": 70}
        if score >= levels["high"]:
            return "high"
        return "medium" if score >= levels["medium"] else "low"

    # ---- run ----------------------------------------------------------------------------
    def run(self) -> CorrelationSummary:
        summary = CorrelationSummary()
        alerts = self._load_alerts()
        summary.alerts = len(alerts)
        self._pivots(alerts)
        for cluster in self._clusters():
            summary.candidates += 1
            built = self._build(cluster)
            if built is None:
                continue
            incident, members = built
            self._save(incident, members, summary)
        self.store.commit()
        return summary

    def _build(self, cluster: list[Item]):
        alerts = [i for i in cluster if i.kind == "alert"]
        pattern, chosen = None, None
        for p in self.s.patterns:
            chosen = self.match_pattern(p, cluster)
            if chosen is not None:
                pattern = p
                break
        if pattern is None:
            rel = self.s.related
            rules = {a.get("rule") for a in alerts}
            if not rel.get("create", True) or len(rules) < int(rel.get("min_rules", 2)):
                return None
            pattern = Pattern(
                id=RELATED_PATTERN,
                name="Related alerts",
                severity=str(rel.get("severity", "MEDIUM")).upper(),
                confidence_base=int(rel.get("confidence_base", 25)),
                steps=[],
                questions=list(rel.get("questions") or []),
                response=list(rel.get("response") or []),
            )
            chosen = {}

        base_rank = SEVERITY_LEVELS.index(pattern.severity)
        top_alert = max(SEVERITY_LEVELS.index(a.row["severity"]) for a in alerts)
        severity = SEVERITY_LEVELS[max(base_rank, top_alert)]
        score, factors = self._confidence(pattern.confidence_base, cluster)
        if pattern.steps:
            optional = [s for s in pattern.steps if s.optional and s.id in chosen]
            for s in optional:
                factors.append((10, f"optional step matched: {s.label}"))
            score = max(0, min(100, score + 10 * len(optional)))

        devices = sorted({i.get("device_id") for i in cluster} - {None})
        sec = [i for i in cluster if i.kind == "security"]
        entities = {
            "devices": devices,
            "users": sorted({i.row["user"] for i in sec if i.get("user")}),
            "claimed_users": sorted(
                {i.row["user"] for i in sec if i.get("event_type") == "LOGIN_FAILURE"}
            ),
            "source_ips": sorted({i.get("source_ip") for i in sec} - {None}),
            "sessions": sorted({i.get("session_id") for i in sec} - {None}),
        }
        steps = [
            {
                "id": s.id,
                "label": s.label,
                "optional": s.optional,
                "record_id": chosen[s.id].record_id if s.id in chosen else None,
                "ts": iso_utc(chosen[s.id].ts) if s.id in chosen else None,
            }
            for s in pattern.steps
        ]
        ids = {i.record_id for i in cluster}
        links = sorted({(a, b, reason) for a, b, reason in self.edges if a in ids and b in ids})
        where = ", ".join(devices) or "the fleet"
        ips = entities["source_ips"]
        title = f"{pattern.name} on {where}" + (f" from {ips[0]}" if len(ips) == 1 else "")
        if pattern.steps:
            parts = [f"{s['label'].lower()} ({s['record_id']})" for s in steps if s["record_id"]]
            description = "Sequence: " + " -> ".join(parts) + "."
        else:
            shared = sorted({r.split(" ")[1] for _, _, r in links if r.startswith("same ")})
            description = (
                f"Alerts connected by shared {', '.join(shared) or 'evidence'}: "
                f"{', '.join(a.record_id for a in alerts)}."
            )
        description += (
            f" {len(alerts)} alerts, {len(cluster) - len(alerts)} related records."
            " Correlation shows the events are related; an analyst must confirm the incident."
        )
        now = iso_utc(datetime.now(UTC))
        incident = {
            "incident_key": cluster[0].record_id,
            "pattern_id": pattern.id,
            "pattern_name": pattern.name,
            "severity": severity,
            "confidence": score,
            "confidence_level": self._level(score),
            "title": title,
            "description": description,
            "steps": json.dumps(steps),
            "confidence_factors": json.dumps(factors),
            "entities": json.dumps(entities),
            "links": json.dumps(links),
            "attack_ids": json.dumps(
                pattern.attack
                or sorted({t for a in alerts for t in json.loads(a.row["attack_ids"])})
            ),
            "implements": json.dumps(
                pattern.implements
                or sorted({t for a in alerts for t in json.loads(a.row["implements"])})
            ),
            "questions": json.dumps(pattern.questions),
            "response": json.dumps(pattern.response),
            "first_seen": iso_utc(cluster[0].ts),
            "last_seen": iso_utc(max(i.ts for i in cluster)),
            "created_at": now,
            "updated_at": now,
        }
        step_of = {chosen[s.id].record_id: s.label for s in pattern.steps if s.id in chosen}
        members = []
        for i in cluster:
            note = i.notes[0] if i.notes else "linked record"
            if i.record_id in step_of:
                note = f"step '{step_of[i.record_id]}': {note}"
            members.append((i.record_id, i.kind, iso_utc(i.ts), note))
        return incident, members

    def _save(self, incident: dict[str, Any], members, summary: CorrelationSummary) -> None:
        existing = sorted(
            self.store.incidents_containing(m[0] for m in members),
            key=lambda x: (x[4:12], int(x.rsplit("-", 1)[1])),
        )
        if existing:
            target = existing[0]
            incident["incident_key"] = self.store.incident_key(target)
        incident_id, created = self.store.save_incident(incident)
        for rid, kind, ts, note in members:
            self.store.add_incident_member(incident_id, rid, kind, ts, note)
        (summary.created if created else summary.updated).append(incident_id)
        for other in existing[1:]:
            self.store.mark_incident_merged(other, incident_id, incident["updated_at"])
            summary.merged.append((other, incident_id))
