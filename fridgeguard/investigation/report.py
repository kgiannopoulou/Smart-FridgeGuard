"""Incident investigation reports (Phase 3, Step 12) in Markdown and PDF.

The report follows the SOC template::

    INCIDENT REPORT
    Incident ID / Detection time / Affected device / Alert severity
    1. Initial alert          4. Event timeline      7. Recommended response
    2. Investigation performed 5. Findings           8. Escalation decision
    3. Evidence collected     6. Potential impact    9. Final status

``build_report`` turns a ``Case`` into a list of sections made of simple blocks; the
Markdown and PDF renderers draw the same blocks, so both formats always say the same.
Every decision is labelled as *recorded by the analyst* or *suggested (not confirmed)*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from fridgeguard.investigation.case import STEP_LABELS, Case, _ts
from fridgeguard.storage.store import INVESTIGATION_STEPS

MAX_EVIDENCE_ROWS = 30
MAX_TIMELINE_ROWS = 60

# ("p", text) | ("h", text) | ("ul" / "ol", [items]) | ("kv", [(key, value)])
# | ("table", head, rows[, pdf column widths])
Block = tuple


@dataclass
class Report:
    title: str
    header: list[tuple[str, str]]
    sections: list[tuple[str, list[Block]]] = field(default_factory=list)
    footer: str = ""


def _fmt(ts: str | None, tz: ZoneInfo | None = None) -> str:
    if not ts:
        return "-"
    t = _ts(ts)
    text = t.strftime("%Y-%m-%d %H:%M:%S UTC")
    if tz is not None:
        text += f" ({t.astimezone(tz):%H:%M} {tz.key})"
    return text


def _decision_text(case: Case, step: str) -> str:
    value, confirmed = case.decision(step)
    return value if confirmed else f"{value} (suggested, not confirmed)"


def _note(case: Case, step: str) -> str:
    entry = case.latest(step)
    return (
        f"{entry['note']} ({entry['analyst']}, {_fmt(entry['ts'])})" if entry else "Not recorded."
    )


def build_report(case: Case, generated_at: datetime | None = None) -> Report:
    a = case.alert
    tz = ZoneInfo(case.settings.timezone)
    dev = case.device
    inc = case.incident
    s = case.settings
    incident_id = case.investigation_id or "not opened"
    if inc:
        incident_id += f" (correlated incident {inc['incident_id']})"
    header = [
        ("Incident ID", incident_id),
        ("Detection time", _fmt(a["first_seen"], tz)),
        (
            "Affected device",
            f"{dev['device_id']} - {dev['name']}, {dev['location']}" if dev else "-",
        ),
        ("Alert severity", f"{a['severity']} (base {a['base_severity']})"),
    ]
    r = Report("INCIDENT REPORT", header)

    # 1. initial alert
    kv = [
        ("Alert", f"{a['alert_id']} - {a['title']}"),
        ("Rule", f"{a['rule_id']} {a['rule_name']}"),
        ("Description", a["description"]),
        ("Severity reason", a["severity_reason"] or "-"),
        ("First / last seen", f"{_fmt(a['first_seen'])} / {_fmt(a['last_seen'])}"),
        ("Evidence records", str(a["evidence_count"])),
        ("Triage status", f"{a['status']} (assigned to {a['assigned_to'] or 'nobody'})"),
        ("MITRE ATT&CK", ", ".join(a["attack_ids"]) or "-"),
        ("Requirements", ", ".join(a["implements"]) or "-"),
    ]
    if inc:
        kv.append(
            (
                "Correlated incident",
                f"{inc['incident_id']} {inc['pattern_id']} {inc['pattern_name']}"
                f" - {inc['severity']}, confidence {inc['confidence']}/100",
            )
        )
    r.sections.append(
        ("1. Initial alert", [("kv", kv), ("p", f"Analyst review: {_note(case, 'review_alert')}")])
    )

    # 2. investigation performed
    rows = []
    for step in INVESTIGATION_STEPS:
        e = case.latest(step)
        rows.append(
            [
                STEP_LABELS[step],
                "done" if e else "open",
                e["analyst"] if e else "-",
                _fmt(e["ts"]) if e else "-",
                (e["decision"] or "-") if e else "-",
                e["note"] if e else "-",
            ]
        )
    opened = case.investigation
    blocks: list[Block] = [
        (
            "p",
            f"Investigation opened by {opened['opened_by']} at {_fmt(opened['opened_at'])}; "
            f"{len(case.steps_done)} of {len(INVESTIGATION_STEPS)} steps recorded."
            if opened
            else "The investigation has not been opened yet.",
        ),
        (
            "table",
            ["Step", "State", "Analyst", "Time", "Decision", "Notes"],
            rows,
            (26, 8, 10, 18, 13, 25),
        ),
        ("h", "Questions to verify"),
        ("ul", case.playbook.get("verify", [])),
    ]
    revisions = len(case.entries) - len(case.steps_done)
    if revisions > 0:
        blocks.append(
            ("p", f"{revisions} earlier answer(s) were revised; all are kept in the audit trail.")
        )
    r.sections.append(("2. Investigation performed", blocks))

    # 3. evidence collected
    ev_rows = [[e["record_id"], e["kind"], _fmt(e["ts"]), e["detail"]] for e in case.evidence]
    blocks = [
        ("h", "Alert evidence"),
        (
            "table",
            ["Record", "Type", "Time", "Detail"],
            ev_rows[:MAX_EVIDENCE_ROWS],
            (14, 10, 20, 56),
        ),
    ]
    if len(ev_rows) > MAX_EVIDENCE_ROWS:
        blocks.append(("p", f"... and {len(ev_rows) - MAX_EVIDENCE_ROWS} more evidence records."))
    integ = case.integrity
    check = (
        f"{integ['verified']} of {integ['records']} evidence records re-verified against "
        "their stored SHA-256 hash"
        + (f"; problems: {'; '.join(integ['problems'])}" if integ["problems"] else "")
    )
    blocks.append(("kv", [("Integrity", check), ("Evidence set SHA-256", integ["sha256"])]))
    if dev:
        at = dev["at_alert"]
        blocks += [
            ("h", "Affected refrigerator"),
            (
                "kv",
                [
                    (
                        "Device",
                        f"{dev['device_id']} {dev['name']} ({dev['device_type']}"
                        f"{', safety-critical stock' if dev['critical'] else ''})",
                    ),
                    ("Location", dev["location"]),
                    (
                        "Expected range / setpoint",
                        f"{dev['expected_range']} / {dev['configured_setpoint_c']} °C",
                    ),
                    ("Allowed source IPs", ", ".join(dev["allowed_ips"]) or "-"),
                    (
                        "At the alert",
                        f"{at['temperature_c']:.1f} °C, setpoint {at['setpoint_c']} °C, "
                        f"{at['device_status']}"
                        if at
                        else "no reading",
                    ),
                    ("Window examined", f"{_fmt(dev['window'][0])} to {_fmt(dev['window'][1])}"),
                    (
                        "Readings",
                        f"{dev['readings']}, min {dev['min_c']} °C, max {dev['max_c']} °C"
                        if dev["readings"]
                        else "none",
                    ),
                    (
                        "Out of range",
                        f"{dev['minutes_out']} min in {len(dev['excursions'])} excursion(s), "
                        f"worst {dev['max_deviation_c']:.1f} °C beyond the range"
                        if dev["excursions"]
                        else "never",
                    ),
                    ("Longest telemetry gap", f"{dev['longest_gap_min']} min"),
                ],
            ),
        ]
    if case.users:
        blocks += [
            ("h", f"Users (activity in the last {s.history.days} days)"),
            (
                "table",
                [
                    "User",
                    "Registered",
                    "Role",
                    "Known IPs",
                    "Logins",
                    "Failed",
                    "Changes",
                    "Off-window logins",
                ],
                [
                    [
                        u["user"],
                        "yes" if u["registered"] else "NO",
                        u["role"],
                        ", ".join(u["known_ips"]) or "-",
                        u["logins"],
                        u["failed_logins"],
                        u["changes"],
                        u["logins_outside_window"],
                    ]
                    for u in case.users
                ],
                (20, 11, 12, 15, 9, 9, 10, 14),
            ),
        ]
    if case.source_ips:
        blocks += [
            ("h", "Source IPs"),
            (
                "table",
                [
                    "Source IP",
                    "On allow-list",
                    "Known for",
                    "Failed",
                    "Logins",
                    "Usernames",
                    "Devices",
                ],
                [
                    [
                        ip["source_ip"],
                        "yes" if ip["on_allow_list"] else "NO",
                        ", ".join(ip["known_for"]) or "-",
                        ip["failed_logins"],
                        ip["logins"],
                        ", ".join(ip["usernames"]),
                        ", ".join(ip["devices"]),
                    ]
                    for ip in case.source_ips
                ],
            ),
        ]
    if case.related_alerts:
        blocks += [
            ("h", "Other alerts on the device in the window"),
            (
                "ul",
                [
                    f"{x['alert_id']} {x['severity']} {x['rule_id']}: {x['title']} ({x['status']})"
                    for x in case.related_alerts
                ],
            ),
        ]
    r.sections.append(("3. Evidence collected", blocks))

    # 4. event timeline
    tl = [[_fmt(t["ts"]), t["source"], t["record"], t["detail"]] for t in case.timeline]
    blocks = [
        (
            "table",
            ["Time", "Source", "Record", "What happened"],
            tl[:MAX_TIMELINE_ROWS],
            (19, 12, 13, 56),
        )
    ]
    if len(tl) > MAX_TIMELINE_ROWS:
        blocks.append(("p", f"... and {len(tl) - MAX_TIMELINE_ROWS} more entries."))
    r.sections.append(("4. Event timeline", blocks))

    # 5. findings
    r.sections.append(
        (
            "5. Findings",
            [
                (
                    "kv",
                    [
                        ("Was the activity authorized?", _decision_text(case, "authorization")),
                        ("Analyst finding", _note(case, "authorization")),
                        ("Affected refrigerator", _note(case, "affected_device")),
                        ("Related events", _note(case, "related_events")),
                        ("User and source IP", _note(case, "user_and_ip")),
                    ],
                ),
                ("h", "Basis (from the evidence)"),
                ("ul", case.authorization.reasons),
                ("h", "Summary"),
                ("p", _note(case, "documentation")),
            ],
        )
    )

    # 6. potential impact
    impact, _ = case.decision("impact")
    r.sections.append(
        (
            "6. Potential impact",
            [
                (
                    "kv",
                    [
                        ("Impact level", _decision_text(case, "impact")),
                        ("Meaning", s.impact_levels.get(impact, "-")),
                        ("Analyst assessment", _note(case, "impact")),
                    ],
                ),
                ("h", "Basis (from the evidence)"),
                ("ul", case.impact.reasons),
            ],
        )
    )

    # 7. recommended response
    source = f"correlated incident {inc['incident_id']}" if inc else f"playbook for {a['rule_id']}"
    r.sections.append(
        (
            "7. Recommended response",
            [
                ("ol", case.playbook.get("response", [])),
                (
                    "p",
                    f"Source: {source} (config/investigation.yaml, config/correlation.yaml).",
                ),
            ],
        )
    )

    # 8. escalation
    esc, confirmed = case.decision("escalation")
    team = (
        s.teams.get(esc, {}).get("name", "No escalation")
        if esc != "not_required"
        else "No escalation"
    )
    r.sections.append(
        (
            "8. Escalation decision",
            [
                (
                    "kv",
                    [
                        (
                            "Decision",
                            f"{team} ({esc})"
                            + ("" if confirmed else " - suggested, not confirmed"),
                        ),
                        ("Analyst note", _note(case, "escalation")),
                    ],
                ),
                ("h", "Suggested from the evidence"),
                ("ul", case.escalation.reasons),
            ],
        )
    )

    # 9. final status
    doc = case.latest("documentation")
    r.sections.append(
        (
            "9. Final status",
            [
                (
                    "kv",
                    [
                        ("Final status", case.final_status),
                        ("Alert status", a["status"]),
                        (
                            "Documented by",
                            f"{doc['analyst']} at {_fmt(doc['ts'])}"
                            if doc
                            else "not documented yet",
                        ),
                        ("Report generated", _fmt((generated_at or datetime.now(UTC)).isoformat())),
                    ],
                ),
            ],
        )
    )
    r.footer = (
        "Generated by Smart-FridgeGuard from simulated data. Suggested decisions are rules over "
        "the stored events; only decisions recorded by an analyst are conclusions."
    )
    return r


# ---- Markdown -----------------------------------------------------------------------------
def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def to_markdown(report: Report) -> str:
    out = [f"# {report.title}", ""]
    out += [f"**{k}:** {_cell(v)}  " for k, v in report.header]
    out.append("")
    for title, blocks in report.sections:
        out += [f"## {title}", ""]
        for block in blocks:
            kind = block[0]
            if kind == "p":
                out += [block[1], ""]
            elif kind == "h":
                out += [f"### {block[1]}", ""]
            elif kind in ("ul", "ol"):
                items = block[1] or ["-"]
                out += [f"{'1.' if kind == 'ol' else '-'} {i}" for i in items] + [""]
            elif kind == "kv":
                out += ["| Field | Value |", "|---|---|"]
                out += [f"| {_cell(k)} | {_cell(v)} |" for k, v in block[1]] + [""]
            elif kind == "table":
                head, rows = block[1], block[2]
                if not rows:
                    out += ["_None._", ""]
                    continue
                out += ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
                out += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows] + [""]
    out += ["---", "", f"_{report.footer}_", ""]
    return "\n".join(out)


# ---- PDF ----------------------------------------------------------------------------------
_PDF_REPLACE = {
    "→": "->",
    "—": "-",
    "–": "-",
    "…": "...",
    "≥": ">=",
    "≤": "<=",
    "×": "x",
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
    "·": "-",
}


def _latin1(text: Any) -> str:
    s = str(text)
    for k, v in _PDF_REPLACE.items():
        s = s.replace(k, v)
    return s.encode("latin-1", "replace").decode("latin-1")


def to_pdf(report: Report) -> bytes:
    from fpdf import FPDF  # imported here so Markdown reports work without fpdf2
    from fpdf.fonts import FontFace

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.alias_nb_pages()
    footer = _latin1(report.footer)

    def page_footer():
        pdf.set_y(-12)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(110)
        pdf.cell(0, 5, f"{footer}   Page {pdf.page_no()}/{{nb}}", align="C")
        pdf.set_text_color(0)

    pdf.footer = page_footer
    pdf.add_page()
    width = pdf.epw
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, report.title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(180)
    pdf.line(15, pdf.get_y(), 15 + width, pdf.get_y())
    pdf.ln(2)
    for k, v in report.header:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(38, 6, _latin1(f"{k}:"))
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, _latin1(v), new_x="LMARGIN", new_y="NEXT")
    heading = FontFace(emphasis="BOLD", fill_color=(230, 233, 238))

    for title, blocks in report.sections:
        pdf.ln(3)
        if pdf.get_y() > pdf.h - 45:  # keep a section title with its first lines
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_fill_color(32, 52, 84)
        pdf.set_text_color(255)
        pdf.cell(0, 8, _latin1(f" {title}"), fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0)
        pdf.set_fill_color(255)
        pdf.ln(1.5)
        for block in blocks:
            kind = block[0]
            if kind == "p":
                pdf.set_font("Helvetica", "", 9)
                pdf.multi_cell(0, 5, _latin1(block[1]), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(1)
            elif kind == "h":
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 6, _latin1(block[1]), new_x="LMARGIN", new_y="NEXT")
            elif kind in ("ul", "ol"):
                pdf.set_font("Helvetica", "", 9)
                for i, item in enumerate(block[1] or ["-"], start=1):
                    mark = f"{i}." if kind == "ol" else "-"
                    pdf.cell(6, 5, mark)
                    pdf.multi_cell(0, 5, _latin1(item), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(1)
            elif kind == "kv":
                pdf.set_font("Helvetica", "", 8.5)
                with pdf.table(
                    col_widths=(32, 68),
                    first_row_as_headings=False,
                    text_align="LEFT",
                    line_height=4.6,
                    padding=1.2,
                ) as t:
                    for k, v in block[1]:
                        row = t.row()
                        row.cell(_latin1(k), style=FontFace(emphasis="BOLD"))
                        row.cell(_latin1(v))
                pdf.ln(2)
            elif kind == "table":
                head, rows = block[1], block[2]
                widths = block[3] if len(block) > 3 else None
                if not rows:
                    pdf.set_font("Helvetica", "I", 9)
                    pdf.cell(0, 5, "None.", new_x="LMARGIN", new_y="NEXT")
                    continue
                pdf.set_font("Helvetica", "", 7.5)
                with pdf.table(
                    headings_style=heading,
                    line_height=4,
                    padding=1,
                    col_widths=widths,
                    text_align="LEFT",
                    repeat_headings=1,
                ) as t:
                    hr = t.row()
                    for h in head:
                        hr.cell(_latin1(h))
                    for data_row in rows:
                        tr = t.row()
                        for c in data_row:
                            tr.cell(_latin1(c))
                pdf.ln(2)
    return bytes(pdf.output())


def render(case: Case, fmt: str = "md", generated_at: datetime | None = None) -> bytes:
    report = build_report(case, generated_at)
    if fmt == "md":
        return to_markdown(report).encode("utf-8")
    if fmt == "pdf":
        return to_pdf(report)
    raise ValueError("format must be 'md' or 'pdf'")
