"""The L1 investigation workflow (Phase 3, Step 12): open a case for an alert, record each
step, and close it with a final status that is written back to the alert's triage status.

Every action goes through ``EventStore`` and is append-only: an answer can be revised by
recording the step again, and the report shows the latest answer.
"""

from __future__ import annotations

from fridgeguard.storage import EventStore
from fridgeguard.storage.store import INVESTIGATION_STEPS

# Decision steps that must be answered before the investigation can be documented.
REQUIRED_BEFORE_DOCUMENTATION = ("authorization", "impact", "escalation")

# Final status -> alert triage statuses to move through (Step 10 workflow).
FINAL_TO_ALERT: dict[str, tuple[str, ...]] = {
    "true_positive": ("confirmed", "resolved"),  # real, handled by L1
    "escalated": ("confirmed",),  # real, stays open with the team it went to
    "false_positive": ("false_positive",),
    "benign": ("resolved",),  # real activity, but authorized / harmless
    "undetermined": (),  # stays under investigation
}


def start(store: EventStore, alert_id: str, analyst: str) -> tuple[str, bool]:
    """Open (or reopen) the investigation of an alert and take ownership of the alert."""
    if not analyst.strip():
        raise ValueError("an analyst name is required")
    investigation_id, created = store.open_investigation(alert_id, analyst)
    alert = store.alert(alert_id)
    if alert["status"] == "new":
        store.set_alert_status(
            alert_id, "under_investigation", analyst, f"{investigation_id} opened"
        )
    return investigation_id, created


def missing_before_documentation(store: EventStore, investigation_id: str) -> list[str]:
    done = {e["step"] for e in store.investigation_entries(investigation_id)}
    return [s for s in REQUIRED_BEFORE_DOCUMENTATION if s not in done]


def record(
    store: EventStore,
    investigation_id: str,
    step: str,
    analyst: str,
    note: str,
    decision: str | None = None,
) -> list[str]:
    """Record one workflow step. Documenting the investigation (the final step) also moves
    the alert to the matching triage status. Returns the alert statuses passed through."""
    inv = store.investigation(investigation_id)
    if inv is None:
        raise KeyError(f"unknown investigation {investigation_id}")
    if step not in INVESTIGATION_STEPS:
        raise ValueError(f"step must be one of {tuple(INVESTIGATION_STEPS)}")
    if step == "documentation":
        missing = missing_before_documentation(store, investigation_id)
        if missing:
            raise ValueError(
                "record these decisions before documenting the investigation: " + ", ".join(missing)
            )
    store.add_investigation_entry(investigation_id, step, analyst, note, decision)
    if step != "documentation":
        return []
    moved: list[str] = []
    reason = f"{investigation_id} documented as {decision}: {note.strip()}"
    for target in FINAL_TO_ALERT[decision]:
        moved += store.move_alert_to(inv["alert_id"], target, analyst, reason)
    return moved
