"""Detection engine: configurable rules DET-001..DET-007, alerting (FR-5, FR-6) and
alert prioritization (Step 10)."""

from fridgeguard.detection.detector import Alert, DetectionSummary, Detector, load_rules
from fridgeguard.detection.prioritizer import Classification, Prioritizer, PrioritySettings

__all__ = [
    "Alert",
    "Classification",
    "DetectionSummary",
    "Detector",
    "Prioritizer",
    "PrioritySettings",
    "load_rules",
]
