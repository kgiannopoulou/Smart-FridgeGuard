"""Detection engine: configurable rules DET-001..DET-006 and alerting (FR-5, FR-6)."""

from fridgeguard.detection.detector import Alert, DetectionSummary, Detector, load_rules

__all__ = ["Alert", "DetectionSummary", "Detector", "load_rules"]
