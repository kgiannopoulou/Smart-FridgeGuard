"""Detection rule types. Importing this package registers every type in RULE_TYPES."""

from fridgeguard.detection.rules import (  # noqa: F401  (imports register the rule types)
    failed_logins,
    maintenance_hours,
    missing_heartbeat,
    temperature_limits,
    unauthorized_change,
)
from fridgeguard.detection.rules.base import RULE_TYPES, Record, Rule, RuleHit

__all__ = ["RULE_TYPES", "Record", "Rule", "RuleHit"]
