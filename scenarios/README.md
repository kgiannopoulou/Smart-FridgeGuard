# Test scenarios (Phase 4, Step 14)

Each file is one controlled system test case. `python -m fridgeguard evaluate` runs them
through the real simulator and the full detection pipeline and writes
[`test_results.md`](../test_results.md); `tests/test_system.py` runs the same cases in pytest.

Times are UTC; the site is Europe/Athens (UTC+2 in November). Maintenance window: Mon-Fri
06:00-09:00 local (04:00-07:00 UTC). Store open 07:00-22:00 local.

| Field | Meaning |
|-------|---------|
| `start`, `duration` | simulated period (readings every 60 s from all three fridges) |
| `activity` | `true`: the normal day-to-day user activity runs in the background (no injected anomalies) |
| `steps` | scripted actions at an offset from `start`: `login`, `fail_logins`, `change`, `logout`, `compressor_fault`, `offline`, `door_open` |
| `expect.alerts` | alerts that must be raised: `rule`, `severity` (exact) or `min_severity`, `from` = step whose time starts the time-to-detect clock |
| `expect.allow` | other rules that may fire without counting as false positives |
| `expect.incident` | correlation pattern that must group the activity |
| `expect.events_status` | status every scripted security event must end with |
| `expect.out_of_range` | boundary cases: the near-miss must really happen (minimum out-of-range readings on a device) |

Any other alert above INFO is a **false positive**; an expected alert that is not raised
is a **missed detection**.
