# Smart-FridgeGuard — System Test Results

**Phase:** 4 – Testing, professional documentation and presentation  
**Step:** 14 – Test the complete system  
**Generated:** 2026-11-17 08:09 UTC by `python -m fridgeguard evaluate --seeds 20` (commit `9cbb577`, Python 3.14.7, Windows)  
**Related:** [test plan scenarios](../scenarios/) · [automated tests](../tests/test_system.py) · [requirements.md](requirements.md) · [threat-model.md](threat-model.md)

---

## 1. Summary

Every test case ran **20 times with different random seeds** (1-20): the seed changes sensor noise, door openings, user passwords, session IDs and (in TC-01) the whole day of normal activity. **200 of 200 runs passed** (all expected alerts with the expected severity, no false positive, expected incident and event status, notifications delivered, re-runs idempotent).

| Metric | Result |
|--------|--------|
| Detection accuracy (runs whose outcome matched the expectation exactly) | **100.0 %** (200 / 200) |
| Detection rate (expected alerts raised with the expected severity) | **100.0 %** (200 / 200) |
| Missed detections | **0** |
| False positives (alerts above INFO that no test expected) | **0** — 0 in 20 simulated days of normal operation |
| Precision | **100.0 %** |
| Time to detect | see section 4 (from immediate to 43.0 min) |
| Alert generation reliability | 200 / 200 runs idempotent on re-run, 10 / 10 cases deterministic per seed, 200 / 200 runs with every HIGH+ alert notified |
| Pipeline processing | 162,293 events in 28.4 s: 0.18 ms per event (simulate + validate + store + detect + notify) |

## 2. Test plan

Each case is a YAML file in [`scenarios/`](../scenarios/). The real simulator runs (thermal model, door openings, sensor noise, users with PBKDF2 passwords and RBAC); the scripted actions go through the same interfaces as normal activity (`AuthService.login / change_config / logout`, the fridges' fault controls). Every event passes through the production pipeline: `EventStore` (validation, SHA-256) → live `Detector` (rules + prioritizer) → `Notifier`, then `Correlator`. Only the scripted actions are abnormal: background anomalies and random faults are off.

| ID | Test | Expected result | What the system must produce | Passed |
|----|------|-----------------|------------------------------|--------|
| TC-01 | Normal operation | No security alert | no alert above INFO | 20 / 20 |
| TC-02 | Unauthorized setpoint change | Critical alert | DET-001 CRITICAL; DET-003 CRITICAL | 20 / 20 |
| TC-03 | Five failed logins | Brute-force alert | DET-002 HIGH | 20 / 20 |
| TC-04 | Temperature rises gradually | Temperature warning | DET-003 >= LOW | 20 / 20 |
| TC-05 | Device stops sending readings | Offline alert | DET-005 HIGH | 20 / 20 |
| TC-06 | Authorized technician changes settings | Authorized activity recorded | no alert above INFO; DET-007 INFO (activity recorded); events normal | 20 / 20 |
| TC-07 | Suspicious login followed by configuration change | Correlated incident | DET-004 MEDIUM; incident COR-002 | 20 / 20 |
| TC-08 | Brute force, account takeover and tampering | Critical incident (full kill chain) | DET-002 HIGH; DET-004 MEDIUM; DET-003 >= HIGH; incident COR-001 | 20 / 20 |
| TC-09 | Four failed logins (below the threshold) | No brute-force alert (boundary case) | no alert above INFO | 20 / 20 |
| TC-10 | Door left open for 10 minutes | No temperature alert (boundary case) | no alert above INFO; >= 5 out-of-range readings on FRIDGE-001 (it really happened) | 20 / 20 |

Anything else above INFO counts as a **false positive**; an expected alert that is missing or has another severity counts as a **missed detection**.

## 3. Results per test case

### TC-01 Normal operation

One full day of normal store activity (manager checks, technician maintenance inside the window, admin tasks, door openings) with no injected anomalies.

Script: 24 h of normal operation.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| no alert above INFO | - | - | - | - |

- false positives: **0**
- INFO maintenance records: 28 (authorized activity, not alerts)
- notifications (HIGH+): 0 sent, 0 held back
- deterministic per seed: yes

### TC-02 Unauthorized setpoint change

The store manager (role without change_setpoint) raises the dairy fridge setpoint from 4 to 12 °C. The compromised controller (threat T-4) applies it anyway; the fridge warms.

Script (3 h simulated): `login` +30.0 min login, `change` +32.0 min change, `logout` +34.0 min logout.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| DET-001 CRITICAL | CRITICAL | 20 / 20 | 0 s | 0 s |
| DET-003 CRITICAL | CRITICAL | 20 / 20 | 28.0 min (min 23.0 min, max 40.0 min) | 28.0 min (min 23.0 min, max 40.0 min) |

- false positives: **0**
- incidents formed: COR-004
- notifications (HIGH+): 60 sent, 0 held back
- deterministic per seed: yes

### TC-03 Five failed logins

Five login attempts in 80 s from an external IP, guessing usernames (one of them a real account with a wrong password).

Script (60.0 min simulated): `burst` +20.0 min fail_logins.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| DET-002 HIGH | HIGH | 20 / 20 | 80 s | 80 s |

- false positives: **0**
- notifications (HIGH+): 20 sent, 0 held back
- deterministic per seed: yes

### TC-04 Temperature rises gradually

The dairy fridge's compressor stops for 3 h; the cabinet warms slowly towards room temperature (door openings continue, store open).

Script (5 h simulated): `fault` +30.0 min compressor_fault.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| DET-003 >= LOW | HIGH | 20 / 20 | 29.5 min (min 20.0 min, max 38.0 min) | 29.5 min (min 20.0 min, max 38.0 min) |

- false positives: **0**
- notifications (HIGH+): 20 sent, 0 held back
- deterministic per seed: yes

### TC-05 Device stops sending readings

The back-room freezer sends no readings for 20 min (network or power loss).

Script (2 h simulated): `outage` +30.0 min offline.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| DET-005 HIGH | HIGH | 20 / 20 | 2.0 min | 2.0 min |

- false positives: **0**
- notifications (HIGH+): 20 sent, 0 held back
- deterministic per seed: yes

### TC-06 Authorized technician changes settings

The maintenance technician logs in from the usual workstation inside the maintenance window and nudges the setpoint from 4.0 to 4.5 °C.

Script (2 h simulated): `login` +30.0 min login, `change` +32.0 min change, `logout` +40.0 min logout.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| DET-007 INFO | INFO | 20 / 20 | 0 s | - |

- false positives: **0**
- INFO maintenance records: 20 (authorized activity, not alerts)
- scripted events all `normal`: 20 / 20
- notifications (HIGH+): 0 sent, 0 held back
- deterministic per seed: yes

### TC-07 Suspicious login followed by configuration change

The technician's account logs in at 03:00 local time (outside the maintenance window) and changes the freezer setpoint in the same session.

Script (2 h simulated): `login` +60.0 min login, `change` +62.0 min change, `logout` +70.0 min logout.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| DET-004 MEDIUM | MEDIUM | 20 / 20 | 0 s | - |

- false positives: **0**
- incident COR-002: 20 / 20
- notifications (HIGH+): 0 sent, 0 held back
- deterministic per seed: yes

### TC-08 Brute force, account takeover and tampering

The kill chain from the threat model: five failed logins from an external IP, then a successful login with the technician's stolen password from the same IP at night, the setpoint raised to 12 °C and the fridge warming.

Script (3 h simulated): `burst` +60.0 min fail_logins, `login` +64.0 min login, `change` +66.0 min change, `logout` +68.0 min logout.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| DET-002 HIGH | HIGH | 20 / 20 | 80 s | 80 s |
| DET-004 MEDIUM | MEDIUM | 20 / 20 | 0 s | - |
| DET-003 >= HIGH | HIGH | 20 / 20 | 40.0 min (min 37.0 min, max 43.0 min) | 40.0 min (min 37.0 min, max 44.0 min) |

- false positives: **0**
- incident COR-001: 20 / 20
- notifications (HIGH+): 40 sent, 0 held back
- deterministic per seed: yes

### TC-09 Four failed logins (below the threshold)

Boundary case for TC-03: four mistyped logins in one minute, one fewer than the DET-002 threshold of five. The events are stored (and marked suspicious where the account is unknown), but no alert may be raised.

Script (60.0 min simulated): `burst` +20.0 min fail_logins.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| no alert above INFO | - | - | - | - |

- false positives: **0**
- notifications (HIGH+): 0 sent, 0 held back
- deterministic per seed: yes

### TC-10 Door left open for 10 minutes

Boundary case for TC-04: at night the dairy fridge's door stays open for 10 min. The cabinet goes about 2-3 °C above its range for roughly 12 min and recovers, under the 15 min DET-003 needs, so it is recorded in the readings but raises no alert.

Script (2 h simulated): `door` +30.0 min door_open.

| Expected | Raised as | Detected | Time to detect | Time to notify |
|---|---|---|---|---|
| no alert above INFO | - | - | - | - |

- false positives: **0**
- out-of-range readings on FRIDGE-001 (the near-miss really happened, and stayed under the alert threshold): 10-13 per run, required >= 5
- notifications (HIGH+): 0 sent, 0 held back
- deterministic per seed: yes

## 4. Time to detect

Measured in simulated time from the scripted action (the step named in the scenario's `from`) to the alert's `first_seen`, over all runs. The delay is set by the rules' thresholds, not by processing: the pipeline needs 0.18 ms per event.

| Rule | Time to detect (median, min, max) | Why |
|------|-----------------------------------|-----|
| DET-001 | 0 s | raised on the change event (HIGH); CRITICAL once the fridge leaves its range (the DET-003 time in TC-02) |
| DET-002 | 80 s | at the 5th failed attempt; the clock starts at the 1st (attempts 20 s apart) |
| DET-003 | 31.5 min (min 20.0 min, max 43.0 min) | temperature must first leave the range (physics), then stay out 15 min |
| DET-004 | 0 s | on the login event itself |
| DET-005 | 2.0 min | 3 missed 60-s readings; the clock starts when the device goes silent |
| DET-007 | 0 s | on the change event itself (audit record) |

Time from the action to the first notification of a HIGH+ alert: 2.0 min (min 0 s, max 44.0 min). A temperature alert can be created as LOW (small deviation) and is notified when it is re-graded to HIGH while the fridge keeps warming.

## 5. Alert generation reliability

| Check | Result |
|-------|--------|
| Same seed run twice gives identical alerts, severities, times, incidents and notification count | 10 / 10 cases |
| Re-running detection over the stored events creates no new alert and no new notification | 200 / 200 runs |
| Every expected HIGH+ alert has a notification decision, none failed | 200 / 200 runs |
| Expected alerts raised in every one of the 20 seeds (no flaky detection) | 10 / 10 expected alerts |
| Events rejected by validation (all scripted and simulated events must be valid) | 0 |

## 6. Defects found by these tests and fixed

| # | Found in | Defect | Fix |
|---|----------|--------|-----|
| 1 | TC-04 (1 of 20 seeds) and TC-08 (3 of 20 seeds) before the fix | A temperature alert created as LOW (deviation still small) was below the HIGH notification threshold. The prioritizer re-graded it to HIGH only at the end of detection, and the notifier only re-checked alerts it had already notified, so the HIGH alert was never notified live. | The detector re-grades open temperature alerts every 5 min of activity time (`reprioritize_every_s` in `config/detection.yaml`) and reports a change through `on_alert`; the notifier also notifies an alert that crosses a channel's threshold for the first time. Regression tests: [`tests/test_system.py`](../tests/test_system.py). |
| 2 | TC-09, TC-10 (every run) | `notify run` and the `detect` command crashed on a database without any alert: the latest alert time defaulted to `"0"`, which is not a timestamp. | Escalation check skipped when there are no alerts. Regression test: `test_notify_run_and_detect_work_on_a_database_without_alerts`. |

## 7. Limitations

- **Verification, not field accuracy.** The cases test the behaviour the rules were designed for, plus two boundary cases just under the thresholds (TC-09, TC-10). 100 % here means the system does what its requirements say; it is not a measured accuracy against real attacks, which would need real data and attacks the rules were not written for.
- **Simulated data.** All events come from the simulator; real controllers may produce noisier data (clock drift, duplicate or late events).
- **Times are simulated time.** Time to detect shows the rule thresholds' delay; it does not include network or broker latency of a real deployment.
- **Stolen credentials.** In TC-08 the change is made with a valid account, so DET-001 (unauthorized change) does not fire; the attack is rated CRITICAL at the incident level (COR-001), and the individual alerts stay HIGH / MEDIUM.
- **TC-02 needs a compromised controller.** With working RBAC the store manager's change is refused (that case is DET-001 MEDIUM, covered by unit tests). TC-02 models threat T-4: the controller applies the change despite `authorized: false`.
- **Channels.** Notifications are checked with an in-memory channel; SMTP and Telegram are covered by unit tests with a local socket server and a mocked API.

## 8. Reproduce

```powershell
python -m fridgeguard evaluate --seeds 20          # all cases, writes docs/test-results.md
python -m fridgeguard evaluate --case TC-03 --seeds 5 --out -   # one case, print only
pytest tests/test_system.py                          # the same cases as automated tests
```

Total evaluation time: 58 s (200 runs + 10 determinism repeats).
