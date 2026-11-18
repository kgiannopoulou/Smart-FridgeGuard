# Smart-FridgeGuard — Event Correlation

**Phase:** 2 – Cybersecurity detection engine
**Step:** 9 – Develop event correlation
**Status:** Done (2026-11-16)
**Related:** [detection-rules.md](detection-rules.md) · [alert-management.md](alert-management.md) ·
[investigation.md](investigation.md) · [requirements.md](requirements.md) DR-9

---

A single alert rarely tells the whole story. "5 failed logins" is noise on its own. It
matters when the same source then logs in, changes the setpoint and the fridge warms up.
Step 9 adds a **correlation engine** that links alerts with the events around them and
groups related activity into one **incident** for investigation.

Correlation shows that events are **related**. It does not prove an attack: every incident
starts as verdict `unverified`, and an analyst decides.

## 1. Quick start

```powershell
python -m fridgeguard simulate --duration 7d --faults-per-day 0.5 --show none   # correlates at the end
python -m fridgeguard correlate                       # re-run over the stored alerts (idempotent)

python -m fridgeguard incidents list                  # most severe first
python -m fridgeguard incidents show INC-20261117-001 # sequence, confidence, timeline, response
python -m fridgeguard incidents review INC-20261117-001 closed --verdict true_positive --note "Owner did not log in"
```

`detect` and `simulate` run the correlator automatically after detection.

## 2. How it works

The correlator ([`fridgeguard/detection/correlator.py`](../fridgeguard/detection/correlator.py))
works in four stages, all configured in [`config/correlation.yaml`](../config/correlation.yaml):

| Stage | What it does |
|-------|--------------|
| 1. Evidence | Every alert (except INFO) and the records it is based on. Each alert rule and event type is mapped to a kill-chain **stage**: `credential_access`, `initial_access`, `tampering`, `impact`, `session`. |
| 2. Pivots | The follow-up lookups an analyst would do by hand (below). They pull in records that no rule alerted on. |
| 3. Linking | Records that share a session, source IP, user or device and are close in time are connected (union-find). Each connected group is a candidate incident. |
| 4. Patterns | Ordered attack sequences name the incident, set its severity and list what to verify and how to respond. |

### Pivots

| Pivot | Question it answers | Setting |
|-------|---------------------|---------|
| `login_after_failures` | Did the source that just failed (DET-002) log in successfully afterwards? | 30 min |
| `session_activity` | What else happened in that login session (changes, logout)? | whole session |
| `changes_before_impact` | What was changed on the device before it went out of range (DET-003)? | 2 h back |
| `temperature_after_change` | Did the **independent sensor** react to an applied setpoint change? The first reading ≥ 1.5 °C from the pre-change value, moving towards the new setpoint, counts as a physical effect. | 1 h |

### Linking rules

| Shared value | Max. distance in time |
|--------------|-----------------------|
| `session_id` | 4 h |
| `source_ip` | 1 h |
| `user` | 1 h, authenticated activity only (a failed login's username is only a claim) |
| `device_id` | 1 h |

## 3. Attack patterns

Patterns are tried in order. The first one whose required steps all match, in order,
names the incident. A step can require that it shares a value with an earlier step
(`same: {source_ip: brute_force}`) and occurs within a time limit. Optional steps raise
confidence when they match.

| ID | Pattern | Steps | Severity |
|----|---------|-------|----------|
| COR-001 | Brute force, account takeover and configuration tampering | DET-002 → successful login from the same IP (≤ 30 min) → applied change in that session (≤ 30 min) → *optional* physical effect on the same device (≤ 2 h) | CRITICAL |
| COR-002 | Suspicious login followed by a configuration change | suspicious/malicious login → applied change in that session (≤ 10 min) → *optional* physical effect | HIGH |
| COR-003 | Brute force followed by a successful login | DET-002 → successful login from the same IP (≤ 30 min) | HIGH |
| COR-004 | Configuration change followed by a temperature excursion | applied setpoint/alarm change → DET-003 on the same device (≤ 2 h) | HIGH |
| COR-000 | Related alerts | connected alerts from ≥ 2 different rules that match no pattern | MEDIUM |

Every pattern carries ATT&CK technique IDs, requirement IDs, **questions the analyst must
verify** and a **recommended response** (contain, recover, safety, eradicate, follow up).
The investigation workflow ([investigation.md](investigation.md)) reuses them.

## 4. Confidence

Severity says how bad an incident *would be*. **Confidence** (0–100) says how strongly the
evidence supports a real attack. It starts at the pattern's base and is adjusted:

| Factor | Points |
|--------|--------|
| A source IP is not on the device's allow-list | +15 |
| Every source IP is on the allow-list | −10 |
| Privileged activity outside the maintenance window | +10 |
| All privileged activity inside the maintenance window | −15 |
| The failed logins tried 3 or more usernames | +10 |
| The failed logins included accounts that do not exist | +5 |
| The sensor shows the device reacting to the change | +15 |
| A setpoint was set outside the device's safe range | +10 |
| Optional pattern step matched | +10 |

Levels: below 40 **low**, 40–69 **medium**, 70+ **high**. Every factor is stored with its
reason and shown in the CLI, the dashboard and the report.

Example (seed 42, one simulated week):

```
INC-20261117-001  HIGH  COR-002 Suspicious login followed by a configuration change
confidence:  65 (medium)
   +40  pattern base
   -10  every source IP is on the device allow-list
   +10  privileged activity outside the maintenance window
   +15  sensor shows the device reacting to the change
   +10  optional step matched: Physical effect on the same device
sequence:
  Suspicious login                              EVT-000018
  Configuration modified in that session        EVT-000019
  Physical effect on the same device            TEL-003989
```

## 5. Re-running, growing and merging

- **Idempotent:** an incident is identified by its earliest record (`incident_key`).
  Running `correlate` again refreshes it instead of creating a duplicate.
- **Growing:** new records that link to an existing incident are added as members
  (`incident_members` is append-only).
- **Merging:** when new activity connects two existing incidents, the newer one is marked
  `merged_into` the older one and disappears from the lists, and nothing is deleted.
- **Reviews:** `incidents review` appends a status (`open`, `investigating`, `closed`)
  and a verdict (`unverified`, `true_positive`, `benign`, `false_positive`,
  `undetermined`) with a required note to `incident_reviews` (append-only). The latest
  review is the current state.

## 6. Results: one simulated week

```powershell
python -m fridgeguard simulate --duration 7d --faults-per-day 0.5 --show none
# detection: 27 new alerts from 42 rule hits (DET-001 6, DET-002 14, DET-003 2, DET-004 8, DET-005 2, DET-007 10)
# correlation: 5 new, 0 updated from 18 alerts (17 connected groups)
```

| Incident | Pattern | Confidence | What it is |
|----------|---------|-----------:|------------|
| INC-20261117-001 | COR-002 | 65 | maintenance_tech logged in on FRIDGE-002 at 04:00 local time and changed the setpoint; the sensor reacted |
| INC-20261118-001 | COR-002 | 65 | same pattern on FRIDGE-001 |
| INC-20261119-001 | COR-002 | 65 | same pattern on FRIDGE-001 |
| INC-20261121-001 | COR-002 | 65 | same pattern on FRIDGE-003 |
| INC-20261120-001 | COR-000 | 15 | a refused change by store_manager and a freezer excursion on FRIDGE-002, linked only by device and time (low confidence: probably unrelated) |

The four COR-002 incidents are the simulator's injected `off_hours_access` anomalies. The
brute-force bursts from 203.0.113.50 never led to a successful login, so no COR-001 or
COR-003 incident was raised. That is correct: those alerts stay single alerts. The
complete kill chain (COR-001) is covered by the hand-made test stories in
[`tests/test_correlation.py`](../tests/test_correlation.py).

## 7. Storage

| Table / view | Content |
|--------------|---------|
| `incidents` | one row per incident: pattern, severity, confidence + factors, entities, links, sequence steps, questions, response, ATT&CK, requirements, `merged_into` |
| `incident_members` | the alerts, security events and readings in each incident, with *why* each belongs (append-only) |
| `incident_reviews` | analyst status + verdict + note (append-only) |
| `v_incidents` | incidents with their latest review and member counts |

## 8. Code map

| File | Role |
|------|------|
| [`fridgeguard/detection/correlator.py`](../fridgeguard/detection/correlator.py) | `CorrelationSettings`, `Correlator` (pivots, union-find linking, pattern matching, confidence, save/merge) |
| [`config/correlation.yaml`](../config/correlation.yaml) | stages, pivots, linking windows, patterns, confidence points |
| [`fridgeguard/storage/store.py`](../fridgeguard/storage/store.py) | incident persistence and pivot queries (`logins_from`, `session_events`, `applied_changes`, …) |
| [`tests/test_correlation.py`](../tests/test_correlation.py) | kill chain, partial chains, time limits, idempotency, merging, reviews, CLI |
