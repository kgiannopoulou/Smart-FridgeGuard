# Smart-FridgeGuard — Refrigerator and Activity Simulation

**Phase:** 1 – Planning, architecture and simulation
**Steps:** 5 – Refrigerator simulation engine · 6 – User and activity simulator
**Status:** Done (2026-11-14)
**Related:** [architecture.md](architecture.md) components 1 and 2

---

## 1. Quick start

```powershell
# Live: one reading per fridge per minute, runs until Ctrl+C
python -m fridgeguard simulate --realtime

# Live demo at 60x speed (one simulated minute per second)
python -m fridgeguard simulate --realtime --speed 60

# Generate three days of data as fast as possible, show only user activity
python -m fridgeguard simulate --duration 3d --show activity

# Fridges only, no users
python -m fridgeguard simulate --duration 12h --no-activity
```

Every event is printed to the console, appended to `data/events.jsonl` and stored in the
event database `data/fridgeguard.db` (both git-ignored; see [event-database.md](event-database.md)). `--out other.jsonl` changes the file and `--out -` disables it.

| Option | Default | Meaning |
|--------|---------|---------|
| `--duration` | continuous | Simulated time to run: `90s`, `30m`, `12h`, `3d`. |
| `--realtime` | off | Wait between readings. Without it, the simulation runs as fast as possible. |
| `--speed` | 1 | Speed-up factor in real-time mode. |
| `--seed` | 42 | Same seed → identical events (reproducible scenarios, NFR-7). |
| `--start` | `2026-11-16T04:00:00Z` | Simulated start (Monday 06:00 Athens time). |
| `--interval` | 60 | Seconds between readings. |
| `--show` | `all` | Console output: `all`, `activity` (no temperatures) or `none`. |
| `--no-activity` | off | Simulate fridges only. |
| `--anomalies-per-day` | 2 | Average number of suspicious activities per day; `0` = clean baseline. |
| `--faults-per-day` | 0 | Device faults (compressor failure, device offline) per day; added in Step 8, see [detection-engine.md §7](detection-engine.md#7-device-faults-for-testing-det-003-and-det-005). |
| `--db` | `data/fridgeguard.db` | Event database; `-` disables it. |
| `--no-detect` | off | Store events without running the detection rules. |

Defaults come from `config/simulation.yaml`; command-line options override them.

## 2. Step 5: refrigerator simulation engine

### 2.1 Simulated refrigerators

Defined in `config/devices.yaml`. Add an entry to grow the fleet.

| Device | Type | Setpoint | Expected range | Hysteresis | Door openings/h |
|--------|------|----------|----------------|------------|-----------------|
| FRIDGE-001 Dairy display fridge | fridge | 4.0 °C | 2.0 … 8.0 °C | 1.0 °C | 6 |
| FRIDGE-002 Back-room freezer | freezer | −18.0 °C | −22.0 … −15.0 °C | 2.0 °C | 2 |
| FRIDGE-003 Pharmacy vaccine fridge | medical fridge | 5.0 °C | 2.0 … 8.0 °C | 0.6 °C | 1 |

Each device also has its own insulation (`leak_per_min`), compressor strength
(`cooling_c_per_min`) and sensor noise. Device settings are validated at start-up;
for example, a setpoint outside the expected range or a compressor too weak to hold the
setpoint is rejected.

### 2.2 Temperature model

The temperatures are not random numbers. Each cabinet follows a small thermal model,
integrated in 5-second steps (`fridgeguard/simulator/fridge.py`):

| Effect | Rule |
|--------|------|
| Heat leaking in | `dT/dt = leak × (ambient − T)`; the leak is 8× larger while the door is open |
| Compressor | removes `cooling_c_per_min` while running |
| Thermostat | compressor **on** above `setpoint + hysteresis/2`, **off** below `setpoint − hysteresis/2` |
| Room temperature | slow random walk within ±1.5 °C of 22 °C |
| Door openings | random, only during opening hours (07:00–22:00), 15–90 s each |
| Sensor | Gaussian noise, reported with 0.1 °C resolution like a real probe |

The result is the slow sawtooth of a real refrigerator. Readings from the simulator
(FRIDGE-001, seed 42):

| Time (UTC) | Refrigerator | Temperature |
|------------|--------------|-------------|
| 04:00 | FRIDGE-001 | 3.8 °C |
| 04:01 | FRIDGE-001 | 3.6 °C |
| 04:02 | FRIDGE-001 | 3.6 °C |
| 04:03 | FRIDGE-001 | 4.0 °C |
| 04:04 | FRIDGE-001 | 3.8 °C |
| 04:05 | FRIDGE-001 | 4.1 °C |

Over a simulated 24 hours FRIDGE-001 stays between about 3.3 and 6.0 °C (mean 4.1 °C).
The short peaks are door openings.

The model also responds to the events later steps will simulate:

| Situation | Effect |
|-----------|--------|
| Setpoint raised (Step 6) | The cabinet settles at the new temperature over the next hour. |
| Door left open | Temperature climbs about 1 °C per minute. |
| Compressor fault (`set_compressor_fault`) | Drifts toward room temperature and leaves the expected range within hours. |
| Device offline (`set_offline`) | No readings are sent (the gap is detected later by DR-8). |

### 2.3 Reading format

One `telemetry.temperature` event per fridge per interval, using the common event schema
([architecture.md §5](architecture.md#5-common-event-schema)):

```json
{
  "event_id": "1f0c5d6e-…",
  "event_type": "telemetry.temperature",
  "device_id": "FRIDGE-001",
  "ts_device": "2026-11-16T04:03:00.000Z",
  "actor": null,
  "source_ip": null,
  "payload": {
    "temperature_c": 4.0,
    "setpoint_c": 4.0,
    "expected_min_c": 2.0,
    "expected_max_c": 8.0,
    "status": "ok",
    "door_open": false,
    "compressor_on": true
  },
  "scenario": "baseline",
  "ts_ingest": null,
  "hash": "sha256:…"
}
```

| Required field | Where |
|----------------|-------|
| Timestamp | `ts_device`, ISO 8601 UTC with milliseconds |
| Refrigerator ID | `device_id` |
| Current temperature | `payload.temperature_c` |
| Expected operating range | `payload.expected_min_c`, `payload.expected_max_c` |
| Configured setpoint | `payload.setpoint_c` |
| Device status | `payload.status`: `ok`, `door_open`, `out_of_range`, `compressor_fault` (offline devices send nothing) |

`ts_ingest` stays empty until the detection pipeline receives the event (Step 7+).

## 3. Step 6: user and activity simulator

### 3.1 Users and roles

Defined in `config/users.yaml`. All users are fictional.

| User | Role | Normal source IP | Permissions |
|------|------|------------------|-------------|
| `store_manager` | manager | 10.10.1.20 | view status, acknowledge alarms |
| `maintenance_tech` | technician | 10.10.1.30 | + change setpoint, alarm thresholds, defrost |
| `system_admin` | admin | 10.10.1.21 | + update firmware, manage users |
| `unknown_user` | none: **not a registered account** | 203.0.113.50, 198.51.100.23, 192.0.2.77 | none |

**Maintenance window:** Monday to Friday, 06:00–09:00 site time (Europe/Athens).

### 3.2 Authentication

`fridgeguard/generator/auth.py` acts as the device's login and settings interface.

- At start-up each registered user gets a random password. The device keeps only a
  **PBKDF2-HMAC-SHA256 hash with a 16-byte salt** (100 000 iterations); comparison uses
  `hmac.compare_digest`.
- The plain passwords exist only in memory, held by the simulated people who "remember"
  them. They are never written to `config/`, events or logs (NFR-6). A test checks that
  no password, hash or salt appears in any event.
- A login fails with `reason = unknown_user` (no such account) or `bad_password`.
- A successful login opens a session; logout records the session length.

### 3.3 Authorization

Every configuration change is checked against the user's role:

| Parameter | Permission needed | manager | technician | admin |
|-----------|-------------------|:-------:|:----------:|:-----:|
| `setpoint_c` | change_setpoint | ✗ | ✓ | ✓ |
| `alarm_low_c`, `alarm_high_c` | change_alarm_thresholds | ✗ | ✓ | ✓ |
| `defrost_interval_h` | change_defrost | ✗ | ✓ | ✓ |
| `firmware_version` | update_firmware | ✗ | ✗ | ✓ |

| Result | Meaning |
|--------|---------|
| `applied` | Authorized and valid; the fridge uses the new value immediately. |
| `denied` | The role lacks the permission; nothing changes. |
| `rejected` | Authorized but physically invalid (e.g. setpoint 99 °C). |

Changes outside the maintenance window are **applied but recorded** with
`within_maintenance_window: false`. Real stores need emergency repairs, so this is a
policy signal for detection (Step 7+), not a hard block. This is how an authorized
technician doing planned work is told apart from the same account used at 03:00.

### 3.4 Simulated activity

`fridgeguard/generator/activity.py` plans every simulated day in advance:

| Who | When (site time) | What | Label |
|-----|------------------|------|-------|
| store_manager | 07:00–08:30 and 20:00–21:30 daily | Logs in to check a fridge (15 % chance of one mistyped password first), logs out after 5–15 min | `baseline` |
| maintenance_tech | Maintenance window, weekdays | Logs in, nudges a setpoint by ±0.5 °C within the safe range, sometimes changes the defrost interval, logs out | `baseline` |
| system_admin | Maintenance window, 40 % of weekdays | Firmware update or defrost setting | `baseline` |
| outsider | Any time | 3–8 failed logins in quick succession, guessing usernames (`unknown_user`, `admin`, `root`, `system_admin`, …) and common passwords from an external IP | `unknown_login_attempts` |
| maintenance_tech account | 00:30–04:30 | Logs in outside the maintenance window and raises a setpoint by 1–2 °C | `off_hours_access` |
| store_manager | 09:00–19:00 | Tries to change a setpoint, **denied** by RBAC | `unauthorized_change_attempt` |

The last three are suspicious activities, injected `--anomalies-per-day` times on
average. Each event carries its ground-truth `scenario` label, so the detection engine
can later be scored against what really happened. The engine itself never reads the label.

### 3.5 Activity event formats

All activity events record the **timestamp** (`ts_device`), **user identity** (`actor`,
the username that was used or attempted), **source IP**, device and role.

| Activity | Event type | Key payload fields |
|----------|------------|--------------------|
| Successful login | `auth.login_success` | `method: password`, `role`, `session_id`, `within_maintenance_window` |
| Failed login / password authentication failure | `auth.login_failure` | `method`, `reason` (`bad_password`, `unknown_user`), `role` |
| Logout | `auth.logout` | `session_id`, `session_s` |
| Setpoint change | `config.change` | `parameter: setpoint_c`, `old_value`, `new_value`, `result`, `authorized`, `permission` |
| Other configuration modification | `config.change` | same, with `alarm_*`, `defrost_interval_h` or `firmware_version` |
| Access outside maintenance hours | any of the above | `within_maintenance_window: false` |

Example `config.change` (off-hours access):

```json
{
  "event_type": "config.change",
  "device_id": "FRIDGE-002",
  "ts_device": "2026-11-17T02:02:00.546Z",
  "actor": "maintenance_tech",
  "source_ip": "10.10.1.30",
  "payload": {
    "parameter": "setpoint_c",
    "old_value": -18.0,
    "new_value": -17.0,
    "change_source": "local_panel",
    "result": "applied",
    "role": "technician",
    "permission": "change_setpoint",
    "authorized": true,
    "within_maintenance_window": false,
    "session_id": "S-4c2ba24c"
  },
  "scenario": "off_hours_access"
}
```

### 3.6 Console output

`python -m fridgeguard simulate --duration 2d --show activity` (seed 42, times in UTC;
Athens is UTC+2 in November):

```
2026-11-16 04:13:31Z  FRIDGE-002  LOGIN   ok      system_admin (admin) from 10.10.1.21
2026-11-16 04:15:22Z  FRIDGE-002  CONFIG  APPLIED firmware_version 2.4.1 -> 2.4.2 by system_admin (admin)
2026-11-16 04:21:09Z  FRIDGE-003  LOGIN   FAILED  technician from 203.0.113.50 reason=unknown_user  <unknown_login_attempts>
2026-11-16 04:21:33Z  FRIDGE-003  LOGIN   FAILED  system_admin from 203.0.113.50 reason=bad_password  <unknown_login_attempts>
...
2026-11-16 05:20:23Z  FRIDGE-003  LOGIN   ok      maintenance_tech (technician) from 10.10.1.30
2026-11-16 05:22:46Z  FRIDGE-003  CONFIG  APPLIED setpoint_c 5.0 -> 4.5 by maintenance_tech (technician)
2026-11-16 05:44:24Z  FRIDGE-003  LOGOUT          maintenance_tech after 1441 s
...
2026-11-17 02:00:53Z  FRIDGE-002  LOGIN   ok      maintenance_tech (technician) from 10.10.1.30  [outside maintenance window]  <off_hours_access>
2026-11-17 02:02:00Z  FRIDGE-002  CONFIG  APPLIED setpoint_c -18.0 -> -17.0 by maintenance_tech (technician)  [outside maintenance window]  <off_hours_access>
...
2026-11-17 16:12:19Z  FRIDGE-003  CONFIG  DENIED  setpoint_c 4.0 -> 6.0 by store_manager (manager)  <unauthorized_change_attempt>
```

`<…>` shows the ground-truth label of injected activity. `[outside maintenance window]` is
shown for technician and admin accounts; the fact is stored in every event regardless of role.

## 4. Code map

| File | Responsibility |
|------|----------------|
| `fridgeguard/models.py` | Common `Event` dataclass, UTC timestamps, SHA-256 event hash |
| `fridgeguard/simulator/fridge.py` | Thermal model, thermostat, sensor, status, settings |
| `fridgeguard/simulator/fleet.py` | Loads `devices.yaml`, ticks all fridges |
| `fridgeguard/generator/auth.py` | Users, password hashing, sessions, RBAC, audit events |
| `fridgeguard/generator/activity.py` | Daily routines and injected suspicious activity |
| `fridgeguard/simulation.py` | Simulated clock, run loop (bounded, continuous, real-time) |
| `fridgeguard/sinks.py` | Console, JSON Lines, queue and in-memory outputs |
| `fridgeguard/timeutil.py` | Time windows in the site timezone |

## 5. Tests

`pytest` covers both steps (`tests/test_fridge_simulation.py`, `tests/test_auth_activity.py`):

- every reading has the required fields; one reading per device per tick, in time order;
- temperatures stay within each fridge's expected range over 24 h and change gradually;
- thermostat cycling, door openings, compressor fault, setpoint changes, offline devices;
- same seed → identical events;
- successful and failed logins (bad password, unknown user), logout, session length;
- no password, hash or salt in any event;
- RBAC: technician vs. manager vs. admin, denied and rejected changes, session required;
- off-hours changes applied but flagged;
- multi-day runs: clean baseline has no anomalies or off-window changes, anomalies are
  labelled, events are time-ordered, JSON Lines output is valid, continuous mode stops cleanly.
