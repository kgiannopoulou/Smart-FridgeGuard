# Smart-FridgeGuard — Requirements

**Phase:** 1 – Planning, architecture and simulation
**Step:** 1 – Define the project requirements
**Status:** Draft v1.0 (2026-11-14)

---

## 1. Purpose

Smart-FridgeGuard is a security monitoring system for a fleet of connected
("smart") refrigerators. It simulates refrigerator telemetry and user/administrative
activity, detects suspicious behaviour, raises security alerts, stores all events
for later analysis, and supports incident investigation.

The IoT foundation is **ThingsBoard Edge** (device connectivity, telemetry
ingestion, rule engine, dashboards). Security detection, event storage and
investigation reporting are built around it.

## 2. Scope

### In scope
- Software simulation of multiple refrigerators (no physical hardware required).
- Telemetry (temperature) and security-relevant events (logins, configuration changes).
- Rule-based detection of suspicious activity with configurable thresholds.
- Security alert generation, persistent event storage, monitoring dashboard.
- Incident investigation reports built from stored evidence.

### Out of scope (Phase 1)
- Real refrigerator firmware or physical devices.
- Machine-learning-based anomaly detection (may be considered in later phases).
- Production cloud deployment, multi-tenant billing, mobile apps.

## 3. Actors

| Actor | Description |
|-------|-------------|
| Simulated refrigerator | A virtual device that publishes telemetry and device events. |
| Household user | Logs in to a refrigerator / companion app; normal activity. |
| Administrator / technician | Changes device configuration (setpoints, firmware, network). |
| Attacker (simulated) | Produces malicious activity: brute-force logins, unauthorised config changes, tampering. |
| Security analyst | Monitors the dashboard, triages alerts, writes investigation reports. |

## 4. Functional requirements

Each requirement has an ID used for traceability in later phases (design, tests, reports).

### FR-1 Simulate multiple refrigerators
- The system shall simulate **N refrigerators** concurrently (N configurable, default ≥ 5).
- Each refrigerator shall have a unique device ID, name, location and model.
- Each simulated device shall connect to ThingsBoard Edge as an individual device.

**Acceptance:** starting the simulator with N = 5 produces 5 distinct, independently reporting devices.

### FR-2 Generate temperature readings
- Each refrigerator shall publish temperature readings (°C) at a configurable interval (default 10 s).
- Normal readings shall vary realistically around a setpoint (e.g. 4 °C ± 1 °C for the fridge
  compartment, −18 °C ± 2 °C for the freezer).
- The simulator shall be able to inject abnormal scenarios: door left open, compressor
  failure, sensor spoofing (impossible values or sudden jumps).

**Acceptance:** telemetry for every device is visible in ThingsBoard with correct timestamps;
each injected scenario produces the expected reading pattern.

### FR-3 Simulate user logins
- The simulator shall generate successful and failed login events per device.
- Each login event shall include: timestamp, device ID, username, source IP, result
  (success/failure) and authentication method.
- Attack scenarios shall include brute-force attempts, logins at unusual hours and logins
  from unknown source IPs.

**Acceptance:** normal and attack login scenarios can be triggered on demand and are recorded.

### FR-4 Record configuration changes
- The system shall record every configuration change: timestamp, device ID, actor,
  parameter changed, old value, new value and change source.
- Tracked parameters shall include at least: temperature setpoint, alarm thresholds,
  firmware version, network settings and user accounts.

**Acceptance:** every configuration change in a scenario appears in the event store with
before/after values.

### FR-5 Identify suspicious activity
The system shall apply detection rules to incoming events, including at least:

| Rule ID | Detection | Example default threshold | Default severity |
|---------|-----------|---------------------------|------------------|
| DR-1 | Brute-force login | ≥ 5 failed logins for one device within 5 min | High |
| DR-2 | Login outside normal hours | Successful login between 00:00 and 05:00 | Medium |
| DR-3 | Login from unknown source IP | IP not in the device's allow-list | Medium |
| DR-4 | Unauthorised configuration change | Configuration or setpoint change where the actor's role lacks the required permission for that specific action (see DR-4 logic below) | High |
| DR-5 | Dangerous setpoint change | Fridge setpoint set above 8 °C | High |
| DR-6 | Temperature out of safe range | > 8 °C for longer than 15 min | High |
| DR-7 | Sensor tampering / spoofing | Jump > 10 °C between consecutive readings, or physically impossible value | High |
| DR-8 | Device silence | No telemetry for > 3 × reporting interval | Medium |
| DR-9 | Correlated attack | Suspicious login followed by a config change on the same device within 10 min | Critical |
| DR-10 | Alarm disabled or alarm range widened | Applied change that sets `alarm_high_c` above or `alarm_low_c` below the device's expected operating range, or `alarm_low_c` ≥ `alarm_high_c` (alarm can never fire) | High |
| DR-11 | Detection configuration changed | Any change to detection thresholds, enabled rules, allow-lists, roles, maintenance window or event retention (hash of the config differs from the last recorded version) | High |

**Acceptance:** each rule fires on its attack scenario and does not fire on the normal baseline.

**DR-4 logic.** A configuration or setpoint change is unauthorised when the actor's role does
not have the required permission for that specific action. Roles and permissions are defined
in `config/users.yaml`, and every `config.change` event records the `permission` it needed
and whether the role had it (`authorized`).

| `authorized` in the event | DR-4 outcome |
|---------------------------|--------------|
| `true` | No unauthorised-change alert; the event stays in the audit log. |
| `false` | Alert, whether the device denied the change or applied it. |
| Missing or invalid (not a boolean, or the role/permission cannot be resolved) | Flagged for investigation as `suspicious`; never treated as authorised. |

Examples: a maintenance technician changing a setpoint (has `change_setpoint`) does **not**
trigger DR-4. The same technician attempting a firmware update (needs `update_firmware`), or
the store manager attempting any setpoint change, **does**. Changes made with a permitted
role but outside the maintenance window are not DR-4's job. Night-time cases are caught by
DR-2 (login 00:00–05:00) and DR-9 (login followed by a change); daytime changes outside the
window are recorded (`within_maintenance_window: false`) but no rule alerts on them yet.

DR-10 and DR-11 were added after threat modelling (threat-model.md §11), because no
existing rule covered these two threats:

- **DR-10** (threat T-4, ATT&CK for ICS T0838 Modify Alarm Settings, T0878 Alarm Suppression).
  DR-4 does not fire when the account has the technician or admin role (for example stolen
  credentials), and DR-5 covers only setpoints. DR-6 fires only after the goods are already
  warm, and widening the alarm range is exactly what keeps DR-6's device alarm silent.
  DR-10 catches the preparation step before any damage.
  *Expected alert:* "Alarm range on FRIDGE-00x widened to a..b °C by <user>", with the
  `config.change` event (old/new value, actor, source IP, role) as evidence.
- **DR-11** (threat T-7). Every other rule watches the refrigerators; DR-11 watches the
  monitoring system itself. Quietly raising a threshold or disabling a rule would blind
  detection without leaving an alert. NFR-4 requires such changes to be *logged*; DR-11
  turns that log entry into an alert.
  *Expected alert:* "Detection configuration changed: <file>", with the before/after hash,
  the diff and the user who made the change as evidence.

### FR-6 Generate security alerts
- A rule match shall create a security alert with: alert ID, timestamp, rule ID, severity
  (Low / Medium / High / Critical), device ID, description and links to the triggering events.
- Alerts shall be visible in ThingsBoard (alarms) and stored in the event database.
- Alerts shall have a lifecycle status: Open → Acknowledged → Resolved / False positive.

**Acceptance:** every rule match yields exactly one alert (repeated matches within a
de-duplication window are grouped instead of creating duplicates).

### FR-7 Store events in a database
- All telemetry, login events, configuration changes and alerts shall be stored persistently.
- Stored events shall be queryable by time range, device, event type, severity and actor.

**Acceptance:** events survive a restart of the system and can be retrieved with filters.

### FR-8 Display monitoring information in a dashboard
The dashboard shall show at least:
- fleet overview: device status (online/offline), current temperature per device;
- temperature history charts with safe-range bands;
- login activity (success vs. failure over time);
- recent configuration changes;
- open security alerts by severity;
- clear visual distinction between normal and suspicious activity.

**Acceptance:** an analyst can identify an ongoing attack scenario from the dashboard alone.

### FR-9 Produce incident investigation reports
- The system shall generate an incident report for a selected alert or time window.
- A report shall contain: incident summary, affected devices, timeline of related events,
  triggered rules, evidence (raw event records), impact assessment and recommended actions.
- Reports shall be exportable (Markdown and/or PDF).

**Acceptance:** a report generated for a simulated attack reconstructs the attack timeline
from stored events, without manual data entry.

## 5. Non-functional requirements

### NFR-1 Clear event timestamps
- All events shall carry timestamps in **UTC, ISO 8601** format with millisecond precision.
- Each event shall store both the device-side time and the ingestion (server) time, so
  clock drift or manipulation can be detected.
- Components shall use synchronised clocks (NTP or a shared host clock in the lab).

### NFR-2 Reliable event storage
- No acknowledged event shall be lost; ThingsBoard Edge shall buffer data while the upstream
  connection is unavailable and forward it once restored.
- Security events (logins, config changes, alerts) shall be stored append-only; records are
  never modified or deleted by normal operation.
- Each event shall have a unique ID to prevent duplicates.
- Data retention period shall be configurable (default 90 days for security events).

### NFR-3 Separation of normal and suspicious activity
- Every event shall carry a classification: `normal`, `suspicious` or `malicious`, plus the
  rule ID(s) that caused the classification.
- Simulated events shall carry a ground-truth scenario label (kept separate from the
  detection result) so detection accuracy can be measured.
- The dashboard and reports shall allow filtering by classification.

### NFR-4 Configurable detection thresholds
- All detection thresholds and time windows (FR-5) shall be defined in a configuration file,
  not hard-coded.
- Threshold changes shall take effect without code changes and shall themselves be logged
  as configuration changes.

### NFR-5 Clear investigation evidence
- Every alert shall link back to the exact events that triggered it.
- Evidence exported in reports shall include original event IDs and timestamps.
- Exported evidence shall include a hash (SHA-256) so its integrity can be verified later.

### NFR-6 Secure handling of credentials and logs
- No credentials, access tokens or API keys shall be committed to the repository;
  secrets are supplied via environment variables or a `.env` file listed in `.gitignore`.
- Each simulated device shall use its own access token / credential.
- Stored passwords (if any) shall be hashed; logs shall never contain plaintext passwords
  or full tokens (mask them, e.g. `abcd****`).
- Communication between devices, ThingsBoard Edge and the database should use TLS where
  supported.
- Access to the dashboard and event store shall require authentication with role-based
  permissions (analyst vs. administrator).

### NFR-7 Reproducibility and usability
- The full lab shall start with a single documented command (e.g. Docker Compose).
- Simulation scenarios shall be repeatable (seeded randomness) so results can be reproduced.

## 6. Traceability matrix

| Requirement | Planned component |
|-------------|-------------------|
| FR-1, FR-2, FR-3, FR-4 | Refrigerator simulator |
| FR-5, FR-6, NFR-4 | Detection engine / ThingsBoard rule chains |
| FR-7, NFR-2, NFR-3 | Event database |
| FR-8 | ThingsBoard dashboard |
| FR-9, NFR-5 | Incident report generator |
| NFR-1 | All components (shared event schema) |
| NFR-6 | Configuration, deployment and logging |
| NFR-7 | Docker Compose lab, scenario files |

## 7. Assumptions and constraints

- The project runs as a local lab on a single machine (Docker).
- ThingsBoard Edge (Community Edition) is used as the IoT foundation.
- All data is synthetic; no real household or personal data is processed.

## 8. Next steps

- Step 2: System architecture design (components, data flow, event schema).
- Step 3: Refrigerator and activity simulator.
