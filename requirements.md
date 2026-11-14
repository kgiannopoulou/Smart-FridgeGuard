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

| Rule ID | Detection | Example default threshold |
|---------|-----------|---------------------------|
| DR-1 | Brute-force login | ≥ 5 failed logins for one device within 5 min |
| DR-2 | Login outside normal hours | Successful login between 00:00 and 05:00 |
| DR-3 | Login from unknown source IP | IP not in the device's allow-list |
| DR-4 | Unauthorised configuration change | Change by an actor without the admin role |
| DR-5 | Dangerous setpoint change | Fridge setpoint set above 8 °C |
| DR-6 | Temperature out of safe range | > 8 °C for longer than 15 min |
| DR-7 | Sensor tampering / spoofing | Jump > 10 °C between consecutive readings, or physically impossible value |
| DR-8 | Device silence | No telemetry for > 3 × reporting interval |
| DR-9 | Correlated attack | Suspicious login followed by a config change on the same device within 10 min |

**Acceptance:** each rule fires on its attack scenario and does not fire on the normal baseline.

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
