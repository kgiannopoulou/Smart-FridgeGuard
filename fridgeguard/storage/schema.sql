-- Smart-FridgeGuard centralized event database (Phase 2, Step 7)
--
-- Two kinds of events are stored separately:
--   telemetry        what a sensor measured (temperature, setpoint, device state).
--                    It has no user or source IP: a reading cannot say who changed a setting.
--   security_events  audit trail of who did what: logins, logouts, setpoint and
--                    configuration changes, with user, source IP, previous/new value.
--
-- Both tables are append-only (triggers block UPDATE and DELETE). The status of a
-- security event can change over time (ingest check, detection rules, analyst), so it
-- is kept in the append-only table event_status_history, and the views show the latest one.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_info (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    location    TEXT NOT NULL,
    device_type TEXT NOT NULL,
    safe_min_c  REAL NOT NULL,
    safe_max_c  REAL NOT NULL
);

-- ---- temperature telemetry ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS telemetry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    reading_id      TEXT GENERATED ALWAYS AS ('TEL-' || printf('%06d', id)) STORED,
    source_event_id TEXT NOT NULL UNIQUE,
    ts_device       TEXT NOT NULL,
    ts_ingest       TEXT NOT NULL,
    device_id       TEXT NOT NULL REFERENCES devices(device_id),
    temperature_c   REAL NOT NULL,
    setpoint_c      REAL NOT NULL,
    expected_min_c  REAL NOT NULL,
    expected_max_c  REAL NOT NULL,
    device_status   TEXT NOT NULL,
    door_open       INTEGER NOT NULL CHECK (door_open IN (0, 1)),
    compressor_on   INTEGER NOT NULL CHECK (compressor_on IN (0, 1)),
    scenario        TEXT NOT NULL,
    hash            TEXT NOT NULL,
    raw_json        TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_telemetry_reading_id ON telemetry(reading_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_device_time ON telemetry(device_id, ts_device);

-- ---- security audit events ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id                  TEXT GENERATED ALWAYS AS ('EVT-' || printf('%06d', id)) STORED,
    source_event_id           TEXT NOT NULL UNIQUE,
    ts_device                 TEXT NOT NULL,
    ts_ingest                 TEXT NOT NULL,
    device_id                 TEXT NOT NULL REFERENCES devices(device_id),
    event_type                TEXT NOT NULL CHECK (event_type IN (
                                  'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT',
                                  'SETPOINT_CHANGE', 'ALARM_THRESHOLD_CHANGE',
                                  'CONFIG_CHANGE', 'FIRMWARE_UPDATE')),
    category                  TEXT NOT NULL CHECK (category IN ('authentication', 'configuration')),
    user                      TEXT NOT NULL,
    role                      TEXT,
    source_ip                 TEXT NOT NULL,
    parameter                 TEXT,
    previous_value            TEXT,
    new_value                 TEXT,
    unit                      TEXT,
    result                    TEXT,     -- success / failure / applied / denied / rejected
    reason                    TEXT,     -- e.g. bad_password, unknown_user
    authorized                INTEGER CHECK (authorized IN (0, 1)),
    within_maintenance_window INTEGER CHECK (within_maintenance_window IN (0, 1)),
    session_id                TEXT,
    scenario                  TEXT NOT NULL,
    hash                      TEXT NOT NULL,
    raw_json                  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_security_event_id ON security_events(event_id);
CREATE INDEX IF NOT EXISTS idx_security_device_time ON security_events(device_id, ts_device);
CREATE INDEX IF NOT EXISTS idx_security_type_time ON security_events(event_type, ts_device);
CREATE INDEX IF NOT EXISTS idx_security_user_time ON security_events(user, ts_device);
-- correlation pivots (Step 9): session reconstruction and "what did this source do next"
CREATE INDEX IF NOT EXISTS idx_security_session ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_security_source_time ON security_events(source_ip, ts_device);

-- ---- status of security events ------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_status_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_ref   INTEGER NOT NULL REFERENCES security_events(id),
    ts          TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('normal', 'suspicious', 'malicious')),
    reason      TEXT NOT NULL,
    set_by      TEXT NOT NULL            -- 'ingest', a rule ID such as 'DET-001', or an analyst
);
CREATE INDEX IF NOT EXISTS idx_status_event ON event_status_history(event_ref, id);

-- ---- events that failed validation --------------------------------------------------
CREATE TABLE IF NOT EXISTS rejected_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ingest TEXT NOT NULL,
    error     TEXT NOT NULL,
    raw_json  TEXT NOT NULL
);

-- ---- append-only enforcement (NFR-2, control C-15) ---------------------------------
CREATE TRIGGER IF NOT EXISTS telemetry_no_update BEFORE UPDATE ON telemetry
BEGIN SELECT RAISE(ABORT, 'telemetry is append-only'); END;
CREATE TRIGGER IF NOT EXISTS telemetry_no_delete BEFORE DELETE ON telemetry
BEGIN SELECT RAISE(ABORT, 'telemetry is append-only'); END;

CREATE TRIGGER IF NOT EXISTS security_events_no_update BEFORE UPDATE ON security_events
BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS security_events_no_delete BEFORE DELETE ON security_events
BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END;

CREATE TRIGGER IF NOT EXISTS status_history_no_update BEFORE UPDATE ON event_status_history
BEGIN SELECT RAISE(ABORT, 'event_status_history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS status_history_no_delete BEFORE DELETE ON event_status_history
BEGIN SELECT RAISE(ABORT, 'event_status_history is append-only'); END;

CREATE TRIGGER IF NOT EXISTS rejected_no_update BEFORE UPDATE ON rejected_events
BEGIN SELECT RAISE(ABORT, 'rejected_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS rejected_no_delete BEFORE DELETE ON rejected_events
BEGIN SELECT RAISE(ABORT, 'rejected_events is append-only'); END;

-- ---- views --------------------------------------------------------------------------
-- Views hold no data, so they are dropped and recreated on every start: existing
-- databases always get the current definitions.
DROP VIEW IF EXISTS v_security_events;
DROP VIEW IF EXISTS v_event_status;
DROP VIEW IF EXISTS v_alerts;
DROP VIEW IF EXISTS v_incidents;
-- Latest status per security event.
CREATE VIEW v_event_status AS
SELECT h.event_ref, h.status, h.reason, h.set_by, h.ts
FROM event_status_history h
JOIN (SELECT event_ref, MAX(id) AS max_id FROM event_status_history GROUP BY event_ref) last
  ON h.id = last.max_id;

-- The centralized event log in the format analysts read.
CREATE VIEW v_security_events AS
SELECT
    e.event_id,
    e.ts_device                                   AS timestamp,
    e.device_id                                   AS device,
    e.event_type,
    e.user,
    e.role,
    CASE WHEN e.previous_value IS NULL THEN NULL
         ELSE e.previous_value || COALESCE(e.unit, '') END AS previous_value,
    CASE WHEN e.new_value IS NULL THEN NULL
         ELSE e.new_value || COALESCE(e.unit, '') END      AS new_value,
    e.source_ip,
    COALESCE(s.status, 'normal')                  AS status,
    s.reason                                      AS status_reason,
    s.set_by                                      AS status_set_by,
    e.result,
    e.reason,
    e.authorized,
    e.within_maintenance_window,
    e.scenario,
    e.id                                          AS ref
FROM security_events e
LEFT JOIN v_event_status s ON s.event_ref = e.id;

-- ---- security alerts (Step 8, prioritization and triage Step 10) -------------------
-- One alert groups repeated hits of a rule for the same subject (device, source IP, ...).
-- alert_key is deterministic (rule + subject + first evidence), so running detection
-- again over the same events finds the existing alert instead of creating a duplicate.
--
-- base_severity is what the rule says; severity is the current classification after
-- prioritization (config/prioritization.yaml) or an analyst override (severity_locked).
-- status is the triage state. Every change of severity or status is recorded in the
-- append-only alert_history table.
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT GENERATED ALWAYS AS ('ALR-' || printf('%06d', id)) STORED,
    alert_key       TEXT NOT NULL UNIQUE,
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL
                    CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    device_id       TEXT REFERENCES devices(device_id),
    subject         TEXT NOT NULL,            -- what the alert is about: device, source IP, user
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    attack_ids      TEXT NOT NULL,            -- JSON array of ATT&CK technique IDs
    implements      TEXT NOT NULL,            -- JSON array of requirement IDs (DR-x)
    first_seen      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new', 'under_investigation', 'confirmed',
                                      'false_positive', 'resolved')),
    base_severity   TEXT NOT NULL
                    CHECK (base_severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    severity_reason TEXT NOT NULL DEFAULT '',
    severity_locked INTEGER NOT NULL DEFAULT 0 CHECK (severity_locked IN (0, 1)),
    assigned_to     TEXT,
    updated_at      TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_alert_id ON alerts(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id, first_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id, first_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, severity);

-- Evidence: the telemetry readings and security events behind each alert (append-only).
CREATE TABLE IF NOT EXISTS alert_evidence (
    alert_ref   INTEGER NOT NULL REFERENCES alerts(id),
    record_id   TEXT NOT NULL,            -- EVT-000123 or TEL-004567
    kind        TEXT NOT NULL CHECK (kind IN ('security', 'telemetry')),
    ts          TEXT NOT NULL,
    note        TEXT NOT NULL,
    PRIMARY KEY (alert_ref, record_id)
);

CREATE TRIGGER IF NOT EXISTS alert_evidence_no_update BEFORE UPDATE ON alert_evidence
BEGIN SELECT RAISE(ABORT, 'alert_evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS alert_evidence_no_delete BEFORE DELETE ON alert_evidence
BEGIN SELECT RAISE(ABORT, 'alert_evidence is append-only'); END;

-- Who changed an alert's status or severity, when and why (append-only).
CREATE TABLE IF NOT EXISTS alert_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_ref   INTEGER NOT NULL REFERENCES alerts(id),
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,            -- analyst name, or 'prioritizer'
    field       TEXT NOT NULL CHECK (field IN ('status', 'severity', 'assigned_to')),
    old_value   TEXT,
    new_value   TEXT,
    note        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_history_alert ON alert_history(alert_ref, id);

CREATE TRIGGER IF NOT EXISTS alert_history_no_update BEFORE UPDATE ON alert_history
BEGIN SELECT RAISE(ABORT, 'alert_history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS alert_history_no_delete BEFORE DELETE ON alert_history
BEGIN SELECT RAISE(ABORT, 'alert_history is append-only'); END;

-- Alerts with hit count, time of the latest evidence and a numeric severity rank
-- (CRITICAL 4 ... INFO 0) for sorting the triage queue.
CREATE VIEW v_alerts AS
SELECT
    a.alert_id, a.rule_id, a.rule_name, a.severity, a.device_id, a.subject, a.title,
    a.description, a.attack_ids, a.implements, a.first_seen,
    -- latest of: when the alert condition was met, newest evidence
    MAX(a.first_seen, COALESCE(MAX(ev.ts), a.first_seen)) AS last_seen,
    COUNT(ev.record_id)                AS evidence_count,
    a.status, a.created_at, a.base_severity, a.severity_reason, a.severity_locked,
    a.assigned_to, a.updated_at,
    CASE a.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1 ELSE 0 END AS severity_rank,
    a.id AS ref
FROM alerts a
LEFT JOIN alert_evidence ev ON ev.alert_ref = a.id
GROUP BY a.id;

-- ---- correlated incidents (Step 9) --------------------------------------------------
-- An incident groups alerts and the events around them (same device, user, source IP or
-- session, close in time) into one investigation. The summary columns are derived data:
-- re-running correlation refreshes them. Membership and analyst reviews are append-only.
-- An incident is a hypothesis for an analyst to validate, not a verdict.
CREATE TABLE IF NOT EXISTS incidents (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id        TEXT NOT NULL UNIQUE,     -- INC-20261117-001 (date of first activity)
    incident_key       TEXT NOT NULL UNIQUE,     -- earliest record of the cluster
    pattern_id         TEXT NOT NULL,            -- COR-001 ... or COR-000 (related alerts)
    pattern_name       TEXT NOT NULL,
    severity           TEXT NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence         INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    confidence_level   TEXT NOT NULL CHECK (confidence_level IN ('low', 'medium', 'high')),
    title              TEXT NOT NULL,
    description        TEXT NOT NULL,
    steps              TEXT NOT NULL,            -- JSON: matched sequence steps
    confidence_factors TEXT NOT NULL,            -- JSON: [[points, reason], ...]
    entities           TEXT NOT NULL,            -- JSON: devices, users, source IPs, sessions
    links              TEXT NOT NULL,            -- JSON: how the records are connected
    attack_ids         TEXT NOT NULL,            -- JSON array of ATT&CK technique IDs
    implements         TEXT NOT NULL,            -- JSON array of requirement IDs
    questions          TEXT NOT NULL,            -- JSON: what the analyst must verify
    response           TEXT NOT NULL,            -- JSON: recommended response actions
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    merged_into        TEXT                      -- set when a later run joined two incidents
);
CREATE INDEX IF NOT EXISTS idx_incidents_first_seen ON incidents(first_seen);

CREATE TABLE IF NOT EXISTS incident_members (
    incident_ref INTEGER NOT NULL REFERENCES incidents(id),
    record_id    TEXT NOT NULL,                  -- ALR-…, EVT-… or TEL-…
    kind         TEXT NOT NULL CHECK (kind IN ('alert', 'security', 'telemetry')),
    ts           TEXT NOT NULL,
    note         TEXT NOT NULL,                  -- why the record belongs to the incident
    PRIMARY KEY (incident_ref, record_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_members_record ON incident_members(record_id);

CREATE TABLE IF NOT EXISTS incident_reviews (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_ref INTEGER NOT NULL REFERENCES incidents(id),
    ts           TEXT NOT NULL,
    analyst      TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'closed')),
    verdict      TEXT NOT NULL CHECK (verdict IN (
                     'unverified', 'true_positive', 'benign', 'false_positive', 'undetermined')),
    note         TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS incident_members_no_update BEFORE UPDATE ON incident_members
BEGIN SELECT RAISE(ABORT, 'incident_members is append-only'); END;
CREATE TRIGGER IF NOT EXISTS incident_members_no_delete BEFORE DELETE ON incident_members
BEGIN SELECT RAISE(ABORT, 'incident_members is append-only'); END;
CREATE TRIGGER IF NOT EXISTS incident_reviews_no_update BEFORE UPDATE ON incident_reviews
BEGIN SELECT RAISE(ABORT, 'incident_reviews is append-only'); END;
CREATE TRIGGER IF NOT EXISTS incident_reviews_no_delete BEFORE DELETE ON incident_reviews
BEGIN SELECT RAISE(ABORT, 'incident_reviews is append-only'); END;

-- Incidents with the latest analyst review and member counts. Every incident starts as
-- status 'open', verdict 'unverified' until an analyst reviews it.
CREATE VIEW v_incidents AS
SELECT
    i.incident_id, i.pattern_id, i.pattern_name, i.severity, i.confidence,
    i.confidence_level, i.title, i.description, i.steps, i.confidence_factors,
    i.entities, i.links, i.attack_ids, i.implements, i.questions, i.response,
    i.first_seen, i.last_seen, i.created_at, i.updated_at, i.merged_into,
    COALESCE(r.status, 'open')        AS status,
    CASE i.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1 ELSE 0 END AS severity_rank,
    COALESCE(r.verdict, 'unverified') AS verdict,
    r.analyst                         AS reviewed_by,
    (SELECT COUNT(*) FROM incident_members m
      WHERE m.incident_ref = i.id AND m.kind = 'alert')  AS alert_count,
    (SELECT COUNT(*) FROM incident_members m
      WHERE m.incident_ref = i.id AND m.kind != 'alert') AS record_count,
    i.id AS ref
FROM incidents i
LEFT JOIN (
    SELECT ir.* FROM incident_reviews ir
    JOIN (SELECT incident_ref, MAX(id) AS max_id FROM incident_reviews GROUP BY incident_ref) last
      ON ir.id = last.max_id
) r ON r.incident_ref = i.id;
