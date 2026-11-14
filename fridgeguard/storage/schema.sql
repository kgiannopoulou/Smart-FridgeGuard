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

-- ---- status of security events ------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_status_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_ref   INTEGER NOT NULL REFERENCES security_events(id),
    ts          TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('normal', 'suspicious', 'malicious')),
    reason      TEXT NOT NULL,
    set_by      TEXT NOT NULL            -- 'ingest', a rule ID such as 'DR-4', or an analyst
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
-- Latest status per security event.
CREATE VIEW IF NOT EXISTS v_event_status AS
SELECT h.event_ref, h.status, h.reason, h.set_by, h.ts
FROM event_status_history h
JOIN (SELECT event_ref, MAX(id) AS max_id FROM event_status_history GROUP BY event_ref) last
  ON h.id = last.max_id;

-- The centralized event log in the format analysts read.
CREATE VIEW IF NOT EXISTS v_security_events AS
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
