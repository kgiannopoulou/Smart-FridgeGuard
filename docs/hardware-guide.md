# Smart-FridgeGuard — Hardware Implementation Guide

**Phase 4 · Step 15**
**Scope:** how a supermarket could move from the Smart-FridgeGuard software simulation to a
real, independent refrigeration security-monitoring deployment.

> **Safety notice — read first.**
> Smart-FridgeGuard is an **independent, read-only security and integrity monitor**. It does
> **not** replace certified refrigeration alarms, the refrigeration controller's own safety
> functions, HACCP temperature records or a pharmacy's validated cold-chain logger. Any real
> deployment must be designed and approved by **refrigeration engineers** (equipment,
> wiring, controller integration) and **food-safety / pharmacy specialists** (critical limits,
> record keeping, corrective actions). Nothing in this guide authorises connecting to, or
> changing, live refrigeration equipment without that approval and the equipment
> manufacturer's guidance.

---

## Contents

1. [From simulation to hardware](#1-from-simulation-to-hardware)
2. [Hardware components and their purpose](#2-hardware-components-and-their-purpose)
3. [Implementation levels](#3-implementation-levels)
   - [Level 1 – Low-cost prototype](#level-1--low-cost-prototype)
   - [Level 2 – Small supermarket](#level-2--small-supermarket)
   - [Level 3 – Enterprise supermarket chain](#level-3--enterprise-supermarket-chain)
4. [Integration protocols: MQTT and Modbus](#4-integration-protocols-mqtt-and-modbus)
5. [Secure communication](#5-secure-communication)
6. [Network segmentation](#6-network-segmentation)
7. [Authentication and authorization](#7-authentication-and-authorization)
8. [Sensor calibration](#8-sensor-calibration)
9. [Independent temperature verification](#9-independent-temperature-verification)
10. [Safe integration with existing refrigeration equipment](#10-safe-integration-with-existing-refrigeration-equipment)
11. [Mapping hardware data to the Smart-FridgeGuard event schema](#11-mapping-hardware-data-to-the-smart-fridgeguard-event-schema)
12. [Commissioning checklist](#12-commissioning-checklist)
13. [Limitations and approvals](#13-limitations-and-approvals)
14. [Traceability to the threat model](#14-traceability-to-the-threat-model)
15. [References](#15-references)

---

## 1. From simulation to hardware

In the lab every component is software ([architecture.md](architecture.md)):

| Lab component (today) | Real-world equivalent |
|-----------------------|-----------------------|
| `fridgeguard/simulator/fridge.py` thermal model | The refrigerated cabinet, cold room or freezer itself |
| Simulated temperature reading (`telemetry.temperature`) | Controller probe **plus** an independent sensor (DS18B20, PT100/PT1000 transmitter) |
| Simulated controller settings (setpoint, alarm delay, defrost) | Refrigeration controller or PLC parameters, read via Modbus/BACnet/vendor gateway |
| `fridgeguard/generator/auth.py` logins and config changes | Audit log of the controller, the vendor's remote-management portal, the store's BMS/HMI |
| `device.heartbeat` events | Gateway/sensor keep-alive messages |
| `QueueSink` → detection engine | MQTT broker / IoT gateway → ingestion service → detection engine |
| SQLite event store | SQLite (Level 1), PostgreSQL/TimescaleDB (Level 2–3), plus SIEM (Level 3) |
| Streamlit SOC dashboard, notifications | Same dashboard and notifications, hosted on a monitoring server |

The detection, correlation, prioritization, investigation and notification code does not
need to change: real hardware only has to produce the **same event envelope**
([section 11](#11-mapping-hardware-data-to-the-smart-fridgeguard-event-schema)).

The key design principle carried over from the threat model is **independence**: the
monitoring path must not depend on the device it is monitoring. A compromised controller
(T-4) can report a normal temperature while the product warms up; only a separate sensor
on a separate path can reveal that (control C-17).

```
         Existing refrigeration system                 Smart-FridgeGuard (added)
  +-------------------------------------------+   +-----------------------------------+
  | Cabinet / cold room                        |   |                                   |
  |   controller probe --> Refrigeration       |   |  Independent sensor (DS18B20 /    |
  |                        controller / PLC ---+-->|  PT100 transmitter) --> gateway   |
  |                        (alarms, setpoint)  | read  |                    |          |
  |                                            | only  |                    v          |
  |   Certified alarm / HACCP logger (stays!)  |   |  Detection engine, event store,   |
  +-------------------------------------------+   |  SOC dashboard, notifications     |
                                                  +-----------------------------------+
```

---

## 2. Hardware components and their purpose

| Hardware | Purpose | Used at level | Notes |
|----------|---------|---------------|-------|
| **ESP32** microcontroller | Prototype sensor collection | 1 | Wi-Fi + Bluetooth MCU; reads sensors and publishes MQTT over TLS. Ideal for a lab or a pilot cabinet, not for certified records. |
| **DS18B20** digital temperature sensor | Independent temperature measurement | 1 (and as a cheap second opinion in 2) | 1-Wire digital sensor, −55 °C to +125 °C, typical accuracy ±0.5 °C between −10 °C and +85 °C, 9–12-bit resolution. Use the waterproof stainless-steel probe version. Each sensor has a unique 64-bit ROM ID that can be bound to a device ID. |
| **Industrial temperature transmitter** | Commercial-grade temperature monitoring | 2, 3 | PT100/PT1000 RTD probe with a transmitter giving 4–20 mA, RS-485 Modbus RTU or a wireless (e.g. LoRaWAN) output. Better accuracy and stability than a DS18B20, available with calibration certificates, suitable food-contact/IP-rated probes. |
| **PLC** (programmable logic controller) | Refrigeration process control | 3 (already present in many sites) | Runs compressor, defrost, fans and alarms in larger plants and cold rooms. Smart-FridgeGuard only **reads** it (setpoints, states, alarms, change logs); it never writes to it. |
| **Industrial IoT gateway** | Secure telemetry transfer | 2, 3 | DIN-rail or embedded edge computer: polls Modbus/BACnet, buffers data during outages (C-16), converts to MQTT/HTTPS over TLS, can run ThingsBoard Edge. Choose one with secure boot, signed updates and a supported OS. |
| **Managed switch** | Network segmentation | 2, 3 | VLANs, port security / 802.1X, disabled unused ports, port mirroring (SPAN) for passive OT monitoring. Industrial (DIN-rail, wide temperature) variants for plant rooms. |
| **UPS** (uninterruptible power supply) | Power backup | 1 (optional), 2, 3 | Keeps sensors, gateway, switch and firewall running during a power cut, so the monitor can prove what happened when the refrigeration lost power. Must report its own status (on battery, low battery) as events. |
| **Industrial firewall** | Network access control | 3 (a small business firewall at 2) | Enforces the zone/conduit rules in [section 6](#6-network-segmentation), terminates site-to-central VPN, ideally with OT protocol awareness (e.g. allow Modbus *read* function codes only). |

Supporting items (all levels): IP-rated enclosures, cable glands, food-safe probe
mounting, labelled cabling, tamper-evident seals on sensor housings and service ports (C-9),
and spare sensors for calibration swaps.

---

## 3. Implementation levels

### Level 1 – Low-cost prototype

**Goal:** prove the end-to-end data path with real sensors on one or two cabinets.
**Stack:** ESP32 + DS18B20 + Python backend (this repository).

```
  DS18B20 probe(s) --1-Wire--> ESP32 --Wi-Fi, MQTT over TLS--> Mosquitto broker
                                                                   |
                                                       Python bridge (MQTT -> Event JSON)
                                                                   |
                                     Smart-FridgeGuard: event store, detection, dashboard
```

| Item | Quantity | Approx. cost (EUR) |
|------|----------|--------------------|
| ESP32 development board | 1 per cabinet | 5–15 |
| Waterproof DS18B20 probe (stainless steel, 1–3 m cable) | 1–2 per cabinet | 3–8 each |
| 4.7 kΩ pull-up resistor, enclosure, USB power supply | 1 set | 10–20 |
| Raspberry Pi or small PC running Mosquitto + Smart-FridgeGuard | 1 | 0–150 (reuse a laptop for a lab) |
| Small UPS / USB power bank (optional) | 1 | 20–80 |

Prices are indicative ranges, not quotes.

**Wiring:** DS18B20 VDD → 3.3 V, GND → GND, DQ → a GPIO (e.g. GPIO4) with a 4.7 kΩ pull-up
to 3.3 V. Several sensors can share one 1-Wire bus; each is addressed by its ROM ID. Route
the probe cable through the door gasket only with the refrigeration technician's agreement
(a badly routed cable breaks the seal and causes the excursion you are trying to detect) —
cabinets often have a spare probe entry or drain-line route.

**Probe placement:** in the warmest representative product zone (usually top front, near
the door or air return), not directly in the evaporator's discharge airflow. For a realistic
"product temperature", the probe can sit in a small bottle of glycol or a food simulant,
which damps the air-temperature spikes from door openings.

**Firmware outline** (illustrative only — not part of the tested code in this repository):

```cpp
// ESP32 + DS18B20 publisher, Arduino framework.
// Libraries: OneWire, DallasTemperature, WiFiClientSecure, PubSubClient.
// Reads every 60 s and publishes JSON to fridgeguard/<device_id>/telemetry over TLS (8883).
// The broker's CA certificate and a per-device credential are provisioned at flash time,
// never hard-coded in source control (C-2, C-20).

float t = sensors.getTempCByIndex(0);
bool valid = (t != DEVICE_DISCONNECTED_C) && (t != 85.0f);   // 85.0 = power-on reset value
// publish {"device_id":"FRIDGE-001","sensor_id":"28-…","temperature_c":t,
//          "valid":valid,"uptime_s":…,"firmware":"proto-0.1","seq":n}
```

**Backend:** a small bridge subscribes to the broker and converts each message into the
Smart-FridgeGuard event envelope (section 11), then appends it to a JSONL file or writes it
directly through `EventStore`. JSONL can be loaded with the existing CLI:

```powershell
python -m fridgeguard events import data/hardware-events.jsonl
python -m fridgeguard detect
streamlit run app.py
```

> The MQTT bridge (`MqttSink` / subscriber) is a planned extension
> ([architecture.md §11](architecture.md#11-relationship-to-thingsboard-edge)); it is
> not implemented in this repository yet.

**What Level 1 proves:** real telemetry, heartbeat loss (unplug the ESP32 → DET-005),
temperature excursions (DET-003), the dashboard and notifications working on live data.

**What it does not provide:** certified accuracy, tamper resistance, controller audit logs
(no setpoint/login events unless the controller exposes them), or anything suitable as a
food-safety record. Wi-Fi in a store is also easy to jam or disrupt.

### Level 2 – Small supermarket

**Goal:** continuous, independent monitoring of all cabinets and cold rooms in one store
(roughly 10–60 measuring points), with central alerting.
**Stack:** commercial temperature sensors + IoT gateway + centralized monitoring server.

```
  PT100/PT1000 transmitters (RS-485 Modbus RTU, or LoRaWAN/wireless sensors)
        |
        v
  Industrial IoT gateway (Modbus master, local buffer, ThingsBoard Edge optional)
        |   read-only Modbus/BACnet poll of controllers (if approved)
        |
  Managed switch: VLANs  [Sensors/OT]  [Monitoring]  [Store IT]
        |
  Business firewall ---- VPN / TLS ----> Monitoring server (on-site or hosted)
                                         Smart-FridgeGuard + PostgreSQL + dashboard
  UPS: gateway, switch, firewall, sensor power supply
```

| Element | Recommendation |
|---------|----------------|
| Sensors | Commercial RTD or digital probes with calibration certificates, IP65+ housings; wired RS-485 preferred for reliability, wireless (LoRaWAN, proprietary sub-GHz) where cabling is impractical. |
| Gateway | Industrial IoT gateway with secure boot, local buffering for at least 72 h, TLS client certificates, remote update with signed images. |
| Controller data | Read-only access to the refrigeration controllers' alarm, setpoint and event registers via the vendor's gateway or Modbus, **only with the installer's approval**. This is what feeds DET-001 (unauthorized setpoint change) and DET-006 in a real store. |
| Server | Small on-site server or hosted VM: Smart-FridgeGuard, PostgreSQL (instead of SQLite for concurrent writers), dashboard behind HTTPS and login, nightly backup. |
| Network | Managed switch with VLANs; a business firewall separating sensors/OT from store IT, POS and guest Wi-Fi. |
| Power | UPS sized for gateway, switch, firewall and sensor PSU for at least the time needed to send alerts and prove the outage window (typically 30–120 min). |
| Alerts | Email/Telegram channels from `config/notifications.yaml`, plus a phone escalation path agreed with the store manager and the refrigeration service company. |

**What Level 2 adds:** commercial-grade, calibrated measurement independent from the
controllers; correlation of temperature with real controller events; buffering during
network outages; segmentation so a compromised store PC cannot reach the controllers.

### Level 3 – Enterprise supermarket chain

**Goal:** many stores, central security operations, compliance reporting.
**Stack:** industrial controllers + segmented OT network + centralized SIEM + security
monitoring across multiple stores.

```
  Store 1..N (identical template)
  +--------------------------------------------------------------------+
  | Level 0-1  Sensors, transmitters, refrigeration controllers / PLCs  |
  | Level 2    Site HMI / BMS, IoT gateway (Edge), passive OT sensor    |
  | Site DMZ   Gateway uplink, jump host for vendor access (MFA)        |
  |            Industrial firewall + UPS + managed switches             |
  +-------------------------|------------------------------------------+
                            | site-to-site VPN (IPsec / TLS), outbound only
                            v
  Central data centre / cloud
  +--------------------------------------------------------------------+
  | Ingestion (MQTT/AMQP/HTTPS) -> Smart-FridgeGuard engines per region |
  | Time-series DB + event store (immutable / WORM backup)              |
  | SIEM (all security events, firewall, VPN, AD, OT sensor alerts)    |
  | SOC: dashboard, investigation workflow, ticketing, on-call          |
  +--------------------------------------------------------------------+
```

| Element | Recommendation |
|---------|----------------|
| Controllers | Industrial refrigeration controllers / PLCs already installed by the refrigeration contractor; Smart-FridgeGuard reads their data through the site gateway or BMS, never directly from the WAN. |
| Network | Per-store template following IEC 62443 zones and conduits (section 6); industrial firewall with OT protocol filtering; port security / 802.1X on switches. |
| OT visibility | Optional passive OT network monitoring via switch port mirroring to detect unexpected Modbus writes, new devices or scanning (complements DET-001/006). |
| Central SIEM | Smart-FridgeGuard alerts and incidents forwarded to the chain's SIEM (syslog/CEF, JSON over HTTPS) and correlated with VPN, identity, firewall and endpoint logs. |
| Identity | Central identity provider (SSO + MFA) for analysts, store managers, technicians and vendors; role mapping to the RBAC model in `config/users.yaml`. |
| Operations | Fleet-wide device inventory, certificate lifecycle, signed firmware rollout, configuration baselines per cabinet model (C-19), documented incident playbooks (C-18). |
| Resilience | Gateway buffering, redundant WAN (e.g. 4G/5G backup) for alerting, UPS per site, central HA database, backups tested by restore. |
| Governance | Change management for every threshold or rule change (DR-11), periodic access reviews, penetration tests of the store template, calibration programme across all stores. |

**What Level 3 adds:** consistent security across hundreds of sites, correlation with the
rest of the company's security data (e.g. the same stolen account used at several stores),
and auditable evidence for food-safety and pharmacy inspections.

### Comparison

| | Level 1 – Prototype | Level 2 – Small supermarket | Level 3 – Enterprise chain |
|---|---|---|---|
| Sensors | DS18B20 | Calibrated RTD / commercial sensors | Calibrated sensors + controller/PLC data |
| Collection | ESP32 over Wi-Fi | Industrial IoT gateway | Gateway per store + passive OT monitoring |
| Protocol | MQTT/TLS | Modbus RTU/TCP → MQTT/TLS | Modbus/BACnet/vendor → MQTT/AMQP over VPN |
| Storage | SQLite | PostgreSQL | Time-series DB + immutable event store + SIEM |
| Network | Lab Wi-Fi | VLANs + business firewall | IEC 62443 zones, industrial firewalls, VPN |
| Power | USB / optional UPS | UPS for gateway and network | UPS per site, redundant WAN |
| Users | Developer | Store manager, technician, analyst | SSO + MFA, SOC team, vendor access via jump host |
| Suitable as food-safety record | No | Only if the system is validated for that | Yes, if validated and approved |

---

## 4. Integration protocols: MQTT and Modbus

### MQTT (sensor/gateway → monitoring)

MQTT is a lightweight publish/subscribe protocol, the natural fit for telemetry.

| Setting | Recommendation |
|---------|----------------|
| Port | **8883 (MQTT over TLS)**; never expose plain 1883 outside a lab. |
| Topics | `fridgeguard/<site>/<device_id>/telemetry`, `.../heartbeat`, `.../event`. ThingsBoard uses `v1/devices/me/telemetry` with a per-device token. |
| Identity | One credential or client certificate per device (C-2); the broker ACL lets a device publish **only** to its own topics and subscribe to nothing it doesn't need. |
| QoS | QoS 1 for telemetry and events (at-least-once); the event store deduplicates by `event_id`. |
| Retained / LWT | Last Will message marks a device offline immediately; DET-005 still checks heartbeat gaps independently. |
| Payload | JSON with `device_id`, `sensor_id`, `seq` (monotonic counter), device timestamp; `seq` gaps and timestamp drift support C-12 replay detection. |

### Modbus (controllers/transmitters → gateway)

Most refrigeration controllers, PLCs and industrial transmitters speak Modbus RTU (RS-485)
or Modbus TCP (port 502).

| Topic | Guidance |
|-------|----------|
| Security | Modbus has **no authentication and no encryption**. Anyone on the segment can read and write registers. Keep it inside the OT zone, never route it to IT or the internet. |
| Direction | The gateway acts as Modbus master and uses **read function codes only** (03 Read Holding Registers, 04 Read Input Registers, 01/02 for coils/inputs). Write codes (05, 06, 15, 16) are blocked by gateway configuration and, at Level 3, by the industrial firewall's protocol filter. |
| Register map | Use the controller manufacturer's documented register map. Agree with the refrigeration contractor which registers may be polled (temperature, setpoint, alarm state, defrost state, door, compressor). |
| Polling rate | Moderate (e.g. every 30–60 s) so polling does not load older controllers; never poll faster than the vendor recommends. |
| Change detection | Setpoint and alarm-limit registers compared with the configuration baseline (C-19); a difference becomes a `config.change` event (actor unknown unless the controller/BMS also logs the user). |
| Secure variant | Where supported, Modbus/TCP Security (TLS, port 802) or the vendor's own secure gateway is preferred. |

Other protocols seen in stores — BACnet (building management), vendor cloud APIs,
LoRaWAN for wireless sensors — follow the same rule: read-only, inside the OT zone, converted
to TLS-protected MQTT/HTTPS at the gateway.

---

## 5. Secure communication

| Link | Protection |
|------|------------|
| Sensor → gateway (wired) | Physical protection of RS-485 cabling and enclosures; short runs inside the OT zone. |
| Sensor → gateway (wireless) | Protocol-level encryption (e.g. LoRaWAN AES-128 session keys, WPA2/WPA3-Enterprise for Wi-Fi); dedicated SSID for sensors, hidden from customers. |
| Gateway / ESP32 → broker | TLS 1.2+ with server certificate validation (pinned CA), per-device client certificate or token, no fallback to plaintext. |
| Site → central | Site-to-site VPN (IPsec or TLS), outbound-initiated from the site; no inbound ports open at the store. |
| Dashboard / API | HTTPS only, HSTS, login required (already enforced by the dashboard), bound to the monitoring network. |
| Notifications | SMTP over TLS (STARTTLS/SMTPS), Telegram bot API over HTTPS; secrets in `.env` or a vault, never in Git (C-20). |
| Time | NTP from a trusted internal source so `ts_device` vs `ts_ingest` comparisons (C-12) are meaningful. |
| Firmware | Signed firmware, secure boot where available (ESP32 supports secure boot and flash encryption), controlled update process (C-7). |

Certificate management: an internal CA issues device certificates during commissioning;
each certificate is listed in the device inventory and revoked when a device is replaced or
suspected compromised (C-18 playbook: "revoke token").

---

## 6. Network segmentation

Segmentation follows the IEC 62443 idea of **zones** (groups of assets with the same security
needs) and **conduits** (the only allowed paths between zones).

| Zone | Contains | Allowed to talk to |
|------|----------|--------------------|
| Z1 Refrigeration control (OT) | Controllers, PLCs, controller probes, HMI | Z2 gateway only (read-only Modbus/BACnet) |
| Z2 Monitoring edge | Independent sensors, IoT gateway, passive OT sensor | Z1 (poll), central monitoring via VPN (outbound MQTT/HTTPS) |
| Z3 Site DMZ | Jump host for vendor/technician remote access | Z1 maintenance interfaces, only during approved maintenance windows, with MFA |
| Z4 Store IT | Back-office PCs, POS, printers | No access to Z1/Z2 |
| Z5 Guest / customer Wi-Fi | Customers | Internet only |
| Z6 Central monitoring | Smart-FridgeGuard, database, SIEM, SOC | Receives from Z2; no route back into Z1 |

Rules of thumb:

- **Deny by default** between zones; document every allowed flow (source, destination,
  port, protocol, purpose, owner).
- Vendor remote access only through the jump host, time-limited and logged; this matches
  the maintenance window (06:00–09:00 in `config/users.yaml`) that DET-004 already monitors.
- Disable unused switch ports, enable port security / 802.1X so a laptop plugged into the
  plant room is noticed.
- The monitoring path (Z2) should keep working when Z1 fails and vice versa — separate power
  supplies and, at Level 3, a separate uplink for alerts.
- Firewall and VPN logs go to the SIEM; a new device on Z1, or a Modbus write, is itself a
  security event.

---

## 7. Authentication and authorization

| Principal | Authentication | Authorization |
|-----------|----------------|---------------|
| Sensor / ESP32 / gateway | Unique client certificate or token per device (C-2); credentials stored in secure storage, not in firmware images in Git | Broker ACL: publish to own topics only |
| Store manager | SSO + MFA (Level 3) or strong password (Level 2) | View dashboard for own store, acknowledge alerts; no setpoint changes |
| Refrigeration technician | Named account (no shared "service" login), MFA, access via jump host | Change parameters **only** through the controller/vendor tools, inside the maintenance window, with a work order; Smart-FridgeGuard logs and checks it (DET-001/004/006/007) |
| System administrator | Named admin account, MFA, privileged access management | Configure gateways, broker, Smart-FridgeGuard; changes to detection thresholds are themselves logged (DR-11) |
| Security analyst | SSO + MFA | Triage, investigate, report; read-only on telemetry and events (append-only store) |
| Vendors / contractors | Individual accounts, time-limited, approved per visit | Least privilege; disabled outside contract periods |

General rules: no default or shared passwords (change all factory credentials on controllers,
gateways and switches before connecting them), account lockout/rate limiting on every login
interface (C-4, DET-002), quarterly access reviews, immediate removal of leavers' accounts.
The role names and permissions in `config/users.yaml` were designed to map directly onto
these real roles.

---

## 8. Sensor calibration

Detection on temperature (DET-003, plausibility checks C-14) is only as good as the sensor.

| Activity | Guidance |
|----------|----------|
| Initial calibration | Use sensors with a calibration certificate traceable to national standards (ISO/IEC 17025 accredited laboratory) for Level 2–3. For DS18B20 prototypes, check every probe before use. |
| Field check | Compare each probe against a calibrated reference thermometer in a stable medium: ice-point (crushed ice + water, 0 °C) for chillers, and a stable reference at the freezer's operating range (e.g. a calibrated dry-block or reference probe in the freezer). |
| Acceptance limit | Agree the maximum error with the food-safety specialist (commonly ±0.5 °C for chilled food monitoring; stricter for pharmacy/vaccine fridges, e.g. per the pharmacy's cold-chain procedure). |
| Interval | At least annually, or per the quality system; after any probe replacement, drop or suspected tampering. |
| Offsets | A small fixed offset may be applied in the gateway, but it must be recorded (who, when, old/new value) — an undocumented offset is indistinguishable from sensor manipulation (T-6). Treat offset changes as `config.change` events. |
| Records | Keep calibration certificates and field-check results per `sensor_id`; link them to the `device_id` in the device inventory. |
| Drift detection | Compare independent sensor vs. controller probe continuously; a slowly growing difference indicates drift or tampering and should trigger a calibration check. |

---

## 9. Independent temperature verification

Independence is the core security value of the hardware design (C-17, T-4, T-6).

1. **Two sources per cabinet:** the controller's own probe (read via Modbus) and an
   independent probe (DS18B20 or transmitter) wired to the monitoring gateway, not to the
   controller.
2. **Separate path:** the independent probe uses its own gateway, power supply and network
   zone, so a compromised controller or controller network cannot alter it.
3. **Cross-check:** the backend compares the two readings. Typical rules:
   - difference greater than an agreed tolerance (e.g. 2 °C) for 15+ minutes → investigate
     (sensor fault, drift, or manipulation);
   - controller reports "normal" while the independent probe shows an excursion →
     treat as high severity (possible T-4, compromised controller);
   - independent probe flat-lines (identical values for hours) → possible replay or
     stuck sensor;
   - DS18B20 reads exactly 85.0 °C or −127 °C → sensor reset/disconnected, mark invalid,
     not an excursion.
4. **Out-of-band record:** for pharmacy/vaccine fridges and HACCP records, a separate
   validated data logger (with its own alarm and record) stays in place; Smart-FridgeGuard can
   import its downloads for comparison but does not replace it.
5. **Product verification:** after a confirmed incident, staff verify product temperatures
   with a calibrated probe thermometer before deciding on stock (C-18 playbook).

> Implementing the controller-vs-independent cross-check as a detection rule is a natural
> next step; it is not one of the current DET-001..007 rules.

---

## 10. Safe integration with existing refrigeration equipment

| Principle | What it means in practice |
|-----------|---------------------------|
| **Read-only by design** | Smart-FridgeGuard never writes setpoints, never acknowledges or silences alarms and never starts/stops compressors or defrost. Gateway configured with read function codes only; firewall blocks writes where possible. |
| **Certified alarms stay primary** | Existing local alarms, the refrigeration contractor's remote alarm service and HACCP records keep working unchanged. Smart-FridgeGuard alerts are an additional, security-focused layer. |
| **Approved by the right people** | Refrigeration engineer approves any wiring, probe entry, controller communication and polling rate; food-safety / pharmacy specialist approves limits, delays and how alerts feed corrective actions; IT/OT security approves network design. |
| **Manufacturer guidance** | Use only documented interfaces (communication ports, vendor gateways, register maps). Opening a controller or tapping internal wiring may void warranty and certification. |
| **Electrical safety** | Low-voltage sensor wiring only; anything in mains or refrigeration electrical panels is done by qualified electricians. Keep sensor wiring separate from power cables. |
| **No new failure modes** | Polling must not overload controllers; a monitoring failure must never stop refrigeration. Test integration first on one non-critical cabinet outside opening hours. |
| **Hygiene and food contact** | Food-safe, cleanable probe materials (stainless steel), placement that doesn't obstruct airflow or product loading, cables sealed so they don't break door gaskets. |
| **Change control** | Every integration change has a work order, rollback plan and post-change verification; it appears in Smart-FridgeGuard as planned maintenance (DET-007) rather than as an unexplained change. |

---

## 11. Mapping hardware data to the Smart-FridgeGuard event schema

Real data must be converted by the gateway or bridge into the common envelope described in
[architecture.md §5](architecture.md#5-common-event-schema). Each device in
`config/devices.yaml` gets its real location, safe range and allowed source IPs.

| Hardware source | Event type | Payload fields filled from |
|-----------------|------------|---------------------------|
| Independent probe / transmitter reading | `telemetry.temperature` | `temperature_c` (probe), `setpoint_c` (controller register or configured value), `expected_min_c` / `expected_max_c` (`safe_min_c` / `safe_max_c`), `status`, `door_open` and `compressor_on` (controller registers or door contact, if available) |
| ESP32 / gateway keep-alive | `device.heartbeat` | `firmware`, `uptime_s` |
| Controller setpoint/alarm register changed vs. baseline | `config.change` | `parameter`, `old_value`, `new_value`, `change_source` (`controller` / `vendor_portal` / `bms`), `result: applied`; `actor` and authorization from the controller/BMS audit log if it exists, otherwise missing → investigate (DR-4) |
| Controller / vendor portal / HMI login log | `auth.login_success`, `auth.login_failure` | `method`, `role`, `reason`; `source_ip` from the log |
| UPS on battery / restored | *(new type suggested)* `device.power` | `on_battery`, `battery_pct` — would let correlation explain excursions caused by power cuts |

Example of a real reading converted by the bridge:

```json
{
  "event_id": "4b1d2c8e-0f7a-4c55-9e41-2a6f3b9d7c10",
  "event_type": "telemetry.temperature",
  "device_id": "FRIDGE-001",
  "ts_device": "2026-11-18T09:15:00.000Z",
  "actor": null,
  "source_ip": "10.10.2.15",
  "payload": {
    "temperature_c": 4.3,
    "setpoint_c": 4.0,
    "expected_min_c": 2.0,
    "expected_max_c": 8.0,
    "status": "normal",
    "door_open": false,
    "compressor_on": true
  },
  "scenario": "baseline"
}
```

`scenario` is a simulation ground-truth label; for real data the bridge always sets
`baseline` (meaning "no label"). `ts_ingest` and `hash` are added by the event store.

---

## 12. Commissioning checklist

- [ ] Written approval from the refrigeration contractor and the food-safety / pharmacy lead.
- [ ] Device inventory: `device_id`, location, cabinet model, controller, sensor IDs, gateway, IPs.
- [ ] All factory/default credentials changed on controllers, gateway, switch, firewall, UPS.
- [ ] Per-device certificates/tokens issued and recorded; broker ACLs tested (a device cannot publish as another device).
- [ ] Sensors calibrated / field-checked; certificates stored; probe placement photographed.
- [ ] VLANs and firewall rules match the zone table; Modbus write function codes blocked and tested.
- [ ] NTP configured on every component; time drift checked.
- [ ] UPS runtime tested by a controlled power cut; on-battery event visible in monitoring.
- [ ] Heartbeat test: disconnect a sensor/gateway → DET-005 alert within the configured time.
- [ ] Excursion test: warm the independent probe (e.g. in hand or warm water) → DET-003 alert, notification delivered.
- [ ] Planned maintenance test: technician change inside the window → DET-007 info only.
- [ ] Gateway buffering test: cut WAN for 30 min → no data lost after reconnect.
- [ ] Alert escalation path (who is called, when) documented and tested with the store manager.
- [ ] Run the existing software test suite (`pytest`, `python -m fridgeguard evaluate`) against the production configuration before go-live.

---

## 13. Limitations and approvals

- This guide is an **engineering concept** produced alongside a software simulation. The
  hardware levels have not been built or tested in this project; costs and specifications
  are indicative.
- A real deployment requires approval from **refrigeration engineers** and **food-safety
  specialists** (and, for medicines/vaccines, the responsible pharmacist and the applicable
  cold-chain regulations).
- The independent monitoring system **must not replace** certified refrigeration alarms,
  safety controls, validated temperature recorders or HACCP procedures. It adds security
  visibility — detecting unauthorized changes, compromised controllers, credential attacks
  and monitoring gaps — on top of them.
- Using Smart-FridgeGuard data as an official food-safety record would require the whole
  chain (sensors, recorders, storage, time synchronisation, access control) to be validated
  against the relevant standards and regulations (for example the EN 12830 / EN 13485 /
  EN 13486 series referenced for temperature recorders and thermometers of chilled and
  frozen food in the EU).
- Data protection: login/audit events contain employee identities; retention and access must
  follow GDPR and the company's policies.

---

## 14. Traceability to the threat model

| Threat ([threat-model.md](threat-model.md)) | Hardware / design measure in this guide |
|-----------------------------------------------|-----------------------------------------|
| T-1 Unauthorized remote access | No inbound ports, VPN + jump host with MFA (§5, §6, §7) — C-1, C-6, C-8 |
| T-2 Stolen employee credentials | Named accounts, SSO + MFA, access reviews (§7) — C-3, C-5 |
| T-3 Brute force | Lockout/rate limiting on all login interfaces, logs to DET-002 (§7) — C-4 |
| T-4 Compromised controller | Independent sensor on a separate path, cross-check, read-only integration, Modbus write blocking (§6, §9, §10) — C-8, C-17, C-19 |
| T-5 Network interruption | Gateway buffering, UPS, redundant WAN, heartbeat/LWT (§3, §4) — C-13, C-16 |
| T-6 Sensor manipulation | Tamper-evident housings, calibration records, documented offsets, drift and flat-line checks (§8, §9) — C-9, C-14 |
| T-7 Log/evidence tampering | Append-only event store, immutable backups, SIEM copy, NTP (§3 Level 3, §5) — C-12, C-15 |

---

## 15. References

- ZedIoT — *Refrigeration Monitoring Solution for Chain Supermarkets* (commercial example of
  an AI + IoT refrigeration monitoring architecture): <https://zediot.com>
- Analog Devices (Maxim Integrated) — DS18B20 Programmable Resolution 1-Wire Digital Thermometer, datasheet.
- Espressif — ESP32 technical reference and security features (secure boot, flash encryption).
- OASIS — MQTT Version 5.0 specification.
- Modbus Organization — Modbus Application Protocol Specification; MODBUS/TCP Security.
- ISA/IEC 62443 series — Security for industrial automation and control systems (zones and conduits).
- NIST SP 800-82 Rev. 3 — Guide to Operational Technology (OT) Security.
- MITRE ATT&CK for ICS — used in [threat-model.md](threat-model.md).
- Regulation (EC) No 37/2005 — monitoring of temperatures of quick-frozen foodstuffs; EN 12830, EN 13485, EN 13486.
- Codex Alimentarius / Regulation (EC) No 852/2004 — food hygiene and HACCP principles.
- Project documents: [requirements.md](requirements.md), [threat-model.md](threat-model.md),
  [architecture.md](architecture.md), [test-results.md](test-results.md).
