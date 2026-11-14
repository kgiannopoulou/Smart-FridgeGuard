# Smart-FridgeGuard — Threat Model

**Phase:** 1 – Planning, architecture and simulation
**Step:** 2 – Research the threat and build a threat model
**Status:** Draft v1.0 (2026-11-14)
**Methodology:** STRIDE per element, attacker behaviour mapped to MITRE ATT&CK for ICS
**Related:** [requirements.md](requirements.md) (FR/NFR and detection rules DR-1…DR-11)

---

## 1. Purpose and approach

This document identifies what could go wrong in the Smart-FridgeGuard system, how an
attacker could cause it, what the consequences would be and which controls prevent or detect it.

Steps followed:

1. Describe the system and draw trust boundaries (section 2).
2. List the assets worth protecting (section 3).
3. List the entry points an attacker can use (section 4).
4. Describe the threat actors (section 5).
5. Analyse each component with **STRIDE** (section 6).
6. Describe the main threat scenarios and map them to **MITRE ATT&CK for ICS** (sections 7–8).
7. Rate the risks (section 9) and define defensive controls (section 10).
8. Link each threat to the detection rules that will catch it (section 11).

Commercial refrigeration (supermarkets, pharmacies, food warehouses, vaccine storage) is
treated as a small **operational technology (OT)** environment: a controller keeps a physical
process (cooling) within safe limits, and failure has physical and financial consequences.
This is why ATT&CK for ICS is used rather than the enterprise matrix alone.

## 2. System overview and trust boundaries

```
 TB-1 Device zone             TB-2 Edge / site network         TB-3 Monitoring / cloud
+---------------------+      +--------------------------+      +--------------------------+
| Temperature sensor  |      |                          |      |                          |
|        |            | MQTT |   ThingsBoard Edge       | sync |  ThingsBoard server      |
|        v            |----->|   - device registry      |----->|  - dashboard             |
| Fridge controller   |<-----|   - rule engine          |      |  - alarms                |
| (setpoint, alarms,  | RPC  |   - local buffer/queue   |      |                          |
|  firmware)          |      |                          |      |  Event database          |
+---------------------+      +--------------------------+      |  Detection engine        |
        ^                              ^                       |  Report generator        |
        |  local/companion login       |  admin web UI         +--------------------------+
        |                              |                                ^
   Household user /              Technician / admin                Security analyst
   store employee                (remote access)                    (dashboard, reports)
```

| Trust boundary | Between | Why it matters |
|----------------|---------|----------------|
| TB-1 | Physical device ↔ edge network | Devices sit in public or semi-public places and can be tampered with physically. |
| TB-2 | Site network ↔ edge gateway | The edge receives untrusted device data and exposes an admin UI and remote access. |
| TB-3 | Edge ↔ central monitoring | Data leaves the site; the link can be interrupted or intercepted. |
| TB-4 | Users ↔ any login interface | Every login interface (device, edge, dashboard) is a credential attack surface. |

In the Phase 1 lab all components are simulated and run in Docker on one host, but the model
keeps the boundaries so the design stays valid for a real deployment.

## 3. Assets

| ID | Asset | Security property needed | Why it is valuable |
|----|-------|--------------------------|--------------------|
| A-1 | Refrigerated goods (food, medicine, vaccines) | Safety / availability | Physical loss, health risk if spoiled goods are sold. |
| A-2 | Fridge controller | Integrity, availability | Controls cooling; compromise means control of the process. |
| A-3 | Temperature sensors and readings | Integrity | Every decision and alarm depends on true readings. |
| A-4 | Device configuration (setpoints, alarm thresholds, firmware, network) | Integrity | Changing it changes physical behaviour or silences alarms. |
| A-5 | Alarms and alert pipeline | Integrity, availability | The safety net; disabling it hides an attack or failure. |
| A-6 | User and employee credentials, device access tokens | Confidentiality | Give direct access to devices and admin functions. |
| A-7 | ThingsBoard Edge gateway | Integrity, availability | Central point for a whole site; one compromise affects all devices. |
| A-8 | Event database and logs | Integrity, availability, confidentiality | Evidence for investigations; attackers want to erase it. |
| A-9 | Monitoring dashboard | Integrity, availability | Analysts act on what it shows. |
| A-10 | Detection thresholds / rule configuration | Integrity | Raising a threshold quietly blinds detection. |
| A-11 | Network connectivity (site ↔ monitoring) | Availability | Without it, monitoring has no visibility. |

## 4. Entry points

| ID | Entry point | Boundary | Used by | Assets reachable |
|----|-------------|----------|---------|------------------|
| EP-1 | Device local interface (front panel, service port, companion app login) | TB-1, TB-4 | User, employee, technician | A-2, A-4 |
| EP-2 | MQTT telemetry channel (device → edge) | TB-1/TB-2 | Devices | A-3, A-5 |
| EP-3 | RPC / command channel (edge → device) | TB-2 | Edge, admin | A-2, A-4 |
| EP-4 | ThingsBoard Edge web UI and REST API | TB-2, TB-4 | Admin, technician | A-4, A-6, A-7, A-10 |
| EP-5 | Remote access path for vendor / technician (VPN, remote desktop, cloud portal) | TB-2, TB-4 | Vendor, technician | A-2, A-4, A-7 |
| EP-6 | Edge ↔ server synchronisation link | TB-3 | System | A-8, A-9, A-11 |
| EP-7 | Dashboard and report interface | TB-3, TB-4 | Analyst | A-8, A-9 |
| EP-8 | Firmware / software update mechanism | TB-1, TB-2 | Vendor | A-2, A-7 |
| EP-9 | Physical access to the fridge and sensor wiring | TB-1 | Anyone on site | A-1, A-2, A-3 |

## 5. Threat actors

| Actor | Motivation | Capability | Typical entry points |
|-------|------------|------------|----------------------|
| Opportunistic external attacker | Botnet recruitment, curiosity, ransom | Internet scanning, default and leaked passwords, public exploits | EP-4, EP-5 |
| Credential attacker | Account takeover, resale of access | Brute force, password spraying, phishing, credential stuffing | EP-1, EP-4, EP-5, EP-7 |
| Malicious or careless insider (employee, technician) | Revenge, theft, covering a mistake, convenience | Valid credentials and physical access | EP-1, EP-4, EP-9 |
| Compromised third-party vendor | Supply-chain or remote-maintenance abuse | Trusted remote access and update channel | EP-5, EP-8 |
| Competitor / fraudster | Spoil stock, hide spoilage to pass inspections, insurance fraud | Insider help or physical access | EP-1, EP-9, EP-2 |
| Targeted OT attacker | Disruption of food or medicine supply chain | Custom tooling, persistence, process knowledge | All |

## 6. STRIDE analysis

STRIDE categories: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure,
**D**enial of service, **E**levation of privilege.

### 6.1 Temperature sensor and telemetry (EP-2)

| STRIDE | Threat | Impact |
|--------|--------|--------|
| S | Attacker publishes readings using a stolen device token, posing as a real fridge. | False readings, hidden failure. |
| T | Sensor physically tampered with or values altered in transit. | False temperature readings. |
| R | No device-side and server-side timestamps → cannot prove when a reading was produced. | Weak evidence. |
| I | Unencrypted MQTT reveals device IDs, tokens and site layout. | Reconnaissance, token theft. |
| D | Telemetry flooding or blocking the sensor's messages. | Loss of monitoring visibility. |
| E | — (sensor has no privileges to escalate) | — |

### 6.2 Fridge controller (EP-1, EP-3, EP-8)

| STRIDE | Threat | Impact |
|--------|--------|--------|
| S | Login with stolen or default credentials. | Account compromise. |
| T | Setpoint raised, alarm thresholds widened, alarms disabled, malicious firmware installed. | Manipulated settings, spoiled goods. |
| R | Config changed without an audit record of who and from where. | Insider cannot be identified. |
| I | Configuration and credentials readable from the service port. | Credential theft. |
| D | Controller forced to restart, crash or stop cooling. | Loss of control, spoilage. |
| E | Normal user account used to reach technician/admin functions. | Unauthorised configuration changes. |

### 6.3 ThingsBoard Edge gateway (EP-4, EP-5, EP-6)

| STRIDE | Threat | Impact |
|--------|--------|--------|
| S | Stolen admin or technician credentials used on the web UI or remote access. | Full site control. |
| T | Rule chains edited to drop alarms; device tokens regenerated or cloned. | Disabled alarms, blind monitoring. |
| R | Admin actions not logged or logs stored only on the edge itself. | Attacker erases traces. |
| I | Device tokens, user list and telemetry exported. | Further attacks. |
| D | Edge overloaded or its uplink cut. | Loss of monitoring visibility for the whole site. |
| E | Exploitation of an unpatched vulnerability or weak role separation. | Compromised controller-level access. |

### 6.4 Edge ↔ server link (EP-6)

| STRIDE | Threat | Impact |
|--------|--------|--------|
| S | Rogue edge or server inserted (adversary-in-the-middle). | False data shown centrally. |
| T | Messages modified in transit. | Manipulated readings and alerts. |
| R | — | — |
| I | Traffic sniffed if TLS is missing. | Data and token disclosure. |
| D | Network interruption, jamming, blocked ports. | Loss of monitoring visibility. |
| E | — | — |

### 6.5 Event database, detection engine and dashboard (EP-7)

| STRIDE | Threat | Impact |
|--------|--------|--------|
| S | Analyst account taken over. | Attacker sees what defenders see. |
| T | Events deleted or edited; detection thresholds raised. | Evidence destroyed, detection blinded. |
| R | Analyst actions (acknowledge, mark false positive) not logged. | Alerts silently closed. |
| I | Logs contain plaintext passwords or tokens; database exposed. | Credential leak. |
| D | Database full or unavailable; dashboard down. | No visibility, lost events. |
| E | Analyst role able to change detection rules or delete events. | Abuse of the monitoring system itself. |

## 7. Threat scenarios

These are the main threats for this project. Each has an ID used in sections 8–11.

| ID | Threat | Potential impact | STRIDE | Assets | Entry points | Actors |
|----|--------|------------------|--------|--------|--------------|--------|
| T-1 | Unauthorized remote access | Control manipulation | S, E | A-2, A-4, A-7 | EP-4, EP-5 | External attacker, compromised vendor |
| T-2 | Stolen employee credentials | Unauthorized configuration changes | S, T, R | A-4, A-6, A-10 | EP-1, EP-4, EP-7 | Credential attacker, insider |
| T-3 | Brute-force attempts | Account compromise | S | A-6 | EP-1, EP-4, EP-5, EP-7 | Credential attacker |
| T-4 | Compromised controller | Manipulated settings or disabled alarms | T, D, E | A-2, A-4, A-5 | EP-3, EP-5, EP-8 | Targeted OT attacker, compromised vendor |
| T-5 | Network interruption | Loss of monitoring visibility | D | A-9, A-11 | EP-6, EP-2 | Any (also accidental) |
| T-6 | Sensor manipulation | False temperature readings | S, T | A-3, A-5 | EP-2, EP-9 | Insider, fraudster |
| T-7 | Log and evidence tampering | Investigation impossible, attack hidden | T, R | A-8, A-10 | EP-4, EP-7 | Any attacker after compromise |

### T-1 Unauthorized remote access → control manipulation
An attacker finds an internet-exposed edge UI or vendor remote access portal, logs in with
default or leaked credentials, and sends commands to fridges (change setpoint, switch off
cooling, start defrost at the wrong time).
**Consequence:** stock spoils within hours; the business may sell unsafe goods without knowing.

### T-2 Stolen employee credentials → unauthorized configuration changes
A phished or reused employee password is used to log in and change the setpoint or alarm
thresholds. The change looks legitimate because the account is real.
**Consequence:** slow, hard-to-notice warming of goods; blame falls on the employee.

### T-3 Brute-force attempts → account compromise
Repeated login attempts against the device or edge login using common passwords or credential
lists until one succeeds.
**Consequence:** the attacker gains a valid account, which leads to T-2 or T-1.

### T-4 Compromised controller → manipulated settings or disabled alarms
Malicious firmware or direct controller access changes control logic, hides the real setpoint
or disables local alarms while reporting "normal" status.
**Consequence:** the process runs outside safe limits while every screen shows it as fine.

### T-5 Network interruption → loss of monitoring visibility
The uplink between site and monitoring is cut (accident, jamming, DoS or deliberately as
cover for another attack).
**Consequence:** no telemetry or alerts reach analysts; an incident can go unseen.

### T-6 Sensor manipulation → false temperature readings
A sensor is moved, insulated, replaced or spoofed so it reports a safe temperature while the
cabinet is warm (hide spoilage), or reports a dangerous temperature (trigger needless
disposal of stock).
**Consequence:** wrong decisions based on false data; fraud or financial loss.

### T-7 Log and evidence tampering
After any of the above, the attacker deletes or edits events, raises detection thresholds or
closes alerts as "false positive".
**Consequence:** the incident cannot be reconstructed; root cause and accountability are lost.

## 8. MITRE ATT&CK for ICS mapping

Technique IDs refer to the MITRE ATT&CK for ICS matrix. Where ICS has no matching technique,
the Enterprise technique is listed and marked *(Enterprise)*.

| Threat | Tactic | Technique | How it applies here |
|--------|--------|-----------|---------------------|
| T-1 | Initial Access | T0883 Internet Accessible Device | Edge UI or device exposed directly to the internet. |
| T-1 | Initial Access | T0822 External Remote Services | Vendor VPN / remote portal used to reach the site. |
| T-1 | Initial Access | T0819 Exploit Public-Facing Application | Unpatched edge web UI or API exploited. |
| T-1 | Lateral Movement | T0886 Remote Services | From the edge to individual fridge controllers. |
| T-1 | Impair Process Control | T0855 Unauthorized Command Message | RPC commands sent to change cooling behaviour. |
| T-2 | Initial Access / Lateral Movement / Persistence | T0859 Valid Accounts | Real employee account used for changes. |
| T-2 | Initial Access | T0865 Spearphishing Attachment | Phishing used to obtain employee credentials. |
| T-2 | Impair Process Control | T0836 Modify Parameter | Setpoint or alarm threshold changed. |
| T-3 | Credential Access | T1110 Brute Force *(Enterprise)* | Password guessing / spraying against logins. |
| T-3 | Lateral Movement | T0812 Default Credentials | Factory default passwords tried first. |
| T-3 | Lateral Movement | T0891 Hardcoded Credentials | Built-in service accounts in device firmware. |
| T-4 | Persistence / Impair Process Control | T0839 Module Firmware, T0857 System Firmware | Malicious firmware installed on the controller. |
| T-4 | Execution | T0858 Change Operating Mode | Controller switched to service/program mode. |
| T-4 | Inhibit Response Function | T0878 Alarm Suppression | Alarms prevented from being raised. |
| T-4 | Inhibit Response Function | T0838 Modify Alarm Settings | Alarm thresholds widened or disabled. |
| T-4 | Inhibit Response Function | T0816 Device Restart/Shutdown | Controller restarted to interrupt cooling. |
| T-4 | Impact | T0831 Manipulation of Control | Cooling logic altered. |
| T-5 | Inhibit Response Function | T0804 Block Reporting Message | Telemetry blocked from reaching monitoring. |
| T-5 | Inhibit Response Function | T0814 Denial of Service | Edge or link flooded. |
| T-5 | Impact | T0829 Loss of View, T0815 Denial of View | Analysts lose sight of the process. |
| T-6 | Impair Process Control | T0856 Spoof Reporting Message | Fake telemetry published with a stolen token. |
| T-6 | Evasion / Impact | T0832 Manipulation of View | Dashboard shows safe values while the cabinet is warm. |
| T-6 | Collection | T0801 Monitor Process State | Attacker learns normal readings to make fakes believable. |
| T-1…T-6 | Discovery | T0846 Remote System Discovery, T0842 Network Sniffing | Finding fridges and tokens on the site network. |
| T-1, T-6 | Collection | T0830 Adversary-in-the-Middle | Telemetry or commands intercepted and altered. |
| T-7 | Evasion | T0872 Indicator Removal on Host | Logs and events deleted. |
| T-7 | Impact | T0809 Data Destruction | Event database wiped. |
| All | Impact | T0879 Damage to Property, T0828 Loss of Productivity and Revenue, T0880 Loss of Safety | Spoiled stock, closed store, unsafe goods sold. |

### Example kill chain (combines T-3 → T-2 → T-4 → T-7)

1. **Discovery:** attacker finds the edge login page exposed on the internet (T0883).
2. **Credential access:** brute-forces an employee account (T1110) → success (T0859).
3. **Impair process control:** raises the fridge setpoint from 4 °C to 10 °C (T0836).
4. **Inhibit response:** widens the alarm threshold so no alarm fires (T0838 / T0878).
5. **Evasion:** deletes the login history on the edge (T0872).
6. **Impact:** stock spoils overnight (T0879, T0828).

This chain is used in Phase 1 Step 3 as the main simulated attack scenario.

## 9. Risk rating

Likelihood (L) and Impact (I) are rated 1 (low) to 5 (high); **Risk = L × I**.
Ratings are for an unprotected baseline system.

| Threat | L | I | Risk | Level | Reasoning |
|--------|---|---|------|-------|-----------|
| T-1 Unauthorized remote access | 4 | 5 | 20 | Critical | Exposed IoT/OT admin interfaces are routinely scanned; impact is full control. |
| T-2 Stolen employee credentials | 4 | 4 | 16 | High | Password reuse and phishing are common; changes look legitimate. |
| T-3 Brute-force attempts | 5 | 3 | 15 | High | Very frequent and automated; impact depends on what follows. |
| T-4 Compromised controller | 2 | 5 | 10 | Medium | Needs more skill, but hides itself and disables safety. |
| T-5 Network interruption | 3 | 3 | 9 | Medium | Often accidental; dangerous when combined with another attack. |
| T-6 Sensor manipulation | 3 | 4 | 12 | High | Requires physical or token access; directly falsifies the data. |
| T-7 Log and evidence tampering | 3 | 4 | 12 | High | Follows most successful attacks; destroys investigation. |

Levels: 1–5 Low, 6–11 Medium, 12–19 High, 20–25 Critical.

## 10. Defensive controls

Controls are grouped as **Prevent**, **Detect** and **Respond/Recover**.
"Phase" shows where each control is implemented in this project (Lab = implemented in the
simulation; Design = documented recommendation for a real deployment).

| ID | Control | Type | Threats | Phase |
|----|---------|------|---------|-------|
| C-1 | No direct internet exposure; remote access only via VPN with MFA | Prevent | T-1 | Design |
| C-2 | Unique per-device access tokens, rotation, revocation on suspicion | Prevent | T-1, T-6 | Lab |
| C-3 | Strong password policy, no default/hardcoded credentials, MFA for admin and analyst roles | Prevent | T-2, T-3 | Design |
| C-4 | Account lockout / rate limiting after repeated failed logins | Prevent | T-3 | Lab |
| C-5 | Role-based access control: user, technician, admin, analyst; least privilege | Prevent | T-2, T-4, T-7 | Lab |
| C-6 | TLS on MQTT, RPC, web UI and edge↔server sync | Prevent | T-1, T-5, T-6 | Design |
| C-7 | Signed firmware and controlled update process | Prevent | T-4 | Design |
| C-8 | Network segmentation: devices, edge and monitoring in separate zones | Prevent | T-1, T-4, T-5 | Design |
| C-9 | Physical protection: tamper-evident sensor housing, locked service ports | Prevent | T-6, T-4 | Design |
| C-10 | Detection rules DR-1…DR-11 with configurable thresholds | Detect | All | Lab |
| C-11 | Audit log of every login and configuration change (who, what, old/new, from where) | Detect | T-2, T-4, T-7 | Lab |
| C-12 | Device-time vs. server-time comparison to spot replay or clock tampering | Detect | T-6, T-7 | Lab |
| C-13 | Heartbeat / silence detection per device and per site | Detect | T-5 | Lab |
| C-14 | Plausibility checks on readings (rate of change, physical limits, cross-check with door/compressor state) | Detect | T-6, T-4 | Lab |
| C-15 | Append-only event store; evidence hashed (SHA-256) on export; changes to thresholds logged | Detect | T-7 | Lab |
| C-16 | Edge local buffering with forward-on-reconnect | Recover | T-5 | Lab |
| C-17 | Independent backup temperature logger (out-of-band check) | Detect | T-4, T-6 | Design |
| C-18 | Incident response playbook: lock account, revoke token, restore known-good config, verify stock | Respond | All | Lab (report recommendations) |
| C-19 | Known-good configuration baseline and automatic diff on change | Detect/Recover | T-2, T-4 | Lab |
| C-20 | Secrets kept out of code and masked in logs | Prevent | T-2, T-7 | Lab |

## 11. Traceability: threats → detection rules → requirements

| Threat | Detection rules (requirements.md) | Main controls | Requirements |
|--------|-----------------------------------|---------------|--------------|
| T-1 Unauthorized remote access | DR-2 unusual hours, DR-3 unknown IP, DR-9 correlated attack | C-1, C-2, C-6, C-8, C-10 | FR-3, FR-5, FR-6 |
| T-2 Stolen employee credentials | DR-2, DR-3, DR-4 unauthorised change, DR-5 dangerous setpoint, DR-9 | C-3, C-5, C-11, C-19 | FR-3, FR-4, FR-5 |
| T-3 Brute-force attempts | DR-1 brute force | C-3, C-4 | FR-3, FR-5, NFR-4 |
| T-4 Compromised controller | DR-4, DR-5, DR-6 out of range, DR-7 tampering, DR-10 alarm widened | C-5, C-7, C-14, C-17, C-19 | FR-4, FR-5 |
| T-5 Network interruption | DR-8 device silence | C-13, C-16 | FR-7, NFR-2 |
| T-6 Sensor manipulation | DR-6, DR-7 | C-2, C-9, C-12, C-14 | FR-2, FR-5, NFR-1 |
| T-7 Log and evidence tampering | DR-11 detection config changed, append-only store | C-11, C-15 | NFR-2, NFR-5, NFR-6 |

### Gaps found during threat modelling

Two threats needed detections that requirements.md did not list at first. Both were
checked for overlap with DR-1…DR-9 and **added to requirements.md (FR-5)** on 2026-11-14:

| Added rule | Detects | Threat |
|------------|---------|--------|
| DR-10 Alarm disabled or threshold widened | Any change that disables an alarm or widens its range beyond policy | T-4 (T0838, T0878) |
| DR-11 Detection/rule configuration changed | Changes to detection thresholds, rule chains or event retention | T-7 |

## 12. Assumptions and residual risk

- The lab simulates attacks; it does not test real firmware vulnerabilities.
- A fully compromised controller that reports perfectly plausible fake data can only be caught
  by an independent measurement (C-17). This residual risk is accepted for the lab.
- An insider with legitimate admin rights can make changes that look normal; detection relies
  on audit trails (C-11), baselines (C-19) and the correlation rule DR-9.

## 13. References

- MITRE ATT&CK for ICS — https://attack.mitre.org/matrices/ics/
- Microsoft STRIDE threat model — https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- ThingsBoard Edge documentation — https://thingsboard.io/docs/edge/
- OWASP IoT Top 10 — https://owasp.org/www-project-internet-of-things/
- NIST SP 800-82 Rev. 3, Guide to Operational Technology (OT) Security
