# Smart-FridgeGuard — Portfolio and Interview Presentation

**Phase:** 4 – Testing, documentation and presentation · **Step:** 16
**Use:** a ready-made structure for presenting the project in an interview or a portfolio
review: a short pitch, a 10-minute talk, a live demo script, and answers to the questions
interviewers usually ask.

---

## 1. One-line summary

> Smart-FridgeGuard is a security monitoring system for supermarket refrigerators: it
> simulates a fleet of connected fridges and their users, detects attacks such as brute
> force, unauthorized setpoint changes and tampering, correlates them into incidents, and
> gives a SOC analyst a dashboard, an investigation workflow and evidence-backed reports.

## 2. 30-second pitch

Connected refrigeration is operational technology in a retail setting: if someone changes a
vaccine fridge's setpoint, the cost is spoiled medicine or a food-safety incident, not just a
data breach. I built a small but complete security monitoring pipeline for that case.
A Python simulator produces realistic telemetry and user activity, including attacks. A
configurable detection engine with seven rules and four correlation patterns turns events
into prioritized alerts and incidents. Everything is stored in a tamper-evident,
append-only database, and analysts work through a Streamlit SOC dashboard with an 8-step
investigation workflow that produces PDF incident reports. I tested it with 10 controlled
scenarios × 20 seeds: 200 out of 200 runs passed with no false positives. I also wrote a
hardware guide for moving it to real sensors.

## 3. Ten-minute talk outline

| Min | Slide / topic | Key points | Show |
|-----|---------------|------------|------|
| 0–1 | Problem | Smart fridges are OT in a store; attacks have physical consequences (spoiled stock, medicine); certified alarms detect temperature, not *who* changed what | — |
| 1–2 | Requirements and threat model | FR/NFR, detection requirements DR-1…11; STRIDE per component, 7 threat scenarios, MITRE ATT&CK for ICS, 20 controls | [requirements.md](requirements.md), [threat-model.md](threat-model.md) |
| 2–3 | Architecture | Simulator → detection (rules → prioritizer → correlator) → SQLite → dashboard / notifications; clean seam for MQTT/ThingsBoard | [architecture.svg](architecture.svg) |
| 3–4 | Simulation | Thermal model per fridge (thermostat, door openings, noise), users with PBKDF2 passwords and RBAC, maintenance window, labelled anomalies | `python simulator.py --duration 1d --show activity` |
| 4–6 | Detection and correlation | DET-001…007 in YAML; context-based severity; COR-001 kill chain (brute force → takeover → tampering → excursion) with a confidence score | [detection-rules.md](detection-rules.md) |
| 6–8 | SOC workflow (demo) | Alert queue → investigation (8 steps, suggested decisions) → PDF report with verified evidence hashes; deduplicated notifications | Dashboard, [INV-000001.pdf](examples/INV-000001.pdf) |
| 8–9 | Testing | 10 test cases × 20 seeds through the real pipeline; detection rate, false positives, time to detect; two defects found and fixed | [test-results.md](test-results.md) |
| 9–10 | Real-world path and lessons | ESP32 prototype → store gateway → chain-wide SIEM; read-only integration; what I would do next | [hardware-guide.md](hardware-guide.md) |

## 4. Live demo script (about 5 minutes)

Prepare once before the interview (takes about a minute):

```powershell
.venv\Scripts\Activate.ps1
python simulator.py --duration 7d --start 2026-11-09 --faults-per-day 0.5 --show none
python correlation.py
streamlit run app.py
```

Then walk through:

1. **Overview page:** 3 fridges, online/offline, active alerts by severity, critical incidents.
   *"This is what the store SOC sees at the start of a shift."*
2. **Temperature monitoring:** pick FRIDGE-003 (pharmacy). Point out the expected range band
   and an excursion. *"Excursions alone are a maintenance problem; the interesting ones
   follow a configuration change."*
3. **Security monitoring:** failed logins by source IP, changes outside the maintenance
   window. *"203.0.113.50 is an external address trying generic usernames and one real one."*
4. **Alert management:** open the queue, sorted by severity; open one alert and show the
   evidence and the reason for its severity.
5. **Alert investigation:** start an investigation on a DET-002 alert, show the suggested
   decisions (authorized / impact / escalation) with their reasons, record them, download
   the PDF.
6. **Terminal:** show the integrity check and the test harness:

   ```powershell
   python database.py verify
   python -m fridgeguard evaluate --case TC-08 --seeds 3 --out -
   ```

   *"The kill chain runs through the real simulator and detection pipeline and is detected
   the same way for every seed."*

Fallback if something fails live: the screenshots in [`screenshots/`](../screenshots/) and the
example report [INV-000001](examples/INV-000001.md).

## 5. Key numbers to remember

| Fact | Value |
|------|-------|
| Detection rules / correlation patterns | 7 (DET-001…007) / 4 (+ related-alerts fallback) |
| Severity levels | INFO, LOW, MEDIUM, HIGH, CRITICAL, set by context |
| System test | 10 scenarios × 20 seeds = 200 runs, 200 passed, 0 false positives, 0 missed |
| Time to detect | immediate (unauthorized change), ~80 s (brute force), ~2 min (offline), 20–43 min (temperature: the cabinet must warm up, then stay out of range 15 min) |
| Notification noise reduction | 300-attempt brute force → 296 rule hits → 3 notifications |
| Automated tests | ~280 pytest tests, CI on Python 3.12 and 3.13 |
| Code size | ~11 500 lines of Python in the package and dashboard, ~3 400 lines of tests |

## 6. Design decisions worth explaining

| Decision | Why | Trade-off |
|----------|-----|-----------|
| Simulate everything first, ThingsBoard Edge only as an optional adapter | Detection logic can be built and tested deterministically without running an IoT platform | Not yet tested against real MQTT traffic |
| Rules in YAML, one Python module per rule *type* | Thresholds and severities change without code changes; analysts can read them | Rule types still need code |
| Separate base severity and context-based prioritization | Same rule can be LOW or CRITICAL depending on what actually happened | More logic to test (covered by tests) |
| Append-only tables with SQLite triggers + SHA-256 per event | Evidence integrity (threat T-7); reports re-verify hashes | No in-place corrections: decisions are added as new rows |
| Deterministic alert keys | Re-running detection never duplicates alerts or notifications | Keys must be stable across versions |
| Suggest, don't decide | Workflow suggests authorization/impact/escalation with reasons; the analyst decides | Analyst still needs judgement |
| RBAC blocks most attacks; detection still alerts on refused attempts | Defence in depth: a refused change is an indicator of a compromised account | More MEDIUM alerts to triage |
| Read-only integration with real refrigeration equipment | Monitoring must never cause a refrigeration failure | Cannot auto-remediate; recovery is a human step |

## 7. Questions interviewers ask — and answers

**How do you know the detection works?**
A controlled test plan: 10 scenarios (7 from the specification, the full kill chain, and two
boundary cases just under the thresholds) run through the real simulator and pipeline with
20 random seeds each. Each case states its expected alert, severity and also what must *not*
fire. Results are generated into [test-results.md](test-results.md), and the same cases run
in CI.

**How do you handle false positives?**
Thresholds sit just above normal behaviour (a user mistyping a password 3–4 times does not
alert; TC-09 checks that). Planned maintenance inside the window is recorded as INFO, not an
alert. Analysts can close an alert as false positive with a mandatory note, and severity
overrides are audited.

**What did testing find?**
Two real defects: a temperature alert created as LOW and later re-graded to HIGH was never
notified live, and two commands crashed on an empty database. Both fixed, with regression
tests.

**What would an attacker do to evade it?**
Stay under thresholds (slow brute force), use a valid technician account inside the
maintenance window, or manipulate the sensor so the controller reports normal temperatures.
The last one is why the hardware guide insists on an independent sensor on a separate path;
the cross-check rule (DR-7) is the most important next detection.

**How would this work in a real supermarket?**
See [hardware-guide.md](hardware-guide.md): ESP32 + DS18B20 for a prototype, commercial
calibrated sensors and an industrial IoT gateway for one store, and a segmented OT network
per store feeding a central SIEM for a chain. Integration with refrigeration controllers is
read-only and approved by refrigeration engineers and food-safety specialists.

**Which frameworks did you use?**
STRIDE for threat modelling, MITRE ATT&CK for ICS for technique mapping, IEC 62443 zones
and conduits for segmentation, NIST SP 800-61 phases for incident response.

**What would you do next?**
Implement the MQTT bridge and test with a real ESP32 sensor; add DR-3 (unknown source IP),
DR-7 (sensor cross-check) and DR-11 (detection config changed); move to PostgreSQL for
several writers; forward alerts to a SIEM in a standard format.

## 8. Skills demonstrated

| Area | Evidence in the repository |
|------|----------------------------|
| SOC analysis and incident response | Alert triage workflow, 8-step investigation, playbooks ([incident-response.md](incident-response.md)), report template |
| Detection engineering | Configurable rules, prioritization, correlation patterns, measured detection rate and time to detect |
| OT / IoT security | Threat model with ATT&CK for ICS, safe-integration principles, hardware guide |
| Python engineering | Package with CLI, typed dataclasses, SQLite with migrations, Streamlit app, ~280 tests, CI |
| Documentation | Requirements with traceability, architecture with diagrams, design decisions, test report |

## 9. Honest limitations

- All data is simulated; no real hardware or MQTT traffic has been tested yet.
- Some detection requirements are not implemented (DR-3, DR-7, DR-11; authorised DR-5/DR-10)
  — see [detection-rules.md §9](detection-rules.md#9-coverage-of-the-requirements).
- SMTP and Telegram notifications were tested with a local test server and mocks, not
  against real services.
- Single-site, single-process design; a chain would need the Level 3 architecture.
