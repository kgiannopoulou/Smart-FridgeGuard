# Smart-FridgeGuard — Incident Response Plan

**Phase:** 4 – Testing, documentation and presentation
**Step:** 16 – Final portfolio (brings together the response work of Steps 10–13)
**Related:** [detection-rules.md](detection-rules.md) · [alert-management.md](alert-management.md) ·
[correlation.md](correlation.md) · [investigation.md](investigation.md) ·
[notifications.md](notifications.md) · [threat-model.md](threat-model.md) (control C-18) ·
[hardware-guide.md](hardware-guide.md)

This plan describes how a supermarket SOC responds to what Smart-FridgeGuard detects: who
does what, how fast, and which steps to follow for each kind of incident. Every step is
backed by a feature of the system (section 8), so the plan can be rehearsed end to end in the
lab.

> **Food safety comes first.** A security incident on a refrigerator is also a potential
> food-safety or medicine-safety incident. Decisions about stock (quarantine, discard,
> release) belong to store management and the food-safety / pharmacy lead, never to the SOC.
> Smart-FridgeGuard does not replace certified refrigeration alarms or HACCP procedures.

---

## 1. Scope

| In scope | Out of scope |
|----------|--------------|
| Unauthorized access to refrigerator controllers and management interfaces | Mechanical repairs (refrigeration contractor) |
| Unauthorized or suspicious configuration changes (setpoint, alarm limits, defrost, firmware) | Stock decisions (store management / food safety) |
| Brute-force and credential attacks against device logins | Company-wide incidents not involving refrigeration (handled by the corporate IR plan) |
| Temperature excursions that may have a security cause | |
| Loss of monitoring (device offline, network interruption) | |
| Tampering with logs or evidence | |

## 2. Lifecycle

The plan follows the phases of NIST SP 800-61 (incident handling):

```
 Preparation -> Detection & analysis -> Containment -> Eradication & recovery -> Post-incident
     ^                                                                                |
     +---------------------------- lessons learned, rule tuning ----------------------+
```

| Phase | What happens | Smart-FridgeGuard support |
|-------|--------------|---------------------------|
| Preparation | Accounts and roles, maintenance window, device allow-lists, notification channels, playbooks, contact list, rehearsals | `config/users.yaml`, `config/devices.yaml`, `config/notifications.yaml`, `config/investigation.yaml`, test plan in `scenarios/` |
| Detection & analysis | Rules raise alerts, prioritizer sets severity, correlator builds incidents, L1 analyst investigates | DET-001…007, COR-001…004, alert queue, 8-step investigation workflow |
| Containment | Stop the attacker: lock account, end sessions, block source IP, isolate the device's network | Recommended responses in each playbook; escalation to IT/network |
| Eradication & recovery | Restore known-good configuration, reset credentials, verify temperature and stock, close the gap | Configuration history (old/new values) in the event database, temperature history on the dashboard |
| Post-incident | Report, root cause, rule tuning, control improvements | Incident report (Markdown/PDF), append-only history, `docs/test-results.md` regression cases |

## 3. Roles and responsibilities

| Role | Responsibility | In the system |
|------|----------------|---------------|
| L1 SOC analyst | Triage the queue, investigate alerts, decide authorized / impact / escalation, document | `alerts queue`, `investigate`, dashboard "Alert investigation" |
| L2 SOC / incident responder | Handle confirmed or likely attacks, CRITICAL alerts and incidents; coordinate containment | Escalation team `l2_soc`; incident reviews (`incidents review`) |
| Refrigeration maintenance engineering | Equipment faults, restoring settings on the controller, on-site checks | Escalation team `maintenance_engineering` |
| Store management / food safety | Product checks, quarantine or disposal, pharmacy stock decisions | Escalation team `store_management` |
| IT / network team | Block source IPs, review remote access, firewall and VPN changes | Escalation team `it_network` |
| System administrator | Account lockout, password resets, token revocation | Roles in `config/users.yaml` |
| Incident owner | The L2 responder (or L1 for LOW/MEDIUM) who owns the incident until closure | Alert/investigation `assigned_to` |

## 4. Severity and response targets

Severities come from the prioritizer ([alert-management.md](alert-management.md)). The
response targets below are the targets proposed for a store SOC; they are a planning
assumption, not something the lab measures.

| Severity | Example | Notified via (default) | Acknowledge within | Escalate |
|----------|---------|------------------------|--------------------|----------|
| CRITICAL | Unauthorized change followed by a temperature excursion; COR-001 kill chain | Console + email (+ Telegram if enabled); bypasses rate limits | 15 min, 24/7 | L2 SOC immediately, store management, maintenance |
| HIGH | Brute force, unauthorized change, device offline, temperature ≥ 2 °C out of range | Console + email | 1 h | L2 SOC if access is unauthorized; maintenance for equipment |
| MEDIUM | Access outside maintenance hours; refused change attempts | Console | 4 h (business hours) | Only if the account owner does not confirm |
| LOW | Small temperature deviation | Dashboard | Next business day | Maintenance if it repeats |
| INFO | Planned maintenance activity | Dashboard (audit trail) | — | — |

## 5. Escalation matrix

From [`config/investigation.yaml`](../config/investigation.yaml), recorded in the
investigation's *escalation* step:

| Team | Escalate when |
|------|---------------|
| L2 SOC / incident response | Confirmed or likely unauthorized access, account takeover, CRITICAL alerts |
| Refrigeration maintenance engineering | Equipment fault, temperature excursion without a security cause, device offline |
| Store management / food safety | Product was out of range and may need quarantine or disposal; pharmacy stock affected |
| IT / network team | External source IP to block, remote access to the controller to review |

Contact the account owner **out of band** (phone, in person), never through the possibly
compromised account.

## 6. Playbooks

Each playbook lists the trigger, the questions the analyst must answer, and the actions per
phase. The *verify* questions match the ones the investigation workflow shows for each rule.

### PB-1 Brute force and account takeover (DET-002, COR-001, COR-003)

**Trigger:** ≥ 5 failed logins from one source IP in 5 min (DET-002); escalated to HIGH by
COR-003 when a login from that IP then succeeds, CRITICAL by COR-001 when that session
changes a setting.

| Phase | Actions |
|-------|---------|
| Analyse | Is the source IP on the device allow-list or a known site/vendor address? Which usernames were tried (generic names = guessing; a real account name = targeted)? Did any login from the same IP succeed afterwards? Same IP against other fridges? |
| Contain | Block the source IP at the store firewall (IT/network). If a login succeeded: lock the account, end its sessions, revoke its tokens. |
| Eradicate / recover | Reset the password of the targeted account(s); if a change was made, follow PB-2. Remove external exposure of the controller login (VPN only, control C-1). |
| Close | Document the usernames tried and the outcome; confirm lockout/rate limiting is active (C-4). |

### PB-2 Unauthorized configuration change (DET-001 / DET-006)

**Trigger:** a setpoint (DET-001) or other configuration change (DET-006: alarm limits,
defrost interval, firmware) by a role without permission, or with missing authorization.

| Phase | Actions |
|-------|---------|
| Analyse | Who made the change, from which IP, and was the role allowed? Was there a work order or call-out? Is the new value inside the safe operating range? Did it weaken monitoring (wider alarm limits, firmware)? Was it applied or refused? |
| Contain | If the account owner did not make it: lock the account and end its sessions (system admin). |
| Eradicate / recover | Restore the setting from the last approved configuration (maintenance engineering; old value is in the event). Watch the temperature for the next hour. |
| Food safety | If the temperature left the range, hand over to store management (PB-3). |
| Close | Review the role's permissions; a refused attempt (MEDIUM) still needs the owner's confirmation. |

### PB-3 Temperature excursion (DET-003, COR-004)

**Trigger:** readings outside the device's range for ≥ 15 min (DET-003); linked to a
preceding change by COR-004 (and CRITICAL if that change was unauthorized).

| Phase | Actions |
|-------|---------|
| Analyse | How far and how long out of range? Was there a configuration change before it (COR-004)? Signs of an equipment fault (compressor not running, door left open)? Is it a safety-critical device (pharmacy fridge)? |
| Contain | Security cause → PB-2. Equipment cause → maintenance engineering on site. |
| Food safety | Store management checks product temperature with a calibrated probe; quarantine or discard according to the food-safety procedure. Pharmacy stock: the responsible pharmacist decides. |
| Recover | Restore the setting if a change caused it; confirm the temperature is back inside the range on the dashboard. |
| Close | Record the excursion duration and the stock decision in the investigation. |

### PB-4 Off-hours or suspicious access (DET-004, COR-002)

**Trigger:** a technician or admin login or change outside the maintenance window (DET-004);
COR-002 when a suspicious login is followed by a change in the same session.

| Phase | Actions |
|-------|---------|
| Analyse | Was the access planned (work order) or an emergency call-out? Does the account owner confirm it (ask directly)? Did the session change anything? |
| Contain | Not confirmed → treat as a compromised account: lock, end sessions, then PB-1 / PB-2. |
| Close | Confirmed → mark false positive or benign with the confirmation as the note; require a work order for future out-of-window access. |

### PB-5 Device offline (DET-005)

**Trigger:** no reading from a device for 3 heartbeat intervals.

| Phase | Actions |
|-------|---------|
| Analyse | Is only this fridge silent, or the whole store (network outage)? Is it powered (staff check the display)? Did a configuration or firmware change happen just before? |
| Contain | Change before silence → treat as possible tampering (PB-2), escalate to L2. |
| Recover | Maintenance / IT restore power or connectivity. Staff take manual temperature readings while telemetry is missing. |
| Close | Confirm readings resumed; record the gap length (data during the gap cannot be verified). |

### PB-6 Evidence or log tampering

**Trigger:** `python -m fridgeguard events verify` reports a hash mismatch, events are missing
for a period while the device was online, or the database's append-only triggers reject an
attempted update/delete.

| Phase | Actions |
|-------|---------|
| Analyse | Which records fail verification? Who had write access to the database host? Does the gap or change overlap another incident? |
| Contain | Take a copy of the database file and its hash; restrict access to the monitoring host. |
| Recover | Restore from the last verified backup; re-import raw event logs (JSONL) where available. |
| Close | Treat as at least HIGH; escalate to L2 and corporate security. |

## 7. Evidence handling

- Events, alerts, alert history, investigations and notifications are **append-only** in
  SQLite (triggers reject `UPDATE`/`DELETE`); analyst decisions are added, never overwritten.
- Every event has a SHA-256 hash; the incident report **re-verifies** each evidence record
  when it is built and shows the result.
- Export the report (Markdown or PDF) and keep it with the incident ticket; the report lists
  the evidence IDs so it can be checked against the database later.
- Timestamps are stored in UTC and shown with the site's local time.
- Personal data (usernames, IPs) in reports is shared on a need-to-know basis.

## 8. Running the plan with Smart-FridgeGuard

| Task | Command (or dashboard page) |
|------|-----------------------------|
| See what needs attention | `python -m fridgeguard alerts queue` · dashboard *Overview* / *Alert management* |
| Take an alert | `python -m fridgeguard alerts status ALR-… under_investigation` |
| See the attack story | `python -m fridgeguard incidents show INC-…` · dashboard *Incident investigation* |
| Investigate step by step | `python -m fridgeguard investigate start ALR-…` then `investigate record …` · dashboard *Alert investigation* |
| Change severity (with reason) | `python -m fridgeguard alerts severity ALR-… CRITICAL --note "…"` |
| Close as false positive | `python -m fridgeguard alerts status ALR-… false_positive --note "…"` |
| Review an incident | `python -m fridgeguard incidents review INC-… closed --verdict true_positive --note "…"` |
| Check notifications sent | `python -m fridgeguard notify list --alert ALR-…` |
| Verify evidence integrity | `python -m fridgeguard events verify` |
| Produce the report | `python -m fridgeguard investigate report INV-… --format pdf` |

## 9. Worked example: INV-000001

[INV-000001](examples/INV-000001.md) ([PDF](examples/INV-000001.pdf)) shows PB-1 end to end:

1. **Detection:** ALR-000025 (DET-002, HIGH) — 7 failed logins in about 1 min from
   203.0.113.50 against FRIDGE-001, usernames `root`, `technician`, `unknown_user` and the real
   account `system_admin`.
2. **Analysis:** no login from that IP ever succeeded, no session, no change; the IP is not on
   the allow-list; the same source tried the other fridges in the same week.
3. **Decisions:** unauthorized · impact low (attempts only) · escalate to IT/network.
4. **Containment requested:** block 203.0.113.50 at the store firewall, review why the
   controller login is reachable from outside; `system_admin` to confirm a strong password.
5. **Closure:** true positive, alert resolved, report generated with all evidence hashes
   verified.

## 10. Post-incident review

Within five working days of any HIGH or CRITICAL incident:

- Timeline: first event, detection, acknowledgement, containment, recovery (from the report).
- Root cause and which control failed or was missing ([threat-model.md §10](threat-model.md#10-defensive-controls)).
- Detection quality: was it detected by the expected rule? Too late? Too noisy? Tune
  `config/detection.yaml` / `config/prioritization.yaml` (changes are reviewed like code).
- Add a regression scenario to `scenarios/` so the attack is part of the system test.
- Stock and food-safety outcome recorded by store management.

## 11. Rehearsal

The system test plan doubles as a tabletop exercise: run a scenario, then work the alert
through the matching playbook.

```powershell
python -m fridgeguard evaluate --case TC-08 --seeds 1 --out -   # full kill chain (PB-1 + PB-2 + PB-3)
python -m fridgeguard simulate --duration 7d --faults-per-day 0.5 --show none
python -m fridgeguard alerts queue
```
