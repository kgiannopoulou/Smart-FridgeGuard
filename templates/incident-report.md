# INCIDENT REPORT

<!--
Blank SOC investigation report template (Phase 3, Step 12).

`python -m fridgeguard investigate report <INV-id> --format md|pdf` fills every section
from the database. Use this blank copy when working by hand (for example when the tool is
not available). Keep the section order; it is the same in the generated reports.
-->

**Incident ID:**  
**Detection time:** (UTC and local time)  
**Affected device:** (device ID, name, location)  
**Alert severity:**  

## 1. Initial alert

- Alert ID, rule and title:
- What triggered it (threshold, evidence records):
- Correlated incident (if any):

## 2. Investigation performed

| Step | Done by | Time | Notes |
|---|---|---|---|
| Review the alert | | | |
| Identify the affected refrigerator | | | |
| Examine the related events | | | |
| Investigate the user and source IP | | | |
| Determine whether the activity was authorized | | | |
| Assess the potential impact | | | |
| Escalate to the appropriate team if necessary | | | |
| Document the investigation | | | |

## 3. Evidence collected

- Evidence records (event / reading IDs):
- Affected refrigerator (expected range, temperature at the alert, time out of range):
- Users (registered? role, usual IPs, recent activity):
- Source IPs (on the allow-list? known for which user? failed / successful logins):
- Evidence integrity (hashes re-verified, evidence set SHA-256):

## 4. Event timeline

| Time (UTC) | Source | Record | What happened |
|---|---|---|---|
| | | | |

## 5. Findings

- Was the activity authorized? (authorized / unauthorized / unknown / not applicable)
- How was it verified (work order, call with the account owner, ...)?
- Summary:

## 6. Potential impact

- Impact level: (none / low / medium / high / critical)
- Why:

## 7. Recommended response

1. 

## 8. Escalation decision

- Decision: (not required / L2 SOC / maintenance engineering / store management / IT-network)
- Handed over to, when, with what request:

## 9. Final status

- Final status: (true positive / false positive / benign / escalated / undetermined)
- Alert status:
- Documented by, date:
