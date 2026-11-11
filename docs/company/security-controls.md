# NexaCore security controls

Each control has a documented state and an actual state. The gap between the two is what the GRC assessment should discover from the evidence. The right-hand column is the answer key.

| ID | Control | Type | What the policy says | Actual state (ground truth) |
| --- | --- | --- | --- | --- |
| C-01 | Multi-factor authentication | Preventive | Required for all staff on email and VPN | Enforced on VPN and admin accounts; email rollout incomplete, Finance not yet enrolled |
| C-02 | Email filtering | Preventive | Messages failing SPF, DKIM or DMARC are quarantined | Gateway is in monitor mode: failures are delivered with a warning banner |
| C-03 | Security awareness | Preventive | Annual training and quarterly phishing simulations | Finance last trained 14 months ago; no simulation has ever run |
| C-04 | Payment approval | Preventive | Two approvers for payments above 5,000,000 naira | Followed, but supplier bank detail changes are confirmed by email only |
| C-05 | Endpoint protection | Detective | EDR on every laptop, blocking malicious activity | Installed everywhere, but set to alert only |
| C-06 | Authentication monitoring | Detective | SIEM alerts on sign-ins from unusual locations | Working; alert goes to a queue reviewed in office hours |
| C-07 | Logging and retention | Detective | All security logs kept 90 days | Sign-in and EDR logs 90 days; DNS logs only 30 days |
| C-08 | Access control | Preventive | Least privilege, reviewed quarterly | Last access review was 7 months ago |
| C-09 | Password policy | Preventive | 12 characters minimum, no reuse of last 10 | Enforced |
| C-10 | Backup | Corrective | Nightly backup, restore test every quarter | Backups run; last restore test 9 months ago |
| C-11 | Incident response plan | Corrective | Version 1.2, tested annually | Exists; never tested with a live exercise |

## Control types

- **Preventive:** stops an incident before it happens.
- **Detective:** identifies an incident in progress or after the fact.
- **Corrective:** restores normal operation and reduces recurrence.

A control existing does not mean it worked. Each one is judged against evidence.

---
All organizations, people, systems and data in this file are fictional and exist only for the CASEFILE 360 portfolio project.
