# GRC fields for assets, risks and controls

Three tables hold the GRC side: assets, controls and risks. Two link tables join them to each other and to the technical findings, which keeps GRC connected to the investigation.

## Fields

| Table | Field | Type | Example from NC-001 |
| --- | --- | --- | --- |
| Asset | asset_id | Text | A-02 |
| Asset | name | Text | Identity provider (Entra ID) |
| Asset | owner | Text | IT Operations |
| Asset | criticality | Low, Medium, High, Critical | Critical |
| Asset | business_process | Text | All staff sign-in |
| Control | control_id | Text | C-01 |
| Control | name | Text | Multi-factor authentication |
| Control | type | Preventive, Detective, Corrective | Preventive |
| Control | documented_state | Text | Required for all staff on email and VPN |
| Control | observed_state | Text | Not enforced on Finance email accounts |
| Control | effectiveness | Effective, Partial, Ineffective, Not tested | Ineffective |
| Control | evidence_ref | Evidence ID | NC-001-E03 |
| Risk | risk_id | Text | R-01 |
| Risk | statement | Text | Stolen passwords give direct mailbox access because MFA is not enforced |
| Risk | likelihood | 1 to 5 | 4 |
| Risk | impact | 1 to 5 | 4 |
| Risk | score | likelihood x impact, calculated | 16 |
| Risk | treatment | Mitigate, Accept, Transfer, Avoid | Mitigate |
| Risk | action | Text | Enforce MFA for all users |
| Risk | owner | Text | Segun Bakare |
| Risk | due_date | Date | To be set |
| Risk | status | Open, In progress, Closed | Open |

The two link tables are `risk_control` (which controls reduce which risk) and `finding_risk` (which technical finding raised which risk). Each holds only two ID columns.

## Starting risk register

Five risks follow directly from the ground truth. Scores use likelihood x impact on a 1 to 5 scale and are project assumptions.

| ID | Risk | Failed or weak control | Asset | L | I | Score | Treatment |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-01 | Stolen passwords give direct mailbox access | C-01: MFA not enforced for Finance | A-02 | 4 | 4 | 16 | Enforce MFA for all users |
| R-02 | Spoofed supplier email reaches staff inboxes | C-02: gateway in monitor mode | A-08 | 4 | 3 | 12 | Quarantine DMARC failures |
| R-03 | Supplier bank details changed on the strength of an email | C-04: email-only verification | A-04 | 3 | 5 | 15 | Require a call-back to a known number |
| R-04 | Staff do not recognise or report phishing | C-03: training 14 months old, no simulations | A-07 | 4 | 3 | 12 | Run training and quarterly simulations |
| R-05 | Account takeover goes unnoticed for too long | C-05, C-06: EDR alert-only; alert queue reviewed only in office hours | A-09 | 3 | 4 | 12 | Auto-escalate location alerts; set EDR to block |

In this incident the attacker had 39 minutes of mailbox access, from 09:35 to 10:14. That number belongs in the executive report as the measure for R-05.

---
All organizations, people, systems and data in this file are fictional and exist only for the CASEFILE 360 portfolio project.
