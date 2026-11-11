# NexaCore users, roles and access relationships

Eight people and one service account are the only identities the evidence names. Email addresses follow `username@nexacore.example`.

## Key users

| Name | Role | Department | Username | Device | Why they matter |
| --- | --- | --- | --- | --- | --- |
| Amara Okafor | Accounts Payable Officer | Finance | a.okafor | NC-LT-0147 | Phishing target; processes supplier invoices |
| Tunde Adeyemi | Finance Manager | Finance | t.adeyemi | NC-LT-0112 | Approves payments; Amara's line manager |
| Ngozi Eze | Chief Financial Officer | Finance | n.eze | NC-LT-0009 | Second approver for large payments; executive risk owner |
| Ibrahim Musa | IT Support Engineer | IT Operations | i.musa | NC-LT-0201 | Handles password resets and device issues |
| Chidi Nwosu | SOC Analyst, Tier 1 | Security | c.nwosu | NC-WS-0305 | Receives the first alert and opens the case |
| Fatima Bello | Security Lead | Security | f.bello | NC-LT-0301 | Incident commander; signs off the response |
| Kemi Adebayo | HR Manager | Human Resources | k.adebayo | NC-LT-0155 | Owns security awareness training records |
| Emeka Obi | Chief Executive Officer | Executive Management | e.obi | NC-LT-0001 | Receives the executive report |
| svc-backup | Service account | IT Operations | svc-backup | NC-SRV-BKP01 | Normal background sign-ins, useful as noise in the logs |

## Access relationships

Who can do what, on which system. A dash means no access.

| User | Email | NexaLedger (finance) | PeopleHub (HR) | Finance file share | Entra ID admin | SIEM and EDR |
| --- | --- | --- | --- | --- | --- | --- |
| a.okafor | Own mailbox | Enter invoices, prepare payments | Own record | Read and write | - | - |
| t.adeyemi | Own mailbox | Edit supplier records, first approver | Own record | Read and write | - | - |
| n.eze | Own mailbox | Second approver, reports | Own record | Read only | - | - |
| i.musa | Own mailbox | - | Own record | - | Reset passwords, revoke sessions | - |
| c.nwosu | Own mailbox, read mailbox audit logs | - | Own record | - | Read sign-in logs | View and acknowledge alerts |
| f.bello | Own mailbox, read mailbox audit logs | - | Own record | - | Read sign-in logs | Full administration |
| k.adebayo | Own mailbox | - | Full administration | - | - | - |
| e.obi | Own mailbox | Reports, read only | Own record | Read only | - | - |
| svc-backup | - | - | - | Read only (backup) | - | - |

## Why these relationships matter to the incident

- **Amara cannot approve payments.** An attacker in her mailbox cannot move money alone; they need Tunde to act. That is why the attacker emails him.
- **Supplier bank details are edited by Tunde and need a second approver.** The second approval is the control that stops the fraud.
- **Ibrahim can reset passwords and revoke sessions.** He performs the containment at 10:14.
- **svc-backup signs in every hour without a person.** Its entries are background noise the analyst must learn to ignore.

---
All organizations, people, systems and data in this file are fictional and exist only for the CASEFILE 360 portfolio project.
