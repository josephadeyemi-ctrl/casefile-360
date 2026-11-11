# NexaCore asset inventory

Thirteen assets cover the whole environment. The last column says which evidence file each asset produces.

| ID | Asset | Owner | Criticality | Evidence it produces |
| --- | --- | --- | --- | --- |
| A-01 | Corporate email (Exchange Online) | IT Operations | High | phishing-email.eml, mailbox-audit.json |
| A-02 | Identity provider (Entra ID) | IT Operations | Critical | authentication.log |
| A-03 | VPN gateway (vpn.nexacore.example) | Network and Cloud | High | VPN entries in authentication.log |
| A-04 | NexaLedger finance system | Finance | Critical | Sign-in entries in authentication.log |
| A-05 | PeopleHub HR system | Human Resources | High | None in this incident |
| A-06 | File storage (NC-FS-01) | IT Operations | High | File access entries in endpoint-events.json |
| A-07 | Employee laptops (about 260, Windows 11) | IT Operations | Medium | endpoint-events.json, browser-history.csv |
| A-08 | Email security gateway | Security | High | Filter verdict in the email headers |
| A-09 | SIEM | Security | High | security-alerts.json |
| A-10 | Endpoint detection and response (EDR) | Security | High | security-alerts.json, endpoint-events.json |
| A-11 | DNS resolver (NC-DNS-01) | Network and Cloud | Medium | dns.log |
| A-12 | Customer cloud hosting platform | Network and Cloud | Critical | None in this incident |
| A-13 | Backup service (NC-SRV-BKP01) | IT Operations | High | Background sign-ins only |

## Criticality scale

| Level | Meaning |
| --- | --- |
| Critical | Loss stops the business or exposes customer data |
| High | Loss seriously disrupts a department |
| Medium | Loss affects individuals; workarounds exist |
| Low | Little business effect |

---
All organizations, people, systems and data in this file are fictional and exist only for the CASEFILE 360 portfolio project.
