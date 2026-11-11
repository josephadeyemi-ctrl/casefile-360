# Case NC-001: incident scenario and ground truth

This file is the answer key. On Tuesday 10 March 2026 an attacker phished Amara Okafor's password, signed in to her mailbox from abroad, and tried to redirect an 18,450,000 naira supplier payment. The fraud was stopped before any money moved.

All times are WAT. The log files store the same moments in UTC, one hour earlier.

## Facts the investigation must establish

1. The phishing email impersonated a real supplier, Brightline Logistics, from a lookalike domain.
2. The email failed SPF and DMARC but was still delivered, because the gateway was in monitor mode.
3. Amara opened the attachment and typed her password into a fake sign-in page at 09:21.
4. The attacker signed in to her mailbox at 09:35 from 198.51.100.140, with no MFA prompt.
5. The attacker created a hidden inbox rule and read her supplier emails.
6. The attacker sent a fake bank-change request from Amara's own mailbox to Tunde Adeyemi at 09:52.
7. The account was contained at 10:14 and the pending bank change was cancelled at 10:27. No payment was released.

| Fictional party | Detail |
| --- | --- |
| Real supplier | Brightline Logistics, brightline-logistics.example |
| Lookalike sender domain | brightline-logistics-ng.example |
| Fake sign-in page | login.nexacore-portal.example |
| Invoice used as the lure | INV-2026-0312, 18,450,000 naira |
| Case number | NC-001 |

## Timeline

| Time (WAT) | Actor | What happened | Recorded in |
| --- | --- | --- | --- |
| 08:02:11 | Amara | Normal sign-in from the Lagos office, 203.0.113.10, on NC-LT-0147 | authentication.log |
| 09:14:22 | Attacker | Phishing email delivered from accounts@brightline-logistics-ng.example, sending IP 198.51.100.23; SPF and DMARC fail | phishing-email.eml |
| 09:20:41 | Amara | Opens the attachment invoice.html in Edge | endpoint-events.json |
| 09:21:05 | Laptop | DNS lookup for login.nexacore-portal.example, answer 198.51.100.77 | dns.log |
| 09:21:07 | Amara | Browser loads the fake sign-in page | browser-history.csv |
| 09:21:10 | EDR | Low-severity alert: HTML attachment opened an external link; alert only, nothing blocked | security-alerts.json |
| 09:21:58 | Amara | Submits her password; page redirects to a harmless error page | browser-history.csv |
| 09:35:12 | Attacker | Successful mailbox sign-in from 198.51.100.140, Firefox on Linux, no MFA | authentication.log |
| 09:37:30 | Attacker | Creates inbox rule named RSS Subscriptions that hides mail mentioning Brightline, invoice or payment | mailbox-audit.json |
| 09:41:03 | Attacker | Reads 14 messages, mostly supplier invoices | mailbox-audit.json |
| 09:48:09 | SIEM | Medium alert: sign-in from an unfamiliar location for a.okafor | security-alerts.json |
| 09:52:36 | Attacker | Sends bank-change request for Brightline from Amara's mailbox to Tunde Adeyemi | mailbox-audit.json |
| 09:53:10 | Attacker | Deletes the sent message | mailbox-audit.json |
| 10:02:45 | Chidi | Picks up the SIEM alert and opens case NC-001 | security-alerts.json |
| 10:04:18 | Tunde | Signs in to NexaLedger and drafts the bank detail change; it waits for a second approver | authentication.log (sign-in only) |
| 10:09:00 | Chidi | Phones Amara; she confirms she is in Lagos and typed her password into a page that morning | analyst-notes.md |
| 10:14:20 | Ibrahim | Resets Amara's password and revokes her sessions | authentication.log |
| 10:15:02 | Attacker | Sign-in attempt from 198.51.100.140 fails | authentication.log |
| 10:27:00 | Fatima | Phones Tunde; the pending bank change is cancelled, no payment released | analyst-notes.md |

The attacker had 39 minutes of mailbox access, from 09:35 to 10:14.

## Indicators of compromise

| Type | Value | First seen in |
| --- | --- | --- |
| Email address | accounts@brightline-logistics-ng.example | phishing-email.eml |
| Email address | brightline.accounts@fastmail-secure.example (Reply-To) | phishing-email.eml |
| Domain | brightline-logistics-ng.example | phishing-email.eml |
| Domain | login.nexacore-portal.example | invoice.html, dns.log |
| URL | https://login.nexacore-portal.example/signin?ref=INV-88213 | invoice.html, browser-history.csv |
| IP address | 198.51.100.23 (sending mail server) | phishing-email.eml |
| IP address | 198.51.100.77 (fake sign-in page) | dns.log, endpoint-events.json |
| IP address | 198.51.100.140 (attacker sign-in) | authentication.log, mailbox-audit.json |
| File hash (SHA-256) | 447623fbf7baa345dfb7e2870faabfb46358ff128ca6d5d5fd7941fd04f3bb19 (invoice.html) | endpoint-events.json |
| Inbox rule name | RSS Subscriptions | mailbox-audit.json |

The real supplier domain, brightline-logistics.example, also appears in the logs. It is a deliberate trap: a careless extractor will flag it as malicious.

## Evidence set

The files live in `evidence/` and are rebuilt by `python tools/generate_evidence.py`. `evidence/MANIFEST.csv` lists the SHA-256 hash of each one.

---
All organizations, people, systems and data in this file are fictional and exist only for the CASEFILE 360 portfolio project.
