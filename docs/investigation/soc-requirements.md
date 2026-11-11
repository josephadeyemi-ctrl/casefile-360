# SOC/DFIR investigation requirements

Seven screens cover the whole investigation. Each one exists to answer a single analyst question, and that question decides what goes on it.

| Screen | Question it answers | Must show | Actions |
| --- | --- | --- | --- |
| Dashboard | What is open and how bad is it? | Case list with status and severity; counts of evidence, IOCs and events; latest alerts | Open a case, create a case |
| Case | What is this incident and where are we? | Case ID, title, status, severity, owner, opened time, summary, affected users and assets | Edit status, add a note |
| Evidence | What do we hold, and can we trust it? | Evidence ID, filename, type, size, SHA-256, upload time, uploaded by, source, parse status | Upload, view raw file, re-verify hash |
| Evidence viewer | What does this file say? | Email: headers, SPF, DKIM and DMARC results, body, attachments. Logs: parsed rows with filter and search | Filter, search, jump to timeline |
| IOCs | What is malicious, and where else does it appear? | Type, value, first seen, source file, number of matching events, analyst verdict | Mark malicious, benign or unknown; show matching events |
| Timeline | What happened, in what order? | Events from all sources in one list, time in WAT, source file, actor, description, matched IOC highlighted | Filter by source, user or IOC; flag an event as key |
| Findings and report | What did we conclude, and what should happen next? | Findings with the evidence and events that support each one; recommendations; link to risks | Add a finding, link evidence, export report |

## Rules that apply to every screen

1. **Every claim links back to evidence.** A finding or timeline row always shows the file and line it came from.
2. **The original file is never changed.** Parsing reads a copy; the stored hash must still match after any action.
3. **The analyst decides.** The platform suggests IOCs and correlations; a person marks them malicious or benign.

## Build order

Evidence, Evidence viewer, IOCs, Timeline, Case, Findings, Dashboard. Each depends on data the one before it produces.

## Questions the investigation must answer

These come from the ground truth in [../incident/ground-truth.md](../incident/ground-truth.md). The platform passes when an analyst can answer all seven from the evidence.

1. Who sent the phishing email, and from what infrastructure?
2. Why was it delivered despite failing sender checks?
3. What did the user do with it, and when?
4. Was the account accessed by someone else? From where?
5. What did the attacker do inside the mailbox?
6. Did the attacker try to reach anyone else or move money?
7. When was the account contained, and was any payment released?

---
All organizations, people, systems and data in this file are fictional and exist only for the CASEFILE 360 portfolio project.
