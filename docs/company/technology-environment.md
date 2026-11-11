# NexaCore technology environment

How NexaCore's systems connect, and the naming rules every log line follows. A wrong hostname or IP in the evidence is a bug, not a clue.

## How mail and sign-ins flow

1. Email from the internet reaches the email security gateway, which checks SPF, DKIM and DMARC.
2. The gateway hands the message to Exchange Online, which delivers it to the user's mailbox.
3. Staff sign in through Entra ID to reach email, NexaLedger, PeopleHub and file storage. Remote staff connect through the VPN first.
4. Laptops resolve domain names through the internal DNS resolver, NC-DNS-01.
5. The EDR agent on each laptop and the sign-in logs from Entra ID feed the SIEM, which raises alerts for the SOC.
6. CASEFILE 360 sits after all of this: it takes exported evidence from these systems and analyses it.

## Naming and addressing conventions

| Item | Convention |
| --- | --- |
| Usernames | First initial, dot, surname: a.okafor |
| Laptops | NC-LT-0001 to NC-LT-0260 |
| SOC workstations | NC-WS-0301 to NC-WS-0308 |
| Servers | NC-SRV-, NC-FS- or NC-DNS- plus a number |
| Finance VLAN | 10.20.10.0/24 |
| HR VLAN | 10.20.20.0/24 |
| IT and Security VLAN | 10.20.30.0/24 |
| Server VLAN | 10.20.50.0/24 |
| VPN address pool | 10.20.200.0/24 |
| Lagos office public IP | 203.0.113.10 |
| Abuja office public IP | 203.0.113.74 |
| Attacker infrastructure | 198.51.100.0/24 addresses and .example domains only |
| Timestamps | Logs are stored in UTC; reports and the timeline display WAT (UTC+1) |

The public ranges 203.0.113.0/24 and 198.51.100.0/24 are reserved for documentation, and .example is a reserved domain. Using them guarantees no real system is ever named.

The full list of systems, with owners and criticality, is in [asset-inventory.md](asset-inventory.md).

---
All organizations, people, systems and data in this file are fictional and exist only for the CASEFILE 360 portfolio project.
