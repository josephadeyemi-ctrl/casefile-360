"""
generate_evidence.py - builds the synthetic evidence set for CASEFILE 360, case NC-001.

Everything here is fictional. Domains end in .example and public IPs come from
the documentation ranges 203.0.113.0/24 and 198.51.100.0/24, so no real system
is ever named.

Run:  python tools/generate_evidence.py   (from the repo root)
Output: evidence/ at the repo root  (8 evidence files + MANIFEST.csv)

The script is deterministic: the same code always produces the same files and
the same SHA-256 hashes, because the random generator uses a fixed seed.
"""

import csv
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

random.seed(360)
OUT = Path(__file__).resolve().parent.parent / "evidence"
OUT.mkdir(exist_ok=True)

DAY = "2026-03-10"
WAT = timezone(timedelta(hours=1))


def utc(wat_time: str) -> str:
    """'09:14:22' in WAT on the incident day -> ISO timestamp in UTC."""
    local = datetime.fromisoformat(f"{DAY}T{wat_time}").replace(tzinfo=WAT)
    return local.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def random_time(start_hour: int, end_hour: int) -> str:
    seconds = random.randint(start_hour * 3600, end_hour * 3600 - 1)
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


# ---------------------------------------------------------------- ground truth
VICTIM = "a.okafor"
VICTIM_HOST = "NC-LT-0147"
VICTIM_IP = "10.20.10.47"
LAGOS_IP = "203.0.113.10"
ABUJA_IP = "203.0.113.74"
SENDER = "accounts@brightline-logistics-ng.example"
SENDER_IP = "198.51.100.23"
PHISH_HOST = "login.nexacore-portal.example"
PHISH_IP = "198.51.100.77"
PHISH_URL = f"https://{PHISH_HOST}/signin?ref=INV-88213"
ATTACKER_IP = "198.51.100.140"
ATTACKER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
EDGE_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0")

OTHER_USERS = [
    ("t.adeyemi", "NC-LT-0112", "10.20.10.12"), ("n.eze", "NC-LT-0009", "10.20.10.9"),
    ("i.musa", "NC-LT-0201", "10.20.30.21"), ("c.nwosu", "NC-WS-0305", "10.20.30.55"),
    ("f.bello", "NC-LT-0301", "10.20.30.31"), ("k.adebayo", "NC-LT-0155", "10.20.20.15"),
    ("e.obi", "NC-LT-0001", "10.20.30.2"), ("b.ogunleye", "NC-LT-0178", "10.20.30.78"),
    ("a.nnamdi", "NC-LT-0133", "10.20.30.133"), ("s.bakare", "NC-LT-0020", "10.20.30.20"),
]

# ---------------------------------------------------------- 1. phishing email
INVOICE_HTML = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Invoice INV-2026-0312</title>
<meta http-equiv="refresh" content="2; url={PHISH_URL}"></head>
<body style="font-family:Arial">
<p>Your secure invoice is loading. If it does not open,
<a href="{PHISH_URL}">sign in to view the document</a>.</p>
<!-- SYNTHETIC TRAINING ARTIFACT - CASEFILE 360 - the target domain does not exist -->
</body></html>
"""

msg = EmailMessage()
msg["Received"] = (f"from mail.brightline-logistics-ng.example ([{SENDER_IP}]) "
                   f"by mx1.nexacore.example with ESMTPS id NC7F31A; "
                   f"Tue, 10 Mar 2026 08:14:22 +0000")
msg["Authentication-Results"] = (
    "mx1.nexacore.example; "
    f"spf=fail (sender IP is {SENDER_IP}) smtp.mailfrom=brightline-logistics-ng.example; "
    "dkim=none (message not signed); "
    "dmarc=fail action=none header.from=brightline-logistics-ng.example")
msg["Received-SPF"] = (f"Fail (mx1.nexacore.example: domain of brightline-logistics-ng.example "
                       f"does not designate {SENDER_IP} as permitted sender)")
msg["X-NexaCore-Gateway"] = "verdict=suspicious; mode=monitor; action=delivered-with-banner"
msg["From"] = f"Brightline Logistics Accounts <{SENDER}>"
msg["Reply-To"] = "brightline.accounts@fastmail-secure.example"
msg["To"] = "Amara Okafor <a.okafor@nexacore.example>"
msg["Subject"] = "Urgent Invoice Payment - INV-2026-0312"
msg["Date"] = "Tue, 10 Mar 2026 09:14:05 +0100"
msg["Message-ID"] = "<20260310081405.7F31A@mail.brightline-logistics-ng.example>"
msg["X-Mailer"] = "PHPMailer 6.8.0"
msg.set_content(
    "[EXTERNAL - this message failed sender verification]\n\n"
    "Dear Amara,\n\n"
    "Our records show invoice INV-2026-0312 for NGN 18,450,000 is due today.\n"
    "To avoid a service suspension, please review the attached invoice and\n"
    "confirm payment before 12:00.\n\n"
    "Please note our banking details have recently changed. The updated\n"
    "details are inside the secure invoice.\n\n"
    "Kind regards,\n"
    "Accounts Receivable\n"
    "Brightline Logistics\n")
msg.add_attachment(INVOICE_HTML.encode(), maintype="text", subtype="html",
                   filename="invoice.html")
(OUT / "phishing-email.eml").write_bytes(msg.as_bytes())
(OUT / "invoice.html").write_text(INVOICE_HTML, encoding="utf-8")

# ------------------------------------------------------- 2. authentication.log
auth = []


def sign_in(t, user, app, result, ip, location, device, ua, mfa, event="SignIn", detail=""):
    auth.append({"timestamp": utc(t), "event_type": event, "user": user, "app": app,
                 "result": result, "source_ip": ip, "location": location,
                 "device": device, "user_agent": ua, "mfa": mfa, "detail": detail})


for user, host, _ in OTHER_USERS:                       # background noise
    office = (ABUJA_IP, "Abuja, NG") if user == "a.nnamdi" else (LAGOS_IP, "Lagos, NG")
    sign_in(random_time(7, 9), user, "Exchange Online", "success", *office, host, EDGE_UA, "not_required")
    for app in random.sample(["SharePoint", "Teams", "VPN", "PeopleHub", "Exchange Online"], 3):
        mfa = "passed" if app == "VPN" else "not_required"
        sign_in(random_time(8, 11), user, app, "success", *office, host, EDGE_UA, mfa)
sign_in("08:47:30", "b.ogunleye", "Exchange Online", "failure", LAGOS_IP, "Lagos, NG",
        "NC-LT-0178", EDGE_UA, "not_required", detail="Invalid password")
for t in ("07:00:04", "08:00:03", "09:00:05", "10:00:04"):
    sign_in(t, "svc-backup", "Backup Service", "success", "10.20.50.14", "Internal",
            "NC-SRV-BKP01", "BackupAgent/4.2", "not_required")

# the events that matter
sign_in("08:02:11", VICTIM, "Exchange Online", "success", LAGOS_IP, "Lagos, NG", VICTIM_HOST, EDGE_UA, "not_required")
sign_in("08:05:40", VICTIM, "NexaLedger", "success", LAGOS_IP, "Lagos, NG", VICTIM_HOST, EDGE_UA, "not_required")
sign_in("09:35:12", VICTIM, "Exchange Online", "success", ATTACKER_IP, "Amsterdam, NL", "Unknown", ATTACKER_UA, "not_required")
sign_in("10:04:18", "t.adeyemi", "NexaLedger", "success", LAGOS_IP, "Lagos, NG", "NC-LT-0112", EDGE_UA, "not_required")
sign_in("10:14:20", VICTIM, "Entra ID", "success", LAGOS_IP, "Lagos, NG", "NC-LT-0201", EDGE_UA, "passed",
        event="PasswordReset", detail="Password reset by i.musa")
sign_in("10:14:26", VICTIM, "Entra ID", "success", LAGOS_IP, "Lagos, NG", "NC-LT-0201", EDGE_UA, "passed",
        event="SessionsRevoked", detail="All refresh tokens revoked by i.musa")
sign_in("10:15:02", VICTIM, "Exchange Online", "failure", ATTACKER_IP, "Amsterdam, NL", "Unknown", ATTACKER_UA,
        "not_required", detail="Session revoked; invalid credentials")
sign_in("10:22:51", VICTIM, "Exchange Online", "success", LAGOS_IP, "Lagos, NG", VICTIM_HOST, EDGE_UA, "not_required",
        detail="First sign-in after password reset")

auth.sort(key=lambda e: e["timestamp"])
with open(OUT / "authentication.log", "w", encoding="utf-8") as f:
    for entry in auth:                                   # JSON Lines: one event per line
        f.write(json.dumps(entry) + "\n")

# -------------------------------------------------------------------- 3. dns.log
BENIGN = ["outlook.office365.com", "login.microsoftonline.com", "teams.microsoft.com",
          "nexaledger.nexacore.example", "peoplehub.nexacore.example", "intranet.nexacore.example",
          "www.bing.com", "update.microsoft.com", "cdn.office.net", "www.brightline-logistics.example"]
dns = []
for _ in range(110):
    _, _, ip = random.choice(OTHER_USERS)
    dns.append((random_time(7, 11), ip, random.choice(BENIGN), f"203.0.113.{random.randint(100, 250)}"))
for t in ("08:02:09", "08:31:44", "09:02:17", "09:44:50", "10:23:02"):
    dns.append((t, VICTIM_IP, random.choice(BENIGN[:6]), f"203.0.113.{random.randint(100, 250)}"))
dns.append(("09:21:05", VICTIM_IP, PHISH_HOST, PHISH_IP))
dns.append(("09:21:57", VICTIM_IP, PHISH_HOST, PHISH_IP))
dns.sort()
with open(OUT / "dns.log", "w", encoding="utf-8") as f:
    for t, client, query, answer in dns:
        f.write(f"{utc(t)} client={client} query={query} type=A answer={answer} rcode=NOERROR\n")

# --------------------------------------------------------- 4. browser-history.csv
history = [
    ("08:03:02", "https://outlook.office365.com/mail/", "Mail - Amara Okafor - Outlook", "typed"),
    ("08:06:11", "https://nexaledger.nexacore.example/dashboard", "NexaLedger - Dashboard", "typed"),
    ("08:19:45", "https://nexaledger.nexacore.example/payables/open", "NexaLedger - Open payables", "link"),
    ("08:41:30", "https://intranet.nexacore.example/finance/calendar", "Finance calendar", "link"),
    ("09:03:12", "https://www.brightline-logistics.example/track", "Brightline Logistics - Track shipment", "link"),
    ("09:20:43", "file:///C:/Users/a.okafor/AppData/Local/Microsoft/Windows/INetCache/Content.Outlook/7KQ2M1XA/invoice.html",
     "Invoice INV-2026-0312", "link"),
    ("09:21:07", PHISH_URL, "Sign in to your account", "redirect"),
    ("09:21:58", f"https://{PHISH_HOST}/signin/verify", "Signing in...", "form_submit"),
    ("09:22:01", f"https://{PHISH_HOST}/error?code=440", "Session expired", "redirect"),
    ("09:23:30", "https://outlook.office365.com/mail/", "Mail - Amara Okafor - Outlook", "typed"),
    ("09:46:02", "https://nexaledger.nexacore.example/payables/open", "NexaLedger - Open payables", "link"),
    ("10:23:15", "https://login.microsoftonline.com/", "Sign in to your account", "typed"),
]
with open(OUT / "browser-history.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["visit_time_utc", "user", "host", "browser", "url", "title", "transition"])
    for t, url, title, transition in history:
        writer.writerow([utc(t), VICTIM, VICTIM_HOST, "Microsoft Edge 122", url, title, transition])

# -------------------------------------------------------- 5. endpoint-events.json
ATTACH_PATH = r"C:\Users\a.okafor\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\7KQ2M1XA\invoice.html"
INVOICE_SHA256 = hashlib.sha256(INVOICE_HTML.encode()).hexdigest()


def endpoint(t, event_type, process, **extra):
    return {"timestamp": utc(t), "host": VICTIM_HOST, "user": VICTIM,
            "event_type": event_type, "process": process, **extra}


endpoint_events = [
    endpoint("08:01:48", "logon", "winlogon.exe", logon_type="interactive"),
    endpoint("08:02:30", "process_start", "OUTLOOK.EXE", parent="explorer.exe", pid=4120),
    endpoint("08:05:55", "process_start", "msedge.exe", parent="explorer.exe", pid=5288),
    endpoint("08:40:12", "process_start", "EXCEL.EXE", parent="explorer.exe", pid=6012,
             command_line=r'"EXCEL.EXE" "\\NC-FS-01\Finance\Payables\March-2026.xlsx"'),
    endpoint("08:40:14", "file_access", "EXCEL.EXE", path=r"\\NC-FS-01\Finance\Payables\March-2026.xlsx"),
    endpoint("09:20:39", "file_create", "OUTLOOK.EXE", path=ATTACH_PATH, sha256=INVOICE_SHA256, size=len(INVOICE_HTML.encode())),
    endpoint("09:20:41", "process_start", "msedge.exe", parent="OUTLOOK.EXE", pid=7344,
             command_line=f'"msedge.exe" "{ATTACH_PATH}"'),
    endpoint("09:21:06", "network_connect", "msedge.exe", pid=7344, dest_ip=PHISH_IP, dest_port=443, dest_host=PHISH_HOST),
    endpoint("09:21:58", "network_connect", "msedge.exe", pid=7344, dest_ip=PHISH_IP, dest_port=443, dest_host=PHISH_HOST),
    endpoint("09:46:20", "file_access", "EXCEL.EXE", path=r"\\NC-FS-01\Finance\Payables\March-2026.xlsx"),
    endpoint("10:22:40", "process_start", "msedge.exe", parent="explorer.exe", pid=8120),
]
(OUT / "endpoint-events.json").write_text(json.dumps(endpoint_events, indent=2), encoding="utf-8")

# --------------------------------------------------------- 6. mailbox-audit.json


def mailbox(t, operation, ip, ua, **extra):
    return {"timestamp": utc(t), "mailbox": "a.okafor@nexacore.example", "operation": operation,
            "client_ip": ip, "user_agent": ua, **extra}


mailbox_events = [
    mailbox("08:03:10", "MailItemsAccessed", LAGOS_IP, EDGE_UA, item_count=6, folder="Inbox"),
    mailbox("08:27:44", "Send", LAGOS_IP, EDGE_UA, to="t.adeyemi@nexacore.example", subject="March payables - draft schedule"),
    mailbox("09:20:35", "MailItemsAccessed", LAGOS_IP, EDGE_UA, item_count=1, folder="Inbox",
            subject="Urgent Invoice Payment - INV-2026-0312"),
    mailbox("09:37:30", "New-InboxRule", ATTACKER_IP, ATTACKER_UA, rule_name="RSS Subscriptions",
            conditions={"subject_or_body_contains": ["Brightline", "invoice", "payment"]},
            actions={"move_to_folder": "RSS Feeds", "mark_as_read": True}),
    mailbox("09:41:03", "MailItemsAccessed", ATTACKER_IP, ATTACKER_UA, item_count=14, folder="Inbox",
            search_query="Brightline OR invoice OR bank details"),
    mailbox("09:52:36", "Send", ATTACKER_IP, ATTACKER_UA, to="t.adeyemi@nexacore.example",
            subject="Updated bank details for Brightline Logistics - INV-2026-0312",
            body_preview=("Hi Tunde, Brightline have changed their bank. New details: Meridian Trust Bank, "
                          "account ending 4471. INV-2026-0312 for NGN 18,450,000 is due today, please update "
                          "the supplier record so we can release it before 12.")),
    mailbox("09:53:10", "SoftDelete", ATTACKER_IP, ATTACKER_UA, folder="Sent Items",
            subject="Updated bank details for Brightline Logistics - INV-2026-0312"),
    mailbox("10:21:15", "Remove-InboxRule", LAGOS_IP, EDGE_UA, rule_name="RSS Subscriptions", performed_by="i.musa"),
]
(OUT / "mailbox-audit.json").write_text(json.dumps(mailbox_events, indent=2), encoding="utf-8")

# ------------------------------------------------------- 7. security-alerts.json
alerts = [
    {"alert_id": "AL-20260310-0007", "timestamp": utc("08:47:35"), "source": "SIEM", "severity": "low",
     "title": "Failed sign-in", "user": "b.ogunleye", "host": "NC-LT-0178", "source_ip": LAGOS_IP,
     "status": "closed", "resolution": "Benign: user mistyped password"},
    {"alert_id": "AL-20260310-0011", "timestamp": utc("09:21:10"), "source": "EDR", "severity": "low",
     "title": "HTML attachment opened an external link", "user": VICTIM, "host": VICTIM_HOST,
     "process": "msedge.exe", "dest_host": PHISH_HOST, "dest_ip": PHISH_IP, "file_sha256": INVOICE_SHA256,
     "action_taken": "none (alert-only mode)", "status": "new"},
    {"alert_id": "AL-20260310-0014", "timestamp": utc("09:48:09"), "source": "SIEM", "severity": "medium",
     "title": "Sign-in from unfamiliar location", "user": VICTIM, "source_ip": ATTACKER_IP,
     "location": "Amsterdam, NL", "previous_location": "Lagos, NG", "previous_sign_in": utc("08:02:11"),
     "status": "acknowledged", "acknowledged_by": "c.nwosu", "acknowledged_at": utc("10:02:45"), "case_id": "NC-001"},
    {"alert_id": "AL-20260310-0016", "timestamp": utc("10:00:09"), "source": "SIEM", "severity": "info",
     "title": "Backup job completed", "user": "svc-backup", "host": "NC-SRV-BKP01", "status": "closed"},
]
(OUT / "security-alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")

# ------------------------------------------------------------ 8. analyst-notes.md
(OUT / "analyst-notes.md").write_text(
    "# Analyst notes - case NC-001\n\n"
    "All times WAT, 10 March 2026.\n\n"
    "## 10:09 - phone call with Amara Okafor (c.nwosu)\n"
    "Amara confirms she is in the Lagos office and has not travelled. She opened an invoice "
    "attachment from Brightline around 09:20, was asked to sign in, typed her password, and saw "
    "a 'session expired' page. She did not report it because the page looked normal.\n\n"
    "## 10:27 - phone call with Tunde Adeyemi (f.bello)\n"
    "Tunde received a bank-change request from Amara's mailbox at 09:52 and drafted the supplier "
    "change in NexaLedger at about 10:05. It was waiting for a second approver. He has cancelled "
    "the draft. No payment was released.\n", encoding="utf-8")

# ------------------------------------------------------------------- MANIFEST.csv
DESCRIPTIONS = {
    "phishing-email.eml": "Phishing email with full headers and attachment",
    "invoice.html": "Attachment extracted from the phishing email",
    "authentication.log": "Sign-in and identity events, JSON Lines, UTC",
    "dns.log": "DNS resolver query log, UTC",
    "browser-history.csv": "Edge history from NC-LT-0147, UTC",
    "endpoint-events.json": "EDR telemetry from NC-LT-0147, UTC",
    "mailbox-audit.json": "Mailbox audit log for a.okafor, UTC",
    "security-alerts.json": "SIEM and EDR alerts, UTC",
    "analyst-notes.md": "Interview notes taken during the response, WAT",
}
with open(OUT / "MANIFEST.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["evidence_id", "filename", "sha256", "size_bytes", "description"])
    for number, (name, description) in enumerate(DESCRIPTIONS.items(), start=1):
        data = (OUT / name).read_bytes()
        writer.writerow([f"NC-001-E{number:02d}", name, hashlib.sha256(data).hexdigest(), len(data), description])
        print(f"NC-001-E{number:02d}  {name:24} {len(data):>6} bytes")

print(f"\nEvidence written to {OUT}")
