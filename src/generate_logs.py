"""
Generate synthetic Entra ID and M365 logs for an AiTM -> BEC scenario.

All data is fictional. Field names follow Microsoft Sentinel table schemas
(SigninLogs, AuditLogs, OfficeActivity), simplified.
"""
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)  # reproducible output
OUT = Path(__file__).resolve().parent.parent / "data"
OUT.mkdir(exist_ok=True)

DOMAIN = "contoso-demo.com"
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
VICTIM = f"carol@{DOMAIN}"
START = datetime(2026, 11, 2, 13, 0, tzinfo=timezone.utc)  # Monday 08:00 ET

# Legitimate corporate egress (fictional, documentation-range IPs)
CORP_IPS = ["198.51.100.10", "198.51.100.11"]
CORP_ASN = 64500
CORP_LOC = {"city": "Toronto", "countryOrRegion": "CA"}
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

# Attacker infrastructure (fictional)
PROXY_IP, PROXY_ASN = "203.0.113.45", 64666     # AiTM proxy relaying victim login
ATTACKER_IP, ATTACKER_ASN = "192.0.2.77", 64777  # cookie replay
ATTACKER_LOC = {"city": "Amsterdam", "countryOrRegion": "NL"}
ATTACKER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def signin(when, upn, ip, asn, loc, ua, session, auth_req="multiFactorAuthentication",
           app="OfficeHome", result=0):
    return {
        "TimeGenerated": ts(when),
        "UserPrincipalName": upn,
        "IPAddress": ip,
        "AutonomousSystemNumber": asn,
        "Location": loc,
        "UserAgent": ua,
        "AppDisplayName": app,
        "SessionId": session,
        "AuthenticationRequirement": auth_req,
        "ResultType": result,
        "CorrelationId": str(uuid.uuid4()),
    }


def office(when, upn, ip, op, params=None, workload="Exchange"):
    return {
        "TimeGenerated": ts(when),
        "UserId": upn,
        "ClientIP": ip,
        "Operation": op,
        "Workload": workload,
        "Parameters": params or [],
    }


signins, audits, office_events = [], [], []

# ---- Benign baseline: 5 workdays, every user ------------------------------
for day in range(5):
    for u in USERS:
        upn = f"{u}@{DOMAIN}"
        session = str(uuid.uuid4())
        t0 = START + timedelta(days=day, minutes=random.randint(0, 90))
        ip = random.choice(CORP_IPS)
        signins.append(signin(t0, upn, ip, CORP_ASN, CORP_LOC, BROWSER_UA, session))
        # token refreshes during the day reuse the same session from the same IP
        for h in range(1, random.randint(3, 6)):
            signins.append(signin(t0 + timedelta(hours=h), upn, ip, CORP_ASN, CORP_LOC,
                                  BROWSER_UA, session, auth_req="singleFactorAuthentication",
                                  app=random.choice(["Outlook", "Teams", "SharePoint"])))
        for _ in range(random.randint(4, 9)):
            office_events.append(office(t0 + timedelta(minutes=random.randint(5, 480)), upn, ip,
                                        random.choice(["MailItemsAccessed", "Send", "FileAccessed"])))

# Benign noise that should NOT alert: a legitimate inbox rule from corp IP
office_events.append(office(START + timedelta(days=1, hours=3), f"dave@{DOMAIN}", CORP_IPS[0],
                            "New-InboxRule",
                            [{"Name": "Name", "Value": "Newsletters"},
                             {"Name": "SubjectContainsWords", "Value": "newsletter"},
                             {"Name": "MoveToFolder", "Value": "Newsletters"}]))
# Benign noise: an employee registers MFA from the office (new phone)
audits.append({"TimeGenerated": ts(START + timedelta(days=2, hours=1)),
               "OperationName": "User registered security info",
               "Category": "UserManagement",
               "InitiatedBy": {"user": {"userPrincipalName": f"erin@{DOMAIN}", "ipAddress": CORP_IPS[1]}},
               "TargetResources": [{"userPrincipalName": f"erin@{DOMAIN}"}],
               "Result": "success"})

# ---- Attack: Wednesday ---------------------------------------------------
t = START + timedelta(days=2, hours=2, minutes=14)   # 10:14 ET
stolen = str(uuid.uuid4())
# 1) victim signs in via AiTM proxy: Microsoft sees the proxy's IP, MFA performed
signins.append(signin(t, VICTIM, PROXY_IP, PROXY_ASN, ATTACKER_LOC, BROWSER_UA, stolen))
# 2) 6 minutes later the attacker replays the cookie: same session, new IP/ASN/UA, no MFA prompt
t_replay = t + timedelta(minutes=6)
signins.append(signin(t_replay, VICTIM, ATTACKER_IP, ATTACKER_ASN, ATTACKER_LOC, ATTACKER_UA,
                      stolen, auth_req="singleFactorAuthentication", app="Outlook"))
# 3) attacker reads mail
office_events.append(office(t_replay + timedelta(minutes=2), VICTIM, ATTACKER_IP, "MailItemsAccessed"))
# 4) hiding inbox rule
office_events.append(office(t_replay + timedelta(minutes=9), VICTIM, ATTACKER_IP, "New-InboxRule",
                            [{"Name": "Name", "Value": "."},
                             {"Name": "SubjectOrBodyContainsWords", "Value": "invoice;payment;wire"},
                             {"Name": "MoveToFolder", "Value": "RSS Feeds"},
                             {"Name": "MarkAsRead", "Value": "True"},
                             {"Name": "StopProcessingRules", "Value": "True"}]))
# 5) MFA persistence
audits.append({"TimeGenerated": ts(t_replay + timedelta(minutes=14)),
               "OperationName": "User registered security info",
               "Category": "UserManagement",
               "InitiatedBy": {"user": {"userPrincipalName": VICTIM, "ipAddress": ATTACKER_IP}},
               "TargetResources": [{"userPrincipalName": VICTIM}],
               "AdditionalDetails": [{"key": "Method", "value": "Authenticator app"}],
               "Result": "success"})
# 6) internal phishing
for i, r in enumerate(["alice", "bob", "frank"]):
    office_events.append(office(t_replay + timedelta(minutes=21 + i), VICTIM, ATTACKER_IP, "Send",
                                [{"Name": "Recipient", "Value": f"{r}@{DOMAIN}"},
                                 {"Name": "Subject", "Value": "Updated payment details - action required"}]))

for name, rows in [("signin_logs.json", signins), ("audit_logs.json", audits),
                   ("office_activity.json", office_events)]:
    rows.sort(key=lambda r: r["TimeGenerated"])
    (OUT / name).write_text(json.dumps(rows, indent=2))
    print(f"wrote {len(rows):>4} events -> data/{name}")