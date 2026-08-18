#!/usr/bin/env python3
"""
SOC-ify Alerting Module (DRAFT - for review, NOT yet wired into apply_rules.py)
==============================================================================
Sends new high-severity findings to an out-of-band channel so an analyst is
actually notified the moment apply_rules.py flags something severe — turning the
pipeline from "log detection" into a working SOC alert flow.

SUPPORTED CHANNELS (enable whichever you configure):
  - Telegram        : SOC_TG_TOKEN + SOC_TG_CHAT_ID
  - Teams webhook   : SOC_TEAMS_WEBHOOK
  - Email SMTP      : SOC_SMTP_HOST/PORT/USER/PASS/FROM/TO

DESIGN
  - Standalone module. Reads NEW findings (severity >= threshold) from siem-findings
    since the last-run watermark, formats them, sends to configured channel(s).
  - Watermark file (SOC_ALERT_STATE) tracks the last sent timestamp so each alert
    fires exactly once (matches the upsert-no-duplication philosophy in apply_rules.py).
  - This file is ADDITIVE: it does not modify apply_rules.py. Wire it in only after
    you review the channel formatting below.

USAGE (preview / test, nothing sent):
    python alerts.py --dry-run --severity 3
    python alerts.py --dry-run --severity 3 --since now-1h

USAGE (live):
    python alerts.py --severity 3

DEPS:
    pip install elasticsearch requests
"""
import argparse, json, os, sys, datetime

try:
    from elasticsearch import Elasticsearch
except ImportError:
    sys.exit("[!] pip install elasticsearch")

try:
    import requests
except ImportError:
    sys.exit("[!] pip install requests")

ES_HOST = os.environ.get("SOC_ES_HOST", "http://localhost:9200")
ES_USER = os.environ.get("SOC_ES_USER", "CHANGE_ME")
ES_PASS = os.environ.get("SOC_ES_PASS", "CHANGE_ME")
FINDINGS = os.environ.get("SOC_FINDINGS", "siem-findings")
STATE_FILE = os.environ.get("SOC_ALERT_STATE",
                            os.path.join(os.path.dirname(__file__), ".alert_last_run"))

# Channel credentials (all optional — configured channels are used)
TG_TOKEN = os.environ.get("SOC_TG_TOKEN", "")
TG_CHAT = os.environ.get("SOC_TG_CHAT_ID", "")
TEAMS_HOOK = os.environ.get("SOC_TEAMS_WEBHOOK", "")
SMTP = {k: os.environ.get(f"SOC_SMTP_{k}", "") for k in
        ("HOST", "PORT", "USER", "PASS", "FROM", "TO")}

SEV_LABEL = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}


def es_client():
    return Elasticsearch([ES_HOST], basic_auth=(ES_USER, ES_PASS),
                         request_timeout=30, verify_certs=False)


def since_watermark():
    """Return ISO/since from state file, or now-30m default."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return f.read().strip() or "now-30m"
        except Exception:
            return "now-30m"
    return "now-30m"


def save_watermark(ts):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        f.write(ts)


def fetch_new(es, since, sev_min, limit=50):
    body = {
        "size": limit,
        "_source": ["@timestamp", "rule_id", "rule_title", "client.ip", "severity",
                    "attack_class", "url.path", "http.response.status_code",
                    "user_agent.original", "false_positive_hint", "first_seen"],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"term": {"status": "open"}},
                    {"range": {"severity": {"gte": sev_min}}},
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    res = es.search(index=FINDINGS, body=body)
    return res["hits"]["hits"]


# --------------------------------------------------------------------------
# Formatters — review these before wiring them live
# --------------------------------------------------------------------------
def fmt_telegram(hit):
    s = hit["_source"]
    return (f"\U0001F6A8 SOC Alert [{SEV_LABEL.get(s.get('severity'),'?')}] {s.get('rule_title')}\n"
            f"IP: {s.get('client.ip')}\n"
            f"Class: {s.get('attack_class')} | Sev={s.get('severity')}\n"
            f"Path: {s.get('url.path')}\n"
            f"Status: {s.get('http.response.status_code')}\n"
            f"First seen: {s.get('first_seen')}\n"
            f"FP hint: {s.get('false_positive_hint') or '-'}")


def fmt_teams(hit):
    s = hit["_source"]
    txt = (f"[{SEV_LABEL.get(s.get('severity'),'?')}] {s.get('rule_title')} — "
           f"{s.get('client.ip')} {s.get('url.path')} (status {s.get('http.response.status_code')})")
    return {"@type": "MessageCard", "@context": "http://schema.org/extensions",
            "summary": txt, "title": f"SOC Alert {s.get('rule_id')}",
            "text": txt}


def fmt_email(hit):
    s = hit["_source"]
    return (f"SOC Alert [{SEV_LABEL.get(s.get('severity'),'?')}] {s.get('rule_title')}\n"
            f"Rule: {s.get('rule_id')}\nIP: {s.get('client.ip')}\n"
            f"Path: {s.get('url.path')}\nStatus: {s.get('http.response.status_code')}\n"
            f"Class: {s.get('attack_class')}\nFirst seen: {s.get('first_seen')}")


# --------------------------------------------------------------------------
# Senders
# --------------------------------------------------------------------------
def send_telegram(text):
    if not (TG_TOKEN and TG_CHAT):
        return False
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    r = requests.post(url, json={"chat_id": TG_CHAT, "text": text}, timeout=10)
    return r.status_code == 200


def send_teams(payload):
    if not TEAMS_HOOK:
        return False
    r = requests.post(TEAMS_HOOK, json=payload, timeout=10)
    return r.status_code in (200, 202)


def send_email(body):
    if not all([SMTP["HOST"], SMTP["TO"]]):
        return False
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "[SOC-ify] Security Alert"
    msg["From"] = SMTP["FROM"] or SMTP["USER"]
    msg["To"] = SMTP["TO"]
    with smtplib.SMTP(SMTP["HOST"], int(SMTP["PORT"] or 25), timeout=15) as srv:
        if SMTP["USER"] and SMTP["PASS"]:
            srv.starttls()
            srv.login(SMTP["USER"], SMTP["PASS"])
        srv.send_message(msg)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--severity", type=int, default=3, help="min severity (default 3=high)")
    ap.add_argument("--since", default=None, help="override watermark (now-1h, ISO)")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--dry-run", action="store_true", help="print alerts, send nothing")
    a = ap.parse_args()

    es = es_client()
    since = a.since or since_watermark()
    hits = fetch_new(es, since, a.severity, a.limit)
    print(f"[*] {len(hits)} new finding(s) severity>={a.severity} since {since}")

    sent = 0
    for h in hits:
        ts = h["_source"]["@timestamp"]
        if a.dry_run:
            print("---- (dry-run) ----")
            print(fmt_telegram(h))
            continue
        # try each configured channel
        ok = []
        if send_telegram(fmt_telegram(h)): ok.append("telegram")
        if send_teams(fmt_teams(h)):      ok.append("teams")
        if send_email(fmt_email(h)):      ok.append("email")
        if ok:
            sent += 1
            print(f"[+] sent to {','.join(ok)}: {h['_source']['rule_id']} {h['_source']['client.ip']}")
        else:
            print(f"[!] no channel configured for {h['_source']['rule_id']} {h['_source']['client.ip']}")

    if not a.dry_run:
        if hits:
            save_watermark(hits[0]["_source"]["@timestamp"])
        print(f"[*] done, {sent} sent")


if __name__ == "__main__":
    main()
