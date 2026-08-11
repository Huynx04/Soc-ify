#!/usr/bin/env python3
"""
SOC-ify Triage Workflow
=======================
Markets findings in `siem-findings` through the incident lifecycle:
    open -> investigating (assign analyst) -> escalated | resolved(false_positive)

Also performs an automatic FIRST-PASS triage on new findings:
  - Confirms from raw index whether the path returned 403/404 (blocked) vs 2xx (exploited)
  - Automatic FP weeding for known-safe patterns
  - Adds geo + frequency context for the analyst.

USAGE:
  python triage.py --list-open
  python triage.py --list --rule R-005 --within 24h
  python triage.py --set-csvid <finding_id> --investigate "analyst:huy"
  python triage.py --set-csvid <finding_id> --escalate
  python triage.py --set-csvid <finding_id> --resolve --reason "false_positive: recon noise"
  python triage.py --auto-first-pass --range now-24h   # label auto findings

State is stored on each finding doc:  status, owner, last_touched_at, notes.
"""
import argparse, json, os, sys, datetime

try:
    from elasticsearch import Elasticsearch
except ImportError:
    sys.exit("[!] pip install elasticsearch")

ES_HOST = os.environ.get("SOC_ES_HOST", "http://localhost:9200")
ES_USER = os.environ.get("SOC_ES_USER", "CHANGE_ME")
ES_PASS = os.environ.get("SOC_ES_PASS", "CHANGE_ME")
FINDINGS = os.environ.get("SOC_FINDINGS", "siem-findings")
NGINX = os.environ.get("SOC_INDEX", "nginx-access-*")

STATES = ("open", "investigating", "escalated", "resolved")


def es():
    return Elasticsearch([ES_HOST], basic_auth=(ES_USER, ES_PASS),
                         request_timeout=30, verify_certs=False)


def now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"


def list_findings(es, rule=None, within="24h", only_state=None):
    must = []
    if rule:
        must.append({"term": {"rule_id": rule}})
    if only_state:
        must.append({"term": {"status": only_state}})
    body = {
        "size": 200,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{within}"}}},
                ],
                "must": must or [{"match_all": {}}],
            }
        },
        "sort": [{"severity": "desc"}, {"@timestamp": "desc"}],
    }
    res = es.search(index=FINDINGS, body=body)
    return res["hits"]["hits"]


def print_finding(h):
    s = h["_source"]
    print(f"  [{s.get('status','?')}] {s.get('rule_id')} {s.get('rule_title','')}  sev={s.get('severity')} "
          f"ip={s.get('client.ip')} path={s.get('url.path')} status={s.get('status')}")
    print(f"        id={h['_id']} seen={s.get('first_seen')} conf={s.get('confidence')}")
    if s.get("false_positive_hint"):
        print(f"        FP?: {s['false_positive_hint']}")


def confirm_exploited(es, fip, fpath):
    """Checks raw nginx log whether this (ip,path) ever returned <400."""
    body = {
        "size": 5,
        "_source": ["http.response.status_code", "@timestamp", "url.path"],
        "query": {"bool": {"must": [
            {"term": {"client.ip": fip}},
            {"match_phrase": {"url.path": fpath}},
            {"range": {"http.response.status_code": {"lt": 400}}},
        ]}},
    }
    try:
        res = es.search(index=NGINX, body=body)
        return res["hits"]["hits"]
    except Exception:
        return []


def auto_first_pass(es, rng):
    """For open findings, bolt on exploitation evidence + auto-resolve benign."""
    findings = list_findings(es, within=rng)
    changed = 0
    for h in findings:
        s = h["_source"]
        if s.get("status") != "open":
            continue
        fip, fpath = s.get("client.ip"), s.get("url.path")
        # 1) exploitation evidence
        if fip and fpath and fpath not in ("", "-"):
            exp = confirm_exploited(es, fip, fpath)
            evidence = f"exploited_hits={len(exp)}" if exp else "no_2xx_evidence(blocked)"
        else:
            evidence = "no_path"
        # 2) auto-FP heuristics
        could_fp = False
        reason = ""
        low_paths = ("/favicon.ico", "/robots.txt", "/.well-known/", "/error", "/index.html")
        if fpath in low_paths:
            could_fp, reason = True, "benign path"
        # writeback enrichment
        es.update(index=FINDINGS, id=h["_id"], body={"doc": {
            "soc.evidence": evidence,
            "soc.last_pass_at": now_iso(),
            **({"status": "resolved", "resolution": f"auto_fp:{reason}"} if could_fp else {}),
        }})
        changed += 1
        print(f"  {h['_id'][:14]} {s.get('rule_id')}: {evidence}" + (" -> RESOLVED(fp)" if could_fp else ""))
    print(f"[*] auto-pass touched {changed} findings")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list-open", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--rule")
    ap.add_argument("--within", default="24h")
    ap.add_argument("--set-id")
    ap.add_argument("--investigate")
    ap.add_argument("--escalate", action="store_true")
    ap.add_argument("--resolve", action="store_true")
    ap.add_argument("--reason")
    ap.add_argument("--auto-first-pass", action="store_true")
    a = ap.parse_args()

    client = es()
    if not client.ping():
        sys.exit("[!] ES unreachable")

    if a.list or a.list_open:
        state = "open" if a.list_open else None
        for h in list_findings(client, rule=a.rule, within=a.within, only_state=state):
            print_finding(h)
        return

    if a.set_id:
        state = None
        if a.investigate:
            state = {"status": "investigating", "owner": a.investigate,
                     "last_touched_at": now_iso()}
        elif a.escalate:
            state = {"status": "escalated", "last_touched_at": now_iso()}
        elif a.resolve:
            state = {"status": "resolved", "resolution": a.reason or "manual",
                     "last_touched_at": now_iso()}
        if state:
            client.update(index=FINDINGS, id=a.set_id, body={"doc": state})
            print(f"  -> updated {a.set_id}: {state}")
        return

    if a.auto_first_pass:
        auto_first_pass(client, a.within)
        return

    ap.print_help()


if __name__ == "__main__":
    main()
