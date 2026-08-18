#!/usr/bin/env python3
"""
SOC-ify Rule Engine (basic-license compatible detector)
=======================================================
Queries nginx access logs from Elasticsearch, runs the 12 SIGMA-style detection
rules (see ../rules/detection-rules.yaml), and writes qualified hits into the
`siem-findings` index as candidate alerts ready for triage.

DESIGN (works on Basic license, no Watcher/Detection-Rules dependency):
  - Detection logic runs here in Python against ES search/adverse (ES clients
    are available on the Basic tier). No watcher, no SIEM license.
  - Rule thresholds + severity come from the YAML spec.
  - Findings are written to siem-findings with stable {rule_id, src_ip, window}
    keys so re-runs upsert (no alert duplication).

USAGE:
  python apply_rules.py --range now-15m --sweep-window 10m
  (run via cron/task scheduler every 5-10 minutes)

REQUIRES:
  pip install elasticsearch
"""
import argparse, hashlib, json, os, re, sys, datetime
from collections import defaultdict

try:
    from elasticsearch import Elasticsearch
except ImportError:
    sys.exit("[!] elasticsearch-py not installed. Run: pip install elasticsearch")

ES_HOST = os.environ.get("SOC_ES_HOST", "http://localhost:9200")
ES_USER = os.environ.get("SOC_ES_USER", "CHANGE_ME")
ES_PASS = os.environ.get("SOC_ES_PASS", "CHANGE_ME")
ES_INDEX = os.environ.get("SOC_INDEX", "nginx-access-*")
FINDINGS = os.environ.get("SOC_FINDINGS", "siem-findings")

# ----------------------------------------------------------------------------
# Rule engine config (mirrors detection-rules.yaml - keep in sync)
# ----------------------------------------------------------------------------
RULES = [
    # (id, title, severity(1-4), attack_class, reg-exs against path+args+ua, fp hint)
    {"id": "R-001", "title": "SQL Injection", "sev": 3, "cls": "sqli",
     "pat": r"(?i)(select\s+.+from\s+|union\s+select|\bselect\s+\*\s+from|sleep\s*\(|0x|information_schema|\bor\s+1=1|benchmark\s*\(|load_file|outfile)",
     "fp": "search apps may pass 'select'; check status + IP rep"},
    {"id": "R-002", "title": "XSS Attempt", "sev": 2, "cls": "xss",
     "pat": r"(?i)(<script|alert\s*\(|javascript\s*:|onerror\s*=|onload\s*=|prompt\s*\(|confirm\s*\(|document\.cookie|iframe\s*src)",
     "fp": "testing tools trigger; check UA"},
    {"id": "R-003", "title": "Path Traversal", "sev": 3, "cls": "path_traversal",
     "pat": r"(?i)(\.\./\.\./|\.\.\x5c\.\.|/etc/passwd|/etc/shadow|windows/system32|(\.\.%2f|%2e%2e%2f))",
     "fp": "always malicious"},
    {"id": "R-004", "title": "Command Injection", "sev": 4, "cls": "command_injection",
     "pat": r"(?i)((\||;|`|\$\()\s*(cat|id|whoami|ls|wget|curl|nc|bash|sh|python|perl|rm|uname)\b|/bin/sh|cmd\.exe|powershell)",
     "fp": "escalate if 4xx/5xx"},
    {"id": "R-005", "title": "Sensitive File Disclosure", "sev": 4, "cls": "info_disclosure",
     "pat": r"(?i)(/\.env|/\.git|/\.aws|/\.ssh|web\.config|\.bak\b|config\.php\b|phpinfo|/dump\.sql|/backup)",
     "fp": "real exposure if 200"},
    {"id": "R-006", "title": "SSRF", "sev": 3, "cls": "ssrf",
     "pat": r"(?i)(url=\s*https?://|proxy=|request=|dest=|target=|uri=\s*\d+\.\d+\.\d+\.\d+|file=\s*https?://|load=\s*https?://)",
     "fp": "apps fetch ext URLs; verify metadata target"},
    {"id": "R-007", "title": "Scanner UA", "sev": 1, "cls": "scanner",
     "pat": r"(?i)(sqlmap|nuclei|nikto|gobuster|dirbuster|acunetix|nessus|wpscan|zap|masscan|fuzz|hydra|libwww-perl|python-requests)",
     "fp": "recon noise; watch freq"},
    {"id": "R-008", "title": "Admin Panel Probe", "sev": 2, "cls": "admin_panel_scan",
     "pat": r"(?i)(/admin|/manager|/wp-admin|/console|/jenkins|/actuator|/webui/|/geoserver/web|/owa|/exchange|/webmail|/\.ssh|/phpmyadmin)",
     "fp": "some legit admin consoles"},
    {"id": "R-009", "title": "Auth Endpoint Scan", "sev": 2, "cls": "auth_scan",
     "pat": r"(?i)(/login|/signin|/auth|j_spring_security|/logon|/authenticate)",
     "fp": "intermittent=normal; spam=brute"},
]

FREQ_THRESHOLD = int(os.environ.get("SOC_FREQ_THRESHOLD", 30))   # R-011
PATH_DISTINCT_THRESHOLD = int(os.environ.get("SOC_PATH_DISTINCT", 15))
CHAIN_WINDOW = int(os.environ.get("SOC_CHAIN_WINDOW", 15))       # R-012 minutes
FIRE_INDEX = os.environ.get("SOC_FIRE_INDEX", "fire-ufw-*")      # R-013 firewall source
SSH_INDEX = os.environ.get("SOC_SSH_INDEX", "auth-*")             # R-014 SSH source
SSH_FAIL_THRESHOLD = int(os.environ.get("SOC_SSH_FAIL", 5))        # R-014 failures per IP

# MITRE ATT&CK mapping (mirrors detection-rules.yaml <mitre> block - keep in sync)
# rule_id -> (technique_id, technique_name, tactic)
MITRE = {
    "R-001": ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "R-002": ("T1189", "Drive-by Compromise", "initial-access"),
    "R-003": ("T1083", "File and Directory Discovery", "discovery"),
    "R-004": ("T1059", "Command and Scripting Interpreter", "execution"),
    "R-005": ("T1005", "Data from Local System", "collection"),
    "R-006": ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "R-007": ("T1595.001", "Active Scanning: Scanning IP Blocks", "reconnaissance"),
    "R-008": ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "R-009": ("T1110.001", "Brute Force: Password Guessing", "credential-access"),
    "R-010": ("T1595", "Active Scanning", "reconnaissance"),
    "R-011": ("T1595", "Active Scanning", "reconnaissance"),
    "R-012": ("T1090", "Multiple Techniques (chain)", "multiple-tactics"),
    "R-013": ("T1595", "Active Scanning (multi-layer recon)", "reconnaissance"),
    "R-014": ("T1110.001", "Brute Force: Password Guessing", "credential-access"),
    "R-015": ("T1078", "Valid Accounts", "persistence"),
}


def es_client():
    return Elasticsearch(
        [ES_HOST], basic_auth=(ES_USER, ES_PASS),
        request_timeout=30, verify_certs=False,
    )


def fetch(es, rng, size):
    """Return raw hits (docs) with needed fields, over the given range."""
    body = {
        "size": size,
        "_source": ["@timestamp", "client.ip", "url.path", "url.query", "http.request.method",
                    "http.response.status_code", "user_agent.original", "referer", "soc.attack_class"],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": rng}}},
                    {"exists": {"field": "url.path"}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    try:
        return es.search(index=ES_INDEX, body=body)["hits"]["hits"]
    except Exception as e:
        print(f"[!] search failed: {e}", file=sys.stderr)
        return []


def eval_rules(doc):
    """Return list of rule dicts matched by a single document."""
    s = doc["_source"]
    ts = s.get("@timestamp", "")
    ip = s.get("client", {}).get("ip", "") or s.get("client_ip", "")
    path = s.get("url", {}).get("path", "") or s.get("path", "")
    query = s.get("url", {}).get("query", "") or s.get("args", "")
    ua = (s.get("user_agent", {}) or {}).get("original", "") if isinstance(s.get("user_agent"), dict) else s.get("user_agent", "")
    status = s.get("http", {}).get("response", {}).get("status_code") or s.get("status_code")
    method = s.get("http", {}).get("request", {}).get("method") or s.get("method", "")
    haystack = f"{path} {query} {ua}".lower()
    hits = []
    for rule in RULES:
        if re.search(rule["pat"], haystack):
            hits.append(rule)
    return {
        "ts": ts, "ip": ip, "path": path, "query": query, "ua": ua,
        "status": status, "method": method, "hits": hits
    }


def make_finding_id(rule_id, ip, ts):
    return hashlib.sha256(f"{rule_id}|{ip}|{ts[:14]}".encode()).hexdigest()[:40]


def write_findings(es, findings):
    """Bulk upsert findings into siem-findings (doc id = finding_id)."""
    if not findings:
        return 0
    body = []
    now = datetime.datetime.utcnow().isoformat() + "Z"
    for f in findings:
        action = {"index": {"_index": FINDINGS, "_id": f["id"]}}
        mid, mname, mtac = MITRE.get(f["rule_id"], ("", "", ""))
        src = {
            "rule_id": f["rule_id"], "rule_title": f["title"],
            "client.ip": f["ip"], "severity": f["sev"], "confidence": f["conf"],
            "attack_class": f["cls"], "url.path": f["path"], "url.query": f["query"],
            "user_agent.original": f["ua"], "http.response.status_code": f["status"],
            "false_positive_hint": f["fp"], "status": "open",
            "mitre.id": mid, "mitre.technique": mname, "mitre.tactic": mtac,
            "@timestamp": now, "first_seen": f["ts"],
        }
        body.extend([action, src])
    try:
        res = es.bulk(body=body, refresh=True)
        return res["items"] and len([i for i in res["items"] if i.get("index", {}).get("status") == 201])
    except Exception as e:
        print(f"[!] bulk write failed: {e}", file=sys.stderr)
        return 0


def freq_detection(es, rng):
    """R-011: aggregate request count + distinct paths per source IP."""
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": rng}}}]}},
        "aggs": {
            "by_ip": {
                "terms": {"field": "client.ip", "size": 1000},
                "aggs": {
                    "paths": {"cardinality": {"field": "url.path"}},
                    "total": {"value_count": {"field": "@timestamp"}},
                    "last_ts": {"max": {"field": "@timestamp"}},
                    "top_path": {"top_hits": {"size": 1, "_source": ["url.path"]}},
                }
            }
        }
    }
    try:
        res = es.search(index=ES_INDEX, body=body)
    except Exception as e:
        print(f"[!] freq agg failed: {e}", file=sys.stderr)
        return []
    out = []
    for b in res["aggregations"]["by_ip"]["buckets"]:
        ip = b["key"]
        total = b["total"]["value"]
        distinct = b["paths"]["value"]
        reason = None
        if total >= FREQ_THRESHOLD:
            reason = f"request_count={total} >= {FREQ_THRESHOLD}"
        elif distinct >= PATH_DISTINCT_THRESHOLD:
            reason = f"distinct_paths={distinct} >= {PATH_DISTINCT_THRESHOLD}"
        if reason:
            out.append({
                "ip": ip, "total": total, "distinct": distinct, "reason": reason,
                "last_ts": b["last_ts"]["value_as_string"] if b["last_ts"].get("value_as_string") else ""
            })
    return out


def firewall_web_correlation(es, rng):
    """R-013: cross-source correlation - source IP blocked by UFW firewall AND
    also hitting nginx web in the same window => attacker reaching multiple layers."""
    def _terms(index, ip_field, query=None):
        q = {"size": 0, "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": rng}}}]}}}
        if query:
            q["query"]["bool"]["filter"].extend(query)
        q["aggs"] = {
            ip_field.replace('.', '_'):
            {"terms": {"field": ip_field, "size": 2000},
             "aggs": {"count": {"value_count": {"field": "@timestamp"}},
                      "last": {"max": {"field": "@timestamp"}}}}
        }
        try:
            res = es.search(index=index, body=q)
            key = ip_field.replace('.', '_')
            return {b["key"]: (b["count"]["value"], b["last"].get("value_as_string", ""))
                    for b in res["aggregations"][key]["buckets"]}
        except Exception as e:
            print(f"[!] {index} agg failed: {e}", file=sys.stderr)
            return {}

    # firewall: IPs that got UFW *blocked* events
    fw = _terms(FIRE_INDEX, "source.ip",
                [{"term": {"event.action": "block"}}])
    # web: IPs with any nginx window
    web = _terms(ES_INDEX, "client.ip")

    out = []
    for ip, (fw_count, _) in fw.items():
        n2 = web.get(ip)
        if n2:
            web_count, last_ts = n2
            # severity scales with how many web hits (deeper probing)
            sev = 3 if web_count >= 10 else 2
            out.append({
                "ip": ip, "fw_blocks": fw_count, "web_hits": web_count,
                "last_ts": last_ts or datetime.datetime.utcnow().isoformat() + "Z",
                "sev": sev,
            })
    return out


def ssh_brute_detection(es, rng):
    """R-014: SSH brute-force - source IP with >= threshold failed auth in window."""
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": rng}}},
            {"term": {"event.outcome": "failure"}},
            {"exists": {"field": "source.ip"}},
        ]}},
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip", "size": 500},
                "aggs": {
                    "fails": {"value_count": {"field": "@timestamp"}},
                    "last": {"max": {"field": "@timestamp"}},
                    "users": {"terms": {"field": "user.name", "size": 5}},
                }
            }
        }
    }
    try:
        res = es.search(index=SSH_INDEX, body=body)
    except Exception as e:
        print(f"[!] ssh brute agg failed: {e}", file=sys.stderr)
        return []
    out = []
    for b in res["aggregations"]["by_ip"]["buckets"]:
        fails = b["fails"]["value"]
        if fails >= SSH_FAIL_THRESHOLD:
            users = ",".join(sorted({u["key"] for u in b["users"]["buckets"]}) or "?")
            out.append({
                "ip": b["key"], "fails": fails, "users": users,
                "last_ts": b["last"].get("value_as_string", "") or datetime.datetime.utcnow().isoformat() + "Z"
            })
    return out


def _index_ips(es, index, ip_field, extra_filters=None, rng=None):
    """Helper: dict {ip: doc_count} for active IPs in an index over a range."""
    q = {"size": 0, "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": rng}}}]}}}
    if extra_filters:
        q["query"]["bool"]["filter"].extend(extra_filters)
    q["aggs"] = {"ip": {"terms": {"field": ip_field, "size": 1000},
                        "aggs": {"n": {"value_count": {"field": "@timestamp"}}}}}
    try:
        res = es.search(index=index, body=q)
        return {b["key"]: b["n"]["value"] for b in res["aggregations"]["ip"]["buckets"]}
    except Exception as e:
        print(f"[!] {index} ip agg failed: {e}", file=sys.stderr)
        return {}


def _ssh_live_ips(es, rng):
    """Active SSH IPs: any successful login OR repeated failures (recon/attack level)."""
    success = _index_ips(es, SSH_INDEX, "source.ip",
                         [{"term": {"event.outcome": "success"}}, {"exists": {"field": "source.ip"}}], rng)
    high_fail = _index_ips(es, SSH_INDEX, "source.ip",
                           [{"term": {"event.outcome": "failure"}}], rng)
    merged = dict(success)
    for ip, n in high_fail.items():
        if n >= SSH_FAIL_THRESHOLD:
            merged.setdefault(ip, n)
    return merged


def _web_ips(es, rng):
    return _index_ips(es, ES_INDEX, "client.ip", rng=rng)


def _fw_ips(es, rng):
    return _index_ips(es, FIRE_INDEX, "source.ip",
                      [{"term": {"event.action": "block"}}, {"exists": {"field": "source.ip"}}], rng)


def _allowed_ips():
    """Trusted admin/VPN source IPs that should not trigger severity-3 on SSH+web overlap."""
    return set(os.environ.get("SOC_ALLOWED_IPS", "").split(",")) - {""}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--range", default="now-15m", help="ES time range to scan")
    ap.add_argument("--count-only", action="store_true", help="print detections, don't write")
    a = ap.parse_args()

    es = es_client()
    if not es.ping():
        sys.exit(f"[!] cannot reach ES at {ES_HOST}")
    print(f"[*] ES OK: {ES_HOST}")
    print(f"[*] scanning {ES_INDEX} over {a.range}")

    docs = fetch(es, a.range, size=2000)
    print(f"[*] fetched {len(docs)} docs")

    findings = []
    rules_by_ip = defaultdict(int)
    for d in docs:
        r = eval_rules(d)
        for rule in r["hits"]:
            fid = make_finding_id(rule["id"], r["ip"], r["ts"])
            findings.append({
                "id": fid, "rule_id": rule["id"], "title": rule["title"],
                "sev": rule["sev"], "cls": rule["cls"], "ip": r["ip"],
                "path": r["path"], "query": r["query"], "ua": r["ua"],
                "status": r["status"], "fp": rule["fp"], "conf": 0.8, "ts": r["ts"]
            })
            rules_by_ip[(r["ip"], rule["id"])] += 1

    # R-011 frequency
    for fb in freq_detection(es, a.range):
        fid = make_finding_id("R-011", fb["ip"], fb["last_ts"][:14] if fb["last_ts"] else "")
        findings.append({
            "id": fid, "rule_id": "R-011",
            "title": "High Request Rate - Scanner/Brute-force",
            "sev": 2, "cls": "transverse_freq", "ip": fb["ip"],
            "path": fb["reason"], "query": "", "ua": "",
            "status": None, "fp": "legit CDN/crawl bursts", "conf": 0.7,
            "ts": fb["last_ts"] or datetime.datetime.utcnow().isoformat() + "Z"
        })

    # R-012 attack chain: source hit >=2 distinct high-severity rules
    sev_high_ips = defaultdict(set)
    for f in findings:
        if f["sev"] >= 3:
            sev_high_ips[f["ip"]].add(f["rule_id"])
    for ip, rules in sev_high_ips.items():
        if len(rules) >= 2:
            fid = make_finding_id("R-012", ip, datetime.datetime.utcnow().isoformat())
            findings.append({
                "id": fid, "rule_id": "R-012",
                "title": "Potential Attack Chain", "sev": 3, "cls": "attack_chain",
                "ip": ip, "path": "rules=" + ",".join(sorted(rules)), "query": "",
                "ua": "", "status": None, "fp": "multi-critical source", "conf": 0.75,
                "ts": datetime.datetime.utcnow().isoformat() + "Z"
            })

    # R-013 cross-source correlation: firewall + web
    for c in firewall_web_correlation(es, a.range):
        fid = make_finding_id("R-013", c["ip"], c["last_ts"][:14])
        findings.append({
            "id": fid, "rule_id": "R-013",
            "title": "Firewall+Web Correlation - Multi-Layer Attacker",
            "sev": c["sev"], "cls": "cross_source_correlation", "ip": c["ip"],
            "path": f"ufw_blocks={c['fw_blocks']}, web_hits={c['web_hits']}", "query": "",
            "ua": "", "status": None,
            "fp": "source blocked by UFW also reached nginx", "conf": 0.85,
            "ts": c["last_ts"]
        })

    # R-014 SSH brute-force
    for sb in ssh_brute_detection(es, a.range):
        fid = make_finding_id("R-014", sb["ip"], sb["last_ts"][:14])
        findings.append({
            "id": fid, "rule_id": "R-014",
            "title": "SSH Brute-Force - Repeated Failed Logins",
            "sev": 3, "cls": "ssh_bruteforce", "ip": sb["ip"],
            "path": f"ssh_failures={sb['fails']}, users={sb['users']}", "query": "",
            "ua": "", "status": None,
            "fp": "distributed or TOR-scan sources; verify legit VPN ranges", "conf": 0.9,
            "ts": sb["last_ts"]
        })

    # R-015 SSH cross-source correlation: IP active in SSH (success or many failures)
    #     that also touched web or firewall in the window => host-layer + network attacker.
    ssh_live = _ssh_live_ips(es, a.range)
    web_ips = _web_ips(es, a.range)
    fw_ips = _fw_ips(es, a.range)
    for ip in ssh_live:
        hit = None; n_web = 0
        if ip in web_ips:
            n_web = web_ips[ip]
        if ip in fw_ips:
            hit = f"ssh_active + fw_blocks"
        if (ip in fw_ips) or (ip in web_ips):
            fid = make_finding_id("R-015", ip, datetime.datetime.utcnow().isoformat())
            sev = 3 if (ip not in _allowed_ips()) else 1
            findings.append({
                "id": fid, "rule_id": "R-015",
                "title": "SSH Cross-Source Correlation - Host+Network Attacker",
                "sev": sev, "cls": "ssh_cross_source", "ip": ip,
                "path": f"web_hits={n_web}, fw_hit={ip in fw_ips}", "query": "",
                "ua": "", "status": None,
                "fp": "admin/VPN IP may legitimately hit web+ssh", "conf": 0.7,
                "ts": datetime.datetime.utcnow().isoformat() + "Z"
            })

    # dedupe by id (keep max severity)
    dedup = {}
    for f in findings:
        key = f["id"]
        if key not in dedup or f["sev"] > dedup[key]["sev"]:
            dedup[key] = f
    final = list(dedup.values())

    # summarize
    by_rule = defaultdict(int)
    for f in final:
        by_rule[f["rule_id"]] += 1
    print("[*] detections by rule:")
    for rid in sorted(by_rule):
        print(f"     {rid}: {by_rule[rid]}")
    print(f"[*] total unique findings: {len(final)}")

    if a.count_only:
        return
    written = write_findings(es, final)
    print(f"[*] written {written} findings to {FINDINGS}")


if __name__ == "__main__":
    main()
