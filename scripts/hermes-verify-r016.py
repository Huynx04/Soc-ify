#!/usr/bin/env python3
"""hermes-verify-r016.py - verification gate for the R-016 file-integrity rule.
Compiles apply_rules.py, greps required symbols, validates detection-rules.yaml,
and live-queries ES to confirm the winlogbeat index exists and the 4663 query shape
runs without error (expected 0 hits until the File System audit is enabled).
Run with:  E:\\anaconda\\python.exe hermes-verify-r016.py
"""
import json, os, re, sys, py_compile, yaml

BASE = r"C:\Users\ADMIN\soc-ify"
APP = os.path.join(BASE, "scripts", "apply_rules.py")
YAML = os.path.join(BASE, "rules", "detection-rules.yaml")
fails = []

def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        fails.append(msg)

# 1. compiles
try:
    py_compile.compile(APP, doraise=True)
    check(True, "apply_rules.py compiles")
except Exception as e:
    check(False, f"apply_rules.py compiles: {e}")

src = open(APP, encoding="utf-8").read()

# 2. required symbols in apply_rules.py
for sym in ["def integrity_detection", "_is_mutation", "MUTATE_MASK_BITS", "WIN_INDEX",
            "INTEGRITY_TRUSTED_PROCS", "DEFAULT_INTEGRITY_PATHS", 'cls": "file_integrity"',
            "winlog.event_id"]:
    check(sym in src, f"apply_rules.py contains {sym}")
check(src.count('"R-016"') >= 2, "R-016 referenced (MITRE dict + wiring)")
check('"R-016": ("T1070", "Indicator Removal on Host", "defense-evasion")' in src,
      "MITRE R-016 -> T1070 present")

# 3. detection-rules.yaml parses and has R-016
try:
    doc = yaml.safe_load(open(YAML, encoding="utf-8"))
    rids = [r["id"] for r in doc["rules"]]
    check("R-016" in rids, f"detection-rules.yaml contains R-016 (18 rules total: {len(rids)})")
    check("R-017" in rids, "detection-rules.yaml contains R-017 (Sysmon FileCreate)")
    check("R-018" in rids, "detection-rules.yaml contains R-018 (Sysmon ProcessCreate)")
    check(len(rids) >= 18, f"detection-rules.yaml rule count >= 18 ({len(rids)})")
except Exception as e:
    check(False, f"detection-rules.yaml parses: {e}")

# 4. live ES checks
es_host = os.environ.get("SOC_ES_HOST", "http://localhost:9200")
es_user = os.environ.get("SOC_ES_USER", "CHANGE_ME")
es_pass = os.environ.get("SOC_ES_PASS", "CHANGE_ME")
try:
    from elasticsearch import Elasticsearch
    es = Elasticsearch([es_host], basic_auth=(es_user, es_pass), request_timeout=30, verify_certs=False)
    check(es.ping(), f"ES reachable at {es_host}")

    # winlogbeat index exists (use indices.exists; get_alias misses .ds-* data-stream backings)
    check(es.indices.exists(index="winlogbeat-*"), "winlogbeat-* indices exist")

    # the exact 4663 query shape the rule runs (should be 0 hits / no error)
    body = {"size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": "now-1d"}}},
                {"term": {"winlog.event_id": "4663"}}]}}}
    res = es.search(index="winlogbeat-*", body=body)
    n = res["hits"]["total"]["value"]
    print(f"      (4663 docs last 1d = {n} - >0 confirms the File System audit is active)")
    check(n >= 0, "4663 query runs without error")
except Exception as e:
    check(False, f"live ES checks: {e}")

print("\nOVERALL: " + ("ALL PASS" if not fails else f"{len(fails)} FAILED"))
sys.exit(1 if fails else 0)
