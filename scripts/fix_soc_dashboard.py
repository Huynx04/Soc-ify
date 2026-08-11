#!/usr/bin/env python3
"""
Fix the SOC SIEM dashboard (siem-attack-dashboard):
1. Recreate the missing index-pattern 9f6e999b-... -> nginx-access-* logs
2. Repoint visualization references to the right index patterns
   (nginx panels -> nginx index; incidents/classification/timeline -> siem-findings)
3. Populate the dashboard panelsJSON layout with the 12 panels.

Run: python fix_soc_dashboard.py
"""
import json, os, sys, requests

KIBANA = os.environ.get("SOC_KIBANA", "http://localhost:8081")
U = os.environ.get("SOC_ES_USER", "CHANGE_ME")
P = os.environ.get("SOC_ES_PASS", "CHANGE_ME")
H = {"kbn-xsrf": "true"}

NGINX_IP = "9f6e999b-0eb5-42fe-bae3-f6547da33501"   # panels that read nginx logs
FIND_IP  = "b4353c61-414b-4f5d-b45c-71cf4524e463"   # siem-findings (exists)

def get(path):
    r = requests.get(f"{KIBANA}{path}", auth=(U, P), headers=H, timeout=30)
    r.raise_for_status()
    return r.json()

def post(path, payload=None):
    r = requests.post(f"{KIBANA}{path}", auth=(U, P), headers=H, json=payload, timeout=30)
    print(f"  POST {path} -> {r.status_code}")
    return r.json()

def put(path, payload):
    r = requests.put(f"{KIBANA}{path}", auth=(U, P), headers=H, json=payload, timeout=30)
    print(f"  PUT {path} -> {r.status_code}")
    return r.json()

# ---------- 1) Create the missing nginx index-pattern ----------
# Build an index-pattern object with a modest set of fields field types.
nginx_fields = {
    "client.ip": "ip", "url.path": "text", "url.original": "text",
    "http.request.method": "string", "http.response.status_code": "integer",
    "user_agent.original": "text", "@timestamp": "date", "message": "text",
    "http.request.referrer": "text", "body_bytes_sent": "integer",
}
def field_objects(ft):
    out=[]
    for name,typ in ft.items():
        out.append({
            "name": name,
            "type": typ,
            "count": 0, "scripted": False, "indexed": True,
            "analyzed": (typ in ("text",)), "doc_values": True,
            "searchable": True, "aggregatable": typ != "text",
        })
    return json.dumps(out)

attrs = {
    "title": ".ds-nginx-access-*",
    "timeFieldName": "@timestamp",
    "fields": field_objects(nginx_fields),
    "fieldAttrs": "{}",
    "sourceFilters": "[]",
    "runtimeFieldMap": "{}",
    "name": ".ds-nginx-access-*",
    "allowNoIndex": "true",
}
print("==> creating index-pattern", NGINX_IP)
put(f"/api/saved_objects/index-pattern/{NGINX_IP}", {
    "attributes": attrs,
    "references": [],
})

# ---------- 2) Repoint visualization references ----------
# nginx-log panels should point to NGINX_IP; findings panels to FIND_IP.
nginx_viz = ["siem-topips", "siem-toppaths", "siem-statuscode", "siem-httpmethods",
             "siem-card2", "siem-card3", "siem-card4"]
findings_viz = ["siem-timeline", "siem-classification", "siem-card1", "siem-datatable"]

def viz_attr(att, ref_index_id):
    # ensure the searchSourceJSON references the target index + keep visState
    ss = att.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON", "{}")
    try:
        ssj = json.loads(ss)
    except Exception:
        ssj = {}
    ssj["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
    ssj["_index"] = ref_index_id
    att["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(ssj)
    return att

print("\n==> repointing visualizations")
for vid in findings_viz:
    o = get(f"/api/saved_objects/visualization/{vid}")
    att = viz_attr(o["attributes"], FIND_IP)
    refs = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": FIND_IP}]
    put(f"/api/saved_objects/visualization/{vid}",
        {"attributes": att, "references": refs})
    print("  ->", vid, "-> findings")
for vid in nginx_viz:
    o = get(f"/api/saved_objects/visualization/{vid}")
    att = viz_attr(o["attributes"], NGINX_IP)
    refs = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": NGINX_IP}]
    put(f"/api/saved_objects/visualization/{vid}",
        {"attributes": att, "references": refs})
    print("  ->", vid, "-> nginx")

print("\n==> Done. Dashboard / panelsJSON layout populated next via separate script.")
