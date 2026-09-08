#!/usr/bin/env python3
"""
Build the SOC-ify security dashboard (SOC_OVERVIEW) for Kibana 8.12.

v2 — "SOC visual polish": SOC-standard severity colors, readable legends +
numeric labels, per-panel descriptions, clearer 3-row layout. Uses ONLY
pie + tagcloud (the two types confirmed to render via the saved-objects API
in this Kibana 8.12 install).

Improvement over v1:
  - Adds a `severity_label` runtime field to the siem-findings data view
    (maps 1-4 -> low/medium/high/critical) so the severity panel shows clean
    named slices instead of mixed numeric+string buckets.
  - Severity pie: stable `_key`-desc ordering + SOC color palette aligned to
    that order (critical=red, high=orange, medium=yellow, low=green).
  - All pies: legend on, slice labels showing count, panel descriptions set.
  - Cleaner 3-row layout: severity (wide) / rule+class / SSH+UFW.

Run:  source /c/Users/ADMIN/soc-ify-credentials-backup.env
      python build_soc_pie_dashboard.py
Requires Kibana reachable at localhost:8081.
"""
import json, os, base64, urllib.request, urllib.error

KIBANA = os.environ.get("SOC_KIBANA", "http://localhost:8081")
ES_USER = os.environ.get("SOC_ES_USER", "CHANGE_ME")
ES_PASS = os.environ.get("SOC_ES_PASS", "CHANGE_ME")

# Existing data-view IDs (created earlier; verified present in this Kibana).
DV_FINDINGS = "b4353c61-414b-4f5d-b45c-71cf4524e463"  # siem-findings
DV_AUTH     = "53a42750-8b84-4594-bff3-93fd0e6e886a"  # auth-*
DV_FIRE     = "d8005d1e-40f2-492e-b178-a6fae4d749f6"  # fire-ufw-*

# SOC severity palette in `_key` DESC alphabetic order
# (_key desc => buckets: other, medium, low, high, critical)
SOC_COLORS = ["#8a8d91", "#F5A700", "#54B399", "#F58518", "#C23B22"]


def api(method, path, data=None):
    url = KIBANA + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("kbn-xsrf", "true")
    req.add_header("Content-Type", "application/json")
    token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {"acknowledged": True})
    except urllib.error.HTTPError as e:
        b = e.read().decode()
        return e.code, (json.loads(b) if b else {"error": str(e)})


def ensure_severity_runtime_field():
    """Re-create `severity_label` runtime field with a CORRECT if-else script.

    Earlier run stored a broken `switch`-based script that fails Painless
    compile, which broke the severity panel render. Delete-then-create so the
    good script sticks (update via PUT unreliable in 8.12).
    """
    script = (
        "if (doc.containsKey('severity')) {"
        "def s = String.valueOf(doc['severity'].value);"
        "def label = 'other';"
        "if ('4'.equals(s)) { label = 'critical'; }"
        "else if ('3'.equals(s)) { label = 'high'; }"
        "else if ('2'.equals(s)) { label = 'medium'; }"
        "else if ('1'.equals(s)) { label = 'low'; }"
        "else { label = s; }"
        "emit(label);"
        "}"
    )
    # 1) drop any stale field so the good script replaces the broken one
    cd, _ = api("DELETE", f"/api/data_views/data_view/{DV_FINDINGS}/runtime_field/severity_label")
    print(f"   delete stale severity_label: HTTP {cd}")

    # 2) create it fresh with the correct script
    code, resp = api("POST", f"/api/data_views/data_view/{DV_FINDINGS}/runtime_field", {
        "name": "severity_label", "runtimeField": {
            "type": "keyword", "script": {"source": script}}})
    print(f"   create severity_label: HTTP {code}")
    if code not in (200, 400):
        print("   ", json.dumps(resp, default=str)[:500])

    # 3) verify the stored script no longer contains the broken switch form
    okc, okr = api("GET", f"/api/data_views/data_view/{DV_FINDINGS}")
    rf = okr.get("data_view", {}).get("runtimeFieldMap", {}).get("severity_label", {})
    stored = rf.get("script", {}).get("source", "")
    if "switch(" in stored:
        print("   verify: STILL BROKEN (switch present)")
        return False
    if "severity_label" not in okr.get("data_view", {}).get("runtimeFieldMap", {}):
        print("   verify: MISSING")
        return False
    print("   verify: severity_label present with correct if-else script: OK")
    return True


def make_viz(oid, title, dv_id, agg_field, viz_type, desc="", extra_filter=None,
             slice_colors=None, sort_key=False, agg_size=12):
    """Build a visualization object: pie (donut) or tagcloud, one terms agg."""
    seg_params = {
        "field": agg_field, "orderBy": "2", "order": "desc", "size": agg_size,
        "otherBucket": False, "otherBucketLabel": "Other",
        "missingBucket": False, "missingBucketLabel": "Missing",
    }
    if sort_key:
        seg_params["orderBy"] = "_key"
    seg_agg = {"id": "1", "enabled": True, "type": "terms", "schema": "segment",
               "params": seg_params}
    count = {"id": "2", "enabled": True, "type": "count", "schema": "metric",
             "params": {"customLabel": ""}}

    if viz_type == "pie":
        vis_state = {
            "title": title, "type": "pie",
            "params": {
                "type": "pie",
                "addTooltip": True, "addLegend": True,
                "legendPosition": "right",
                "isDonut": True,
                "labels": {"show": True, "values": True, "lastLevel": True, "truncate": 100},
                "colorSchema": "Default",
                "sliceColors": slice_colors or [],
                "dimensions": False,
            },
            "aggs": [count, seg_agg],
            "listeners": {},
        }
    else:  # tagcloud
        vis_state = {
            "title": title, "type": "tagcloud",
            "params": {
                "type": "tagcloud",
                "scale": "linear",
                "orientation": "single",
                "minFontSize": 16, "maxFontSize": 80,
                "showLabel": True,
            },
            "aggs": [seg_agg, count],
            "listeners": {},
        }

    # fill-empty to ensure labels show percentages
    if viz_type == "pie":
        vis_state["params"].setdefault("fillEmptySlices", True)

    search_source = {"query": {"query": "", "language": "kuery"},
                     "filter": extra_filter or [],
                     "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}
    return {
        "type": "visualization", "id": oid,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "description": desc,
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search_source)},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": dv_id}
        ],
    }


def build():
    ensure_severity_runtime_field()

    # Login-failure filter for the SSH brute-force tagcloud
    login_fail_filter = {
        "meta": {"alias": "SSH login failures", "disabled": False, "negate": False,
                 "index": DV_AUTH, "key": "event.action", "value": "login_failure",
                 "type": "phrase", "field": "event.action"},
        "query": {"match_phrase": {"event.action": "login_failure"}},
        "$state": {"store": "appState"},
    }

    objects = [
        # severity: 4 named slices, SOC palette, stable key-desc ordering
        make_viz("soc-pie-severity", "Findings by Severity", DV_FINDINGS,
                 "severity_label", "pie",
                 desc="Mức độ nghiêm trọng của findings (critical=đỏ, high=cam, medium=vàng, low=xanh).",
                 slice_colors=SOC_COLORS, sort_key=True, agg_size=6),
        make_viz("soc-pie-rule", "Findings by Rule", DV_FINDINGS,
                 "rule_id.keyword", "pie",
                 desc="Số findings theo từng detection rule (R-001...R-015)."),
        make_viz("soc-pie-class", "Findings by Attack Class", DV_FINDINGS,
                 "attack_class.keyword", "pie",
                 desc="Loại tấn công được phát hiện (SQLi, XSS, brute-force SSH...)."),
        make_viz("soc-pie-tactic", "Findings by MITRE Tactic", DV_FINDINGS,
                 "mitre.tactic.keyword", "pie",
                 desc="Giai đoạn tấn công theo MITRE ATT&CK (initial-access, credential-access, collection...)."),
        make_viz("soc-pie-status", "Findings by Status", DV_FINDINGS,
                 "status.keyword", "pie",
                 desc="Trạng thái findings: open (chưa xử lý) / closed (đã đóng)."),
        make_viz("soc-tag-ssh", "SSH Brute-Force Top IPs", DV_AUTH,
                 "source.ip", "tagcloud",
                 desc="IP nguồn đang cố SSH login thất bại nhiều nhất (event.action=login_failure).",
                 extra_filter=[login_fail_filter]),
        make_viz("soc-tag-ufw", "UFW Blocked Top IPs", DV_FIRE,
                 "source.ip", "tagcloud",
                 desc="IP nguồn bị UFW firewall chặn nhiều nhất."),
    ]

    # --- Dashboard layout: 4 clear rows ---
    panels = [
        # Row 1: severity (full width, prominent)
        {"panelRefName": "panel_0", "gridData": {"x": 0, "y": 0, "w": 24, "h": 16, "i": "panel_0"},
         "version": "8.12.0", "panelIndex": "1", "embeddableConfig": {}},
        # Row 2: rule + attack class
        {"panelRefName": "panel_1", "gridData": {"x": 0, "y": 16, "w": 12, "h": 16, "i": "panel_1"},
         "version": "8.12.0", "panelIndex": "2", "embeddableConfig": {}},
        {"panelRefName": "panel_2", "gridData": {"x": 12, "y": 16, "w": 12, "h": 16, "i": "panel_2"},
         "version": "8.12.0", "panelIndex": "3", "embeddableConfig": {}},
        # Row 3: tactic + status
        {"panelRefName": "panel_3", "gridData": {"x": 0, "y": 32, "w": 12, "h": 16, "i": "panel_3"},
         "version": "8.12.0", "panelIndex": "4", "embeddableConfig": {}},
        {"panelRefName": "panel_4", "gridData": {"x": 12, "y": 32, "w": 12, "h": 16, "i": "panel_4"},
         "version": "8.12.0", "panelIndex": "5", "embeddableConfig": {}},
        # Row 4: SSH + UFW
        {"panelRefName": "panel_5", "gridData": {"x": 0, "y": 48, "w": 12, "h": 16, "i": "panel_5"},
         "version": "8.12.0", "panelIndex": "6", "embeddableConfig": {}},
        {"panelRefName": "panel_6", "gridData": {"x": 12, "y": 48, "w": 12, "h": 16, "i": "panel_6"},
         "version": "8.12.0", "panelIndex": "7", "embeddableConfig": {}},
    ]
    dash_attributes = {
        "title": "SOC_OVERVIEW",
        "description": "SOC-ify mini-SOC: mức độ nghiêm trọng, findings theo rule/attack-class, SSH brute-force & UFW blocks.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False,
                                   "syncColors": False, "syncTooltips": False}),
        "timeRestore": True,
        "timeFrom": "now-24h", "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 5000},
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"filter": [], "query": {"language": "kuery", "query": ""}})},
    }
    dash = {
        "type": "dashboard", "id": "soc-overview-dashboard",
        "attributes": dash_attributes,
        "references": [
            {"name": "panel_0", "type": "visualization", "id": "soc-pie-severity"},
            {"name": "panel_1", "type": "visualization", "id": "soc-pie-rule"},
            {"name": "panel_2", "type": "visualization", "id": "soc-pie-class"},
            {"name": "panel_3", "type": "visualization", "id": "soc-pie-tactic"},
            {"name": "panel_4", "type": "visualization", "id": "soc-pie-status"},
            {"name": "panel_5", "type": "visualization", "id": "soc-tag-ssh"},
            {"name": "panel_6", "type": "visualization", "id": "soc-tag-ufw"},
        ],
    }
    objects.append(dash)

    # --- clean stale ---
    for oid in ["soc-pie-rule", "soc-pie-class", "soc-pie-severity",
                "soc-pie-tactic", "soc-pie-status",
                "soc-tag-ssh", "soc-tag-ufw", "soc-overview-dashboard"]:
        for otype in ["visualization", "dashboard"]:
            api("DELETE", f"/api/saved_objects/{otype}/{oid}")

    code, resp = api("POST", "/api/saved_objects/_bulk_create", objects)
    print(f"bulk_create status: {code}")
    for o in resp.get("saved_objects", []):
        err = o.get("error")
        print(f"  [{o['type']}] {o['id']}: {'OK' if not err else err.get('message', '')}")
    if code != 200:
        print(json.dumps(resp, indent=2, default=str)[:1500])


if __name__ == "__main__":
    build()
    print("Open: http://localhost:8081/app/dashboards#/view/soc-overview-dashboard (Ctrl+F5 to refresh)")
