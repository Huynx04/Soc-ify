#!/usr/bin/env python3
"""
Generate a Kibana 8.12 NDJSON export for the SOC_OVERVIEW dashboard +
data views + a few aggregations visualizations, then import it via the
Kibana Saved Objects Import API.

Run: python build_dashboard.py
Requires Kibana reachable at localhost:8081.
"""
import json, os, sys, time, urllib.request, urllib.parse

KIBANA = os.environ.get("SOC_KIBANA", "http://localhost:8081")
ES_USER = os.environ.get("SOC_ES_USER", "CHANGE_ME")
ES_PASS = os.environ.get("SOC_ES_PASS", "CHANGE_ME")
OUT = os.path.join(os.path.dirname(__file__), "..", "dashboards", "soc_overview.ndjson")
SIZE = 8   # panel grid size

def obj(_id, _type, attributes, references=None, migration=None, cver=None):
    return {
        "id": _id,
        "type": _type,
        "references": references or [],
        "attributes": attributes,
        "coreMigrationVersion": "8.12.0",
        "typeMigrationVersion": migration or "8.3.0",
        "managed": False,
    }

# ---------------- Data views ----------------
def dataview(_id, title):
    attrs = {
        "name": title,
        "title": title,
        "timeFieldName": "@timestamp",
        "fields": "[]",
        "fieldAttrs": "{}",
        "allowNoIndex": "true",
        "sourceFilters": "[]",
        "runtimeFieldMap": "{}",
    }
    return obj(_id, "index-pattern", attrs)

dv_findings = dataview("soc-findings-view", "siem-findings")
dv_nginx = dataview("soc-nginx-view", "nginx-access-*")

# ---------------- Aggregation visualizations ----------------
def vis(id_, title, dv_id, agg_type):
    """Build a simple aggregation (metric / vertical_bar / table) visState."""
    dc_rule = {
        "id": "1", "enabled": True,
        "type": "terms",
        "schema": "segment",
        "params": {"field": "rule_id.keyword", "orderBy": "2", "order": "desc",
                   "size": 10, "otherBucket": False, "otherBucketLabel": "Other",
                   "missingBucket": False, "missingBucketLabel": "Missing"},
        "aggConfigParams": {
            "field": "rule_id.keyword", "orderBy": "2", "order": "desc", "size": 10,
            "otherBucket": False, "otherBucketLabel": "Other",
            "missingBucket": False, "missingBucketLabel": "Missing",
        },
    }
    dc_class = {
        "id": "1", "enabled": True,
        "type": "terms",
        "schema": "segment",
        "params": {"field": "attack_class.keyword", "orderBy": "2", "order": "desc",
                   "size": 10, "otherBucket": False},
        "aggConfigParams": {
            "field": "attack_class.keyword", "orderBy": "2", "order": "desc", "size": 10,
            "otherBucket": False, "otherBucketLabel": "Other",
            "missingBucket": False, "missingBucketLabel": "Missing",
        },
    }
    count = {
        "id": "2", "enabled": True,
        "type": "count", "schema": "metric",
        "params": {"customLabel": ""},
        "aggConfigParams": {},
    }
    vis_state = {
        "title": title,
        "type": agg_type,
        "params": {
            "type": agg_type,
            "addTooltip": True, "addLegend": True, "addTimeMarker": False,
            "categoryAxes": [{"id": "CatAxis-1", "labels": {"show": True, "rotate": 0},
                              "scale": {"type": "linear"}, "type": "category", "position": "bottom"}],
            "valueAxes": [{"id": "ValueAxis-1", "labels": {"show": True},
                           "scale": {"type": "linear"}, "type": "value", "position": "left"}],
            "grid": {"categoryLines": True, "valueLines": True},
            "labels": {"show": False},
            "maxCols": 1,
        },
        "aggs": [count, dc_rule if "Rule" in title else dc_class],
        "listeners": {},
    }
    return obj(id_, "visualization", {
        "title": title,
        "visState": json.dumps(vis_state),
        "description": "",
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "query": {"query": "", "language": "kuery"},
            "filter": [], "fields": [{"field": "rule_id"}],
        })},
        "uiStateJSON": "{}",
        "version": 1,
    }, references=[{
        "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "type": "index-pattern", "id": dv_id,
    }])

vis_rule = vis("soc-vis-rule", "Findings by Rule", dv_findings, "vertical_bar")
vis_class = vis("soc-vis-class", "Findings by Attack Class", dv_findings, "vertical_bar")

# simple metric count of findings
vis_metric_state = {
    "title": "Total Findings", "type": "metric",
    "params": {"type": "metric", "metricPosition": "top", "autoScaleMetric": True},
    "aggs": [count := {"id": "2", "enabled": True, "type": "count", "schema": "metric",
                       "params": {"customLabel": "Findings"}, "aggConfigParams": {}}],
}
vis_metric = obj("soc-vis-metric", "visualization", {
    "title": "Total Findings",
    "visState": json.dumps(vis_metric_state),
    "description": "",
    "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "query": {"query": "", "language": "kuery"}, "filter": [{"phase": 1}]})},
    "uiStateJSON": "{}", "version": 1,
}, references=[{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern", "id": dv_findings}])

# ---------------- Dashboard ----------------
panels = [
    {"id": "soc-vis-metric", "x": 0, "y": 0, "w": 24, "h": 8, "type": "visualization", "panelIndex": "1",
     "gridData": {"x": 0, "y": 0, "w": 24, "h": 9, "i": "1"},
     "embeddableConfig": {}, "version": "8.12.0"},
    {"id": "soc-vis-rule", "x": 0, "y": 9, "w": 24, "h": 12, "type": "visualization", "panelIndex": "2",
     "gridData": {"x": 0, "y": 9, "w": 24, "h": 12, "i": "2"},
     "embeddableConfig": {}, "version": "8.12.0"},
    {"id": "soc-vis-class", "x": 24, "y": 9, "w": 24, "h": 12, "type": "visualization", "panelIndex": "3",
     "gridData": {"x": 24, "y": 9, "w": 24, "h": 12, "i": "3"},
     "embeddableConfig": {}, "version": "8.12.0"},
]
dash_attributes = {
    "title": "SOC_OVERVIEW",
    "description": "Mini-SOC security dashboard. Findings from siem-findings + nginx attack surface.",
    "panelsJSON": json.dumps(panels),
    "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False,
                               "syncColors": False, "syncTooltips": False}),
    "timeRestore": True,
    "timeFrom": "now-24h", "timeTo": "now",
    "refreshInterval": {"pause": False, "value": 5000},
    "version": 1,
}
dash = obj("soc-overview-dashboard", "dashboard", dash_attributes, references=[
    {"name": "1:panel_1", "type": "visualization", "id": "soc-vis-metric"},
    {"name": "2:panel_2", "type": "visualization", "id": "soc-vis-rule"},
    {"name": "3:panel_3", "type": "visualization", "id": "soc-vis-class"},
])

objects = [dv_findings, dv_nginx, vis_metric, vis_rule, vis_class, dash]

import io
with io.open(OUT, "w", encoding="utf-8") as f:
    for o in objects:
        f.write(json.dumps(o) + "\n")
print(f"Wrote {len(objects)} saved objects -> {OUT}")


def import_ndjson(path):
    """POST saved objects import via Kibana API (multipart)."""
    import requests
    with open(path, "rb") as fp:
        files = {"file": (os.path.basename(path), fp, "application/ndjson")}
        data = {}
        params = {"overwrite": "true"}
        r = requests.post(f"{KIBANA}/api/saved_objects/_import",
                          auth=(ES_USER, ES_PASS), files=files, params=params,
                          headers={"kbn-xsrf": "true"},
                          timeout=30)
    print(f"import status: {r.status_code}")
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print(r.text[:500])

if "--import" in sys.argv:
    import_ndjson(OUT)
