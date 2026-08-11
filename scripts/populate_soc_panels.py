#!/usr/bin/env python3
"""
Populate the panelsJSON layout of the SOC SIEM dashboard (siem-attack-dashboard)
with its 12 visualization panels, arranged in 3 SOC sections.

Reads current dashboard object, keeps its references, sets a clean panelsJSON.

Run: python populate_soc_panels.py
"""
import json, os, sys, requests

KIBANA = os.environ.get("SOC_KIBANA", "http://localhost:8081")
U = os.environ.get("SOC_ES_USER", "CHANGE_ME")
P = os.environ.get("SOC_ES_PASS", "CHANGE_ME")
H = {"kbn-xsrf": "true"}
DASH = "siem-attack-dashboard"

# panel layout: (viz id, title, x, y, w, h)
# unit = grid units (48-wide canvas). Section headers span full width.
PANELS = [
    # SECTION 1 - OVERVIEW
    ("siem-hdr-overview",  "OVERVIEW",           0, 0,  48, 4),
    ("siem-card1",         "Total Events",       0, 4,  12, 6),
    ("siem-card2",         "Unique IPs",         12, 4, 12, 6),
    ("siem-card3",         "Nginx Requests",     24, 4, 12, 6),
    ("siem-card4",         "403 Blocked",        36, 4, 12, 6),
    # SECTION 2 - ATTACK ANALYSIS
    ("siem-hdr-analysis",  "ATTACK ANALYSIS",    0, 10, 48, 4),
    ("siem-timeline",      "Attack Timeline",    0, 14, 24, 10),
    ("siem-classification","Attack Types",       24, 14, 24, 10),
    ("siem-topips",        "Top Attacker IPs",   0, 24, 24, 10),
    ("siem-toppaths",      "Top Paths",          24, 24, 24, 10),
    ("siem-statuscode",    "HTTP Status",        0, 34, 16, 10),
    ("siem-httpmethods",   "HTTP Methods",       16, 34, 16, 10),
    ("siem-card4",         "403 Blocked",        32, 34, 16, 10),
    # SECTION 3 - INCIDENTS
    ("siem-hdr-incidents", "RECENT INCIDENTS",   0, 44, 48, 4),
    ("siem-datatable",     "Recent Incidents",   0, 48, 48, 14),
]

def build_panels_json():
    panels = []
    refs = []
    for i, (vid, title, x, y, w, h) in enumerate(PANELS):
        pidx = str(i)
        panels.append({
            "id": vid,
            "type": "visualization",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pidx},
            "panelIndex": pidx,
            "embeddableConfig": {"title": title},
            "version": "8.12.0",
        })
        refs.append({"id": vid, "name": f"panel_{i}", "type": "visualization"})
    return panels, refs


def main():
    # read current dashboard to preserve non-panel attributes + other refs
    r = requests.get(f"{KIBANA}/api/saved_objects/dashboard/{DASH}",
                     auth=(U, P), headers=H, timeout=30)
    r.raise_for_status()
    obj = r.json()
    att = obj["attributes"]
    # existing refs that are NOT the visualization panels we're replacing (e.g. any index patterns)
    old_refs = [x for x in obj.get("references", []) if x.get("type") != "visualization"]

    panels, viz_refs = build_panels_json()
    att["panelsJSON"] = json.dumps(panels)
    att["optionsJSON"] = json.dumps({"darkTheme": False, "useMargins": True,
                                     "hidePanelTitles": True})
    att["timeRestore"] = True
    att["timeFrom"] = "now-7d"
    att["timeTo"] = "now"
    att["refreshInterval"] = {"pause": False, "value": 5000}

    body = {"attributes": att, "references": old_refs + viz_refs}
    pu = requests.put(f"{KIBANA}/api/saved_objects/dashboard/{DASH}",
                      auth=(U, P), headers={**H, "Content-Type": "application/json"},
                      json=body, timeout=30)
    print("PUT dashboard ->", pu.status_code)
    print(pu.text[:400])
    if pu.status_code in (200, 200):
        print("==> panels populated:", json.dumps(panels, indent=0)[:200], "...")

if __name__ == "__main__":
    main()
