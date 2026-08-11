#!/usr/bin/env bash
# ============================================================================
# SOC-ify deployment script (Basic-license compatible security stack on ES)
# Applies the ingest pipeline + index template for findings + transform jobs.
# Run from this directory. Requires MSYS_NO_PATHCONV=1 on git-bash Windows.
#
#   bash deploy.sh
#
# Steps:
#   1. Register ingest pipeline  nginx-soc-enrich
#   2. Register siem-findings write index + template
#   3. Register transform       freq-detection (R-011)
#   4. Install optional filebeat processor hook (adds pipeline to index template)
#   5. Scheduler note for apply_rules.py (cron / Task Scheduler)
# ============================================================================
set -euo pipefail

export MSYS_NO_PATHCONV=1
ES="http://localhost:9200"
USER="${SOC_ES_USER:-CHANGE_ME}"
PASS="${SOC_ES_PASS:-CHANGE_ME}"
AUTH="--user ${USER}:${PASS}"
CT="Content-Type: application/json"

echo "==> ES version check"
curl -s $AUTH "$ES/" | python -c "import sys,json;print('  ES',json.load(sys.stdin)['version']['number'])"

echo "==> Register ingest pipeline: nginx-soc-enrich"
curl -s $AUTH -XPUT "$ES/_ingest/pipeline/nginx-soc-enrich" -H "$CT" \
  --data-binary @ingest-pipelines/nginx-soc-enrich.json | python -m json.tool

echo "==> Create siem-findings template (basic mappings, avoids dynamic pitfalls)"
curl -s $AUTH -XPUT "$ES/_index_template/siem-findings" -H "$CT" -d '{
  "index_patterns": ["siem-findings", "siem-findings-*"],
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "properties": {
        "rule_id":        { "type": "keyword" },
        "rule_title":     { "type": "text" },
        "client.ip":      { "type": "ip" },
        "severity":       { "type": "integer" },
        "confidence":     { "type": "float" },
        "attack_class":   { "type": "keyword" },
        "url.path":       { "type": "text" },
        "status":         { "type": "keyword" },
        "false_positive_hint": { "type": "text" },
        "status":         { "type": "keyword" },
        "@timestamp":     { "type": "date" },
        "first_seen":     { "type": "date" }
      }
    }
  }
}' | python -m json.tool

echo "==> Register transform: freq-detection-by-ip (R-011)"
curl -s $AUTH -XPUT "$ES/_transform/freq-detection-by-ip" -H "$CT" \
  --data-binary @transforms/freq-detection-by-ip.json | python -m json.tool

echo "==> Start transform (false for continuous so it respects retention)"
curl -s $AUTH -XPOST "$ES/_transform/freq-detection-by-ip/_start" | python -m json.tool
curl -s $AUTH -XPOST "$ES/_transform/freq-detection-by-ip/_stop" | python -m json.tool 2>/dev/null || true

echo "==> (optional) wire ingest pipeline into the nginx-access index template"
# If you want enrichment applied to every doc as it lands, add pipeline to the
# index template used by filebeat. Current setup writes to "nginx-access-YYYY.MM.DD"
# (custom mapping, not a data stream). Wire default_pipeline:
#   PUT /_index_template/nginx-access  { index_patterns:["nginx-access-*"], template:{settings:{"index.default_pipeline":"nginx-soc-enrich"}} }
# NOTE: reindexing ALREADY-INDEXED docs is out of scope; new docs get enriched.

echo "==> Schedule note (do this manually or with cron)")
cat <<'NOTE'
Run detection every 10m (CRON example):
  * * * * *   cd /path/to/soc-ify && python scripts/apply_rules.py --range now-15m >> soc_engine.log 2>&1
On Windows Task Scheduler create task: schtasks /create /tn SOC_Rules /tr "<abs path>/python.exe <abs path>/scripts/apply_rules.py --range now-15m" /sc minute /mo 10
NOTE

echo "==> DONE. Verify:"
echo "  curl -s $AUTH \"$ES/_ingest/pipeline/nginx-soc-enrich\""
echo "  curl -s $AUTH \"$ES/_transform/freq-detection-by-ip\""
