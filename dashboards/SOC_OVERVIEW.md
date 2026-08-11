# SOC Dashboard Specification — "SOC_OVERVIEW"

Build in Kibana (localhost:8081) → **Dashboard → Create visualization**.
Data views used: `nginx-access*` and `siem-findings`.
Set global time picker to **Last 24h**, then enable **auto-refresh = 5s** for a live SOC feel.

> DEV NOTE: Elastic 8.12 supports dashboard *saved objects* export (`.ndjson`). This spec
> describes each panel so you can recreate them precisely. If you have a `.kibana_8.12.0_001`
> backup you imported before, you can paste the dashboard object directly; otherwise follow the
> panels below. **Metric visualisations with failed aggregation on nginx-access can flip to
> tagcloud/pie — see memory note (Kibana 8.12 metric panels sometimes fail to reduce).** Prefer
> using Discover + TSVB/Lens where a metric errors.

Panel widths: K = metric (narrow), B = bar/line, T = table/tagcloud.

---

## SECTION 1 — OVERVIEW (top row)

### K1. Total Requests (last 24h)
- Lens/Discover: `nginx-access*`, metric of count(*), label "Total Requests".

### K2. Unique Source IPs
- Metric visualization: `client.ip` cardinality. Label "Unique IPs".

### K3. Error Rate 4xx+5xx
- Metric: ratio `[4xx + 5xx] / total`. Use two filters or Lens formula.

### K4. Critical + High Findings
- Index `siem-findings`, filter `severity >= 3`, metric count. Label "Critical/High".

### K5. Open Findings
- Index `siem-findings`, filter `status:open`, metric count. Label "Open".

### B1. Request Trend (line, 2 lines: 4xx vs 2xx)
> The user prefers ONE line chart with 2 lines on a shared time axis for before/after comparisons.
- x-axis: `@timestamp` (hourly).
- Line 1: `http.response.status_code` in [200,201,204] → label "2xx OK".
- Line 2: `http.response.status_code` >= 400 → label "4xx/5xx errors".
- Add a **marker/vertical line** where a scan started (e.g. nuclei run) for before/after reference.

### K6. Top Method
- Pie or tagcloud of `http.request.method`.

### K7. Geo Blocked (403) Count
- Metric on `nginx-access*` where `http.response.status_code:403`. Label "403 Geo-Blocked".

---

## SECTION 2 — ATTACK ANALYSIS

### B2. Attacks by Class (bar)
- Index `nginx-access*`, group by `soc.attack_class` (keyword) → bar. Shows sqli/xss/etc.
- If `soc.attack_class` is empty, fall back to path-mapping in K8.

### K8. Top Attack Paths (tag cloud)
- Discover → tagcloud, field `url.path` top 20. Raw probe paths (e.g. `/.env`, `/geoserver/web/`) are prominent.

### B3. Top Attacker IPs (bar or table)
- `client.ip` top 15 by count.

### P1. Status Code Pie
- Pie by `http.response.status_code`.

### K9. New Findings by Rule (bar)
- Index `siem-findings`, terms on `rule_id.keyword`.

---

## SECTION 3 — RECENT INCIDENTS / TRIAGE

### T1. Open Findings Table
- Index `siem-findings`, filter `status:open`, columns:
  `rule_id`, `rule_title`, `client.ip`, `severity`, `url.path`, `first_seen`.
- Sort by severity desc. This is your live case queue (populated by `apply_rules.py` + `triage.py`).

### B4. Findings Trend
- Line: `siem-findings` count over time (hourly), split by `severity`.

### T2. Latest 50 Raw Events
- `nginx-access*`, table: `@timestamp`, `client.ip`, `url.path`, `http.response.status_code`,
  `user_agent.original`, message. Refresh 5s to watch live scan traffic.

---

## SAVE / IMPORT
1. Create each panel in **Visualize Library** (save named `SOC_*`).
2. Dashboard → add panels → arrange according to the 3 sections above.
3. Turn on **Auto-refresh 5 seconds** (top-right).
4. Export the dashboard for reproducibility:
   **Stack Management → Saved Objects → select dashboard + visualizations → Export**.

---

## Optional "Before/After Scan" view (pre/post)
Create a second dashboard `SOC_SCAN_DELTA` with a single line chart:
- x-axis time, line A = attack_count, line B = baseline (7d avg), plus a **marker at scan_start**.
This directly answers "did my scan change the attack surface" with the 2-line chart you prefer.
