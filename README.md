# 🔐 SOC-ify — Mini Security Operations Center on Azure + Elasticsearch

A reproducible, **basic-license-compatible** security monitoring pipeline that turns a
single Azure VM's nginx access logs into a working SOC: enrichment, detection rules,
alert triage, live dashboards and daily reporting — all without requiring Elastic's
paid Detection Rules / Watcher features.

> Status: scaffolds complete (config + scripts validated). Deploy via `scripts/deploy.sh`
> after review. Built against Elasticsearch **8.12.0 (docker)** + Kibana :8081 + MCP tools.

---

## 🏗 Architecture

```
                          ┌───────────────────────────────────────────────┐
Internet ──► Azure VM ──► Nginx (+ModSecurity CRS + geo-block VN-only)     │
 (attackers) │              │  access.log                                   │
             │              │                                               │
             │              └─► Filebeat ──► ES 100.117.2.50:9200           │
             │                                        │  nginx-access-*     │
             │                                   ┌────▼─────┐               │
             │                                   │ Ingest pipeline         │
             │                                   │ nginx-soc-enrich        │
             │                                   │ (attack class/severity/ │
             │                                   │  geo)                    │
             │                                   └────┬─────┘               │
             │                                        │                     │
             │   ┌───────────────────────────────────▼───────────────────┐ │
             │   │ Detection engine (scripts/apply_rules.py)             │ │
             │   │  · 9 signature rules (SQLi…scanner)  ── R-001..009     │ │
             │   │  · frequency/threshold (scan, brute)  ── R-011          │ │
             │   │  · attack-chain correlation         ── R-012            │ │
             │   └───────────────────┬───────────────────────────────────┘ │
             │                       │ writes qualified hits               │
             │                  ┌────▼────────┐                            │
             │                  │ siem-findings│ ◄── case queue             │
             │                  └────┬────────┘                            │
             │        triage.py ─────┤ (open→investigating→escalated/resolved)
             │  daily_report.py ─────┤ (SOC daily summary)
             │  Kibana SOC_OVERVIEW ──┘ (dashboards)
             └────────────────────────────────────────────────────────────┘
```

### Data flow
1. **Filebeat** ships nginx access.log → ES index `nginx-access-YYYY.MM.DD`.
2. **Ingest pipeline** `nginx-soc-enrich` (optional on existing index template) classifies every
   request: `soc.attack_class`, `soc.severity`, `soc.confidence`, `soc.tags`, plus ECS fields
   (`http.*`, `url.*`, `user_agent.*`) and GeoIP → `source.geo`.
3. **Detection engine** (scheduled) scans recent logs, tags hits with rule IDs, and writes
   non-duplicated findings to `siem-findings`.
4. **Triage** labels findings and removes auto-FPs.
5. **Kibana SOC_OVERVIEW** + **daily report** turn raw events into decisions.

---

## 📁 Repository layout

```
soc-ify/
├── ingest-pipelines/
│   └── nginx-soc-enrich.json      # attack classification + ECS + GeoIP pipeline (validated)
├── rules/
│   └── detection-rules.yaml       # 12 sigma-style rules (R-001..R-012) + FP guidance
├── transforms/
│   └── freq-detection-by-ip.json  # R-011 transform (group by client.ip over window)
├── scripts/
│   ├── deploy.sh                  # applies pipeline/template/transform to ES (curl)
│   ├── apply_rules.py             # detection engine (basic-license compatible)
│   ├── triage.py                  # case lifecycle + auto FP pass
│   └── daily_report.py            # SOC daily summary → MD/HTML
├── dashboards/
│   └── SOC_OVERVIEW.md            # Kibana panel-by-panel build spec (3 SOC sections)
└── docs/                          # (future) runbooks, red-team notes
```

---

## 🔌 Detection rules (R-001..012)

| ID    | Title                     | Sev | Class            |
|-------|---------------------------|-----|------------------|
| R-001 | SQL Injection             | 3   | sqli             |
| R-002 | XSS Attempt               | 2   | xss              |
| R-003 | Path Traversal / LFI      | 3   | path_traversal   |
| R-004 | Command Injection         | 4   | command_injection|
| R-005 | Sensitive File Disclosure | 4   | info_disclosure  |
| R-006 | SSRF                      | 3   | ssrf             |
| R-007 | Scanner UA                | 1   | scanner          |
| R-008 | Admin Panel Probe         | 2   | admin_panel_scan |
| R-009 | Auth Endpoint Scan        | 2   | auth_scan        |
| R-010 | Geo-block bypass probe    | 1   | geoblock_bypass  |
| R-011 | High Request Rate (freq)  | 2   | transverse_freq  |
| R-012 | Attack Chain correlation  | 3   | attack_chain     |

Signature rules are regex-based and mirror what ModSecurity CRS catches at the edge; the
value-add of this SOC is **correlation** (R-011/R-012) + **persistent case queue** that a
layer-7 WAF alone cannot provide.

---

## 🚀 Deploy & run

### Prereqs
- Python 3 + `pip install elasticsearch`
- Elasticsearch reachable at `http://localhost:9200` (self-hosted docker, trial→basic is fine)
- Your Filebeat already shipping `nginx-access-*`

### 1. Apply pipeline + template + transform
```bash
cd soc-ify
export MSYS_NO_PATHCONV=1          # git-bash / Windows
bash scripts/deploy.sh
```
This registers `nginx-soc-enrich`, creates the `siem-findings` index template, and the
`freq-detection-by-ip` transform. For enrichment on new docs, wire the pipeline into the
nginx index template (step commented in deploy.sh) — existing docs are left as-is.

### 2. Run the detection engine
```bash
python scripts/apply_rules.py --range now-15m --count-only   # dry-run: what would fire
python scripts/apply_rules.py --range now-15m                # write findings
```
Schedule every 10 min (cron / Windows Task Scheduler), e.g. `schtasks /create /tn SOC_Rules
/tr "...python.exe ... apply_rules.py --range now-15m" /sc minute /mo 10`.

### 3. Triage + auto FP
```bash
python scripts/triage.py --list-open
python scripts/triage.py --auto-first-pass --range now-24h    # label FPs / add evidence
python scripts/triage.py --set-id <id> --escalate
python scripts/triage.py --set-id <id> --resolve --reason "false_positive: benign path"
```

### 4. Reports
```bash
python scripts/daily_report.py --days 1 --html
```

### 5. Dashboards
Follow `dashboards/SOC_OVERVIEW.md` in Kibana (localhost:8081). Build the 3 SOC sections:
OVERVIEW (metric cards + 2-line trend), ATTACK ANALYSIS (bars/tagcloud/pie),
RECENT INCIDENTS (open-cases table + live events). Enable 5s auto-refresh.

---

## ✅ Verification checklist
- [ ] `curl -s ... /_ingest/pipeline/nginx-soc-enrich` returns 200
- [ ] New nginx docs carry `soc.attack_class` after deploy
- [ ] `apply_rules.py --count-only` prints non-zero matches to a SQLi/path probe
- [ ] Findings appear in `siem-findings` (count grows; no duplicates on re-run)
- [ ] Kibana SOC_OVERVIEW renders all 3 sections with live auto-refresh

---

## 📌 Known constraints / roadmap
- **License**: current ES is **trial (expires ~2026-08-13, user extending → Basic)**. This stack
  deliberately avoids Watcher/paid Detection Rules so it survives the downgrade. `--count-only`
  and transforms keep working on Basic.
- **Enrichment backfill**: existing indexed logs are not retro-enriched; run this live going forward.
- **Backend-direct bypass**: logs only capture traffic that hits nginx (port 80/443). Local/Direct
  attacks on DVWA(:8080) / JuiceShop are NOT in nginx-access — a known SIEM gap. Extending
  Filebeat inputs to container logs closes it (see roadmap in docs/).
- **RAM**: VM is OOM-prone (897MB). Keep rule scans rate-limited; prefer `--range now-15m` +
  small window over full-history.
- **Roadmap**: add suricata IDS + auditd → ES, GeoIP/threat-intel enrichment, Slack/Telegram
  webhook notify in `daily_report.py`.

---

## Why this matters (portfolio angle)
This is not just "logs in a dashboard". It's an **entire detection → triage → report loop**
running on a live internet-exposed Azure box with real scanner traffic (Censys, probes on
`/.env`, `/geoserver/web/`, `/webui/`), fully reproducible, free-license-compatible, and
extensible toward a production SIEM.
