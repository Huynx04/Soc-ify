# 🔐 SOC-ify — Mini Security Operations Center on Azure + Elasticsearch

> A reproducible, **Basic-license-compatible** security monitoring pipeline that turns a
> single Azure VM's nginx access logs into a working SOC: **detect → triage → report**,
> with live Kibana dashboards — no paid Elastic Security / Watcher required.

![License](https://img.shields.io/badge/license-MIT-blue) ![ES](https://img.shields.io/badge/Elasticsearch-8.12-orange) ![Kibana](https://img.shields.io/badge/Kibana-8.12-teal) ![Azure](https://img.shields.io/badge/infra-Azure%20VM-lightgrey) ![Python](https://img.shields.io/badge/python-3.10%2B-green)

---

## ✨ Features

- 🛡️ **Ingest-pipeline enrichment** — auto-classifies every request into an attack class
  (SQLi, XSS, path traversal, command injection, SSRF, scanner…) with severity + confidence.
- 🔍 **12 detection rules** (Sigma-style) — from single-request signatures to **frequency**
  (scan/brute-force) and **attack-chain** correlation across a source IP.
- 🧠 **Persistent case queue** — qualified hits land in `siem-findings` with stable
  `{rule, src_ip, window}` keys so re-runs dedupe — no alert spam.
- 👩‍💻 **Triage workflow** — open → investigating → escalated → resolved, with an auto-FP pass
  that checks whether a blocked path ever returned 2xx.
- 📊 **SOC Kibana dashboard** — 3 sections (OVERVIEW / ATTACK ANALYSIS / RECENT INCIDENTS),
  metric cards, pie + tagcloud + table panels.
- 📄 **Daily SOC report** — auto-generated Markdown/HTML summary (top IPs, attacks, open cases)
  ready to route to Slack/Telegram/email.
- ⏱️ **Scheduled detection** — cron-drives `apply_rules.py` every few minutes for continuous monitoring.

---

## 🏗️ Architecture

```
Internet ──► Azure VM ──► nginx (+ ModSecurity CRS + geo-block VN-only)
                           │  access.log
                           ├──── Filebeat ──► Elasticsearch 8.12 ── nginx-access-*
                           │                                    │
                           │                     ingest-pipeline/nginx-soc-enrich.json
                           │                     (attack_class · severity · geoip)
                           │                                    │
                           │                     scripts/apply_rules.py  ◄─ cron
                           │                     (R-001..R-012 detection)
                           │                                    │
                           ├──────────► siem-findings (case queue)
                           │              │   ◄─ triage.py · daily_report.py
                           └──────────► Kibana 8.12 ── SOC SIEM DASHBOARD
```

### Data flow
1. **Filebeat** ships nginx `access.log` → ES index `nginx-access-YYYY.MM.DD`.
2. **Ingest pipeline** classifies each request → `soc.attack_class`, `soc.severity`,
   `soc.confidence`, plus ECS (`http.*`, `url.*`) and GeoIP.
3. **`apply_rules.py`** (scheduled) scans recent logs, tags hits with rule IDs, writes
   non-duplicated findings to `siem-findings`.
4. **Triage** labels findings, removes auto-FPs.
5. **Kibana dashboard + daily report** turn raw events into decisions.

---

## 📁 Repository layout

```
soc-ify/
├── AGENTS.md                     # AI-agent context (Claude Code/Codex/Hermes)
├── ingest-pipelines/
│   └── nginx-soc-enrich.json     # attack classification + ECS + GeoIP (validated)
├── rules/
│   └── detection-rules.yaml      # 12 Sigma-style rules (R-001..R-012)
├── transforms/
│   └── freq-detection-by-ip.json # R-011 frequency transform
├── scripts/
│   ├── deploy.sh                 # apply pipeline/template/transform to ES
│   ├── apply_rules.py            # detection engine (scheduled)
│   ├── triage.py                 # case lifecycle + auto-FP
│   ├── daily_report.py           # SOC daily report → MD/HTML
│   ├── build_dashboard.py        # Kibana dashboard generator/importer
│   ├── fix_soc_dashboard.py      # repair missing index-pattern + refs
│   ├── populate_soc_panels.py    # fill dashboard panelsJSON layout
│   └── push_github.sh            # create + push this repo
├── dashboards/
│   ├── SOC_OVERVIEW.md           # panel-by-panel build spec
│   └── soc_overview.ndjson       # importable dashboard export
└── reports/                      # generated daily reports (gitignored output)
```

---

## 🔌 Detection rules (R-001…012)

| ID | Title | Sev | Class |
|----|-------|-----|-------|
| R-001 | SQL Injection | 3 | `sqli` |
| R-002 | XSS Attempt | 2 | `xss` |
| R-003 | Path Traversal / LFI | 3 | `path_traversal` |
| R-004 | Command Injection | 4 | `command_injection` |
| R-005 | Sensitive File Disclosure | 4 | `info_disclosure` |
| R-006 | SSRF | 3 | `ssrf` |
| R-007 | Scanner UA | 1 | `scanner` |
| R-008 | Admin Panel Probe | 2 | `admin_panel_scan` |
| R-009 | Auth Endpoint Scan | 2 | `auth_scan` |
| R-010 | Geo-block bypass probe | 1 | `geoblock_bypass` |
| R-011 | High Request Rate (freq) | 2 | `transverse_freq` |
| R-012 | Attack Chain correlation | 3 | `attack_chain` |

> Signature rules mirror what ModSecurity CRS catches at the edge; the **value-add** is
> correlation (R-011/R-012) + a **persistent triage queue** a layer-7 WAF can't provide.

---

## 🚀 Quick start

### Prerequisites
- Python 3.10+ · `pip install "elasticsearch>=8.12,<9"`
  > ⚠️ Version **9.x breaks**: it sends `Accept: compatible-with=9`, rejected by ES 8.12
  > (`media_type_header_exception`). Stick to 8.x.
- Elasticsearch 8.x + Kibana reachable at `http://localhost:9200` / `:8081`
- Filebeat already shipping `nginx-access-*`

### 1. Configure credentials
```bash
cp .env.example .env.local        # fill in SOC_ES_USER / SOC_ES_PASS
export MSYS_NO_PATHCONV=1         # Windows git-bash only
source .env.local                 # or export the SOC_* vars in your shell
```

### 2. Apply pipeline + template + transform
```bash
cd soc-ify
bash scripts/deploy.sh
```

### 3. Run detection
```bash
python scripts/apply_rules.py --range now-24h --count-only   # dry run
python scripts/apply_rules.py --range now-20m                # write findings
```

### 4. Triage + report
```bash
python scripts/triage.py --list-open                       # open cases
python scripts/triage.py --auto-first-pass --within 24h    # label FPs
python scripts/daily_report.py --days 1 --html             # daily summary
```

### 5. Schedule it (every ~10 min)
```bash
# cron / Windows Task Scheduler / your orchestrator:
cd scripts && python apply_rules.py --range now-20m
```

### 6. Dashboard
Import `dashboards/soc_overview.ndjson` via **Stack Management → Saved Objects → Import**
(overwrite), or follow `dashboards/SOC_OVERVIEW.md` to build panels by hand. Enable 5 s
auto-refresh for a live SOC feel.

---

## ✅ Verification checklist

- [ ] `curl -s …/_ingest/pipeline/nginx-soc-enrich` → 200
- [ ] New nginx docs carry `soc.attack_class`
- [ ] `apply_rules.py --count-only` returns non-zero on a SQLi/path probe
- [ ] Findings appear in `siem-findings` (no duplicates on re-run)
- [ ] Kibana SOC SIEM DASHBOARD renders all 3 sections

---

## 🧠 SIEM gaps & roadmap

- **Backend-direct bypass** — logs only capture traffic through nginx (80/443). Direct
  attacks on DVWA(:8080)/JuiceShop bypass nginx and aren't in `nginx-access`. Roadmap:
  ship Filebeat into the backend containers for full coverage.
- **Enrichment backfill** — existing indexed logs aren't retro-enriched; run this live going
  forward.
- **License** — deliberately no Watcher/paid Detection Rules dependency, so it survives an
  Elastic trial→Basic downgrade.
- **Alerting** — extend `daily_report.py` with a Slack/Telegram webhook for push notifications.

---

## 🧑‍💻 Deploying to GitHub

The repo includes `scripts/push_github.sh` (credential-safe: reads `GITHUB_TOKEN` from env):

```bash
cd soc-ify
GITHUB_TOKEN=<your-PAT-with-repo-scope> bash scripts/push_github.sh [repo-name]
```
It resolves your username from the token, creates a **public** repo, and pushes `main`.
For a private repo, set `"public": false` inside the script.

---

## 📄 License

[MIT](LICENSE) — use it, learn from it, harden your own lab.

*Built on Azure + Elasticsearch 8.12 + Kibana as a learning/portfolio SOC. Not a production SIEM.*
