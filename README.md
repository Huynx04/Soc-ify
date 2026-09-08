# 🔐 SOC-ify — Mini Security Operations Center on Azure + Elasticsearch

> A reproducible, **Basic-license-compatible** security monitoring pipeline that turns a
> single Azure VM's nginx access logs into a working SOC: **detect → triage → report**,
> with live Kibana dashboards — no paid Elastic Security / Watcher required.

![License](https://img.shields.io/badge/license-MIT-blue) ![ES](https://img.shields.io/badge/Elasticsearch-8.12-orange) ![Kibana](https://img.shields.io/badge/Kibana-8.12-teal) ![Azure](https://img.shields.io/badge/infra-Azure%20VM-lightgrey) ![Python](https://img.shields.io/badge/python-3.10%2B-green)

---

## ✨ Features

- 🛡️ **Ingest-pipeline enrichment** — auto-classifies every request into an attack class
  (SQLi, XSS, path traversal, command injection, SSRF, scanner…) with severity + confidence.
- 🔍 **18 detection rules** (Sigma-style), mapped to MITRE ATT&CK — from single-request
  signatures to **frequency** (scan/brute-force), **attack-chain** correlation,
  **multi-source** correlation across nginx + UFW firewall + SSH auth logs, and
  **host file-integrity** (FIM) on a Windows endpoint.
- 🖥️ **Windows endpoint coverage** — correlates Security **4663** (R-016) + **Sysmon**
  event 11 FileCreate (R-017) / event 1 startup process-launch (R-018) shipped via
  winlogbeat, giving a host-local FIM layer alongside the cloud/web sources.
- 🧠 **Persistent case queue** — qualified hits land in `siem-findings` with stable
  `{rule, src_ip, window}` keys so re-runs dedupe — no alert spam.
- 👩‍💻 **Triage workflow** — open → investigating → escalated → resolved, with an auto-FP pass
  that checks whether a blocked path ever returned 2xx.
- 📊 **SOC Kibana dashboard** (24h) — pie + tagcloud panels for Severity, Rule, Attack
  Class, MITRE Tactic, Status, SSH Top IPs, UFW Top IPs. (Kibana 8.12 render via the
  saved-objects API is limited to pie/tagcloud; bar/line/metric need hand-drawing in UI.)
- 📄 **Daily SOC report** — auto-generated Markdown/HTML summary (top IPs, attacks, open cases)
  ready to route to Slack/Telegram/email.
- ⏱️ **Scheduled detection** — cron-drives `apply_rules.py` every few minutes for continuous monitoring.

---

## 🏗️ Architecture

```
Internet ──► Azure VM ──► nginx (+ ModSecurity CRS + geo-block VN-only)
                           │  access.log
                           ├──── Filebeat ──► Elasticsearch 8.12 ── nginx-access-*
                           │         ▲                      │
                           │  UFW firewall log      ingest-pipeline/nginx-soc-enrich.json
                           │  fire-ufw-*            (attack_class · severity · geoip)
                           │  SSH auth log auth-*           │
                           │                     scripts/apply_rules.py  ◄─ cron
Windows endpoint ──► winlogbeat ──► winlogbeat-*            (R-001..R-018 detection)
(Security 4663 + Sysmon)                                  │
                           ├──────────► siem-findings (case queue)
                           │              │   ◄─ triage.py · daily_report.py
                           └──────────► Kibana 8.12 ── SOC SIEM DASHBOARD
```

### Data flow
1. **Filebeat** ships nginx `access.log`, UFW `fire-ufw-*`, and SSH `auth-*` logs → ES.
2. **Ingest pipeline** classifies each request → `soc.attack_class`, `soc.severity`,
   `soc.confidence`, plus ECS (`http.*`, `url.*`) and GeoIP.
3. **`apply_rules.py`** (scheduled) scans recent logs from nginx + firewall + SSH +
   winlogbeat, tags hits with rule IDs (R-001..R-018), writes non-duplicated findings
   to `siem-findings`.
4. **Triage** labels findings, removes auto-FPs.
5. **Kibana dashboard + daily report** turn raw events into decisions.
6. **Windows FIM** (R-016/017/018) runs host-local: `apply_rules.py` correlates Security
   4663 (mutations on sensitive paths) and Sysmon FileCreate/ProcessCreate to catch
   tampering/persistence — sources have **no IP**, so joins are by process+path+time.

---

## 📁 Repository layout

```
soc-ify/
├── AGENTS.md                     # AI-agent context (Claude Code/Codex/Hermes)
├── ingest-pipelines/
│   └── nginx-soc-enrich.json     # attack classification + ECS + GeoIP (validated)
├── rules/
│   └── detection-rules.yaml      # 18 Sigma-style rules (R-001..R-018)
├── transforms/
│   └── freq-detection-by-ip.json # R-011 frequency transform
├── docs/
│   └── MULTI_SOURCE_CORRELATION_PLAN.md
├── scripts/
│   ├── deploy.sh                 # apply pipeline/template/transform to ES
│   ├── apply_rules.py            # detection engine R-001..R-018 (scheduled)
│   ├── triage.py                 # case lifecycle + auto-FP
│   ├── daily_report.py           # SOC daily report → MD/HTML
│   ├── build_soc_summary_xlsx.py # export SOC summary to xlsx
│   ├── build_project_report.py   # generate Word project report (driven by rules .yaml)
│   ├── build_soc_pie_dashboard.py# (re)build pie/tagcloud SOC panels
│   ├── enable_file_integrity_audit.ps1  # turn on Security 4663 audit + SACL (R-016)
│   ├── hermes-verify-r016.py     # self-check R-016 FIM correlation vs ES
│   ├── alerts.py                 # (draft) push-notification alerting
│   ├── build_dashboard.py        # Kibana dashboard generator/importer
│   ├── fix_soc_dashboard.py      # repair missing index-pattern + refs
│   ├── populate_soc_panels.py    # fill dashboard panelsJSON layout
│   ├── run_soc_detect.bat        # Windows Task Scheduler wrapper
│   ├── run_soc_detect_hidden.vbs # hidden (no window) scheduler launcher
│   └── push_github.sh            # create + push this repo (credential-safe)
├── sysmon/
│   ├── sysmon-config.xml         # minimal FIM Sysmon config (evt 1/11 FileCreate)
│   ├── sysmon-config-swiftonsecurity.xml  # full SwiftOnSecurity base (deployment default)
│   └── (binaries gitignored per Sysinternals redistributable EULA)
├── dashboards/
│   ├── SOC_OVERVIEW.md           # panel-by-panel build spec
│   └── soc_overview.ndjson       # importable dashboard export
└── reports/                      # daily + project reports (Word/xlsx)
```

---

## 🔌 Detection rules (R-001…018)

| ID | Title | Sev | Class | Source |
|----|-------|-----|-------|--------|
| R-001 | SQL Injection | High | `sqli` | nginx |
| R-002 | XSS Attempt | Med | `xss` | nginx |
| R-003 | Path Traversal / LFI | High | `path_traversal` | nginx |
| R-004 | Command Injection | Crit | `command_injection` | nginx |
| R-005 | Sensitive File Disclosure | Crit | `info_disclosure` | nginx |
| R-006 | SSRF | High | `ssrf` | nginx |
| R-007 | Scanner UA | Low | `scanner` | nginx |
| R-008 | Admin Panel Probe | Med | `admin_panel_scan` | nginx |
| R-009 | Auth Endpoint Scan | Med | `auth_scan` | nginx |
| R-010 | Geo-block bypass probe | Low | `geoblock_bypass` | nginx |
| R-011 | High Request Rate (freq) | Med | `transverse_freq` | nginx |
| R-012 | Attack Chain correlation | High | `attack_chain` | nginx |
| R-013 | Firewall+Web correlation | Med | `cross_source_correlation` | UFW + nginx |
| R-014 | SSH Brute-Force | High | `ssh_bruteforce` | SSH auth |
| R-015 | SSH Cross-Source correlation | Low-Med | `ssh_cross_source` | SSH + web/fw |
| R-016 | Sensitive File Modified (4663 FIM) | High | `file_integrity` | winlogbeat (Security 4663) |
| R-017 | Sysmon File Create in sensitive path | High | `file_integrity` | winlogbeat (Sysmon evt 11) |
| R-018 | Sysmon Process launched from Startup | High | `persistence` | winlogbeat (Sysmon evt 1) |

> Signature rules (R-001..R-010) mirror what ModSecurity CRS catches at the edge; the
> **value-add** is correlation — single-source (R-011/R-012), **multi-source**
> (R-013/R-015) across nginx, UFW firewall, and SSH auth logs, and **host FIM**
> (R-016/017/018) across a Windows endpoint via winlogbeat — plus a **persistent triage
> queue** a layer-7 WAF can't provide. All 18 rules map to **MITRE ATT&CK**.
> R-016 needs the File System audit (auditpol + SACL) enabled on the client (see
> `scripts/enable_file_integrity_audit.ps1`); R-017/018 need Sysmon installed with
> `Microsoft-Windows-Sysmon/Operational` in winlogbeat (see `sysmon/`). Sysmon FIM
> events carry **no IP**, so host rules join by process+path+time.

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
- **Durable alerting** — `alerts.py` is a draft; wire it to a Slack/Telegram webhook
  (reads `SOC_ALERT_*` channel creds from env, never committed) to close the detect→notify loop.
- **Windows FIM prerequisites** — R-016 requires the File System audit turned on
  (auditpol subcategory + SACL); R-017/018 require Sysmon (`sysmon/`) + the
  `Microsoft-Windows-Sysmon/Operational` channel enabled in winlogbeat. See AGENTS.md.

> ✅ **Done:** multi-source UFW + SSH correlation (R-013/014/015) against nginx, plus
> Windows endpoint FIM (R-016/017/018) over winlogbeat — see
> `docs/MULTI_SOURCE_CORRELATION_PLAN.md` and `sysmon/`.

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
