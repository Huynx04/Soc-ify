# AGENTS.md — Guidance for AI coding agents working in this repo

This is **SOC-ify**, a mini Security Operations Center (SOC) that turns an exposed
Azure VM's nginx access logs into a working detection → triage → reporting pipeline,
built on Elasticsearch 8.12 + Kibana, fully **Basic-license compatible** (no paid
Elastic Security / Watcher dependency).

## What this repo does (architecture)

```
Internet → Azure VM → nginx (+ModSecurity CRS + geo-block VN-only)
                       └─ access.log → Filebeat → Elasticsearch (nginx-access-*)
                       └─ UFW firewall log          → Elasticsearch (fire-ufw-*)
                       └─ SSH auth log              → Elasticsearch (auth-*)
                                                    │
                          ┌─────────────────────────┤
                          │ ingest-pipeline/nginx-soc-enrich.json
                          │   (classifies attack_class / severity / geoip)
                          └─────────────────────────┤
                          │ scripts/apply_rules.py (scheduled every ~10m)
                          │   scans nginx+firewall+SSH → siem-findings (R-001..R-015)
                          └─────────────────────────┤
                              triage.py · daily_report.py · Kibana SOC dashboard
```

## Python projects & dependencies

- Requires **Python 3.10+** and `elasticsearch-py` **8.x ONLY**.
  - `elasticsearch>=8.12,<9` — version 9.x sends `Accept: ...compatible-with=9` which
    ES 8.12 rejects with `media_type_header_exception` (400).
- Install: `pip install "elasticsearch>=8.12,<9"`
- Scripts are CLI tools under `scripts/`. Never use `python -c` inline for repo logic.

## Environment / credentials (never commit)

All scripts read ES credentials from the environment (see `.env.example`):
- `SOC_ES_HOST` (default `http://localhost:9200`)
- `SOC_ES_USER`, `SOC_ES_PASS`
- `SOC_INDEX`, `SOC_FINDINGS`, `SOC_FIRE_INDEX`, `SOC_SSH_INDEX`
- `SOC_FREQ_THRESHOLD`, `SOC_PATH_DISTINCT`, `SOC_CHAIN_WINDOW`
- `SOC_SSH_FAIL`, `SOC_ALLOWED_IPS`
- `SOC_WIN_INDEX` (R-016 winlogbeat source), `SOC_INTEGRITY_PATHS`, `SOC_INTEGRITY_TRUSTED_PROCS`

Real local credentials live in `.env.local` which is **gitignored** — never add it.
On Windows git-bash export `MSYS_NO_PATHCONV=1` before running curl/tools.

## Common tasks

```bash
# Apply ingest pipeline + siem-findings template + transforms to ES
bash scripts/deploy.sh

# Run detection once (write findings to siem-findings)
cd scripts && python apply_rules.py --range now-20m

# Dry-run (don't write)
python apply_rules.py --range now-24h --count-only

# Triage findings
python triage.py --list-open
python triage.py --auto-first-pass --within 24h

# Daily report (markdown + optional html)
python daily_report.py --days 1 --html

# Rebuild/import the SOC dashboard + data views in Kibana
python build_dashboard.py --import        # create/overwrite SOC_OVERVIEW
python fix_soc_dashboard.py               # repoint viz refs / recreate missing index-pattern
python populate_soc_panels.py             # fill dashboard panelsJSON layout
```

## Detection rules

18 rules live in `rules/detection-rules.yaml` (R-001..R-018): SQLi, XSS, path
traversal, command injection, sensitive-file disclosure, SSRF, scanner UA, admin-panel
probe, auth scan, geo-block probe, high-request-rate (freq), attack-chain correlation,
firewall+web correlation (multi-source), SSH brute-force, SSH cross-source
correlation, file-integrity correlation (R-016, local Windows 4663), Sysmon file-create
(R-017, event 11) and Sysmon startup process-launch (R-018, event 1). All map to
MITRE ATT&CK. The aggregation rules (R-011/012) run over `nginx-access-*`;
multi-source rules (R-013/014/015) correlate `fire-ufw-*` and `auth-*`; R-016/R-017/R-018 are
in-host (joins by process/path/time on `winlogbeat-*`, NOT by IP — 4663/Sysmon have no
source.ip). The Windows File System audit (auditpol + SACL) must be enabled on the
client for R-016 to produce findings; see `scripts/enable_file_integrity_audit.ps1`.
R-017/R-018 require **Sysmon** installed (see `sysmon/sysmon-config.xml`) with the
`Microsoft-Windows-Sysmon/Operational` channel enabled in winlogbeat.yml; the security
driver (SysmonDrv) is currently running the full SwiftOnSecurity config (deployment
kept it because hand-written minimal configs triggered a driver-load crash
0xC0000409 on Sysmon 15.21 — the SwiftOnSecurity base loads cleanly and already emits
event 11). Note: <FileDelete> within a hand-written config is the confirmed crash
trigger; it is omitted from the FIM configs.
Severity 1-4; findings are written with stable `{rule_id, client.ip, window}` keys so
re-runs upsert (no duplicates).

## Conventions

- All paths in scripts/kibana use **forward slashes** (`/c/Users/...` or `C:/...`) and
  remain MSYS/git-bash compatible.
- Dashboard/data-view automation goes through the **Kibana Saved Objects API**
  (`/api/saved_objects/...`, requires `kbn-xsrf: true` header).
- Never hardcode ES credentials; use the `SOC_*` env vars.
- Keep generated artifacts (`reports/*.html|*.md`, `__pycache__`, `.env.local`) out of
  the repo (see `.gitignore`).
