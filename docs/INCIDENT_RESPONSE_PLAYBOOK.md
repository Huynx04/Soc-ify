# 🚨 Incident Response Playbook — SOC-ify

> Operational runbook for handling a detection fired by SOC-ify's 19 rules.
> Written against the **actual** pipeline in this repo (Elasticsearch 8.12 + Kibana,
> Basic licence, no Watcher), so every step below maps to a real index, script or
> dashboard panel you can open right now.

---

## 0. The one rule that outranks everything

**Preserve before you purge. Never clean up before you have captured evidence.**

The single most common junior-SOC mistake is: alert fires → SSH in → `kill -9` the
process, delete the file, restart the service. That destroys the evidence *and* the
attacker's tracks, and you lose the ability to answer "how far did they get?".

Order of operations is fixed:

```
1. Validate   →  2. Contain   →  3. Preserve   →  4. Eradicate   →  5. Recover   →  6. Learn
   (is it      (only if it's     (BEFORE          (remove)        (restore)        (tune
    real?)      live/ongoing)     cleanup)                                          rules)
```

SOC-ify gives you a structural advantage here: **logs are shipped off-host in
real time** (Filebeat → `100.117.2.50:9200`, winlogbeat → ES). If an attacker wipes
`/var/log` on the VM, your evidence already lives in Elasticsearch. That single
design decision is what makes step 3 possible at all.

---

## 1. Validate — is the alert real?

Answer these five questions before touching anything. Every one is answerable from
Kibana or the `siem-findings` index.

| Question | Where to look in SOC-ify |
|---|---|
| Which rule fired? | `rule_id` / `rule_title` in `siem-findings` (R-001…R-019) |
| What is affected? | `client.ip`, `url.path`, `file.path`, `host.name` |
| Is it still happening? | compare `first_seen` vs `@timestamp`; rerun `apply_rules.py --range now-15m` |
| How bad really? | **do not trust** the rule's `severity` — reassess with context |
| Could it be legitimate? | read `false_positive_hint`, then check the change window |

### Fast triage commands

```bash
# Open cases, newest first
python scripts/triage.py --list-open

# Automatic first pass: flags findings whose "blocked" path actually returned 2xx
python scripts/triage.py --auto-first-pass --within 24h

# Re-run detection over a tight window to see if it is ongoing
python scripts/apply_rules.py --range now-15m --count-only
```

### Severity reassessment (the part that separates analysts from alert-clearers)

| Signal | Interpretation |
|---|---|
| `http.response.status_code` = **403/404** on R-004/R-005 | *Attempt blocked.* Probe only. Real exposure would need 200. |
| `http.response.status_code` = **200** on R-005 | **Real disclosure.** Escalate immediately, treat as confirmed data exposure. |
| R-014 SSH brute-force, all logins failed | Attempt, not breach. Block + record. Check if *any* login succeeded. |
| R-019 / R-016 / R-017 changed a **sensitive path** | Compare against change window (`apt` run? admin edit?). AIDE baseline noise is common. |
| `client.ip` = `Nginx` / hostname (R-019, R-016) | Host-local FIM finding — **no attacker IP exists**. Join by file path + time, not by IP. |

**Worked example (real data from this lab):**

```
R-005  Sensitive File Disclosure   sev 4   160.119.76.210   /admin/config.php   HTTP 403
```
→ Rule says "critical", but status is 403. This is a **blocked probe**, not a
disclosure. Correct action: record, block the IP, do **not** page anyone. The
`false_positive_hint` literally says *"real exposure if 200"* — the hint exists to
stop exactly this over-reaction. This is the signal-vs-noise judgement a SOC hires for.

---

## 2. Contain — only if the attack is live

Decide on one question: **does the attacker have an active foothold right now?**

| Situation | Contain? | Action |
|---|---|---|
| Brute-force, all attempts failed (R-014) | No | Block IP at the edge; move on |
| Scanner / probe, blocked with 403 (R-007, R-008, R-010) | No | Block IP; no host action |
| Successful login after brute-force | **Yes** | Disable the account, kill sessions, isolate host |
| R-019 file-integrity: unexpected persistence file (e.g. `/etc/cron.d/*`) | **Yes** | Check for live sessions before disconnecting |
| R-016/R-017: sensitive-file tampering with an unexplained process | **Yes** | Isolate host, preserve process state first |

### Containment primitives available in this stack

```bash
# Edge blocking (cheapest, safest — prefer this over touching the host)
sudo ufw deny from <IP>            # UFW already ships to fire-ufw-*
# or add to the nginx geo-block allowlist deny list

# Account containment
sudo passwd -l <user>              # lock
sudo pkill -KILL -u <user>         # kill sessions (AFTER capturing ps output)
```

> **Principle:** isolate at the smallest sufficient scope, and prefer the *network
> edge* over the host. Blocking an IP costs nothing and risks nothing. Touching a
> live host risks destroying evidence and tipping off the attacker.

> ⚠️ Before isolating a host, capture `ps auxf`, `ss -tunap`, and `lsof -i` output.
> Once the process is killed, that state is gone forever.

---

## 3. Preserve — do this BEFORE any cleanup

This is the step that makes the difference between an incident you can explain and
one you can only apologise for.

### Evidence checklist

- [ ] **Changed files** — for R-019/R-016/R-017 copy the file off-host, then hash it:
  ```bash
  cp -a /etc/cron.d/backdoor /root/evidence/   # copy, never move
  sha256sum /etc/cron.d/backdoor | tee -a /root/evidence/hashes.txt
  ```
- [ ] **AIDE report** — `/var/log/aide/aide-check-report.txt` holds the raw
  added/removed/changed detail with original metadata.
- [ ] **Logs from Elasticsearch** (attacker cannot delete these — they are off-host):
  ```bash
  python scripts/daily_report.py --days 1 --html   # snapshot the window
  ```
  or export the raw docs from `nginx-access-*`, `fire-ufw-*`, `auth-*`,
  `logs-aide.check-*`, `winlogbeat-*` for the incident window.
- [ ] **Process / network state** (if the host is still live) — `ps auxf`, `ss -tunap`,
  `lsof -i`, `last`, `w`, `who`.
- [ ] **Persistence sweep** — capture (do not yet delete): `crontab -l`,
  `ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/`, `systemctl list-units --type=service`,
  `cat /etc/rc.local`, `cat ~/.ssh/authorized_keys`, `/etc/passwd` (+ any new UID 0).
- [ ] **Timeline** — record `first_seen` → `@timestamp` for every related finding.
- [ ] **Chain of custody** — who collected what, when, and the hash of each artifact.

### Why this works here

Because Filebeat and winlogbeat ship continuously, the Elasticsearch copy is
**independent of host state**. An attacker with root on the VM can shred local logs;
they cannot reach the ES copy (different host, `100.117.2.50`). This is the
"logs must leave the host immediately" principle, implemented.

---

## 4. Eradicate — remove the foothold

Only after step 3 is complete.

### Automated quarantine (R-019 / Linux FIM)

`scripts/response_fim.py` automates the safe part of containment for Linux FIM
findings. It is deliberately conservative:

- **Never deletes** — it *moves* the file to `/var/quarantine/` (always reversible).
- **Dry-run by default** — prints what it *would* do; `--apply` is opt-in.
- **Only acts on `file_created`** (new files = strongest webshell/persistence signal).
  Modified files are left for a human, since legitimate updates touch them too.
- **Path allowlist** (`PROTECTED_PREFIXES`) + **never-touch whitelist** + a
  `MAX_ACTIONS` cap so a false-positive storm can't mass-quarantine the host.

```bash
# On the nginx VM (it must touch that host's filesystem):
python3 scripts/response_fim.py --dry-run              # preview (default)
python3 scripts/response_fim.py --range now-2h --apply # quarantine
python3 scripts/response_fim.py --list-quarantine      # what's held
python3 scripts/response_fim.py --restore <name>       # put one back
```

It records `sha256` + original path in a `.meta.json` beside each quarantined file,
so quarantine doubles as evidence (step 3) and rollback.

### Manual eradication

```bash
# 1. Remove the malicious artifact (now that it is copied + hashed)
#    e.g. the test persistence file used in this lab:
#    rm /etc/cron.d/backdoor

# 2. Verify every persistence vector is clean
crontab -l; ls -la /etc/cron.*/; systemctl list-unit-files --state=enabled
cat ~/.ssh/authorized_keys; getent passwd | awk -F: '$3==0'

# 3. Rotate credentials that touched the host
#    SSH keys, ES/Nginx creds, any token in .env.local
```

**Revert the FIM baseline** so the same known-good state stops re-alerting:

```bash
sudo aide --update      # after you have CONFIRMED the current state is clean
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

> ⚠️ Never run `aide --update` before you are certain the host is clean — otherwise
> you baseline the attacker's files as "trusted" and blind your own detection.

---

## 5. Recover — restore service safely

- Restore modified files from a known-good source (package reinstall / backup),
  not from the tampered copy.
- **Rebuild rather than clean** if you cannot fully explain the intrusion. A VM is
  disposable; a half-cleaned host is a liability.
- Re-enable monitoring *before* reopening the service, so you catch a re-attack.
- Verify: `python scripts/apply_rules.py --range now-5m` returns the expected
  (clean) result, and the Kibana dashboard shows no new findings on that vector.

---

## 6. Learn — close the loop

| Action | Where |
|---|---|
| Was the detection correct? | If missed → add/tune a rule in `rules/detection-rules.yaml` |
| Was it a false positive? | Tune `false_positive_hint` / severity, or add a suppression allowlist (`SOC_ALLOWED_IPS`) |
| Did baseline noise cause it? | Update the AIDE baseline (step 4) |
| Multi-source confirmation possible? | Check whether R-013/R-015 correlated the same actor — that is the value of cross-source rules |
| Report | `python scripts/build_project_report.py` / `daily_report.py` |
| Metrics | Track **MTTD** (first log → first finding) and **MTTR** (finding → resolved). Improving these *is* the job. |

---

## Per-rule quick reference

| Rule | Trigger | Typical verdict | First action |
|---|---|---|---|
| R-001..R-003 | SQLi / XSS / path traversal | Blocked probe (ModSec/geo-block) | Confirm status code, record |
| R-004 | Command injection | Probe; escalate if any 2xx | Check response code |
| R-005 | Sensitive file disclosure | 403/404 = blocked; **200 = real breach** | Inspect status immediately |
| R-006..R-010 | SSRF / scanner / admin / auth scan / geo probe | Recon noise | Block IP, no host action |
| R-011 | High request rate | Scan or DoS prep | Check volume + target |
| R-012 | Attack chain | **Escalate** — multi-stage | Full timeline review |
| R-013 | Firewall + web correlation | Confirms web attack reached firewall | Correlate both sources |
| R-014 | SSH brute-force | Attempt unless a login succeeded | Block IP; grep for success |
| R-015 | SSH cross-source | Attacker active across layers | Escalate |
| R-016 | Windows 4663 FIM | Often legitimate (Office/Windows) | Check change window |
| R-017 | Sysmon FileCreate in sensitive path | Verify the writing process | Inspect `process.name` |
| R-018 | Sysmon process from Startup folder | **Persistence — escalate** | Capture process tree |
| R-019 | AIDE Linux FIM | Verify against change window | Compare to package updates |

> R-016/017/018/019 are **host-local**: sources carry no `client.ip`. Join on
> `file.path` + `process.name` + timestamp, *not* on IP.

---

## The three principles to memorise

1. **Preserve before purge.** Evidence first, always.
2. **Contain at the smallest scope, prefer the edge.** Blocking an IP beats touching a host.
3. **Logs must leave the host.** Off-host logs survive an attacker with root.

---

*Part of SOC-ify — a learning/portfolio SOC on Azure + Elasticsearch 8.12. Not a
production IR policy; adapt to your organisation's escalation matrix.*
