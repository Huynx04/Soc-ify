#!/usr/bin/env python3
"""Generate a polished Word (.docx) project report for SOC-ify.

Sources of truth:
  - rules/detection-rules.yaml  -> dynamic rule table (18 rules R-001..R-018).
  - Detection dashboard metrics section is a SAMPLE (kept static on purpose so the
    report builds offline / in CI with no live ES). Update figures manually as needed.

Usage:  python build_project_report.py   (writes reports/SOC-ify_Project_Report.docx)
"""
import os
import sys
from docx import Document
from docx.shared import Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RULES_YAML = os.path.join(REPO, "rules", "detection-rules.yaml")
OUT = os.path.join(REPO, "reports", "SOC-ify_Project_Report.docx")

DARK = RGBColor(0x1F, 0x3A, 0x5F)
ACCENT = RGBColor(0xC2, 0x3B, 0x22)  # SOC red accent

# Rule -> data source label (not modelled in the .yaml; kept here as the single,
# compact map). Rules 016/017/018 run host-local on winlogbeat-* (no source.ip).
SOURCE = {
    "R-001": "nginx", "R-002": "nginx", "R-003": "nginx", "R-004": "nginx",
    "R-005": "nginx", "R-006": "nginx", "R-007": "nginx", "R-008": "nginx",
    "R-009": "nginx", "R-010": "nginx", "R-011": "nginx-access-*",
    "R-012": "nginx-access-*", "R-013": "UFW + nginx",
    "R-014": "SSH auth", "R-015": "SSH + web/fw",
    "R-016": "winlogbeat (4663)", "R-017": "winlogbeat (Sysmon evt 11)",
    "R-018": "winlogbeat (Sysmon evt 1)",
}

# ---- Load rules dynamically from the YAML of truth -------------------------
def load_rules():
    """Return list of dicts ordered by rule id, one per rule in the yaml."""
    try:
        import yaml
    except ImportError as e:
        sys.exit("[!] PyYAML required:  pip install pyyaml")
    with open(RULES_YAML, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    rules = doc.get("rules", [])
    rules = [r for r in rules if str(r.get("id", "")).startswith("R-")]
    rules.sort(key=lambda r: int(r["id"][2:]))
    return rules


def sev_label(sev):
    """'high' -> 'HIGH'; unknown -> str(sev) upper."""
    return sev.upper() if isinstance(sev, str) else str(sev)


# ---- Helpers ----------------------------------------------------------------
def h1(doc, text):
    p = doc.add_heading(text, level=1)
    for r in p.runs:
        r.font.color.rgb = DARK
    return p


def h2(doc, text):
    p = doc.add_heading(text, level=2)
    for r in p.runs:
        r.font.color.rgb = DARK
    return p


def para(doc, text, bold=False, color=None, size=None):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.bold = bold
    if color:
        r.font.color.rgb = color
    if size:
        r.font.size = Pt(size)
    return p


def bullet(doc, text):
    doc.add_paragraph(text, style="List Bullet")


def build():
    rules = load_rules()
    n = len(rules)
    ids = [r["id"] for r in rules]
    id_span = f"{ids[0]}…{ids[-1]}"

    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    # ---- Cover ----
    t = doc.add_paragraph(); t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = t.add_run("SOC-ify"); r.font.size = Pt(40); r.bold = True; r.font.color.rgb = DARK
    sub = doc.add_paragraph(); sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run("Mini Security Operations Center trên Azure + Elasticsearch")
    r.font.size = Pt(16); r.font.color.rgb = ACCENT
    meta = doc.add_paragraph(); meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = meta.add_run("Báo cáo tổng thể dự án  •  Elasticsearch 8.12 + Kibana  •  MIT License")
    r.font.size = Pt(10)
    doc.add_paragraph()

    # ---- 1. Tổng quan ----
    h1(doc, "1. Tổng quan dự án")
    para(doc, "SOC-ify là một Security Operations Center (SOC) thu nhỏ, có thể tái tạo "
              "(reproducible), xây dựng trên một Azure VM phơi bày có chủ đích, với mục tiêu "
              "biến log truy cập nginx thành một pipeline giám sát bảo mật hoàn chỉnh: "
              "Phát hiện → Triage → Báo cáo (detect → triage → report), kèm dashboard Kibana "
              "trực tiếp. Bản nâng cấp mở rộng nguồn sang Windows endpoint (winlogbeat + Sysmon) "
              "cho FIM.")
    para(doc, "Điểm đặc biệt: hệ thống hoàn toàn tương thích giấy phép Basic của Elastic "
              "(không phụ thuộc các tính năng trả phí như Elastic Security / Watcher).", bold=True)

    # ---- 2. Kiến trúc ----
    h1(doc, "2. Kiến trúc hệ thống")
    para(doc, "Luồng dữ liệu: Internet → Azure VM → nginx (+ ModSecurity CRS + geo-block VN-only). "
         "Filebeat thu thập 3 nguồn log rồi đẩy về Elasticsearch; winlogbeat phía Windows endpoint "
         "gửi bổ sung log Security (4663) + Sysmon:")
    bullet(doc, "nginx access.log  → index nginx-access-*")
    bullet(doc, "UFW firewall log  → index fire-ufw-*")
    bullet(doc, "SSH auth log      → index auth-*")
    bullet(doc, "Windows endpoint  → winlogbeat-* (Security 4663 + Sysmon/Operational) → R-016/017/018")
    para(doc, "Đường ống xử lý:")
    bullet(doc, "Ingest pipeline (nginx-soc-enrich.json) tự phân loại mỗi request thành class tấn công "
                "(SQLi, XSS, path traversal, command injection, SSRF, scanner...) kèm severity + confidence.")
    bullet(doc, "scripts/apply_rules.py (chạy định kỳ ~10 phút) quét các nguồn, gắn rule ID "
                f"({id_span} = {n} rule), ghi findings vào index siem-findings — với key "
                "{rule, src_ip, window} ổn định để khử trùng lặp.")
    bullet(doc, "triage.py quản lý vòng đời case (open → investigating → escalated → resolved).")
    bullet(doc, "daily_report.py tự sinh báo cáo Markdown/HTML hàng ngày.")
    bullet(doc, "Kibana dashboard hiển thị findings thành quyết định giám sát.")

    # ---- 3. Tính năng ----
    h1(doc, "3. Tính năng chính")
    f_list = [
        "Ingest-pipeline enrichment: tự phân loại attack class tự động cho mọi request.",
        f"{n} detection rules kiểu Sigma, ánh xạ MITRE ATT&CK.",
        "Tương quan đa nguồn: nginx + UFW firewall + SSH auth (R-013/R-014/R-015).",
        "Giám sát Integrity endpoint (FIM): Security 4663 (R-016) + Sysmon FileCreate "
        "(R-017, event 11) + Sysmon process-launch — kiểm chứng Startup/persistence (R-018).",
        "Hàng đợi case bền vững (siem-findings) — hết cảnh báo trùng lặp.",
        "Triage workflow + auto false-positive pass.",
        "Dashboard Kibana + báo cáo daily tự động.",
        "Giám sát liên tục qua cron/Task Scheduler.",
    ]
    for f in f_list:
        bullet(doc, f)

    # ---- 4. Detection rules ----
    h1(doc, f"4. Detection Rules ({id_span})")
    para(doc, f"{n} rule bao phủ từ chữ ký đơn-request đến tương quan tần suất, chuỗi tấn công, "
         "đa nguồn và FIM endpoint. Tất cả ánh xạ MITRE ATT&CK.")

    tab = doc.add_table(rows=1, cols=5)
    tab.style = "Light Grid Accent 1"
    tab.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr = tab.rows[0].cells
    for i, htxt in enumerate(["ID", "Title", "Sev", "Class", "Source"]):
        hdr[i].text = htxt
        for p in hdr[i].paragraphs:
            for rr in p.runs:
                rr.bold = True
    for rule in rules:
        rid = rule["id"]
        cells = tab.add_row().cells
        row = (rid, rule.get("title", ""), sev_label(rule.get("severity", "")),
               rule.get("attack_class", ""), SOURCE.get(rid, ""))
        for i, val in enumerate(row):
            cells[i].text = val
    para(doc, "")
    para(doc, "Giá trị gia tăng cốt lõi: tương quan — đơn nguồn (R-011/R-012), đa nguồn "
              "(R-013/R-015) xuyên nginx + UFW + SSH, và in-host FIM (R-016/017/018) nối nguồn "
              "Windows — mà chỉ WAF lớp-7 không cung cấp được.")

    # ---- 5. Dashboard ----
    h1(doc, "5. Kibana Dashboard (SOC_OVERVIEW)")
    para(doc, "Dashboard gồm 7 panel kiểu pie/tagcloud (hạn chế render của Kibana 8.12 qua API): "
         "Severity, Rule, Attack Class, MITRE Tactic, Status, SSH Top IPs, UFW Top IPs — cửa sổ 24h.")
    para(doc, "Số liệu mẫu (24h gần nhất — cập nhật thủ công; báo cáo không nối ES để chạy offline):", bold=True)
    bullet(doc, "Severity: Mixed nginx + Windows — chiếm ưu thế SSH brute-force (credential-access) "
                "và FIM (defense-evasion).")
    bullet(doc, "Rule nổi bật từ nginx: R-014 SSH brute-force, R-005 info disclosure, R-008 admin-panel "
                "scan; từ endpoint: R-016/R-017 file-integrity.")
    bullet(doc, "MITRE Tactic chính: credential-access, defense-evasion, initial-access.")
    bullet(doc, "Status: findings đều open → triage qua triage.py.")

    # ---- 6. Thành phần repo ----
    h1(doc, "6. Cấu trúc repo")
    for line in [
        "AGENTS.md — hướng dẫn cho AI coding agent",
        "ingest-pipelines/nginx-soc-enrich.json — pipeline phân loại tấn công + ECS + GeoIP",
        f"rules/detection-rules.yaml — {n} rule Sigma-style",
        "transforms/freq-detection-by-ip.json — R-011 frequency transform",
        "scripts/ — deploy.sh, apply_rules.py, triage.py, daily_report.py, build_dashboard.py, "
        "alerts.py (draft), build_project_report.py, apply_rules (18 rule engine), "
        "enable_file_integrity_audit.ps1",
        "dashboards/ — soc_overview.ndjson + SOC_OVERVIEW.md",
        "sysmon/ — Sysmon FIM config (binaries gitignored EULA)",
        "reports/ — báo cáo hàng ngày và báo cáo tổng thể",
    ]:
        bullet(doc, line)

    # ---- 7. Roadmap / hạn chế ----
    h1(doc, "7. Roadmap & hạn chế đã biết")
    for item in [
        "Backend-direct bypass: log chỉ bắt traffic qua nginx (80/443); tấn công trực tiếp vào backend "
        "(DVWA:8080/JuiceShop) không vào nginx-access. Hướng: cài Filebeat trong container backend.",
        "Enrichment backfill: log cũ chưa được enrich ngược; chỉ enrich từ thời điểm chạy.",
        "R-016 cần bật File System audit (auditpol + SACL) trên client; R-017/018 cần Sysmon "
        "installed với channel 'Microsoft-Windows-Sysmon/Operational' bật trong winlogbeat (như AGENTS.md).",
        "Alerting: alerts.py là bản nháp — cần nối Slack/Telegram webhook (SOC_ALERT_* env).",
        "Dashboard: chỉ pie/tagcloud qua API; bar/line/metric cần vẽ tay trên UI Kibana.",
    ]:
        bullet(doc, item)

    # ---- 8. Kết luận ----
    h1(doc, "8. Kết luận")
    para(doc, f"SOC-ify hoàn thành mục tiêu là một SOC thu nhỏ dạy được và có thể tái tạo trên "
         f"Azure + Elasticsearch 8.12 + Kibana, không phụ thuộc giấy phép trả phí. Hệ thống đi "
         f"từ phát hiện ({n} rule: nginx web + UFW/SSH đa nguồn + Windows FIM) đến triage và báo cáo, "
         f"là nền tảng học SIEM/SOC và portfolio công việc vững chắc. Không phải SIEM sản xuất thương mại.")

    doc.save(OUT)
    print(f"Saved: {os.path.abspath(OUT)}  ({n} rules)")


if __name__ == "__main__":
    build()
