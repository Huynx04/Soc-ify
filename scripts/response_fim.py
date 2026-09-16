#!/usr/bin/env python3
"""
SOC-ify — Response Playbook: FIM (R-019) auto-quarantine
=========================================================
CHẠY TRÊN VM (nginx host) — vì phải đụng file thật trên filesystem đó.
Đọc findings từ ES (qua Tailscale), rồi cách ly file tại chỗ.

THIẾT KẾ AN TOÀN (quan trọng):
  - KHÔNG XOÁ gì. Chỉ CÁCH LY (move vào /var/quarantine/) — luôn khôi phục được.
  - DRY-RUN mặc định: chỉ in ra hành động sẽ làm, không đụng file.
  - Chỉ xử lý action=file_created (file MỚI) — đây là dấu hiệu rõ nhất của
    webshell/persistence. KHÔNG tự động sửa file bị modified (rủi ro hơn,
    cần người xem vì có thể là update hợp lệ).
  - Có WHITELIST: file/path hợp lệ không bị đụng.
  - Giới hạn MAX_ACTIONS mỗi lần chạy (tránh xử lý hàng loạt nếu false positive).

CÁCH DÙNG (trên VM):
  python3 response_fim.py --dry-run          # xem sẽ làm gì (mặc định)
  python3 response_fim.py --apply            # thực thi cách ly
  python3 response_fim.py --range now-2h --apply
  python3 response_fim.py --list-quarantine  # xem đã cách ly gì
  python3 response_fim.py --restore <name>   # khôi phục 1 file

CHẠY ĐỊNH KỲ: cron mỗi 15 phút, hoặc gọi ngay sau apply_rules.py
"""
import argparse, datetime, hashlib, json, os, re, shutil, subprocess, sys

try:
    from elasticsearch import Elasticsearch
except ImportError:
    sys.exit("[!] cần elasticsearch-py: pip install 'elasticsearch>=8.12,<9'")

ES_HOST = os.environ.get("SOC_ES_HOST", "http://100.117.2.50:9200")
ES_USER = os.environ.get("SOC_ES_USER", "")
ES_PASS = os.environ.get("SOC_ES_PASS", "")
FINDINGS = os.environ.get("SOC_FINDINGS", "siem-findings")
QUARANTINE = os.environ.get("SOC_QUARANTINE", "/var/quarantine")
MAX_ACTIONS = int(os.environ.get("SOC_RESPONSE_MAX", "10"))

# Chỉ những path này mới được tự động cách ly (khớp với AIDE_SENSITIVE_PATHS của R-019)
PROTECTED_PREFIXES = (
    "/usr/share/nginx/html/",
    "/var/www/",
    "/etc/nginx/",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
)

# KHÔNG bao giờ đụng (file hợp lệ / chỉ đọc / do hệ thống quản)
WHITELIST = (
    "/usr/share/nginx/html/index.html",
    "/usr/share/nginx/html/index.nginx-debian.html",
    "/etc/nginx/mime.types",
)


def es_client():
    kw = {"hosts": [ES_HOST]}
    if ES_USER:
        kw["basic_auth"] = (ES_USER, ES_PASS)
    return Elasticsearch(**kw)


def fetch_fim_created(es, rng):
    """Lấy các finding R-019 action=file_created chưa xử lý."""
    body = {
        "size": 200,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": rng}}},
            {"match_phrase": {"rule_title": "AIDE File Integrity"}},
        ], "must_not": [{"term": {"response.action": "quarantined"}}]}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["url.path", "url.query", "severity", "first_seen", "rule_id", "_id"],
    }
    try:
        res = es.search(index=FINDINGS, body=body)
    except Exception as e:
        print(f"[!] ES query lỗi: {e}")
        return []
    out = []
    for h in res["hits"]["hits"]:
        s = h["_source"]
        q = s.get("url.query", "") or ""
        if "action=file_created" not in q:
            continue                      # chỉ xử lý file MỚI
        out.append({"_id": h["_id"], "path": s.get("url.path", ""),
                    "sev": s.get("severity"), "ts": s.get("first_seen")})
    return out


def is_actionable(path):
    if not path or not path.startswith("/"):
        return False, "path không hợp lệ"
    if path in WHITELIST:
        return False, "whitelist"
    if not any(path.startswith(p) for p in PROTECTED_PREFIXES):
        return False, "ngoài phạm vi tự động"
    return True, "ok"


def quarantine(path, apply=False):
    """Cách ly file: move sang QUARANTINE (KHÔNG xoá). Trả về (ok, dest, note)."""
    if not os.path.exists(path):
        return False, None, "file không tồn tại (đã bị xử lý?)"
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    try:
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return False, None, f"không đọc được: {e}"

    safe = path.strip("/").replace("/", "__")
    dest = os.path.join(QUARANTINE, f"{stamp}__{sha[:12]}__{safe}")
    if not apply:
        return True, dest, f"[dry-run] sẽ move -> {dest} (sha256={sha[:12]})"
    try:
        os.makedirs(QUARANTINE, exist_ok=True)
        shutil.move(path, dest)
        meta = {"original_path": path, "quarantined_at": stamp, "sha256": sha,
                "host": "Nginx", "rule": "R-019"}
        with open(dest + ".meta.json", "w") as f:
            json.dump(meta, f, indent=2)
        return True, dest, f"đã cách ly -> {dest}"
    except Exception as e:
        return False, None, f"move lỗi: {e}"


def mark_finding(es, fid, dest, apply=False):
    if not apply or not fid:
        return
    try:
        es.update(index=FINDINGS, id=fid, body={"doc": {
            "response.action": "quarantined",
            "response.quarantine_path": dest,
            "response.at": datetime.datetime.utcnow().isoformat() + "Z",
        }})
    except Exception as e:
        print(f"    (cảnh báo: không update được finding {fid}: {e})")


def list_quarantine():
    if not os.path.isdir(QUARANTINE):
        print("(chưa có gì trong quarantine)")
        return
    for f in sorted(os.listdir(QUARANTINE)):
        if f.endswith(".meta.json"):
            continue
        meta = f + ".meta.json"
        info = ""
        if os.path.exists(os.path.join(QUARANTINE, meta)):
            m = json.load(open(os.path.join(QUARANTINE, meta)))
            info = f"  <- {m['original_path']}"
        print(f"  {f}{info}")


def restore(name):
    src = os.path.join(QUARANTINE, name)
    meta = src + ".meta.json"
    if not os.path.exists(meta):
        sys.exit(f"[!] không thấy {meta}")
    m = json.load(open(meta))
    dest = m["original_path"]
    print(f"[*] khôi phục {src}\n    -> {dest}")
    shutil.move(src, dest)
    os.remove(meta)
    print("[*] xong")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--range", default="now-2h", help="cửa sổ tìm finding (mặc định now-2h)")
    ap.add_argument("--apply", action="store_true", help="THỰC THI (mặc định dry-run)")
    ap.add_argument("--list-quarantine", action="store_true")
    ap.add_argument("--restore", metavar="NAME")
    a = ap.parse_args()

    if a.list_quarantine:
        list_quarantine(); return
    if a.restore:
        restore(a.restore); return

    mode = "APPLY" if a.apply else "DRY-RUN"
    print(f"[*] SOC-ify FIM Response Playbook [{mode}] range={a.range}")
    if not a.apply:
        print("    (dry-run: không đụng file nào. Dùng --apply để thực thi)")

    es = es_client()
    if not es.ping():
        sys.exit(f"[!] không kết nối được ES {ES_HOST}")

    findings = fetch_fim_created(es, a.range)
    print(f"[*] finding R-019 file_created chưa xử lý: {len(findings)}")

    acted = 0
    for f in findings:
        ok, why = is_actionable(f["path"])
        if not ok:
            print(f"    SKIP  {f['path']}  ({why})")
            continue
        if acted >= MAX_ACTIONS:
            print(f"    (đã đạt MAX_ACTIONS={MAX_ACTIONS}, dừng để tránh xử lý hàng loạt)")
            break
        ok, dest, note = quarantine(f["path"], apply=a.apply)
        print(f"    {'OK  ' if ok else 'FAIL'}  {f['path']}")
        print(f"          {note}")
        if ok:
            acted += 1
            mark_finding(es, f["_id"], dest, apply=a.apply)

    print(f"[*] tổng hành động: {acted} ({'đã thực thi' if a.apply else 'dry-run, chưa thực thi'})")
    if not a.apply and acted:
        print("[!] Chạy lại với --apply để cách ly thật.")


if __name__ == "__main__":
    main()
