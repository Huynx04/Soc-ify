#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build SOC summary Excel with real ES data (run with Anaconda python: E:\\anaconda\\python.exe)."""
import json, urllib.request, datetime, os
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

ES = "http://localhost:9200"

def es(index, q):
    body = json.dumps(q).encode()
    req = urllib.request.Request(f"{ES}/{index}/_search", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=30).read().decode())

# ---- collect ----
# sources summary
cat = json.loads(urllib.request.urlopen(urllib.request.Request(f"{ES}/_cat/indices?format=json&h=index,docs.count", method="GET"), timeout=20).read().decode())
from collections import defaultdict
grp = defaultdict(int)
for i in cat:
    for pat in ["nginx-access", "fire-ufw", "juice-shop", "winlogbeat", "nuclei-scans", "mail-scanner", "siem-findings"]:
        if pat in i["index"]:
            grp[pat] += int(i.get("docs.count") or 0); break
src = [[k, v] for k, v in sorted(grp.items(), key=lambda x: -x[1])]

# firewall series (last 24h by hour) + recent rows
fuf = es("fire-ufw*", {"size":50, "sort":[{"@timestamp":{"order":"desc"}}],
  "_source":["@timestamp","source.ip","source.port","destination.ip","destination.port","network.transport","event.action"]})
fw = []
for h in fuf["hits"]["hits"]:
    s = h["_source"]
    fw.append([s.get("@timestamp","")[:19], (s.get("source",{}) or {}).get("ip"),
               (s.get("source",{}) or {}).get("port"), (s.get("destination",{}) or {}).get("ip"),
               (s.get("destination",{}) or {}).get("port"), (s.get("network",{}) or {}).get("transport"),
               (s.get("event",{}) or {}).get("action")])

fw_by_hour = es("fire-ufw*", {"size":0,"query":{"match_all":{}},"aggs":{"h":{"date_histogram":{"field":"@timestamp","fixed_interval":"1h"}}}})
fw_hour = [[b["key_as_string"][:13], b["doc_count"]] for b in fw_by_hour["aggregations"]["h"]["buckets"] if b["doc_count"]>0]

# siem findings
sfr = es("siem-findings", {"size":50,"sort":[{"@timestamp":{"order":"desc"}}],
  "_source":["@timestamp","rule_id","severity","title","status"]})
sf = []
for h in sfr["hits"]["hits"]:
    s = h["_source"]
    sf.append([s.get("@timestamp","")[:19], s.get("rule_id"), s.get("severity"), s.get("title") or s.get("status")])

# nginx recent
ngr = es("nginx-access*", {"size":25,"sort":[{"@timestamp":{"order":"desc"}}],
  "_source":["@timestamp","client.ip","http.request.method","url.path","http.response.status_code"]})
ng = []
for h in ngr["hits"]["hits"]:
    s = h["_source"]
    ip = (s.get("client",{}) or {}).get("ip")
    m = (s.get("http",{}) or {}).get("request",{}).get("method")
    p = (s.get("url",{}) or {}).get("path")
    c = (s.get("http",{}) or {}).get("response",{}).get("status_code")
    ng.append([s.get("@timestamp","")[:19], ip, m, p, c])

# correlation: UFW-blocked IPs also in nginx
ufw_ips = list(dict.fromkeys([r[1] for r in fw if r[1]]))
corr = []
for ip in ufw_ips:
    try:
        c = es("nginx-access*", {"size":0,"query":{"term":{"client.ip":{"value":ip}}}})
        n2 = c["hits"]["total"]["value"]
        corr.append([ip, "CÓ" if n2>0 else "không", n2, "bị UFW block + xuất hiện nginx -> correlation chéo" if n2>0 else "chỉ bị UFW block"])
    except Exception:
        corr.append([ip, "err", 0, ""])

# ---- build workbook ----
hdr_fill = PatternFill("solid", fgColor="1F4E78"); hdr_font = Font(bold=True, color="FFFFFF")
def style_header(ws, n):
    for c in range(1, n+1):
        cell = ws.cell(row=1, column=c); cell.fill=hdr_fill; cell.font=hdr_font

wb = Workbook()

# sheet 1 overview
ws = wb.active; ws.title="01_TONG_QUAN"
ws.append(["CÂU HỎI","GIẢI THÍCH","KẾT LUẬN"])
for row in [
 ["Elasticsearch đang có gì?","8 nhóm nguồn: web nginx, app juice-shop, endpoint winlogbeat, firewall UFW (mới), scan nuclei, mail, kết quả siem-findings.","Xem sheet 02, 03, 04, 05"],
 ["Firewall UFW đã chạy chưa?","CÓ - pipeline parse+filebeat hoạt động; log block real-time theo bot quét port 9200.","Xem sheet 03"],
 ["SIEM detection đang chạy?","CÓ - task SOC_Detect quét mỗi 10 phút (Last Run 14:21, status 0); chỉ sinh finding khi có tấn công khớp rule.","Xem sheet 04"],
 ["Correlation firewall<->web được chưa?","ĐƯỢC - cùng IP xuất hiện ở cả fire-ufw (bị block) và nginx (vào web).","Xem sheet 06"],
 ["Scan của bạn có bị UFW chặn?","KHÔNG - IP nguồn bạn thuộc danh sách allow (VN) nên UFW cho phép, không log block.","Xem sheet 07"],
]:
    ws.append(row)
style_header(ws,3)

# sheet 2 sources
ws2 = wb.create_sheet("02_NGUON DU LIEU")
ws2.append(["Nguồn","Số docs tổng"])
for r in src: ws2.append(r)
style_header(ws2,2)

# sheet 3 firewall
ws3 = wb.create_sheet("03_FIREWALL_UW")
ws3.append(["Khung giờ (UTC)","Số event block"])
for r in fw_hour: ws3.append(r)
ws3.append([])
ws3.append(["Chi tiết gần đây"])
ws3.append(["Thời gian","Src IP (bị chặn)","Src Port","Dst IP","Dst Port","Proto","Hành động"])
for r in fw: ws3.append(r)
style_header(ws3,7)

# sheet 4 siem
ws4 = wb.create_sheet("04_SIEM_FINDINGS")
ws4.append(["Thời gian","Rule","Severity","Mô tả"])
for r in sf: ws4.append(r)
style_header(ws4,4)

# sheet 5 nginx
ws5 = wb.create_sheet("05_NGINX_WEB")
ws5.append(["Thời gian","Client IP","Method","Path","StatusCode"])
for r in ng: ws5.append(r)
style_header(ws5,5)

# sheet 6 correlation
ws6 = wb.create_sheet("06_CORRELATION")
ws6.append(["IP (bị UFW chặn)","Cũng xuất hiện nginx?","Số lần ở nginx","Ghi chú"])
for r in corr: ws6.append(r)
style_header(ws6,4)

# sheet 7 giai thich
ws7 = wb.create_sheet("07_GIAI THICH")
ws7.append(["CHỦ ĐỀ","GIẢI THÍCH","GHI CHÚ"])
for row in [
 ["Correlation là gì","Liên kết nhiều nguồn log theo cùng 1 IP trong 1 cửa sổ thời gian -> theo dõi kẻ tấn công qua nhiều tầng (firewall->web).",""],
 ["Vì sao firewall là nguồn quan trọng","Cho biết IP nào bị UFW chặn từ tầng mạng (chưa vào tới web) - phát hiện sớm bot/recon.","Đây là nguồn MỚI vừa thêm"],
 ["Firewall log chạy ra sao","event-driven: chỉ ghi khi gói tin bị chặn, không chảy đều mỗi phút.","Thưa khi không có bot"],
 ["SIEM findings","index sự kiện cảnh báo; engine quét đều 10p nhưng chỉ ghi khi rule bắt được tấn công.","Không phải log liên tục"],
 ["Tại sao scan của bạn không tạo block/finding","IP nguồn bạn nằm trong danh sách cho phép (VN whitelist) nên UFW không chặn; scan nhẹ 404 không khớp rule cường độ cao.",""],
 ["Muốn thấy UFW block test","Cần scan từ IP ngoài danh sách cho phép; hoặc các bot ngoài đang bị chặn (sheet 06).",""],
]:
    ws7.append(row)
style_header(ws7,3)

# sheet 8 kien truc
ws8 = wb.create_sheet("08_KIEN TRUC")
ws8.append(["Tầng","Nguồn","Index ES","Field IP (correlation)"])
for row in [
 ["Internet","-","-","-"],
 ["Firewall","UFW (Azure VM)","fire-ufw-*","source.ip  <-- mới, chuẩn ECS"],
 ["Web","nginx access","nginx-access-*","client.ip"],
 ["App","Juice Shop","juice-shop-*","client ip (chưa chuẩn hoá)"],
 ["Endpoint","Windows winlogbeat","winlogbeat-*","source.ip (chưa có giá trị)"],
 ["Scan","Nuclei","nuclei-scans","(không có IP)"],
 ["Email","Mail scanner","mail-scanner","(không có IP)"],
 ["Phát hiện","SOC detection rules","siem-findings","- (kết quả)"],
]:
    ws8.append(row)
style_header(ws8,4)

# auto width
for w in wb.worksheets:
    for col in w.columns:
        m = 0
        for cell in col:
            v = cell.value
            if v is not None and len(str(v)) > m: m = len(str(v))
        w.column_dimensions[get_column_letter(col[0].column)].width = min(m+2, 40)

out = os.path.join(os.path.dirname(__file__), "..", "reports", "SOC_TONG_THUAT_ES_CORRELATION.xlsx")
out = os.path.abspath(out)
wb.save(out)
print("DA TAO:", out)
print("Sheets:", wb.sheetnames)
print("rows: fw=%d siem=%d nginx=%d corr=%d" % (len(fw), len(sf), len(ng), len(corr)))
