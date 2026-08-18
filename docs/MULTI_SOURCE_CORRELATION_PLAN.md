# SOC-ify: Multi-Source Correlation Plan (Đề xuất)

> Draft — chưa triển khai gì trên VM/ES. Bạn xem rồi chọn hướng, tôi sẽ làm sau.

## 1. Mục tiêu

Đưa **nhiều nguồn log** (firewall, web, endpoint, ...) về Elasticsearch, **chuẩn hóa về ECS**,
rồi **correlation chéo theo IP/thời gian**: theo dõi một IP attacker đi qua nhiều tầng.

## 2. Hiện trạng các nguồn (đã kiểm tra #query thực tế)

| Nguồn | Index | Field IP | Timestamp | ECS? |
|---|---|---|---|---|
| Web (Azure nginx)  | `nginx-access*`   | `client.ip` / `source.ip` | `@timestamp` | ✅ chuẩn |
| Endpoint Windows   | `winlogbeat`      | `source.ip`             | `@timestamp` | ✅ chuẩn |
| App (Juice Shop)   | `juice-shop*`     | field riêng (app)       | `@timestamp` | ⚠️ chưa |
| Scan (Nuclei)      | `nuclei-scans`    | **KHÔNG** (chỉ `target`) | `@timestamp` | ❌ |
| Email scanner      | `mail-scanner`    | **KHÔNG**              | `timestamp`  | ❌ |
| **Firewall (chưa có)** | —            | —                        | —            | — |

**Rào cản #1:** `mail-scanner` + `nuclei-scans` không có field IP dùng chung → không correlation
theo IP được. Cần chuẩn hóa về ECS (`source.ip`, `destination.ip`, `@timestamp`).

**Rào cản #2:** chưa có firewall log.

## 3. Nguồn firewall khả thi trên Azure VM

**Lựa chọn rẻ + ship được qua Filebeat hiện có (giống nginx):**

- **A. UFW firewall log** (đã cài `ufw` trên VM) → syslog `/var/log/ufw.log`
  → Filebeat **system module** (hoặc riêng) → `firewall-*`. Cho biết **IP nào bị UFW chặn/drop**
  (mức firewall). ⭐ Nên bắt đầu ở đây: rẻ, hiệu quả, bắt kẻ quét port không vào tới nginx.
- **B. Azure NSG flow log** (cloud firewall, traffic-level) → cần bật qua Azure Monitor →
  xuất có độ trễ (~10-15 phút), phức tạp hơn. Có `source.ip`, `destination.ip` đầy đủ.
- **C. Windows Defender Firewall (local máy bạn)** → qua winlogbeat Windows Security channel.

## 4. Kiến trúc correlation đa-nguồn

```
Internet
   |  --(bị UFW chặn/drop)--> [UFW firewall log]   fire-ufw-*  ⭐ nguồn mới
   |  --(vào tới nginx)-----> [nginx access log]   nginx-access-*
   |                          └── explode/attack    siem-findings
   └------------Quan sát cùng IP-------------> [winlogbeat Windows]   winlogbeat-*
                                              [juice-shop app]        juice-shop-*
```

**Correlation rule mong muốn (ví dụ):**
- Cùng một `source.ip` xuất hiện ở **UFW (bị chặn)** + **nginx (attempt)** + **winlogbeat (event)**
  trong cửa sổ vd 15 phút → flag **attack chain / nhiều tầng**.

**Cách hiện thực (Elastic Basic-friendly, không cần paid):**
1. **ECS normalize** mọi nguồn về `source.ip`/`destination.ip`/`@timestamp` (ingest pipeline
   hoặc thêm field khi ship).
2. **Data view chung** trong Kibana (`nginx-access-*,fire-ufw-*,winlogbeat*,juice-shop-*`)
   → query/visualize chung 1 trục thời gian + filter theo IP.
3. **Correlation engine** (thuật toán như rule R-012, mở rộng cross-index): script quét nhiều
   index, gom theo `source.ip` trong window → ghi finding vào `siem-findings`.

## 5. Các bước triển khai (khi bạn chọn)

- [ ] Thêm **UFW log** → Filebeat trên VM → index `fire-ufw-*` (đụng VM).
- [ ] Chuẩn hóa `nuclei-scans`, `mail-scanner` thêm `source.ip` (tùy ý, có giá trị thấp).
- [ ] Tạo **data view chung** + dashboard "Multi-Source Correlation".
- [ ] Mở rộng detection: rule **cross-source attack chain** gom theo `source.ip`.

## 6. Cần bạn quyết định

Nhấc máy chọn giúp tôi (tôi không tự sửa VM khi bạn vắng):
1. Bắt đầu với **UFW firewall** (khuyến nghị, rẻ + ship qua Filebeat có sẵn) ?
2. Hay **Azure NSG flow log** (mạnh hơn, phức tạp hơn, có độ trễ) ?
3. Hay trước tiên chỉ cần **data view chung + dashboard** gộp các nguồn sẵn có
   (nginx + winlogbeat + juice-shop) để correlation xem được ngay, thêm firewall sau?
