# Mini-SOC AI Agent

Hệ thống Mini-SOC tự động theo dõi cảnh báo từ **Wazuh** (`alerts.json`), thu thập ngữ cảnh hệ thống bằng Python, gửi cho **LLM** (DeepSeek / OpenAI-compatible API) phân tích, cảnh báo qua **Telegram** và hỗ trợ **chặn IP qua `nftables`** trực tiếp từ Telegram.

---

## Kiến trúc & Luồng hoạt động

```text
[Wazuh alerts.json]
       │ (1. Tail realtime & lọc level >= min_level, chống trùng 60s)
       ▼
    main.py
       │ (2. Python tự kiểm tra trước khi gọi AI)
       ▼
    tools.py (check_ip_whitelist, query_recent_logs, get_active_connections)
       │ (3. Đóng gói dữ liệu gửi LLM phân tích + hậu kiểm an toàn)
       ▼
  llm_client.py
       │ (4. Xuất kết quả)
       ▼
   notifier.py (Console + agent_detail.log + Telegram kèm nút bấm)
       │ (5. Admin bấm nút hoặc nhắn tin trên Telegram)
       ▼
  responder.py (nftables drop IP + agent_actions.log + hỏi đáp AI)
```

---

## Cấu trúc thư mục

| File | Vai trò |
| :--- | :--- |
| `main.py` | Vòng lặp chính theo dõi `alerts.json` realtime (`AlertTailer`), lọc `rule.level`, chống trùng lặp (`AlertDeduplicator`) và khởi chạy `TelegramResponder`. |
| `tools.py` | Các hàm kiểm tra hệ thống: kiểm tra whitelist/CIDR (`check_ip_whitelist`), truy vấn log gần đây (`query_recent_logs`), kiểm tra kết nối đang mở bằng `ss` (`get_active_connections`) và đọc lịch sử chi tiết (`query_detail_logs`). |
| `llm_client.py` | Trích xuất IP nguồn, chạy các hàm trong `tools.py`, gửi dữ liệu cho LLM phân tích (`run_agent`) và xử lý câu hỏi/yêu cầu từ admin qua Telegram (`handle_admin_query`). |
| `notifier.py` | In cảnh báo ra console, ghi log chi tiết JSON (`agent_detail.log`) và gửi thông báo kèm nút bấm tương tác về Telegram. |
| `responder.py` | Lắng nghe nút bấm (`callback_query`) và tin nhắn (`message`) từ Telegram, thực thi chặn IP bằng `nftables` (`block_ip`) và ghi log hành động (`agent_actions.log`). |
| `config_loader.py` | Đọc `config.yaml` và tự động nạp các secret từ file `.env` / biến môi trường. |
| `config.yaml` | Cấu hình Wazuh, LLM, whitelist, đường dẫn log và `nftables`. |
| `.env.example` | File mẫu chứa các biến môi trường bí mật. |
| `requirements.txt` | Danh sách thư viện Python cần thiết. |

---

## Yêu cầu hệ thống

- Hệ điều hành Linux (Gateway/Server chạy Wazuh Manager, có sẵn lệnh `ss` và `nft` của `nftables`).
- Python 3.10+.
- Quyền đọc file `/var/ossec/logs/alerts/alerts.json`, quyền ghi `/var/log/mini-soc/`, và quyền chạy `nft` (thường chạy dưới quyền `root` hoặc user có `CAP_NET_ADMIN`).

---

## Cài đặt & Cấu hình

### 1. Cài đặt thư viện Python
```bash
pip install -r requirements.txt
```

### 2. Tạo file `.env` từ mẫu
```bash
cp .env.example .env
```
Mở `.env` và điền thông tin thật của bạn (file `.env` đã được thêm vào `.gitignore` để tránh lộ key khi đẩy lên GitHub):
```env
DEEPSEEK_API_KEY=your_deepseek_api_key_here
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
TELEGRAM_CHAT_ID=your_telegram_chat_id_here
```

### 3. Kiểm tra `config.yaml`
Chỉnh sửa các thông số phù hợp với hệ thống của bạn trong `config.yaml`:
- `wazuh.alerts_file`: Đường dẫn file `alerts.json` của Wazuh (mặc định `/var/ossec/logs/alerts/alerts.json`).
- `wazuh.min_level`: Ngưỡng level tối thiểu để xử lý alert (mặc định `10`).
- `wazuh.lookback_minutes`: Số phút nhìn lại lịch sử alert cho cùng một IP (mặc định `10`).
- `wazuh.cooldown_seconds`: Gộp alert cùng IP và cùng nhóm sự kiện trong khoảng thời gian này; nhóm sự kiện mới hoặc alert có level cao hơn vẫn được xử lý để không bỏ sót hành vi mới/escalation (mặc định `300`).
- `llm`: `base_url`, `model`, `max_tokens`, `temperature` (hỗ trợ DeepSeek hoặc bất kỳ endpoint tương thích OpenAI nào).
- `whitelist`: Danh sách IP hoặc subnet CIDR (ví dụ `192.168.1.0/24`) không bao giờ bị chặn.
- `logging`: Đường dẫn `detail_log` và `action_log`.
- `nftables`: Cấu hình bảng/chain `nftables`.

---

## Khởi chạy

```bash
python3 main.py
```

Khi khởi động thành công, hệ thống sẽ:
1. Bắt đầu theo dõi các alert mới ghi vào `alerts.json`.
2. Bật luồng lắng nghe lệnh và nút bấm từ Telegram.

---

## Tương tác qua Telegram

Bot chỉ phản hồi đúng `TELEGRAM_CHAT_ID` đã cấu hình:

- **Bấm nút dưới cảnh báo:**
  - `🚫 BLOCK <ip>`: Chặn ngay IP nguồn bằng `nftables` và ghi nhận vào `agent_actions.log`.
  - `❌ Bỏ qua` / `👁 Theo dõi`: Ghi nhận bỏ qua vào `agent_actions.log`.
- **Gửi lệnh trực tiếp:**
  - `/help` hoặc `/start`: Xem hướng dẫn nhanh.
  - `/block <ip>`: Kiểm tra IP hợp lệ + whitelist rồi thực thi chặn ngay qua `nftables`.
  - `/unblock <ip>`: Gỡ các rule block do Mini-SOC tạo cho IP đó.
  - `/detail [ip hoặc alert_id]`: Xem tối đa 3 bản ghi phân tích chi tiết gần nhất từ `agent_detail.log` (bỏ trống tham số để xem 3 bản ghi mới nhất).
- **Nhắn tin tự nhiên:**
  - Ví dụ: *"Kiểm tra giúp tôi IP 1.2.3.4"*, *"Lịch sử alert gần đây thế nào?"*, *"Block giúp tôi IP 1.2.3.4"*.
  - Python sẽ tự trích xuất IP/`alert_id`, thu thập dữ liệu từ log và `ss`, gửi AI tổng hợp trả lời. Nếu có yêu cầu block IP hợp lệ (không nằm trong whitelist), bot sẽ gửi kèm nút **`🚫 Xác nhận BLOCK <ip>`** để bạn bấm xác nhận.

`/unblock` chỉ gỡ rule có dấu nhận diện do Mini-SOC thêm từ phiên bản này trở đi. Các rule block được tạo bởi phiên bản cũ không có dấu nhận diện nên cần gỡ thủ công để tránh xóa nhầm rule firewall khác.
