"""
main.py — Vòng lặp chính: tail alerts.json realtime, lọc, gửi Agent xử lý
"""

import json
import os
import sys
import time
import signal
import threading
from datetime import datetime

from config_loader import load_config
from llm_client import _extract_source_ip, run_agent
from notifier import notify_all
from responder import TelegramResponder


# ============================================================
# Deduplication — tránh xử lý cùng 1 alert nhiều lần
# ============================================================
class AlertDeduplicator:    
    def __init__(self, ttl_seconds: int = 60):
        self._seen: dict[str, float] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def is_new(self, alert_id: str) -> bool:
        if self._ttl <= 0:
            return True
        now = time.time()
        with self._lock:
            # Dọn dẹp các entry cũ
            self._seen = {
                k: v for k, v in self._seen.items()
                if now - v < self._ttl
            }
            if alert_id in self._seen:
                return False
            self._seen[alert_id] = now
            return True


# ============================================================
# Tail file realtime
# ============================================================
class AlertTailer:
    """
    Đọc file alerts.json theo kiểu tail -f:
    - Mở file, seek đến cuối
    - Mỗi vòng lặp đọc các dòng mới
    - Nếu file bị rotate (inode thay đổi), mở lại từ đầu
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file = None
        self._inode = None
        self._open()

    def _open(self):
        if self._file:
            self._file.close()
        self._file = open(self.filepath, "r", encoding="utf-8")
        # Seek về cuối để chỉ đọc alert mới
        self._file.seek(0, 2)
        self._inode = os.stat(self.filepath).st_ino
        print(f"[Tailer] Đang theo dõi: {self.filepath}")

    def _check_rotate(self):
        """Kiểm tra file có bị rotate không."""
        try:
            current_inode = os.stat(self.filepath).st_ino
            if current_inode != self._inode:
                print("[Tailer] File đã rotate, mở lại...")
                self._open()
        except FileNotFoundError:
            time.sleep(2)

    def readlines(self):
        """Trả về các dòng mới từ file."""
        self._check_rotate()
        lines = []
        while True:
            line = self._file.readline()
            if not line:
                break
            line = line.strip()
            if line:
                lines.append(line)
        return lines

    def close(self):
        if self._file:
            self._file.close()


# ============================================================
# Xử lý từng alert
# ============================================================
def process_alert(
    alert: dict,
    min_level: int,
    dedup: AlertDeduplicator,
    cooldown: AlertDeduplicator,
    ignore_rules: set[str],
    ignore_groups: set[str]
):
    """
    Kiểm tra level, rule bỏ qua, dedup, cooldown theo IP, rồi chạy Agent nếu hợp lệ.
    Chạy trong thread riêng để không block vòng lặp chính.
    """
    rule = alert.get("rule", {})
    level = rule.get("level", 0)

    # Lọc theo level
    try:
        level = int(level)
    except (ValueError, TypeError):
        return

    if level < min_level:
        return

    # Lọc bỏ qua theo rule.id
    rule_id = str(rule.get("id", ""))
    if rule_id in ignore_rules:
        return

    # Lọc bỏ qua theo rule.groups
    rule_groups = set(str(g).lower() for g in rule.get("groups", []))
    if rule_groups & ignore_groups:
        return

    # Deduplication theo alert id hoặc nội dung
    alert_id = alert.get("id") or f"{alert.get('timestamp','')}_{rule.get('id','')}_{alert.get('agent',{}).get('ip','')}"
    if not dedup.is_new(alert_id):
        return

    # Cooldown theo (IP nguồn, rule_id): cùng IP + cùng loại tấn công mới bỏ qua, đổi loại tấn công vẫn báo
    src_ip = _extract_source_ip(alert)
    cooldown_key = f"ip:{src_ip}|rule:{rule_id}"
    if not cooldown.is_new(cooldown_key):
        return

    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] Alert mới — Level {level} — {rule.get('description', 'N/A')}")

    # Chạy Agent trong thread riêng
    def _run():
        try:
            result = run_agent(alert)
            notify_all(result, alert)
        except Exception as e:
            print(f"[Agent] Lỗi xử lý alert: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()


# ============================================================
# Main loop
# ============================================================
def main():
    cfg = load_config()
    alerts_file = cfg["wazuh"]["alerts_file"]
    min_level = cfg["wazuh"]["min_level"]
    cooldown_seconds = int(cfg["wazuh"].get("cooldown_seconds", 300))
    ignore_rules = set(str(r) for r in cfg["wazuh"].get("ignore_rules", []))
    ignore_groups = set(str(g).lower() for g in cfg["wazuh"].get("ignore_groups", []))

    # Kiểm tra file tồn tại
    if not os.path.exists(alerts_file):
        print(f"[ERROR] Không tìm thấy file alerts: {alerts_file}")
        print("Hãy kiểm tra Wazuh Manager đang chạy và đường dẫn trong config.yaml")
        sys.exit(1)

    print("=" * 55)
    print("  Mini-SOC AI Agent đang khởi động...")
    print(f"  File alerts : {alerts_file}")
    print(f"  Min level   : {min_level}")
    print(f"  Cooldown    : {cooldown_seconds}s / IP")
    if ignore_rules:
        print(f"  Ignore rules: {', '.join(sorted(ignore_rules))}")
    if ignore_groups:
        print(f"  Ignore grps : {', '.join(sorted(ignore_groups))}")
    print(f"  LLM         : {cfg['llm']['model']}")
    print("=" * 55)

    # Khởi động Telegram responder
    responder = TelegramResponder()
    responder.start()

    # Khởi động tailer
    tailer = AlertTailer(alerts_file)
    dedup = AlertDeduplicator(ttl_seconds=60)
    cooldown = AlertDeduplicator(ttl_seconds=cooldown_seconds)

    # Graceful shutdown
    _shutdown = threading.Event()

    def _signal_handler(sig, frame):
        print("\n[Main] Nhận tín hiệu dừng, đang thoát...")
        _shutdown.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    print("[Main] Đang chờ alert mới...\n")

    try:
        while not _shutdown.is_set():
            lines = tailer.readlines()

            for line in lines:
                try:
                    alert = json.loads(line)
                    process_alert(alert, min_level, dedup, cooldown, ignore_rules, ignore_groups)
                except json.JSONDecodeError:
                    continue

            # Poll mỗi 1 giây
            time.sleep(1)

    finally:
        tailer.close()
        responder.stop()
        print("[Main] Agent đã dừng.")


if __name__ == "__main__":
    main()
