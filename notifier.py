"""
notifier.py — In ra console, ghi file log chi tiết, gửi Telegram
"""

import json
import os
import requests
from datetime import datetime
from html import escape

from config_loader import load_config


# ============================================================
# Màu terminal
# ============================================================
class Color:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


SEVERITY_COLOR = {
    "CRITICAL": Color.RED,
    "HIGH":     Color.RED,
    "MEDIUM":   Color.YELLOW,
    "LOW":      Color.GREEN,
}


# ============================================================
# 1. In ra console (gọn)
# ============================================================
def print_console(result: dict):
    severity = result.get("severity", "MEDIUM")
    color = SEVERITY_COLOR.get(severity, Color.CYAN)
    ts = datetime.now().strftime("%H:%M:%S")

    print(f"\n{color}{Color.BOLD}{'='*55}{Color.RESET}")
    print(f"{color}{Color.BOLD}[{ts}] CẢNH BÁO AN NINH — {severity}{Color.RESET}")
    print(f"{color}{'='*55}{Color.RESET}")
    print(f"  IP nguồn   : {Color.BOLD}{result.get('src_ip', 'N/A')}{Color.RESET}")
    print(f"  Tấn công   : {result.get('attack_type', 'N/A')}")
    print(f"  MITRE      : {result.get('mitre_technique', 'N/A')}")
    print(f"  Còn active : {'⚠ CÒN KẾT NỐI' if result.get('still_active') else 'Không'}")
    print(f"  Whitelist  : {'✓ Có (không block)' if result.get('is_whitelisted') else 'Không'}")
    print(f"\n  {Color.BOLD}Tóm tắt:{Color.RESET} {result.get('summary', '')}")
    print(f"\n  {Color.BOLD}Đề xuất:{Color.RESET} {result.get('recommendation', '')}")

    if result.get("recommend_block"):
        print(f"\n  {Color.RED}{Color.BOLD}→ AGENT ĐỀ XUẤT BLOCK IP NÀY{Color.RESET}")
    print(f"{color}{'='*55}{Color.RESET}")


# ============================================================
# 2. Ghi file log chi tiết (JSON)
# ============================================================
def write_detail_log(result: dict, raw_alert: dict):
    cfg = load_config()
    log_path = cfg["logging"]["detail_log"]

    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    record = {
        "logged_at": datetime.utcnow().isoformat(),
        "analysis": result,
        "raw_alert": raw_alert
    }

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_action_log(action: str, src_ip: str, success: bool, detail: str = ""):
    cfg = load_config()
    log_path = cfg["logging"]["action_log"]

    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    record = {
        "logged_at": datetime.utcnow().isoformat(),
        "action": action,
        "src_ip": src_ip,
        "success": success,
        "detail": detail
    }

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ============================================================
# 3. Gửi Telegram với nút BLOCK / Bỏ qua
# ============================================================
def send_telegram(result: dict):
    cfg = load_config()
    tg = cfg["telegram"]
    bot_token = tg["bot_token"]
    chat_id = tg["chat_id"]

    severity = result.get("severity", "MEDIUM")
    src_ip = result.get("src_ip", "N/A")

    # Icon theo severity
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

    text = (
        f"{icon} <b>CẢNH BÁO AN NINH — {escape(str(severity))}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 <b>IP nguồn:</b> <code>{escape(str(src_ip))}</code>\n"
        f"⚔️ <b>Tấn công:</b> {escape(str(result.get('attack_type', 'N/A')))}\n"
        f"🎯 <b>MITRE:</b> {escape(str(result.get('mitre_technique', 'N/A')))}\n"
        f"🔌 <b>Còn active:</b> {'⚠ CÒN KẾT NỐI' if result.get('still_active') else 'Không'}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📋 <b>Tóm tắt:</b> {escape(str(result.get('summary', '')))}\n\n"
        f"💡 <b>Đề xuất:</b> {escape(str(result.get('recommendation', '')))}"
    )

    # Chỉ hiện nút BLOCK nếu agent đề xuất block và IP không trong whitelist
    if result.get("recommend_block") and not result.get("is_whitelisted"):
        keyboard = {
            "inline_keyboard": [[
                {
                    "text": f"🚫 BLOCK {src_ip}",
                    "callback_data": f"block:{src_ip}"
                },
                {
                    "text": "❌ Bỏ qua",
                    "callback_data": f"ignore:{src_ip}"
                }
            ]]
        }
    else:
        keyboard = {
            "inline_keyboard": [[
                {
                    "text": "👁 Theo dõi",
                    "callback_data": f"ignore:{src_ip}"
                }
            ]]
        }

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "reply_markup": json.dumps(keyboard)
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        if not resp.ok:
            print(f"[Telegram] Lỗi gửi: {resp.text}")
    except requests.RequestException as e:
        print(f"[Telegram] Không gửi được: {e}")


# ============================================================
# Hàm tổng hợp — gọi 1 lần cho mỗi alert xử lý xong
# ============================================================
def notify_all(result: dict, raw_alert: dict):
    print_console(result)
    try:
        write_detail_log(result, raw_alert)
    except OSError as e:
        print(f"[Log] Không ghi được agent_detail.log: {e}")
    send_telegram(result)
