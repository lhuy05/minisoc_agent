"""
responder.py — Lắng nghe callback từ Telegram, thực thi block IP qua nftables
"""

import ipaddress
import json
import re
import subprocess
import threading
import time
import requests

from config_loader import load_config
from llm_client import handle_admin_query
from notifier import write_action_log
from tools import check_ip_whitelist, query_detail_logs


_NFTABLES_RULE_COMMENT = "mini-soc-managed"


# ============================================================
# Block IP bằng nftables
# ============================================================
def block_ip(src_ip: str, direction: str = "source") -> tuple[bool, str]:
    """Block IP nguồn hoặc IP đích trên các chain nftables đã cấu hình."""
    if direction not in ("source", "destination"):
        msg = f"Hướng block không hợp lệ: {direction}"
        write_action_log("block_ip", src_ip, False, msg)
        return False, msg

    is_destination = direction == "destination"
    action = "block_destination_ip" if is_destination else "block_ip"
    addr_field = "daddr" if is_destination else "saddr"
    direction_label = "IP đích" if is_destination else "IP nguồn"

    try:
        ip_obj = ipaddress.ip_address(src_ip)
    except ValueError:
        msg = f"IP không hợp lệ: {src_ip}"
        write_action_log(action, src_ip, False, msg)
        return False, msg

    cfg = load_config()
    nft = cfg.get("nftables", {})
    family = nft.get("family", "inet")
    table = nft.get("table", "filter")
    if is_destination:
        chains = nft.get("destination_chains") or ["forward"]
    else:
        chains = nft.get("chains") or [nft.get("input_chain", "input")]
    addr_family = "ip6" if ip_obj.version == 6 else "ip"

    errors = []
    try:
        for chain in chains:
            cmd = [
                "sudo", "/usr/sbin/nft", "insert", "rule",
                family, table, chain,
                addr_family, addr_field, str(ip_obj),
                "drop", "comment", _NFTABLES_RULE_COMMENT
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                errors.append(f"{chain}: {result.stderr.strip()}")

        if not errors:
            msg = f"Đã block {direction_label} {ip_obj} trên chain {', '.join(chains)}"
            write_action_log(action, str(ip_obj), True, msg)
            _send_telegram_confirm(str(ip_obj), True, msg, direction=direction)
            return True, msg
        else:
            msg = f"nftables lỗi ({'; '.join(errors)})"
            write_action_log(action, str(ip_obj), False, msg)
            _send_telegram_confirm(str(ip_obj), False, msg, direction=direction)
            return False, msg

    except subprocess.TimeoutExpired:
        msg = "Lệnh nftables timeout"
        write_action_log(action, str(ip_obj), False, msg)
        return False, msg
    except Exception as e:
        msg = f"Lỗi: {str(e)}"
        write_action_log(action, str(ip_obj), False, msg)
        return False, msg


def unblock_ip(src_ip: str, direction: str = "source") -> tuple[bool, str]:
    """Gỡ rule block IP nguồn hoặc IP đích do Mini-SOC tạo."""
    if direction not in ("source", "destination"):
        msg = f"Hướng unblock không hợp lệ: {direction}"
        write_action_log("unblock_ip", src_ip, False, msg)
        return False, msg

    is_destination = direction == "destination"
    action = "unblock_destination_ip" if is_destination else "unblock_ip"
    addr_field = "daddr" if is_destination else "saddr"
    direction_label = "IP đích" if is_destination else "IP nguồn"

    try:
        ip_obj = ipaddress.ip_address(src_ip)
    except ValueError:
        msg = f"IP không hợp lệ: {src_ip}"
        write_action_log(action, src_ip, False, msg)
        return False, msg

    src_ip = str(ip_obj)
    cfg = load_config()
    nft = cfg.get("nftables", {})
    family = nft.get("family", "inet")
    table = nft.get("table", "filter")
    if is_destination:
        chains = nft.get("destination_chains") or ["forward"]
    else:
        chains = nft.get("chains") or [nft.get("input_chain", "input")]
    addr_family = "ip6" if ip_obj.version == 6 else "ip"
    rule_pattern = re.compile(
        rf'^\s*{addr_family}\s+{addr_field}\s+{re.escape(src_ip)}(?:/\d+)?'
        rf'\s+drop\s+comment\s+"{re.escape(_NFTABLES_RULE_COMMENT)}"'
        rf'\s+#\s*handle\s+(\d+)\s*$'
    )

    removed = 0
    errors = []
    for chain in chains:
        try:
            listed = subprocess.run(
                ["sudo", "/usr/sbin/nft", "-a", "list", "chain", family, table, chain],
                capture_output=True,
                text=True,
                timeout=10
            )
        except subprocess.TimeoutExpired:
            errors.append(f"{chain}: nft list timeout")
            continue
        except OSError as e:
            errors.append(f"{chain}: không chạy được nft: {e}")
            continue

        if listed.returncode != 0:
            errors.append(f"{chain}: {listed.stderr.strip()}")
            continue

        handles = []
        for line in listed.stdout.splitlines():
            match = rule_pattern.match(line)
            if match:
                handles.append(match.group(1))

        for handle in handles:
            try:
                result = subprocess.run(
                    ["sudo", "/usr/sbin/nft", "delete", "rule", family, table, chain, "handle", handle],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            except subprocess.TimeoutExpired:
                errors.append(f"{chain} handle {handle}: nft delete timeout")
                continue
            except OSError as e:
                errors.append(f"{chain} handle {handle}: không chạy được nft: {e}")
                continue

            if result.returncode != 0:
                errors.append(f"{chain} handle {handle}: {result.stderr.strip()}")
            else:
                removed += 1

    if errors:
        msg = f"Không gỡ được đầy đủ rule cho {direction_label} {src_ip}: {'; '.join(errors)}"
        write_action_log(action, src_ip, False, msg)
        return False, msg

    if not removed:
        msg = (
            f"Không tìm thấy rule block do Mini-SOC quản lý cho {direction_label} {src_ip}. "
            "Các rule cũ chưa có dấu nhận diện cần được xử lý thủ công."
        )
        write_action_log(action, src_ip, False, msg)
        return False, msg

    msg = f"Đã gỡ {removed} rule block do Mini-SOC quản lý cho {direction_label} {src_ip}"
    write_action_log(action, src_ip, True, msg)
    return True, msg


def _send_telegram_confirm(src_ip: str, success: bool, message: str, direction: str = "source"):
    """Gửi thông báo kết quả block về Telegram."""
    cfg = load_config()
    tg = cfg["telegram"]
    direction_label = "IP đích/C2" if direction == "destination" else "IP nguồn"

    if success:
        text = f"✅ *BLOCK THÀNH CÔNG*\n{direction_label} `{src_ip}` đã bị chặn bởi nftables."
    else:
        text = f"❌ *BLOCK THẤT BẠI*\n{direction_label} `{src_ip}` — Lỗi: {message}"

    url = f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage"
    try:
        requests.post(url, json={
            "chat_id": tg["chat_id"],
            "text": text,
            "parse_mode": "Markdown"
        }, timeout=10)
    except Exception:
        pass


# ============================================================
# Telegram Webhook polling — lắng nghe nút bấm của admin
# ============================================================
class TelegramResponder:
    def __init__(self):
        cfg = load_config()
        tg = cfg["telegram"]
        self.bot_token = tg["bot_token"]
        self.chat_id = str(tg["chat_id"])
        self.last_update_id = 0
        self._running = False
        self._thread = None

    def start(self):
        """Chạy polling trong background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        print("[Responder] Đang lắng nghe lệnh từ Telegram...")

    def stop(self):
        self._running = False

    def _poll_loop(self):
        url = f"https://api.telegram.org/bot{self.bot_token}/getUpdates"

        while self._running:
            try:
                resp = requests.get(url, params={
                    "offset": self.last_update_id + 1,
                    "timeout": 30,
                    "allowed_updates": json.dumps(["callback_query", "message"])
                }, timeout=35)

                if not resp.ok:
                    time.sleep(5)
                    continue

                data = resp.json()

                for update in data.get("result", []):
                    self.last_update_id = update["update_id"]
                    self._handle_update(update)

            except requests.RequestException:
                time.sleep(5)
            except Exception as e:
                print(f"[Responder] Lỗi polling: {e}")
                time.sleep(5)

    def _handle_update(self, update: dict):
        """Xử lý callback nút bấm hoặc tin nhắn văn bản từ admin trên Telegram."""
        callback = update.get("callback_query")
        if callback:
            self._handle_callback(callback)
            return

        message = update.get("message")
        if message:
            from_chat = str(message.get("chat", {}).get("id", ""))
            if from_chat != self.chat_id:
                return
            text = (message.get("text") or "").strip()
            if not text:
                return
            # Chạy trong thread riêng để không block vòng lặp polling
            threading.Thread(
                target=self._handle_text_message,
                args=(text,),
                daemon=True
            ).start()

    def _handle_callback(self, callback: dict):
        callback_id = callback["id"]
        data = callback.get("data", "")
        from_chat = str(callback.get("message", {}).get("chat", {}).get("id", ""))

        # Chỉ chấp nhận từ đúng chat_id
        if from_chat != self.chat_id:
            return

        # Trả lời callback để nút không bị loading mãi
        self._answer_callback(callback_id)

        block_callbacks = {
            "block": "source",
            "block-src": "source",
            "block-dst": "destination",
        }
        callback_action, separator, target_ip = data.partition(":")
        if separator and callback_action in block_callbacks:
            direction = block_callbacks[callback_action]
            whitelist = check_ip_whitelist(target_ip)
            if whitelist.get("is_whitelisted"):
                msg = f"Từ chối block `{target_ip}`: {whitelist.get('reason')}"
                self._send_reply(msg)
                print(f"\n[Responder] {msg}")
                return

            print(
                f"\n[Responder] Admin yêu cầu block {direction} IP: {target_ip}"
            )
            success, msg = block_ip(target_ip, direction=direction)
            status = "✅ Thành công" if success else "❌ Thất bại"
            print(f"[Responder] {status} — {msg}")

        elif data.startswith("ignore:"):
            src_ip = data.split(":", 1)[1]
            print(f"\n[Responder] Admin bỏ qua alert từ IP: {src_ip}")
            write_action_log("ignore", src_ip, True, "Admin chọn bỏ qua")

    def _handle_text_message(self, text: str):
        """Xử lý lệnh (/block, /detail, /help) hoặc câu hỏi tự nhiên cho AI Agent."""
        lower = text.lower()

        if lower in ("/start", "/help"):
            help_text = (
                "🤖 *Mini-SOC Assistant*\n"
                "• `/block <ip>` — Block IP nguồn (có kiểm tra whitelist)\n"
                "• `/block-src <ip>` — Block IP nguồn\n"
                "• `/block-dst <ip>` — Chặn traffic đi tới IP đích/C2 trên chain forward\n"
                "• `/unblock <ip>` — Gỡ các rule block do Mini-SOC tạo\n"
                "• `/unblock-src <ip>` — Gỡ rule block IP nguồn\n"
                "• `/unblock-dst <ip>` — Gỡ rule chặn IP đích/C2\n"
                "• `/detail [ip hoặc alert_id]` — Xem lịch sử chi tiết từ log\n"
                "• Hoặc nhắn tự nhiên (vd: _'Kiểm tra IP 1.2.3.4'_, _'Block giúp tôi IP 1.2.3.4'_)"
            )
            self._send_reply(help_text)
            return

        parts = text.split(maxsplit=1)
        command = parts[0].split("@", 1)[0].lower() if parts else ""
        block_directions = {
            "/block": "source",
            "/block-src": "source",
            "/block-dst": "destination",
        }
        if command in block_directions:
            if len(parts) < 2:
                self._send_reply(f"Cú pháp: `{command} <ip>`")
                return
            target_ip = parts[1].strip()
            try:
                ipaddress.ip_address(target_ip)
            except ValueError:
                self._send_reply(f"IP không hợp lệ: `{target_ip}`")
                return

            wl = check_ip_whitelist(target_ip)
            if wl.get("is_whitelisted"):
                self._send_reply(f"⛔ Từ chối block `{target_ip}`: {wl.get('reason')}")
                return

            direction = block_directions[command]
            print(f"\n[Responder] Admin dùng lệnh {command} IP: {target_ip}")
            block_ip(target_ip, direction=direction)
            return

        unblock_directions = {
            "/unblock": "source",
            "/unblock-src": "source",
            "/unblock-dst": "destination",
        }
        if command in unblock_directions:
            if len(parts) < 2:
                self._send_reply(f"Cú pháp: `{command} <ip>`")
                return

            target_ip = parts[1].strip()
            direction = unblock_directions[command]
            success, message = unblock_ip(target_ip, direction=direction)
            prefix = "✅" if success else "❌"
            self._send_reply(f"{prefix} {message}", parse_mode=None)
            return

        if lower.startswith("/detail"):
            parts = text.split(maxsplit=1)
            target = parts[1].strip() if len(parts) > 1 else ""
            res = query_detail_logs(target=target, limit=3)
            records = res.get("records", [])
            if not records:
                self._send_reply(f"Không tìm thấy lịch sử alert nào khớp `{target or 'gần đây'}`.")
                return

            lines = [f"📜 Lịch sử chi tiết ({len(records)}/{res.get('count', 0)} bản ghi):"]
            for r in records:
                a = r.get("analysis", {})
                lines.append(
                    f"\n• [{r.get('timestamp', 'N/A')}] ID: {r.get('alert_id', 'N/A')}\n"
                    f"  IP: {a.get('src_ip', 'N/A')} | Mức: {a.get('severity', 'N/A')}\n"
                    f"  Rule: {r.get('rule_description', 'N/A')}\n"
                    f"  Chi tiết: {a.get('detail', a.get('summary', 'N/A'))}"
                )
            self._send_reply("\n".join(lines), parse_mode=None)
            return

        # Tin nhắn tự nhiên → chuyển cho AI Agent
        try:
            result = handle_admin_query(text)
            reply = result.get("reply", "Không có phản hồi.")
            action = result.get("action", "none")
            target_ip = result.get("target_ip")

            keyboard = None
            if action == "confirm_block" and target_ip:
                keyboard = {
                    "inline_keyboard": [[
                        {"text": f"🚫 Xác nhận BLOCK {target_ip}", "callback_data": f"block:{target_ip}"},
                        {"text": "❌ Hủy", "callback_data": f"ignore:{target_ip}"},
                    ]]
                }

            self._send_reply(reply, reply_markup=keyboard, parse_mode=None)
        except Exception as e:
            self._send_reply(f"Lỗi khi xử lý yêu cầu: {e}", parse_mode=None)

    def _send_reply(self, text: str, reply_markup: dict | None = None, parse_mode: str | None = "Markdown"):
        """Gửi tin nhắn trả lời admin, tự cắt nếu vượt giới hạn Telegram."""
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        if len(text) > 4000:
            text = text[:3990] + "\n...(đã cắt bớt)"

        payload = {
            "chat_id": self.chat_id,
            "text": text,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup)

        try:
            resp = requests.post(url, json=payload, timeout=10)
            if not resp.ok and parse_mode:
                # Fallback gửi plain text nếu Markdown bị lỗi ký tự đặc biệt
                payload.pop("parse_mode", None)
                requests.post(url, json=payload, timeout=10)
        except Exception:
            pass

    def _answer_callback(self, callback_id: str):
        url = f"https://api.telegram.org/bot{self.bot_token}/answerCallbackQuery"
        try:
            requests.post(url, json={"callback_query_id": callback_id}, timeout=5)
        except Exception:
            pass
