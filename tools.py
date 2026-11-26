"""
tools.py — Các tool cho Python gọi để thu thập thêm thông tin
"""

import ipaddress
import json
import re
import subprocess
from datetime import datetime, timedelta

from config_loader import load_config


# ============================================================
# Tool 1: Truy vấn các alert gần đây liên quan đến một IP
# ============================================================
def query_recent_logs(src_ip: str) -> dict:
    """
    Đọc lại alerts.json, tìm tất cả alert liên quan đến src_ip
    trong N phút gần nhất (config: lookback_minutes).

    Trả về:
        {
            "ip": str,
            "count": int,
            "alert_types": list[str],
            "first_seen": str,
            "last_seen": str,
            "raw_alerts": list[dict]   # tối đa 10 alert gần nhất
        }
    """
    cfg = load_config()
    alerts_file = cfg["wazuh"]["alerts_file"]
    lookback = cfg["wazuh"]["lookback_minutes"]
    cutoff = datetime.utcnow() - timedelta(minutes=lookback)

    matched = []

    try:
        with open(alerts_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Lấy IP nguồn từ các trường sự kiện mạng (không lấy agent.ip của victim)
                alert_ip = (
                    alert.get("data", {}).get("srcip")
                    or alert.get("data", {}).get("src_ip")
                    or alert.get("src_ip", "")
                )

                if alert_ip != src_ip:
                    continue

                # Kiểm tra thời gian
                ts_str = alert.get("timestamp", "")
                try:
                    ts = datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S")
                    if ts < cutoff:
                        continue
                except Exception:
                    pass  # Nếu parse lỗi, vẫn giữ alert

                matched.append(alert)

    except FileNotFoundError:
        return {"error": f"Không tìm thấy file: {alerts_file}"}

    if not matched:
        return {
            "ip": src_ip,
            "count": 0,
            "alert_types": [],
            "first_seen": None,
            "last_seen": None,
            "raw_alerts": []
        }

    alert_types = list({
        a.get("rule", {}).get("description", "Unknown")
        for a in matched
    })

    timestamps = []
    for a in matched:
        ts_str = a.get("timestamp", "")
        if ts_str:
            timestamps.append(ts_str[:19])

    timestamps.sort()

    return {
        "ip": src_ip,
        "count": len(matched),
        "alert_types": alert_types,
        "first_seen": timestamps[0] if timestamps else None,
        "last_seen": timestamps[-1] if timestamps else None,
        "raw_alerts": matched[-10:]   # 10 alert gần nhất
    }


# ============================================================
# Tool 2: Kiểm tra IP có trong whitelist không
# ============================================================
def check_ip_whitelist(src_ip: str) -> dict:
    """
    Kiểm tra IP có nằm trong danh sách whitelist config không.

    Trả về:
        {
            "ip": str,
            "is_whitelisted": bool,
            "reason": str
        }
    """
    cfg = load_config()
    whitelist = cfg.get("whitelist", [])

    if src_ip in whitelist:
        return {
            "ip": src_ip,
            "is_whitelisted": True,
            "reason": "IP nằm trong whitelist hệ thống"
        }

    try:
        ip_obj = ipaddress.ip_address(src_ip)
    except ValueError:
        return {
            "ip": src_ip,
            "is_whitelisted": False,
            "reason": "IP không hợp lệ hoặc không xác định"
        }

    for entry in whitelist:
        if "/" in str(entry):
            try:
                if ip_obj in ipaddress.ip_network(entry, strict=False):
                    return {
                        "ip": src_ip,
                        "is_whitelisted": True,
                        "reason": f"IP thuộc subnet {entry}"
                    }
            except ValueError:
                continue

    return {
        "ip": src_ip,
        "is_whitelisted": False,
        "reason": "IP không nằm trong whitelist"
    }


# ============================================================
# Tool 3: Kiểm tra kết nối active từ IP trên Gateway
# ============================================================
def get_active_connections(src_ip: str) -> dict:
    """
    Chạy lệnh ss trên Gateway để kiểm tra IP đang tấn công
    có còn kết nối active không.

    Trả về:
        {
            "ip": str,
            "active_count": int,
            "connections": list[str],
            "still_active": bool
        }
    """
    try:
        result = subprocess.run(
            ["ss", "-tn", "state", "established"],
            capture_output=True,
            text=True,
            timeout=5
        )
        lines = result.stdout.strip().split("\n")
        ip_pattern = re.compile(rf"(?<![0-9a-fA-F:.]){re.escape(src_ip)}(?![0-9a-fA-F:.])")

        connections = []
        for line in lines:
            if ip_pattern.search(line):
                connections.append(line.strip())

        return {
            "ip": src_ip,
            "active_count": len(connections),
            "connections": connections,
            "still_active": len(connections) > 0
        }

    except subprocess.TimeoutExpired:
        return {"error": "Lệnh ss timeout"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# Tool 4: Truy vấn lịch sử chi tiết từ agent_detail.log
# ============================================================
def query_detail_logs(target: str = "", limit: int = 5) -> dict:
    """
    Đọc file agent_detail.log để lấy lịch sử phân tích chi tiết các alert.
    Nếu có target (IP hoặc alert_id), lọc các bản ghi khớp target.
    Trả về tối đa `limit` bản ghi gần nhất.
    """
    cfg = load_config()
    log_path = cfg.get("logging", {}).get("detail_log", "")
    if not log_path:
        return {"error": "Chưa cấu hình logging.detail_log"}

    matched = []
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                analysis = record.get("analysis", {})
                raw_alert = record.get("raw_alert", {})

                if target:
                    src_ip = analysis.get("src_ip", "")
                    alert_id = str(raw_alert.get("id", ""))
                    if target != src_ip and target != alert_id:
                        continue

                matched.append({
                    "logged_at": record.get("logged_at"),
                    "alert_id": raw_alert.get("id"),
                    "timestamp": raw_alert.get("timestamp"),
                    "rule_id": raw_alert.get("rule", {}).get("id"),
                    "rule_level": raw_alert.get("rule", {}).get("level"),
                    "rule_description": raw_alert.get("rule", {}).get("description"),
                    "analysis": analysis,
                })
    except FileNotFoundError:
        return {"count": 0, "records": [], "note": f"Chưa có file log: {log_path}"}

    recent = matched[-limit:]
    return {
        "target": target or "all",
        "count": len(matched),
        "records": recent,
    }
