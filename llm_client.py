"""
llm_client.py — Thu thập dữ liệu bằng Python và gửi cho DeepSeek phân tích
"""

import ipaddress
import json
import re
from openai import OpenAI
from urllib.parse import urlparse

from config_loader import load_config
from tools import (
    check_ip_whitelist,
    get_active_connections,
    query_detail_logs,
    query_recent_logs,
)


SYSTEM_PROMPT = """Bạn là một AI Agent chuyên phân tích cảnh báo an ninh mạng trong hệ thống Mini-SOC.

Nhiệm vụ của bạn:
1. Phân tích alert được cung cấp
2. Dùng kết quả kiểm tra đã được cung cấp để đưa ra nhận định và đề xuất hành động

Quy tắc bắt buộc:
- Dữ liệu whitelist, lịch sử alert và kết nối active được lấy từ hệ thống; không tự suy đoán hoặc sửa các dữ liệu này
- Nếu IP nằm trong whitelist: KHÔNG đề xuất block, chỉ cảnh báo để theo dõi
- src_ip là IP nguồn của flow; với tiến trình audit outbound, dùng agent.ip làm IP cục bộ và không coi đó mặc định là hacker
- destination_ip là IP đích/remote/C2 trích từ trường đích hoặc URL nếu có
- Đề xuất block chỉ áp dụng cho BLOCK TARGET IP và BLOCK DIRECTION được cung cấp; không đổi hướng hoặc thay IP mục tiêu
- Chỉ trả về JSON hợp lệ, không dùng Markdown/code fence hoặc thêm văn bản ngoài JSON
- summary tối đa 2 câu; detail tối đa 3 gạch đầu dòng ngắn, không lặp lại toàn bộ lịch sử alert

Định dạng output cuối cùng (JSON, không giải thích thêm):
{
    "src_ip": "IP nguồn của flow; với tiến trình outbound dùng IP agent cục bộ",
    "destination_ip": "IP đích/C2 nếu xác định được; nếu không, ghi unknown",
    "attack_type": "Loại tấn công",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "mitre_technique": "Txx - Tên kỹ thuật",
    "summary": "Mô tả ngắn gọn tình huống (1-2 câu)",
    "still_active": true/false/null",
    "is_whitelisted": true/false,
    "recommend_block": true/false,
    "recommendation": "Hành động đề xuất cụ thể",
    "detail": "Tối đa 3 gạch đầu dòng ngắn"
}"""


def run_agent(alert: dict) -> dict:
    """
    Thu thập dữ liệu bằng Python, sau đó gửi alert và dữ liệu cho LLM
    để phân tích trong một lần gọi.

    Trả về dict kết quả phân tích từ LLM.
    """
    cfg = load_config()
    llm_cfg = cfg["llm"]

    client = OpenAI(
        api_key=llm_cfg["api_key"],
        base_url=llm_cfg["base_url"]
    )

    src_ip = _extract_source_ip(alert)
    destination_ip = _extract_destination_ip(alert)
    is_outbound_flow = _is_outbound_alert(alert)
    block_direction, block_target_ip = _get_block_candidate(alert)
    if block_target_ip == "unknown":
        tool_results = {
            "whitelist": {
                "ip": block_target_ip,
                "is_whitelisted": False,
                "reason": "Không xác định được IP mục tiêu để block"
            },
            "recent_logs": {
                "ip": block_target_ip,
                "count": 0,
                "alert_types": [],
                "first_seen": None,
                "last_seen": None,
                "raw_alerts": []
            },
            "active_connections": {
                "ip": block_target_ip,
                "active_count": 0,
                "connections": [],
                "still_active": None
            },
        }
    else:
        tool_results = {
            "whitelist": check_ip_whitelist(block_target_ip),
            "recent_logs": query_recent_logs(block_target_ip, direction=block_direction),
            "active_connections": (
                {"ip": block_target_ip, "active_count": 0, "connections": [], "still_active": None}
                if is_outbound_flow
                else get_active_connections(block_target_ip)
            ),
        }

    user_message = _build_user_message(
        alert, tool_results, block_direction, block_target_ip
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message}
    ]

    response = client.chat.completions.create(
        model=llm_cfg["model"],
        messages=messages,
        max_tokens=llm_cfg["max_tokens"],
        temperature=llm_cfg["temperature"]
    )

    content = response.choices[0].message.content or ""
    result = _parse_final_output(content, alert)
    result["src_ip"] = src_ip
    result["destination_ip"] = destination_ip
    result["block_direction"] = block_direction
    result["block_target_ip"] = block_target_ip

    whitelist_result = tool_results["whitelist"]
    is_whitelisted = whitelist_result.get("is_whitelisted")
    if isinstance(is_whitelisted, bool):
        result["is_whitelisted"] = is_whitelisted
    else:
        result["recommend_block"] = False
        result["recommendation"] = (
            "Không xác minh được whitelist; cần kiểm tra thủ công trước khi block."
        )

    if result["is_whitelisted"]:
        result["recommend_block"] = False
        result["recommendation"] = "IP mục tiêu nằm trong whitelist; không block, chỉ cảnh báo và theo dõi."
    elif block_target_ip == "unknown":
        result["recommend_block"] = False
        result["still_active"] = None

    active_result = tool_results["active_connections"]
    still_active = active_result.get("still_active")
    if isinstance(still_active, bool):
        result["still_active"] = still_active
    else:
        result["still_active"] = None

    return result


def _extract_source_ip(alert: dict) -> str:
    """Lấy IP nguồn của flow; với tiến trình outbound dùng IP agent làm IP cục bộ."""
    data = alert.get("data", {})
    source_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or alert.get("src_ip")
    )
    if source_ip:
        return source_ip

    if _is_outbound_alert(alert):
        agent_ip = alert.get("agent", {}).get("ip")
        if isinstance(agent_ip, str):
            try:
                return str(ipaddress.ip_address(agent_ip))
            except ValueError:
                pass

    return "unknown"


def _extract_destination_ip(alert: dict) -> str:
    """Lấy IP đích từ field mạng hoặc URL trong dữ liệu tiến trình/audit."""
    data = alert.get("data", {})
    if not isinstance(data, dict):
        return "unknown"

    for key in ("dstip", "dst_ip", "destination_ip"):
        value = data.get(key)
        if isinstance(value, str):
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                pass

    audit = data.get("audit", {})
    execve = audit.get("execve", {}) if isinstance(audit, dict) else {}
    values = list(execve.values()) if isinstance(execve, dict) else []
    full_log = alert.get("full_log", "")
    if values and isinstance(full_log, str):
        values.append(full_log)

    for value in values:
        if not isinstance(value, str):
            continue
        for match in re.finditer(r"https?://[^\s\"'<>]+", value, re.IGNORECASE):
            try:
                hostname = urlparse(match.group(0).rstrip(".,;:)]}")).hostname
            except ValueError:
                continue
            if hostname:
                try:
                    return str(ipaddress.ip_address(hostname))
                except ValueError:
                    continue

    return "unknown"


def _is_outbound_alert(alert: dict) -> bool:
    data = alert.get("data", {})
    audit = data.get("audit", {}) if isinstance(data, dict) else {}
    execve = audit.get("execve", {}) if isinstance(audit, dict) else {}
    values = list(execve.values()) if isinstance(execve, dict) else []
    full_log = alert.get("full_log", "")
    if values and isinstance(full_log, str):
        values.append(full_log)
    if any(
        isinstance(value, str)
        and re.search(r"https?://", value, re.IGNORECASE)
        for value in values
    ):
        return True

    agent_ip = alert.get("agent", {}).get("ip")
    source_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or alert.get("src_ip")
    ) if isinstance(data, dict) else alert.get("src_ip")
    if not isinstance(agent_ip, str) or not isinstance(source_ip, str):
        return False

    try:
        return (
            ipaddress.ip_address(agent_ip) == ipaddress.ip_address(source_ip)
            and _extract_destination_ip(alert) != "unknown"
        )
    except ValueError:
        return False


def _get_block_candidate(alert: dict) -> tuple[str, str]:
    if _is_outbound_alert(alert):
        destination_ip = _extract_destination_ip(alert)
        if destination_ip != "unknown":
            return "destination", destination_ip
        return "none", "unknown"

    source_ip = _extract_source_ip(alert)
    if source_ip != "unknown":
        return "source", source_ip
    return "none", "unknown"


def _build_user_message(
    alert: dict,
    tool_results: dict,
    block_direction: str,
    block_target_ip: str
) -> str:
    """Tạo message gồm alert và dữ liệu đã thu thập bằng Python."""
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    agent = alert.get("agent", {})
    src_ip = _extract_source_ip(alert)
    destination_ip = _extract_destination_ip(alert)

    return f"""Phân tích alert an ninh sau đây:

ALERT ID     : {alert.get('id', 'N/A')}
TIMESTAMP    : {alert.get('timestamp', 'N/A')}
RULE ID      : {rule.get('id', 'N/A')}
RULE LEVEL   : {rule.get('level', 'N/A')}
DESCRIPTION  : {rule.get('description', 'N/A')}
GROUPS       : {', '.join(rule.get('groups', []))}
SOURCE IP    : {src_ip}
DESTINATION IP / C2: {destination_ip}
BLOCK DIRECTION: {block_direction}
BLOCK TARGET IP: {block_target_ip}
AGENT NAME   : {agent.get('name', 'N/A')}
AGENT IP     : {agent.get('ip', 'N/A')}
FULL DATA    : {json.dumps(data, ensure_ascii=False)}

KẾT QUẢ KIỂM TRA HỆ THỐNG:
{json.dumps(tool_results, ensure_ascii=False)}

Hãy phân tích và đề xuất hành động phù hợp."""


def _parse_final_output(content: str, alert: dict) -> dict:
    """
    Parse JSON output từ LLM. Nếu không parse được thì trả fallback.
    """
    # Thử tìm JSON trong content
    content = content.strip()
    start = content.find("{")
    end = content.rfind("}") + 1

    if start != -1 and end > start:
        try:
            result = json.loads(content[start:end])
            # Đảm bảo có đủ trường
            result.setdefault("src_ip", _extract_source_ip(alert))
            result.setdefault("destination_ip", _extract_destination_ip(alert))
            direction, target_ip = _get_block_candidate(alert)
            result.setdefault("block_direction", direction)
            result.setdefault("block_target_ip", target_ip)
            result.setdefault("attack_type", alert.get("rule", {}).get("description", "Unknown"))
            result.setdefault("severity", "MEDIUM")
            result.setdefault("mitre_technique", _extract_alert_mitre(alert))
            if result["mitre_technique"] in (None, "", "Unknown"):
                result["mitre_technique"] = _extract_alert_mitre(alert)
            result.setdefault("summary", "Không có tóm tắt")
            result.setdefault("still_active", False)
            result.setdefault("is_whitelisted", False)
            result.setdefault("recommend_block", False)
            result.setdefault("recommendation", "Theo dõi thêm")
            result.setdefault("detail", content)
            return result
        except json.JSONDecodeError:
            pass

    # Fallback to alert metadata when the LLM response is unavailable or invalid.
    return {
        "src_ip": _extract_source_ip(alert),
        "destination_ip": _extract_destination_ip(alert),
        "block_direction": _get_block_candidate(alert)[0],
        "block_target_ip": _get_block_candidate(alert)[1],
        "attack_type": alert.get("rule", {}).get("description", "Unknown"),
        "severity": "MEDIUM",
        "mitre_technique": _extract_alert_mitre(alert),
        "summary": "AI không phân tích được phản hồi; hiển thị dữ liệu từ rule Wazuh.",
        "still_active": None,
        "is_whitelisted": False,
        "recommend_block": False,
        "recommendation": "Kiểm tra thủ công",
        "detail": content
    }


def _extract_alert_mitre(alert: dict) -> str:
    """Lấy MITRE ATT&CK từ metadata của rule Wazuh."""
    mitre = alert.get("rule", {}).get("mitre", {})
    if not isinstance(mitre, dict):
        return "Unknown"

    raw_ids = mitre.get("id", [])
    raw_techniques = mitre.get("technique", [])
    ids = [raw_ids] if isinstance(raw_ids, str) else raw_ids
    techniques = [raw_techniques] if isinstance(raw_techniques, str) else raw_techniques
    if not isinstance(ids, list):
        ids = []
    if not isinstance(techniques, list):
        techniques = []

    formatted = []
    for index, technique_id in enumerate(ids):
        if not isinstance(technique_id, str) or not technique_id.strip():
            continue
        technique_name = techniques[index] if index < len(techniques) else ""
        if isinstance(technique_name, str) and technique_name.strip():
            formatted.append(f"{technique_id} - {technique_name}")
        else:
            formatted.append(technique_id)

    return "; ".join(formatted) if formatted else "Unknown"


ADMIN_CHAT_SYSTEM_PROMPT = """Bạn là trợ lý AI của hệ thống Mini-SOC trên Telegram, hỗ trợ admin tra cứu lịch sử alert và xử lý sự cố.

Quy tắc bắt buộc:
- Chỉ trả lời dựa trên dữ liệu hệ thống được cung cấp; không bịa thêm IP, alert hay trạng thái kết nối.
- Nếu không tìm thấy dữ liệu cho IP hoặc alert mà admin hỏi, hãy nói rõ là chưa có dữ liệu.
- Nếu admin yêu cầu block một IP:
  + Nếu IP nằm trong whitelist hoặc không hợp lệ: KHÔNG đề xuất block, giải thích lý do rõ ràng (action = "none").
  + Nếu IP hợp lệ và không nằm trong whitelist: đặt action = "confirm_block" và target_ip = IP đó để hệ thống gửi nút xác nhận cho admin bấm.

Trả về JSON đúng định dạng sau (không giải thích thêm):
{
    "reply": "Câu trả lời ngắn gọn, rõ ràng bằng tiếng Việt cho admin",
    "action": "none|confirm_block",
    "target_ip": "IP cần xác nhận block hoặc null"
}"""


def handle_admin_query(user_text: str) -> dict:
    """
    Xử lý tin nhắn hỏi đáp / yêu cầu từ admin trên Telegram.
    Python tự trích xuất IP hoặc alert ID từ câu hỏi, thu thập dữ liệu
    từ tools.py và agent_detail.log rồi gửi cho LLM tổng hợp trả lời.
    """
    cfg = load_config()
    llm_cfg = cfg["llm"]

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_text)
    target_ip = None
    if ip_match:
        candidate = ip_match.group(0)
        try:
            ipaddress.ip_address(candidate)
            target_ip = candidate
        except ValueError:
            target_ip = None

    # Tìm alert_id nếu không có IP (vd: 1732620000.12345)
    alert_id_match = re.search(r"\b\d{8,}\.\d+\b", user_text)
    target_id = alert_id_match.group(0) if alert_id_match else ""

    context: dict = {}
    if target_ip:
        context["whitelist"] = check_ip_whitelist(target_ip)
        context["recent_logs"] = query_recent_logs(target_ip)
        context["active_connections"] = get_active_connections(target_ip)
        context["detail_history"] = query_detail_logs(target=target_ip, limit=5)
    elif target_id:
        context["detail_history"] = query_detail_logs(target=target_id, limit=5)
    else:
        context["recent_detail_history"] = query_detail_logs(target="", limit=5)

    client = OpenAI(
        api_key=llm_cfg["api_key"],
        base_url=llm_cfg["base_url"]
    )

    user_message = (
        f"YÊU CẦU CỦA ADMIN:\n{user_text}\n\n"
        f"DỮ LIỆU HỆ THỐNG THU THẬP ĐƯỢC:\n"
        f"{json.dumps(context, ensure_ascii=False)}"
    )

    response = client.chat.completions.create(
        model=llm_cfg["model"],
        messages=[
            {"role": "system", "content": ADMIN_CHAT_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        max_tokens=llm_cfg["max_tokens"],
        temperature=llm_cfg["temperature"],
    )

    content = (response.choices[0].message.content or "").strip()
    parsed = _parse_admin_output(content)

    # Guardrail: kiểm tra lại target_ip và whitelist bằng Python
    if parsed["action"] == "confirm_block":
        ip_to_block = parsed.get("target_ip") or target_ip
        if not ip_to_block:
            parsed["action"] = "none"
            parsed["target_ip"] = None
        else:
            try:
                ipaddress.ip_address(ip_to_block)
                wl = check_ip_whitelist(ip_to_block)
                if wl.get("is_whitelisted"):
                    parsed["action"] = "none"
                    parsed["target_ip"] = None
                    parsed["reply"] = (
                        f"Không thể block IP {ip_to_block}: {wl.get('reason', 'IP nằm trong whitelist')}."
                    )
                else:
                    parsed["target_ip"] = ip_to_block
            except ValueError:
                parsed["action"] = "none"
                parsed["target_ip"] = None

    return parsed


def _parse_admin_output(content: str) -> dict:
    """Parse JSON phản hồi cho admin chat, fallback về text thô nếu lỗi."""
    start = content.find("{")
    end = content.rfind("}") + 1
    if start != -1 and end > start:
        try:
            data = json.loads(content[start:end])
            return {
                "reply": str(data.get("reply") or content),
                "action": data.get("action") if data.get("action") in ("none", "confirm_block") else "none",
                "target_ip": data.get("target_ip"),
            }
        except json.JSONDecodeError:
            pass

    return {
        "reply": content or "Không có phản hồi từ AI.",
        "action": "none",
        "target_ip": None,
    }
