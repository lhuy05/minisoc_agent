"""
config_loader.py — Đọc config.yaml và nạp các secret từ file .env / biến môi trường
"""

import os
import yaml


def _load_dotenv(env_path: str):
    """Đọc file .env (nếu có) và nạp vào os.environ."""
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)


def load_config() -> dict:
    """Đọc config.yaml và ghi đè các API key/token từ biến môi trường hoặc .env."""
    base = os.path.dirname(os.path.abspath(__file__))
    _load_dotenv(os.path.join(base, ".env"))

    with open(os.path.join(base, "config.yaml"), "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    if os.environ.get("DEEPSEEK_API_KEY"):
        cfg.setdefault("llm", {})["api_key"] = os.environ["DEEPSEEK_API_KEY"]

    if os.environ.get("TELEGRAM_BOT_TOKEN"):
        cfg.setdefault("telegram", {})["bot_token"] = os.environ["TELEGRAM_BOT_TOKEN"]

    if os.environ.get("TELEGRAM_CHAT_ID"):
        cfg.setdefault("telegram", {})["chat_id"] = os.environ["TELEGRAM_CHAT_ID"]

    return cfg
