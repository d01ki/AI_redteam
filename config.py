"""設定管理モジュール."""
from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()

# LLM設定
MODEL_NAME = os.environ.get("MODEL_NAME", "claude-sonnet-4-5-20250929")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# API Keys
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# デフォルト設定
DEFAULT_TARGET = os.environ.get("TARGET_IP", "log4j")
DEFAULT_DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
MAX_EXPLOIT_ATTEMPTS = int(os.environ.get("MAX_EXPLOIT_ATTEMPTS", "5"))

# Web Server
PORT = int(os.environ.get("PORT", 8080))