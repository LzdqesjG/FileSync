# -*- coding: utf-8 -*-
"""全局配置：路径、常量、终端颜色。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_TITLE = "FileSync"
DEFAULT_SERVER_URL = "https://example.com/file_sync/api.php"

BASE_DIR = Path(__file__).resolve().parent.parent
LOCAL_DIR = BASE_DIR / "local_files"            # 工作区
KEY_DIR = BASE_DIR / "keys"
CONFIG_PATH = BASE_DIR / "client_config.json"
FILESYNC_IGNORE_PATH = BASE_DIR / ".filesyncignore"

CLIENT_PRIVATE_KEY = KEY_DIR / "client_private.pem"
SERVER_PUBLIC_KEY = KEY_DIR / "server_public.pem"

# 本地仓库
STATE_DIR = BASE_DIR / ".filesync"
OBJECTS_DIR = STATE_DIR / "objects"
BACKUP_DIR = STATE_DIR / "backups"
TRASH_DIR = STATE_DIR / "trash"
INDEX_PATH = STATE_DIR / "index.json"
COMMITS_PATH = STATE_DIR / "commits.json"

KEY_CLIENT_PRIVATE = "client_private.pem"
KEY_CLIENT_PUBLIC = "client_public.pem"
KEY_SERVER_PRIVATE = "server_private.pem"
KEY_SERVER_PUBLIC = "server_public.pem"

# 远端受保护路径（与 api.php 的 LG_PROTECTED 保持一致）
PROTECTED_REMOTE = {
    "api.php", "lg_config.php", "lg_keys", ".lg_keys",
    ".user.ini", ".htaccess", ".well-known", "404.html",
}

REQUEST_TIMEOUT = 60
MAX_DIFF_CELLS = 2_000_000

UPLOAD_CHUNK_BYTES = 2 * 1024 * 1024
UPLOAD_MIN_CHUNK = 128 * 1024

PROTOCOL_TAG = "lg1"
RESPONSE_TAG = "lgresp1"

# 终端颜色
_COLOR_ON = sys.stdout.isatty()
C_RESET = "\033[0m"
C_GREEN = "\033[32m"
C_RED = "\033[31m"
C_YELLOW = "\033[33m"
C_CYAN = "\033[36m"
C_DIM = "\033[2m"


def col(text: str, color: str) -> str:
    return f"{color}{text}{C_RESET}" if _COLOR_ON else text


def init_console() -> None:
    """Windows 10+ 打开 ANSI 转义支持"""
    if os.name == "nt":
        try:
            os.system("")
        except Exception:  # noqa: BLE001
            pass
