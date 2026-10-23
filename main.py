#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 FileSync - Client（仿 git 命令行）
================================================================================

把 local_files/ 当作工作区，用 git 的思维同步到远端站点：

    pull            拉取远端内容到 local_files/（覆盖前自动备份到 .filesync/backups/）
    add             暂存改动（默认全部；也可指定文件/目录）
    status          查看工作区 / 暂存区状态
    commit -m MSG   生成提交（自动生成 commit id）
    push            推送本地提交（文件内容 + 提交信息 + commit id）
    check ID        查看某次提交的详情（文件改动，绿色 +X / 红色 -Y）
    check list [N]  查看提交记录（默认最近 20 条，N 为条数）
    diff [PATH]     查看暂存区相对 HEAD 的行级差异
    rm PATH...      删除工作区文件（备份后标记为待提交删除）
    restore PATH    从某次提交恢复文件（默认 HEAD）
    --ping / --list / --genkeys [--force] / --url URL

本地状态目录 `.filesync/`：

    index.json      暂存区
    commits.json    本地提交历史（head / pushed / head_manifest / commits）
    objects/        按 sha256 存放的文件内容快照
    backups/        pull 覆盖前的自动备份
    trash/          rm 删除文件的备份

远端（FileSync_Server/api.php）在站点根维护 `.lgrepo/`：
提交历史、对象库与暂存区；在线编辑器（code/）共用同一套数据。

依赖： pip install requests cryptography
================================================================================
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import secrets
import shutil
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write("缺少依赖 requests，请先执行：pip install requests cryptography\n")
    raise

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:  # pragma: no cover
    sys.stderr.write("缺少依赖 cryptography，请先执行：pip install requests cryptography\n")
    raise


# ============================================================================
#  配置
# ============================================================================

APP_TITLE = "FileSync Client"
DEFAULT_SERVER_URL = "https://example.com/file_sync/api.php"

BASE_DIR = Path(__file__).resolve().parent
LOCAL_DIR = BASE_DIR / "local_files"            # 工作区（同步根）
KEY_DIR = BASE_DIR / "keys"
CONFIG_PATH = BASE_DIR / "client_config.json"
FILESYNC_IGNORE_PATH = BASE_DIR / ".filesyncignore"

CLIENT_PRIVATE_KEY = KEY_DIR / "client_private.pem"
SERVER_PUBLIC_KEY = KEY_DIR / "server_public.pem"

# 本地仓库状态
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


# ============================================================================
#  客户端配置
# ============================================================================

_URL_OVERRIDE: str | None = None


def load_client_config() -> dict:
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_client_config(config: dict) -> None:
    CONFIG_PATH.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def configured_server_url() -> str:
    if _URL_OVERRIDE:
        return _URL_OVERRIDE
    url = load_client_config().get("server_url")
    if isinstance(url, str) and url.strip():
        return url.strip()
    return DEFAULT_SERVER_URL


# ============================================================================
#  密钥
# ============================================================================

def _write_private(path: Path, pem: bytes) -> None:
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def keypair_pems() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub


def generate_keys(force: bool = False) -> list[str]:
    lines: list[str] = []
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    targets = [KEY_CLIENT_PRIVATE, KEY_CLIENT_PUBLIC, KEY_SERVER_PRIVATE, KEY_SERVER_PUBLIC]
    existing = [t for t in targets if (KEY_DIR / t).exists()]
    if existing and not force:
        lines.append(f"{KEY_DIR} 下已存在以下密钥，未做任何改动：")
        lines.extend(f"  - {name}" for name in existing)
        lines.append("如需重新生成，请使用 --force（旧密钥立即失效）。")
        return lines

    client_priv, client_pub = keypair_pems()
    server_priv, server_pub = keypair_pems()

    _write_private(KEY_DIR / KEY_CLIENT_PRIVATE, client_priv)
    _write_private(KEY_DIR / KEY_SERVER_PRIVATE, server_priv)
    (KEY_DIR / KEY_CLIENT_PUBLIC).write_bytes(client_pub)
    (KEY_DIR / KEY_SERVER_PUBLIC).write_bytes(server_pub)

    lines.append(f"密钥已生成到：{KEY_DIR}")
    lines.append("")
    lines.append("【本地保留，切勿外传】 client_private.pem / server_public.pem")
    lines.append("【上传到远端 lg_keys/】 server_private.pem / client_public.pem")
    return lines


# ============================================================================
#  网络客户端
# ============================================================================

class FileSyncError(Exception):
    def __init__(self, message: str, code: str = "", status: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


class FileSyncClient:
    def __init__(self, url: str | None = None,
                 client_key: Path | None = None,
                 server_key: Path | None = None,
                 timeout: int = REQUEST_TIMEOUT) -> None:
        self.url = (url or configured_server_url()).strip()
        self.timeout = timeout
        self._client_key_path = client_key or CLIENT_PRIVATE_KEY
        self._server_key_path = server_key or SERVER_PUBLIC_KEY
        self._priv = None
        self._server_pub = None
        self._session = requests.Session()

    def _private(self):
        if self._priv is None:
            if not self._client_key_path.exists():
                raise FileSyncError(
                    f"找不到客户端私钥：{self._client_key_path}\n"
                    f"请先执行：python {Path(sys.argv[0]).name} --genkeys"
                )
            self._priv = serialization.load_pem_private_key(
                self._client_key_path.read_bytes(), password=None
            )
        return self._priv

    def _server_public(self):
        if self._server_pub is None:
            if not self._server_key_path.exists():
                raise FileSyncError(
                    f"找不到服务端公钥：{self._server_key_path}\n"
                    f"请先执行：python {Path(sys.argv[0]).name} --genkeys"
                )
            self._server_pub = serialization.load_pem_public_key(
                self._server_key_path.read_bytes()
            )
        return self._server_pub

    def request(self, action: str, **params) -> dict:
        body = json.dumps(
            {"action": action, **params}, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        canonical = f"{PROTOCOL_TAG}\n{action}\n{ts}\n{nonce}\n{sha256_hex(body)}".encode("utf-8")

        signature = self._private().sign(canonical, padding.PKCS1v15(), hashes.SHA256())
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "X-LG-Timestamp": ts,
            "X-LG-Nonce": nonce,
            "X-LG-Signature": base64.b64encode(signature).decode("ascii"),
        }

        try:
            resp = self._session.post(self.url, data=body, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise FileSyncError(f"网络请求失败：{exc}") from exc

        self._verify_response(resp, nonce)

        try:
            payload = resp.json()
        except ValueError as exc:
            raise FileSyncError(
                f"服务端返回了非 JSON 内容（HTTP {resp.status_code}）：{resp.text[:200]}",
                "body_too_large" if resp.status_code == 413 else "",
                resp.status_code,
            ) from exc

        if not isinstance(payload, dict):
            raise FileSyncError("服务端响应格式异常")
        if not payload.get("ok"):
            code = str(payload.get("error", ""))
            raise FileSyncError(self._describe_error(payload, resp.status_code), code,
                                resp.status_code)
        return payload

    def _verify_response(self, resp, nonce: str) -> None:
        sig_b64 = resp.headers.get("X-LG-Signature")
        if not sig_b64:
            if resp.status_code == 200:
                raise FileSyncError("服务端响应未签名，拒绝信任（请检查服务端密钥配置）")
            return
        try:
            signature = base64.b64decode(sig_b64, validate=True)
        except ValueError as exc:
            raise FileSyncError("服务端签名不是合法 base64") from exc

        canonical = f"{RESPONSE_TAG}\n{nonce}\n{sha256_hex(resp.content)}".encode("utf-8")
        try:
            self._server_public().verify(
                signature, canonical, padding.PKCS1v15(), hashes.SHA256()
            )
        except InvalidSignature as exc:
            raise FileSyncError("服务端响应签名校验失败（可能密钥不匹配，或响应被篡改）") from exc

    @staticmethod
    def _describe_error(payload: dict, status: int) -> str:
        mapping = {
            "method_not_allowed": "请求方法不被允许",
            "server_not_configured": "服务端未正确配置密钥目录（需位于站点根之外）",
            "unauthorized": "认证失败：签名无效、请求过期或已被重放",
            "body_too_large": "请求体过大（服务端或 nginx 的 body 上限更低）",
            "bad_request": "请求参数不合法",
            "bad_path": "文件路径不合法或属于受保护路径",
            "bad_base64": "文件内容编码错误",
            "bad_range": "分片参数不合法",
            "chunk_not_started": "分片续传失败：服务端没有这个文件的首片（请重新上传）",
            "chunk_offset_mismatch": "分片偏移不匹配：上一片可能没落盘（请重新上传）",
            "size_mismatch": "文件大小与声明不符",
            "hash_mismatch": "文件校验值不匹配",
            "not_found": "文件或提交不存在",
            "read_error": "服务端读取文件失败",
            "write_failed": "服务端写入失败",
            "conflict": "提交冲突：服务端已有新的提交，请先 pull",
            "sync_conflict": "服务端文件与提交清单不一致，请先 pull 或重新 push",
            "unknown_action": "未知的操作类型（服务端 api.php 可能不是最新版）",
            "server_error": "服务端内部错误",
        }
        code = payload.get("error", "unknown")
        text = f"{mapping.get(code, '服务端返回错误')}（{code}，HTTP {status}）"
        build = payload.get("api_build")
        if build:
            text += f"\n服务端版本：{build}"
        for key, label in (("hint", "原因"), ("head", "服务端 HEAD"),
                           ("path", "文件"), ("detail", "详情")):
            value = payload.get(key)
            if value:
                text += f"\n{label}：{value}"
        return text

    # ---------------- 业务方法 ----------------

    def ping(self) -> dict:
        return self.request("ping")

    def list_files(self) -> list[dict]:
        return list(self.request("list").get("files", []))

    def read_file(self, path: str) -> bytes:
        return base64.b64decode(self.request("read", path=path)["content_b64"])

    def write_files(self, files: list[dict]) -> tuple[int, list[dict]]:
        result = self.request("write", files=files)
        return len(result.get("written", [])), list(result.get("errors", []))

    def git_log(self, limit: int = 20) -> dict:
        return self.request("git_log", limit=limit)

    def git_show(self, commit_id: str) -> dict:
        return dict(self.request("git_show", id=commit_id)["commit"])

    def git_state(self) -> dict:
        return self.request("git_state")

    def git_commit(self, commit: dict) -> dict:
        return self.request("git_commit", commit=commit)


# ============================================================================
#  忽略规则 / 本地扫描
# ============================================================================

def load_filesyncignore() -> list[tuple[str, bool]]:
    rules: list[tuple[str, bool]] = []
    if not FILESYNC_IGNORE_PATH.is_file():
        return rules
    try:
        text = FILESYNC_IGNORE_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rules
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:].strip()
        if line:
            rules.append((line, negated))
    return rules


def _match_pattern(pattern: str, rel: str, is_dir: bool) -> bool:
    dir_only = pattern.endswith("/")
    pat = pattern.rstrip("/")
    if not pat:
        return False
    parts = rel.split("/")
    ancestors = ["/".join(parts[:i]) for i in range(1, len(parts))]
    targets = list(ancestors)
    if not dir_only or is_dir:
        targets.append(rel)
    if "/" in pat:
        return any(fnmatch.fnmatchcase(t, pat) for t in targets)
    return any(fnmatch.fnmatchcase(t.rsplit("/", 1)[-1], pat) for t in targets)


def is_ignored(rel: str, rules: list[tuple[str, bool]], is_dir: bool = False) -> bool:
    ignored = False
    for pattern, negated in rules:
        if _match_pattern(pattern, rel, is_dir):
            ignored = not negated
    return ignored


def scan_local(root: Path | None = None) -> dict[str, dict]:
    """扫描工作区，返回 {相对路径: {path, size, sha256}}"""
    if root is None:
        root = LOCAL_DIR
    result: dict[str, dict] = {}
    if not root.is_dir():
        return result
    rules = load_filesyncignore()
    for dirpath, dirnames, filenames in os.walk(root):
        kept: list[str] = []
        for d in dirnames:
            if d.startswith(".") or d in PROTECTED_REMOTE:
                continue
            rel_dir = (Path(dirpath) / d).relative_to(root).as_posix()
            if is_ignored(rel_dir, rules, is_dir=True):
                continue
            kept.append(d)
        dirnames[:] = sorted(kept)

        for name in sorted(filenames):
            if name.startswith(".") or name in PROTECTED_REMOTE:
                continue
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if is_ignored(rel, rules):
                continue
            try:
                result[rel] = {
                    "path": rel,
                    "size": full.stat().st_size,
                    "sha256": sha256_file(full),
                }
            except OSError:
                continue
    return result


# ============================================================================
#  行级 diff
# ============================================================================

@dataclass
class DiffOp:
    tag: str
    i1: int
    i2: int
    j1: int
    j2: int


def _merge_ops(raw: list[tuple[str, int, int]], off_a: int, off_b: int) -> list[DiffOp]:
    ops: list[DiffOp] = []
    k = 0
    total = len(raw)
    while k < total:
        if raw[k][0] == "equal":
            a0, b0 = raw[k][1], raw[k][2]
            count = 0
            while k < total and raw[k][0] == "equal":
                count += 1
                k += 1
            ops.append(DiffOp("equal", a0 + off_a, a0 + count + off_a,
                              b0 + off_b, b0 + count + off_b))
            continue

        a0, b0 = raw[k][1], raw[k][2]
        dels = ins = 0
        while k < total and raw[k][0] != "equal":
            if raw[k][0] == "delete":
                dels += 1
            else:
                ins += 1
            k += 1
        tag = "replace" if (dels and ins) else ("delete" if dels else "insert")
        ops.append(DiffOp(tag, a0 + off_a, a0 + dels + off_a, b0 + off_b, b0 + ins + off_b))
    return ops


def _diff_core(a: list[str], b: list[str], off_a: int, off_b: int) -> list[DiffOp]:
    n, m = len(a), len(b)
    if n == 0 and m == 0:
        return []
    if n == 0:
        return [DiffOp("insert", off_a, off_a, off_b, off_b + m)]
    if m == 0:
        return [DiffOp("delete", off_a, off_a + n, off_b, off_b)]
    if n * m > MAX_DIFF_CELLS:
        return [DiffOp("replace", off_a, off_a + n, off_b, off_b + m)]

    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        row, nxt, ai = dp[i], dp[i + 1], a[i]
        for j in range(m - 1, -1, -1):
            row[j] = nxt[j + 1] + 1 if ai == b[j] else (nxt[j] if nxt[j] >= row[j + 1] else row[j + 1])

    raw: list[tuple[str, int, int]] = []
    i = j = 0
    while i < n and j < m:
        if a[i] == b[j]:
            raw.append(("equal", i, j))
            i += 1
            j += 1
        elif dp[i + 1][j] >= dp[i][j + 1]:
            raw.append(("delete", i, j))
            i += 1
        else:
            raw.append(("insert", i, j))
            j += 1
    while i < n:
        raw.append(("delete", i, j))
        i += 1
    while j < m:
        raw.append(("insert", i, j))
        j += 1
    return _merge_ops(raw, off_a, off_b)


def diff_lines(a: list[str], b: list[str]) -> list[DiffOp]:
    n, m = len(a), len(b)
    start = 0
    while start < n and start < m and a[start] == b[start]:
        start += 1
    tail = 0
    while tail < n - start and tail < m - start and a[n - 1 - tail] == b[m - 1 - tail]:
        tail += 1

    ops: list[DiffOp] = []
    if start:
        ops.append(DiffOp("equal", 0, start, 0, start))
    mid_a = a[start:n - tail] if tail else a[start:]
    mid_b = b[start:m - tail] if tail else b[start:]
    ops.extend(_diff_core(mid_a, mid_b, start, start))
    if tail:
        ops.append(DiffOp("equal", n - tail, n, m - tail, m))
    return ops


def decode_text(data: bytes | None) -> str | None:
    if data is None:
        return ""
    if b"\x00" in data[:8192]:
        return None
    for encoding in ("utf-8", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def diff_stat(old: bytes | None, new: bytes | None) -> tuple[int, int]:
    """返回 (新增行数, 删除行数)；二进制文件返回 (0, 0)"""
    a = decode_text(old)
    b = decode_text(new)
    if a is None or b is None:
        return 0, 0
    ops = diff_lines(a.splitlines(), b.splitlines())
    added = sum(op.j2 - op.j1 for op in ops if op.tag in ("insert", "replace"))
    removed = sum(op.i2 - op.i1 for op in ops if op.tag in ("delete", "replace"))
    return added, removed


# ============================================================================
#  本地仓库（.filesync/）
# ============================================================================

def ensure_state() -> None:
    for d in (STATE_DIR, OBJECTS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def _read_json(path: Path, default: dict) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default
    return data if isinstance(data, dict) else default


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def load_index() -> dict:
    data = _read_json(INDEX_PATH, {"files": {}})
    if not isinstance(data.get("files"), dict):
        data["files"] = {}
    return data


def save_index(data: dict) -> None:
    ensure_state()
    _write_json(INDEX_PATH, data)


def load_repo() -> dict:
    data = _read_json(COMMITS_PATH, {"head": "", "pushed": "", "head_manifest": {}, "commits": []})
    data.setdefault("head", "")
    data.setdefault("pushed", "")
    data.setdefault("head_manifest", {})
    if not isinstance(data["head_manifest"], dict):
        data["head_manifest"] = {}
    if not isinstance(data.get("commits"), list):
        data["commits"] = []
    return data


def save_repo(repo: dict) -> None:
    ensure_state()
    _write_json(COMMITS_PATH, repo)


def store_object(data: bytes) -> str:
    ensure_state()
    sha = sha256_hex(data)
    target = OBJECTS_DIR / sha
    if not target.is_file():
        tmp = target.with_name(sha + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)
    return sha


def read_object(sha: str) -> bytes | None:
    if not sha:
        return None
    path = OBJECTS_DIR / sha
    if not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def find_local_commit(repo: dict, commit_id: str) -> dict | None:
    if commit_id.upper() == "HEAD":
        commit_id = repo.get("head", "")
    for c in repo.get("commits", []):
        if c.get("id") == commit_id:
            return c
    return None


def make_commit_id(parent: str, message: str, manifest: dict) -> str:
    payload = json.dumps(
        {"p": parent, "m": message, "f": manifest},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )
    raw = f"{parent}\n{message}\n{payload}\n{time.time_ns()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12]


def short_time(ts: int | float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ts)))
    except (OSError, ValueError):
        return "-"


def fmt_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} GB"


def status_mark(status: str) -> str:
    return {"added": "A", "modified": "M", "deleted": "D"}.get(status, "?")


# ============================================================================
#  pull
# ============================================================================

def remote_snapshot(client: FileSyncClient) -> dict[str, dict]:
    rules = load_filesyncignore()
    return {f["path"]: f for f in client.list_files()
            if f.get("path") and not is_ignored(str(f["path"]), rules)}


def cmd_pull(args) -> int:
    repo = load_repo()
    if repo.get("head") and repo.get("head") != repo.get("pushed"):
        print(col("[x] 本地有未推送的提交，pull 会覆盖本地历史。", C_RED))
        print("    请先 push，或手动备份 .filesync/ 后删除再 pull。")
        return 1

    client = FileSyncClient()
    info = client.ping()
    print(f"远端接口：{client.url}")
    print(f"服务端 v{info.get('version')}（{info.get('api_build', '未知')}）")
    if "git" not in set(info.get("features") or []):
        print(col("[x] 服务端 api.php 不是最新版（不支持 git 协议），请先更新服务端。", C_RED))
        return 1

    LOCAL_DIR.mkdir(parents=True, exist_ok=True)
    remote = remote_snapshot(client)
    print(f"远端文件 {len(remote)} 个")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup_root = BACKUP_DIR / stamp
    downloaded = backed_up = 0

    for path, item in sorted(remote.items()):
        local_path = LOCAL_DIR / path
        if local_path.is_file():
            try:
                if sha256_file(local_path) == item.get("sha256"):
                    continue
            except OSError:
                pass
        data = client.read_file(path)
        if local_path.exists():
            target = backup_root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_path, target)
            backed_up += 1
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(data)
        downloaded += 1
        print(f"  ↓ {path}")

    # 同步提交历史
    state = client.git_state()
    commits = client.git_log(limit=200).get("commits", [])
    head = state.get("head", "")
    manifest: dict = {}
    if head:
        try:
            manifest = dict(client.git_show(head).get("manifest") or {})
        except FileSyncError:
            manifest = {}

    repo = {
        "head": head,
        "pushed": head,
        "head_manifest": manifest,
        "commits": commits,
    }
    save_repo(repo)
    save_index({"files": {}})

    print("")
    print(col(f"[OK] 更新 {downloaded} 个文件", C_GREEN)
          + (f"，本地原文件已备份到 {backup_root}" if backed_up else ""))
    print(f"     服务端 HEAD：{head or '（无提交）'}，历史 {len(commits)} 条")
    return 0


# ============================================================================
#  add / status / rm
# ============================================================================

def _select_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        rel = str(p).replace("\\", "/").strip().lstrip("./")
        if rel:
            out.append(rel.rstrip("/"))
    return out


def cmd_add(args) -> int:
    repo = load_repo()
    head_manifest: dict = repo.get("head_manifest", {})
    work = scan_local()
    targets = _select_paths(args.paths or [])

    if targets:
        chosen = [rel for rel in work
                  if any(rel == t or rel.startswith(t + "/") for t in targets)]
        deleted = [p for p in head_manifest
                   if p not in work
                   and any(p == t or p.startswith(t + "/") for t in targets)]
    else:
        chosen = list(work)
        deleted = [p for p in head_manifest if p not in work]

    if not chosen and not deleted:
        print("没有需要暂存的文件（工作区为空？检查 local_files/）")
        return 0

    index = load_index()
    staged = 0
    for rel in sorted(chosen):
        sha = work[rel]["sha256"]
        if head_manifest.get(rel) == sha and rel not in index["files"]:
            continue                     # 与 HEAD 相同，无需暂存
        try:
            data = (LOCAL_DIR / rel).read_bytes()
        except OSError as exc:
            print(col(f"[!] 读取失败：{rel}（{exc}）", C_YELLOW))
            continue
        store_object(data)
        index["files"][rel] = {
            "sha256": sha,
            "size": len(data),
            "status": "modified" if rel in head_manifest else "added",
        }
        staged += 1
        print(f"  {col('M' if rel in head_manifest else 'A', C_GREEN)} {rel}")

    for rel in sorted(deleted):
        index["files"][rel] = {"sha256": "", "size": 0, "status": "deleted"}
        staged += 1
        print(f"  {col('D', C_RED)} {rel}")

    save_index(index)
    print(col(f"[OK] 已暂存 {staged} 个改动", C_GREEN))
    return 0


def cmd_rm(args) -> int:
    index = load_index()
    repo = load_repo()
    head_manifest = repo.get("head_manifest", {})
    removed = 0
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for raw in args.paths:
        picked = _select_paths([raw])
        rel = picked[0] if picked else ""
        if not rel:
            continue
        full = LOCAL_DIR / rel
        if not full.is_file():
            print(col(f"[!] 本地不存在：{rel}", C_YELLOW))
            continue
        target = TRASH_DIR / stamp / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(full), str(target))
        if rel in head_manifest:
            index["files"][rel] = {"sha256": "", "size": 0, "status": "deleted"}
        else:
            index["files"].pop(rel, None)
        removed += 1
        print(f"  {col('D', C_RED)} {rel}  （备份：{target}）")
    save_index(index)
    print(col(f"[OK] 已删除 {removed} 个文件并暂存", C_GREEN))
    return 0


def cmd_status(args) -> int:
    repo = load_repo()
    head_manifest: dict = repo.get("head_manifest", {})
    index = load_index()["files"]
    work = scan_local()

    staged = sorted(index.items())
    unstaged: list[str] = []
    untracked: list[str] = []
    for rel, item in work.items():
        if rel in index:
            continue
        if rel in head_manifest:
            if head_manifest[rel] != item["sha256"]:
                unstaged.append(rel)
        else:
            untracked.append(rel)
    missing = [p for p in head_manifest if p not in work and p not in index]

    print(f"分支：local    HEAD：{repo.get('head') or '（无提交）'}"
          f"    已推送：{repo.get('pushed') or '（无）'}")
    print("")

    if staged:
        print("待提交的更改：")
        for rel, item in staged:
            mark = status_mark(item.get("status", "modified"))
            color = C_GREEN if mark == "A" else (C_RED if mark == "D" else C_YELLOW)
            print(f"  {col(mark, color)} {rel}")
    else:
        print("待提交的更改：无")

    if unstaged or missing:
        print("\n未暂存的更改：")
        for rel in unstaged:
            print(f"  {col('M', C_YELLOW)} {rel}")
        for rel in missing:
            print(f"  {col('D', C_RED)} {rel}（已从工作区消失，需 add）")

    if untracked:
        print("\n未跟踪的文件：")
        for rel in untracked:
            print(f"  {col('?', C_DIM)} {rel}")

    if not (staged or unstaged or missing or untracked):
        print(col("工作区干净，没有改动。", C_GREEN))
    return 0


# ============================================================================
#  commit
# ============================================================================

def cmd_commit(args) -> int:
    message = (args.message or "").strip()
    if not message:
        print(col("[x] 提交信息不能为空，使用 -m \"说明\"", C_RED))
        return 1

    index = load_index()["files"]
    if not index:
        print(col("[x] 暂存区为空，请先 add", C_RED))
        return 1

    repo = load_repo()
    parent = repo.get("head", "")
    manifest = dict(repo.get("head_manifest", {}))

    changes: list[dict] = []
    for rel, item in sorted(index.items()):
        st = item.get("status", "modified")
        old_sha = str(repo.get("head_manifest", {}).get(rel, ""))
        if st == "deleted":
            manifest.pop(rel, None)
            removed = diff_stat(read_object(old_sha), b"")[1]
            changes.append({"path": rel, "status": "deleted",
                            "added": 0, "removed": removed})
        else:
            sha = str(item.get("sha256", ""))
            manifest[rel] = sha
            added, removed = diff_stat(read_object(old_sha), read_object(sha))
            changes.append({"path": rel, "status": st,
                            "added": added, "removed": removed})

    commit_id = make_commit_id(parent, message, manifest)
    commit = {
        "id": commit_id,
        "message": message,
        "time": int(time.time()),
        "author": "client",
        "parent": parent,
        "changes": changes,
        "manifest": manifest,
    }
    repo["commits"].append(commit)
    repo["head"] = commit_id
    repo["head_manifest"] = manifest
    save_repo(repo)
    save_index({"files": {}})

    print(col(f"[OK] 已提交 {commit_id}", C_GREEN))
    _print_commit_detail(commit)
    if repo.get("pushed") != commit_id:
        print(f"\n提示：执行 {col('python main.py push', C_CYAN)} 推送到服务端")
    return 0


def _print_commit_detail(commit: dict) -> None:
    print("")
    print(f"commit {col(str(commit.get('id', '')), C_YELLOW)}")
    print(f"Author: {commit.get('author', 'client')}")
    print(f"Date:   {short_time(commit.get('time', 0))}")
    print("")
    for line in str(commit.get("message", "")).splitlines():
        print(f"    {line}")
    print("")

    changes = commit.get("changes") or []
    if not changes:
        print("（无文件改动）")
        return
    print("变更文件：")
    for ch in changes:
        path = ch.get("path", "")
        st = str(ch.get("status", "modified"))
        added = int(ch.get("added", 0))
        removed = int(ch.get("removed", 0))
        color = C_GREEN if st == "added" else (C_RED if st == "deleted" else C_YELLOW)
        print(f"  {col(status_mark(st), color)} {path}")
        print(f"      {col('+' + str(added), C_GREEN)}  {col('-' + str(removed), C_RED)}")


# ============================================================================
#  push
# ============================================================================

def _plan_blob_group(items: list[dict], start: int, budget: int):
    item = items[start]
    if len(item["data"]) > budget:
        groups = []
        offset = 0
        while offset < len(item["data"]):
            length = min(budget, len(item["data"]) - offset)
            groups.append([{"kind": "chunk", "item": item, "offset": offset, "length": length}])
            offset += length
        return groups, start + 1

    parts = []
    used = 0
    index = start
    while index < len(items):
        cur = items[index]
        if len(cur["data"]) > budget:
            break
        if parts and used + len(cur["data"]) > budget:
            break
        parts.append({"kind": "whole", "item": cur})
        used += len(cur["data"])
        index += 1
    return [parts], index


def _materialize_blob(part: dict) -> dict:
    item = part["item"]
    if part["kind"] == "whole":
        return {
            "path": item["path"],
            "content_b64": base64.b64encode(item["data"]).decode("ascii"),
            "sha256": item["sha256"],
        }
    offset = part["offset"]
    chunk = item["data"][offset:offset + part["length"]]
    final = offset + len(chunk) >= len(item["data"])
    return {
        "path": item["path"],
        "chunk_b64": base64.b64encode(chunk).decode("ascii"),
        "offset": offset,
        "total": len(item["data"]),
        "final": final,
        "sha256": item["sha256"] if final else "",
    }


def upload_blobs(client: FileSyncClient, items: list[dict]) -> int:
    """把内存中的文件内容写进远端；小文件打包，大文件分片，413 自动降档"""
    budget = UPLOAD_CHUNK_BYTES
    uploaded = 0
    index = 0
    while index < len(items):
        groups, nxt = _plan_blob_group(items, index, budget)
        try:
            for parts in groups:
                payload = [_materialize_blob(p) for p in parts]
                count, errors = client.write_files(payload)
                uploaded += count
                for err in errors:
                    print(col(f"  [!] 写入失败 {err.get('path')}（{err.get('error')}）", C_YELLOW))
        except FileSyncError as exc:
            if (exc.status == 413 or exc.code == "body_too_large") and budget > UPLOAD_MIN_CHUNK:
                budget = max(budget // 2, UPLOAD_MIN_CHUNK)
                print(col(f"  服务端拒绝请求体，降档为 {fmt_bytes(budget)} 后重试", C_YELLOW))
                continue
            raise
        index = nxt
    return uploaded


def cmd_push(args) -> int:
    repo = load_repo()
    head = repo.get("head", "")
    pushed = repo.get("pushed", "")
    if not head:
        print("没有提交可推送（先 add + commit）")
        return 0
    if head == pushed:
        print(col("已经是最新，没有需要推送的提交。", C_GREEN))
        return 0

    by_id = {c.get("id"): c for c in repo.get("commits", [])}
    pending: list[dict] = []
    cursor = head
    while cursor and cursor != pushed:
        commit = by_id.get(cursor)
        if commit is None:
            break
        pending.append(commit)
        cursor = str(commit.get("parent", ""))
    pending.reverse()

    if not pending:
        print(col("[x] 找不到待推送的提交链（本地历史可能损坏，可在 .filesync/commits.json 检查）", C_RED))
        return 1

    client = FileSyncClient()
    info = client.ping()
    if "git" not in set(info.get("features") or []):
        print(col("[x] 服务端 api.php 不是最新版（不支持 git 协议）", C_RED))
        return 1

    state = client.git_state()
    if state.get("head", "") != pushed:
        print(col("[x] 服务端已有新的提交，请先 pull 再 push", C_RED))
        print(f"    服务端 HEAD：{state.get('head')}    本地已推送：{pushed or '（无）'}")
        return 1

    remote = remote_snapshot(client)
    print(f"待推送提交 {len(pending)} 个")

    for commit in pending:
        cid = str(commit.get("id"))
        manifest = dict(commit.get("manifest") or {})
        if not manifest:
            print(col(f"[x] 提交 {cid} 缺少文件清单，无法推送", C_RED))
            return 1

        blobs: list[dict] = []
        for path, sha in sorted(manifest.items()):
            if remote.get(path, {}).get("sha256") == sha:
                continue
            data = read_object(str(sha))
            if data is None:
                full = LOCAL_DIR / path
                if not full.is_file():
                    print(col(f"[x] 缺少文件快照：{path}（请重新 add）", C_RED))
                    return 1
                data = full.read_bytes()
            blobs.append({"path": path, "data": data, "sha256": str(sha)})

        if blobs:
            upload_blobs(client, blobs)
            for b in blobs:
                remote[b["path"]] = {"path": b["path"], "sha256": b["sha256"],
                                     "size": len(b["data"])}
            print(f"  上传 {len(blobs)} 个文件")

        result = client.git_commit(commit)
        repo["pushed"] = str(result.get("head", cid))
        save_repo(repo)
        print(col(f"  ✓ {cid}  {commit.get('message', '')}", C_GREEN))

    print(col(f"[OK] 推送完成，服务端 HEAD：{repo.get('pushed')}", C_GREEN))
    return 0


# ============================================================================
#  check / diff / restore
# ============================================================================

def cmd_check(args) -> int:
    target = [str(t) for t in args.target]
    if target and target[0].lower() == "list":
        limit = 20
        if len(target) > 1:
            try:
                limit = max(1, min(200, int(target[1])))
            except ValueError:
                print("[!] 条数必须是数字，例如：check list 10")
                return 1
        return _check_list(limit)

    commit_id = target[0] if target else "HEAD"
    repo = load_repo()
    commit = find_local_commit(repo, commit_id)

    if commit is None:
        client = FileSyncClient()
        try:
            commit = client.git_show(commit_id)
        except FileSyncError as exc:
            print(col(f"[x] {exc}", C_RED))
            return 1

    _print_commit_detail(commit)
    return 0


def _check_list(limit: int) -> int:
    repo = load_repo()
    commits = repo.get("commits", [])

    # 优先取服务端最新历史；离线时回退本地
    try:
        client = FileSyncClient()
        remote = client.git_log(limit=limit)
        commits = remote.get("commits", [])
        head = remote.get("head", "")
        total = remote.get("total", len(commits))
    except FileSyncError:
        head = repo.get("head", "")
        total = len(commits)
        commits = list(reversed(commits))

    if not commits:
        print("还没有任何提交记录。")
        return 0

    print(f"HEAD：{head or '（无）'}    共 {total} 条提交\n")
    for c in commits[:limit]:
        cid = col(str(c.get("id", ""))[:12], C_YELLOW)
        msg = str(c.get("message", "")).splitlines()[0] if c.get("message") else ""
        files = len(c.get("changes") or [])
        author = str(c.get("author", ""))
        print(f"{cid}  {short_time(c.get('time', 0))}  [{author}]  {msg}  ({files} 个文件)")
    return 0


def cmd_diff(args) -> int:
    repo = load_repo()
    head_manifest: dict = repo.get("head_manifest", {})
    index = load_index()["files"]

    if args.path:
        rel = _select_paths([args.path])[0]
        pairs = [(rel, index.get(rel))]
    else:
        pairs = [(rel, item) for rel, item in sorted(index.items())]

    if not pairs:
        print("暂存区为空，没有可显示的差异（先 add）")
        return 0

    shown = 0
    for rel, item in pairs:
        old_sha = head_manifest.get(rel, "")
        if item is None:
            # 工作区 vs HEAD
            full = LOCAL_DIR / rel
            if not full.is_file():
                continue
            old_data = read_object(old_sha)
            new_data = full.read_bytes()
        else:
            new_sha = str(item.get("sha256", ""))
            old_data = read_object(old_sha)
            new_data = read_object(new_sha) if new_sha else b""
            if item.get("status") == "deleted":
                new_data = b""

        old_text = decode_text(old_data)
        new_text = decode_text(new_data)
        if old_text is None or new_text is None:
            print(f"{rel}：二进制文件，无法显示行差异")
            continue

        a = old_text.splitlines()
        b = new_text.splitlines()
        ops = diff_lines(a, b)
        if all(op.tag == "equal" for op in ops):
            continue

        print(col(f"--- a/{rel}", C_RED))
        print(col(f"+++ b/{rel}", C_GREEN))
        for op in ops:
            if op.tag == "equal":
                continue
            for k in range(op.i1, op.i2):
                print(col(f"- {a[k]}", C_RED))
            for k in range(op.j1, op.j2):
                print(col(f"+ {b[k]}", C_GREEN))
        shown += 1

    if not shown:
        print("没有差异。")
    return 0


def cmd_restore(args) -> int:
    rel = _select_paths([args.path])[0]
    repo = load_repo()
    from_id = args.from_id or "HEAD"
    commit = find_local_commit(repo, from_id)
    client = None

    if commit is None:
        client = FileSyncClient()
        commit = client.git_show(from_id)

    manifest = dict(commit.get("manifest") or {})
    if commit.get("id") == repo.get("head"):
        manifest = dict(repo.get("head_manifest") or manifest)
    sha = str(manifest.get(rel, ""))
    if not sha:
        print(col(f"[x] 提交 {from_id} 中不存在文件：{rel}", C_RED))
        return 1

    data = read_object(sha)
    if data is None:
        if client is None:
            client = FileSyncClient()
        try:
            data = client.read_file(rel)
        except FileSyncError as exc:
            print(col(f"[x] 本地没有该文件快照，且从服务端读取失败：{exc}", C_RED))
            return 1

    target = LOCAL_DIR / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    print(col(f"[OK] 已恢复 {rel}（来自 {commit.get('id')}）", C_GREEN))
    return 0


# ============================================================================
#  其他命令
# ============================================================================

def cmd_ping() -> int:
    client = FileSyncClient()
    try:
        info = client.ping()
    except FileSyncError as exc:
        print(col(f"[x] {exc}", C_RED))
        return 1
    print(col("[OK] 连通性与双向签名校验通过", C_GREEN))
    print(f"  远端接口：{client.url}")
    for key in ("version", "api_build", "features", "php_version", "ignored_count"):
        if key in info:
            print(f"  {key}: {info[key]}")
    return 0


def cmd_list() -> int:
    client = FileSyncClient()
    try:
        files = client.list_files()
    except FileSyncError as exc:
        print(col(f"[x] {exc}", C_RED))
        return 1
    for item in files:
        print(f"{item['size']:>10}  {item['sha256'][:12]}  {item['path']}")
    print(f"共 {len(files)} 个文件（{client.url}）")
    return 0


def cmd_genkeys(force: bool) -> int:
    for line in generate_keys(force=force):
        print(line)
    return 0


# ============================================================================
#  入口
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=f"{APP_TITLE} —— 仿 git 的文件同步工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""常用流程：
  python main.py pull                 拉取远端（本地自动备份）
  python main.py add                  暂存全部改动
  python main.py commit -m "说明"      生成提交
  python main.py push                 推送到服务端
  python main.py check list 10        查看最近 10 条提交
  python main.py check <commit_id>    查看某次提交的文件改动
""",
    )
    parser.add_argument("--genkeys", action="store_true", help="生成两对 RSA 密钥")
    parser.add_argument("--force", action="store_true", help="配合 --genkeys 覆盖已有密钥")
    parser.add_argument("--ping", action="store_true", help="测试连通性与签名")
    parser.add_argument("--list", action="store_true", help="列出远端文件")
    parser.add_argument("--url", metavar="URL", help="临时指定远端接口地址（不写入配置）")

    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("pull", help="拉取远端文件到 local_files（覆盖前自动备份）")

    p_add = sub.add_parser("add", help="暂存改动（默认全部）")
    p_add.add_argument("paths", nargs="*", help="文件/目录（默认全部）")

    sub.add_parser("status", help="查看工作区与暂存区状态")

    p_commit = sub.add_parser("commit", help="生成提交")
    p_commit.add_argument("-m", "--message", required=True, help="提交信息")

    sub.add_parser("push", help="推送本地提交到服务端")

    p_check = sub.add_parser("check", help="查看提交详情 / 列表")
    p_check.add_argument("target", nargs="*", help="commit id，或 list [N]")

    p_rm = sub.add_parser("rm", help="删除本地文件并暂存删除")
    p_rm.add_argument("paths", nargs="+")

    p_diff = sub.add_parser("diff", help="查看暂存区相对 HEAD 的差异")
    p_diff.add_argument("path", nargs="?")

    p_restore = sub.add_parser("restore", help="从某次提交恢复文件")
    p_restore.add_argument("path")
    p_restore.add_argument("--from", dest="from_id", default="HEAD", metavar="ID")

    return parser


def main() -> int:
    init_console()
    parser = build_parser()
    args = parser.parse_args()

    if args.url:
        global _URL_OVERRIDE
        _URL_OVERRIDE = args.url.strip()

    if args.genkeys:
        return cmd_genkeys(force=args.force)
    if args.ping:
        return cmd_ping()
    if args.list:
        return cmd_list()

    handlers = {
        "pull": cmd_pull,
        "add": cmd_add,
        "status": cmd_status,
        "commit": cmd_commit,
        "push": cmd_push,
        "check": cmd_check,
        "rm": cmd_rm,
        "diff": cmd_diff,
        "restore": cmd_restore,
    }
    handler = handlers.get(args.cmd)
    if handler is None:
        parser.print_help()
        return 0

    try:
        return handler(args)
    except FileSyncError as exc:
        print(col(f"[x] {exc}", C_RED))
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
