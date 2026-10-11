#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 File Sync - Client
================================================================================

一个基于 PyQt6 + requests 的桌面客户端，用来把本地 `local_files/` 目录
同步到远端站点（通过远端站点上的 api.php），并提供双端文件的按行对比。

两种模式
--------
1. 上传文件：把 local_files/ 下所有文件上传到远端（同名覆盖），
   然后把远端多出来的文件移入 ignored/ 归档目录（api.php 除外）。
2. 文件对比：按行对比两端同名文件的内容（自研 LCS 行级 diff 引擎）。

远端接口地址可在界面右上角「设置」里配置，默认 https://example.com/file_sync/api.php，
保存后写入同目录的 client_config.json。

安全模型（双向 RSA 签名）
-------------------------
本地需要两个文件：
    keys/client_private.pem   客户端私钥 —— 用于给每个请求签名
    keys/server_public.pem    服务端公钥 —— 用于校验每个响应

远端需要两个文件（放在 lg_keys/ 目录）：
    server_private.pem        服务端私钥
    client_public.pem         客户端公钥

因此：只有同时拿到 client_private.pem 的人才能让 api.php 执行任何操作，
也才拿得到任何数据；反过来，没有 server_private.pem 也无法伪造服务端响应。

目录结构
--------
    main.py                本客户端
    client_config.json     客户端配置（远端地址）
    keys/                  本地密钥（client_private.pem + server_public.pem）
    local_files/           待同步到远端的文件
    FileSync_Server/       远端（服务端）文件，需部署到服务器

用法
----
    python main.py --genkeys      # 生成两对密钥
    python main.py --ping         # 命令行自检：测试连通性与签名
    python main.py --list         # 列出远端文件
    python main.py                # 打开图形界面

依赖
----
    pip install PyQt6 requests cryptography
================================================================================
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

# ------------------------------------------------------------------ 依赖检查

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write("缺少依赖 requests，请先执行：pip install PyQt6 requests cryptography\n")
    raise

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "缺少依赖 cryptography，请先执行：pip install PyQt6 requests cryptography\n"
    )
    raise


# ============================================================================
#  配置
# ============================================================================

APP_TITLE = "File Sync - Client"
DEFAULT_SERVER_URL = "https://example.com/file_sync/api.php"

BASE_DIR = Path(__file__).resolve().parent
LOCAL_DIR = BASE_DIR / "local_files"          # 待同步的本地目录
KEY_DIR = BASE_DIR / "keys"                   # 本地密钥目录
CONFIG_PATH = BASE_DIR / "client_config.json"  # 客户端配置（远端地址等）

CLIENT_PRIVATE_KEY = KEY_DIR / "client_private.pem"
SERVER_PUBLIC_KEY = KEY_DIR / "server_public.pem"

KEY_CLIENT_PRIVATE = "client_private.pem"
KEY_CLIENT_PUBLIC = "client_public.pem"
KEY_SERVER_PRIVATE = "server_private.pem"
KEY_SERVER_PUBLIC = "server_public.pem"

# 远端受保护路径：不会上传覆盖，也不会被归档（需与 api.php 的 LG_PROTECTED 保持一致）
PROTECTED_REMOTE = {
    "api.php",
    "lg_config.php",
    "lg_keys",
    ".lg_keys",
    ".user.ini",
    ".htaccess",
    ".well-known",
    "404.html",
}

REQUEST_TIMEOUT = 60          # 单次 HTTP 超时（秒）
MAX_DIFF_CELLS = 2_000_000    # diff 动态规划的规模上限，超出则退化为整块替换

# 分片上传：单个 write 请求的目标原始字节数（base64 后约 1.35 倍）。
# 超过这个大小的文件会被切片，避免整份塞进一个请求触发 413。
UPLOAD_CHUNK_BYTES = 2 * 1024 * 1024   # 2 MiB
UPLOAD_MIN_CHUNK = 128 * 1024          # 服务端拒绝请求体时的自动降档下限
# 这些错误通常意味着上一片没落盘（或文件在传输中被改动），允许整份重传一次
UPLOAD_RETRY_ERRORS = {
    "chunk_not_started", "chunk_offset_mismatch", "size_mismatch",
    "hash_mismatch", "write_failed", "rename_failed",
}

PROTOCOL_TAG = "lg1"
RESPONSE_TAG = "lgresp1"


# ============================================================================
#  客户端配置（client_config.json）
# ============================================================================

_URL_OVERRIDE: str | None = None   # 仅由命令行 --url 临时设置，不落盘


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
    """生成一对 RSA-2048 密钥，返回 (私钥 PEM, 公钥 PEM)。"""
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
    """生成客户端 / 服务端两对密钥到 keys/ 目录，返回输出内容。"""
    lines: list[str] = []
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    targets = [
        KEY_CLIENT_PRIVATE,
        KEY_CLIENT_PUBLIC,
        KEY_SERVER_PRIVATE,
        KEY_SERVER_PUBLIC,
    ]
    existing = [t for t in targets if (KEY_DIR / t).exists()]
    if existing and not force:
        lines.append(f"{KEY_DIR} 下已存在以下密钥，未做任何改动：")
        lines.extend(f"  - {name}" for name in existing)
        lines.append("如需重新生成，请使用 --force（旧的密钥将立即失效）。")
        return lines

    client_priv, client_pub = keypair_pems()
    server_priv, server_pub = keypair_pems()

    _write_private(KEY_DIR / KEY_CLIENT_PRIVATE, client_priv)
    _write_private(KEY_DIR / KEY_SERVER_PRIVATE, server_priv)
    (KEY_DIR / KEY_CLIENT_PUBLIC).write_bytes(client_pub)
    (KEY_DIR / KEY_SERVER_PUBLIC).write_bytes(server_pub)

    server_dir = BASE_DIR / "FileSync_Server"
    lines.append(f"密钥已生成到：{KEY_DIR}")
    lines.append("")
    lines.append("【本地保留，切勿外传】")
    lines.append(f"  {KEY_CLIENT_PRIVATE}")
    lines.append(f"  {KEY_SERVER_PUBLIC}")
    lines.append("")
    lines.append("【上传到远端】这两个文件放到服务器上的 lg_keys/ 目录：")
    lines.append(f"  {KEY_SERVER_PRIVATE}   ->  <密钥目录>/{KEY_SERVER_PRIVATE}")
    lines.append(f"  {KEY_CLIENT_PUBLIC}    ->  <密钥目录>/{KEY_CLIENT_PUBLIC}")
    lines.append("")
    lines.append("密钥目录按以下优先级查找（第一个存在且可读的生效）：")
    lines.append("  1. api.php 同目录的 lg_config.php 中配置的 key_dir")
    lines.append("  2. 环境变量 LG_KEY_DIR")
    lines.append("  3. 站点根的上一级 /lg_keys        （推荐，需加入 open_basedir）")
    lines.append("  4. 站点根内 /lg_keys 或 /.lg_keys （需在 lg_config.php 中显式放行）")
    lines.append("")
    lines.append(f"服务端文件在本项目的：{server_dir}")
    return lines


# ============================================================================
#  客户端：签名请求 / 验签响应
# ============================================================================

class FileSyncError(Exception):
    """业务或协议层面的错误。"""

    def __init__(self, message: str, code: str = "", status: int = 0) -> None:
        super().__init__(message)
        self.code = code        # 服务端返回的 error 字段，便于按错误类型分支处理
        self.status = status    # HTTP 状态码


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FileSyncClient:
    def __init__(
        self,
        url: str | None = None,
        client_key: Path = CLIENT_PRIVATE_KEY,
        server_key: Path = SERVER_PUBLIC_KEY,
        timeout: int = REQUEST_TIMEOUT,
    ) -> None:
        self.url = (url or configured_server_url()).strip()
        self.timeout = timeout
        self._client_key_path = client_key
        self._server_key_path = server_key
        self._priv = None
        self._server_pub = None
        self._session = requests.Session()

    # -------------------------------------------------- 密钥加载

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

    # -------------------------------------------------- 请求

    def request(self, action: str, **params) -> dict:
        body = json.dumps(
            {"action": action, **params},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        canonical = (
            f"{PROTOCOL_TAG}\n{action}\n{ts}\n{nonce}\n{sha256_hex(body)}"
        ).encode("utf-8")

        signature = self._private().sign(
            canonical, padding.PKCS1v15(), hashes.SHA256()
        )

        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "X-LG-Timestamp": ts,
            "X-LG-Nonce": nonce,
            "X-LG-Signature": base64.b64encode(signature).decode("ascii"),
        }

        try:
            resp = self._session.post(
                self.url, data=body, headers=headers, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise FileSyncError(f"网络请求失败：{exc}") from exc

        self._verify_response(resp, nonce)

        try:
            payload = resp.json()
        except ValueError as exc:
            # nginx 自己拦下的 413 是 HTML，这里补一个错误码，好让上传逻辑自动降档重试
            raise FileSyncError(
                f"服务端返回了非 JSON 内容（HTTP {resp.status_code}）："
                f"{resp.text[:200]}",
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
                raise FileSyncError(
                    "服务端响应未签名，拒绝信任（请检查服务端密钥配置）"
                )
            # 非 200 的错误响应可以不带签名，这里只在下方统一抛错
            return
        try:
            signature = base64.b64decode(sig_b64, validate=True)
        except ValueError as exc:
            raise FileSyncError("服务端签名不是合法 base64") from exc

        canonical = (
            f"{RESPONSE_TAG}\n{nonce}\n{sha256_hex(resp.content)}"
        ).encode("utf-8")
        try:
            self._server_public().verify(
                signature, canonical, padding.PKCS1v15(), hashes.SHA256()
            )
        except InvalidSignature as exc:
            raise FileSyncError(
                "服务端响应签名校验失败（可能密钥不匹配，或响应被篡改）"
            ) from exc

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
            "not_found": "文件不存在",
            "read_error": "服务端读取文件失败",
            "unknown_action": "未知的操作类型（服务端 api.php 可能不是最新版）",
            "server_error": "服务端内部错误",
        }
        code = payload.get("error", "unknown")
        text = f"{mapping.get(code, '服务端返回错误')}（{code}，HTTP {status}）"

        # 版本标记：判断服务端跑的是不是最新版 api.php
        build = payload.get("api_build")
        if build:
            text += f"\n服务端版本：{build}"
        else:
            text += ("\n服务端未返回版本标记，说明它仍在运行旧版 api.php —— "
                     "请把最新的 api.php 重新上传到站点根目录")

        # 追加服务端给出的排障信息
        labels = {
            "hint": "原因",
            "key_dir": "密钥目录",
            "open_basedir": "服务端 open_basedir",
            "tried": "已尝试的路径",
            "files": "读取失败的文件",
            "parse": "密钥解析",
            "detail": "详情",
        }
        for key, label in labels.items():
            value = payload.get(key)
            if value is None or value == "" or value == [] or value == {}:
                continue
            text += f"\n{label}：" + _render_extra(value)

        # 其余未知字段一并展示，方便服务端后续扩展时客户端无需同步改动
        known = {"ok", "error", "api_build", "fix", *labels}
        for key, value in payload.items():
            if key in known or value is None or value == "" or value == [] or value == {}:
                continue
            text += f"\n{key}：" + _render_extra(value)

        fixes = payload.get("fix")
        if isinstance(fixes, list) and fixes:
            text += "\n处理办法："
            for index, item in enumerate(fixes, start=1):
                text += f"\n  {index}. {item}"
        return text

    # -------------------------------------------------- 业务方法

    def ping(self) -> dict:
        return self.request("ping")

    def list_files(self) -> list[dict]:
        return list(self.request("list").get("files", []))

    def read_file(self, path: str) -> bytes:
        data = self.request("read", path=path)
        return base64.b64decode(data["content_b64"])

    def write_files(self, files: list[dict]) -> tuple[int, list[dict]]:
        """一次 write 请求。

        files 里每一项二选一：
          - 整文件：{"path", "content_b64", "sha256"}
          - 分片：  {"path", "chunk_b64", "offset", "total", "final", "sha256"}
        返回 (完成的文件数, 错误列表)；分片请求的中间片不计入完成数。
        """
        result = self.request("write", files=files)
        return len(result.get("written", [])), list(result.get("errors", []))

    def prune(self, keep: list[str]) -> dict:
        return self.request("prune", keep=keep)


# ============================================================================
#  本地文件扫描
# ============================================================================

def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def scan_local(root: Path) -> dict[str, dict]:
    """返回 {相对路径: {path, size, sha256}}，跳过隐藏项与受保护文件。"""
    result: dict[str, dict] = {}
    if not root.is_dir():
        return result
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if not d.startswith(".") and d not in PROTECTED_REMOTE
        )
        for name in sorted(filenames):
            if name.startswith(".") or name in PROTECTED_REMOTE:
                continue
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            try:
                size = full.stat().st_size
                digest = sha256_file(full)
            except OSError:
                continue
            result[rel] = {"path": rel, "size": size, "sha256": digest}
    return result


# ------------------------------------------------------------------ 分片上传

def fmt_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    value = size / 1024
    for unit in ("KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def plan_upload_group(pending: list[dict], start: int, budget: int):
    """规划从 pending[start] 起的一批写操作。

    返回 (group, next_index)：group 是「若干次请求」，每次请求是一个 part 列表。
      - 小文件（≤ budget）贪心打包进同一个请求，保持成批的高效；
      - 大文件按 budget 切片，每片一个请求，offset 严格递增；
      - 只有整个文件传完，next_index 才会跳过它。
    """
    item = pending[start]
    if item["size"] > budget:                       # 大文件：切片
        requests: list[list[dict]] = []
        offset = 0
        while offset < item["size"]:
            length = min(budget, item["size"] - offset)
            requests.append([{"kind": "chunk", "item": item,
                              "offset": offset, "length": length}])
            offset += length
        return requests, start + 1

    parts: list[dict] = []                           # 小文件：贪心打包
    used = 0
    index = start
    while index < len(pending):
        cur = pending[index]
        if cur["size"] > budget:
            break
        if parts and used + cur["size"] > budget:
            break
        parts.append({"kind": "whole", "item": cur})
        used += cur["size"]
        index += 1
    return [parts], index


def part_raw_size(part: dict) -> int:
    return part["length"] if part["kind"] == "chunk" else part["item"]["size"]


def materialize_part(part: dict) -> dict:
    """把 part 描述读成 api.php 的字段（大文件按需 seek，不整份读入内存）。"""
    item = part["item"]
    full = LOCAL_DIR / item["path"]
    if part["kind"] == "whole":
        raw = full.read_bytes()
        return {
            "path": item["path"],
            "content_b64": base64.b64encode(raw).decode("ascii"),
            "sha256": item["sha256"],
        }
    offset = part["offset"]
    with open(full, "rb") as fh:
        fh.seek(offset)
        raw = fh.read(part["length"])
    final = offset + len(raw) >= item["size"]
    return {
        "path": item["path"],
        "chunk_b64": base64.b64encode(raw).decode("ascii"),
        "offset": offset,
        "total": item["size"],
        "final": final,
        "sha256": item["sha256"] if final else "",
    }


def upload_pending(client, pending: list[dict], log, progress,
                   budget: int | None = None, capabilities: set[str] | None = None):
    """把 pending 里的文件写进远端：小文件成批打包，大文件切片。

    budget 是单次请求的原始字节预算；服务端返回 413（body_too_large）时自动减半重试。
    capabilities 来自 ping 的 features；旧版 api.php 不认识分片字段，会把分片写成空文件，
    所以缺少 chunked_write 能力时直接报错，而不是冒险上传。
    返回 (上传完成的文件数, 错误列表, 最终生效的 budget)。
    """
    if budget is None:
        budget = UPLOAD_CHUNK_BYTES
    total_bytes = sum(item["size"] for item in pending) or 1
    uploaded = 0
    failures: list[dict] = []
    retried: set[str] = set()
    done = 0
    index = 0

    while index < len(pending):
        group, next_index = plan_upload_group(pending, index, budget)
        group_names = [pending[k]["path"] for k in range(index, next_index)]
        group_paths = set(group_names)
        if (capabilities is not None and "chunked_write" not in capabilities
                and any(p["kind"] == "chunk" for parts in group for p in parts)):
            raise FileSyncError(
                "服务端 api.php 不支持分片上传，请把最新的 FileSync_Server/api.php "
                "重新上传到站点根目录（它是受保护文件，同步工具不会覆盖它）"
            )
        base = done
        sent = 0
        errors_here: list[dict] = []
        try:
            for parts in group:
                payload = [materialize_part(p) for p in parts]
                count, errors = client.write_files(payload)
                uploaded += count
                errors_here.extend(errors)
                sent += sum(part_raw_size(p) for p in parts)
                progress(base + sent, total_bytes, "上传中")
        except FileSyncError as exc:
            if ((exc.status == 413 or exc.code == "body_too_large")
                    and budget > UPLOAD_MIN_CHUNK):
                new_budget = max(budget // 2, UPLOAD_MIN_CHUNK)
                log(f"服务端拒绝请求体（{fmt_bytes(budget)}），自动降档为 "
                    f"{fmt_bytes(new_budget)} 后重试"
                    f"（想更快可调大 nginx 的 client_max_body_size）", "warn")
                budget = new_budget
                continue
            raise
        done = base + sent

        # 分片类错误（上一片没落盘等）→ 该文件整份重传一次
        retry_path = next(
            (e["path"] for e in errors_here
             if e.get("error") in UPLOAD_RETRY_ERRORS
             and e.get("path") in group_paths
             and e.get("path") not in retried),
            None,
        )
        if retry_path is not None:
            retried.add(retry_path)
            log(f"文件 {retry_path} 的分片校验失败，正在重新上传 ...", "warn")
            failures.extend(e for e in errors_here
                            if e.get("path") != retry_path)
            index = next(k for k in range(index, next_index)
                         if pending[k]["path"] == retry_path)
            continue

        failures.extend(errors_here)
        names = ", ".join(group_names[:3])
        more = " ..." if len(group_names) > 3 else ""
        log(f"已写入 {len(group_names)} 个文件：{names}{more}", "ok")
        index = next_index

    return uploaded, failures, budget


# ------------------------------------------------------------------ 静态资源版本号

# 只碰这些标签上的 href/src，不会动 <a href> 之类的页面跳转
_ASSET_TAG_RE = re.compile(
    r"<(?P<tag>link|script|img|audio|video|source|iframe)\b(?P<attrs>[^>]*)>",
    re.IGNORECASE | re.DOTALL,
)
_ASSET_ATTR_RE = re.compile(r'''(\b(?:href|src)\s*=\s*)(["'])([^"']+)\2''', re.IGNORECASE)
# 内联 <style> 里的 url(...)
_STYLE_RE = re.compile(
    r"(?P<open><style\b[^>]*>)(?P<body>.*?)(?P<close></style>)",
    re.IGNORECASE | re.DOTALL,
)
_STYLE_URL_RE = re.compile(r'''url\(\s*(["']?)([^"')]+)\1\s*\)''', re.IGNORECASE)
# 没有 src 的内联 <script>：里面的脚本字符串也要扫
# （fetch('bg.lrc')、img.src = 'bg.webp' 这种，标签规则看不到）
_SCRIPT_RE = re.compile(
    r"(?P<open><script\b(?![^>]*\bsrc=)[^>]*>)(?P<body>.*?)(?P<close></script>)",
    re.IGNORECASE | re.DOTALL,
)
_SCRIPT_STR_RE = re.compile(r'''(["'])([^"'<>\s]+?)\1''')

# 脚本字符串里只认这些扩展名。标签属性不需要白名单（href/src 本身就说明是资源），
# 但脚本里的字符串长得像什么都有可能，加一层白名单防止误改普通文本。
_ASSET_EXTS = frozenset({
    ".css", ".js", ".mjs", ".json", ".html", ".htm", ".txt", ".xml",
    ".lrc", ".vtt", ".srt",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp",
    ".mp3", ".m4a", ".aac", ".ogg", ".oga", ".wav", ".flac", ".opus", ".weba",
    ".mp4", ".webm", ".ogv", ".mov",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".glb", ".gltf", ".wasm",
})

# 这些不是本地资源，不能加版本号
_SKIP_URL_PREFIXES = ("http://", "https://", "//", "data:", "blob:", "mailto:",
                      "javascript:", "#")


def _with_version(url: str, version: str) -> str:
    """给 url 加上/更新 ?v=version，保留原有的其它查询参数与 #fragment。"""
    frag = ""
    if "#" in url:
        url, _, tail = url.partition("#")
        frag = "#" + tail
    base, _, query = url.partition("?")
    keep = [p for p in query.split("&") if p and p.split("=", 1)[0] != "v"]
    keep.append(f"v={version}")
    return f"{base}?{'&'.join(keep)}{frag}"


def _asset_target(base_dir: Path, html_path: Path, url: str) -> Path | None:
    """把引用地址映射到本地文件；是外部资源或找不到文件则返回 None。"""
    if url.lower().startswith(_SKIP_URL_PREFIXES):
        return None
    path_part = url.split("#", 1)[0].split("?", 1)[0]
    if not path_part:
        return None
    if path_part.startswith("/"):
        candidates = [base_dir / path_part.lstrip("/")]
    else:
        # 相对本文件的路径优先，再退回站点根
        candidates = [html_path.parent / path_part, base_dir / path_part]
    for cand in candidates:
        try:
            if cand.is_file():
                return cand
        except OSError:
            continue
    return None


def asset_version(target: Path, cache: dict[str, str]) -> str:
    """资源版本号 = 文件内容 sha256 的前 12 位。

    内容不变 → 版本号不变 → 浏览器可以一直用缓存；
    内容一变 → 版本号自动变 → URL 变了，立刻就刷新，不用手动强刷。
    """
    key = str(target)
    if key not in cache:
        try:
            cache[key] = sha256_file(target)[:12]
        except OSError:
            cache[key] = ""
    return cache[key]


def bump_asset_versions(html_path: Path, base_dir: Path, cache: dict[str, str]) -> int:
    """给 HTML 里的本地静态资源引用加上/更新 ?v=<内容哈希>，返回改写的引用数量。

    覆盖：link / script / img / audio / video / source / iframe 上的 href|src，
          内联 <style> 里的 url(...)，
          以及内联 <script> 里的脚本字符串（fetch('bg.lrc')、img.src = 'bg.webp'）。
          第三种要带扩展名白名单，且必须能在本地找到同名文件，否则不动。
    跳过：http(s)://、//、data:、blob:、mailto:、javascript:、纯 #锚点，
          以及本地不存在的文件（拿不到内容哈希就不乱加参数）。
    按字节读写，避免把 Windows 的 CRLF 换行改写成 LF。
    """
    try:
        text = html_path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return 0

    count = 0

    def fix_url(url: str, in_script: bool = False) -> str:
        nonlocal count
        if in_script:
            # 脚本字符串：先过扩展名白名单，再要求本地真有这个文件
            ext = Path(url.split("#", 1)[0].split("?", 1)[0]).suffix.lower()
            if ext not in _ASSET_EXTS:
                return url
        target = _asset_target(base_dir, html_path, url)
        if target is None:
            return url
        version = asset_version(target, cache)
        if not version:
            return url
        new_url = _with_version(url, version)
        if new_url == url:
            return url
        count += 1
        return new_url

    def fix_tag(match: "re.Match[str]") -> str:
        attrs = match.group("attrs")
        if not attrs:
            return match.group(0)
        new_attrs = _ASSET_ATTR_RE.sub(
            lambda m: f"{m.group(1)}{m.group(2)}{fix_url(m.group(3))}{m.group(2)}",
            attrs,
        )
        return match.group(0).replace(attrs, new_attrs, 1)

    def fix_style(match: "re.Match[str]") -> str:
        body = _STYLE_URL_RE.sub(
            lambda u: f"url({u.group(1)}{fix_url(u.group(2))}{u.group(1)})",
            match.group("body"),
        )
        return match.group("open") + body + match.group("close")

    def fix_script(match: "re.Match[str]") -> str:
        body = _SCRIPT_STR_RE.sub(
            lambda m: f"{m.group(1)}{fix_url(m.group(2), True)}{m.group(1)}",
            match.group("body"),
        )
        return match.group("open") + body + match.group("close")

    text = _ASSET_TAG_RE.sub(fix_tag, text)
    text = _STYLE_RE.sub(fix_style, text)
    text = _SCRIPT_RE.sub(fix_script, text)

    if count:
        html_path.write_bytes(text.encode("utf-8"))
    return count


def decode_text(data: bytes) -> str | None:
    """尽量把字节解码成文本；二进制返回 None。"""
    if b"\x00" in data[:8192]:
        return None
    for encoding in ("utf-8", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


# ============================================================================
#  行级 diff 引擎（自研：公共前后缀裁剪 + LCS 动态规划 + 操作块合并）
# ============================================================================

@dataclass
class DiffOp:
    tag: str      # equal / replace / delete / insert
    i1: int
    i2: int
    j1: int
    j2: int


def _merge_ops(raw: list[tuple[str, int, int]], off_a: int, off_b: int) -> list[DiffOp]:
    """把逐行操作合并成区间操作块。"""
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
            ops.append(
                DiffOp("equal", a0 + off_a, a0 + count + off_a,
                       b0 + off_b, b0 + count + off_b)
            )
            continue

        a0, b0 = raw[k][1], raw[k][2]
        dels = ins = 0
        while k < total and raw[k][0] != "equal":
            if raw[k][0] == "delete":
                dels += 1
            else:
                ins += 1
            k += 1
        if dels and ins:
            tag = "replace"
        elif dels:
            tag = "delete"
        else:
            tag = "insert"
        ops.append(
            DiffOp(tag, a0 + off_a, a0 + dels + off_a, b0 + off_b, b0 + ins + off_b)
        )
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

    # LCS 长度表（自底向上）
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        row, nxt, ai = dp[i], dp[i + 1], a[i]
        for j in range(m - 1, -1, -1):
            if ai == b[j]:
                row[j] = nxt[j + 1] + 1
            else:
                row[j] = nxt[j] if nxt[j] >= row[j + 1] else row[j + 1]

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
    """按行对比两个文本，返回区间操作列表。"""
    n, m = len(a), len(b)

    # 裁剪公共前缀
    start = 0
    while start < n and start < m and a[start] == b[start]:
        start += 1
    # 裁剪公共后缀
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


@dataclass
class DiffRow:
    text: str
    kind: str            # equal / delete / insert / filler
    lineno: int | None   # 源文件行号，占位行为 None


def build_diff_rows(a: list[str], b: list[str], ops: list[DiffOp]) -> tuple[list[DiffRow], list[DiffRow], int, int]:
    """把操作块展开成左右两列对齐的行。"""
    left: list[DiffRow] = []
    right: list[DiffRow] = []
    added = removed = 0

    for op in ops:
        if op.tag == "equal":
            for k in range(op.i2 - op.i1):
                left.append(DiffRow(a[op.i1 + k], "equal", op.i1 + k + 1))
                right.append(DiffRow(b[op.j1 + k], "equal", op.j1 + k + 1))
        elif op.tag == "delete":
            for k in range(op.i1, op.i2):
                left.append(DiffRow(a[k], "delete", k + 1))
                right.append(DiffRow("", "filler", None))
                removed += 1
        elif op.tag == "insert":
            for k in range(op.j1, op.j2):
                left.append(DiffRow("", "filler", None))
                right.append(DiffRow(b[k], "insert", k + 1))
                added += 1
        else:  # replace
            rows = max(op.i2 - op.i1, op.j2 - op.j1)
            for k in range(rows):
                li = op.i1 + k
                rj = op.j1 + k
                if li < op.i2:
                    left.append(DiffRow(a[li], "delete", li + 1))
                    removed += 1
                else:
                    left.append(DiffRow("", "filler", None))
                if rj < op.j2:
                    right.append(DiffRow(b[rj], "insert", rj + 1))
                    added += 1
                else:
                    right.append(DiffRow("", "filler", None))
    return left, right, added, removed


# ============================================================================
#  样式（Bootstrap 5 风格）
# ============================================================================

QSS = """
* {
    font-family: "Segoe UI", "Microsoft YaHei UI", "Microsoft YaHei", sans-serif;
    font-size: 13px;
}
QMainWindow, QWidget#Root { background: #f5f7fb; }

/* ---------- 顶栏 ---------- */
QFrame#NavBar { background: #0d6efd; border: none; }
QLabel#NavTitle { color: #ffffff; font-size: 16px; font-weight: 700; }
QLabel#NavStatus { color: rgba(255,255,255,0.92); font-size: 12px; }

/* ---------- 卡片 ---------- */
QFrame#Card {
    background: #ffffff;
    border: 1px solid #e6e9ef;
    border-radius: 12px;
}
QLabel#CardTitle { font-size: 14px; font-weight: 700; color: #212529; }
QLabel#PageTitle { font-size: 20px; font-weight: 700; color: #212529; }
QLabel#PageDesc  { color: #6c757d; }
QLabel#Muted     { color: #6c757d; }
QLabel#Metric    { font-size: 22px; font-weight: 700; color: #0d6efd; }

/* ---------- 首页两个大选项 ---------- */
QFrame#OptionCard {
    background: #ffffff;
    border: 1px solid #e6e9ef;
    border-radius: 14px;
}
QFrame#OptionCard:hover { border: 1px solid #0d6efd; background: #f7fbff; }
QLabel#OptionTitle { font-size: 17px; font-weight: 700; color: #212529; }
QLabel#OptionDesc  { color: #6c757d; }

/* ---------- 按钮 ---------- */
QPushButton {
    border-radius: 8px;
    padding: 8px 18px;
    font-weight: 600;
    border: 1px solid transparent;
}
QPushButton:disabled { background: #e9ecef; color: #adb5bd; border-color: #e9ecef; }

QPushButton#Primary { background: #0d6efd; color: #ffffff; }
QPushButton#Primary:hover { background: #0b5ed7; }
QPushButton#Primary:pressed { background: #0a58ca; }

QPushButton#Success { background: #198754; color: #ffffff; }
QPushButton#Success:hover { background: #157347; }
QPushButton#Success:pressed { background: #146c43; }

QPushButton#Secondary { background: #ffffff; color: #0d6efd; border: 1px solid #0d6efd; }
QPushButton#Secondary:hover { background: #eef5ff; }

QPushButton#Ghost { background: #eef0f4; color: #495057; }
QPushButton#Ghost:hover { background: #e2e6ea; }

/* 顶栏上的按钮（深色底） */
QPushButton#NavBtn {
    background: rgba(255,255,255,0.16);
    color: #ffffff;
    border: 1px solid rgba(255,255,255,0.38);
    padding: 6px 16px;
}
QPushButton#NavBtn:hover { background: rgba(255,255,255,0.30); }
QPushButton#NavBtn:pressed { background: rgba(255,255,255,0.42); }

/* ---------- 对话框 ---------- */
QDialog { background: #f5f7fb; }
QLineEdit {
    background: #ffffff;
    border: 1px solid #ced4da;
    border-radius: 8px;
    padding: 8px 12px;
    selection-background-color: #cfe2ff;
}
QLineEdit:focus { border-color: #0d6efd; }

/* ---------- 表格 ---------- */
QTableWidget {
    background: #ffffff;
    border: 1px solid #e6e9ef;
    border-radius: 10px;
    gridline-color: #eef0f4;
    selection-background-color: #dbe9ff;
    selection-color: #212529;
}
QTableWidget::item { padding: 6px 8px; border: none; }
QHeaderView::section {
    background: #f1f3f5;
    color: #495057;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #e6e9ef;
    font-weight: 600;
}

/* ---------- 输入控件 ---------- */
QPlainTextEdit, QTextEdit {
    background: #ffffff;
    border: 1px solid #e6e9ef;
    border-radius: 10px;
    selection-background-color: #cfe2ff;
    selection-color: #212529;
}
QCheckBox { color: #495057; spacing: 6px; }
QComboBox {
    background: #ffffff; border: 1px solid #ced4da;
    border-radius: 8px; padding: 6px 10px;
}
QComboBox:hover { border-color: #0d6efd; }
QComboBox::drop-down { border: none; width: 20px; }

/* ---------- 进度条 ---------- */
QProgressBar {
    background: #e9ecef;
    border: none;
    border-radius: 7px;
    height: 14px;
    text-align: center;
    color: #495057;
    font-size: 11px;
}
QProgressBar::chunk { background: #0d6efd; border-radius: 7px; }

/* ---------- 日志 ---------- */
QPlainTextEdit#Log { font-family: "Cascadia Mono", "Consolas", monospace; font-size: 12px; }

QStatusBar { background: #ffffff; color: #6c757d; }
QSplitter::handle { background: #eef0f4; }
QSplitter::handle:horizontal { width: 4px; }
"""

# diff 视图配色
COLOR_DELETE_BG = "#ffe6e6"
COLOR_INSERT_BG = "#e3f9e5"
COLOR_FILLER_BG = "#f1f3f5"
COLOR_DELETE_FG = "#8a1c1c"
COLOR_INSERT_FG = "#14622b"
COLOR_LINENO_BG = "#f8f9fa"
COLOR_LINENO_FG = "#adb5bd"


# ============================================================================
#  后台任务
# ============================================================================

def _make_worker_class():
    from PyQt6.QtCore import QThread, pyqtSignal

    class Worker(QThread):
        sig_log = pyqtSignal(str, str)        # (level, message)
        sig_progress = pyqtSignal(int, int, str)
        sig_done = pyqtSignal(object)
        sig_fail = pyqtSignal(str)

        def __init__(self, fn, parent=None):
            super().__init__(parent)
            self._fn = fn

        def run(self):
            try:
                result = self._fn(self._log, self._progress)
            except Exception as exc:  # noqa: BLE001 - 统一回报到 UI
                self.sig_fail.emit(f"{type(exc).__name__}: {exc}")
            else:
                self.sig_done.emit(result)

        def _log(self, message: str, level: str = "info") -> None:
            self.sig_log.emit(level, message)

        def _progress(self, current: int, total: int, label: str = "") -> None:
            self.sig_progress.emit(current, total, label)

    return Worker


def _make_line_number_area_class():
    from PyQt6.QtCore import QSize, Qt
    from PyQt6.QtWidgets import QWidget

    class LineNumberArea(QWidget):
        def __init__(self, editor):
            super().__init__(editor)
            self._editor = editor

        def sizeHint(self):
            return QSize(self._editor.line_number_area_width(), 0)

        def paintEvent(self, event):
            self._editor.line_number_area_paint_event(event)

    return LineNumberArea


# ============================================================================
#  界面
# ============================================================================

def build_ui_classes():
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import (
        QColor,
        QFont,
        QTextBlockFormat,
        QTextCharFormat,
        QTextCursor,
    )
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QCheckBox,
        QComboBox,
        QDialog,
        QFrame,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QSizePolicy,
        QSplitter,
        QStackedWidget,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )

    Worker = _make_worker_class()
    LineNumberArea = _make_line_number_area_class()

    def make_button(text: str, kind: str = "Primary") -> QPushButton:
        btn = QPushButton(text)
        btn.setObjectName(kind)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        return btn

    # ------------------------------------------------------------------ 代码窗格

    class CodePane(QPlainTextEdit):
        """带行号、可按行着色的只读文本窗格。"""

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setReadOnly(True)
            self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            font = QFont()
            font.setFamilies(["Cascadia Mono", "Consolas", "Courier New", "monospace"])
            font.setStyleHint(QFont.StyleHint.Monospace)
            font.setPointSize(10)
            self.setFont(font)
            self._labels: list[str] = []
            self._area = LineNumberArea(self)
            self.blockCountChanged.connect(self._update_area_width)
            self.updateRequest.connect(self._update_area)
            self._update_area_width()

        # ---- 行号区域 ----
        def line_number_area_width(self) -> int:
            digits = max(3, len(str(max(1, self.blockCount()))))
            return 14 + self.fontMetrics().horizontalAdvance("9") * digits

        def _update_area_width(self, *_):
            self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

        def _update_area(self, rect, dy):
            if dy:
                self._area.scroll(0, dy)
            else:
                self._area.update(0, rect.y(), self._area.width(), rect.height())
            if rect.contains(self.viewport().rect()):
                self._update_area_width()

        def resizeEvent(self, event):
            super().resizeEvent(event)
            cr = self.contentsRect()
            self._area.setGeometry(
                cr.left(), cr.top(), self.line_number_area_width(), cr.height()
            )

        def line_number_area_paint_event(self, event):
            from PyQt6.QtGui import QPainter
            painter = QPainter(self._area)
            painter.fillRect(event.rect(), QColor(COLOR_LINENO_BG))
            painter.setPen(QColor(COLOR_LINENO_FG))

            block = self.firstVisibleBlock()
            block_number = block.blockNumber()
            top = int(
                self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
            )
            bottom = top + int(self.blockBoundingRect(block).height())
            height = self.fontMetrics().height()
            width = self._area.width() - 6

            while block.isValid() and top <= event.rect().bottom():
                if block.isVisible() and bottom >= event.rect().top():
                    label = (
                        self._labels[block_number]
                        if block_number < len(self._labels) else ""
                    )
                    painter.drawText(
                        0, top, width, height,
                        int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                        label,
                    )
                block = block.next()
                top = bottom
                bottom = top + int(self.blockBoundingRect(block).height())
                block_number += 1

        # ---- 内容渲染 ----
        def render_rows(self, rows) -> None:
            self.setPlainText("\n".join(r.text for r in rows))
            self._labels = [str(r.lineno) if r.lineno else "" for r in rows]

            backgrounds = {
                "delete": QColor(COLOR_DELETE_BG),
                "insert": QColor(COLOR_INSERT_BG),
                "filler": QColor(COLOR_FILLER_BG),
            }
            foregrounds = {
                "delete": QColor(COLOR_DELETE_FG),
                "insert": QColor(COLOR_INSERT_FG),
            }

            block = self.document().begin()
            index = 0
            while block.isValid():
                kind = rows[index].kind if index < len(rows) else "equal"
                cursor = QTextCursor(block)
                cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
                if kind in backgrounds:
                    fmt = QTextBlockFormat()
                    fmt.setBackground(backgrounds[kind])
                    cursor.setBlockFormat(fmt)
                if kind in foregrounds:
                    char_fmt = QTextCharFormat()
                    char_fmt.setForeground(foregrounds[kind])
                    cursor.setCharFormat(char_fmt)
                cursor.clearSelection()
                block = block.next()
                index += 1

            self._labels = self._labels[: max(index, 1)]
            self.moveCursor(QTextCursor.MoveOperation.Start)

    # ------------------------------------------------------------------ 顶栏

    class NavBar(QFrame):
        def __init__(self, on_settings):
            super().__init__()
            self.setObjectName("NavBar")
            self.setFixedHeight(56)
            layout = QHBoxLayout(self)
            layout.setContentsMargins(20, 0, 20, 0)
            layout.setSpacing(14)

            title = QLabel(APP_TITLE)
            title.setObjectName("NavTitle")
            layout.addWidget(title)
            layout.addStretch(1)

            self.status = QLabel("未连接")
            self.status.setObjectName("NavStatus")
            layout.addWidget(self.status)

            settings_btn = make_button("设置", "NavBtn")
            settings_btn.setToolTip("配置远端接口地址，并执行连接测试 / 密钥生成等命令")
            settings_btn.clicked.connect(on_settings)
            layout.addWidget(settings_btn)

        def set_status(self, text: str) -> None:
            self.status.setText(text)

    # ------------------------------------------------------------------ 首页

    class OptionCard(QFrame):
        def __init__(self, title: str, desc: str, on_click):
            super().__init__()
            self.setObjectName("OptionCard")
            self.setCursor(Qt.CursorShape.PointingHandCursor)
            self.setMinimumHeight(150)
            self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            self._on_click = on_click

            layout = QVBoxLayout(self)
            layout.setContentsMargins(24, 22, 24, 22)
            layout.setSpacing(8)

            lbl_title = QLabel(title)
            lbl_title.setObjectName("OptionTitle")
            lbl_desc = QLabel(desc)
            lbl_desc.setObjectName("OptionDesc")
            lbl_desc.setWordWrap(True)
            layout.addWidget(lbl_title)
            layout.addWidget(lbl_desc)
            layout.addStretch(1)

        def mouseReleaseEvent(self, event):
            if event.button() == Qt.MouseButton.LeftButton:
                self._on_click()
            super().mouseReleaseEvent(event)

    class HomePage(QWidget):
        def __init__(self, on_upload, on_diff):
            super().__init__()
            layout = QVBoxLayout(self)
            layout.setContentsMargins(48, 40, 48, 40)
            layout.setSpacing(24)

            title = QLabel("选择要执行的操作")
            title.setObjectName("PageTitle")
            desc = QLabel(f"本地目录：{LOCAL_DIR}")
            desc.setObjectName("PageDesc")
            self.lbl_server = QLabel("")
            self.lbl_server.setObjectName("PageDesc")
            self.lbl_server.setWordWrap(True)
            layout.addWidget(title)
            layout.addWidget(desc)
            layout.addWidget(self.lbl_server)
            layout.addSpacing(6)

            row = QHBoxLayout()
            row.setSpacing(20)
            row.addWidget(OptionCard(
                "上传文件",
                "把 local_files 中的全部文件同步到远端，同名覆盖；\n"
                "远端多出来的文件会被移入 ignored/ 目录归档（api.php 除外）。",
                on_upload,
            ))
            row.addWidget(OptionCard(
                "文件对比",
                "按行对比本地与远端同名文件的内容，\n"
                "差异以左右对照方式高亮显示。",
                on_diff,
            ))
            layout.addLayout(row)
            layout.addStretch(1)

            self.set_server_url(configured_server_url())

        def set_server_url(self, url: str) -> None:
            self.lbl_server.setText(f"远端接口：{url}")

    # ------------------------------------------------------------------ 页眉

    class PageHeader(QWidget):
        def __init__(self, title: str, desc: str, on_back):
            super().__init__()
            layout = QHBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(14)

            back = make_button("返回", "Ghost")
            back.clicked.connect(on_back)
            layout.addWidget(back, 0, Qt.AlignmentFlag.AlignTop)

            box = QVBoxLayout()
            box.setSpacing(4)
            lbl_title = QLabel(title)
            lbl_title.setObjectName("PageTitle")
            lbl_desc = QLabel(desc)
            lbl_desc.setObjectName("PageDesc")
            lbl_desc.setWordWrap(True)
            box.addWidget(lbl_title)
            box.addWidget(lbl_desc)
            layout.addLayout(box, 1)
            self._layout = layout

        def add_right(self, widget) -> None:
            self._layout.addWidget(widget, 0, Qt.AlignmentFlag.AlignTop)

    # ------------------------------------------------------------------ 卡片

    class Card(QFrame):
        def __init__(self, title: str = ""):
            super().__init__()
            self.setObjectName("Card")
            self.body = QVBoxLayout(self)
            self.body.setContentsMargins(18, 16, 18, 16)
            self.body.setSpacing(10)
            if title:
                label = QLabel(title)
                label.setObjectName("CardTitle")
                self.body.addWidget(label)

    # ------------------------------------------------------------------ 日志

    class LogView(QPlainTextEdit):
        COLORS = {
            "info": "#495057",
            "ok": "#198754",
            "warn": "#b8860b",
            "error": "#dc3545",
            "step": "#0d6efd",
        }

        def __init__(self):
            super().__init__()
            self.setObjectName("Log")
            self.setReadOnly(True)

        def append_line(self, level: str, message: str) -> None:
            color = self.COLORS.get(level, "#495057")
            stamp = time.strftime("%H:%M:%S")
            body = _html_escape(message).replace("\n", "<br>")
            text = (
                f'<span style="color:#adb5bd">{stamp}</span> '
                f'<span style="color:{color}">{body}</span>'
            )
            self.appendHtml(text)
            self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    # ------------------------------------------------------------------ 设置

    class SettingsDialog(QDialog):
        """配置远端接口地址，并可直接执行 ping / list / genkeys / force。"""

        def __init__(self, parent, client: FileSyncClient, on_applied=None):
            super().__init__(parent)
            self.client = client
            self.on_applied = on_applied
            self.worker = None
            self.cmd_buttons = []

            self.setWindowTitle("设置")
            self.setMinimumWidth(680)
            self.resize(720, 600)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(20, 20, 20, 20)
            layout.setSpacing(16)

            # ---------- 远端地址 ----------
            addr_card = Card("远端接口地址")
            addr_row = QHBoxLayout()
            addr_row.setSpacing(10)
            self.url_edit = QLineEdit(self.client.url)
            self.url_edit.setPlaceholderText(DEFAULT_SERVER_URL)
            self.url_edit.returnPressed.connect(self.apply_url)
            btn_apply = make_button("保存并应用", "Primary")
            btn_apply.clicked.connect(self.apply_url)
            addr_row.addWidget(self.url_edit, 1)
            addr_row.addWidget(btn_apply)
            addr_card.body.addLayout(addr_row)
            addr_hint = QLabel("保存后写入 client_config.json，上传与对比立即使用新地址。")
            addr_hint.setObjectName("Muted")
            addr_card.body.addWidget(addr_hint)
            layout.addWidget(addr_card)

            # ---------- 快捷命令 ----------
            cmd_card = Card("快捷命令")
            cmd_row = QHBoxLayout()
            cmd_row.setSpacing(10)
            commands = [
                ("--ping", "测试连通性、双向签名校验与服务端配置"),
                ("--list", "列出远端当前所有文件"),
                ("--genkeys", "生成两对密钥（已存在时不覆盖）"),
                ("--genkeys --force", "强制重新生成密钥（旧密钥立即失效）"),
            ]
            for label, tip in commands:
                btn = make_button(label, "Secondary")
                btn.setToolTip(tip)
                btn.clicked.connect(lambda _checked=False, text=label: self.run_command(text))
                cmd_row.addWidget(btn)
                self.cmd_buttons.append(btn)
            cmd_card.body.addLayout(cmd_row)
            cmd_hint = QLabel("命令针对上方地址执行；地址若有改动会先自动保存并应用。")
            cmd_hint.setObjectName("Muted")
            cmd_card.body.addWidget(cmd_hint)
            layout.addWidget(cmd_card)

            # ---------- 输出 ----------
            out_card = Card("输出")
            self.output = LogView()
            out_card.body.addWidget(self.output)
            layout.addWidget(out_card, 1)

            self.output.append_line("info", f"远端接口：{self.client.url}")
            self.output.append_line("info", f"密钥目录：{KEY_DIR}")

        # ---------------- 地址 ----------------

        def apply_url(self) -> bool:
            url = self.url_edit.text().strip()
            if not url:
                self.output.append_line("error", "地址不能为空")
                return False
            if not url.lower().startswith(("http://", "https://")):
                self.output.append_line("error", "地址需要以 http:// 或 https:// 开头")
                return False
            self.client.url = url
            config = load_client_config()
            config["server_url"] = url
            try:
                save_client_config(config)
            except OSError as exc:
                self.output.append_line("error", f"写入 client_config.json 失败：{exc}")
                return False
            self.url_edit.setText(url)
            self.output.append_line("ok", f"已保存并应用：{url}")
            if self.on_applied:
                self.on_applied(url)
            return True

        # ---------------- 命令 ----------------

        def run_command(self, label: str) -> None:
            if self.worker is not None and self.worker.isRunning():
                self.output.append_line("warn", "上一条命令还在执行中，请稍候")
                return
            if not self.apply_url():
                return

            self._busy(True)
            self.output.append_line("step", f"$ python main.py {label}")

            if label == "--ping":
                task = self._task_ping
            elif label == "--list":
                task = self._task_list
            else:
                force = "--force" in label
                task = lambda log, progress, f=force: self._task_genkeys(log, f)

            self.worker = Worker(task, self)
            self.worker.sig_log.connect(self.output.append_line)
            self.worker.sig_done.connect(self._on_done)
            self.worker.sig_fail.connect(self._on_fail)
            self.worker.start()

        def _busy(self, busy: bool) -> None:
            for btn in self.cmd_buttons:
                btn.setEnabled(not busy)

        def _on_done(self, _result) -> None:
            self._busy(False)

        def _on_fail(self, message: str) -> None:
            self._busy(False)
            self.output.append_line("error", message)

        def _task_ping(self, log, progress):
            info = self.client.ping()
            log(f"连接成功：{self.client.url}", "ok")
            for key, value in info.items():
                log(f"  {key}: {value}")
            return None

        def _task_list(self, log, progress):
            files = self.client.list_files()
            for item in files:
                log(f"{_human_size(item.get('size')):>10}  "
                    f"{str(item.get('sha256', ''))[:12]}  {item.get('path')}")
            log(f"共 {len(files)} 个文件", "ok")
            return None

        def _task_genkeys(self, log, force: bool):
            for line in generate_keys(force=force):
                if not line:
                    continue
                level = "ok" if line.startswith("密钥已生成") else "info"
                log(line, level)
            return None

    # ------------------------------------------------------------------ 上传页

    class UploadPage(QWidget):
        def __init__(self, client: FileSyncClient, on_back):
            super().__init__()
            self.client = client
            self.worker: Worker | None = None
            # 单次请求的原始字节预算；被服务端 413 拒绝后会调低并在本次会话内记住
            self._upload_budget = UPLOAD_CHUNK_BYTES

            layout = QVBoxLayout(self)
            layout.setContentsMargins(28, 24, 28, 24)
            layout.setSpacing(18)

            layout.addWidget(PageHeader(
                "上传文件",
                "local_files → 远端站点根目录；同名覆盖，多余文件移入 ignored/ 归档。",
                on_back,
            ))

            # 统计卡片
            stats = QHBoxLayout()
            stats.setSpacing(16)
            self.card_local = Card("本地文件")
            self.lbl_local = QLabel("—")
            self.lbl_local.setObjectName("Metric")
            self.card_local.body.addWidget(self.lbl_local)
            self.card_remote = Card("远端文件")
            self.lbl_remote = QLabel("—")
            self.lbl_remote.setObjectName("Metric")
            self.card_remote.body.addWidget(self.lbl_remote)
            self.card_plan = Card("本次计划")
            self.lbl_plan = QLabel("—")
            self.lbl_plan.setObjectName("Metric")
            self.card_plan.body.addWidget(self.lbl_plan)
            for c in (self.card_local, self.card_remote, self.card_plan):
                stats.addWidget(c, 1)
            layout.addLayout(stats)

            # 操作区
            actions = Card()
            row = QHBoxLayout()
            row.setSpacing(12)
            self.check_skip = QCheckBox("跳过内容完全相同的文件（推荐）")
            self.check_skip.setChecked(True)
            self.check_bump = QCheckBox("自动刷新静态资源版本号（?v=）")
            self.check_bump.setChecked(True)
            self.btn_scan = make_button("扫描远端", "Secondary")
            self.btn_upload = make_button("开始上传", "Primary")
            self.btn_scan.clicked.connect(self.on_scan)
            self.btn_upload.clicked.connect(self.on_upload)
            row.addWidget(self.check_skip)
            row.addWidget(self.check_bump)
            row.addStretch(1)
            row.addWidget(self.btn_scan)
            row.addWidget(self.btn_upload)
            actions.body.addLayout(row)

            self.progress = QProgressBar()
            self.progress.setRange(0, 100)
            self.progress.setValue(0)
            actions.body.addWidget(self.progress)
            layout.addWidget(actions)

            self.log = LogView()
            layout.addWidget(self.log, 1)

        # ---------------- 通用执行 ----------------

        def _busy(self, busy: bool) -> None:
            self.btn_scan.setEnabled(not busy)
            self.btn_upload.setEnabled(not busy)

        def _run(self, fn, title: str) -> None:
            if self.worker is not None and self.worker.isRunning():
                return
            self._busy(True)
            self.progress.setValue(0)
            self.log.append_line("step", f"— {title} —")
            self.worker = Worker(fn, self)
            self.worker.sig_log.connect(self.log.append_line)
            self.worker.sig_progress.connect(self._on_progress)
            self.worker.sig_done.connect(self._on_done)
            self.worker.sig_fail.connect(self._on_fail)
            self.worker.start()

        def _on_progress(self, current: int, total: int, label: str) -> None:
            if total <= 0:
                self.progress.setRange(0, 0)
                return
            self.progress.setRange(0, total)
            self.progress.setValue(current)
            if label:
                self.progress.setFormat(f"{label}  %p%")

        def _on_done(self, result) -> None:
            self._busy(False)
            self.progress.setRange(0, 100)
            self.progress.setValue(100)
            self.progress.setFormat("%p%")
            if isinstance(result, dict):
                self._apply_stats(result)

        def _on_fail(self, message: str) -> None:
            self._busy(False)
            self.progress.setRange(0, 100)
            self.progress.setValue(0)
            self.log.append_line("error", message)

        def _apply_stats(self, result: dict) -> None:
            if "local_count" in result:
                self.lbl_local.setText(str(result["local_count"]))
            if "remote_count" in result:
                self.lbl_remote.setText(str(result["remote_count"]))
            if "plan" in result:
                self.lbl_plan.setText(str(result["plan"]))

        # ---------------- 扫描 ----------------

        def on_scan(self) -> None:
            self._run(self._task_scan, "扫描两端")

        def _task_scan(self, log, progress):
            log("正在连接远端 ...")
            info = self.client.ping()
            log(f"连接成功：服务端 v{info.get('version')}"
                f"（构建 {info.get('api_build') or '未知'}），PHP {info.get('php_version')}", "ok")
            log(f"远端归档目录已有 {info.get('ignored_count', 0)} 个文件")

            progress(0, 1, "扫描本地")
            local = scan_local(LOCAL_DIR)
            log(f"本地文件 {len(local)} 个", "ok")

            progress(0, 1, "扫描远端")
            remote = {f["path"]: f for f in self.client.list_files()}
            log(f"远端文件 {len(remote)} 个", "ok")

            changed = [
                p for p, item in local.items()
                if remote.get(p, {}).get("sha256") != item["sha256"]
            ]
            extra = [p for p in remote if p not in local]
            log(f"需要上传 {len(changed)} 个，远端多余待归档 {len(extra)} 个", "step")

            progress(1, 1, "完成")
            return {
                "local_count": len(local),
                "remote_count": len(remote),
                "plan": f"{len(changed)} / {len(extra)}",
            }

        # ---------------- 上传 ----------------

        def on_upload(self) -> None:
            skip_same = self.check_skip.isChecked()
            bump_assets = self.check_bump.isChecked()
            self._run(
                lambda log, progress: self._task_upload(
                    log, progress, skip_same, bump_assets
                ),
                "上传并归档",
            )

        def _task_upload(self, log, progress, skip_same: bool, bump_assets: bool):
            log("正在连接远端 ...")
            info = self.client.ping()
            capabilities = set(info.get("features") or [])
            log(f"连接成功：服务端 v{info.get('version')}"
                f"（构建 {info.get('api_build') or '未知'}），PHP {info.get('php_version')}", "ok")

            local = scan_local(LOCAL_DIR)
            if not local:
                raise FileSyncError(f"本地目录为空或不存在：{LOCAL_DIR}")
            log(f"本地文件 {len(local)} 个", "ok")

            # 刷新页面里的静态资源版本号（?v= 取被引用文件的内容哈希）。
            # 必须在扫描之后、比对之前重算 sha256，否则会把新内容配上旧哈希发出去。
            if bump_assets:
                htmls = sorted(
                    rel for rel in local if rel.lower().endswith((".html", ".htm"))
                )
                if htmls:
                    cache: dict[str, str] = {}
                    refs = sum(
                        bump_asset_versions(LOCAL_DIR / rel, LOCAL_DIR, cache)
                        for rel in htmls
                    )
                    if refs:
                        local = scan_local(LOCAL_DIR)
                        log(f"静态资源版本号已刷新：{refs} 处 -> ?v=<内容哈希前 12 位>")

            remote = {f["path"]: f for f in self.client.list_files()}
            log(f"远端文件 {len(remote)} 个", "ok")

            if skip_same:
                pending = [
                    item for path, item in sorted(local.items())
                    if remote.get(path, {}).get("sha256") != item["sha256"]
                ]
                log(f"内容有变化的文件 {len(pending)} 个（其余跳过）")
            else:
                pending = [item for _, item in sorted(local.items())]
                log(f"将上传全部 {len(pending)} 个文件（覆盖同名）")

            if not pending:
                log("没有需要上传的文件", "ok")

            # 分片上传：小文件成批打包、大文件按预算切片，遇 413 自动降档
            uploaded, failures, self._upload_budget = upload_pending(
                self.client, pending, log, progress, self._upload_budget, capabilities
            )
            total_bytes = sum(item["size"] for item in pending) or 1

            if failures:
                for item in failures:
                    log(f"写入失败：{item.get('path')}（{item.get('error')}）", "error")

            # 归档远端多余文件
            progress(total_bytes, total_bytes, "归档多余文件")
            log("正在归档远端多余文件 ...")
            result = self.client.prune(list(local.keys()))
            moved = result.get("moved", [])
            if moved:
                for path in moved[:20]:
                    log(f"已归档 -> ignored/{path}", "warn")
                if len(moved) > 20:
                    log(f"... 其余 {len(moved) - 20} 个已归档", "warn")
            else:
                log("远端没有多余文件需要归档", "ok")

            for item in result.get("errors", []):
                log(f"归档失败：{item.get('path')}（{item.get('error')}）", "error")

            after = self.client.list_files()
            log(
                f"完成：上传 {uploaded} 个，归档 {len(moved)} 个，"
                f"远端现有 {len(after)} 个文件",
                "ok",
            )
            progress(total_bytes, total_bytes, "完成")
            return {
                "local_count": len(local),
                "remote_count": len(after),
                "plan": f"上传 {uploaded} / 归档 {len(moved)}",
            }

    # ------------------------------------------------------------------ 对比页

    @dataclass
    class Comparison:
        path: str
        status: str           # same / diff / local_only / remote_only
        local_size: int | None
        remote_size: int | None
        local_sha: str | None
        remote_sha: str | None

    STATUS_TEXT = {
        "same": "相同",
        "diff": "内容不同",
        "local_only": "仅本地",
        "remote_only": "仅远端",
    }
    STATUS_COLOR = {
        "same": "#198754",
        "diff": "#dc3545",
        "local_only": "#0d6efd",
        "remote_only": "#b8860b",
    }

    class DiffViewer(QWidget):
        def __init__(self):
            super().__init__()
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(8)

            head = QHBoxLayout()
            self.lbl_path = QLabel("未选择文件")
            self.lbl_path.setObjectName("CardTitle")
            self.lbl_stat = QLabel("")
            self.lbl_stat.setObjectName("Muted")
            head.addWidget(self.lbl_path)
            head.addStretch(1)
            head.addWidget(self.lbl_stat)
            layout.addLayout(head)

            self.splitter = QSplitter(Qt.Orientation.Horizontal)
            self.left_title = QLabel("本地")
            self.right_title = QLabel("远端")
            left_box = QWidget()
            lv = QVBoxLayout(left_box)
            lv.setContentsMargins(0, 0, 0, 0)
            lv.setSpacing(4)
            self.left_title.setObjectName("Muted")
            lv.addWidget(self.left_title)
            self.pane_left = CodePane()
            lv.addWidget(self.pane_left)

            right_box = QWidget()
            rv = QVBoxLayout(right_box)
            rv.setContentsMargins(0, 0, 0, 0)
            rv.setSpacing(4)
            self.right_title.setObjectName("Muted")
            rv.addWidget(self.right_title)
            self.pane_right = CodePane()
            rv.addWidget(self.pane_right)

            self.splitter.addWidget(left_box)
            self.splitter.addWidget(right_box)
            self.splitter.setSizes([520, 520])
            layout.addWidget(self.splitter, 1)

            # 左右滚动同步
            self.pane_left.verticalScrollBar().valueChanged.connect(
                self.pane_right.verticalScrollBar().setValue
            )
            self.pane_right.verticalScrollBar().valueChanged.connect(
                self.pane_left.verticalScrollBar().setValue
            )
            self.pane_left.horizontalScrollBar().valueChanged.connect(
                self.pane_right.horizontalScrollBar().setValue
            )
            self.pane_right.horizontalScrollBar().valueChanged.connect(
                self.pane_left.horizontalScrollBar().setValue
            )

        def show_message(self, title: str, message: str) -> None:
            self.lbl_path.setText(title)
            self.lbl_stat.setText("")
            self.left_title.setText("本地")
            self.right_title.setText("远端")
            self.pane_left.render_rows([])
            self.pane_right.render_rows([])
            self.pane_left.setPlainText(message)

        def show_diff(
            self,
            path: str,
            local_text: str,
            remote_text: str,
            local_label: str = "本地",
            remote_label: str = "远端",
        ) -> None:
            a = local_text.splitlines()
            b = remote_text.splitlines()
            ops = diff_lines(a, b)
            left_rows, right_rows, added, removed = build_diff_rows(a, b, ops)

            self.lbl_path.setText(path)
            if added == 0 and removed == 0:
                self.lbl_stat.setText(f"两端一致（{len(a)} 行）")
            else:
                self.lbl_stat.setText(f"+{added} 行  -{removed} 行")
            self.left_title.setText(f"{local_label}（{len(a)} 行）")
            self.right_title.setText(f"{remote_label}（{len(b)} 行）")
            self.pane_left.render_rows(left_rows)
            self.pane_right.render_rows(right_rows)

    class DiffPage(QWidget):
        def __init__(self, client: FileSyncClient, on_back):
            super().__init__()
            self.client = client
            self.worker: Worker | None = None
            self.rows: list = []
            self.remote_cache: dict[str, bytes] = {}

            layout = QVBoxLayout(self)
            layout.setContentsMargins(28, 24, 28, 24)
            layout.setSpacing(16)

            header = PageHeader(
                "文件对比",
                "按行对比两端同名文件；选择左侧列表中的文件查看差异。",
                on_back,
            )
            self.btn_refresh = make_button("重新对比", "Primary")
            self.btn_refresh.clicked.connect(self.on_refresh)
            header.add_right(self.btn_refresh)
            layout.addWidget(header)

            bar = QHBoxLayout()
            bar.setSpacing(10)
            self.filter = QComboBox()
            self.filter.addItems(["全部", "仅显示差异", "仅本地", "仅远端", "内容相同"])
            self.filter.currentIndexChanged.connect(self._fill_table)
            self.lbl_summary = QLabel("尚未对比")
            self.lbl_summary.setObjectName("Muted")
            bar.addWidget(QLabel("筛选："))
            bar.addWidget(self.filter)
            bar.addStretch(1)
            bar.addWidget(self.lbl_summary)
            layout.addLayout(bar)

            splitter = QSplitter(Qt.Orientation.Horizontal)
            self.table = QTableWidget(0, 4)
            self.table.setHorizontalHeaderLabels(["状态", "路径", "本地", "远端"])
            self.table.verticalHeader().setVisible(False)
            self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            self.table.setAlternatingRowColors(False)
            header_view = self.table.horizontalHeader()
            header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            self.table.itemSelectionChanged.connect(self._on_select)

            self.viewer = DiffViewer()
            splitter.addWidget(self.table)
            splitter.addWidget(self.viewer)
            splitter.setSizes([420, 760])
            layout.addWidget(splitter, 1)

            self.viewer.show_message("未选择文件", "先点击右上角「重新对比」，再选择左侧文件。")

        # ---------------- 对比 ----------------

        def on_refresh(self) -> None:
            if self.worker is not None and self.worker.isRunning():
                return
            self.btn_refresh.setEnabled(False)
            self.lbl_summary.setText("正在对比 ...")
            self.worker = Worker(self._task_compare, self)
            self.worker.sig_done.connect(self._on_compared)
            self.worker.sig_fail.connect(self._on_error)
            self.worker.start()

        def _task_compare(self, log, progress):
            progress(0, 1, "读取远端")
            remote = {f["path"]: f for f in self.client.list_files()}
            progress(0, 1, "读取本地")
            local = scan_local(LOCAL_DIR)

            rows: list[Comparison] = []
            for path in sorted(set(local) | set(remote)):
                l = local.get(path)
                r = remote.get(path)
                if l and r:
                    status = "same" if l["sha256"] == r["sha256"] else "diff"
                elif l:
                    status = "local_only"
                else:
                    status = "remote_only"
                rows.append(Comparison(
                    path=path,
                    status=status,
                    local_size=l["size"] if l else None,
                    remote_size=r["size"] if r else None,
                    local_sha=l["sha256"] if l else None,
                    remote_sha=r["sha256"] if r else None,
                ))
            return rows

        def _on_compared(self, rows) -> None:
            self.btn_refresh.setEnabled(True)
            self.rows = rows
            self.remote_cache.clear()
            self._fill_table()
            counts = {"same": 0, "diff": 0, "local_only": 0, "remote_only": 0}
            for row in rows:
                counts[row.status] += 1
            self.lbl_summary.setText(
                f"共 {len(rows)} 项 · 不同 {counts['diff']} · 仅本地 {counts['local_only']} · "
                f"仅远端 {counts['remote_only']} · 相同 {counts['same']}"
            )

        def _on_error(self, message: str) -> None:
            self.btn_refresh.setEnabled(True)
            self.lbl_summary.setText("对比失败")
            self.viewer.show_message("对比失败", message)

        def _fill_table(self, *_):
            wanted = self.filter.currentIndex()
            predicate = {
                0: lambda r: True,
                1: lambda r: r.status != "same",
                2: lambda r: r.status == "local_only",
                3: lambda r: r.status == "remote_only",
                4: lambda r: r.status == "same",
            }[wanted]
            rows = [r for r in self.rows if predicate(r)]

            self.table.setRowCount(len(rows))
            for index, row in enumerate(rows):
                status_item = QTableWidgetItem(STATUS_TEXT.get(row.status, row.status))
                status_item.setForeground(QColor(STATUS_COLOR.get(row.status, "#495057")))
                self.table.setItem(index, 0, status_item)
                self.table.setItem(index, 1, QTableWidgetItem(row.path))
                self.table.setItem(index, 2, QTableWidgetItem(_human_size(row.local_size)))
                self.table.setItem(index, 3, QTableWidgetItem(_human_size(row.remote_size)))

        # ---------------- 查看差异 ----------------

        def _selected(self) -> Comparison | None:
            items = self.table.selectedItems()
            if not items:
                return None
            path = self.table.item(items[0].row(), 1).text()
            for row in self.rows:
                if row.path == path:
                    return row
            return None

        def _on_select(self) -> None:
            row = self._selected()
            if row is None:
                return
            if row.status == "remote_only":
                self.viewer.show_message(row.path, "该文件只存在于远端（下次上传时会被归档到 ignored/）。")
                return
            if row.status == "local_only":
                self.viewer.show_message(row.path, "该文件只存在于本地（下次上传时会写入远端）。")
                return

            local_path = LOCAL_DIR / row.path
            try:
                local_bytes = local_path.read_bytes()
            except OSError as exc:
                self.viewer.show_message(row.path, f"读取本地文件失败：{exc}")
                return

            remote_bytes = self.remote_cache.get(row.path)
            if remote_bytes is None:
                if self.worker is not None and self.worker.isRunning():
                    return
                self.viewer.show_message(row.path, "正在从远端读取文件 ...")
                self.btn_refresh.setEnabled(False)
                self.worker = Worker(
                    lambda log, progress, p=row.path: self.client.read_file(p), self
                )
                self.worker.sig_done.connect(
                    lambda data, p=row.path, lb=local_bytes: self._show_pair(p, lb, data)
                )
                self.worker.sig_fail.connect(self._on_error)
                self.worker.start()
                return

            self._show_pair(row.path, local_bytes, remote_bytes)

        def _show_pair(self, path: str, local_bytes: bytes, remote_bytes: bytes) -> None:
            self.btn_refresh.setEnabled(True)
            self.remote_cache[path] = remote_bytes

            local_text = decode_text(local_bytes)
            remote_text = decode_text(remote_bytes)
            if local_text is None or remote_text is None:
                self.viewer.show_message(
                    path,
                    f"二进制文件，无法按行对比。\n\n"
                    f"本地：{len(local_bytes)} 字节\n"
                    f"远端：{len(remote_bytes)} 字节\n"
                    f"内容{'一致' if local_bytes == remote_bytes else '不一致'}。",
                )
                return
            self.viewer.show_diff(path, local_text, remote_text)

    # ------------------------------------------------------------------ 主窗口

    class MainWindow(QMainWindow):
        def __init__(self, client: FileSyncClient):
            super().__init__()
            self.client = client
            self.setWindowTitle(APP_TITLE)
            self.resize(1200, 780)

            root = QWidget()
            root.setObjectName("Root")
            # 普通 QWidget 默认不绘制样式表背景，需要显式开启
            root.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
            self.setCentralWidget(root)
            layout = QVBoxLayout(root)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            self.nav = NavBar(on_settings=self.open_settings)
            layout.addWidget(self.nav)

            self.stack = QStackedWidget()
            layout.addWidget(self.stack, 1)

            self.page_home = HomePage(
                on_upload=lambda: self._go(1),
                on_diff=lambda: self._go(2),
            )
            self.page_upload = UploadPage(self.client, on_back=lambda: self._go(0))
            self.page_diff = DiffPage(self.client, on_back=lambda: self._go(0))

            self.stack.addWidget(self.page_home)
            self.stack.addWidget(self.page_upload)
            self.stack.addWidget(self.page_diff)

            self.statusBar().showMessage(f"本地目录：{LOCAL_DIR}")
            self.nav.set_status(self.client.url)

        def open_settings(self) -> None:
            dialog = SettingsDialog(self, self.client, on_applied=self._on_settings_applied)
            dialog.exec()

        def _on_settings_applied(self, url: str) -> None:
            self.page_home.set_server_url(url)
            self.nav.set_status(url)
            self.statusBar().showMessage(f"远端接口已更新：{url}")

        def _go(self, index: int) -> None:
            self.stack.setCurrentIndex(index)
            if index == 0:
                self.nav.set_status(self.client.url)

    return MainWindow


# ============================================================================
#  小工具
# ============================================================================

def _html_escape(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _render_extra(value) -> str:
    """把服务端返回的排障字段渲染成多行文本。"""
    if isinstance(value, dict):
        return "".join(f"\n  {key}: {val}" for key, val in value.items())
    if isinstance(value, (list, tuple)):
        return "".join(f"\n  - {item}" for item in value)
    return str(value)


def _human_size(size: int | None) -> str:
    if size is None:
        return "—"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


# ============================================================================
#  入口
# ============================================================================

def cmd_ping() -> int:
    client = FileSyncClient()
    try:
        info = client.ping()
    except FileSyncError as exc:
        print(f"[失败] {exc}")
        return 1
    print("[成功] 连通性与双向签名校验通过"
          f"（服务端构建 {info.get('api_build', '未知 —— 可能是旧版 api.php')}）")
    print(f"  远端接口：{client.url}")
    for key, value in info.items():
        print(f"  {key}: {value}")
    return 0


def cmd_list() -> int:
    client = FileSyncClient()
    try:
        files = client.list_files()
    except FileSyncError as exc:
        print(f"[失败] {exc}")
        return 1
    for item in files:
        print(f"{item['size']:>10}  {item['sha256'][:12]}  {item['path']}")
    print(f"共 {len(files)} 个文件（远端接口：{client.url}）")
    return 0


def cmd_genkeys(force: bool) -> int:
    for line in generate_keys(force=force):
        print(line)
    return 0


# ============================================================================
#  启动自检：本地目录结构初始化
# ============================================================================
#
#  每次打开图形界面都会检查一遍。判定标准是「三项齐备」：
#
#     local_files/            要被同步上去的目录
#     keys/                   两把本地密钥（client_private.pem + server_public.pem）
#     client_config.json      远端接口地址
#
#  缺任一项就弹窗问是否初始化。点确定后：
#     1. 弹出文件列表（os.listdir 的结果），勾选要放进 local_files 的条目
#     2. 确认后建目录 / 补配置 / 缺密钥就生成 / 把勾中的条目移进 local_files
#
#  列表里三类条目的待遇（都写在下方的提示区里）：
#     · 不显示        —— 正在运行的本文件、client_config.json（本来就在根目录）
#     · ⛔ 不可勾选   —— 移进去会破坏客户端或把不该公开的东西同步上网
#     · 🟠 橙色警告   —— 被 .gitignore 标记；默认不勾，但允许勾

# 缺省 .gitignore 时用的内置清单，保证开箱就有意义
DEFAULT_IGNORE = (
    ".venv", "venv", "env", "__pycache__", "*.pyc", "*.pyo",
    ".git", ".svn", ".hg", ".idea", ".vscode", ".DS_Store",
    "node_modules", "*.log", "*.tmp", "*.bak",
)

# 列表里完全不显示的名字
def _hidden_from_list() -> set[str]:
    hidden = {"client_config.json"}
    for candidate in (sys.argv[0] if sys.argv else "", __file__):
        try:
            hidden.add(Path(candidate).resolve().name)
        except (OSError, ValueError):
            continue
    return hidden


# 显示但禁止勾选（名字 -> 原因）
LOCKED_IN_LIST = {
    "local_files": "目标目录本身，就是要往这里放东西",
    "keys": "客户端密钥目录，移进去会让私钥被同步上传到公网",
    "FileSync_Server": "服务端源文件，移进去会被同步到站点根目录",
    ".git": "版本库目录，移走会破坏仓库",
}


def _missing_structure() -> list[str]:
    """返回缺失的初始化项（人类可读的描述），齐备时返回空列表。"""
    missing: list[str] = []
    if not LOCAL_DIR.is_dir():
        missing.append("local_files/")
    local_keys = [KEY_DIR / KEY_CLIENT_PRIVATE, KEY_DIR / KEY_SERVER_PUBLIC]
    if not KEY_DIR.is_dir():
        missing.append("keys/")
    elif not all(p.is_file() for p in local_keys):
        missing.append("keys/ 里的本地密钥")
    if not CONFIG_PATH.is_file():
        missing.append("client_config.json")
    return missing


def _gitignore_rules() -> tuple[list[tuple[str, bool]], bool]:
    """读 .gitignore。

    返回 (规则列表, 是否用了内置清单)。
    规则 = [(pattern, negated), ...]，pattern 已去掉首尾斜杠与 `!` 前缀，
    按文件里的先后顺序生效（后面的规则可以覆盖前面的，与 git 一致）。

    两种情况会退回内置的 DEFAULT_IGNORE：
      · 根本没有 .gitignore
      · .gitignore 存在但一条规则都没有（空的 / 全是注释）
    后者容易被忽略：如果只用文件里的规则，一个橙色标记都不会出现，
    .venv / __pycache__ 这类反而没人提醒了，还不如没有这个文件。
    """
    path = BASE_DIR / ".gitignore"
    text = None
    if path.is_file():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = None

    rules: list[tuple[str, bool]] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:].strip()
        line = line.strip("/")
        if line:
            rules.append((line, negated))

    used_builtin = not rules
    if used_builtin:
        rules = [(pat, False) for pat in DEFAULT_IGNORE]
    return rules, used_builtin


def _ignored_names(names: list[str], rules: list[tuple[str, bool]]) -> set[str]:
    """算出 names 里哪些被规则命中。含斜杠的按路径匹配，不含的按名字匹配。"""
    hit: set[str] = set()
    for name in names:
        state = False
        for pattern, negated in rules:
            if "/" in pattern:
                matched = fnmatch.fnmatch(name, pattern) or name.startswith(pattern + "/")
            else:
                matched = fnmatch.fnmatch(name, pattern)
            if matched:
                state = not negated
        if state:
            hit.add(name)
    return hit


def _list_candidates() -> tuple[list[str], set[str], bool]:
    """列出根目录下可选的条目（已排序、已排除不显示的）。"""
    try:
        raw = os.listdir(BASE_DIR)
    except OSError:
        return [], set(), False
    hidden = _hidden_from_list()
    names = [n for n in raw if n not in hidden]
    # 目录在前，然后按名字排
    names.sort(key=lambda n: (not (BASE_DIR / n).is_dir(), n.lower()))
    rules, found = _gitignore_rules()
    return names, _ignored_names(names, rules), found


def _pick_files_to_archive(parent, names: list[str], ignored: set[str],
                           used_builtin: bool):
    """文件选择弹窗。返回勾选的名字列表；用户取消时返回 None。"""
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QBrush, QColor
    from PyQt6.QtWidgets import (
        QDialog, QDialogButtonBox, QLabel, QListWidget, QListWidgetItem,
        QVBoxLayout,
    )

    ORANGE = QColor("#d97706")
    GREY = QColor("#8a94a6")

    dlg = QDialog(parent)
    dlg.setWindowTitle(f"{APP_TITLE} — 初始化：选择要放进 local_files 的文件")
    dlg.resize(600, 560)

    lay = QVBoxLayout(dlg)

    head = QLabel(
        "勾选的文件 / 目录会被**移动**到 local_files/ 里（同步工具上传的就是这个目录）。\n"
        "移动是真正的移动，原位置不会再保留 —— 不放心就先自己备份一份。"
    )
    head.setWordWrap(True)
    lay.addWidget(head)

    lst = QListWidget()
    lst.setSelectionMode(QListWidget.SelectionMode.NoSelection)
    lay.addWidget(lst, 1)

    for name in names:
        full = BASE_DIR / name
        is_dir = full.is_dir()
        locked = name in LOCKED_IN_LIST

        item = QListWidgetItem(name + ("/" if is_dir else ""))
        item.setData(Qt.ItemDataRole.UserRole, name)

        if locked:
            # 不给复选框，直接在名字后面写明原因
            item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            item.setText(f"{item.text()}    ⛔ {LOCKED_IN_LIST[name]}")
            item.setForeground(QBrush(GREY))
        else:
            item.setFlags(
                Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable
            )
            item.setCheckState(Qt.CheckState.Unchecked)   # 默认一个都不勾
            if name in ignored:
                item.setForeground(QBrush(ORANGE))
        lst.addItem(item)

    warn = QLabel("🟠 橙色标注的文件被 .gitignore 标记，请谨慎勾选")
    warn.setStyleSheet("color:#d97706;")
    lay.addWidget(warn)

    note_bits = ["⛔ 标注的条目禁止移动（移了会破坏客户端，或把不该公开的文件同步上网）。"]
    if used_builtin:
        note_bits.append("未找到 .gitignore（或它里面没有任何规则），橙色清单用的内置默认值。")
    note = QLabel("\n".join(note_bits))
    note.setWordWrap(True)
    note.setStyleSheet("color:#8a94a6; font-size:12px;")
    lay.addWidget(note)

    box = QDialogButtonBox(
        QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
    )
    ok_btn = box.button(QDialogButtonBox.StandardButton.Ok)
    cancel_btn = box.button(QDialogButtonBox.StandardButton.Cancel)
    if ok_btn is not None:
        ok_btn.setText("确定")
    if cancel_btn is not None:
        cancel_btn.setText("取消")
    box.accepted.connect(dlg.accept)
    box.rejected.connect(dlg.reject)
    lay.addWidget(box)

    if dlg.exec() != QDialog.DialogCode.Accepted:
        return None

    chosen: list[str] = []
    for i in range(lst.count()):
        item = lst.item(i)
        if item.checkState() == Qt.CheckState.Checked:
            chosen.append(item.data(Qt.ItemDataRole.UserRole))
    return chosen


def _apply_init(chosen: list[str]) -> tuple[list[str], list[str], list[str]]:
    """真正落地：建目录 / 补配置 / 补密钥 / 移动文件。

    返回 (已移动, 已跳过, 提示信息)。
    """
    notes: list[str] = []

    LOCAL_DIR.mkdir(parents=True, exist_ok=True)
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    if not CONFIG_PATH.is_file():
        save_client_config({"server_url": DEFAULT_SERVER_URL})
        notes.append(f"已创建 client_config.json（远端地址默认 {DEFAULT_SERVER_URL}，"
                     "以后可在右上角「设置」里改）")

    # generate_keys 自己会跳过"已存在"的情况，所以直接调就行
    pair_ok = all(
        (KEY_DIR / n).is_file() for n in (KEY_CLIENT_PRIVATE, KEY_SERVER_PUBLIC)
    )
    if not pair_ok:
        try:
            lines = generate_keys(force=False)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"⚠ 密钥生成失败：{exc}")
        else:
            notes.append(f"已生成两对密钥：{KEY_DIR}")
            for line in lines:
                if line.startswith("  "):
                    notes.append(line)

    moved: list[str] = []
    skipped: list[str] = []
    protected = _hidden_from_list() | set(LOCKED_IN_LIST)
    for name in chosen:
        # 再拦一道：弹窗层已经不给勾了，但这里是执行层，
        # 万一有人绕过界面直接调，也不能把 keys/ 这种挪走
        if name in protected:
            skipped.append(f"{name}（受保护，未移动）")
            continue
        src = BASE_DIR / name
        dst = LOCAL_DIR / name
        try:
            if not src.exists():
                continue
            if dst.exists():
                skipped.append(name)       # 绝不覆盖已有内容
                continue
            shutil.move(str(src), str(dst))
            moved.append(name)
        except (OSError, shutil.Error) as exc:
            skipped.append(f"{name}（{exc}）")

    return moved, skipped, notes


def run_startup_check(parent=None) -> None:
    """启动时检查本地目录结构；缺了就引导初始化。

    整段包在 try 里 —— 这是启动路径上的钩子，任何意外都不该拦住程序打开。
    """
    try:
        missing = _missing_structure()
        if not missing:
            return                      # 齐备，什么都不做、不打扰

        from PyQt6.QtWidgets import QMessageBox

        ask = QMessageBox(parent)
        ask.setIcon(QMessageBox.Icon.Question)
        ask.setWindowTitle(f"{APP_TITLE} — 初始化")
        ask.setText("本地目录结构还不完整，是否初始化 FileSync 服务？")
        ask.setInformativeText(
            "当前缺少：\n    " + "\n    ".join(missing) + "\n\n"
            f"初始化会在 {BASE_DIR} 下建好这些内容，"
            "并让你挑选哪些文件移入 local_files/（也就是会被上传的目录）。"
        )
        ok_btn = ask.addButton("确定", QMessageBox.ButtonRole.AcceptRole)
        ask.addButton("取消", QMessageBox.ButtonRole.RejectRole)
        ask.exec()
        if ask.clickedButton() is not ok_btn:
            return

        names, ignored, used_builtin = _list_candidates()
        chosen = _pick_files_to_archive(parent, names, ignored, used_builtin)
        if chosen is None:
            return                      # 第二步取消 → 什么都不做

        moved, skipped, notes = _apply_init(chosen)

        done = QMessageBox(parent)
        done.setIcon(QMessageBox.Icon.Information)
        done.setWindowTitle(f"{APP_TITLE} — 初始化完成")
        done.setText(f"初始化完成，已把 {len(moved)} 个条目移入 local_files/。")
        detail: list[str] = []
        if notes:
            detail.extend(notes)
            detail.append("")
        if moved:
            detail.append("已移动：")
            detail.extend(f"  {n}" for n in moved)
        if skipped:
            detail.append("")
            detail.append("跳过（目标已存在同名，未覆盖）：")
            detail.extend(f"  {n}" for n in skipped)
        if detail:
            done.setDetailedText("\n".join(detail))
        done.exec()
    except Exception:  # noqa: BLE001
        traceback.print_exc()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=f"{APP_TITLE} —— 双端文件同步与对比",
    )
    parser.add_argument("--genkeys", action="store_true", help="生成两对 RSA 密钥")
    parser.add_argument("--force", action="store_true", help="配合 --genkeys 覆盖已有密钥")
    parser.add_argument("--ping", action="store_true", help="测试远端连通性与签名")
    parser.add_argument("--list", action="store_true", help="列出远端文件")
    parser.add_argument("--url", metavar="URL", help="临时指定远端接口地址（不写入配置）")
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

    from PyQt6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setStyleSheet(QSS)

    MainWindow = build_ui_classes()
    window = MainWindow(FileSyncClient())
    window.show()
    # 每次打开都检查一遍本地目录结构，缺了就引导初始化（见 run_startup_check）
    run_startup_check(window)
    return app.exec()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
