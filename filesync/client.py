# -*- coding: utf-8 -*-
"""网络层：RSA 双签请求、密钥生成、远端接口封装。"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

import requests

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import config

_URL_OVERRIDE: str | None = None


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


# ---------------------------------------------------------------- 配置

def load_client_config() -> dict:
    try:
        data = json.loads(config.CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_client_config(data: dict) -> None:
    config.CONFIG_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def set_url_override(url: str | None) -> None:
    global _URL_OVERRIDE
    _URL_OVERRIDE = (url or "").strip() or None


def configured_server_url() -> str:
    if _URL_OVERRIDE:
        return _URL_OVERRIDE
    url = load_client_config().get("server_url")
    if isinstance(url, str) and url.strip():
        return url.strip()
    return config.DEFAULT_SERVER_URL


# ---------------------------------------------------------------- 密钥

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
    key_dir = config.KEY_DIR
    key_dir.mkdir(parents=True, exist_ok=True)
    targets = [
        config.KEY_CLIENT_PRIVATE, config.KEY_CLIENT_PUBLIC,
        config.KEY_SERVER_PRIVATE, config.KEY_SERVER_PUBLIC,
    ]
    existing = [t for t in targets if (key_dir / t).exists()]
    if existing and not force:
        lines.append(f"{key_dir} 下已存在以下密钥，未做任何改动：")
        lines.extend(f"  - {name}" for name in existing)
        lines.append("如需重新生成，请使用 --force（旧密钥立即失效）。")
        return lines

    client_priv, client_pub = keypair_pems()
    server_priv, server_pub = keypair_pems()

    _write_private(key_dir / config.KEY_CLIENT_PRIVATE, client_priv)
    _write_private(key_dir / config.KEY_SERVER_PRIVATE, server_priv)
    (key_dir / config.KEY_CLIENT_PUBLIC).write_bytes(client_pub)
    (key_dir / config.KEY_SERVER_PUBLIC).write_bytes(server_pub)

    lines.append(f"密钥已生成到：{key_dir}")
    lines.append("")
    lines.append("【本地保留，切勿外传】 client_private.pem / server_public.pem")
    lines.append("【上传到远端 lg_keys/】 server_private.pem / client_public.pem")
    return lines


# ---------------------------------------------------------------- 客户端

class FileSyncClient:
    def __init__(self, url: str | None = None,
                 client_key: Path | None = None,
                 server_key: Path | None = None,
                 timeout: int = config.REQUEST_TIMEOUT) -> None:
        self.url = (url or configured_server_url()).strip()
        self.timeout = timeout
        self._client_key_path = client_key or config.CLIENT_PRIVATE_KEY
        self._server_key_path = server_key or config.SERVER_PUBLIC_KEY
        self._priv = None
        self._server_pub = None
        self._session = requests.Session()

    def _private(self):
        if self._priv is None:
            if not self._client_key_path.exists():
                raise FileSyncError(
                    f"找不到客户端私钥：{self._client_key_path}\n"
                    f"请先执行：python main.py --genkeys"
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
                    f"请先执行：python main.py --genkeys"
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
        canonical = (
            f"{config.PROTOCOL_TAG}\n{action}\n{ts}\n{nonce}\n{sha256_hex(body)}"
        ).encode("utf-8")

        signature = self._private().sign(canonical, padding.PKCS1v15(), hashes.SHA256())
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "X-LG-Timestamp": ts,
            "X-LG-Nonce": nonce,
            "X-LG-Signature": base64.b64encode(signature).decode("ascii"),
        }

        try:
            resp = self._session.post(self.url, data=body, headers=headers,
                                     timeout=self.timeout)
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
            raise FileSyncError(self._describe_error(payload, resp.status_code),
                                code, resp.status_code)
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

        canonical = f"{config.RESPONSE_TAG}\n{nonce}\n{sha256_hex(resp.content)}".encode("utf-8")
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
