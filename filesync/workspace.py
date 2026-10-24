# -*- coding: utf-8 -*-
"""工作区：忽略规则、扫描、本地仓库（.filesync/）。"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import time
from pathlib import Path

from . import config
from .client import sha256_file


# ---------------------------------------------------------------- 忽略 / 扫描

def load_filesyncignore() -> list[tuple[str, bool]]:
    rules: list[tuple[str, bool]] = []
    path = config.FILESYNC_IGNORE_PATH
    if not path.is_file():
        return rules
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
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
        root = config.LOCAL_DIR
    result: dict[str, dict] = {}
    if not root.is_dir():
        return result
    rules = load_filesyncignore()
    for dirpath, dirnames, filenames in os.walk(root):
        kept: list[str] = []
        for d in dirnames:
            if d.startswith(".") or d in config.PROTECTED_REMOTE:
                continue
            rel_dir = (Path(dirpath) / d).relative_to(root).as_posix()
            if is_ignored(rel_dir, rules, is_dir=True):
                continue
            kept.append(d)
        dirnames[:] = sorted(kept)

        for name in sorted(filenames):
            if name.startswith(".") or name in config.PROTECTED_REMOTE:
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


# ---------------------------------------------------------------- 本地仓库

def ensure_state() -> None:
    for d in (config.STATE_DIR, config.OBJECTS_DIR):
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
    data = _read_json(config.INDEX_PATH, {"files": {}})
    if not isinstance(data.get("files"), dict):
        data["files"] = {}
    return data


def save_index(data: dict) -> None:
    ensure_state()
    _write_json(config.INDEX_PATH, data)


def load_repo() -> dict:
    data = _read_json(config.COMMITS_PATH, {
        "head": "", "pushed": "", "head_manifest": {}, "commits": [],
    })
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
    _write_json(config.COMMITS_PATH, repo)


def store_object(data: bytes) -> str:
    ensure_state()
    sha = hashlib.sha256(data).hexdigest()
    target = config.OBJECTS_DIR / sha
    if not target.is_file():
        tmp = target.with_name(sha + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)
    return sha


def read_object(sha: str) -> bytes | None:
    if not sha:
        return None
    path = config.OBJECTS_DIR / sha
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


def workspace_status() -> dict:
    """结构化状态，CLI 与 GUI 共用"""
    repo = load_repo()
    head_manifest: dict = repo.get("head_manifest", {})
    index = load_index()["files"]
    work = scan_local()

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
    return {
        "head": repo.get("head", ""),
        "pushed": repo.get("pushed", ""),
        "staged": [{"path": p, "status": str(i.get("status", "modified"))}
                   for p, i in sorted(index.items())],
        "unstaged": sorted(unstaged),
        "untracked": sorted(untracked),
        "missing": sorted(missing),
        "work_count": len(work),
    }


# ---------------------------------------------------------------- 小工具

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


def status_text(status: str) -> str:
    return {"added": "新增", "modified": "修改", "deleted": "删除"}.get(status, status)


def select_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        rel = str(p).replace("\\", "/").strip().lstrip("./")
        if rel:
            out.append(rel.rstrip("/"))
    return out
