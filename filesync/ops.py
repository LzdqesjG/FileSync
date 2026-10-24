# -*- coding: utf-8 -*-
"""业务操作：pull / add / status / commit / push / check / diff / rm / restore。

所有函数都接受 `log(message, level)` 回调，CLI 与 GUI 共用同一套逻辑。
"""

from __future__ import annotations

import base64
import shutil
import time
from pathlib import Path

from . import config, diff as diffmod, workspace as ws
from .client import FileSyncClient, FileSyncError, sha256_file

Log = object  # 仅作类型提示


def _noop_log(message: str, level: str = "info") -> None:  # pragma: no cover
    print(message)


# ============================================================ pull

def pull(log=_noop_log) -> int:
    repo = ws.load_repo()
    if repo.get("head") and repo.get("head") != repo.get("pushed"):
        log("本地有未推送的提交，pull 会覆盖本地历史。请先 push。", "error")
        return 1

    client = FileSyncClient()
    info = client.ping()
    log(f"远端接口：{client.url}")
    log(f"服务端 v{info.get('version')}（{info.get('api_build', '未知')}）")
    if "git" not in set(info.get("features") or []):
        log("服务端 api.php 不是最新版（不支持 git 协议），请先更新服务端。", "error")
        return 1

    local_dir = config.LOCAL_DIR
    local_dir.mkdir(parents=True, exist_ok=True)
    remote = _remote_snapshot(client)
    log(f"远端文件 {len(remote)} 个")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup_root = config.BACKUP_DIR / stamp
    downloaded = backed_up = 0

    for path, item in sorted(remote.items()):
        local_path = local_dir / path
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
        log(f"↓ {path}", "info")

    state = client.git_state()
    commits = client.git_log(limit=200).get("commits", [])
    head = state.get("head", "")
    manifest: dict = {}
    if head:
        try:
            manifest = dict(client.git_show(head).get("manifest") or {})
        except FileSyncError:
            manifest = {}

    ws.save_repo({
        "head": head,
        "pushed": head,
        "head_manifest": manifest,
        "commits": commits,
    })
    ws.save_index({"files": {}})

    msg = f"更新 {downloaded} 个文件"
    if backed_up:
        msg += f"，本地原文件已备份到 {backup_root}"
    log(msg, "ok")
    log(f"服务端 HEAD：{head or '（无提交）'}，历史 {len(commits)} 条")
    return 0


def _remote_snapshot(client: FileSyncClient) -> dict[str, dict]:
    rules = ws.load_filesyncignore()
    return {f["path"]: f for f in client.list_files()
            if f.get("path") and not ws.is_ignored(str(f["path"]), rules)}


# ============================================================ add / rm / status

def add(paths: list[str] | None = None, log=_noop_log) -> int:
    repo = ws.load_repo()
    head_manifest: dict = repo.get("head_manifest", {})
    work = ws.scan_local()
    targets = ws.select_paths(paths or [])

    if targets:
        chosen = [rel for rel in work
                  if any(rel == t or rel.startswith(t + "/") for t in targets)]
        deleted = [p for p in head_manifest
                   if p not in work and any(p == t or p.startswith(t + "/") for t in targets)]
    else:
        chosen = list(work)
        deleted = [p for p in head_manifest if p not in work]

    if not chosen and not deleted:
        log("没有需要暂存的文件（检查 local_files/）", "warn")
        return 0

    index = ws.load_index()
    staged = 0
    for rel in sorted(chosen):
        sha = work[rel]["sha256"]
        if head_manifest.get(rel) == sha and rel not in index["files"]:
            continue
        try:
            data = (config.LOCAL_DIR / rel).read_bytes()
        except OSError as exc:
            log(f"读取失败：{rel}（{exc}）", "warn")
            continue
        ws.store_object(data)
        index["files"][rel] = {
            "sha256": sha,
            "size": len(data),
            "status": "modified" if rel in head_manifest else "added",
        }
        staged += 1
        log(f"{'M' if rel in head_manifest else 'A'} {rel}")

    for rel in sorted(deleted):
        index["files"][rel] = {"sha256": "", "size": 0, "status": "deleted"}
        staged += 1
        log(f"D {rel}")

    ws.save_index(index)
    log(f"已暂存 {staged} 个改动", "ok")
    return 0


def remove(paths: list[str], log=_noop_log) -> int:
    index = ws.load_index()
    repo = ws.load_repo()
    head_manifest = repo.get("head_manifest", {})
    stamp = time.strftime("%Y%m%d-%H%M%S")
    removed = 0
    for raw in paths:
        picked = ws.select_paths([raw])
        rel = picked[0] if picked else ""
        if not rel:
            continue
        full = config.LOCAL_DIR / rel
        if not full.is_file():
            log(f"本地不存在：{rel}", "warn")
            continue
        target = config.TRASH_DIR / stamp / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(full), str(target))
        if rel in head_manifest:
            index["files"][rel] = {"sha256": "", "size": 0, "status": "deleted"}
        else:
            index["files"].pop(rel, None)
        removed += 1
        log(f"D {rel}（备份：{target}）")
    ws.save_index(index)
    log(f"已删除 {removed} 个文件并暂存", "ok")
    return 0


def status(log=_noop_log) -> int:
    st = ws.workspace_status()
    log(f"HEAD：{st['head'] or '（无提交）'}    已推送：{st['pushed'] or '（无）'}")

    if st["staged"]:
        log("待提交的更改：")
        for item in st["staged"]:
            mark = ws.status_mark(item["status"])
            log(f"  {mark} {item['path']}")
    else:
        log("待提交的更改：无")

    if st["unstaged"] or st["missing"]:
        log("未暂存的更改：")
        for rel in st["unstaged"]:
            log(f"  M {rel}")
        for rel in st["missing"]:
            log(f"  D {rel}（已从工作区消失，需 add）")

    if st["untracked"]:
        log("未跟踪的文件：")
        for rel in st["untracked"]:
            log(f"  ? {rel}")

    if not (st["staged"] or st["unstaged"] or st["missing"] or st["untracked"]):
        log("工作区干净，没有改动。", "ok")
    return 0


# ============================================================ commit

def commit(message: str, log=_noop_log) -> int:
    message = (message or "").strip()
    if not message:
        log("提交信息不能为空", "error")
        return 1

    index = ws.load_index()["files"]
    if not index:
        log("暂存区为空，请先 add", "error")
        return 1

    repo = ws.load_repo()
    parent = repo.get("head", "")
    manifest = dict(repo.get("head_manifest", {}))
    changes: list[dict] = []

    for rel, item in sorted(index.items()):
        st = item.get("status", "modified")
        old_sha = str(repo.get("head_manifest", {}).get(rel, ""))
        if st == "deleted":
            manifest.pop(rel, None)
            removed = diffmod.diff_stat(ws.read_object(old_sha), b"")[1]
            changes.append({"path": rel, "status": "deleted",
                            "added": 0, "removed": removed})
        else:
            sha = str(item.get("sha256", ""))
            manifest[rel] = sha
            added, removed = diffmod.diff_stat(ws.read_object(old_sha),
                                               ws.read_object(sha))
            changes.append({"path": rel, "status": st,
                            "added": added, "removed": removed})

    commit_id = ws.make_commit_id(parent, message, manifest)
    commit_obj = {
        "id": commit_id,
        "message": message,
        "time": int(time.time()),
        "author": "client",
        "parent": parent,
        "changes": changes,
        "manifest": manifest,
    }
    repo["commits"].append(commit_obj)
    repo["head"] = commit_id
    repo["head_manifest"] = manifest
    ws.save_repo(repo)
    ws.save_index({"files": {}})

    log(f"已提交 {commit_id}", "ok")
    log(format_commit(commit_obj))
    if repo.get("pushed") != commit_id:
        log("下一步：python main.py push")
    return 0


def format_commit(commit: dict) -> str:
    """把提交渲染成纯文本（CLI 与 GUI 共用）"""
    lines = [
        f"commit {commit.get('id', '')}",
        f"Author: {commit.get('author', 'client')}",
        f"Date:   {ws.short_time(commit.get('time', 0))}",
        "",
    ]
    for line in str(commit.get("message", "")).splitlines():
        lines.append(f"    {line}")
    lines.append("")

    changes = commit.get("changes") or []
    if not changes:
        lines.append("（无文件改动）")
        return "\n".join(lines)

    lines.append("变更文件：")
    for ch in changes:
        mark = ws.status_mark(str(ch.get("status", "modified")))
        lines.append(f"  {mark} {ch.get('path', '')}")
        lines.append(f"      +{int(ch.get('added', 0))}  -{int(ch.get('removed', 0))}")
    return "\n".join(lines)


# ============================================================ push

def _plan_blob_group(items: list[dict], start: int, budget: int):
    item = items[start]
    if len(item["data"]) > budget:
        groups = []
        offset = 0
        while offset < len(item["data"]):
            length = min(budget, len(item["data"]) - offset)
            groups.append([{"kind": "chunk", "item": item,
                            "offset": offset, "length": length}])
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


def upload_blobs(client: FileSyncClient, items: list[dict], log=_noop_log) -> int:
    budget = config.UPLOAD_CHUNK_BYTES
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
                    log(f"写入失败 {err.get('path')}（{err.get('error')}）", "warn")
        except FileSyncError as exc:
            if ((exc.status == 413 or exc.code == "body_too_large")
                    and budget > config.UPLOAD_MIN_CHUNK):
                budget = max(budget // 2, config.UPLOAD_MIN_CHUNK)
                log(f"服务端拒绝请求体，降档为 {ws.fmt_bytes(budget)} 后重试", "warn")
                continue
            raise
        index = nxt
    return uploaded


def push(log=_noop_log) -> int:
    repo = ws.load_repo()
    head = repo.get("head", "")
    pushed = repo.get("pushed", "")
    if not head:
        log("没有提交可推送（先 add + commit）", "warn")
        return 0
    if head == pushed:
        log("已经是最新，没有需要推送的提交。", "ok")
        return 0

    by_id = {c.get("id"): c for c in repo.get("commits", [])}
    pending: list[dict] = []
    cursor = head
    while cursor and cursor != pushed:
        item = by_id.get(cursor)
        if item is None:
            break
        pending.append(item)
        cursor = str(item.get("parent", ""))
    pending.reverse()

    if not pending:
        log("找不到待推送的提交链（本地历史可能损坏）", "error")
        return 1

    client = FileSyncClient()
    info = client.ping()
    if "git" not in set(info.get("features") or []):
        log("服务端 api.php 不是最新版（不支持 git 协议）", "error")
        return 1

    state = client.git_state()
    if state.get("head", "") != pushed:
        log("服务端已有新的提交，请先 pull 再 push", "error")
        log(f"服务端 HEAD：{state.get('head')}    本地已推送：{pushed or '（无）'}")
        return 1

    remote = _remote_snapshot(client)
    log(f"待推送提交 {len(pending)} 个")

    for item in pending:
        cid = str(item.get("id"))
        manifest = dict(item.get("manifest") or {})
        if not manifest:
            log(f"提交 {cid} 缺少文件清单，无法推送", "error")
            return 1

        blobs: list[dict] = []
        for path, sha in sorted(manifest.items()):
            if remote.get(path, {}).get("sha256") == sha:
                continue
            data = ws.read_object(str(sha))
            if data is None:
                full = config.LOCAL_DIR / path
                if not full.is_file():
                    log(f"缺少文件快照：{path}（请重新 add）", "error")
                    return 1
                data = full.read_bytes()
            blobs.append({"path": path, "data": data, "sha256": str(sha)})

        if blobs:
            upload_blobs(client, blobs, log)
            for b in blobs:
                remote[b["path"]] = {"path": b["path"], "sha256": b["sha256"],
                                     "size": len(b["data"])}
            log(f"上传 {len(blobs)} 个文件")

        result = client.git_commit(item)
        repo["pushed"] = str(result.get("head", cid))
        ws.save_repo(repo)
        log(f"✓ {cid}  {item.get('message', '')}", "ok")

    log(f"推送完成，服务端 HEAD：{repo.get('pushed')}", "ok")
    return 0


# ============================================================ check / history

def history(limit: int = 20) -> list[dict]:
    """提交历史：优先服务端，离线时回退本地"""
    try:
        return list(FileSyncClient().git_log(limit=limit).get("commits", []))
    except FileSyncError:
        return list(reversed(ws.load_repo().get("commits", [])))[:limit]


def commit_detail(commit_id: str) -> dict:
    repo = ws.load_repo()
    found = ws.find_local_commit(repo, commit_id)
    if found is not None:
        return found
    return FileSyncClient().git_show(commit_id)


def check(target: str, log=_noop_log) -> int:
    try:
        commit_obj = commit_detail(target)
    except FileSyncError as exc:
        log(str(exc), "error")
        return 1
    log(format_commit(commit_obj))
    return 0


def check_list(limit: int = 20, log=_noop_log) -> int:
    commits = history(limit)
    if not commits:
        log("还没有任何提交记录。")
        return 0
    log(f"最近 {min(limit, len(commits))} 条提交：")
    for c in commits[:limit]:
        msg = str(c.get("message", "")).splitlines()
        first = msg[0] if msg else ""
        files = len(c.get("changes") or [])
        log(f"{str(c.get('id', ''))[:12]}  {ws.short_time(c.get('time', 0))}  "
            f"{(c.get('author') or ''):<8}  {first}  ({files} 个文件)")
    return 0


# ============================================================ diff / restore

def diff(path: str | None = None, log=_noop_log) -> int:
    repo = ws.load_repo()
    head_manifest: dict = repo.get("head_manifest", {})
    index = ws.load_index()["files"]

    if path:
        rel = ws.select_paths([path])[0]
        pairs = [(rel, index.get(rel))]
    else:
        pairs = [(rel, item) for rel, item in sorted(index.items())]

    if not pairs:
        log("暂存区为空，没有可显示的差异（先 add）", "warn")
        return 0

    shown = 0
    for rel, item in pairs:
        old_sha = head_manifest.get(rel, "")
        if item is None:
            full = config.LOCAL_DIR / rel
            if not full.is_file():
                continue
            old_data = ws.read_object(old_sha)
            new_data = full.read_bytes()
        else:
            new_sha = str(item.get("sha256", ""))
            old_data = ws.read_object(old_sha)
            new_data = ws.read_object(new_sha) if new_sha else b""
            if item.get("status") == "deleted":
                new_data = b""

        old_text = diffmod.decode_text(old_data)
        new_text = diffmod.decode_text(new_data)
        if old_text is None or new_text is None:
            log(f"{rel}：二进制文件，无法显示行差异", "warn")
            continue

        a, b = old_text.splitlines(), new_text.splitlines()
        ops = diffmod.diff_lines(a, b)
        if all(op.tag == "equal" for op in ops):
            continue

        log(f"--- a/{rel}")
        log(f"+++ b/{rel}")
        for op in ops:
            if op.tag == "equal":
                continue
            for k in range(op.i1, op.i2):
                log(f"- {a[k]}", "del")
            for k in range(op.j1, op.j2):
                log(f"+ {b[k]}", "add")
        shown += 1

    if not shown:
        log("没有差异。")
    return 0


def restore(path: str, from_id: str = "HEAD", log=_noop_log) -> int:
    picked = ws.select_paths([path])
    if not picked:
        log("路径不合法", "error")
        return 1
    rel = picked[0]
    repo = ws.load_repo()
    commit_obj = ws.find_local_commit(repo, from_id)
    client = None

    if commit_obj is None:
        client = FileSyncClient()
        commit_obj = client.git_show(from_id)

    manifest = dict(commit_obj.get("manifest") or {})
    if commit_obj.get("id") == repo.get("head"):
        manifest = dict(repo.get("head_manifest") or manifest)

    sha = str(manifest.get(rel, ""))
    if not sha:
        log(f"提交 {from_id} 中不存在文件：{rel}", "error")
        return 1

    data = ws.read_object(sha)
    if data is None:
        if client is None:
            client = FileSyncClient()
        try:
            data = client.read_file(rel)
        except FileSyncError as exc:
            log(f"本地没有该文件快照，且从服务端读取失败：{exc}", "error")
            return 1

    target = config.LOCAL_DIR / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    log(f"已恢复 {rel}（来自 {commit_obj.get('id')}）", "ok")
    return 0


# ============================================================ 其他

def ping(log=_noop_log) -> int:
    client = FileSyncClient()
    try:
        info = client.ping()
    except FileSyncError as exc:
        log(str(exc), "error")
        return 1
    log("连通性与双向签名校验通过", "ok")
    log(f"远端接口：{client.url}")
    for key in ("version", "api_build", "features", "php_version", "ignored_count"):
        if key in info:
            log(f"{key}: {info[key]}")
    return 0


def list_remote(log=_noop_log) -> int:
    client = FileSyncClient()
    try:
        files = client.list_files()
    except FileSyncError as exc:
        log(str(exc), "error")
        return 1
    for item in files:
        log(f"{item['size']:>10}  {item['sha256'][:12]}  {item['path']}")
    log(f"共 {len(files)} 个文件（{client.url}）", "ok")
    return 0
