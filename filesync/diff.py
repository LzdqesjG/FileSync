# -*- coding: utf-8 -*-
"""行级 diff：公共前后缀裁剪 + LCS，用于统计 +X / -Y。"""

from __future__ import annotations

from dataclasses import dataclass

from . import config


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
    if n * m > config.MAX_DIFF_CELLS:
        return [DiffOp("replace", off_a, off_a + n, off_b, off_b + m)]

    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        row, nxt, ai = dp[i], dp[i + 1], a[i]
        for j in range(m - 1, -1, -1):
            row[j] = (nxt[j + 1] + 1 if ai == b[j]
                      else (nxt[j] if nxt[j] >= row[j + 1] else row[j + 1]))

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
    """尽量解码成文本；二进制返回 None"""
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
    """返回 (新增行数, 删除行数)；二进制返回 (0, 0)"""
    a = decode_text(old)
    b = decode_text(new)
    if a is None or b is None:
        return 0, 0
    ops = diff_lines(a.splitlines(), b.splitlines())
    added = sum(op.j2 - op.j1 for op in ops if op.tag in ("insert", "replace"))
    removed = sum(op.i2 - op.i1 for op in ops if op.tag in ("delete", "replace"))
    return added, removed
