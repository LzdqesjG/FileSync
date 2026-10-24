#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FileSync 入口。

    python main.py              打开图形界面
    python main.py pull         拉取远端（本地自动备份）
    python main.py add          暂存
    python main.py commit -m 说明
    python main.py push
    python main.py check list 10
    python main.py check <id>

实现分别在 filesync/ 包内：
    config.py     路径与常量
    client.py     签名请求 / 密钥 / 远端接口
    diff.py       行级 diff
    workspace.py  忽略规则、扫描、本地仓库
    ops.py        pull/add/commit/push/check 等业务
    cli.py        命令行
    gui.py        tkinter 界面
"""

import sys

from filesync.cli import entry

if __name__ == "__main__":
    sys.exit(entry())
