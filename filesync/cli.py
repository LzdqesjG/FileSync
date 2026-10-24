# -*- coding: utf-8 -*-
"""命令行入口（无子命令时启动 tkinter 图形界面）。"""

from __future__ import annotations

import argparse
import sys
import traceback

from . import config, ops
from .client import FileSyncError, generate_keys, set_url_override


def make_log():
    def log(message: str, level: str = "info") -> None:
        color = {
            "ok": config.C_GREEN,
            "error": config.C_RED,
            "warn": config.C_YELLOW,
            "add": config.C_GREEN,
            "del": config.C_RED,
        }.get(level, "")
        print(config.col(str(message), color) if color else message)

    return log


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=f"{config.APP_TITLE} —— 仿 git 的文件同步工具（无参数运行 = 图形界面）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""常用流程：
  python main.py                      打开图形界面
  python main.py pull                 拉取远端（本地自动备份）
  python main.py add                  暂存全部改动
  python main.py commit -m 首页改版    生成提交（多词不用引号）
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
    sub.add_parser("gui", help="打开图形界面")

    p_add = sub.add_parser("add", help="暂存改动（默认全部）")
    p_add.add_argument("paths", nargs="*", help="文件/目录（默认全部）")

    sub.add_parser("status", help="查看工作区与暂存区状态")

    p_commit = sub.add_parser("commit", help="生成提交")
    p_commit.add_argument("-m", "--message", nargs="+", required=True,
                          help="提交信息（可以写多个词，不必加引号）")

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


def main(argv: list[str] | None = None) -> int:
    config.init_console()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.url:
        set_url_override(args.url)

    log = make_log()

    if args.genkeys:
        for line in generate_keys(force=args.force):
            print(line)
        return 0
    if args.ping:
        return ops.ping(log)
    if args.list:
        return ops.list_remote(log)

    if args.cmd in (None, "gui"):
        from .gui import run
        return run()

    try:
        if args.cmd == "pull":
            return ops.pull(log)
        if args.cmd == "add":
            return ops.add(args.paths, log)
        if args.cmd == "status":
            return ops.status(log)
        if args.cmd == "commit":
            return ops.commit(" ".join(args.message), log)
        if args.cmd == "push":
            return ops.push(log)
        if args.cmd == "check":
            if args.target and args.target[0].lower() == "list":
                limit = 20
                if len(args.target) > 1:
                    try:
                        limit = max(1, min(200, int(args.target[1])))
                    except ValueError:
                        log("条数必须是数字，例如：check list 10", "error")
                        return 1
                return ops.check_list(limit, log)
            return ops.check(args.target[0] if args.target else "HEAD", log)
        if args.cmd == "rm":
            return ops.remove(args.paths, log)
        if args.cmd == "diff":
            return ops.diff(args.path, log)
        if args.cmd == "restore":
            return ops.restore(args.path, args.from_id, log)
    except FileSyncError as exc:
        log(str(exc), "error")
        return 1
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        return 1

    parser.print_help()
    return 0


def entry() -> int:
    try:
        return main()
    except KeyboardInterrupt:
        return 130
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(entry())
