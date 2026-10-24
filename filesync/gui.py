# -*- coding: utf-8 -*-
"""tkinter 简易图形界面：状态列表 + 暂存/提交/推送 + 日志 + 历史。"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from . import config, ops, workspace as ws
from .client import FileSyncError, configured_server_url

FONT_UI = ("Microsoft YaHei UI", 10)
FONT_MONO = ("Consolas", 10)

TAG_COLORS = {
    "added": "#1a7f37",
    "modified": "#9a6700",
    "deleted": "#cf222e",
    "untracked": "#6e7781",
}


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.busy = False
        self.queue: queue.Queue = queue.Queue()

        root.title(f"{config.APP_TITLE} — {configured_server_url()}")
        root.geometry("1080x760")
        root.minsize(820, 560)

        self._build()
        self.root.after(120, self._poll_log)
        self.refresh_status()
        self.log(f"工作区：{config.LOCAL_DIR}")
        self.log(f"远端：{configured_server_url()}")
        self.log("提示：先「拉取」再改文件；改完「暂存选中/全部」→「提交」→「推送」。")

    # ------------------------------------------------------------ UI

    def _build(self) -> None:
        root = self.root
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        # 顶栏
        top = ttk.Frame(root, padding=(10, 8))
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="远端：", font=FONT_UI).grid(row=0, column=0, sticky="w")
        self.url_var = tk.StringVar(value=configured_server_url())
        ttk.Label(top, textvariable=self.url_var, font=FONT_MONO,
                  foreground="#555").grid(row=0, column=1, sticky="w", padx=(0, 8))
        self.btn_ping = ttk.Button(top, text="连接测试", command=self.on_ping, width=10)
        self.btn_ping.grid(row=0, column=2, padx=3)
        self.btn_pull = ttk.Button(top, text="拉取 pull", command=self.on_pull, width=10)
        self.btn_pull.grid(row=0, column=3, padx=3)
        self.btn_refresh = ttk.Button(top, text="刷新状态", command=self.refresh_status, width=10)
        self.btn_refresh.grid(row=0, column=4, padx=3)

        # 中部：左状态表 + 右操作区
        body = ttk.Panedwindow(root, orient="horizontal")
        body.grid(row=1, column=0, sticky="nsew", padx=10)

        left = ttk.Frame(body)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)
        ttk.Label(left, text="工作区状态", font=("Microsoft YaHei UI", 10, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 4))
        self.tree = ttk.Treeview(left, columns=("state", "path"), show="headings",
                                 selectmode="extended")
        self.tree.heading("state", text="状态")
        self.tree.heading("path", text="路径")
        self.tree.column("state", width=110, anchor="w", stretch=False)
        self.tree.column("path", width=420, anchor="w")
        self.tree.grid(row=1, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        scroll.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll.set)
        for key, color in TAG_COLORS.items():
            self.tree.tag_configure(key, foreground=color)
        body.add(left, weight=3)

        right = ttk.Frame(body, padding=(12, 0, 0, 0))
        right.columnconfigure(0, weight=1)
        ttk.Label(right, text="提交 / 推送", font=("Microsoft YaHei UI", 10, "bold")).grid(
            row=0, column=0, sticky="w")
        ttk.Label(right, text="提交信息", font=FONT_UI).grid(row=1, column=0, sticky="w",
                                                          pady=(10, 2))
        self.message = tk.Text(right, height=5, font=FONT_UI, wrap="word",
                               relief="solid", bd=1)
        self.message.grid(row=2, column=0, sticky="ew")

        row1 = ttk.Frame(right)
        row1.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        self.btn_add_sel = ttk.Button(row1, text="暂存选中", command=self.on_add_selected)
        self.btn_add_sel.pack(side="left")
        self.btn_add_all = ttk.Button(row1, text="暂存全部", command=self.on_add_all)
        self.btn_add_all.pack(side="left", padx=6)

        row2 = ttk.Frame(right)
        row2.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        self.btn_commit = ttk.Button(row2, text="提交 commit", command=self.on_commit)
        self.btn_commit.pack(side="left")
        self.btn_push = ttk.Button(row2, text="推送 push", command=self.on_push)
        self.btn_push.pack(side="left", padx=6)
        self.btn_history = ttk.Button(row2, text="提交历史", command=self.on_history)
        self.btn_history.pack(side="left")

        ttk.Separator(right).grid(row=5, column=0, sticky="ew", pady=12)
        self.summary = tk.StringVar(value="")
        ttk.Label(right, textvariable=self.summary, font=FONT_UI,
                  foreground="#444", wraplength=300, justify="left").grid(
            row=6, column=0, sticky="w")
        ttk.Label(right, text="说明：pull 覆盖前会自动备份；\n提交后记得 push。",
                  foreground="#888", font=("Microsoft YaHei UI", 9)).grid(
            row=7, column=0, sticky="w", pady=(12, 0))
        body.add(right, weight=1)

        # 底部日志
        log_frame = ttk.Frame(root, padding=(10, 0, 10, 10))
        log_frame.grid(row=2, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=12, font=FONT_MONO, wrap="none",
                                state="disabled", background="#1e1e1e",
                                foreground="#d4d4d4", insertbackground="#d4d4d4")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.tag_configure("ok", foreground="#4ec9b0")
        self.log_text.tag_configure("error", foreground="#f48771")
        self.log_text.tag_configure("warn", foreground="#dcdcaa")
        self.log_text.tag_configure("add", foreground="#4ec9b0")
        self.log_text.tag_configure("del", foreground="#f48771")
        self.log_text.tag_configure("info", foreground="#d4d4d4")

        self.buttons = [self.btn_ping, self.btn_pull, self.btn_refresh,
                        self.btn_add_sel, self.btn_add_all, self.btn_commit,
                        self.btn_push, self.btn_history]

    # ------------------------------------------------------------ 日志

    def log(self, message: str, level: str = "info") -> None:
        self.queue.put((level, str(message)))

    def _poll_log(self) -> None:
        try:
            while True:
                level, message = self.queue.get_nowait()
                self._append_log(message, level)
        except queue.Empty:
            pass
        self.root.after(120, self._poll_log)

    def _append_log(self, message: str, level: str) -> None:
        text = self.log_text
        text.configure(state="normal")
        text.insert("end", message + "\n", level)
        # 控制日志长度，避免长时间运行后卡顿
        if int(text.index("end-1c").split(".")[0]) > 3000:
            text.delete("1.0", "500.0")
        text.see("end")
        text.configure(state="disabled")

    # ------------------------------------------------------------ 后台任务

    def run_async(self, fn, on_done=None) -> None:
        if self.busy:
            self.log("上一个操作还在执行，请稍候…", "warn")
            return
        self.busy = True
        self._set_buttons(False)

        def worker():
            result = None
            try:
                result = fn(self.log)
            except FileSyncError as exc:
                self.log(str(exc), "error")
            except Exception as exc:  # noqa: BLE001
                self.log(f"{type(exc).__name__}: {exc}", "error")
            finally:
                self.root.after(0, lambda: self._finish(on_done, result))

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, on_done, result) -> None:
        self.busy = False
        self._set_buttons(True)
        if on_done is not None:
            try:
                on_done(result)
            except Exception as exc:  # noqa: BLE001
                self.log(f"回调失败：{exc}", "error")
        self.refresh_status()

    def _set_buttons(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for btn in self.buttons:
            btn.configure(state=state)

    # ------------------------------------------------------------ 状态

    def refresh_status(self) -> None:
        def worker():
            try:
                st = ws.workspace_status()
            except Exception as exc:  # noqa: BLE001
                self.log(f"读取状态失败：{exc}", "error")
                return
            self.root.after(0, lambda: self._render_status(st))

        threading.Thread(target=worker, daemon=True).start()

    def _render_status(self, st: dict) -> None:
        self.tree.delete(*self.tree.get_children())
        for item in st["staged"]:
            status = item["status"]
            self.tree.insert("", "end", iid=f"staged:{item['path']}",
                             values=(f"待提交·{ws.status_text(status)}", item["path"]),
                             tags=(status,))
        for rel in st["unstaged"]:
            self.tree.insert("", "end", iid=f"unstaged:{rel}",
                             values=("未暂存·修改", rel), tags=("modified",))
        for rel in st["missing"]:
            self.tree.insert("", "end", iid=f"missing:{rel}",
                             values=("未暂存·删除", rel), tags=("deleted",))
        for rel in st["untracked"]:
            self.tree.insert("", "end", iid=f"untracked:{rel}",
                             values=("未跟踪", rel), tags=("untracked",))

        head = (st["head"] or "无")[:12]
        pushed = (st["pushed"] or "无")[:12]
        self.summary.set(
            f"HEAD：{head}\n已推送：{pushed}\n"
            f"待提交 {len(st['staged'])} · 未暂存 "
            f"{len(st['unstaged']) + len(st['missing'])} · 未跟踪 {len(st['untracked'])}\n"
            f"工作区文件 {st['work_count']} 个"
        )

    # ------------------------------------------------------------ 操作

    def on_ping(self) -> None:
        self.run_async(lambda log: ops.ping(log))

    def on_pull(self) -> None:
        if not messagebox.askyesno(
            "拉取确认",
            "将从服务端拉取文件并覆盖本地，\n本地原文件会自动备份到 .filesync/backups/。\n\n继续？",
        ):
            return
        self.run_async(lambda log: ops.pull(log))

    def on_add_all(self) -> None:
        self.run_async(lambda log: ops.add([], log))

    def on_add_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            self.log("先在列表里选择文件（可多选）", "warn")
            return
        paths = [self._path_of(iid) for iid in selected]
        paths = [p for p in paths if p]
        if not paths:
            self.log("选中的条目不需要暂存（已暂存）", "warn")
            return
        self.run_async(lambda log: ops.add(paths, log))

    @staticmethod
    def _path_of(iid: str) -> str:
        return iid.split(":", 1)[1] if ":" in iid else ""

    def on_commit(self) -> None:
        message = self.message.get("1.0", "end").strip()
        if not message:
            messagebox.showwarning("缺少提交信息", "请填写提交信息。")
            return

        def done(result):
            if result == 0:
                self.message.delete("1.0", "end")

        self.run_async(lambda log: ops.commit(message, log), done)

    def on_push(self) -> None:
        self.run_async(lambda log: ops.push(log))

    def on_history(self) -> None:
        self.run_async(self._fetch_history, self._open_history)

    @staticmethod
    def _fetch_history(log):
        return ops.history(100)

    def _open_history(self, commits) -> None:
        if not commits:
            self.log("还没有提交记录。", "warn")
            return

        win = tk.Toplevel(self.root)
        win.title("提交历史")
        win.geometry("760x460")

        frame = ttk.Frame(win, padding=8)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        tree = ttk.Treeview(frame, columns=("id", "time", "author", "message", "files"),
                            show="headings")
        for col, title, width in (
            ("id", "ID", 110), ("time", "时间", 130), ("author", "作者", 80),
            ("message", "提交信息", 320), ("files", "文件", 60),
        ):
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor="w",
                        stretch=(col == "message"))
        tree.grid(row=0, column=0, sticky="nsew")
        bar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        bar.grid(row=0, column=1, sticky="ns")
        tree.configure(yscrollcommand=bar.set)

        for c in commits:
            msg = str(c.get("message", "")).splitlines()
            tree.insert("", "end", iid=str(c.get("id", "")), values=(
                str(c.get("id", ""))[:12],
                ws.short_time(c.get("time", 0)),
                c.get("author", ""),
                msg[0] if msg else "",
                len(c.get("changes") or []),
            ))

        def on_double(_event=None):
            sel = tree.selection()
            if not sel:
                return
            commit_id = sel[0]

            def worker():
                try:
                    detail = ops.commit_detail(commit_id)
                    text = ops.format_commit(detail)
                except Exception as exc:  # noqa: BLE001
                    text = f"读取失败：{exc}"
                self.root.after(0, lambda: self._show_detail(text))

            threading.Thread(target=worker, daemon=True).start()

        tree.bind("<Double-1>", on_double)
        ttk.Label(frame, text="双击一行查看该提交的文件改动（+X / -Y）",
                  foreground="#888").grid(row=1, column=0, columnspan=2, sticky="w",
                                          pady=(6, 0))

    def _show_detail(self, text: str) -> None:
        win = tk.Toplevel(self.root)
        win.title("提交详情")
        win.geometry("640x480")
        box = tk.Text(win, font=FONT_MONO, wrap="none", padx=8, pady=8)
        box.pack(fill="both", expand=True)
        box.insert("1.0", text)
        box.configure(state="disabled")


def run() -> int:
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.2)
    except tk.TclError:
        pass
    App(root)
    root.mainloop()
    return 0
