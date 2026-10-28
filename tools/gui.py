#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FinalShell 激活助手 · 图形界面版
=================================

对标第三方算号器 `finashellpp.exe` 的交互形态，但补上了它漏掉的那一环：
**云端复核域名 `yunce.hostbuf.com` / `fw.d1sm.net` 也一并屏蔽**。

功能
----
  1. 输入版本号 + 机器码 → 实时算出 16 位激活码，可一键复制
  2. 「一键激活」= 写 hosts 屏蔽 12 个校验域名（自动备份，可回退）
  3. 「回退 Hosts」= 从备份还原
  4. 全程不修改 FinalShell 安装目录里的任何文件

依赖：Python 3.8+ 标准库（tkinter）。打包成 exe 后无需 Python 环境。

免责声明：仅用于安全研究与自有软件学习。
"""

import os
import platform
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

try:
    from finalshell_keygen import BRANCHES, gen, pick_branch, parse_version
    from activate import BLOCK_DOMAINS
except Exception as e:  # pragma: no cover
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("缺少依赖",
                         f"找不到 finalshell_keygen.py / activate.py：\n{e}\n\n"
                         f"请把本程序与它们放在同一目录。")
    sys.exit(1)

APP_TITLE = "FinalShell 激活助手"
APP_VERSION = "1.0.0"

# ── 配色（青绿主题，与 finashellpp 观感接近） ─────────────────────────────
C_BG = "#f2f7f8"
C_CARD = "#ffffff"
C_TEXT = "#12343b"
C_SUB = "#6a858b"
C_ACCENT = "#23a6a8"
C_ACCENT_HOVER = "#1e8f91"
C_ACCENT_DOWN = "#167274"
C_BORDER = "#d7e5e7"
C_ERR = "#c0392b"
C_OK = "#1e7e34"


def is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def hosts_path() -> str:
    if platform.system() == "Windows":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


MARK_BEGIN = "# ==== finalshell-re activation block BEGIN ===="
MARK_END = "# ==== finalshell-re activation block END ===="


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.branch_var = tk.StringVar(value="")
        root.title(f"{APP_TITLE} v{APP_VERSION}")
        root.configure(bg=C_BG)
        root.minsize(720, 600)
        root.resizable(True, True)

        try:
            root.iconbitmap(default="")
        except Exception:
            pass

        self._build()

    # ── 界面 ────────────────────────────────────────────────────────────
    def _build(self):
        pad = tk.Frame(self.root, bg=C_BG)
        pad.pack(fill="both", expand=True, padx=28, pady=22)

        tk.Label(pad, text="FinalShell 激活助手", bg=C_BG, fg=C_TEXT,
                 font=("Microsoft YaHei UI", 22, "bold")).pack(anchor="w")
        tk.Label(pad,
                 text="输入版本号和机器码，激活码自动生成；点「一键激活」屏蔽云端复核",
                 bg=C_BG, fg=C_SUB,
                 font=("Microsoft YaHei UI", 10)).pack(anchor="w", pady=(2, 16))

        card = tk.Frame(pad, bg=C_CARD, highlightbackground=C_BORDER,
                        highlightthickness=1)
        card.pack(fill="both", expand=True)

        inner = tk.Frame(card, bg=C_CARD)
        inner.pack(fill="both", expand=True, padx=22, pady=18)

        # 版本号
        tk.Label(inner, text="版本号", bg=C_CARD, fg=C_TEXT,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
        self.ver_entry = self._entry(inner, "4.6.5")

        # 机器码
        tk.Label(inner, text="机器码", bg=C_CARD, fg=C_TEXT,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w", pady=(14, 0))
        self.mc_entry = self._entry(inner, "")
        tk.Label(inner,
                 text="FinalShell → 登录/激活 → 离线激活...，复制窗口里显示的那串",
                 bg=C_CARD, fg=C_SUB, font=("Microsoft YaHei UI", 8)).pack(anchor="w")

        # 激活码
        tk.Label(inner, text="激活码", bg=C_CARD, fg=C_TEXT,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w", pady=(14, 0))
        row = tk.Frame(inner, bg=C_CARD)
        row.pack(fill="x")
        self.code_var = tk.StringVar(value="")
        self.code_entry = tk.Entry(row, textvariable=self.code_var, state="readonly",
                                   font=("Consolas", 14), readonlybackground="#fbfdfd",
                                   fg=C_TEXT, relief="solid", bd=1)
        self.code_entry.pack(side="left", fill="x", expand=True, ipady=7)
        self.copy_btn = tk.Button(row, text="复制", command=self.copy_code,
                                  bg=C_CARD, fg=C_ACCENT, relief="flat",
                                  font=("Microsoft YaHei UI", 10, "bold"),
                                  activebackground=C_CARD, cursor="hand2", width=8)
        self.copy_btn.pack(side="left", padx=(8, 0))

        self.branch_lbl = tk.Label(inner, text="", bg=C_CARD, fg=C_SUB,
                                   font=("Microsoft YaHei UI", 8))
        self.branch_lbl.pack(anchor="w", pady=(4, 0))

        # 按钮
        btns = tk.Frame(pad, bg=C_BG)
        btns.pack(fill="x", pady=(16, 0))

        self.btn_activate = self._btn(btns, "一键激活（算号 + 屏蔽 hosts）",
                                      self.on_activate)
        self.btn_activate.pack(side="left")
        self._btn(btns, "回退 Hosts", self.on_revert).pack(side="left", padx=(10, 0))
        self._btn(btns, "仅算号", self.on_calc).pack(side="left", padx=(10, 0))

        # 状态栏
        self.status = tk.Label(pad, text="就绪", bg=C_BG, fg=C_SUB, anchor="w",
                               font=("Microsoft YaHei UI", 9), wraplength=680,
                               justify="left")
        self.status.pack(fill="x", pady=(12, 0))

        if not is_admin():
            self.set_status("提示：当前不是管理员，写 hosts 会失败。"
                            "请右键 → 以管理员身份运行。", C_ERR)

        # 实时计算
        self.ver_entry.bind("<KeyRelease>", lambda e: self.on_calc(silent=True))
        self.mc_entry.bind("<KeyRelease>", lambda e: self.on_calc(silent=True))

    def _entry(self, parent, default=""):
        e = tk.Entry(parent, font=("Consolas", 12), relief="solid", bd=1,
                     bg="#fbfdfd", fg=C_TEXT)
        e.pack(fill="x", ipady=7, pady=(4, 0))
        if default:
            e.insert(0, default)
        return e

    def _btn(self, parent, text, cmd):
        b = tk.Button(parent, text=text, command=cmd,
                      bg=C_ACCENT, fg="white", relief="flat",
                      font=("Microsoft YaHei UI", 10, "bold"),
                      activebackground=C_ACCENT_DOWN, activeforeground="white",
                      cursor="hand2", padx=16, pady=8)
        b.bind("<Enter>", lambda e: b.config(bg=C_ACCENT_HOVER))
        b.bind("<Leave>", lambda e: b.config(bg=C_ACCENT))
        return b

    def set_status(self, text, color=C_SUB):
        self.status.config(text=text, fg=color)

    # ── 业务 ────────────────────────────────────────────────────────────
    def calc(self):
        """返回 (激活码, 错误信息)"""
        mc = self.mc_entry.get().strip()
        ver = self.ver_entry.get().strip()
        if not mc:
            return None, "请先填机器码"
        v = parse_version(ver)
        if not v:
            return None, f"版本号格式不对：{ver}（应形如 4.6.5）"
        br = pick_branch(*v)
        return gen(mc, br), BRANCHES[br]

    def on_calc(self, silent=False):
        code, info = self.calc()
        if code is None:
            self.code_var.set("")
            self.branch_lbl.config(text="")
            if not silent:
                self.set_status(info, C_ERR)
            return None
        self.code_var.set(code)
        self.branch_lbl.config(
            text=f"分支 {info['name']} · {info['hash'].upper()}(code + {info['suffix']!r})"
                 f".hex()[{info['pos']}:{info['pos'] + 16}]")
        if not silent:
            self.set_status("激活码已生成，复制后粘到「离线激活」窗口", C_OK)
        return code

    def copy_code(self):
        code = self.code_var.get()
        if not code:
            self.set_status("还没有激活码可复制", C_ERR)
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(code)
        self.set_status(f"已复制：{code}", C_OK)

    def on_activate(self):
        code = self.on_calc(silent=True)
        if not code:
            self.on_calc()
            return
        if not is_admin():
            messagebox.showerror("需要管理员",
                                 "写 hosts 需要管理员权限。\n\n"
                                 "请关闭本程序，右键 → 以管理员身份运行。")
            return
        ok = messagebox.askyesno(
            "确认",
            f"激活码：{code}\n\n"
            f"接下来会修改系统 hosts，把 {len(BLOCK_DOMAINS)} 个 FinalShell 校验域名\n"
            f"指向 127.0.0.1（首次会备份为 hosts.finalshell-re.bak）。\n\n"
            f"继续吗？")
        if not ok:
            return
        self._run_async(self._do_fix_hosts)

    def on_revert(self):
        if not is_admin():
            messagebox.showerror("需要管理员", "恢复 hosts 需要管理员权限。")
            return
        if not messagebox.askyesno("确认", "从备份恢复 hosts？"):
            return
        self._run_async(self._do_revert)

    def _run_async(self, fn):
        self.btn_activate.config(state="disabled")
        threading.Thread(target=fn, daemon=True).start()

    def _done(self):
        self.btn_activate.config(state="normal")

    def _do_fix_hosts(self):
        try:
            hp = hosts_path()
            with open(hp, "r", encoding="utf-8", errors="replace") as f:
                cur = f.read()

            lines, out, skip = cur.splitlines(), [], False
            for ln in lines:
                if ln.strip() == MARK_BEGIN:
                    skip = True
                    continue
                if ln.strip() == MARK_END:
                    skip = False
                    continue
                if not skip:
                    out.append(ln)

            block = [MARK_BEGIN] + [f"127.0.0.1 {d}" for d in BLOCK_DOMAINS] + [MARK_END]
            new_text = "\n".join(out).rstrip("\n") + "\n\n" + "\n".join(block) + "\n"

            backup = hp + ".finalshell-re.bak"
            if not os.path.exists(backup):
                shutil.copy2(hp, backup)

            with open(hp, "w", encoding="utf-8", newline="\n") as f:
                f.write(new_text)

            if platform.system() == "Windows":
                subprocess.run(["ipconfig", "/flushdns"],
                               capture_output=True, timeout=15)

            self.root.after(0, lambda: self._after_hosts(True))
        except Exception as e:
            msg = str(e)
            self.root.after(0, lambda: self._after_hosts(False, msg))

    def _after_hosts(self, ok, err=""):
        self._done()
        if ok:
            self.set_status(
                f"完成：{len(BLOCK_DOMAINS)} 个域名已指向 127.0.0.1，DNS 已刷新。"
                f"现在重启 FinalShell 生效。", C_OK)
            messagebox.showinfo("完成",
                                "hosts 已更新。\n\n"
                                "现在重启 FinalShell，功能应当保持激活状态。")
        else:
            self.set_status(f"失败：{err}", C_ERR)
            messagebox.showerror("失败", err)

    def _do_revert(self):
        try:
            hp = hosts_path()
            backup = hp + ".finalshell-re.bak"
            if not os.path.exists(backup):
                raise RuntimeError(f"没找到备份：{backup}")
            shutil.copy2(backup, hp)
            if platform.system() == "Windows":
                subprocess.run(["ipconfig", "/flushdns"],
                               capture_output=True, timeout=15)
            self.root.after(0, self._after_revert)
        except Exception as e:
            msg = str(e)
            self.root.after(0, lambda: self._after_revert(msg))

    def _after_revert(self, err=None):
        self._done()
        if err:
            self.set_status(f"失败：{err}", C_ERR)
            messagebox.showerror("失败", err)
        else:
            self.set_status("hosts 已从备份恢复", C_OK)
            messagebox.showinfo("完成", "hosts 已恢复。")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
