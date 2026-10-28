#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FinalShell 一键激活助手
========================

把「算激活码」和「屏蔽云端校验」两件事合成一条命令。

核心原理见 docs/activation-algorithm.md 与 docs/persistence-findings.md：

  1. 激活码 = Keccak384(机器码 + 盐).hex()[12:28]（4.6.x 用 MODERN-C 盐）
  2. 光有激活码不够 —— 客户端会向 yunce.hostbuf.com 心跳复核，
     必须把这个域名也指到 127.0.0.1，否则激活状态会被服务端覆盖

用法
----
    # 只算号（不碰系统）
    python activate.py "admin@0123456789abcdef" -v 4.6.5

    # 算号 + 自动改 hosts（需要管理员 / root）
    python activate.py "admin@0123456789abcdef" -v 4.6.5 --fix-hosts

    # 只改 hosts，不算号
    python activate.py --fix-hosts

    # 恢复 hosts 到改动前的备份
    python activate.py --revert-hosts

    # 先看看会写什么，不动手
    python activate.py "admin@0123456789abcdef" --fix-hosts --dry-run

免责声明：本工具仅用于安全研究与自有软件学习，使用者自行承担一切后果。
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import time

# ---- 复用 tools/ 下的算号实现 ------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from finalshell_keygen import BRANCHES, gen, keccak_384, pick_branch, parse_version
except ImportError:
    sys.stderr.write("[!] 找不到 finalshell_keygen.py，请与本脚本放在同一目录\n")
    raise

# ---- 需要屏蔽的域名 ----------------------------------------------------------
# 前 10 个来自第三方算号器 .rdata 里的常量；
# 后 2 个是动态取证补上的（见 docs/persistence-findings.md）——
# 缺了它们，激活会在客户端联网后被服务端结论覆盖。
BLOCK_DOMAINS = [
    "www.youtusoft.com",
    "youtusoft.com",
    "hostbuf.com",
    "www.hostbuf.com",
    "backup.www.hostbuf.com",
    "dkys.org",
    "tcpspeed.com",
    "www.wn1998.com",
    "wn1998.com",
    "pwlt.wn1998.com",
    # ↓ 关键补充
    "yunce.hostbuf.com",
    "fw.d1sm.net",
]

MARK_BEGIN = "# ==== finalshell-re activation block BEGIN ===="
MARK_END = "# ==== finalshell-re activation block END ===="


def hosts_path() -> str:
    """定位系统 hosts 文件"""
    if platform.system() == "Windows":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


def is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def show_code(machine_code: str, version: str, show_all: bool) -> None:
    print("=" * 62)
    print("  激活码计算")
    print("=" * 62)
    print(f"  机器码 : {machine_code}")

    if show_all:
        print(f"  版本   : (列出全部 4 个分支，逐个粘贴试)\n")
        for br in sorted(BRANCHES):
            spec = BRANCHES[br]
            print(f"    分支 {br}  {spec['name']:<9} {spec['hash']:<6} "
                  f"→ {gen(machine_code, br)}")
        print()
        return

    ver = parse_version(version)
    if not ver:
        sys.exit(f"[!] 版本号格式不对: {version}（应形如 4.6.5）")

    br = pick_branch(*ver)
    spec = BRANCHES[br]
    code = gen(machine_code, br)
    print(f"  版本   : {version}  → 分支 {br} ({spec['name']})")
    print(f"  算法   : {spec['hash'].upper()}(code + {spec['suffix']!r})"
          f".hex()[{spec['pos']}:{spec['pos'] + 16}]")
    print(f"  激活码 : {code}")
    print()
    print("  → 打开 FinalShell 登录窗口，点「离线激活...」，把上面的激活码粘进去")
    print()


def read_hosts() -> str:
    with open(hosts_path(), "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def write_hosts(text: str) -> None:
    with open(hosts_path(), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def fix_hosts(dry_run: bool = False) -> int:
    hp = hosts_path()
    print("=" * 62)
    print("  屏蔽云端校验域名")
    print("=" * 62)
    print(f"  hosts  : {hp}")

    if not os.path.exists(hp):
        print("[!] 找不到 hosts 文件")
        return 1
    if not is_admin() and not dry_run:
        print("[!] 需要管理员权限（Windows 用管理员 PowerShell，Linux 用 sudo）")
        return 1

    cur = read_hosts()

    if MARK_BEGIN in cur:
        print("  [i] 检测到已有本工具写入的区块，先移除旧区块再重写")

    # 清掉上一次本工具写的区块
    lines = cur.splitlines()
    out, skip = [], False
    for ln in lines:
        if ln.strip() == MARK_BEGIN:
            skip = True
            continue
        if ln.strip() == MARK_END:
            skip = False
            continue
        if not skip:
            out.append(ln)

    block = [MARK_BEGIN]
    for d in BLOCK_DOMAINS:
        block.append(f"127.0.0.1 {d}")
    block.append(MARK_END)

    new_text = "\n".join(out).rstrip("\n") + "\n\n" + "\n".join(block) + "\n"

    print(f"  将写入 {len(BLOCK_DOMAINS)} 条记录：")
    for d in BLOCK_DOMAINS:
        tag = "  ← 关键补充" if d in ("yunce.hostbuf.com", "fw.d1sm.net") else ""
        print(f"      127.0.0.1 {d}{tag}")
    print()

    if dry_run:
        print("  [dry-run] 未写入。预览尾部内容：\n")
        for ln in new_text.splitlines()[-len(block) - 2:]:
            print("      " + ln)
        return 0

    backup = hp + ".finalshell-re.bak"
    if not os.path.exists(backup):
        shutil.copy2(hp, backup)
        print(f"  备份   : {backup}")
    else:
        print(f"  备份   : 已存在，不覆盖（{backup}）")

    write_hosts(new_text)
    print("  [√] hosts 已更新")

    # 刷新 DNS
    try:
        if platform.system() == "Windows":
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=15)
        else:
            subprocess.run(["sh", "-c", "command -v resolvectl >/dev/null && "
                                        "resolvectl flush-caches || "
                                        "command -v systemd-resolve >/dev/null && "
                                        "systemd-resolve --flush-caches"],
                           capture_output=True, timeout=15)
        print("  [√] DNS 缓存已刷新")
    except Exception as e:
        print(f"  [i] DNS 刷新跳过: {e}")

    return 0


def revert_hosts(dry_run: bool = False) -> int:
    hp = hosts_path()
    backup = hp + ".finalshell-re.bak"
    print("=" * 62)
    print("  恢复 hosts")
    print("=" * 62)

    if not os.path.exists(backup):
        print(f"[!] 没找到备份 {backup}，无法恢复")
        return 1

    if dry_run:
        print(f"  [dry-run] 将用 {backup} 覆盖 {hp}")
        return 0

    if not is_admin():
        print("[!] 需要管理员权限")
        return 1

    shutil.copy2(backup, hp)
    print(f"  [√] 已从备份恢复: {backup} → {hp}")
    try:
        if platform.system() == "Windows":
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=15)
    except Exception:
        pass
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="FinalShell 一键激活助手（算号 + 屏蔽云端校验）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python activate.py \"admin@0123456789abcdef\" -v 4.6.5 --fix-hosts\n"
               "  python activate.py --revert-hosts")
    ap.add_argument("machine_code", nargs="?",
                    help="机器码，形如 admin@0123456789abcdef 或 0123456789abcdef")
    ap.add_argument("-v", "--version", default="4.6.5",
                    help="FinalShell 版本号，默认 4.6.5")
    ap.add_argument("--all", action="store_true", help="列出全部 4 个分支的激活码")
    ap.add_argument("--fix-hosts", action="store_true", help="写入 hosts 屏蔽云端校验域名")
    ap.add_argument("--revert-hosts", action="store_true", help="从备份恢复 hosts")
    ap.add_argument("--dry-run", action="store_true", help="只预览，不实际修改系统")
    args = ap.parse_args(argv)

    if args.revert_hosts:
        return revert_hosts(args.dry_run)

    if not args.machine_code and not args.fix_hosts:
        ap.print_help()
        return 2

    if args.machine_code:
        code = args.machine_code.strip()
        if not code:
            sys.exit("[!] 机器码不能为空")
        show_code(code, args.version, args.all)

    if args.fix_hosts:
        return fix_hosts(args.dry_run)

    return 0


if __name__ == "__main__":
    sys.exit(main())
