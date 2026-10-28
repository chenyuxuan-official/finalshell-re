#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""callers.py <target_hex,...> : 在 disasm.txt 中找出所有直接 call <target> 的位置, 并打印所属函数
(所属函数 = 该调用点之前最近的、被 call 到的函数入口或 0x140001000 起的分段)。"""
import re, sys

targets = {int(t, 16) for t in sys.argv[1].split(',')}
fn = sys.argv[2] if len(sys.argv) > 2 else 'disasm.txt'
lines = open(fn, encoding='latin1').read().splitlines()
addr_re = re.compile(r'^\s*([0-9a-f]+):\s*(\S+)(.*)$')
# 收集所有 call/jmp 直接目标的函数入口集合
entries = set()
insns = []
for ln in lines:
    m = addr_re.match(ln)
    if not m: continue
    a = int(m.group(1), 16); mn = m.group(2); ops = m.group(3)
    insns.append((a, mn, ops))
    if mn in ('call', 'jmp'):
        t = ops.strip().split()[0] if ops.strip() else ''
        if re.fullmatch(r'0x[0-9a-f]+', t):
            entries.add(int(t, 16))
entries = sorted(entries)

def owner(a):
    import bisect
    i = bisect.bisect_right(entries, a) - 1
    return entries[i] if i >= 0 else None

for a, mn, ops in insns:
    if mn == 'call':
        t = ops.strip().split()[0] if ops.strip() else ''
        if re.fullmatch(r'0x[0-9a-f]+', t) and int(t, 16) in targets:
            print(f'call {t}  at {a:#x}   (in func {owner(a):#x})')
