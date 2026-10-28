#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""refs.py <addr_hex,...> : 找出 disasm.txt 中所有 rip 相对引用（# 0xTARGET）的位置。"""
import re, sys, bisect
targets = {int(t, 16) for t in sys.argv[1].split(',')}
fn = sys.argv[2] if len(sys.argv) > 2 else 'disasm.txt'
pat = re.compile(r'^\s*([0-9a-f]+):.*#\s*(0x[0-9a-f]+)\s*$')
entries = set()
rows = []
for ln in open(fn, encoding='latin1'):
    m = re.match(r'^\s*([0-9a-f]+):\s*(\S+)(.*)$', ln)
    if m:
        a = int(m.group(1), 16); mn = m.group(2); ops = m.group(3)
        rows.append((a, mn, ops, ln.rstrip()))
        if mn in ('call', 'jmp'):
            t = ops.strip().split()[0] if ops.strip() else ''
            if re.fullmatch(r'0x[0-9a-f]+', t):
                entries.add(int(t, 16))
entries = sorted(entries)
def owner(a):
    i = bisect.bisect_right(entries, a) - 1
    return entries[i] if i >= 0 else None
for a, mn, ops, ln in rows:
    m = pat.match(ln)
    if m:
        t = int(m.group(2), 16)
        if t in targets:
            print(f'{ln}      ; in func {owner(a):#x}' if owner(a) else ln)
