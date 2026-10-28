#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""strings_xref.py: 把 disasm.txt 里所有 rip 相对 lea/mov 引用的 .rdata 目标解析成字符串，
输出 "指令地址 -> 目标 -> 字符串 -> 所属函数"。用于报告里的证据表。"""
import re, sys, bisect, struct

EXE = sys.argv[1]
DIS = sys.argv[2]
OUT = sys.argv[3]
d = open(EXE, 'rb').read()
e = struct.unpack_from('<I', d, 0x3C)[0]
coff = e + 4
nsec, sizeopt = struct.unpack_from('<H', d, coff + 2)[0], struct.unpack_from('<H', d, coff + 16)[0]
opt = coff + 20
magic = struct.unpack_from('<H', d, opt)[0]
image_base = struct.unpack_from('<Q', d, opt+24)[0] if magic == 0x20b else struct.unpack_from('<I', d, opt+28)[0]
secs = []
p = opt + sizeopt
for i in range(nsec):
    nm = d[p:p+8].rstrip(b'\0').decode('latin1')
    vs, va, rs, rp = struct.unpack_from('<IIII', d, p+8)
    secs.append((nm, va, vs, rp, rs))
    p += 40
def rva2off(rva):
    for nm, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            if rva - va < rs:
                return rp + (rva - va)
    return None
def cstr(vaddr):
    o = rva2off(vaddr - image_base)
    if o is None: return None
    s = d[o:o+200].split(b'\0')[0]
    try: t = s.decode('utf-8')
    except UnicodeDecodeError:
        try: t = s.decode('utf-16-le')
        except Exception: t = repr(s)
    if not t or sum(32 <= ord(c) < 127 for c in t) < max(1, len(t)*0.5):
        # 试 UTF-16
        w = d[o:o+400]
        try:
            t2 = w.decode('utf-16-le').split('\0')[0]
            if t2 and len(t2) > 1: t = t2
        except Exception: pass
    return t

rows = []
entries = set()
for ln in open(DIS, encoding='latin1'):
    m = re.match(r'^\s*([0-9a-f]+):\s*(\S+)(.*)$', ln)
    if not m: continue
    a = int(m.group(1), 16); mn = m.group(2); ops = m.group(3)
    rows.append((a, mn, ops, ln.rstrip()))
    if mn in ('call', 'jmp'):
        t = ops.strip().split()[0] if ops.strip() else ''
        if re.fullmatch(r'0x[0-9a-f]+', t): entries.add(int(t, 16))
entries = sorted(entries)
def owner(a):
    i = bisect.bisect_right(entries, a) - 1
    return entries[i] if i >= 0 else None

xref = {}
pat = re.compile(r'#\s*(0x[0-9a-f]+)\s*$')
for a, mn, ops, ln in rows:
    if '#' not in ln: continue
    t = int(pat.search(ln).group(1), 16)
    if image_base + 0xB000 <= t < image_base + 0xBD90:
        s = cstr(t)
        if s:
            xref.setdefault(owner(a), []).append((a, t, s))
with open(OUT, 'w', encoding='utf-8') as f:
    for fn_addr in sorted(k for k in xref if k):
        f.write(f'--- func {fn_addr:#x} ---\n')
        for a, t, s in xref[fn_addr]:
            f.write(f'  {a:#x} -> {t:#x} : {s}\n')
        f.write('\n')
print('funcs', len(xref))
