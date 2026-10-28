#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 objdump 反汇编里的 call QWORD PTR [rip+...] # 0xADDR 映射回导入函数名，
并统计每个导入函数的所有调用点。只读。"""
import re, sys, json, struct, os

EXE = sys.argv[1]
DIS = sys.argv[2]
OUT = sys.argv[3]

# ---- 重建 IAT: RVA -> (dll, name)
d = open(EXE, 'rb').read()
e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
coff = e_lfanew + 4
machine, nsec, ts, psym, nsym, sizeopt, chars = struct.unpack_from('<HHIIIHH', d, coff)
opt = coff + 20
magic = struct.unpack_from('<H', d, opt)[0]
pe32plus = magic == 0x20b
if pe32plus:
    image_base = struct.unpack_from('<Q', d, opt+24)[0]
    ndirs = struct.unpack_from('<I', d, opt+108)[0]
    dir_off = opt + 112
else:
    image_base = struct.unpack_from('<I', d, opt+28)[0]
    ndirs = struct.unpack_from('<I', d, opt+92)[0]
    dir_off = opt + 96
secs = []
p = opt + sizeopt
for i in range(nsec):
    name = d[p:p+8].rstrip(b'\0').decode('latin1')
    vs, va, rs, rp = struct.unpack_from('<IIII', d, p+8)
    secs.append((name, va, vs, rp, rs))
    p += 40

def rva2off(rva):
    for name, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            off = rva - va
            if off < rs:
                return rp + off
    return rva if rva < 0x400 else None

def cstr(rva):
    o = rva2off(rva)
    if o is None: return ''
    e = d.find(b'\0', o, o+256)
    return d[o:e].decode('latin1', 'replace')

imp_rva, imp_sz = struct.unpack_from('<II', d, dir_off + 8)     # dir[1]
iat = {}
p = imp_rva
while True:
    desc = d[rva2off(p):rva2off(p)+20]
    if len(desc) < 20 or desc == b'\0'*20: break
    oft, ts_, fwd, name_rva, ft = struct.unpack('<IIIII', desc)
    dll = cstr(name_rva)
    thunk = oft or ft
    i = 0
    while True:
        if pe32plus:
            v = struct.unpack_from('<Q', d, rva2off(thunk + i*8))[0]
        else:
            v = struct.unpack_from('<I', d, rva2off(thunk + i*4))[0]
        if v == 0: break
        if v & (1 << (63 if pe32plus else 31)):
            nm = '#ord%d' % (v & 0xFFFF)
        else:
            nm = cstr((v & 0x7FFFFFFF) + 2)
        slot = image_base + ft + i*(8 if pe32plus else 4)
        iat[slot] = (dll, nm)
        i += 1
        if i > 4000: break
    p += 20

# ---- 解析反汇编
call_re = re.compile(r'^\s*([0-9a-f]+):\s+call\s+QWORD PTR \[rip\+0x([0-9a-f]+)\]\s*#\s*(0x[0-9a-f]+)')
jmp_re = re.compile(r'^\s*([0-9a-f]+):\s+(?:call|jmp)\s+([0-9a-f]+)')
xref = {}
lines = open(DIS, encoding='latin1').read().splitlines()
for ln in lines:
    m = call_re.match(ln)
    if m:
        site = int(m.group(3), 16)
        if site in iat:
            dll, nm = iat[site]
            xref.setdefault((dll, nm), []).append(int(m.group(1), 16))

with open(OUT, 'w', encoding='utf-8') as f:
    for (dll, nm), sites in sorted(xref.items(), key=lambda kv: -len(kv[1])):
        f.write(f'{dll}!{nm}  ({len(sites)} calls)\n')
        for s in sites:
            f.write(f'    {s:#x}\n')
        f.write('\n')

json.dump({f'{k[0]}!{k[1]}': v for k, v in xref.items()},
          open(OUT + '.json', 'w', encoding='utf-8'), indent=1)
print('iat entries', len(iat), 'xref keys', len(xref))
for (dll, nm), s in sorted(xref.items(), key=lambda kv: -len(kv[1]))[:40]:
    print(f'{len(s):3d}  {dll}!{nm}')
