#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""iat_refs.py: 列出所有引用 IAT 槽位的指令（不只 call），并标注导入函数名。
用法: python iat_refs.py <exe> <disasm> [filter_substr]"""
import re, sys, struct

EXE, DIS = sys.argv[1], sys.argv[2]
flt = sys.argv[3] if len(sys.argv) > 3 else ''
d = open(EXE, 'rb').read()
e = struct.unpack_from('<I', d, 0x3C)[0]; coff = e+4
nsec, sizeopt = struct.unpack_from('<H', d, coff+2)[0], struct.unpack_from('<H', d, coff+16)[0]
opt = coff+20
magic = struct.unpack_from('<H', d, opt)[0]
ib = struct.unpack_from('<Q', d, opt+24)[0] if magic == 0x20b else struct.unpack_from('<I', d, opt+28)[0]
dir_off = opt + (112 if magic == 0x20b else 96)
secs = []; p = opt+sizeopt
for i in range(nsec):
    vs, va, rs, rp = struct.unpack_from('<IIII', d, p+8); secs.append((va, vs, rp, rs)); p += 40
def r2o(rva):
    for va, vs, rp, rs in secs:
        if va <= rva < va+max(vs, rs) and rva-va < rs: return rp+(rva-va)
    return None
def cstr(rva):
    o = r2o(rva)
    if o is None: return ''
    return d[o:d.find(b'\0', o, o+200)].decode('latin1', 'replace')
imp_rva = struct.unpack_from('<I', d, dir_off+8)[0]
iat = {}
p = imp_rva
while True:
    o = r2o(p); desc = d[o:o+20]
    if len(desc) < 20 or desc == b'\0'*20: break
    oft, ts, fwd, name_rva, ft = struct.unpack('<IIIII', desc)
    dll = cstr(name_rva); thunk = oft or ft; i = 0
    while True:
        v = struct.unpack_from('<Q', d, r2o(thunk+i*8))[0] if magic == 0x20b else struct.unpack_from('<I', d, r2o(thunk+i*4))[0]
        if v == 0: break
        nm = '#ord%d' % (v & 0xFFFF) if v & (1 << (63 if magic == 0x20b else 31)) else cstr((v & 0x7FFFFFFF)+2)
        iat[ib+ft+i*(8 if magic == 0x20b else 4)] = f'{dll}!{nm}'
        i += 1
    p += 20
pat = re.compile(r'^\s*([0-9a-f]+):\s*(\S+)(.*)$')
hpat = re.compile(r'#\s*(0x[0-9a-f]+)')
for ln in open(DIS, encoding='latin1'):
    m = pat.match(ln)
    if not m: continue
    h = hpat.search(ln)
    if not h: continue
    t = int(h.group(1), 16)
    if t in iat and (flt == '' or flt in iat[t]):
        print(f'{m.group(1)}: {m.group(2):6s}{m.group(3).strip():45s} => {iat[t]}')
