#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成报告用的数据块：节表/导入表/关键字符串(带虚拟地址)/overlay/imphash。"""
import sys, struct, hashlib, json, os, re

EXE = sys.argv[1]
OUT = sys.argv[2]
d = open(EXE, 'rb').read()
e = struct.unpack_from('<I', d, 0x3C)[0]
coff = e + 4
machine, nsec, ts, psym, nsym, sizeopt, chars = struct.unpack_from('<HHIIIHH', d, coff)
opt = coff + 20
magic = struct.unpack_from('<H', d, opt)[0]
ib = struct.unpack_from('<Q', d, opt+24)[0] if magic == 0x20b else struct.unpack_from('<I', d, opt+28)[0]
dir_off = opt + (112 if magic == 0x20b else 96)
secs = []
p = opt + sizeopt
for i in range(nsec):
    nm = d[p:p+8].rstrip(b'\0').decode('latin1')
    vs, va, rs, rp = struct.unpack_from('<IIII', d, p+8)
    secs.append((nm, va, vs, rp, rs)); p += 40

def r2o(rva):
    for nm, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs) and rva - va < rs: return rp + (rva - va)
    return None

def o2v(off):     # 文件偏移 → 虚拟地址
    for nm, va, vs, rp, rs in secs:
        if rp <= off < rp + rs:
            return va + (off - rp)
    return None

def cstr(rva):
    o = r2o(rva)
    if o is None: return ''
    return d[o:d.find(b'\0', o, o+300)].decode('latin1', 'replace')

# imports
imp_rva = struct.unpack_from('<I', d, dir_off+8)[0]
imports = []
p = imp_rva
while True:
    o = r2o(p); desc = d[o:o+20]
    if len(desc) < 20 or desc == b'\0'*20: break
    oft, _, _, name_rva, ft = struct.unpack('<IIIII', desc)
    dll = cstr(name_rva); thunk = oft or ft; funcs = []; i = 0
    while True:
        v = struct.unpack_from('<Q', d, r2o(thunk+i*8))[0] if magic == 0x20b else struct.unpack_from('<I', d, r2o(thunk+i*4))[0]
        if v == 0: break
        funcs.append('#ord%d' % (v & 0xFFFF) if v & (1 << (63 if magic == 0x20b else 31)) else cstr((v & 0x7FFFFFFF)+2))
        i += 1
    imports.append((dll, funcs)); p += 20

def demangle(n):
    # 极简 Itanium 反修饰：只处理本样本覆盖的子集
    m = re.match(r'^_ZN(?:K)?(\d+)(.*)$', n)
    return n

overlay_start = max(rp + rs for nm, va, vs, rp, rs in secs if rs)
imphash = hashlib.md5(','.join(f'{dll.lower()}.{f.lower()}' for dll, fs in imports for f in fs).encode()).hexdigest()

KEY = ['hosts', 'backup', '127.0.0.1', 'youtusoft', 'hostbuf', 'dkys', 'tcpspeed', 'wn1998',
       'LEGACY', 'MODERN', 'V45', 'V46', '2356', '13593', 'FF3Go', 'b(xxkHn', 'Scfg*Zkv',
       'finashell', 'finalshell', '机器码', '授权码', '激活', '版本号', '复制', 'Hosts',
       'SHA', 'MD5', 'Keccak', 'md5', 'key', 'token', 'Token', 'generateToken', 'copyToken',
       '.jar', 'config.json', 'user_name', 'huw', 'HKEY', 'Software\\', 'http://', 'https://',
       'QTextStream', 'QCryptographicHash', 'QRegularExpression', '[0-9]', 'GCC', 'QString']

asc = []
for mt in re.finditer(rb'[\x20-\x7e\t\r\n]{4,}', d):
    asc.append((mt.start(), mt.group().decode('latin1')))
wides = []
for mt in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', d):
    wides.append((mt.start(), mt.group().decode('utf-16-le')))
uw = []
for mt in re.finditer(rb'(?:[\x20-\x7e]\x00|[\x00-\xff][\x4e-\x9f]){4,}', d):
    try:
        s = mt.group().decode('utf-16-le')
    except Exception:
        continue
    if any('\u4e00' <= c <= '\u9fff' for c in s):
        uw.append((mt.start(), s))

lines = []
lines.append('## 节表\n')
lines.append('| # | 节名 | RVA | 虚拟大小 | 原始偏移 | 原始大小 | 熵 | 权限 | 含入口点 |')
lines.append('|---|------|-----|---------|---------|---------|----|------|---------|')
for i, (nm, va, vs, rp, rs) in enumerate(secs):
    raw = d[rp:rp+rs] if rs else b''
    import math, collections
    if raw:
        c = collections.Counter(raw); n = len(raw)
        ent = -sum((v/n)*math.log2(v/n) for v in c.values())
    else:
        ent = 0.0
    lines.append(f'| {i} | `{nm}` | 0x{va:X} | 0x{vs:X} | 0x{rp:X} | 0x{rs:X} | {ent:.3f} | — | {"是" if va <= struct.unpack_from("<I", d, opt+16)[0] < va+max(vs,rs) else ""} |')

lines.append('\n## 导入表\n')
lines.append('| DLL | 函数数 | 说明 |')
lines.append('|-----|-------|------|')
for dll, fs in imports:
    lines.append(f'| `{dll}` | {len(fs)} | — |')
lines.append(f'\n总导入条目: {sum(len(f) for _, f in imports)}')

lines.append('\n## 关键字符串（含虚拟地址）\n')
seen = set()
for off, s in asc + wides + uw:
    if any(k in s for k in KEY):
        v = o2v(off)
        if v is None or (off, s) in seen: continue
        seen.add((off, s))
        lines.append(f'| 0x{off:06X} | 0x{ib + v:012X} | `{s.strip()}` |')

lines.append(f'\n## 其它\n')
lines.append(f'- overlay 起点(最后一个节结束): 0x{overlay_start:X}, 文件大小 0x{len(d):X} → '
             f'{"无 overlay" if overlay_start >= len(d) else "存在 overlay " + hex(len(d)-overlay_start)}')
lines.append(f'- imphash: `{imphash}`')
lines.append(f'- ASCII 字符串(>=4): {len(asc)} 条; UTF-16LE(>=4): {len(wides)} 条; 中文宽字符: {len(uw)} 条')
lines.append(f'- 文件 SHA256: `{hashlib.sha256(d).hexdigest()}`')
lines.append(f'- 文件 MD5: `{hashlib.md5(d).hexdigest()}`')
open(OUT, 'w', encoding='utf-8').write('\n'.join(lines))
print('\n'.join(lines)[:1500])
print('...written', OUT)
