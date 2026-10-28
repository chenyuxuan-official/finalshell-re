#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
只读 PE 静态分析器（纯标准库实现，不依赖 pefile）
用法: python pe_analyze.py <pe_file> <out_dir>
输出: sections.csv / imports.txt / exports.txt / resources.txt / strings_ascii.txt /
      strings_utf16.txt / keywords.txt / rawjson.json
绝不执行目标、绝不写入目标目录。
"""
import sys, os, json, struct, math, hashlib, collections, datetime

# ---------------------------------------------------------------- 基础读取
class PE:
    def __init__(self, data):
        self.d = data
        self.size = len(data)
        self.parse_dos()
        self.parse_nt()
        self.parse_sections()
        self.parse_dirs()

    def u16(self, off): return struct.unpack_from('<H', self.d, off)[0]
    def u32(self, off): return struct.unpack_from('<I', self.d, off)[0]
    def u64(self, off): return struct.unpack_from('<Q', self.d, off)[0]

    def parse_dos(self):
        if self.d[:2] != b'MZ':
            raise SystemExit('not MZ')
        self.e_lfanew = self.u32(0x3C)
        # DOS stub 内容
        stub_start = 0x40
        stub_end = min(self.e_lfanew, self.size)
        self.dos_stub = self.d[stub_start:stub_end]
        self.dos_stub_ascii = ''.join(chr(c) if 32 <= c < 127 else '.' for c in self.dos_stub)

    def parse_nt(self):
        assert self.d[self.e_lfanew:self.e_lfanew+4] == b'PE\0\0', 'no PE sig'
        p = self.e_lfanew + 4
        (self.machine, self.nsec, self.timestamp, self.p_symtab, self.n_sym,
         self.size_opt, self.characteristics) = struct.unpack_from('<HHIIIHH', self.d, p)
        self.opt_off = p + 20
        o = self.opt_off
        self.opt_magic = self.u16(o)
        self.pe32plus = (self.opt_magic == 0x20b)
        self.major_linker = self.d[o+2]; self.minor_linker = self.d[o+3]
        self.size_code = self.u32(o+4)
        self.size_init = self.u32(o+8)
        self.size_uninit = self.u32(o+12)
        self.entry_rva = self.u32(o+16)
        self.base_of_code = self.u32(o+20)
        if self.pe32plus:
            self.image_base = self.u64(o+24)
            self.section_align = self.u32(o+32)
            self.file_align = self.u32(o+36)
            self.os_ver = (self.u16(o+40), self.u16(o+42))
            self.img_ver = (self.u16(o+44), self.u16(o+46))
            self.subsys_ver = (self.u16(o+48), self.u16(o+50))
            self.size_image = self.u32(o+56)
            self.size_headers = self.u32(o+60)
            self.checksum = self.u32(o+64)
            self.subsystem = self.u16(o+68)
            self.dll_chars = self.u16(o+70)
            self.stack_reserve = self.u64(o+72)
            self.stack_commit = self.u64(o+80)
            self.heap_reserve = self.u64(o+88)
            self.heap_commit = self.u64(o+96)
            self.loader_flags = self.u32(o+104)
            self.ndirs = self.u32(o+108)
            self.dir_off = o + 112
        else:
            self.image_base = self.u32(o+28)
            self.section_align = self.u32(o+32)
            self.file_align = self.u32(o+36)
            self.os_ver = (self.u16(o+40), self.u16(o+42))
            self.img_ver = (self.u16(o+44), self.u16(o+46))
            self.subsys_ver = (self.u16(o+48), self.u16(o+50))
            self.size_image = self.u32(o+56)
            self.size_headers = self.u32(o+60)
            self.checksum = self.u32(o+64)
            self.subsystem = self.u16(o+68)
            self.dll_chars = self.u16(o+70)
            self.stack_reserve = self.u32(o+72)
            self.stack_commit = self.u32(o+76)
            self.heap_reserve = self.u32(o+80)
            self.heap_commit = self.u32(o+84)
            self.loader_flags = self.u32(o+88)
            self.ndirs = self.u32(o+92)
            self.dir_off = o + 96
        DIRNAMES = ['Export', 'Import', 'Resource', 'Exception', 'Certificate', 'BaseReloc',
                    'Debug', 'Architecture', 'GlobalPtr', 'TLS', 'LoadConfig', 'BoundImport',
                    'IAT', 'DelayImport', 'CLR', 'Reserved']
        self.dirs = {}
        for i in range(min(self.ndirs, 16)):
            rva = self.u32(self.dir_off + i*8)
            sz = self.u32(self.dir_off + i*8 + 4)
            self.dirs[DIRNAMES[i]] = (rva, sz)

    def parse_sections(self):
        self.sections = []
        p = self.opt_off + self.size_opt
        for i in range(self.nsec):
            name = self.d[p:p+8].rstrip(b'\0')
            vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', self.d, p+8)
            relptr, nrel = struct.unpack_from('<II', self.d, p+24)
            chars = self.u32(p+36)
            raw = self.d[rawptr:rawptr+rawsize] if rawsize else b''
            s = dict(index=i, name=name.decode('latin1'), raw_name=name.hex(),
                     vsize=vsize, vaddr=vaddr, rawsize=rawsize, rawptr=rawptr,
                     relptr=relptr, nrel=nrel, chars=chars,
                     entropy=round(entropy(raw), 4) if raw else 0.0,
                     md5=hashlib.md5(raw).hexdigest() if raw else '',
                     char_flags=char_flags(chars),
                     contains_entry=False)
            self.sections.append(s)
            p += 40
        for s in self.sections:
            if s['vaddr'] <= self.entry_rva < s['vaddr'] + max(s['vsize'], s['rawsize']):
                s['contains_entry'] = True

    # RVA -> 文件偏移
    def rva2off(self, rva):
        for s in self.sections:
            span = max(s['vsize'], s['rawsize'])
            if s['vaddr'] <= rva < s['vaddr'] + span:
                delta = rva - s['vaddr']
                if delta < s['rawsize']:
                    return s['rawptr'] + delta
                return None
        if rva < self.size_headers:
            return rva
        return None

    def read_rva(self, rva, n):
        o = self.rva2off(rva)
        if o is None or o + n > self.size:
            return None
        return self.d[o:o+n]

    def cstr(self, rva, maxlen=512):
        o = self.rva2off(rva)
        if o is None: return None
        e = self.d.find(b'\0', o, min(o+maxlen, self.size))
        if e < 0: e = min(o+maxlen, self.size)
        return self.d[o:e].decode('latin1', 'replace')

    def parse_dirs(self):
        self.imports = self.parse_imports()
        self.delay_imports = self.parse_delay_imports()
        self.exports = self.parse_exports()
        self.resources = self.parse_resources()
        self.tls = self.parse_tls()

    # ------------------------------------------------------------ 导入表
    def parse_imports(self):
        rva, sz = self.dirs.get('Import', (0, 0))
        out = []
        if not rva: return out
        p = rva
        for _ in range(512):
            desc = self.read_rva(p, 20)
            if not desc or desc == b'\0'*20: break
            oft, ts, fwd, name_rva, ft = struct.unpack('<IIIII', desc)
            dll = self.cstr(name_rva) or ''
            thunk_rva = oft or ft
            funcs = []
            i = 0
            while True:
                if self.pe32plus:
                    v = self.read_rva(thunk_rva + i*8, 8)
                    if not v: break
                    v = struct.unpack('<Q', v)[0]
                    if v == 0: break
                    if v & 0x8000000000000000:
                        funcs.append(('ord', v & 0xFFFF, None))
                    else:
                        hint = self.read_rva((v & 0x7FFFFFFF), 2)
                        hintv = struct.unpack('<H', hint)[0] if hint else None
                        funcs.append(('name', hintv, self.cstr((v & 0x7FFFFFFF) + 2)))
                else:
                    v = self.read_rva(thunk_rva + i*4, 4)
                    if not v: break
                    v = struct.unpack('<I', v)[0]
                    if v == 0: break
                    if v & 0x80000000:
                        funcs.append(('ord', v & 0xFFFF, None))
                    else:
                        hint = self.read_rva(v, 2)
                        hintv = struct.unpack('<H', hint)[0] if hint else None
                        funcs.append(('name', hintv, self.cstr(v + 2)))
                i += 1
                if i > 5000: break
            out.append(dict(dll=dll, funcs=funcs))
            p += 20
        return out

    def parse_delay_imports(self):
        rva, sz = self.dirs.get('DelayImport', (0, 0))
        out = []
        if not rva: return out
        p = rva
        for _ in range(256):
            desc = self.read_rva(p, 32)
            if not desc or desc == b'\0'*32: break
            attrs, name_rva, hmod, iat, int_rva, bound, unload, ts = struct.unpack('<IIIIIIII', desc)
            dll = self.cstr(name_rva) or ''
            funcs = []
            thunk = int_rva or iat
            i = 0
            while thunk and i < 5000:
                if self.pe32plus:
                    v = self.read_rva(thunk + i*8, 8)
                    if not v: break
                    v = struct.unpack('<Q', v)[0]
                    if v == 0: break
                    if not (v & 0x8000000000000000):
                        funcs.append(('name', None, self.cstr((v & 0x7FFFFFFF) + 2)))
                    else:
                        funcs.append(('ord', v & 0xFFFF, None))
                else:
                    v = self.read_rva(thunk + i*4, 4)
                    if not v: break
                    v = struct.unpack('<I', v)[0]
                    if v == 0: break
                    if not (v & 0x80000000):
                        funcs.append(('name', None, self.cstr(v + 2)))
                    else:
                        funcs.append(('ord', v & 0xFFFF, None))
                i += 1
            out.append(dict(dll=dll, funcs=funcs, attrs=attrs))
            p += 32
        return out

    # ------------------------------------------------------------ 导出表
    def parse_exports(self):
        rva, sz = self.dirs.get('Export', (0, 0))
        if not rva: return None
        hdr = self.read_rva(rva, 40)
        if not hdr: return None
        (flags, ts, maj, minr, name_rva, base, nexp, nnames, a_funcs, a_names, a_ords) = \
            struct.unpack('<IIHHIIIIIII', hdr)
        dllname = self.cstr(name_rva)
        funcs = []
        for i in range(min(nexp, 4096)):
            frva = self.read_rva(a_funcs + i*4, 4)
            if not frva: break
            frva = struct.unpack('<I', frva)[0]
            nm = None
            for j in range(min(nnames, 4096)):
                ov = self.read_rva(a_ords + j*2, 2)
                if not ov: break
                if struct.unpack('<H', ov)[0] == i:
                    nr = self.read_rva(a_names + j*4, 4)
                    if nr:
                        nm = self.cstr(struct.unpack('<I', nr)[0])
                    break
            funcs.append(dict(ordinal=base+i, rva=frva, name=nm,
                              forwarder=self.cstr(frva) if frva and self.rva2off(frva) and
                              self.dirs['Export'][0] <= frva < self.dirs['Export'][0]+self.dirs['Export'][1] else None))
        return dict(name=dllname, base=base, count=nexp, funcs=funcs)

    # ------------------------------------------------------------ 资源
    def parse_resources(self):
        rva, sz = self.dirs.get('Resource', (0, 0))
        if not rva: return []
        out = []
        TYPES = {1:'CURSOR',2:'BITMAP',3:'ICON',4:'MENU',5:'DIALOG',6:'STRING',7:'FONTDIR',
                 8:'FONT',9:'ACCELERATOR',10:'RCDATA',11:'MESSAGETABLE',12:'GROUP_CURSOR',
                 14:'GROUP_ICON',16:'VERSION',17:'DLGINCLUDE',19:'PLUGPLAY',20:'VXD',
                 21:'ANICURSOR',22:'ANIICON',23:'HTML',24:'MANIFEST'}
        def name_of(ent_off):
            v = self.u32(ent_off)
            if v & 0x80000000:
                so = self.rva2off(rva + (v & 0x7FFFFFFF))
                if so is None: return '?'
                n = self.u16(so)
                return self.d[so+2:so+2+n*2].decode('utf-16-le', 'replace')
            return v
        def walk(off, depth, path):
            if depth > 3: return
            o = self.rva2off(rva + off)
            if o is None: return
            nnamed = self.u16(o+12); nid = self.u16(o+14)
            for i in range(nnamed + nid):
                eo = o + 16 + i*8
                if eo + 8 > self.size: return
                nm = name_of(eo)
                child = self.u32(eo+4)
                if child & 0x80000000:
                    walk(child & 0x7FFFFFFF, depth+1, path + [nm])
                else:
                    do = self.rva2off(rva + child)
                    if do is None: continue
                    drva, dsz, cpg, res = struct.unpack_from('<IIII', self.d, do)
                    data = self.read_rva(drva, min(dsz, 1<<20)) or b''
                    t = path[0]
                    tn = TYPES.get(t, str(t)) if isinstance(t, int) else str(t)
                    out.append(dict(type=tn, name=path[1] if len(path) > 1 else '',
                                    lang=path[2] if len(path) > 2 else '',
                                    rva=drva, size=dsz, entropy=round(entropy(data), 3),
                                    magic=data[:16].hex(),
                                    preview=data[:64].decode('latin1', 'replace')))
        walk(0, 0, [])
        return out

    def parse_tls(self):
        rva, sz = self.dirs.get('TLS', (0, 0))
        if not rva: return None
        hdr = self.read_rva(rva, 40)
        if not hdr: return None
        if self.pe32plus:
            s, e, idx, cba, zf, ch = struct.unpack('<QQQQII', hdr)
        else:
            s, e, idx, cba, zf, ch = struct.unpack('<IIIIII', hdr[:24])
        cbs = []
        o = self.rva2off(cba or 0)
        for i in range(32):
            if not o or o + 8 > self.size: break
            v = struct.unpack_from('<Q', self.d, o)[0] if self.pe32plus else struct.unpack_from('<I', self.d, o)[0]
            if v == 0: break
            cbs.append(hex(v))
            o += 8 if self.pe32plus else 4
        return dict(callbacks=cbs, address_of_callbacks=hex(cba) if cba else None)

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def char_flags(c):
    f = []
    m = {0x00000020:'CNT_CODE',0x00000040:'CNT_INIT_DATA',0x00000080:'CNT_UNINIT_DATA',
         0x02000000:'MEM_DISCARDABLE',0x04000000:'MEM_NOT_CACHED',0x08000000:'MEM_NOT_PAGED',
         0x10000000:'MEM_SHARED',0x20000000:'MEM_EXECUTE',0x40000000:'MEM_READ',0x80000000:'MEM_WRITE'}
    for k, v in m.items():
        if c & k: f.append(v)
    return '|'.join(f)

# ---------------------------------------------------------------- 字符串
def strings_ascii(data, minlen=4):
    out = []
    cur = bytearray(); start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D):
            if not cur: start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append((start, cur.decode('latin1')))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append((start, cur.decode('latin1')))
    return out

def strings_utf16(data, minlen=4):
    out = []
    i = 0; n = len(data)
    while i + 1 < n:
        start = i
        cur = []
        while i + 1 < n:
            lo = data[i]; hi = data[i+1]
            if hi == 0 and (0x20 <= lo < 0x7F or lo in (0x09, 0x0A, 0x0D)):
                cur.append(chr(lo)); i += 2
            else:
                break
        if len(cur) >= minlen:
            out.append((start, ''.join(cur)))
            continue
        i = start + 2 if cur else i + 1
    # 再来一遍支持中文（非 0 高字节）的宽字符串
    i = 0
    while i + 1 < n:
        start = i; cur = []
        while i + 1 < n:
            ch = data[i] | (data[i+1] << 8)
            if ch == 0: break
            if 0x20 <= ch < 0x7F or 0x4E00 <= ch <= 0x9FFF or 0x3000 <= ch <= 0x303F or 0xFF00 <= ch <= 0xFFEF:
                cur.append(chr(ch)); i += 2
            else:
                break
        if len(cur) >= minlen and any(ord(c) > 0x7F for c in cur):
            out.append((start, ''.join(cur)))
            continue
        i = start + 2
    seen = set(); res = []
    for off, s in sorted(out):
        key = (off, s)
        if key in seen: continue
        seen.add(key); res.append((off, s))
    return res

def main():
    path = sys.argv[1]
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    data = open(path, 'rb').read()
    pe = PE(data)
    result = dict(file=path, size=len(data),
                  sha256=hashlib.sha256(data).hexdigest(),
                  md5=hashlib.md5(data).hexdigest(),
                  dos=dict(e_lfanew=pe.e_lfanew, stub_len=len(pe.dos_stub),
                           stub_text=pe.dos_stub_ascii),
                  nt=dict(machine=hex(pe.machine), nsec=pe.nsec,
                          timestamp=pe.timestamp,
                          timestamp_utc=datetime.datetime.utcfromtimestamp(pe.timestamp).isoformat()+'Z' if 0 < pe.timestamp < 0x80000000 else None,
                          characteristics=hex(pe.characteristics),
                          opt_magic=hex(pe.opt_magic), pe32plus=pe.pe32plus,
                          linker=f'{pe.major_linker}.{pe.minor_linker}',
                          entry_rva=hex(pe.entry_rva), image_base=hex(pe.image_base),
                          section_align=pe.section_align, file_align=pe.file_align,
                          size_image=pe.size_image, size_headers=pe.size_headers,
                          checksum=hex(pe.checksum), subsystem=pe.subsystem,
                          dll_chars=hex(pe.dll_chars), checksum_ok=None,
                          dirs={k: [hex(v[0]), v[1]] for k, v in pe.dirs.items()}),
                  sections=pe.sections,
                  imports=[dict(dll=i['dll'], funcs=[f[2] if f[0]=='name' else f'#{f[1]}' for f in i['funcs']],
                                count=len(i['funcs'])) for i in pe.imports],
                  delay_imports=[dict(dll=i['dll'], funcs=[f[2] if f[0]=='name' else f'#{f[1]}' for f in i['funcs']]) for i in pe.delay_imports],
                  exports=pe.exports, resources=pe.resources, tls=pe.tls)
    json.dump(result, open(os.path.join(outdir, 'rawjson.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=2)

    # ---- sections.csv
    with open(os.path.join(outdir, 'sections.csv'), 'w', encoding='utf-8') as f:
        f.write('idx,name,vaddr,vsize,rawptr,rawsize,entropy,contains_entry,md5,char_flags\n')
        for s in pe.sections:
            f.write(f"{s['index']},{s['name']},0x{s['vaddr']:08X},0x{s['vsize']:X},{s['rawptr']},"
                    f"0x{s['rawsize']:X},{s['entropy']},{s['contains_entry']},{s['md5']},{s['char_flags']}\n")

    # ---- imports.txt
    with open(os.path.join(outdir, 'imports.txt'), 'w', encoding='utf-8') as f:
        for i in pe.imports:
            f.write(f"[{i['dll']}]  {len(i['funcs'])} funcs\n")
            for kind, hint, nm in i['funcs']:
                f.write(f"    {nm if kind=='name' else '#'+str(hint)}\n")
            f.write('\n')
        if pe.delay_imports:
            f.write('=== DELAY IMPORTS ===\n')
            for i in pe.delay_imports:
                f.write(f"[{i['dll']}] {len(i['funcs'])} funcs: " +
                        ', '.join(x[2] or '#'+str(x[1]) for x in i['funcs']) + '\n')

    # ---- exports.txt
    with open(os.path.join(outdir, 'exports.txt'), 'w', encoding='utf-8') as f:
        if not pe.exports:
            f.write('(no export directory)\n')
        else:
            f.write(json.dumps(pe.exports, ensure_ascii=False, indent=2))

    # ---- resources.txt
    with open(os.path.join(outdir, 'resources.txt'), 'w', encoding='utf-8') as f:
        for r in pe.resources:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')

    # ---- strings
    asc = strings_ascii(data)
    wid = strings_utf16(data)
    with open(os.path.join(outdir, 'strings_ascii.txt'), 'w', encoding='utf-8') as f:
        for off, s in asc:
            f.write(f'{off:08X}\t{s}\n')
    with open(os.path.join(outdir, 'strings_utf16.txt'), 'w', encoding='utf-8') as f:
        for off, s in wid:
            f.write(f'{off:08X}\t{s}\n')

    print(json.dumps(dict(sections=[(s['name'], hex(s['vaddr']), s['rawsize'], s['entropy']) for s in pe.sections],
                          n_imports=len(pe.imports), n_dlls=len(pe.imports),
                          n_ascii=len(asc), n_utf16=len(wid),
                          resources=len(pe.resources),
                          sha256=result['sha256']), ensure_ascii=False, indent=1))

if __name__ == '__main__':
    main()
