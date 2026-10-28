#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fk_string_decrypt.py —— FinalShell (Zelix KlassMaster) 私有字符串解密器 b(int,int) 的纯 Python 复现

Class files: Lk / DU / aW / ... 每个 class 自带一份
    private static String b(int arg0, int arg1)
算法（详见 docs/02-string-decrypt.md）：
    idx = (arg0 ^ INDEX_XOR) & 0xFFFF             # INDEX_XOR = -17846
    c[] = f[idx]                                  # 密文块（静态 String[] f）
    m   = M[c[0] & 0xFF]                          # 255 分支 tableswitch 查出的扰动量
    k1  = (arg1       & 0xFF) - m  (mod 256)      # 偶数位密钥
    k2  = ((arg1 & 0xFFFF) >> 8) - m (mod 256)    # 奇数位密钥
    for j in 0..len-1:
        if j even: c[j] ^= k1; k1 = ror3(k1) ^ c[j] & 0xFF
        else:      c[j] ^= k2; k2 = ror3(k2) ^ c[j] & 0xFF
    return new String(c)                          # 并 intern 进 i[idx]

其中 M[] 从真实 class 的 tableswitch 里反读（本工具自动做），f[] 用 tools/DumpStringTable.java
导出（JSON）。两者都是「数据」，本工具是纯 Python、离线、不依赖 JVM。

用法示例：
    python fk_string_decrypt.py --dump-m                       # 打印 M 表与 class 信息
    python fk_string_decrypt.py --pair 5:-12360                # 单个 idx:key
    python fk_string_decrypt.py --idx 5 --key -12360
    python fk_string_decrypt.py --pairs-file data/lk_known_pairs.tsv --limit 20
    python fk_string_decrypt.py --selftest data/lk_known_pairs.tsv   # 与运行期实测明文比对
    python fk_string_decrypt.py --callsites data/callsites.sample.tsv --out out/strings.tsv
"""
import argparse
import io
import json
import os
import struct
import sys
import zipfile

INDEX_XOR = -17846          # idx = (arg0 ^ INDEX_XOR) & 0xFFFF
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_JAR = os.path.join(ROOT, "finalshell.orig.jar")
DEFAULT_BLOCKS = os.path.join(ROOT, "data", "lk_string_table.json")
DEFAULT_CLASS = "Lk"

CP_Utf8, CP_Integer, CP_Float, CP_Long, CP_Double = 1, 3, 4, 5, 6
CP_Class, CP_String, CP_Fieldref, CP_Methodref = 7, 8, 9, 10
CP_InterfaceMethodref, CP_NameAndType = 11, 12
CP_MethodHandle, CP_MethodType, CP_Dynamic, CP_InvokeDynamic = 15, 16, 17, 18
CP_Module, CP_Package = 19, 20


# --------------------------------------------------------------- class 解析
class Reader(object):
    __slots__ = ("b", "p")

    def __init__(self, data, pos=0):
        self.b, self.p = data, pos

    def u1(self):
        v = self.b[self.p]
        self.p += 1
        return v

    def u2(self):
        v = (self.b[self.p] << 8) | self.b[self.p + 1]
        self.p += 2
        return v

    def u4(self):
        v = struct.unpack_from(">I", self.b, self.p)[0]
        self.p += 4
        return v

    def take(self, n):
        v = self.b[self.p:self.p + n]
        self.p += n
        return v


def parse_cp(data):
    r = Reader(data, 8)
    count = r.u2()
    cp = [None] * count
    i = 1
    while i < count:
        tag = r.u1()
        if tag == CP_Utf8:
            cp[i] = (tag, r.take(r.u2()).decode("utf-8", "replace"))
        elif tag in (CP_Integer, CP_Float):
            cp[i] = (tag, struct.unpack_from(">i", data, r.p)[0])
            r.p += 4
        elif tag in (CP_Long, CP_Double):
            cp[i] = (tag, struct.unpack_from(">q", data, r.p)[0])
            r.p += 8
            i += 1
        elif tag in (CP_Class, CP_String, CP_MethodType, CP_Module, CP_Package):
            cp[i] = (tag, r.u2())
        elif tag in (CP_Fieldref, CP_Methodref, CP_InterfaceMethodref,
                     CP_NameAndType, CP_Dynamic, CP_InvokeDynamic):
            cp[i] = (tag, r.u2(), r.u2())
        elif tag == CP_MethodHandle:
            cp[i] = (tag, r.u1(), r.u2())
        else:
            raise ValueError("bad cp tag %d @ %d" % (tag, i))
        i += 1
    return cp, r.p


def utf8(cp, i):
    e = cp[i]
    return e[1] if e and e[0] == CP_Utf8 else None


def find_method_code(data, name, desc):
    """返回目标方法的 code 字节（第一个 Code 属性）。"""
    cp, pos = parse_cp(data)
    r = Reader(data, pos)
    r.u2()                      # access
    r.u2()                      # this
    r.u2()                      # super
    nif = r.u2()                # interfaces（同样不能写成 r.p += 2 * r.u2()）
    r.p += 2 * nif
    for _ in range(r.u2()):     # fields
        r.p += 6
        _skip_attrs(r)
    for _ in range(r.u2()):     # methods
        r.u2()
        mn = utf8(cp, r.u2())
        md = utf8(cp, r.u2())
        for _ in range(r.u2()):
            an = utf8(cp, r.u2())
            ln = r.u4()
            end = r.p + ln
            if mn == name and md == desc and an == "Code":
                r.u2(), r.u2()                       # max_stack / max_locals
                return bytes(r.take(r.u4())), cp
            r.p = end
    raise ValueError("method %s%s not found" % (name, desc))


def _skip_attrs(r):
    for _ in range(r.u2()):
        r.u2()
        ln = r.u4()              # 先取值再推进：写成 r.p += r.u4() 会吞掉 u4 的 4 字节
        r.p += ln


# ----------------------------------------------------------- 指令长度与解码
LEN = [1] * 256
for _op in (0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38,
            0x39, 0x3A, 0xA9, 0xBC):
    LEN[_op] = 2
for _op in (0x11, 0x13, 0x14, 0x84, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
            0xB8, 0xBB, 0xBD, 0xC0, 0xC1, 0xC6, 0xC7):
    LEN[_op] = 3
LEN[0xC5] = 4
for _op in (0xB9, 0xBA, 0xC8, 0xC9):
    LEN[_op] = 5
for _op in range(0x99, 0xA9):
    LEN[_op] = 3


def decode(code):
    """yield (offset, opcode, operand_offset, next_offset)"""
    n = len(code)
    pc = 0
    while pc < n:
        op = code[pc]
        if op == 0xAA:                                   # tableswitch
            pad = (4 - ((pc + 1) % 4)) % 4
            p = pc + 1 + pad
            low = struct.unpack_from(">i", code, p + 4)[0]
            high = struct.unpack_from(">i", code, p + 8)[0]
            nxt = p + 12 + 4 * (high - low + 1)
            yield pc, op, pc + 1, nxt
            pc = nxt
        elif op == 0xAB:                                 # lookupswitch
            pad = (4 - ((pc + 1) % 4)) % 4
            p = pc + 1 + pad
            npairs = struct.unpack_from(">i", code, p + 4)[0]
            nxt = p + 8 + 8 * npairs
            yield pc, op, pc + 1, nxt
            pc = nxt
        elif op == 0xC4:                                 # wide
            nxt = pc + (6 if code[pc + 1] == 0x84 else 4)
            yield pc, op, pc + 2, nxt
            pc = nxt
        else:
            nxt = pc + LEN[op]
            yield pc, op, pc + 1, nxt
            pc = nxt


def const_int(cp, code, op, ps):
    """该指令压栈的 int 常量（只认 iconst_/bipush/sipush/ldc）"""
    if 0x02 <= op <= 0x08:
        return op - 0x03
    if op == 0x10:
        v = code[ps]
        return v - 256 if v > 127 else v
    if op == 0x11:
        v = (code[ps] << 8) | code[ps + 1]
        return v - 65536 if v > 32767 else v
    if op in (0x12, 0x13):
        k = code[ps] if op == 0x12 else ((code[ps] << 8) | code[ps + 1])
        if 0 < k < len(cp) and cp[k] and cp[k][0] == CP_Integer:
            return cp[k][1]
    return None


def build_m_table(code, cp):
    """从 b(int,int) 的 tableswitch 反读出 M[0..254]（case 值 = 密文首字符低字节）。"""
    ins = list(decode(code))
    by_off = {o: (op, ps) for o, op, ps, _ in ins}
    for pc, op, ps, nxt in ins:
        if op != 0xAA:
            continue
        pad = (4 - ((pc + 1) % 4)) % 4
        p = pc + 1 + pad
        default = struct.unpack_from(">i", code, p)[0]
        low = struct.unpack_from(">i", code, p + 4)[0]
        high = struct.unpack_from(">i", code, p + 8)[0]
        table = {}
        for k in range(low, high + 1):
            off = struct.unpack_from(">i", code, p + 12 + 4 * (k - low))[0]
            target = pc + off
            if target in by_off:
                v = const_int(cp, code, by_off[target][0], by_off[target][1])
                if v is not None:
                    table[k] = v
        dflt = None
        if pc + default in by_off:
            dflt = const_int(cp, code, by_off[pc + default][0], by_off[pc + default][1])
        return table, dflt
    raise ValueError("b(int,int) 里没有找到 tableswitch")


# ------------------------------------------------------------------ 解密本体
def ror3(k):
    """(k >>> 3) | (k << 5) ，8 位域内等价循环右移 3"""
    return ((k >> 3) | (k << 5)) & 0xFF


def decrypt_block(block, arg1, m):
    """block: 密文 str；arg1: 调用点第二参数；m: 该块的扰动量 -> 明文 str"""
    c = [ord(ch) for ch in block]
    if not c:
        return ""
    k1 = (arg1 & 0xFF) - m
    if k1 < 0:
        k1 += 256
    k2 = ((arg1 & 0xFFFF) >> 8) - m
    if k2 < 0:
        k2 += 256
    out = []
    for j, ch in enumerate(c):
        if (j & 1) == 0:
            ch ^= k1
            k1 = ror3(k1) ^ ch
        else:
            ch ^= k2
            k2 = ror3(k2) ^ ch
        out.append(chr(ch))
    return "".join(out)


class Decryptor(object):
    def __init__(self, blocks, m_table, m_default):
        self.blocks = blocks
        self.m_table = m_table
        self.m_default = 3 if m_default is None else m_default

    def decrypt(self, arg0, arg1):
        idx = (arg0 ^ INDEX_XOR) & 0xFFFF
        block = self.blocks[idx]
        m = self.m_table.get(ord(block[0]) & 0xFF, self.m_default) if block else self.m_default
        return decrypt_block(block, arg1, m)

    def decrypt_idx(self, idx, arg1):
        return self.decrypt(idx ^ INDEX_XOR, arg1)


def load_jar_class(jar, cls):
    with zipfile.ZipFile(jar) as z:
        name = cls.replace(".", "/") + ".class"
        if name not in z.namelist():
            raise SystemExit("jar 内没有 %s" % name)
        return z.read(name)


def load_blocks(path, cls, field="f"):
    with io.open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    fields = doc.get("fields") or {}
    if field not in fields:
        raise SystemExit("%s 里没有字段 %s（可用字段：%s）"
                         % (path, field, ", ".join(sorted(fields))))
    vals = fields[field]["values"]
    return ["" if v is None else v for v in vals], doc


def make_decryptor(args):
    code, cp = find_method_code(load_jar_class(args.jar, args.klass),
                               args.method, "(II)Ljava/lang/String;")
    m_table, m_default = build_m_table(code, cp)
    blocks, doc = load_blocks(args.blocks, args.klass, args.field)
    return Decryptor(blocks, m_table, m_default), m_table, m_default, doc


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="FinalShell/Zelix 私有字符串解密器 b(int,int) 的纯 Python 复现")
    ap.add_argument("--jar", default=DEFAULT_JAR, help="原始 jar（只读，取 class 里的 M 表用）")
    ap.add_argument("--class", dest="klass", default=DEFAULT_CLASS, help="目标类内部名，默认 Lk")
    ap.add_argument("--method", default="b", help="解密方法名，默认 b")
    ap.add_argument("--blocks", default=DEFAULT_BLOCKS, help="密文块表 JSON（DumpStringTable 导出）")
    ap.add_argument("--field", default="f", help="密文块在 JSON 里的字段名，默认 f")
    ap.add_argument("--idx", type=int, help="密文块下标")
    ap.add_argument("--key", type=int, help="调用点第二参数 arg1")
    ap.add_argument("--pair", action="append", default=[],
                    help="idx:key，可重复，例如 --pair 5:-12360")
    ap.add_argument("--arg0", type=int, help="直接给原始 arg0（会自动算 idx）")
    ap.add_argument("--pairs-file", help="TSV：idx<TAB>key[<TAB>expected]")
    ap.add_argument("--callsites", help="scan_callsites.py 输出的 callsites.tsv（idx/key/class/method/desc）")
    ap.add_argument("--decryptor", help="只处理该解密器类的调用点（callsites.tsv 第 5 列），例如 Lk")
    ap.add_argument("--out", help="把结果写成 TSV")
    ap.add_argument("--limit", type=int, default=0, help="最多处理多少行（0=全部）")
    ap.add_argument("--selftest", help="与运行期实测明文比对：TSV idx<TAB>key<TAB>plain")
    ap.add_argument("--dump-m", action="store_true", help="打印 M 表统计与块数")
    a = ap.parse_args(argv)

    dec, m_table, m_default, doc = make_decryptor(a)

    if a.dump_m:
        vals = sorted(set(m_table.values()))
        print("class        : %s (%s)" % (doc.get("class"), doc.get("jar")))
        print("密文块 f[]   : %d 项，最长 %d 字符"
              % (len(dec.blocks), max(len(x) for x in dec.blocks)))
        print("M 表         : %d 个 case，default=%s，取值集合(共 %d 种) 前 12：%s"
              % (len(m_table), m_default, len(vals), vals[:12]))
        return 0

    if a.selftest:
        total = ok = 0
        bad = []
        with io.open(a.selftest, encoding="utf-8") as fh:
            for line in fh:
                p = line.rstrip("\n").split("\t")
                if len(p) < 3 or p[0].startswith("#"):
                    continue
                try:
                    idx, key = int(p[0]), int(p[1])
                except ValueError:
                    continue
                got = dec.decrypt_idx(idx, key)
                total += 1
                if got == p[2]:
                    ok += 1
                elif len(bad) < 10:
                    bad.append((idx, key, p[2], got))
        print("selftest: %d/%d 通过 (%.2f%%)" % (ok, total, 100.0 * ok / max(1, total)))
        for idx, key, want, got in bad:
            print("  MISMATCH idx=%d key=%d want=%r got=%r" % (idx, key, want, got))
        return 0 if ok == total else 1

    pairs = []
    if a.idx is not None and a.key is not None:
        pairs.append((a.idx, a.key))
    if a.arg0 is not None and a.key is not None:
        pairs.append(((a.arg0 ^ INDEX_XOR) & 0xFFFF, a.key))
    for spec in a.pair:
        i, k = spec.split(":", 1)
        pairs.append((int(i), int(k)))
    if a.pairs_file:
        with io.open(a.pairs_file, encoding="utf-8") as fh:
            for line in fh:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 2 and not p[0].startswith("#"):
                    try:
                        pairs.append((int(p[0]), int(p[1])))
                    except ValueError:
                        pass
    if a.callsites:
        with io.open(a.callsites, encoding="utf-8") as fh:
            header = fh.readline()
            for line in fh:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 2:
                    if a.decryptor and len(p) >= 5 and p[4] != a.decryptor:
                        continue
                    try:
                        pairs.append((int(p[0]), int(p[1])))
                    except ValueError:
                        pass
    if not pairs:
        ap.error("至少给一组 --idx/--key、--pair、--pairs-file 或 --callsites")

    if a.limit:
        pairs = pairs[:a.limit]
    out = io.open(a.out, "w", encoding="utf-8", newline="\n") if a.out else None
    if out:
        out.write("idx\tkey\tplain\n")
    for idx, key in pairs:
        plain = dec.decrypt_idx(idx, key)
        readable = "".join(ch if 0x20 <= ord(ch) <= 0x7e or 0x4e00 <= ord(ch) <= 0x9fff
                           else "." for ch in plain)
        print("%4d\t%8d\t%s" % (idx, key, readable))
        if out:
            out.write("%d\t%d\t%s\n" % (idx, key, plain.replace("\t", "\\t")
                                        .replace("\n", "\\n").replace("\r", "")))
    if out:
        out.close()
        print("[OK] -> %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
