#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""jar_patcher.py —— 纯 Python 的 jar 字节码方法体替换工具（无第三方依赖）

用法:
  python jar_patcher.py --jar finalshell.orig.jar --class Lk \
      --method "check:()Z" --value true --out out/finalshell.patched.jar

  --method 支持 "name:descriptor" 或只给 name（name 在本类中必须唯一）
  --value  true | false | <int> | null   （按目标描述符自动选指令）

原理: 完整解析 class 文件的常量池/字段/方法/属性结构，定位目标方法的 Code
属性，把 code[] 换成最小等价序列，重算 max_stack / code_length 并重建
Code 属性的 u4 attribute_length；exception_table 与 Code 子属性（LineNumber-
Table / LocalVariableTable / StackMapTable …）一并清空以保持自洽。
"""

import argparse
import io
import os
import struct
import sys
import zipfile

# ---------------------------------------------------------------- 常量池 tag
CP_Utf8, CP_Integer, CP_Float, CP_Long, CP_Double = 1, 3, 4, 5, 6
CP_Class, CP_String, CP_Fieldref, CP_Methodref, CP_InterfaceMethodref = 7, 8, 9, 10, 11
CP_NameAndType, CP_MethodHandle, CP_MethodType = 12, 15, 16
CP_Dynamic, CP_InvokeDynamic, CP_Module, CP_Package = 17, 18, 19, 20
# 单槽 (tag -> 数据字节数)
CP_SIZE = {1: None, 3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4,
           12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


class ClassFileError(Exception):
    pass


# ============================================================ class 文件模型
class ConstantPool:
    def __init__(self):
        self.entries = []      # 索引 i -> dict(tag=..., data=bytes)；双槽的第二格为 None

    @classmethod
    def parse(cls, buf, pos):
        cp = cls()
        count = struct.unpack_from('>H', buf, pos)[0]
        pos += 2
        i = 1
        while i < count:
            tag = buf[pos]
            pos += 1
            if tag == CP_Utf8:
                ln = struct.unpack_from('>H', buf, pos)[0]
                pos += 2
                raw = buf[pos:pos + ln]
                pos += ln
                cp.entries.append({'tag': tag, 'data': raw})
            else:
                if tag not in CP_SIZE:
                    raise ClassFileError('未知常量池 tag=%d @cp#%d' % (tag, i))
                size = CP_SIZE[tag]
                cp.entries.append({'tag': tag, 'data': bytes(buf[pos:pos + size])})
                pos += size
            if tag in (CP_Long, CP_Double):
                cp.entries.append(None)     # 双槽占位
                i += 2
            else:
                i += 1
        return cp, pos

    def utf8(self, idx):
        e = self.entries[idx - 1]
        if not e or e['tag'] != CP_Utf8:
            raise ClassFileError('常量池 #%d 不是 Utf8' % idx)
        return e['data'].decode('utf-8', 'replace')

    def add_integer(self, value):
        for i, e in enumerate(self.entries, 1):
            if e and e['tag'] == CP_Integer:
                if struct.unpack('>i', e['data'])[0] == value:
                    return i
        self.entries.append({'tag': CP_Integer, 'data': struct.pack('>i', value)})
        return len(self.entries)

    def serialize(self):
        out = io.BytesIO()
        out.write(struct.pack('>H', len(self.entries) + 1))
        for e in self.entries:
            if e is None:
                continue
            out.write(bytes([e['tag']]))
            if e['tag'] == CP_Utf8:
                out.write(struct.pack('>H', len(e['data'])))
            out.write(e['data'])
        return out.getvalue()


def _read_attributes(buf, pos):
    """返回 (attrs, pos)。attrs = [dict(name=idx, data=bytes)]"""
    n = struct.unpack_from('>H', buf, pos)[0]
    pos += 2
    attrs = []
    for _ in range(n):
        name_idx, length = struct.unpack_from('>HI', buf, pos)
        pos += 6
        attrs.append({'name': name_idx, 'data': bytes(buf[pos:pos + length])})
        pos += length
    return attrs, pos


def _write_attributes(attrs, cp):
    out = io.BytesIO()
    out.write(struct.pack('>H', len(attrs)))
    for a in attrs:
        data = a['data'] if isinstance(a['data'], (bytes, bytearray)) else bytes(a['data'])
        out.write(struct.pack('>HI', a['name'], len(data)))
        out.write(data)
    return out.getvalue()


class Method:
    def __init__(self, access, name_idx, desc_idx, attrs):
        self.access, self.name_idx, self.desc_idx, self.attrs = access, name_idx, desc_idx, attrs

    def serialize(self, cp):
        return (struct.pack('>HHH', self.access, self.name_idx, self.desc_idx)
                + _write_attributes(self.attrs, cp))


class ClassFile:
    def __init__(self):
        self.minor = self.major = 0
        self.cp = ConstantPool()
        self.access = self.this = self.super = 0
        self.interfaces = []
        self.fields = []          # [dict(access,name,desc,attrs)]
        self.methods = []         # [Method]
        self.attrs = []           # class 级属性

    # -------------------------------------------------------------- 解析
    @classmethod
    def load(cls, data):
        if data[:4] != b'\xca\xfe\xba\xbe':
            raise ClassFileError('不是 class 文件（magic 不符）')
        self = cls()
        self.minor, self.major = struct.unpack_from('>HH', data, 4)
        self.cp, pos = ConstantPool.parse(data, 8)
        self.access, self.this, self.super = struct.unpack_from('>HHH', data, pos)
        pos += 6
        n = struct.unpack_from('>H', data, pos)[0]
        pos += 2
        self.interfaces = list(struct.unpack_from('>%dH' % n, data, pos)) if n else []
        pos += 2 * n
        # fields
        nfields = struct.unpack_from('>H', data, pos)[0]
        pos += 2
        for _ in range(nfields):
            fc = struct.unpack_from('>HHH', data, pos)
            pos += 6
            attrs, pos = _read_attributes(data, pos)
            self.fields.append({'access': fc[0], 'name': fc[1], 'desc': fc[2], 'attrs': attrs})
        # methods
        nmethods = struct.unpack_from('>H', data, pos)[0]
        pos += 2
        for _ in range(nmethods):
            mc = struct.unpack_from('>HHH', data, pos)
            pos += 6
            attrs, pos = _read_attributes(data, pos)
            self.methods.append(Method(mc[0], mc[1], mc[2], attrs))
        self.attrs, pos = _read_attributes(data, pos)
        self._raw_tail = data[pos:]
        return self

    # -------------------------------------------------------------- 序列化
    def serialize(self):
        out = io.BytesIO()
        out.write(b'\xca\xfe\xba\xbe')
        out.write(struct.pack('>HH', self.minor, self.major))
        out.write(self.cp.serialize())
        out.write(struct.pack('>HHH', self.access, self.this, self.super))
        out.write(struct.pack('>H', len(self.interfaces)))
        for i in self.interfaces:
            out.write(struct.pack('>H', i))
        out.write(struct.pack('>H', len(self.fields)))
        for f in self.fields:
            out.write(struct.pack('>HHH', f['access'], f['name'], f['desc']))
            out.write(_write_attributes(f['attrs'], self.cp))
        out.write(struct.pack('>H', len(self.methods)))
        for m in self.methods:
            out.write(m.serialize(self.cp))
        out.write(_write_attributes(self.attrs, self.cp))
        try:
            out.write(self._raw_tail)     # 正常 class 文件此处为 0 字节
        except AttributeError:
            pass
        return out.getvalue()

    # -------------------------------------------------------------- 辅助
    def method_by(self, name, desc=None):
        hits = [m for m in self.methods if self.cp.utf8(m.name_idx) == name
                and (desc is None or self.cp.utf8(m.desc_idx) == desc)]
        if not hits:
            raise ClassFileError('未找到方法 %s%s' % (name, desc or ''))
        if len(hits) > 1:
            cand = ', '.join(self.cp.utf8(m.desc_idx) for m in hits)
            raise ClassFileError('方法 %s 存在重载，请给描述符: %s' % (name, cand))
        return hits[0]

    def code_attr(self, method):
        code_name = None
        for e in self.cp.entries:     # 找 "Code" 的 Utf8 索引
            if e and e['tag'] == CP_Utf8 and e['data'] == b'Code':
                code_name = self.cp.entries.index(e) + 1
                break
        if code_name is None:
            raise ClassFileError('常量池无 "Code" 字符串？class 文件异常')
        for a in method.attrs:
            if a['name'] == code_name:
                return a
        raise ClassFileError('该方法没有 Code 属性（abstract/native？）')


# ============================================================ 指令生成
DESC_RET = {'Z': 'int', 'B': 'int', 'C': 'int', 'S': 'int', 'I': 'int',
            'J': 'long', 'F': 'float', 'D': 'double', 'V': 'void'}


def _iconst_insn(v):
    if -1 <= v <= 5:
        return bytes([0x03 + v])                 # iconst_<n>  (iconst_m1=0x02)
    if -128 <= v <= 127:
        return bytes([0x10, v & 0xFF])           # bipush
    if -32768 <= v <= 32767:
        return bytes([0x11]) + struct.pack('>h', v)   # sipush
    return None                                  # 需要 ldc


def build_replacement(desc, value_text, cp):
    """依据方法返回描述符生成 (code_bytes, max_stack)。"""
    ret = desc[desc.rindex(')') + 1:]
    what = (value_text or '').strip().lower()

    if ret == 'V':
        return bytes([0x0C]) if what in ('true', 'false', 'null', '') else bytes([0x0C]), 0  # return

    if ret in ('Z', 'B', 'C', 'S', 'I'):
        if what == 'true':
            v = 1
        elif what == 'false':
            v = 0
        else:
            try:
                v = int(what, 0)
            except ValueError:
                raise ClassFileError('返回值 %r 无法转成整数' % value_text)
        insn = _iconst_insn(v)
        if insn is None:                          # 走 ldc
            idx = cp.add_integer(v)
            insn = bytes([0x12, idx]) if idx <= 0xFF else bytes([0x13]) + struct.pack('>H', idx)
        return insn + bytes([0xAC]), 1            # ireturn

    if ret == 'J':
        v = 0 if what in ('true', 'false', 'null', '') else int(what, 0)
        if v == 0:
            return bytes([0x09, 0xAD]), 2         # lconst_0; lreturn
        if v == 1:
            return bytes([0x0A, 0xAD]), 2
        return bytes([0x09, 0xAD]), 2

    if ret in ('F', 'D'):
        return (bytes([0x0B, 0xAE]) if ret == 'F' else bytes([0x0E, 0xAF])), 2  # fconst_0;freturn

    # 引用类型：只支持 null
    if ret.startswith('L') or ret.startswith('['):
        if what not in ('null', 'true', 'false', ''):
            raise ClassFileError('引用返回只支持 null')
        return bytes([0x01, 0xB0]), 1             # aconst_null; areturn

    raise ClassFileError('不支持的返回描述符: %r' % ret)


def patch_class_bytes(data, class_internal, method_name, method_desc, value_text):
    """返回 (新 class 字节, 信息 dict)。class_internal 形如 'Lk' 或 'k/L'。"""
    cf = ClassFile.load(data)
    m = cf.method_by(method_name, method_desc)
    code_attr = cf.code_attr(m)
    cd = code_attr['data']
    old_max_stack, old_max_locals = struct.unpack_from('>HH', cd, 0)
    old_len = struct.unpack_from('>I', cd, 4)[0]
    old_code = cd[8:8 + old_len]
    exc_len = struct.unpack_from('>H', cd, 8 + old_len)[0]
    nsub = struct.unpack_from('>H', cd, 8 + old_len + 2 + 8 * exc_len)[0]

    desc = cf.cp.utf8(m.desc_idx)
    new_code, new_stack = build_replacement(desc, value_text, cf.cp)

    # 重建 Code 属性体：exception_table 与 Code 子属性全部清空
    body = struct.pack('>HHI', new_stack, old_max_locals, len(new_code)) + new_code
    body += struct.pack('>H', 0) + struct.pack('>H', 0)
    code_attr['data'] = body

    return cf.serialize(), {
        'class': class_internal, 'method': '%s%s' % (method_name, desc),
        'old_code_len': old_len, 'new_code_len': len(new_code),
        'old_code_hex': old_code.hex(), 'new_code_hex': new_code.hex(),
        'old_max_stack': old_max_stack, 'new_max_stack': new_stack,
        'max_locals': old_max_locals,
        'dropped_exception_table': exc_len, 'dropped_code_subattrs': nsub,
        'old_code_attr_len': len(cd), 'new_code_attr_len': len(body),
    }


# ============================================================ jar 读写
def entry_name_of(class_internal):
    name = class_internal
    if name.startswith('L') and name.endswith(';'):
        name = name[1:-1]
    return name.replace('.', '/') + '.class'


def patch_jar(jar_in, jar_out, class_internal, method_name, method_desc, value):
    target = entry_name_of(class_internal)
    zin = zipfile.ZipFile(jar_in, 'r')
    names = set(zin.namelist())
    if target not in names:
        close = [n for n in names if n.endswith(target.split('/')[-1])][:15]
        raise ClassFileError('jar 内无 %s；相近条目: %s' % (target, close))

    os.makedirs(os.path.dirname(os.path.abspath(jar_out)) or '.', exist_ok=True)
    info = None
    with zipfile.ZipFile(jar_out, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
        # manifest 优先
        order = sorted(zin.infolist(), key=lambda i: (i.filename != 'META-INF/MANIFEST.MF',))
        for it in order:
            raw = zin.read(it.filename)
            data = raw
            if it.filename == target:
                data, info = patch_class_bytes(raw, class_internal, method_name,
                                              method_desc, value)
            zi = zipfile.ZipInfo(it.filename, date_time=it.date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = it.external_attr
            zi.internal_attr = it.internal_attr
            zi.create_system = it.create_system or 0
            try:
                zi.flag_bits |= it.flag_bits & 0x800
            except Exception:
                pass
            zi.file_size = len(data)
            zout.writestr(zi, data)
    zin.close()
    info['jar_in'] = jar_in
    info['jar_out'] = jar_out
    info['entry'] = target
    return info


def main(argv=None):
    ap = argparse.ArgumentParser(description='纯 Python jar 字节码方法体替换（可回滚）')
    ap.add_argument('--jar', required=True, help='原始 jar 路径（不会被修改）')
    ap.add_argument('--class', dest='klass', required=True,
                    help='类内部名，如 Lk 或 k/L 或 k/L;')
    ap.add_argument('--method', required=True, help='name:descriptor 或 name')
    ap.add_argument('--value', required=True, help='true | false | <int> | null')
    ap.add_argument('--out', required=True, help='输出 jar 路径（不得等于 --jar）')
    a = ap.parse_args(argv)

    if os.path.abspath(a.jar) == os.path.abspath(a.out):
        ap.error('--out 不能与 --jar 相同（原 jar 必须保留）')
    if ':' in a.method:
        name, desc = a.method.split(':', 1)
    else:
        name, desc = a.method, None
    info = patch_jar(a.jar, a.out, a.klass, name, desc, a.value)
    print('[OK] %s -> %s' % (info['jar_in'], info['jar_out']))
    print('  条目        : %s' % info['entry'])
    print('  方法        : %s' % info['method'])
    print('  原始字节长度: %d  (%s)' % (info['old_code_len'], info['old_code_hex'][:120]))
    print('  新字节长度  : %d  (%s)' % (info['new_code_len'], info['new_code_hex']))
    print('  max_stack    : %d -> %d, max_locals=%d'
          % (info['old_max_stack'], info['new_max_stack'], info['max_locals']))
    print('  Code 属性长度: %d -> %d（清空异常表 %d 条、子属性 %d 个）'
          % (info['old_code_attr_len'], info['new_code_attr_len'],
             info['dropped_exception_table'], info['dropped_code_subattrs']))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except ClassFileError as e:
        print('[ERR] %s' % e, file=sys.stderr)
        sys.exit(2)
