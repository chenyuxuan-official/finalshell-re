#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FinalShell 离线激活码生成器（算法逆向自 finashellpp.exe）

────────────────────────────────────────────────────────────
算法总览
  输入：机器码（离线激活窗口里显示的 "<用户名>@<硬件哈希>" 或纯硬件哈希）
  步骤：Keccak384( 前缀 + 机器码 + 后缀 )  →  取十六进制串的第 12..28 位（16 字符）

  注意：是 **原版 Keccak-384**（Qt 的 QCryptographicHash::Keccak_384），
        不是 NIST SHA3-384。两者域分隔符不同（0x01 vs 0x06），结果完全不同。

  这也解释了为什么网上流传的各种 md5(机器码+salt) 公式在 4.x 上全部失效。

────────────────────────────────────────────────────────────
版本 → 算法分支（还原自 exe 内 0x1400050f0 的版本判定函数）

  设解析出的版本号为 (major, minor, patch)：

    major <= 2                              → 分支 0 (LEGACY)
    major == 3 且 minor <= 8                → 分支 0 (LEGACY)
    major == 3 且 minor == 9 且 patch <= 5  → 分支 0 (LEGACY)
    major == 3 且 minor == 9 且 patch >  5  → 分支 1
    major == 3 且 minor >  9                → 分支 1
    major == 4 且 minor == 5                → 分支 2
    major == 4 且 minor == 6                → 分支 3
    major == 4 且 minor 为其它               → 分支 1
    major >= 5                              → 分支 1

  分支对应的前后缀：

    0 (LEGACY)  prefix="2356"   suffix="13593"
    1           prefix=""       suffix="FF3Go(*Xvbb5s2"
    2           prefix=""       suffix="b(xxkHn%z);x"
    3           prefix=""       suffix="Scfg*ZkvJZc,s,Y"

  分支 1 是最通用的一支（FinalShell 3.9.6 之后长期沿用），
  多数 4.x 版本实测都能被它激活。

────────────────────────────────────────────────────────────
用法
  python finalshell_keygen.py "admin@0123456789abcdef" -v 4.6.5
  python finalshell_keygen.py "0123456789abcdef" -v 4.6.5 --all
  python finalshell_keygen.py "0123456789abcdef"            # 交互输入
"""

import argparse
import hashlib
import re
import sys

MASK = (1 << 64) - 1

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK


def _keccak_f(a):
    for rnd in range(24):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]

        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])

        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])

        a[0][0] ^= _RC[rnd]
    return a


def keccak(data: bytes, bits: int) -> bytes:
    """原版 Keccak（域分隔符 0x01）。bits ∈ {224,256,384,512}"""
    rate = (1600 - 2 * bits) // 8
    a = [[0] * 5 for _ in range(5)]

    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] ^= 0x80

    for off in range(0, len(msg), rate):
        blk = msg[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(blk[i * 8:(i + 1) * 8], 'little')
        _keccak_f(a)

    out = bytearray()
    while len(out) < bits // 8:
        for i in range(rate // 8):
            if len(out) >= bits // 8:
                break
            out += a[i % 5][i // 5].to_bytes(8, 'little')
        if len(out) < bits // 8:
            _keccak_f(a)
    return bytes(out[:bits // 8])


def keccak_384(data: bytes) -> bytes:
    return keccak(data, 384)


# ── 分支定义 ────────────────────────────────────────────────
# hash : 'md5' 或 'keccak'（原版 Keccak，非 SHA3）
# slice: 从 hex 串里取哪一段（16 字符）
BRANCHES = {
    0: dict(name='LEGACY',   hash='md5',    prefix='2356', suffix='13593',        pos=8),
    1: dict(name='MODERN-A', hash='keccak', prefix='',     suffix='FF3Go(*Xvbb5s2', pos=12),
    2: dict(name='MODERN-B', hash='keccak', prefix='',     suffix='b(xxkHn%z);x',  pos=12),
    3: dict(name='MODERN-C', hash='keccak', prefix='',     suffix='Scfg*ZkvJZc,s,Y', pos=12),
}


def pick_branch(major: int, minor: int, patch: int) -> int:
    """把版本号映射到算法分支（与 finashellpp.exe 的 0x1400050f0 完全一致）"""
    if major == 4:
        if minor == 5:
            return 2
        if minor == 6:
            return 3
        return 1
    if major <= 2:
        return 0
    if major == 3:
        if minor <= 8:
            return 0
        if minor == 9:
            return 1 if patch > 5 else 0
        return 1
    return 1


def gen(machine_code: str, branch: int) -> str:
    """
    生成激活码。

    分支 0 (LEGACY) 与其它三支的实现不同：
      LEGACY  : MD5("2356" + code + "13593").hex()[8:24]     <- 0x140005c90, r8d=8, r9d=0x10
      MODERN* : Keccak384(code + salt).hex()[12:28]          <- 0x140005cb8/cd8/cf8, r8d=12, r9d=16
    """
    spec = BRANCHES[branch]
    raw = (spec['prefix'] + machine_code + spec['suffix']).encode('utf-8')
    if spec['hash'] == 'md5':
        h = hashlib.md5(raw).hexdigest()
        pos = spec['pos']
    else:
        h = keccak_384(raw).hex()
        pos = spec['pos']
    return h[pos:pos + 16]


def parse_version(text: str):
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)$', text.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='FinalShell 离线激活码生成器（Keccak-384，算法逆向自 finashellpp.exe）')
    ap.add_argument('machine_code', nargs='?', help='机器码，形如 admin@0123456789abcdef 或 0123456789abcdef')
    ap.add_argument('-v', '--version', default='4.6.5', help='FinalShell 版本号，默认 4.6.5')
    ap.add_argument('--all', action='store_true', help='列出全部 4 个分支的结果（用于逐个试）')
    args = ap.parse_args(argv)

    code = (args.machine_code or input('请输入机器码: ')).strip()
    if not code:
        print('[!] 机器码不能为空')
        return 2

    if args.all:
        print(f'机器码: {code}\n')
        for br in sorted(BRANCHES):
            spec = BRANCHES[br]
            print(f'  分支 {br}  {spec["name"]:<9} 前缀={spec["prefix"]!r:<8} 后缀={spec["suffix"]!r:<20} -> {gen(code, br)}')
        return 0

    ver = parse_version(args.version)
    if not ver:
        print(f'[!] 版本号格式不对: {args.version}（应形如 4.6.5）')
        return 2

    br = pick_branch(*ver)
    spec = BRANCHES[br]
    print(f'机器码 : {code}')
    print(f'版本   : {args.version}  -> 分支 {br} ({spec["name"]})')
    print(f'算法   : Keccak384({spec["prefix"]!r} + code + {spec["suffix"]!r}).hex()[12:28]')
    print(f'激活码 : {gen(code, br)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
