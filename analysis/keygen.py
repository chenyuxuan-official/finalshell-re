#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
finashellpp.exe 授权码算法重实现（仅依据静态反汇编，未运行样本）
- 与反汇编对应关系见 exe_report.md 第 7 节
- Keccak-384 用自实现（Qt6 QCryptographicHash::Keccak_384 = 原始 Keccak 填充 0x01，非 SHA3）
用法: python keygen.py <版本号如4.6.5> <机器码>
      python keygen.py --selftest
"""
import sys, hashlib

# ----------------------------- Keccak-384 (original padding 0x01)
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M = (1 << 64) - 1
RATE = 104          # 384-bit capacity 768 → rate 832 bit = 104 byte

def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M if n else x

def keccak_f(A):
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rol(A[x][y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
        A[0][0] ^= RC[rnd]
    return A

def keccak384(data: bytes) -> bytes:
    A = [[0] * 5 for _ in range(5)]
    m = bytearray(data)
    m.append(0x01)          # Keccak 原始填充
    while len(m) % RATE:
        m.append(0x00)
    m[-1] ^= 0x80
    for off in range(0, len(m), RATE):
        blk = m[off:off + RATE]
        for i in range(RATE // 8):
            x, y = i % 5, i // 5
            A[x][y] ^= int.from_bytes(blk[i * 8:i * 8 + 8], 'little')
        A = keccak_f(A)
    out = bytearray()
    for i in range(48 // 8):
        x, y = i % 5, i // 5
        out += A[x][y].to_bytes(8, 'little')
    return bytes(out)

# ----------------------------- 分支选择（对应 0x1400050f0）
def mode_of(major, minor, patch):
    if major <= 2:
        return 0                     # LEGACY
    if major == 3:
        if minor <= 8:
            return 0
        if minor > 9:
            return 1                 # MODERN
        return 1 if patch > 5 else 0 # minor == 9
    if major == 4:
        if minor == 5:
            return 2                 # V45
        if minor == 6:
            return 3                 # V46
        return 1                     # MODERN
    return 1                         # major >= 5 → MODERN

SALT = {1: 'FF3Go(*Xvbb5s2', 2: 'b(xxkHn%z);x', 3: 'Scfg*ZkvJZc,s,Y'}
NAMES = {0: 'LEGACY', 1: 'MODERN', 2: 'V45', 3: 'V46'}

def token(major, minor, patch, machine_code: str):
    mc = machine_code.strip()            # 0x140005670 用 trimmed_helper
    mode = mode_of(major, minor, patch)
    if mode == 0:                        # md5("2356"+mc+"13593").hex()[8:24]
        h = hashlib.md5(('2356' + mc + '13593').encode('utf-8')).hexdigest()
        return NAMES[mode], h[8:24], h
    h = keccak384((mc + SALT[mode]).encode('utf-8')).hex()   # 48B → 96 hex
    return NAMES[mode], h[12:28], h

def selftest():
    vectors = {
        # 官方 Keccak 测试向量（原始填充 0x01）
        b'': '2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b'
              '2dd2b21362337441ac12b515911957ff',
        b'abc': 'f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99'
                'f8c681e4afaf31a34db29fb763e3c28e',
    }
    for k, v in vectors.items():
        got = keccak384(k).hex()
        print(('OK  ' if got == v else 'FAIL') + f'  keccak384({k!r}) = {got}')

if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == '--selftest':
        selftest()
    elif len(sys.argv) >= 3:
        ver = sys.argv[1]
        mc = sys.argv[2]
        a, b, c = (ver.split('.') + ['0', '0'])[:3]
        name, tok, full = token(int(a), int(b), int(c), mc)
        print(f'version={ver}  mode={name}')
        print(f'full_digest={full}')
        print(f'token={tok}')
    else:
        print(__doc__)
        print('--- 版本 → 模式对照 ---')
        for v in ['2.9.9', '3.8.0', '3.9.5', '3.9.6', '3.10.0', '4.4.1', '4.5.0', '4.6.0',
                  '4.6.5', '4.7.0', '5.0.0']:
            a, b, c = [int(x) for x in v.split('.')]
            print(f'  {v} -> {NAMES[mode_of(a, b, c)]}')
