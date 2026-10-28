#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
纯 Python 的 Keccak（原版 Keccak，非 NIST SHA-3）实现，支持 224/256/384/512。

FinalShell 的激活码用的是 **Keccak-384**（Qt 的 QCryptographicHash::Keccak_384），
注意这与 hashlib 的 sha3_384 不同：SHA-3 的域分隔符是 0x06，原版 Keccak 是 0x01。

自检向量（Keccak-384 空串）：
  2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b
  2dd2b21362337441ac12b515911957ff
"""

MASK = (1 << 64) - 1

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK


def keccak_f(A):
    """keccak-f[1600] 置换，A 是 5x5 的 64 位字列表"""
    for rnd in range(24):
        # theta
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        # rho + pi
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rol(A[x][y], ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
        # iota
        A[0][0] ^= RC[rnd]
    return A


def _keccak(data: bytes, bits: int) -> bytes:
    """bits ∈ {224,256,384,512}，输出 bits//8 字节"""
    rate = (1600 - 2 * bits) // 8            # 字节数
    A = [[0] * 5 for _ in range(5)]

    # 填充：原版 Keccak 用 0x01 域分隔符（SHA-3 是 0x06）
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] ^= 0x80

    # 吸收
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], 'little')
            A[i % 5][i // 5] ^= lane
        keccak_f(A)

    # 挤出
    out = bytearray()
    need = bits // 8
    while len(out) < need:
        for i in range(rate // 8):
            if len(out) >= need:
                break
            out += A[i % 5][i // 5].to_bytes(8, 'little')
        if len(out) < need:
            keccak_f(A)
    return bytes(out[:need])


def keccak_224(data: bytes) -> bytes: return _keccak(data, 224)
def keccak_256(data: bytes) -> bytes: return _keccak(data, 256)
def keccak_384(data: bytes) -> bytes: return _keccak(data, 384)
def keccak_512(data: bytes) -> bytes: return _keccak(data, 512)


if __name__ == '__main__':
    # 自检
    expect = ('2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b'
              '2dd2b21362337441ac12b515911957ff')
    got = keccak_384(b'').hex()
    print('Keccak-384("") =', got)
    print('SELF TEST     :', 'PASS' if got == expect else 'FAIL')
