#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""交叉校验 keygen.py 的 Keccak 海绵结构：把填充字节换成 0x06 应得到标准 SHA3-384，
与 hashlib.sha3_384 对比（独立实现互校）。"""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keygen

def sponge(data, pad, outlen=48, rate=keygen.RATE):
    A = [[0] * 5 for _ in range(5)]
    m = bytearray(data); m.append(pad)
    while len(m) % rate: m.append(0)
    m[-1] ^= 0x80
    for off in range(0, len(m), rate):
        blk = m[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            A[x][y] ^= int.from_bytes(blk[i*8:i*8+8], 'little')
        A = keygen.keccak_f(A)
    out = bytearray()
    for i in range((outlen + 7) // 8):
        x, y = i % 5, i // 5
        out += A[x][y].to_bytes(8, 'little')
    return bytes(out[:outlen])

ok = True
for n in [0, 1, 3, 55, 103, 104, 105, 200, 1000]:
    d = bytes((i * 37 + n) & 0xFF for i in range(n))
    a = sponge(d, 0x06).hex()
    b = hashlib.sha3_384(d).hexdigest()
    same = a == b
    ok &= same
    print(('OK  ' if same else 'FAIL') + f'  len={n:4d}  sha3_384 match')
print('---')
print('Keccak-384("") =', keygen.keccak384(b'').hex())
print('Keccak-384("abc") =', keygen.keccak384(b'abc').hex())
print('SHA3-384("") =', hashlib.sha3_384(b'').hexdigest(), '(对照：填充不同, 结果必须不同)')
print('sponge 结构与 hashlib 全部一致:', ok)
