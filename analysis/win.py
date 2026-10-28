#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 disasm.txt 抽取某个地址区间。用法: python win.py <start_hex> <end_hex> [file]"""
import re, sys
start = int(sys.argv[1], 16); end = int(sys.argv[2], 16)
fn = sys.argv[3] if len(sys.argv) > 3 else 'disasm.txt'
for ln in open(fn, encoding='latin1'):
    m = re.match(r'^\s*([0-9a-f]+):', ln)
    if m:
        a = int(m.group(1), 16)
        if start <= a <= end:
            sys.stdout.write(ln)
