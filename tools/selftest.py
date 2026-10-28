#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest.py —— jar_patcher.py 自测：找 jar 内无害的 static boolean() 方法，
替换为 iconst_1;ireturn，再用 javap -c 验证。"""
import os, re, struct, subprocess, sys, zipfile, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jar_patcher as jp

JAR = 'finalshell.orig.jar'
OUT = 'out/finalshell.selftest.jar'
JAVAP = (os.environ.get('JAVAP')
         or (os.path.join(os.environ['JAVA_HOME'], 'bin', 'javap.exe')
             if os.environ.get('JAVA_HOME') else 'javap'))
ACC_STATIC, ACC_ABSTRACT, ACC_NATIVE = 0x0008, 0x0400, 0x0100


def find_candidates(jar, limit=4000):
    hits = []
    with zipfile.ZipFile(jar) as z:
        for it in z.infolist():
            if not it.filename.endswith('.class') or it.filename.startswith('META-INF/'):
                continue
            limit -= 1
            if limit < 0:
                break
            try:
                cf = jp.ClassFile.load(z.read(it.filename))
            except Exception:
                continue
            for m in cf.methods:
                try:
                    nm, ds = cf.cp.utf8(m.name_idx), cf.cp.utf8(m.desc_idx)
                except Exception:
                    continue
                if ds != '()Z' or not (m.access & ACC_STATIC):
                    continue
                if m.access & (ACC_ABSTRACT | ACC_NATIVE):
                    continue
                if any(cf.cp.entries[a['name'] - 1]['data'] == b'Code' for a in m.attrs):
                    hits.append((it.filename[:-6], nm, ds))
    return hits


def javap_code(jar, cls, method):
    r = subprocess.run([JAVAP, '-c', '-p', '-cp', jar, cls.replace('/', '.')],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    txt = r.stdout
    # 抓取该方法段落
    pat = re.compile(r'\n  [^\n]*' + re.escape(method) + r'\(\);(.*?)(?=\n  [^\n]*\(|\n\}\s*$)', re.S)
    m = pat.search(txt + '\n}')
    return (m.group(0) if m else txt), r.returncode


def main():
    cands = find_candidates(JAR)
    if not cands:
        print('未找到候选'); return 1
    # 优先挑名字像工具判定的（is*/has*/can*），且类名短的
    def score(c):
        cls, nm, ds = c
        return (0 if re.match(r'^(is|has|can|should|check)', nm) else 1, len(cls), cls)
    cls, nm, ds = sorted(cands, key=score)[0]
    print('候选总数 %d，选用: %s.%s%s' % (len(cands), cls, nm, ds))

    # 1) 先看原始字节码
    before, _ = javap_code(JAR, cls, nm)
    print('---- 原始 ----'); print(before.strip()[:400])

    # 2) 打补丁
    info = jp.patch_jar(JAR, OUT, cls, nm, ds, 'true')
    print('---- 补丁信息 ----')
    print(' 方法 %s: 原 %d 字节 (%s) -> 新 %d 字节 (%s), max_stack %d->%d'
          % (info['method'], info['old_code_len'], info['old_code_hex'],
             info['new_code_len'], info['new_code_hex'],
             info['old_max_stack'], info['new_max_stack']))

    # 3) javap 验证
    after, rc = javap_code(OUT, cls, nm)
    print('---- 修补后 ----'); print(after.strip()[:400])
    ok = ('iconst_1' in after and 'ireturn' in after and rc == 0)
    # 4) 结构自校验：重新解析新 class，确认方法仍在、jar 可读
    with zipfile.ZipFile(OUT) as z:
        bad = z.testzip()
        cf = jp.ClassFile.load(z.read(info['entry']))
        m = cf.method_by(nm, ds)
        cdat = cf.code_attr(m)['data']
        code = cdat[8:8 + struct.unpack_from('>I', cdat, 4)[0]]
    print('zip 完整性: %s; 重解析 code=%s' % ('OK' if bad is None else bad, code.hex()))
    ok = ok and code == b'\x04\xac' and bad is None
    # 5) 其它类未被改动
    with zipfile.ZipFile(JAR) as a, zipfile.ZipFile(OUT) as b:
        diff = [n for n in a.namelist() if n in b.namelist() and a.read(n) != b.read(n)]
    print('变更条目: %s' % diff)
    ok = ok and diff == [info['entry']]
    json.dump({'class': cls, 'method': nm + ds, 'info': info, 'ok': ok},
              open('out/selftest.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print('[SELFTEST] %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
