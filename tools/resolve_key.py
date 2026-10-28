#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
resolve_key.py —— finalshell.jar Zelix KlassMaster「反射化混淆」key 解析器

原理（由 com.c 反汇编得出，详见 docs/zelix-key-resolver.md）：
  key 是 64 位 long，位段划分：
      index    = (key >>> 46)                     # slot in a[] / b[] (populated 0..9021)
      selector = (key >>> 42) & 0x3F              # seed selector, tableswitch 0..62
      seed     = SEED[selector]                   # 0..63, participates in decryption
      bits 0..41 = 6 groups of 7 bits             # per-character XOR offsets
  com.c.a(long) -> slot index, decrypting a[idx] into b[idx] on first use
  com.c.b(long) -> Class   (Class.forName, so it INITIALIZES the class)
  com.c.c(long) -> Field   (call site of a field key)
  com.c.d(long) -> Method  (call site of a method key)
  b[idx] plaintext: <declClassKey36>\x08<memberName>[\x08<typeKey36>...][\x08]
      field      : cls \x08 name \x08 type                 (2 separators)
      0-arg meth : cls \x08 name \x08 ret  \x08  (trailing) (3 separators)
      n-arg meth : cls \x08 name \x08 p0 \x08 ... \x08 ret \x08
  Each *Key36 segment is another key written in base36; com.c.b(long) turns it into a Class.

Paths are resolved relative to the repository (script lives in tools/), so nothing is
hard-coded to an absolute drive. Override anything with a flag or an env var:
  FINALSHELL_JAR   default jar
  FINALSHELL_COMC  default com_c_full.txt (only used by --com-c / --verify)

用法：
  python tools/resolve_key.py 184823010927613107 517287540690064504
  python tools/resolve_key.py --keys-file aW_keys_kind.txt
  python tools/resolve_key.py --offline 184823010927613107      # cache only, no JVM
  python tools/resolve_key.py --kind M 409729356224766465       # force method
  python tools/resolve_key.py --json
  python tools/resolve_key.py --jar finalshell.orig.jar 184823010927613107
  python tools/resolve_key.py --com-c com_c_full.txt            # verify shift/SEED table
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)                      # repo root when this file lives in tools/

# Relative candidates, tried in order. Nothing absolute is baked in.
JAR_CANDIDATES = (
    "finalshell.orig.jar",
    "finalshell.jar",
    os.path.join("run", "finalshell.jar"),
    os.path.join("finalshell", "finalshell.jar"),
)
COM_C_CANDIDATES = ("com_c_full.txt", os.path.join("dump", "com_c_full.txt"))

CACHE_NAME = "key_table.json"                     # cache lives at repo root
WORK = os.path.join(REPO, "_keytool")             # javac scratch dir (already git-ignored)
TIMEOUT = 20

# ---------------------------------------------------------------- Java side helper
JAVA_SRC = r'''
import java.io.File;
import java.io.PrintStream;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class KeyResolve {
    static Field fB; static Method mA; static URLClassLoader cl;

    static String q(String s){ if(s==null) return "null"; StringBuilder sb=new StringBuilder("\"");
        for(char ch: s.toCharArray()){ switch(ch){ case '"': sb.append("\\\""); break; case '\\': sb.append("\\\\"); break;
            default: if(ch<0x20) sb.append(String.format("\\u%04x",(int)ch)); else sb.append(ch);} }
        return sb.append('"').toString(); }
    static String tn(Class<?> c){ if(c==null) return "?"; if(c.isArray()) return tn(c.getComponentType())+"[]"; return c.getName(); }
    static Long b36(String s){ if(s==null||s.isEmpty()) return null; try{ return Long.parseLong(s,36);}catch(Throwable t){return null;} }
    static String dec(long key) throws Exception { int idx=(Integer)mA.invoke(null,key); String[] b=(String[])fB.get(null);
        return (idx>=0&&idx<b.length)? b[idx] : null; }
    static String norm(String s){ if(s==null) return null;
        int i=s.lastIndexOf('.'); String n=i<0?s:s.substring(i+1);
        switch(n){ case "Boolean": return "boolean"; case "Byte": return "byte"; case "Character": return "char";
            case "Short": return "short"; case "Integer": return "int"; case "Long": return "long";
            case "Float": return "float"; case "Double": return "double"; case "Void": return "void"; }
        return n; }
    static String simple(String s){ if(s==null) return "?"; if(s.endsWith("[]")) return simple(s.substring(0,s.length()-2))+"[]";
        int i=s.lastIndexOf('.'); return i<0?s:s.substring(i+1); }

    public static void main(String[] a) throws Exception {
        PrintStream out=new PrintStream(System.out,true,StandardCharsets.UTF_8);
        String mode=a[0];
        cl=new URLClassLoader(new URL[]{new File(a[1]).toURI().toURL()}, KeyResolve.class.getClassLoader());
        Class<?> cc=Class.forName("com.c",true,cl);
        fB=cc.getDeclaredField("b"); fB.setAccessible(true);
        mA=cc.getDeclaredMethod("a", long.class); mA.setAccessible(true);
        Method mC=cc.getDeclaredMethod("c", long.class); mC.setAccessible(true);
        Method mD=cc.getDeclaredMethod("d", long.class); mD.setAccessible(true);

        for(int i=2;i<a.length;i++){
            String spec=a[i]; char force=0;
            if(spec.length()>2 && (spec.charAt(0)=='F'||spec.charAt(0)=='M') && spec.charAt(1)==':'){ force=spec.charAt(0); spec=spec.substring(2); }
            long key=Long.parseLong(spec.trim().replaceAll("[lL]$",""));
            StringBuilder o=new StringBuilder("{");
            o.append("\"key\":").append(key);
            o.append(",\"keyHex\":\"").append(String.format("%016X",key)).append('"');
            o.append(",\"index\":").append(key>>>46);
            o.append(",\"selector\":").append((key>>>42)&63L);
            if("full".equals(mode)) full(o,key,force,mC,mD);
            else safe(o,key,force);
            o.append('}');
            out.println(o);
        }
    }

    // Real com.c.c / com.c.d: needs the declaring class initialized (GUI classes may hang)
    static void full(StringBuilder o,long key,char force,Method mC,Method mD){
        try{
            if(force!='M'){ try{ Field f=(Field)mC.invoke(null,key);
                if(f!=null){ o.append(",\"kind\":\"FIELD\",\"declaring\":").append(q(f.getDeclaringClass().getName()))
                    .append(",\"member\":").append(q(f.getName())).append(",\"descriptor\":").append(q(tn(f.getType())))
                    .append(",\"signature\":").append(q(f.getDeclaringClass().getName()+"."+f.getName()+" : "+tn(f.getType()))); return; } }catch(Throwable ignore){} }
            Method m=(Method)mD.invoke(null,key);
            StringBuilder d=new StringBuilder("("); StringBuilder s=new StringBuilder(m.getDeclaringClass().getName()+"."+m.getName()+"(");
            Class<?>[] ps=m.getParameterTypes();
            for(int j=0;j<ps.length;j++){ d.append(tn(ps[j])); if(j>0) s.append(", "); s.append(tn(ps[j])); }
            d.append(')').append(tn(m.getReturnType()));
            o.append(",\"kind\":\"METHOD\",\"declaring\":").append(q(m.getDeclaringClass().getName()))
             .append(",\"member\":").append(q(m.getName())).append(",\"descriptor\":").append(q(d.toString()))
             .append(",\"signature\":").append(q(s+") -> "+tn(m.getReturnType())));
        }catch(Throwable e){ Throwable r=e; while(r.getCause()!=null) r=r.getCause();
            o.append(",\"error\":").append(q(r.getClass().getName()+": "+r.getMessage())); }
    }

    // No class initialization: decrypt the string only, then Class.forName(...,false,...) + enumerate
    static void safe(StringBuilder o,long key,char force){
        try{
            String raw=dec(key);
            o.append(",\"raw\":").append(q(raw));
            String[] seg=raw.split("\u0008",-1); int n=seg.length; if(n>0&&seg[n-1].isEmpty()) n--;
            String declName=dec(b36(seg[0]));
            o.append(",\"declaring\":").append(q(declName)).append(",\"member\":").append(q(seg[1]));
            Class<?> decl=Class.forName(declName,false,cl);
            // Expected member types recovered from the ciphertext segments (scoring hint only)
            List<String> want=new ArrayList<>();
            for(int k=2;k<n;k++) want.add(norm(dec(b36(seg[k]))));
            List<String> hits=new ArrayList<>(); List<String> sigs=new ArrayList<>();
            List<Integer> scores=new ArrayList<>(); List<Character> kinds2=new ArrayList<>();
            for(Class<?> k=decl;k!=null;k=k.getSuperclass()){
                for(Field f: k.getDeclaredFields()) if(f.getName().equals(seg[1])) { hits.add("FIELD|"+simple(tn(f.getType())))
                    ; sigs.add(k.getName()+"."+f.getName()+" : "+tn(f.getType())); scores.add(0); kinds2.add('F'); }
                for(Method m: k.getDeclaredMethods()){
                    if(!m.getName().equals(seg[1])) continue;
                    if(m.getParameterTypes().length!=Math.max(0,n-3)) continue;
                    Class<?>[] ps=m.getParameterTypes();
                    int score=0;
                    for(int j=0;j<ps.length&&j<want.size();j++) if(want.get(j)!=null&&want.get(j).equals(simple(tn(ps[j])))) score++;
                    if(n-1<want.size()&&want.get(n-1)!=null&&want.get(n-1).equals(simple(tn(m.getReturnType())))) score++;
                    StringBuilder d=new StringBuilder("("); StringBuilder s=new StringBuilder(k.getName()+"."+m.getName()+"(");
                    for(int j=0;j<ps.length;j++){ d.append(tn(ps[j])); if(j>0) s.append(", "); s.append(tn(ps[j])); }
                    d.append(')').append(tn(m.getReturnType()));
                    hits.add("METHOD|"+score+"|"+d); sigs.add(s+") -> "+tn(m.getReturnType()));
                    scores.add(score); kinds2.add('M');
                }
            }
            o.append(",\"wantTypes\":").append(arr(want));
            o.append(",\"candidates\":").append(arr(hits));
            int best=-1;
            for(int i2=0;i2<sigs.size();i2++){
                if(force=='M' && kinds2.get(i2)!='M') continue;
                if(force=='F' && kinds2.get(i2)!='F') continue;
                if(best<0 || scores.get(i2)>scores.get(best)) best=i2;
            }
            if(best>=0){
                o.append(",\"kind\":").append(kinds2.get(best)=='M'? "\"METHOD\"":"\"FIELD\"");
                o.append(",\"signature\":").append(q(sigs.get(best)));
            }
        }catch(Throwable e){ Throwable r=e; while(r.getCause()!=null) r=r.getCause();
            o.append(",\"error\":").append(q(r.getClass().getName()+": "+r.getMessage())); }
    }

    static String arr(List<String> l){ StringBuilder sb=new StringBuilder("["); for(int i=0;i<l.size();i++){ if(i>0)sb.append(','); sb.append(q(l.get(i))); } return sb.append(']').toString(); }
}
'''


# ---------------------------------------------------------------- path helpers
def pick(candidates, env_key=None, base=REPO):
    """First existing path among base-relative candidates, then the env override."""
    for rel in candidates:
        p = rel if os.path.isabs(rel) else os.path.join(base, rel)
        if os.path.isfile(p):
            return p
    return os.environ.get(env_key) or None


def find_jar(explicit=None):
    if explicit:
        return explicit
    env = os.environ.get("FINALSHELL_JAR")
    if env:
        return env
    return pick(JAR_CANDIDATES) or os.path.join(REPO, "finalshell.orig.jar")


def find_com_c(explicit=None):
    if explicit:
        return explicit
    return os.environ.get("FINALSHELL_COMC") or pick(COM_C_CANDIDATES)


def java_bin(name):
    roots = [os.environ.get("JAVA_HOME", ""), r"C:\Program Files\Java\latest\jdk-17",
             r"C:\Program Files\Java\jdk-17", "/usr/lib/jvm/default-java"]
    for p in roots:
        if not p:
            continue
        cand = os.path.join(p, "bin", name + (".exe" if os.name == "nt" else ""))
        if os.path.isfile(cand):
            return cand
    return name  # fall back to PATH


# ---------------------------------------------------------------- com.c verification
def read_text(path):
    """javap output is UTF-16 when redirected by PowerShell, UTF-8 otherwise."""
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw.decode("utf-8-sig", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def probe_com_c(path):
    """Read a `javap -p -c com.c` dump and re-derive the shift widths and SEED table.

    Prints the recovered facts so the constants quoted in the docs can be re-checked
    without launching a JVM. Returns the SEED list (len 63) or None.
    """
    try:
        text = read_text(path)
    except OSError as e:
        print("[com.c] cannot read %s: %s" % (path, e), file=sys.stderr)
        return None

    # Restrict to a(long) so unrelated `bipush 42` elsewhere cannot pollute the count
    start = text.find("private static int a(long)")
    body = text[start:] if start >= 0 else text
    end = re.search(r"\n\s+(?:private|public) static [^\n]*\([^\n]*\);", body[len("private static int a(long)"):])
    if end:
        body = body[:len("private static int a(long)") + end.start()]

    facts = []
    for width in (46, 42):
        n = len(re.findall(r"bipush\s+%d\s+\d+:\s*lushr" % width, body))
        facts.append("key>>>%d x%d" % (width, n))
    facts.append("mask 63l %s" % ("ok" if re.search(r"ldc2_w[^\n]*long 63l", body) else "missing"))
    facts.append("mask 127l %s" % ("ok" if re.search(r"ldc2_w[^\n]*long 127l", body) else "missing"))
    facts.append("6 groups %s" % ("ok" if re.search(r"bipush\s+6\s+\d+:\s*newarray\s+int", body) else "missing"))

    m = re.search(r"tableswitch\s*\{\s*//\s*0 to (\d+)", body)
    n = int(m.group(1)) + 1 if m else 0
    facts.append("tableswitch 0..%d" % (n - 1) if n else "tableswitch NOT FOUND")

    seeds = []
    if n:
        table = re.findall(r"^\s*(\d+):\s*(\d+)\s*$", body, re.M)[:n]
        if len(table) == n:
            by_off = {}
            for ln in body.splitlines():
                g = re.match(r"^\s*(\d+):\s+(bipush\s+(-?\d+)|iconst_m1|iconst_(\d))", ln.strip())
                if g:
                    off = int(g.group(1))
                    if g.group(3) is not None:
                        by_off[off] = int(g.group(3))
                    elif g.group(4) is not None:
                        by_off[off] = int(g.group(4))
                    else:
                        by_off[off] = -1
            for _, tgt in table:
                if int(tgt) in by_off:
                    seeds.append(by_off[int(tgt)])
    if len(seeds) == n and n:
        facts.append("SEED[0..%d] = %s" % (n - 1, " ".join(str(s) for s in seeds)))
    else:
        facts.append("SEED recovered %d/%d" % (len(seeds), n))
    print("[com.c] " + " | ".join(facts), file=sys.stderr)
    return seeds or None


def ensure_built():
    os.makedirs(WORK, exist_ok=True)
    src = os.path.join(WORK, "KeyResolve.java")
    cls = os.path.join(WORK, "KeyResolve.class")
    old = open(src, encoding="utf-8").read() if os.path.isfile(src) else ""
    if old != JAVA_SRC:                       # always refresh from the embedded source
        with open(src, "w", encoding="utf-8") as f:
            f.write(JAVA_SRC)
    if not os.path.isfile(cls) or os.path.getmtime(src) > os.path.getmtime(cls):
        r = subprocess.run([java_bin("javac"), "-encoding", "UTF-8", "-d", WORK, src],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("javac failed:\n" + r.stdout + r.stderr)


def run_java(jar, mode, keys):
    """keys: ['F:123', 'M:456'] -> list of parsed dicts, or None on timeout/failure."""
    ensure_built()
    cp = WORK + os.pathsep + jar
    try:
        r = subprocess.run([java_bin("java"), "-cp", cp, "KeyResolve", mode, jar] + keys,
                           capture_output=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    out = r.stdout.decode("utf-8", "replace").strip()
    res = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                res.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return res or None


def full_ok(rec):
    return bool(rec) and "error" not in rec and bool(rec.get("signature")) and rec.get("mode") != "safe(no-init)"


def resolve(keys, jar, kinds, cache_path, offline, verbose):
    cache = {}
    if os.path.isfile(cache_path):
        try:
            cache = json.load(open(cache_path, encoding="utf-8"))
        except Exception:
            cache = {}
    rows = []
    todo = []
    for k in keys:
        rec = cache.get(str(k))
        if rec and full_ok(rec):
            rows.append(rec)
        elif offline:
            rows.append(rec or {"key": int(k), "error": "cache miss (--offline)"})
        else:
            todo.append(k)
    if todo:
        # One JVM per key: whichever class blocks in <clinit> only costs its own 20 s.
        for k in todo:
            spec = (kinds.get(str(k), "") + ":" if kinds.get(str(k)) else "") + str(k)
            got = run_java(jar, "full", [spec])
            if got and full_ok(got[0]):
                rec = got[0]
            else:
                rec = (got[0] if got else {"key": int(k), "error": "full mode timed out"})
                # Fall back to the no-init mode
                safe_spec = (kinds.get(str(k)) + ":" if kinds.get(str(k)) else "") + str(k)
                got2 = run_java(jar, "safe", [safe_spec])
                if got2:
                    rec.update({k2: v for k2, v in got2[0].items() if v is not None})
                    rec["mode"] = "safe(no-init)"
                else:
                    rec["mode"] = "full"
            rec.setdefault("mode", "full")
            rows.append(rec)
            cache[str(k)] = rec
            if verbose:
                print("  -", k, rec.get("signature") or rec.get("error"), file=sys.stderr)
        try:
            json.dump(cache, open(cache_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        except Exception:
            pass
    return rows


def main():
    ap = argparse.ArgumentParser(description="Resolve Zelix KlassMaster reflection-obfuscated long keys")
    ap.add_argument("keys", nargs="*", help="keys (decimal long, optional L suffix; F:123 / M:456 forces kind)")
    ap.add_argument("--keys-file", help="read keys from a file (whitespace or comma separated)")
    ap.add_argument("--jar", help="finalshell jar (default: auto-detect next to the repo)")
    ap.add_argument("--cache", default=os.path.join(REPO, CACHE_NAME), help="key_table.json cache path")
    ap.add_argument("--offline", action="store_true", help="cache only, never start a JVM")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--kind", choices=["F", "M"], help="force every key to field (F) or method (M)")
    ap.add_argument("--com-c", dest="com_c", help="com_c_full.txt, verify shift widths / SEED table")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.com_c or (args.verbose and not args.keys and not args.keys_file):
        probe_com_c(find_com_c(args.com_c) or args.com_c or "com_c_full.txt")

    raw_keys = list(args.keys)
    if args.keys_file:
        txt = open(args.keys_file, encoding="utf-8").read()
        raw_keys += [x for x in re.split(r"[\s,]+", txt) if x]
    if not raw_keys:
        ap.error("need at least one key (--keys-file or positional)")

    kinds, keys = {}, []
    for s in raw_keys:
        s = s.strip()
        if re.match(r"^[FM]:", s):
            kinds[s[2:].strip().rstrip("lL")] = s[0]
            keys.append(s[2:].strip().rstrip("lL"))
        else:
            keys.append(s.rstrip("lL"))
            if args.kind:
                kinds[s.rstrip("lL")] = args.kind

    jar = find_jar(args.jar)
    if not os.path.isfile(jar):
        sys.exit("jar not found: %s\n  pass --jar PATH or set FINALSHELL_JAR" % jar)
    if args.verbose:
        print("[paths] jar=%s cache=%s" % (jar, args.cache), file=sys.stderr)

    rows = resolve(keys, jar, kinds, args.cache, args.offline, args.verbose)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=1))
        return

    print("%-20s %-16s %3s %5s %-7s %s" % ("key", "hex", "sel", "idx", "kind", "class.member / descriptor"))
    print("-" * 118)
    for r in rows:
        k = r.get("key")
        hexs = r.get("keyHex") or ("%016X" % (int(k) & 0xFFFFFFFFFFFFFFFF))
        sig = r.get("signature") or r.get("error") or "?"
        kind = r.get("kind", "?")
        if r.get("mode") == "safe(no-init)":
            cands = r.get("candidates") or []
            if len(cands) > 1:
                sig += "   [%d overload candidates: %s]" % (len(cands), "; ".join(cands))
            kind = kind if kind != "?" else (cands[0].split("|")[0] if cands else "?")
        print("%-20s %-16s %3s %5s %-7s %s" % (k, hexs, r.get("selector", "?"), r.get("index", "?"), kind, sig))
    print("\nNote: a field key goes through c(long), a method key through d(long);"
          " the call site decides. Use --kind F|M when unsure.")


if __name__ == "__main__":
    main()
