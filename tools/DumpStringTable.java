import java.io.*;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;

/**
 * DumpStringTable —— 把目标类里 Zelix 生成的静态常量表（String[] / long[] / int[]）
 * 导成 JSON，供纯 Python 的离线解密工具使用。
 *
 * 背景：FinalShell 的密文块表是 private static String[] f，由 &lt;clinit&gt; 里一段
 * 变长切片逻辑从常量池的大串切出来；只在运行期才存在。用反射把 f 原样取出，
 * 之后 python 侧就能完全离线复算解密（不需要再起 JVM）。
 *
 * 用法：
 *   javac -encoding UTF-8 -d out tools/DumpStringTable.java
 *   java -cp "out;finalshell.orig.jar" DumpStringTable finalshell.orig.jar Lk f [i]
 *
 *   参数：<jar> <类名，点分> [要导出的静态字段名 ...]（省略则导出所有数组型静态字段）
 * 输出：JSON（UTF-8，字符串按 U+XXXX 转义，二进制安全）
 *
 * 注意：会触发目标类的 &lt;clinit&gt;（这正是我们要的），只读，不写任何文件。
 */
public class DumpStringTable {

    static StringBuilder sb = new StringBuilder();

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: java DumpStringTable <jar> <className> [field ...]");
            System.exit(2);
        }
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8");
        URLClassLoader cl = new URLClassLoader(
                new URL[]{new File(args[0]).toURI().toURL()},
                DumpStringTable.class.getClassLoader());
        Class<?> c = Class.forName(args[1], true, cl);
        List<String> want = new ArrayList<String>();
        for (int i = 2; i < args.length; i++) want.add(args[i]);

        out.println("{");
        out.println("  \"jar\": " + q(new File(args[0]).getName()) + ",");
        out.println("  \"class\": " + q(c.getName()) + ",");
        out.println("  \"fields\": {");

        boolean firstField = true;
        for (Field f : c.getDeclaredFields()) {
            if (!Modifier.isStatic(f.getModifiers())) continue;
            if (!want.isEmpty() && !want.contains(f.getName())) continue;
            Class<?> t = f.getType();
            if (!t.isArray() || t.getComponentType() == null) continue;
            f.setAccessible(true);
            Object v;
            try {
                v = f.get(null);
            } catch (Throwable e) {
                continue;
            }
            if (v == null) continue;
            int n = Array.getLength(v);
            if (n == 0) continue;

            if (!firstField) out.println(",");
            firstField = false;
            out.println("    " + q(f.getName()) + ": {");
            out.println("      \"type\": " + q(t.getComponentType().getName()) + ",");
            out.println("      \"length\": " + n + ",");
            out.print("      \"values\": [");
            for (int i = 0; i < n; i++) {
                if (i > 0) out.print(",");
                if (i % 8 == 0) out.print("\n        ");
                Object e = Array.get(v, i);
                if (e == null) out.print("null");
                else if (e instanceof String) out.print(q((String) e));
                else if (e instanceof Long || e instanceof Integer || e instanceof Short
                        || e instanceof Byte) out.print(String.valueOf(e));
                else if (e instanceof Character) out.print((int) ((Character) e).charValue());
                else out.print(q(String.valueOf(e)));
            }
            out.print("\n      ]\n    }");
        }
        out.println();
        out.println("  }");
        out.println("}");
    }

    /** JSON 字符串转义（非 ASCII 一律 U+XXXX，保证控制字符与代理对都能安全往返） */
    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n");  break;
                case '\r': b.append("\\r");  break;
                case '\t': b.append("\\t");  break;
                default:
                    if (ch < 0x20 || ch > 0x7e) b.append(String.format("\\u%04x", (int) ch));
                    else b.append(ch);
            }
        }
        return b.append('"').toString();
    }
}
