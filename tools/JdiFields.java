import com.sun.jdi.*;
import com.sun.jdi.connect.*;

import java.util.*;

/**
 * 读取指定类所有 static 字段的当前值。
 *
 * 用途：dD 类的 static 字段一一对应 config.json 的顶层字段，
 * 把它们的值 dump 出来，即可确定 `huw` 落在哪个字段上。
 *
 * 用法：
 *   java -cp . JdiFields 127.0.0.1 5005 dD
 */
public class JdiFields {

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        String port = args.length > 1 ? args[1] : "5005";
        String cls = args.length > 2 ? args[2] : "dD";

        AttachingConnector conn = null;
        for (AttachingConnector c : Bootstrap.virtualMachineManager().attachingConnectors()) {
            if ("com.sun.jdi.SocketAttach".equals(c.name())) { conn = c; break; }
        }
        Map<String, Connector.Argument> a = conn.defaultArguments();
        a.get("hostname").setValue(host);
        a.get("port").setValue(port);
        System.out.println("[*] attaching " + host + ":" + port);
        VirtualMachine vm = conn.attach(a);
        System.out.println("[+] attached: " + vm.name());

        List<ReferenceType> types = vm.classesByName(cls);
        if (types.isEmpty()) {
            System.out.println("[!] class not loaded: " + cls);
            return;
        }

        for (ReferenceType rt : types) {
            System.out.println("=== " + rt.name() + " ===");
            for (Field f : rt.fields()) {
                if (!f.isStatic()) continue;
                String val;
                try {
                    Value v = rt.getValue(f);
                    val = describe(v);
                } catch (Throwable t) {
                    val = "<unreadable: " + t.getClass().getSimpleName() + ">";
                }
                System.out.println(String.format("  %-6s %-12s = %s",
                        f.name(), shortType(f.typeName()), val));
            }
        }
        try { vm.dispose(); } catch (Throwable ignored) { }
    }

    static String shortType(String t) {
        if (t == null) return "?";
        int i = t.lastIndexOf('.');
        return i >= 0 ? t.substring(i + 1) : t;
    }

    static String describe(Value v) {
        if (v == null) return "null";
        if (v instanceof StringReference) {
            String s = ((StringReference) v).value();
            if (s != null && s.length() > 160) s = s.substring(0, 160) + "…(" + s.length() + " chars)";
            return "\"" + s + "\"";
        }
        if (v instanceof ArrayReference) {
            ArrayReference ar = (ArrayReference) v;
            int n = ar.length();
            StringBuilder sb = new StringBuilder("array[" + n + "]");
            if (n <= 64) {
                try {
                    List<Value> vals = ar.getValues();
                    sb.append(" {");
                    boolean first = true;
                    for (Value x : vals) {
                        if (!first) sb.append(", ");
                        first = false;
                        if (x instanceof StringReference) {
                            sb.append(((StringReference) x).value());
                        } else {
                            sb.append(String.valueOf(x));
                        }
                    }
                    sb.append("}");
                } catch (Throwable t) {
                    sb.append(" <unreadable>");
                }
            }
            return sb.toString();
        }
        if (v instanceof ObjectReference && !(v instanceof StringReference)) {
            return v.type().name() + "@" + Long.toHexString(((ObjectReference) v).uniqueID());
        }
        return String.valueOf(v);
    }
}
