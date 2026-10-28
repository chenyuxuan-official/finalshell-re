import com.sun.jdi.*;
import com.sun.jdi.connect.*;
import com.sun.jdi.event.*;
import com.sun.jdi.request.*;

import java.util.*;

/**
 * JDI 参数观察器（断点版）。
 *
 * 在目标方法**入口字节码**下断点，命中时打印全部实参，然后恢复线程。
 * 用 BreakpointRequest 而不是 MethodEntryRequest —— 后者只能按类过滤，
 * 会让该类的每一次调用都暂停一次，高频类（如 lr.C）会把 EDT 拖死。
 *
 * 用法：
 *   java -cp . JdiWatch 127.0.0.1 5005 <className> <method1[,method2]> [maxHits]
 * 例：
 *   java -cp . JdiWatch 127.0.0.1 5005 lr u 100
 */
public class JdiWatch {

    static final int MAX_BYTES = 4096;

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        String port = args.length > 1 ? args[1] : "5005";
        String cls = args.length > 2 ? args[2] : "lr";
        String methods = args.length > 3 ? args[3] : "u";
        int maxHits = args.length > 4 ? Integer.parseInt(args[4]) : 100;

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
            System.out.println("[!] class not loaded yet: " + cls);
            waitForClass(vm, cls);
            types = vm.classesByName(cls);
        }
        if (types.isEmpty()) { System.out.println("[!] still not found, abort"); return; }

        EventRequestManager erm = vm.eventRequestManager();
        Set<String> want = new HashSet<>();
        for (String m : methods.split(",")) { m = m.trim(); if (!m.isEmpty()) want.add(m); }

        int set = 0;
        for (ReferenceType rt : types) {
            for (Method m : rt.methods()) {
                if (!want.contains(m.name())) continue;
                if (!m.isStatic() && !m.isAbstract()) { /* instance ok */ }
                Location loc;
                try {
                    loc = m.location();
                } catch (Throwable t) {
                    continue;
                }
                if (loc == null || loc.codeIndex() < 0) continue;
                BreakpointRequest br = erm.createBreakpointRequest(loc);
                br.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                br.enable();
                System.out.println("[*] bp " + rt.name() + "." + m.name() + m.signature()
                        + "  @line " + loc.lineNumber());
                set++;
            }
        }
        if (set == 0) { System.out.println("[!] no breakpoint set"); return; }
        System.out.println("[*] " + set + " breakpoint(s) armed, waiting...");

        EventQueue q = vm.eventQueue();
        int hits = 0;
        while (hits < maxHits) {
            EventSet es = q.remove();
            for (Event e : es) {
                if (!(e instanceof BreakpointEvent)) continue;
                BreakpointEvent be = (BreakpointEvent) e;
                hits++;
                System.out.println("\n===== HIT #" + hits + " "
                        + be.location().declaringType().name() + "."
                        + be.location().method().name()
                        + " (line " + be.location().lineNumber() + ") =====");
                try {
                    ThreadReference th = be.thread();
                    StackFrame fr = th.frame(0);
                    List<Value> vals = fr.getArgumentValues();
                    int i = 0;
                    for (Value v : vals) {
                        System.out.println("  arg[" + i + "] " + describe(v));
                        i++;
                    }
                    for (int k = 1; k < Math.min(4, th.frameCount()); k++) {
                        Location l = th.frame(k).location();
                        System.out.println("  <- " + l.declaringType().name() + "."
                                + l.method().name() + " (line " + l.lineNumber() + ")");
                    }
                } catch (Exception ex) {
                    System.out.println("  [!] " + ex);
                }
                System.out.flush();
            }
            es.resume();
        }
        System.out.println("[*] maxHits reached, detaching");
        try { vm.dispose(); } catch (Throwable ignored) { }
    }

    static void waitForClass(VirtualMachine vm, String cls) throws Exception {
        EventRequestManager erm = vm.eventRequestManager();
        ClassPrepareRequest cpr = erm.createClassPrepareRequest();
        cpr.addClassFilter(cls);
        cpr.enable();
        EventQueue q = vm.eventQueue();
        long deadline = System.currentTimeMillis() + 20000;
        while (System.currentTimeMillis() < deadline) {
            EventSet es = q.remove(1000);
            if (es == null) continue;
            es.resume();
            for (Event e : es) {
                if (e instanceof ClassPrepareEvent) return;
            }
        }
    }

    static String describe(Value v) {
        if (v == null) return "null";
        if (v instanceof ArrayReference) {
            ArrayReference ar = (ArrayReference) v;
            if (ar.length() > MAX_BYTES) return "array[" + ar.length() + "] (too long)";
            try {
                List<Value> vals = ar.getValues();
                if (!vals.isEmpty() && vals.get(0) instanceof ByteValue) {
                    StringBuilder hex = new StringBuilder();
                    StringBuilder asc = new StringBuilder();
                    for (Value x : vals) {
                        byte b = ((ByteValue) x).byteValue();
                        hex.append(String.format("%02x", b));
                        asc.append(b >= 32 && b < 127 ? (char) b : '.');
                    }
                    return "byte[" + ar.length() + "]\n           hex  =" + hex + "\n           ascii=" + asc;
                }
                return "array[" + ar.length() + "] " + vals;
            } catch (Throwable t) {
                return "array[" + ar.length() + "] <unreadable>";
            }
        }
        if (v instanceof StringReference) return "String = " + ((StringReference) v).value();
        return v.type().name() + " = " + v;
    }
}
