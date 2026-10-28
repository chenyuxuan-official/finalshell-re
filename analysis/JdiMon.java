import com.sun.jdi.*;
import com.sun.jdi.connect.*;
import com.sun.jdi.event.*;
import com.sun.jdi.request.*;

import java.util.*;

/**
 * 通过 JDWP 挂到正在运行的 FinalShell，给 javax.swing.JOptionPane 下方法断点，
 * 一旦弹出任何提示框（比如"激活码无效"），立即打印当前线程的调用栈，
 * 从而直接把「谁在校验激活码」这个调用点找出来。
 */
public class JdiMon {

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        String port = args.length > 1 ? args[1] : "5005";
        String filter = args.length > 2 ? args[2] : "javax.swing.JOptionPane";

        AttachingConnector conn = null;
        for (AttachingConnector c : Bootstrap.virtualMachineManager().attachingConnectors()) {
            if ("com.sun.jdi.SocketAttach".equals(c.name())) { conn = c; break; }
        }
        Map<String, Connector.Argument> a = conn.defaultArguments();
        a.get("hostname").setValue(host);
        a.get("port").setValue(port);
        System.out.println("[*] attaching to " + host + ":" + port);
        VirtualMachine vm = conn.attach(a);
        System.out.println("[+] attached, vm=" + vm.name());

        EventRequestManager erm = vm.eventRequestManager();
        for (String one : filter.split(",")) {
            one = one.trim();
            if (one.isEmpty()) continue;
            MethodEntryRequest mer = erm.createMethodEntryRequest();
            mer.addClassFilter(one);
            mer.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
            mer.enable();
            System.out.println("[*] breakpoint on " + one);
        }

        EventQueue q = vm.eventQueue();
        System.out.println("[*] waiting for JOptionPane calls...");

        while (true) {
            EventSet es;
            try {
                es = q.remove();
            } catch (InterruptedException ie) {
                break;
            }
            boolean resume = true;
            for (Event e : es) {
                if (e instanceof MethodEntryEvent) {
                    MethodEntryEvent me = (MethodEntryEvent) e;
                    ThreadReference th = me.thread();
                    System.out.println("\n===== HIT " + me.method().declaringType().name()
                            + "." + me.method().name() + " =====");
                    for (int i = 0; i < th.frameCount() && i < 40; i++) {
                        StackFrame f = th.frame(i);
                        Location loc = f.location();
                        System.out.println("   #" + i + " "
                                + loc.declaringType().name() + "." + loc.method().name()
                                + "  (line " + loc.lineNumber() + ")");
                    }
                    System.out.println("===== END =====");
                    System.out.flush();
                }
            }
            if (resume) es.resume();
        }
    }
}
