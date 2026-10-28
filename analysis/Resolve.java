import java.lang.reflect.*;

/**
 * 用 com.c 自身的反射解析器把 Zelix 的 64 位 key 还原成真实成员。
 * com.c 的静态表在 <clinit> 里初始化，因此可以在独立 JVM 里离线解析，不需要跑整个程序。
 */
public class Resolve {
    public static void main(String[] a) throws Exception {
        Class<?> c = Class.forName("com.c");
        Method fieldM = c.getDeclaredMethod("c", long.class);
        Method methodM = c.getDeclaredMethod("d", long.class);
        fieldM.setAccessible(true);
        methodM.setAccessible(true);

        for (String s : a) {
            long key;
            try { key = Long.parseLong(s.trim()); } catch (Exception e) { continue; }
            String f = null, m = null;
            try {
                Object r = fieldM.invoke(null, key);
                if (r != null) f = r.toString();
            } catch (Throwable t) { f = "ERR:" + t.getClass().getSimpleName(); }
            try {
                Object r = methodM.invoke(null, key);
                if (r != null) m = r.toString();
            } catch (Throwable t) { m = "ERR:" + t.getClass().getSimpleName(); }
            System.out.println(key + "\n   FIELD : " + f + "\n   METHOD: " + m);
        }
    }
}
