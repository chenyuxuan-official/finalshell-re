> 本章为原始分析报告（源文件：`key_resolve_report.md`，保留在仓库根目录以供其它流程引用）。

# finalshell.jar · Zelix KlassMaster「反射化混淆」key 解析报告

- 目标：`<FINALSHELL_HOME>\finalshell.jar`（只读，未修改）
- 环境：JDK 17（`%JAVA_HOME%\bin`）、Python 3.13
- 产物：`com_c_full.txt`（`javap -p -c com.c`，5.1 MB）、`resolve_key.py`、`key_table.json`（缓存）、本报告

---

## 1. 一句话结论

key 是 **纯数据坐标**，不含任何依赖运行期才生成的随机量：`index = key >>> 46`、`selector = (key >>> 42) & 63`，
密文表 `com.c.a[]` 与明文缓存 `com.c.b[]` 在 `<clinit>` 里就被完整构造（9022 槽），因此
**任何 key 都能在「只加载 com.c、不初始化目标类」的前提下算出「类.成员名.描述符」**。
`resolve_key.py` 已实现该解析（真反射模式 + 不初始化类的兜底模式），并用 `aW` 的 21 个 key 完成验证。

---

## 2. `com.c` 的结构（`javap -p -s com.c`）

```java
public class com.c {
  private static final Object[] a;      // 槽位主表：密文 String 字面量 / 预置 Class / 解析后的 Field|Method 缓存
  private static final String[] b;      // 明文缓存：a[idx] 解密后的字符串（也是 Class 名缓存）
  private static final String[] c;      // <clinit> 中间数组
  private static final String[] d;      // <clinit> 中间数组

  private static int    a(long);                                   // key -> 槽号 idx（并触发解密）
  private static void   a(); b(); c(); d(); e();                    // <clinit> 调用：批量填充 a[]/b[]
  private static Class  b(long);                                   // 类 key -> Class
  private static Field  a(Class,String,Class);                      // getDeclaredFields 精确匹配 名+类型
  private static Field  b(Class,String,Class);                      // 同上，递归走接口
  public  static Field  c(long);                                   // 字段 key -> Field
  private static Method a(Class,String,Class,int,Class[]);          // getDeclaredMethods 精确匹配
  private static Method b(Class,String,Class,int,Class[]);
  public  static Method d(long);                                   // 方法 key -> Method
  private static String b(int, int);                                // 字面量解密器（<clinit> 内部专用）
}
```

`<clinit>` 先 `new String[9022]`（即 `b` 的容量）再逐块构造；`a()`…`e()` 五个方法把 9022 个
**加密字面量**按 `aastore` 写进 `a[]`，遇到原始类型则直接放 `Void.TYPE` / `Integer.TYPE` 之类
**Class 对象**（这就是 `boolean`/`void` 这类槽“不需要解密”的原因）。所以：

- `a[]`：槽 → 密文 `String`（待解密）、或 `Class`（原始类型/已解析类）、或已解析的 `Field`/`Method`
- `b[]`：槽 → 明文（解密后的 `"类key\x08成员名\x08类型key…"`，或类名）

---

## 3. key 的位段布局

```
 63                48 47 46 45        42 41                        0
 +------------------+--+--+------------+---------------------------+
 |   index (18 bit)    |sel(6bit)|        6 × 7 bit 解密偏移        |
 +---------------------+---------+--------------------------------+
 index   = key >>> 46                (0..9021，实际表长 9022)
 selector= (key >>> 42) & 0x3F        (0..62 → 查表得 seed；其它 → 1)
 seed    = SEED[selector]
```

`private static int a(long)` 的还原：

```java
int a(long key) {
    int idx = (int)(key >>> 46);
    if (b[idx] != null) return idx;                    // 已解密
    Object v = a[idx];
    if (!(v instanceof String)) return idx;            // 已是 Class / 已缓存的 Field|Method
    int seed = SEED[(int)((key >>> 42) & 63)];
    int[] m = new int[6];
    for (int i = 0; i < 6; i++) {                      // 每 7 位一组，减 seed、负数 +128
        int x = (int)((key >>> (7 * (5 - i))) & 127) - seed;
        if (x < 0) x += 128;
        m[i] = x;
    }
    char[] cs = ((String) v).toCharArray();
    for (int i = 0; i < cs.length; i++) {
        int t = m[i % 6];
        if (t == 0) break;
        cs[i] = (char)(cs[i] ^ t);
    }
    b[idx] = new String(cs);                           // 写回明文缓存
    return idx;
}
```

`SEED[selector]`（由 `tableswitch` 反汇编得到，default → 1）：

```
0:33 1:50 2:10 3:28 4:0  5:54 6:44 7:22 8:34 9:45 10:29 11:60 12:21 13:14 14:20 15:16
16:56 17:4 18:2 19:18 20:53 21:26 22:7 23:48 24:17 25:31 26:6 27:59 28:32 29:39 30:41 31:51
32:25 33:42 34:11 35:38 36:49 37:12 38:24 39:62 40:35 41:63 42:15 43:5 44:3 45:19 46:52 47:36
48:27 49:37 50:47 51:57 52:46 53:40 54:23 55:61 56:30 57:9 58:13 59:55 60:43 61:8 62:58
```

---

## 4. 明文格式（`b[idx]`）

分隔符是 **字符 `\u0008`（Backspace）**，各段是另一枚 key 的 **base36** 文本；`com.c.b(long)`
负责把「类 key」换成 `Class`（`instanceof String ? Class.forName(...) : (Class) a[idx]`）。

| 成员 | 明文布局 |
|---|---|
| 字段 | `declClassKey36 \x08 name \x08 typeKey36` |
| 方法 | `declClassKey36 \x08 name \x08 p0Key36 \x08 … \x08 retKey36`（0 参时 = 3 段，**与字段同形**，所以段数不能判断种类） |

`c(long)` 还原：

```java
Field c(long key) {
    int idx = a(key); Object v = a[idx];
    if (!(v instanceof String)) return (Field) v;      // 命中 a[] 缓存
    String s = b[idx];
    int p = s.indexOf(8);  Class decl = b(Long.parseLong(s.substring(0,p), 36));
    p++; int q = s.indexOf(8, p); String name = s.substring(p, q);
    q++; Class type = b(Long.parseLong(s.substring(q), 36));
    for (Class k = decl; ; ) {
        Field f = a(k, name, type);                    // 声明字段精确匹配 名 + 类型
        if (f != null) { a[idx] = f; return f; }
        for (Class i : k.getInterfaces()) { f = b(i, name, type); if (f != null) { a[idx]=f; return f; } }
        if (k.getName().equals("java.lang.Object")) throw new RuntimeException("NoSuchFieldException in …");
        k = (k = k.getSuperclass()) != null ? k : b(2880218812819064L);   // 兜底回 Object
    }
}
```

`d(long)` 同构：先数一遍 `\u0008` 得到段数 → 除末段（返回类型）外都是参数类型 → 调
`getDeclaredMethods` 精确匹配「名 + 参数个数 + 返回类型」。

---

## 5. `resolve_key.py` 用法

```powershell
# 单/多 key（位置参数）
python resolve_key.py 184823010927613107 517287540690064504
# 批量 + 指定种类（F=字段 key，M=方法 key；不给则两种都试）
python resolve_key.py --keys-file aW_keys_kind.txt
python resolve_key.py --kind M 409729356224766465
python resolve_key.py --offline 517287540690064504      # 只用 key_table.json 缓存，不启动 JVM
```

实现要点（两种模式，自动降级）：

1. **full 模式**：`java -cp <jar> KeyResolve full …`，直接调 `com.c.c(long)` / `com.c.d(long)`
   拿真 `Field`/`Method`，描述符取真实反射类型（原始类型天然正确）。**每个 key 独立 JVM**，
   这样某个类的 `<clinit>` 卡死（如 `yT` 会拉 GUI）只影响它自己（20 s 超时）。
2. **safe 模式**（超时/失败自动回落）：只调 `com.c.a(long)` 完成字符串解密，得到
   `declClassKey36\x08name`，再用 `Class.forName(name, **false**, loader)`（不初始化）枚举
   同名成员，按 `--kind` 与解密出的类型段打分消歧。—— 这就是任务里要求的「不依赖运行期填充数组」的可行路径；
   如果连 `com.c` 都不想加载，另有 `--offline` + `key_table.json` 纯查表。

`_keytool/KeyResolve.java` 由脚本按内嵌源码自动重写并 `javac` 编译，无需手工准备。

---

## 6. `aW` 类 21 个 key 的验证表

key 的来源：`javap -p -c aW` 里所有 `ldc2_w #n // long …l`（去重 21 个）；
种类（字段/方法）由**调用点**判定 —— `invokestatic com/c.c:(J)Field` → 字段，`com/c.d:(J)Method` → 方法。

| # | key | hex | sel | idx | 种类 | 解析结果 |
|---|---|---|---|---|---|---|
| 1 | 184823010927613107 | 02909F8C98A894B3 | 39 | 2626 | FIELD | `aW.y : javax.swing.JTextField` |
| 2 | 191807067392725406 | 02A96F82F55A519E | 27 | 2725 | METHOD | `u6.D() -> java.lang.String` |
| 3 | 195109804691767143 | 02B52B5568D93F67 | 10 | 2772 | FIELD | `aW.l : javax.swing.JPasswordField` |
| 4 | 204000105621842013 | 02D4C103E5BB685D | 48 | 2899 | METHOD | `u6.X() -> java.lang.String` |
| 5 | 220378371334645424 | 030EF0F60B94A6B0 | 60 | 3131 | FIELD | `aW.k : javax.swing.JTextField` |
| 6 | 256291570319778198 | 038E87D347D66196 | 33 | 3642 | METHOD | `u6.L() -> java.lang.String` |
| 7 | 270389152141252877 | 03C09D80547F990D | 39 | 3842 | METHOD | `yT.i() -> yT` |
| 8 | 281854482764394826 | 03E95928A385F14A | 22 | 4005 | FIELD | `aW.Z : javax.swing.JLabel` |
| 9 | 296586054365034220 | 041DAF71EFC336EC | 43 | 4214 | METHOD | `Lk.M() -> javax.swing.JTextArea` |
| 10 | 306266403902896148 | 044013ABF344B814 | 4 | 4352 | METHOD | `yT.h() -> u6` |
| 11 | 322267315291882359 | 0478EC6A72B10377 | 59 | 4579 | METHOD | `YJ.o(javax.swing.text.JTextComponent) -> boolean` |
| 12 | 370149877875067536 | 0523095A5065CA90 | 2 | 5260 | METHOD | `YJ.Y(javax.swing.text.JTextComponent, boolean) -> boolean` |
| 13 | 390088110481030006 | 0569DF11D8533B76 | 55 | 5543 | METHOD | `aW.e(java.lang.String) -> javax.swing.JButton` |
| 14 | 409729356224766465 | 05AFA6ADBBD3A201 | 41 | 5822 | METHOD | `aW.X() -> void` |
| 15 | 459969040127248336 | 06622367AC7647D0 | 8 | 6536 | METHOD | `yT.B(Fb) -> void` |
| 16 | 492016222988846142 | 06D3FE25E2FAC43E | 63 | 6991 | METHOD | `Lk.E(java.lang.String) -> java.lang.String` |
| 17 | 517287540690064504 | 072DC6470D911478 | 49 | 7351 | METHOD | `Lk.B(java.lang.String) -> java.lang.String` |
| 18 | 560784054776466487 | 07C84E206CA78C37 | 19 | 7969 | METHOD | `Lk.W(javax.swing.JComponent) -> void` |
| 19 | 592404269438552519 | 0838A48B5B4F49C7 | 41 | 8418 | FIELD | `aW.G : java.lang.String` |
| 20 | 602443583399287704 | 085C4F3F49BA5B98 | 19 | 8561 | FIELD | `aW.p : DU` |
| 21 | 614660311662874560 | 0887B64BFE324FC0 | 45 | 8734 | FIELD | `aW.d : javax.swing.JTextField` |

交叉验证：`javap -p aW` 实有字段 `l,d,G,Z,p,y,k` 与方法 `X(), e(String)`
（还有继承自 `JDialog` 的 `setVisible`）；`javap -p yT` 实有 `public static yT i()`、
`public u6 h()`、`synchronized void B(Fb)`；`javap -p` 里确实存在 `Fb.class`、`u6.class`、
`Lk.class`、`YJ.class`、`yT.class`。全部一致。

任务给出的两个示例 key：
- `184823010927613107` → **`aW.y`，字段，类型 `javax.swing.JTextField`**
- `517287540690064504` → **`Lk.B(java.lang.String) : java.lang.String`**（`Lk` 里 `B` 有 4 个重载，按类型段精确定位到 `(String)String`）

---

## 7. 限制与坑（必须知道）

1. **种类不能靠明文段数判断**：0 参方法 = `类\x08名\x08返回`，与字段同形。种类只体现在
   `<clinit>`/调用点是 `c(long)` 还是 `d(long)`，或靠真实反射（`resolve_key.py` 两种模式都处理了）。
2. **`a[]`/`b[]` 按槽号复用**：同一 idx 若被不同 selector 的 key 先后使用，缓存会「串味」。
   所以 `resolve_key.py` 的 full 模式**每个 key 一个独立 JVM**（`resolve` 里逐 key 调用），
   批量塞进同一个 JVM 会得到互相污染的结果（实测：`c()` 会返回上一个 key 缓存的成员）。
3. **原始类型槽预置 `Class`**：`a[3] = Void.TYPE` 之类，`b[idx]` 一直是 null，`a(long)` 直接返回 idx；
   此时只能靠真反射拿描述符（safe 模式用「类型段解密 + 候选打分」兜底，够用但不如 full 稳）。
4. **`<clinit>` 会卡死**：`yT` 等 GUI 类的静态初始化在本机 20 s 内不返回，`com.c.b(long)` 内部是
   `Class.forName(String)`（会初始化），因此 **key 15/10/7 必须走 safe 模式**（本报告已用 safe 模式解出，
   并用 `javap -p yT` 核对 `i()/h()/B(Fb)`）。
5. **未做**：`c[]`/`d[]` 两个中间数组的具体切片规则（`<clinit>` 约 5.4 万行「取子串 + `jsr` 解密」）
   没有逐条还原——不影响解析，因为 `a(long)` 已把每个槽的密文/明文关系完全确定，运行期直接可用。

---

## 8. 复现命令

```powershell
javap -p -c -cp "<FINALSHELL_HOME>\finalshell.jar" com.c > com_c_full.txt
javap -p -c -cp "<FINALSHELL_HOME>\finalshell.jar" aW  > aWc_full.txt
python resolve_key.py --keys-file aW_keys_kind.txt
# 只读校验：jar 未被修改
Get-FileHash "<FINALSHELL_HOME>\finalshell.jar" -Algorithm SHA256
```
