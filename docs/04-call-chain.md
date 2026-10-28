> 本章为原始分析报告（源文件：`DU_lr_analysis.md`，保留在仓库根目录以供其它流程引用）。

# DU / lr 静态逆向分析报告 — finalshell.jar

- 目标：`<FINALSHELL_HOME>\finalshell.jar`（只读，未修改）；JDK 17.0.18 `javap`
- 工作目录：`<REPO_ROOT>`（本报告与所有中间产物只写在此目录）
- 关键工具产物：`lr_members.txt` / `lr_code.txt` / `DU_members.txt` / `DU_code.txt` / `aW_code.txt` / `Lk_code.txt` / `tokmap.txt`（token→真实成员解析）

## 0. 先纠正一个前提（重要）

jar 里存在**同名不同大小写**的多份类（Zelix 混淆特征）：`DU/ Du / dU / com.DU`、`lr / Lr / lR / LR / com.lr`。

经 `javap -p -s` 逐个比对，与「离线激活」相关的只有**默认包**的两个：

- `DU`（`DU.class`）：`extends javax.swing.JDialog`，字段 `JPasswordField d`、`JTextField C`、`u6 Y`、`JLabel c`、`aW K` —— 这是 aW 里 `DU p` 指向的**子对话框**（激活/购买提示框）。
- `lr`（`lr.class`）：静态工具类，唯一的哈希/加解密封装。
- `com.lr` 是 iText 的 `implements com.E`（图形），`LR/Lr` 是表格渲染器/日志，**与本任务无关**。
- `aW`（`aW.class`）才是真正的「离线激活」主对话框：`JPasswordField l`、`JTextField d/y/k`、`JLabel Z`、`DU p`，与题面描述完全一致。

## 1. DU 与 lr 的全部成员（javap -p -s）

### 1.1 DU

```
public class DU extends javax.swing.JDialog
  javax.swing.JPasswordField d      // 注册码输入
  javax.swing.JTextField C          // 机器码展示
  u6 Y                              // 数据模型（u6）
  javax.swing.JLabel c
  aW K                              // 父对话框回指
  private static int[] W
  private static final String[] a, b ; long[] e ; Integer[] f   // Zelix 字符串解密表
  public DU(java.awt.Window)
  void W()                                    ()V
  public void setVisible(boolean)             (Z)V
  public aW R()                               ()LaW;
  public void E(aW)                           (LaW;)V
  public static void M()                      ()V
  static void d(String)                       (Ljava/lang/String;)V
  javax.swing.JButton C(String)               (Ljava/lang/String;)Ljavax/swing/JButton;
  public static void e(int[])                 ([I)V
  public static int[] u()                     ()[I
  private static String a(int,int)            (II)Ljava/lang/String;   // Zelix 字符串解密
  private static int a(int,long)              (IJ)I                     // Zelix 数组/整型解密
```

**DU 里没有任何 `md5/sha/Cipher/DigestUtils` 调用，也没有任何字符串相等/比较逻辑**（`-p -c` 全量核对：33 次 `com/c.d(J)Method` + 33 次 `Method.invoke`，其余全是 Swing 布局与 `setText`）。
DU 的全部行为：用反射填 `C`/`d` 两个文本框（`W()`），`setVisible` 里 `C.requestFocus()`，`d(String)` = `Desktop.browse(URI)`（点「购买」开网页），`C(String)` = 造一个 `JButton` 并 `setFocusable(false)`。**DU 是纯 UI，不含校验**。

### 1.2 lr（哈希/加密封装，唯一带 md5 的类）

```
static int S, n
private static final String[] a, b ; long[] c ; Integer[] d    // Zelix 解密表
public lr()                                        ()V
static byte[] C(byte[])                            ([B)[B      ★ DigestUtils.md5
public static String a(String)   throws ...        (Ljava/lang/String;)Ljava/lang/String;   // 编码
public static String X(String)   throws ...        (Ljava/lang/String;)Ljava/lang/String;   // 解码
static byte[] x(int)                               (I)[B       // 随机 Key 派生
void B(byte[], long)   /  void x()                              // 空壳（埋点用）
public static byte[] u(byte[], byte[]) throws ...  ([B[B)[B    // DES 加密（Cipher.ENCRYPT_MODE=1）
public static byte[] J(byte[], byte[]) throws ...  ([B[B)[B    // DES 解密（Cipher.DECRYPT_MODE=2）
private static String a(int,int) / int a(int,long)              // Zelix 解密
```

**哈希判定**：`lr` 中唯一的摘要调用在 `C([B)[B`（`invokestatic org/apache/commons/codec/digest/DigestUtils.md5`）。全类无 `MessageDigest`、无 SHA/Keccak。`u/J` 用的是 **DES**（`DESKeySpec` + `SecretKeyFactory` + `Cipher`），不是 AES。

## 2. lr.C 反汇编逐段解读（这是运行时断点命中的那个方法）

```
0-50:  Random r1 = new Random(input[5]);  k = r1.nextInt(a(16462,1508...));   // 索引 5 必须存在
       if (k==0) k += 5 + r1.nextInt(a(17670,5390...));
50-62: long seed = yT.x(静态 long 字段，见 §3) / k;
64-111:Random r2 = new Random(seed);
       for (i=0;i<input[0];i++) r2.nextLong();        // 用 input[0] 做「跳过次数」
       long v = r2.nextLong();
113-218:long[] arr = new long[8];
       arr[0]=input[4]; arr[1]=new Random(v).nextLong(); arr[2]=input[a(25282,...)];
       arr[3]=input[3];  arr[4]=new Random(v).nextLong(); arr[5]=input[1];
       arr[6]=new Random(v).nextLong(); arr[7]=input[2];
220-316:ByteArrayOutputStream+DataOutputStream 依次 writeLong(arr[0..7]) → bytes
316:   return DigestUtils.md5(bytes);
```

特征结论：
- 输入是**字节数组**，且必须长度 ≥ 6（`baload 5`、`baload 0/2/4`），否则 `ArrayIndexOutOfBoundsException`；
- 输出固定 16 字节 = **DES 密钥材料**（正好喂给 `lr.u/lr.J` 的 `byte[] key` → `DESKeySpec`）；
- 混淆密钥里混入 `yT.x`（一个静态 `long` 常量）与 `Random` 序列 —— 这是**「机器码字节 → DES 密钥」的派生函数**，不是直接 md5(字符串)。
- **静态调用点为零**：`lr.C` 的 Zelix token `399526969200892305` 在整个 jar 中只出现在 `lr.class` 自身（全 jar 二进制扫描），`Llr;` 类型引用 0 处 → 说明它只经 `com.c.d(J)`/`Method.invoke` 反射调用，静态 call graph 里看不到边。运行时断点命中即为此路径。

## 3. 关键证据：Zelix 反射 token → 真实成员（动态解析，未改 jar）

`com.c` 是 Zelix 的反射解析器，公开 API：`com.c.c(long)->Field`、`com.c.d(long)->Method`、`com.c.a(Object...)->Object[]`。
写 `Probe2.java / Probe3.java`（放在本目录，classpath 加 jar）把 `DU/aW/lr` 反汇编里出现的 56 个 `ldc2_w long` 全部解析成真实成员，产物 `tokmap.txt`。摘录：

| token | 解析结果 |
|---|---|
| 567239955528735437 | **field `yT.x : long`**（lr.C 读的密钥种子） |
| 399526969200892305 | method `lr.C(byte[])->byte[]`（md5 派生） |
| 536745044160553083 | `lr.u(byte[],byte[])->byte[]`（DES 加密） |
| 311611991731435620 | `lr.J(byte[],byte[])->byte[]`（DES 解密） |
| 559282308271873822 | `lr.x(int)->byte[]` |
| 330094358428833085 | `Lk.Y(String)->boolean`（**判空**：`s==null||s.trim().equals("")`） |
| 354142893546746586 | `uG.z(String)->byte[]`（Base64/编码） |
| 480173285509129670 | `uG.b(byte[])->String` |
| 480173285509129670→ | `uG.b` 同上；`uG` 另有 `a(byte[])`、`Q(String,String)` |
| 204000105621842013 / 191807067392725406 / 256291570319778198 | `u6.X()->String` / `u6.D()->String` / `u6.L()->String` |
| 270389152141252877 / 306266403902896148 | `yT.i()->yT` / `yT.h()->u6` |
| 429952889391243847 / 228183978052282907 / 181350030129350521 / 608857086159868835 | `DU.C:JTextField` / `DU.d:JPasswordField` / `DU.Y:u6` / `DU.K:aW` |
| 184823010927613107 / 195109804691767143 / 220378371334645424 / 281854482764394826 / 602443583399287704 | `aW.y` / `aW.l` / `aW.k` / `aW.Z:JLabel` / `aW.p:DU` |
| 322267315291882359 / 370149877875067536 | `YJ.o(JTextComponent)->boolean` / `YJ.Y(JTextComponent,boolean)->boolean` |
| 270491844808295405 | `DU.d(String)->void`（= `Desktop.browse`） |
| 533245190623110246 / 390088110481030006 | `DU.C(String)->JButton` / `aW.e(String)->JButton` |

由此可确定：`aW.X()` 全是 `setText(反射取值)`（`_y.l()`→机器码、`u6.X()/D()/L()`→各项文本），**是「刷新」而非「校验」**；DU 侧全部反射目标均为 Swing/取值，**无一处返回 boolean 的校验调用**。

## 4. 候选方法清单（类.方法 + 描述符 + 证据）

| # | 方法 | 描述符 | 是否含哈希 | 证据 |
|---|---|---|---|---|
| 1 | `lr.C` | `([B)[B` | **DigestUtils.md5** | `lr_code.txt:190`；输入 ≥6 字节；输出 16B 作 DES key |
| 2 | `lr.a` | `(Ljava/lang/String;)Ljava/lang/String;` | 否（先 `Lk.Y` 判空 → `uG.z`/`lr.u`） | `lr_code.txt:200-322`；token 330094358428833085/354142893546746586 |
| 3 | `lr.X` | `(Ljava/lang/String;)Ljava/lang/String;` | 否（`lr.J` DES 解密 + 编码） | `lr_code.txt:323-442` |
| 4 | `lr.u` | `([B[B)[B` | 否（DES/ECB，`Cipher.init(1,..)`） | `lr_code.txt:487-535` |
| 5 | `lr.J` | `([B[B)[B` | 否（DES 解密，`Cipher.init(2,..)`） | `lr_code.txt:536-570` |
| 6 | `lr.x` | `(I)[B` | 否（`new Random()` 填充） | `lr_code.txt:443-471` |
| 7 | `DU.d` | `(Ljava/lang/String;)V` | 否 | `Desktop.browse`，开购买页 |
| 8 | `DU.C` | `(Ljava/lang/String;)Ljavax/swing/JButton;` | 否 | 造按钮 |
| 9 | `Lk.Y`（DU/lr 的反射目标） | `(Ljava/lang/String;)Z` | 否 | 仅 `trim().equals("")` 判空 |

字符串常量：`lr` 与 `DU` 的 `ldc` 全部是 **Zelix 密文**（`// String !\u0086...`、`// String ??vSt...`、`// String ?\u001fd?w...`），真实明文由 `private static String a(int,int)`（`lr`/`DU` 各自的解密器，内含 `tableswitch` XOR 密钥表 `123/50/71/67/21/92/5`）在运行时解出；`Cipher.getInstance`/`SecretKeyFactory.getInstance` 的算法名（形如 `DES`、`DES/ECB/PKCS5Padding`）同样是**密文**，需动态解或 hook 才能拿到明文。

## 5. 最可能的「激活校验方法」前 3 名及理由

1. **`lr.C([B)[B`（md5 派生）** — 唯一 md5 调用点；运行时断点已验证在激活流程被命中；输入为字节且必须 ≥6 字节；输出 16 字节恰好是 DES 密钥长度，直接喂 `lr.u/lr.J`；密钥里混入 `yT.x` 静态常量（应用级密钥）。这就是「机器码 → 密钥」的核心派生。
2. **`lr.a(Ljava/lang/String;)Ljava/lang/String;`** — 先 `Lk.Y` 判空再走 `uG.z`→`lr.u`，签名与「把 用户名/机器码/注册码 拼好后编码」高度吻合；`lr.X` 是其逆运算。激活对话框（`aW.k` 输入注册码）读写配置必经此路。
3. **`lr.J([B,[B)[B`（DES 解密）** — 若激活码/授权文件是加密块，则「解密后比对」的比对发生在它的**调用者**里；解密失败即校验失败，且它是 `lr.X(String)` 的唯一内层调用。

补充结论（对排查方向很重要）：
- 题面假设的 `DU.某方法(String,String,String)Z` / 返回 int 会员等级 **在 `DU` 中不存在**（DU 仅 11 个方法，全部列于 §1.1）。三字符串比较逻辑必然在反射派发目标中——`u6`（数据模型，含多个 `String`/`boolean`/`int` 字段）、`yT`（`public static long x`、`public static boolean yi`、`public static String Z` 等静态授权状态）、`uG`（编码）、`Lk`（工具）四个类上，下一步应 `javap -p -c` 这几个类并配合运行时 hook（`com.c.d`/`Method.invoke` 统一打日志）定位真正的比较点。

## 6. 复现命令

```bat
set J=%JAVA_HOME%\bin
"%J%\javap.exe" -p -s -cp <FINALSHELL_HOME>\finalshell.jar lr
"%J%\javap.exe" -p -c -cp <FINALSHELL_HOME>\finalshell.jar lr   > lr_code.txt
"%J%\javap.exe" -p -c -cp <FINALSHELL_HOME>\finalshell.jar DU   > DU_code.txt
"%J%\javap.exe" -p -c -cp <FINALSHELL_HOME>\finalshell.jar aW   > aW_code.txt
"%J%\javac.exe" -encoding UTF-8 -cp <FINALSHELL_HOME>\finalshell.jar -d . Probe3.java
"%J%\java.exe" -cp ".;<FINALSHELL_HOME>\finalshell.jar" Probe3  > tokmap.txt
```

`Probe3` 只调用 `com.c.c(long)` / `com.c.d(long)` 解析符号，**不执行任何业务逻辑、不改动 jar**。（注：进程结束时会有非守护线程残留，输出已落盘，直接 `taskkill` 即可。）
