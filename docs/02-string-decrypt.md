> 本章为原始分析报告（源文件：`Lk_decrypt_analysis.md`，保留在仓库根目录以供其它流程引用）。

# Lk 类字符串解密结构分析（FinalShell finalshell.jar）

目标：`<FINALSHELL_HOME>\finalshell.jar`（只读，未修改）
导出命令：

```
"%JAVA_HOME%\bin\javap.exe" -p -c -cp "<FINALSHELL_HOME>\finalshell.jar" Lk
```

输出：`<REPO_ROOT>\Lk_full_disasm.txt`（UTF-8，14,644 行，162 个方法/字段签名）

---

## 1. 结论先行

**28 个 `(String)->String` 方法里，没有一个本身是解密器。**
`javap` 实际统计到 **27 个** `public static String x(String)`（外加若干同名重载如 `o(long,String)`、`B(String,String)`）。
这 27 个全部是**业务工具方法**，其中 8 个内部会调用真正的解密器来还原自己用到的常量字符串。

**真正的解密器是：`private static java.lang.String b(int, int)`**（disasm 第 13447 行，1134 条指令）。
它有两个同族辅助方法：

| 方法 | 位置 | 作用 |
|---|---|---|
| `private static String b(int,int)` | 13447 | **主解密器**：表查找 + 交错双密钥异或链 + intern 缓存 |
| `private static int a(int,long)` | 14582 | 反射常量取值的整数还原（读 `j[]`/`a[]`） |
| `private static long b(int,long)` | 14613 | 反射常量取值的长整数还原（读 `o[]`/`l[]`） |

---

## 2. 六个字段的真实角色

`<clinit>`（disasm 第 12099 行）中：

```
12185: putstatic Field f:[Ljava/lang/String;   // 密文表，长度 118
12188: putstatic Field i:[Ljava/lang/String;   // 解密结果缓存，长度 124（new String[124]）
12464: putstatic Field a:[J                    // long 密钥表，配合 j[] 缓存
12467: putstatic Field j:[Ljava/lang/Integer;  // 整数结果缓存
12581: putstatic Field l:[J                    // long 密钥表，配合 o[] 缓存
12584: putstatic Field o:[Ljava/lang/Long;     // long 结果缓存
```

- `f[]` 由 `<clinit>` 中一段**变长切片**逻辑从一个巨型密文串切出：起始 `iconst_4`/`istore 17`，每轮
  `substring(i, i+len)` 取一段后，再用 `charAt(i+len)` 作为下一段的长度。→ 密文表本身也被打散。
- `i[]` 是同下标的 `intern()` 缓存，`aaload` 命中即返回（二次调用不再解密）。
- `a[]/j[]`、`l[]/o[]` 是 **Memo 型延迟计算缓存**：`j[idx]==null` 时才用 `a[idx] ^ 入参` 算出来并回填。
  注意这**不是**字符串解密，它是把 `long` 形态的反射常量（如 `0x6F8C...`）还原成 int / long 立即数。

**关键事实：27 个 `(String)->String` 方法体内没有任何一处 `getstatic Lk.f/i/a/l/j/o`。**
全文件中这 6 个字段的读取点只有 4 处：`b(int,int)` 内 3 处（`i`、`f`、`i`）、`a(int,long)` 内 2 处（`j`、`a`）、
`b(int,long)` 内 2 处（`o`、`l`）。

---

## 3. 逐方法判定表

`指令数` = Code 属性中编号指令条数；`含循环` = 存在回边 `goto`（部分只是 try/catch 回边，非真正循环）；
`引用表` = 是否直接读写 `f/i/a/l/j/o`；`b(II)` = 是否调用主解密器及其实参。

| # | 方法 | 指令数 | 含循环 | charAt/toCharArray | 引用表 | b(II) 实参 | 结论 |
|---|---|---|---|---|---|---|---|
| 1 | `E` | 45 | 否 | toCharArray | 无 | — | **字符偏移混淆**：`c[i]=(char)(c[i]+t[i])`，`t` 为 `com.c` 反射取出的 `int[]`（key `502159663893205874L`） |
| 2 | `a` | 41 | 否 | toCharArray | 无 | — | **字符偏移混淆**：同上但 `(char)(c[i]-t[i])`（与 `E` 互为逆运算，加法/减法对） |
| 3 | `x` | 220 | 是 | — | 无 | `(-17902, 26437)` | 业务工具：`startsWith`/`substring` 去前缀 + 反射调用 |
| 4 | `K` | 21 | 是(回边) | — | 无 | — | 纯反射包装（`com.c.a`+`Method.invoke`），非解密 |
| 5 | `V` | 21 | 是(回边) | — | 无 | — | 纯反射包装 |
| 6 | `B` | 21 | 是(回边) | — | 无 | — | 纯反射包装 |
| 7 | `X` | 21 | 是(回边) | — | 无 | — | 纯反射包装 |
| 8 | `d` | 73 | 是 | charAt | 无 | — | **转义/映射**：双层循环用 `char[]` 实体表匹配替换（HTML/实体解码） |
| 9 | `s` | 61 | 是 | charAt | 无 | — | **转义/映射**：与 `d` 同族的反向映射 |
| 10 | `k` | 25 | 是(回边) | — | 无 | `(-17871, 6541)` | 编码转换：`getBytes(解密出的字符集名)` + 反射方法 |
| 11 | `Q` | 36 | 是(回边) | — | 无 | `(-17871, 6541)` | 编码转换：同上，`StringBuilder.append` 拼装 |
| 12 | `q` | 74 | 是 | — | 无 | `(-17896, -24721)` | 编码/十六进制：`Integer.toHexString` + `getBytes` |
| 13 | `Z` | 20 | 是(回边) | — | 无 | — | 工具：反射取串后 `substring(a(22081,L),a(32650,L))` 截取 |
| 14 | `A` | 197 | 是 | — | 无 | `(-17863,25437)`、`(-17883,-20368)` 等 | 业务工具：`equals`/`trim`，内嵌多个解密密文 |
| 15 | `S` | 426 | 是 | — | 无 | 多处（`-17813,5668`…） | 业务工具：`trim`/`substring`/`valueOf`，解密密文调用最多 |
| 16 | `G` | 167 | 是 | charAt | 无 | 多处（`-17853,16889`…） | 业务工具：`split`/`substring` 解析，内嵌解密密文 |
| 17 | `b` | 9 | 否 | — | 无 | `(-17847, 3823)` | 极简包装：`s.replaceAll(decrypt, "/")` 路径分隔符归一 |
| 18 | `O` | 14 | 是(回边) | — | 无 | — | 纯反射包装（`com.c.a(Object,Z)`） |
| 19 | `L` | 107 | 是 | toCharArray | 无 | — | 转义清理：`equals`/`replaceAll` 过滤 |
| 20 | `j` | 53 | 是 | — | 无 | — | 工具：`lastIndexOf`/`substring` |
| 21 | `h` | 65 | 是 | — | 无 | — | 工具：`endsWith`/`startsWith`/`substring` |
| 22 | `J` | 15 | 否 | — | 无 | — | 工具：取最后一个 `.` 前的子串（扩展名/包名） |
| 23 | `N` | 17 | 否 | — | 无 | — | 工具：`lastIndexOf`/`substring` |
| 24 | `M` | 119 | 是 | — | 无 | — | 工具：路径判断 + `StringBuilder` |
| 25 | `y` | 22 | 是(回边) | — | 无 | `(-17820, -19938)` | 工具：`replaceAll(解密串, ...)` |
| 26 | `e` | 12 | 否 | — | 无 | — | 工具：`lastIndexOf` 单行判断 |
| 27 | `m` | 48 | 是 | — | 无 | — | 工具：`lastIndexOf`/`substring` |

> 只有 #1/#2 是"字符级变换"，#8/#9/#19 是"转义/映射"，其余全是业务工具。
> #17 的 `b` 只是把解密器当"常量提供者"用了一次，本身不含解密算法。

---

## 4. 主解密器 `b(int,int)` 完整算法

### 4.1 索引与缓存

```
idx = (arg0 ^ (-17846)) & 0xFFFF        // -17846 == 0xFFFFBA4A
if (i[idx] != null) return i[idx];      // intern 缓存命中
```

调用方传入的 `arg0` 都是 `sipush` 负常量（`-17813`…`-17920`），与之异或后落进 `0..118`，
正好覆盖 `f[]` 的 118 项，并与 `i[]` 的 124 项上限吻合。→ **`(-17846, 0xFFFF)` 就是"表索引密钥"**。

### 4.2 取密文 + 选变体

```
char[] c = f[idx].toCharArray();
switch (c[0] & 0xFF) {                  // 只取低字节，0..254 共 255 个分支
   case 0:  m = 130;   ...              // 每个分支只是把 m 赋成一张常量表里的一个值
   case 1:  m = 176;
   ...
   default: m = 3;                      // 指令 2466: iconst_3
}
```

`tableswitch` 的 255 个分支**只负责给 `m` 赋值**（`sipush 130` / `bipush 176` …），随后统一
`goto 2467`。即 `m` 是一个 **0..255 范围内的"变体号/扰动量"**，由密文首字符低字节选出，默认 3。

### 4.3 由第二参数派生两把逐位密钥

```
k1 = (arg1 & 0xFF)            - m;   if (k1 < 0) k1 += 256;   // 低字节
k2 = ((arg1 & 0xFFFF) >>> 8)  - m;   if (k2 < 0) k2 += 256;   // 高字节
```

- `arg1` 是调用方的第二个 `sipush` 常量（如 `26437`、`3823`、`-24721`）；
- 拆成**低字节 / 高字节**两份，各减 `m` 后对 256 取模归位。

### 4.4 交错异或链（核心）

```
for (int j = 0; j < c.length; j++) {
    if ((j % 2) == 0) {                       // 偶数下标 → 用 k1
        c[j] = (char) (c[j] ^ k1);
        k1 = (((k1 >>> 3) | (k1 << 5)) ^ c[j]) & 0xFF;
    } else {                                  // 奇数下标 → 用 k2
        c[j] = (char) (c[j] ^ k2);
        k2 = (((k2 >>> 3) | (k2 << 5)) ^ c[j]) & 0xFF;
    }
}
return i[idx] = new String(c).intern();
```

要点：

1. **步长 1**，从 0 开始，逐字符处理，无跳读；
2. 偶数位用 `k1`、奇数位用 `k2`，**两把密钥交替**；
3. 异或后立即**滚动更新**该密钥：先做 `(k >>> 3) | (k << 5)` 的 8 位循环右移 3（等价 ROR-3，
   等价于 ROL-5），再与**刚解出的字符** `c[j]` 异或，最后 `& 0xFF` 收敛到字节域；
4. 因此每个字符的密钥依赖"前一个同奇偶位置的明文字符"，是**自同步流密码**，必须从头顺序解；
5. 结果 `intern()` 进 `i[idx]`，同一索引只解一次。

### 4.5 还原字符的方式

`c[j] ^= key` 后直接 `castore` 回字符数组，最后 `new String(char[])`（指令 2602–2610）。
所以字符集是 UTF-16 `char`，中文等双字节字符按单个 `char` 参与异或。

### 4.6 配套的常量还原器（不是字符串解密）

`a(int,long)` —— 整数表：

```
idx = ((arg0 ^ (arg1 & 0x7FFF)) ^ 19510) & 0xFFFF     // 32767 == 0x7FFF, sipush 19510
if (j[idx] == null) j[idx] = (int)(a[idx] ^ arg1);
return j[idx];
```

`b(int,long)` —— 长整数表：

```
idx = ((arg0 ^ (int)arg1) ^ 21478) & 0x7FFF           // sipush 21478, iand 32767
if (o[idx] == null) o[idx] = l[idx] ^ arg1;
return o[idx];
```

这两者把 `ldc2_w` 里的 `long` 常量（如 `2379467392432576318L`）在运行时算成小整数，
用于 `substring` 下标、`append(char)` 字符、`replaceAll` 参数等。**它们只解数字，不解字符串。**

---

## 5. 复现解密的最小步骤

1. 从 `<clinit>` 还原 `f[]`：按"首段长度 4、之后每段长度 = 上段末尾字符"的变长切片逻辑，
   把密文大串切成 118 段；
2. 对每个 `b(int k, int key)` 调用点（全类共 **136** 处 `invokestatic Method b:(II)`，其中 27 个
   `(String)->String` 方法内 20 余处），按 `sipush k` + `sipush key` 取参后按 §4.1–4.5 计算；
3. `E`/`a` 另行处理：从 `com.c.c(502159663893205874L).get(null)` 取 `int[]`，逐位 `+/-(int)c[i]`；
4. `d`/`s` 另行处理：从 `com.c.c(569080910441913458L).get(null)` 取 `char[]` 实体表做双向映射。

> 说明：`com.c.c(long)` / `com.c.d(long)` / `com.c.a(Object, ...)` 是同一个混淆框架的反射入口，
> 负责"隐藏字段访问与方法调用"，与本题的字符串表解密是两套独立机制。
