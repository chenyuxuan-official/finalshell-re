# FinalShell 4.6.5 逆向分析

> **GUI 版激活助手（已发布链接）**：[FinalShell-Activator.exe v1.0.0](https://github.com/chenyuxuan-official/finalshell-re/releases/download/v1.0.0/FinalShell-Activator.exe)
> —— 发布包大小和运行状态本次未核验；源码见 `tools/gui.py`。全部 Release：[Releases](https://github.com/chenyuxuan-official/finalshell-re/releases)

> **English abstract** — A reproducible **static + dynamic** reverse-engineering study of FinalShell 4.6.5
> (`finalshell.jar`, 49,174,505 B, SHA-256 `2FE4A313…A3228C67`), producing reusable tools and evidence documents.
> Three findings: **(1)** the offline activation code is a truncated **Keccak-384** digest, **not** MD5 —
> a one-word error that explains why every circulating `md5(machineCode + salt)` formula fails;
> **(2)** the jar is **double-obfuscated by Zelix KlassMaster** — 1,393 per-class private `(II)String` string
> decryptors plus a `com/c` reflection shim that hides every field and method access, which is why static
> cross-references go dark; **(3)** the `huw` field in `config.json` **changed in three observed launches**; its generation and
> relationship to membership have not been established. Ships zero-dependency Python tools
> (keygen, string decryptor, class-bytecode patcher) and the disassembly evidence behind each claim.
> **For security research and study of self-owned software only.**

---

## 1. 项目定位

对 **FinalShell 4.6.5** 做静态（javap / 字节码 / PE 反汇编）+ 动态（agent 反射、JDWP、断点）双向分析，
把结论沉淀成**可复用的工具**与**可复现的文档**。

仓库未跟踪目标软件本体或已打包 exe；仓库内容主要是结论、证据与工具源码。

分析过程中反复踩到的坑（字符串全加密、类名打乱、反射化调用、同名大小写类）都已写成文档，
后续再碰同类 ZKM 样本时可以照着流程走。

---

## 2. 目标版本与指纹

| 项 | 值 |
| :--- | :--- |
| 产品 / 版本 | FinalShell **4.6.5** |
| 分析对象 | `finalshell.jar` |
| 大小 | **49,174,505** B |
| SHA-256 | `2FE4A3131E488C3B2C7E0BF59B1EDA9EC44DE1E12ECCEAF4989C4183A3228C67` |
| 压缩包条目 | 20,338（其中 `.class` **17,373** 条 / 17,372 个唯一类，`module-info.class` 重复一次） |
| class 版本 | major 52（Java 8 目标），运行时 JDK 17 |
| 混淆器 | Zelix KlassMaster（ZKM）+ Stringer 式字符串加密 + `com/c` 反射垫片 |
| 分析工具 | JDK 17 `javap`、自写 class 解析器、Python 3.13、IDA/Ghidra 级反汇编（用于第三方算号器 PE） |

> 原 jar **不入库**。检出本仓库后请自备同版本 jar，并先校验上面的 SHA-256 —— 后续所有偏移、
> 索引、token 都与这份二进制绑定，换版本结论不保证成立。

---

## 3. 三个核心发现

### ① 激活码是 Keccak-384，不是 md5

```
激活码 = Keccak384( prefix + 机器码 + suffix ).hex()[12:28]
```

原版 **Keccak-384**（Qt `QCryptographicHash::Keccak_384`），**不是** NIST `SHA3-384` —— 域分隔符
`0x01` vs `0x06`，结果完全不同。证据是第三方算号器 `finashellpp.exe` 里
`mov r8d, 9` → Qt 算法枚举 `Keccak_384`，再 `mid(12, 16)` 取 16 个 hex 字符。

对拍：`0123456789abcdef` → `929ae2afb3b2d11a`（示例机器码，非真实机器码；原始实测用作者本机机器码，结论一致） —— 网上那些「md5 算号器」能出正确结果，
是因为它们内部算的其实是 Keccak-384，只是挂错了名字。

📄 完整反汇编证据链（盐值偏移、版本判定函数、导入表）：**[docs/activation-algorithm.md](docs/activation-algorithm.md)**

### ② jar 是 Zelix 双重混淆：每类私有解密器 + `com/c` 反射垫片

| 层次 | 形态 | 规模（全量实测） |
| :--- | :--- | :--- |
| 类名打散 | 顶层类名收进 `A`..`zz` 命名空间 | 1,941 个顶层类（1 字符 43 个 + 2 字符 1,898 个） |
| 大小写陷阱 | 同名不同大小写并存，只有默认包那个是真身 | 647 组，如 `DU/Du/dU/du`、`LR/Lr/lR/lr` |
| 字符串加密 | 每个类自带 `private static String x(int,int)` 解密器 | **1,393** 个类 / 1,393 个方法（`a` 1,131、`b` 223、`c` 39） |
| 成员访问反射化 | `com/c` 提供 `c(long)→Field`、`d(long)→Method` | 61 个 public static 入口（含 57 个 `a(...)` 参数打包重载） |

后果很直接：**字符串全加密 + 调用点全反射** ⇒ 静态 xref 天然断链。`lr.C` 的 token 在整个 jar 里
只出现在 `lr.class` 自己身上，`grep huw` 在 14,271 个 class 的原始字节里 **0 命中**。

📄 架构总览与判别方法：**[docs/01-obfuscation.md](docs/01-obfuscation.md)**

### ③ `huw` 三次启动值不同，授权语义未定位

`config.json` 的 `huw`：观察到的 base64 值为 96 字符，解码后 **72 字节**；三次启动得到不同值。
这说明它不是稳定的明文标识，但随机 IV 加密固定内容等解释尚未排除；生成函数、消费方及其与授权的关系尚未定位。
观察到配置文件重写与 `backup/app_config/` 快照，不能单凭这些现象断定授权状态的存储方式或服务端复核路径。

📄 三次启动对比实验与结构分析：**[docs/05-config-huw.md](docs/05-config-huw.md)**

---

## 4. 仓库结构

```
逆向finalshell/
├── README.md                    ← 本文件
├── docs/                        INDEX.md、01–06 专题及补充文档
├── tools/                       Python/Java 工具、GUI 与 build_exe.ps1
│   ├── activate.py                  命令行入口
│   ├── gui.py / build_exe.ps1        GUI 源码 / Windows 打包脚本
│   ├── finalshell_keygen.py / keccak.py
│   ├── fk_string_decrypt.py / DumpStringTable.java
│   └── jar_patcher.py / selftest.py
├── data/                        key_table.json、lk_string_table.json
├── analysis/                    PE 分析脚本与报告（转储文件不入库）
├── .gitignore
└── LICENSE
```

这是**跟踪文件的概要**，完整列表以 `git ls-files` 为准。`finalshell.orig.jar` 与生成的转储可存在于本地，但受 `.gitignore` 排除；见第 8 节。

---

## 5. 快速开始

### 5.0 一键激活（推荐入口）

`tools/activate.py` 把「算激活码」和「屏蔽云端复核」合成一条命令。

```bash
# ① 只算号
python tools/activate.py "admin@0123456789abcdef" -v 4.6.5
#   激活码 : a68b68ba533b731c

# ② 算号 + 自动改 hosts（需要管理员 / root）
python tools/activate.py "admin@0123456789abcdef" -v 4.6.5 --fix-hosts

# ③ 只改 hosts，不算号
python tools/activate.py --fix-hosts

# ④ 想反悔 → 从备份恢复
python tools/activate.py --revert-hosts

# ⑤ 先看会写什么，不动系统
python tools/activate.py --fix-hosts --dry-run
```

**操作步骤**

1. 打开 FinalShell → 登录窗口 → 点「离线激活...」，复制上面显示的**机器码**
   （形如 `用户名@16位十六进制`）
2. 用你在用的版本号执行上面的命令，拿到 16 位激活码
3. 粘回「激活码」输入框 → 点「确定」
4. 执行 `--fix-hosts`，然后**重启 FinalShell**

> 第 4 步不能省。理由见 [docs/persistence-findings.md](docs/persistence-findings.md)：
> 客户端会向 `yunce.hostbuf.com` 心跳复核，不屏蔽它，激活状态联网后会被服务端覆盖。

改 hosts 是**全局**的，会影响本机对这批域名的所有访问；备份写在
`hosts.finalshell-re.bak`，`--revert-hosts` 可一键还原。

### 5.1 只算号（不碰系统）

```bash
# 指定版本，自动选盐分支（4.6.5 → 分支 3 MODERN-C）
python tools/finalshell_keygen.py "0123456789abcdef" -v 4.6.5
#   → 4d6602d9625a0fe1

# 不确定版本就四支全列出来逐个试
python tools/finalshell_keygen.py "0123456789abcdef" --all
#   分支 0  LEGACY   2356 / 13593            → e9ecf3dd4ec7d3c7
#   分支 1  MODERN-A ""   / FF3Go(*Xvbb5s2   → 929ae2afb3b2d11a   ← 3.9.6+ 长期通用
#   分支 2  MODERN-B ""   / b(xxkHn%z);x     → c42fbe8938b44f03   ← 4.5.x
#   分支 3  MODERN-C ""   / Scfg*ZkvJZc,s,Y  → 4d6602d9625a0fe1   ← 4.6.x（已实测闭环）

# 纯算法自检（标准测试向量）
python tools/keccak.py
#   Keccak-384("") = 2c23146a…1957ff
#   SELF TEST     : PASS
```

### 5.2 jar 补丁（方法体 → 常量返回）

```bash
# 任意静态方法改成返回指定常量（这里把 FlatLaf.isLafDark() 钉成 true）
python tools/jar_patcher.py --jar finalshell.orig.jar \
    --class com/formdev/flatlaf/FlatLaf --method "isLafDark:()Z" \
    --value true --out out/finalshell.patched.jar

# 工具自测：扫全量 17,373 个 class，选中 449 个可补丁的 static ()Z 方法 + JVM 校验
python tools/selftest.py
```

输出会打印原/新字节码 hex、`max_stack` 与 Code 属性长度变化；jar 内只有命中的那个 `.class` 被替换，
其余条目字节级不变。`-Xverify:all` 已实测通过（详见 [docs/06-jar-patching.md](docs/06-jar-patching.md)）。

### 5.3 字符串还原（离线，不起 JVM）

```bash
# 单个调用点：idx:key → 明文
python tools/fk_string_decrypt.py --pair 3:3823
#   idx=3 key=3823 → /+          （Lk.b(3, 3823)）

# 打印从 tableswitch 反读出来的扰动表 M[] 与类信息
python tools/fk_string_decrypt.py --dump-m
```

算法本体（截取自 [Lk_decrypt_analysis.md](docs/02-string-decrypt.md) §4）：

```text
idx = (arg0 ^ -17846) & 0xFFFF          # 表索引密钥
c[] = f[idx].toCharArray()             # 密文块
m   = M[c[0] & 0xFF]                   # 255 分支 tableswitch 查出的扰动量
k1  = (arg1 & 0xFF) - m   (mod 256)    # 偶数位密钥
k2  = (arg1 >> 8 & 0xFF) - m (mod 256) # 奇数位密钥
for j in 0..len-1:
    c[j] ^= (j even ? k1 : k2)
    (j even ? k1 : k2) = ror3(key) ^ c[j] & 0xFF   # 自同步滚动
return new String(c)                   # 结果 intern 进 i[idx]
```

要给**别的类**导表（`DumpStringTable` 需 JDK 17；会触发目标类 `<clinit>`，只读）：

```bash
javac -encoding UTF-8 -d out tools/DumpStringTable.java
java -cp "out;finalshell.orig.jar" DumpStringTable finalshell.orig.jar Lk f
# 注：进程退出时可能因残留非守护线程返回非 0，输出已完整打印
```

---

## 6. 验证状态

| 结论 | 状态 | 证据 |
| :--- | :--- | :--- |
| **MODERN 分支是 Keccak-384；LEGACY 分支仍是 MD5** | ✅ 反汇编 + 标准向量 + 三组对拍 | [`docs/activation-algorithm.md`](docs/activation-algorithm.md) §3–4 |
| 4 个盐分支与版本判定 | ✅ 反汇编还原 | 同上 §2–3 |
| 每类私有 `(II)String` 解密器 | ✅ 全量扫描 1,393 个 | [`docs/01-obfuscation.md`](docs/01-obfuscation.md) |
| `b(int,int)` 算法可离线复现 | ✅ 对已导出表复算命中 | [`tools/fk_string_decrypt.py`](tools/fk_string_decrypt.py) |
| `com/c` 反射垫片（token 解析） | ✅ 动态解析出 21 条 | [`data/key_table.json`](data/key_table.json) |
| `huw` 每次启动值不同 | ✅ 三次启动实测 | [`docs/05-config-huw.md`](docs/05-config-huw.md) §3 |
| jar 字节码补丁工具 | ✅ 449 用例扫描 + `-Xverify:all` | [`docs/06-jar-patching.md`](docs/06-jar-patching.md) |
| **算号器输入版本 4.6.5 时的盐分支** | ✅ 分支 3（MODERN-C）已对拍；客户端端到端接受情况未独立确认 | [算法说明 §7](docs/activation-algorithm.md#7-实测确认已闭环) |
| **激活不持久的根因** | ⚠️ `yunce.hostbuf.com` 未列入原 10 条域名；是否导致状态回退仍待 A/B 验证 | [`docs/persistence-findings.md`](docs/persistence-findings.md) §4 |
| `huw` 是否含授权信息 | ⚠️ 存疑（「每次变」不足以证伪） | 同上 §5 |

---

## 7. 已知限制与未解决项

诚实列清楚，别把「没验完」写成「已确认」：

1. **4.6.5 的算号器分支与客户端实际接受结果是两种验证范围。** [算号器对拍](docs/activation-algorithm.md#7-实测确认已闭环)记录版本 `4.6.5` 映射分支 3，并给出经脱敏重算的示例；该记录并非客户端干净环境端到端提交验证。
2. **会员/授权状态的持久化机制未定位。** 已知：激活后安装目录**不产生**授权文件，`config.json`
   不新增字段，备份快照也无变化 ⇒ 疑似只存在于进程内存（重启可能需重新激活），或干脆在服务端。
   Java 层全库明文常量检索不到 `会员/到期/vip` 类分支，因此**不排除**本地根本没有会员判定。
3. **`huw` 的生成函数与消费方未定位。** 明文常量里没有 `huw` 这个 key（⇒ 运行时拼接或由内存对象序列化），
   写入路径经 `dD`（`user.dir`/`user.home` + `/config.json`）与配置 Bean `yT`，但具体生成算法、
   以及是否有服务端消费，均未证明。
4. **解密器只对 Lk 做了完整表导出。** 1,393 个类各有自己的密文表，目前 `data/` 只有 `Lk` 的 124 槽；
   其余类需要时按 5.3 的命令逐个导出（或在 Python 侧直接解 class 常量池 + `<clinit>` 切片逻辑）。
5. **token 解析只覆盖 21 条。** `key_table.json` 是一次针对性扫描的结果，完整 token 库需要批量扫
   `ldc2_w` 常量并逐个调 `com.c.d/c`；反射化调用链的静态重建仍然做不了（这是 ZKM 的设计目的）。
6. **补丁工具能力边界：只做「方法体整体替换为常量返回」。** 复杂注入（插桩打日志、改分支条件、
   加新方法）尚未实现；它解决的是「钉住一个 boolean / 改成返回 null」这类需求。
7. **动态分析依赖可启动的非加固环境。** 部分验证用 JDWP/agent 完成，若目标环境启用反调试或改动启动参数，
   需重新校准（`monitor_commands.sh` 里有关联的观察命令）。

---

## 8. `.gitignore` 策略

仓库只留**结论 + 工具 + 小数据**：

- 排除：`finalshell.orig.jar`（49 MB）、`*.hprof`（堆转储）、`*.log`、`decrypted_all*.txt`（2 MB 明文常量）、
  `strings_full.txt`（39 MB）、`callsites*.tsv`、`heap_cjk.txt`、`cp_index.json`（35 MB）、`entries.txt`、
  `jar_list.txt`、`*.class`、`__pycache__/`；
- 排除解包/构建目录：`out/`、`run/`、`temp/`、`extract/`、`jar_x/`、`extracted_classes/`、`com/`、
  `agentcls/`、`_mf/`、`_keytool/`、`_stacktest/`；
- 保留：`tools/`、`docs/`、`data/key_table.json`（以及 `data/` 下的表文件）。

---

## 9. 免责声明

本项目面向**安全研究与学习者对自有软件的学习**：理解商业 Java 桌面程序的混淆与授权实现方式、
沉淀通用分析工具链。仓库**不含**被分析软件的二进制、不含成品补丁、不提供分发渠道。

所有反汇编偏移、token、密文表都与 README 第 2 节那份 SHA-256 的二进制绑定；换版本请重新取证。
使用本仓库内容所产生的一切后果由使用者自行承担。

---

## 10. 占位符与脱敏约定

仓库内所有涉及作者本机环境的字面量都已替换为占位符，复现时按自己的环境替换：

| 占位符 | 含义 | 原始值类型（不公开具体值） |
| :--- | :--- | :--- |
| `<FINALSHELL_HOME>` | FinalShell 安装目录 | 本机绝对路径 |
| `<TOOL_DIR>` | 存放第三方算号器样本（`finashellpp.exe`）的目录 | 本机绝对路径 |
| `<REPO_ROOT>` | 本仓库检出目录 | 本机绝对路径 |
| `<MACHINE_CODE>` | FinalShell 机器码（硬件指纹） | 16 位十六进制哈希 |
| `0123456789abcdef` | 用于对拍的示例机器码 | **示例值，非真实机器码** |
| `admin@0123456789abcdef` | 带用户名的示例机器码 | **示例值，非真实机器码** |

- 文中 `<FINALSHELL_HOME>` 指 FinalShell 安装目录（例如它的 `finalshell.jar`、`config.json`、`lib-run/` 都在其下）。
- `<TOOL_DIR>` 指存放第三方算号器样本的目录；样本文件名 `finashellpp.exe` 本身保留不变。
- 示例机器码仅用于演示算法输入输出格式，配套的激活码/摘要都是按同一算法重算的，与本机无关。
