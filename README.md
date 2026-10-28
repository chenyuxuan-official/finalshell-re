# FinalShell 4.6.5 逆向分析

> **English abstract** — A reproducible **static + dynamic** reverse-engineering study of FinalShell 4.6.5
> (`finalshell.jar`, 49,174,505 B, SHA-256 `2FE4A313…A3228C67`), producing reusable tools and evidence documents.
> Three findings: **(1)** the offline activation code is a truncated **Keccak-384** digest, **not** MD5 —
> a one-word error that explains why every circulating `md5(machineCode + salt)` formula fails;
> **(2)** the jar is **double-obfuscated by Zelix KlassMaster** — 1,393 per-class private `(II)String` string
> decryptors plus a `com/c` reflection shim that hides every field and method access, which is why static
> cross-references go dark; **(3)** the `huw` field in `config.json` is a **per-launch random token with no
> membership semantics**, so editing the config file changes nothing. Ships zero-dependency Python tools
> (keygen, string decryptor, class-bytecode patcher) and the disassembly evidence behind each claim.
> **For security research and study of self-owned software only.**

---

## 1. 项目定位

对 **FinalShell 4.6.5** 做静态（javap / 字节码 / PE 反汇编）+ 动态（agent 反射、JDWP、断点）双向分析，
把结论沉淀成**可复用的工具**与**可复现的文档**。

不做「一键破解分发」，不提供软件本体。仓库里只有：结论、证据、能独立跑起来的脚本。

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

### ③ 会员状态不落盘，`huw` 与授权无关

`config.json` 的 `huw`：base64 96 字符 → **72 字节**原始数据，每次启动重新生成（三次启动三个值），
前 8 字节是可打印魔数（`TA_[/o<i`、`DU8hWCUF`、`ZGQ3MGw+`），熵 5.66–6.00 —— 典型的一次性混淆令牌。

- 不是硬件指纹（每次都变）；
- 不是会员位（全库明文常量检索 `激活/试用/到期/vip/member/价格` → **0 命中**）；
- 改它没有意义：启动流程会把 `config.json` 整体重写，并在 `backup/app_config/<毫秒>.json` 留快照。

真正的门在**服务端响应 + 云同步口令校验**，不在本地这份 JSON 里。

📄 三次启动对比实验与结构分析：**[huw_analysis.md](docs/05-config-huw.md)**

---

## 4. 仓库结构

```
逆向finalshell/
├── README.md                    ← 本文件
├── docs/                        结论文档（按主题编号）
│   ├── 01-obfuscation.md            ZKM 双重混淆架构总览 / 判别方法
│   └── activation-algorithm.md      算号算法 + 反汇编证据链（核心结论）
├── tools/                       可复用工具（全部零依赖）
│   ├── keccak.py                    纯 Python Keccak-224/256/384/512（带自检向量）
│   ├── finalshell_keygen.py         算号器：4 个盐分支 + 版本号自动选支
│   ├── fk_string_decrypt.py         ZKM 私有解密器 b(int,int) 的纯 Python 复现（离线）
│   └── DumpStringTable.java         反射导出目标类的密文表/常量表为 JSON（一次性，需 JDK）
├── data/                        工具依赖的数据
│   └── lk_string_table.json         Lk 的 f[] 密文表（124 槽，17,196 B）
├── analysis/                    第三方算号器 finashellpp.exe 的 PE 分析产物
│   ├── pe_analyze.py                 PE 头/节表/导入导出解析
│   ├── *.disasm.txt                 反汇编（.text 全量 + 关键函数）
│   ├── strings_ascii.txt            字符串提取
│   └── xrefs.txt / iat_refs.py      导入表交叉引用
├── archive/                     归档（当前为空，留作历史版本/样本）
│
├── jar_patcher.py               ★ 纯 Python class 字节码修补器（零依赖，不要 ASM）
├── selftest.py                  jar_patcher 的自测脚本
├── key_table.json              Zelix token → 真实成员 的解析表（21 条，动态解析所得）
├── Lk_decrypt_analysis.md      Lk 类 162 个成员的逐个判定 + 主解密器完整算法
├── DU_lr_analysis.md           DU（纯 UI）/ lr（md5+DES）定位报告
├── huw_analysis.md             config.json → huw 三次启动对比实验
├── REPORT-jar-patcher.md       补丁工具自测报告（JVM `-Xverify:all` 级验证）
└── monitor_commands.sh         Linux 侧无代理监控命令集（观察运行时行为用）
```

> 根目录还留有若干分析期的临时脚本（`an*.py`、`scan_*.py`、`resolve_key.py`、`Probe*.java` 等），
> 它们是定位过程中的探针，保留作可复现线索，后续会逐步归入 `tools/`、`docs/`。
> `finalshell.orig.jar`、`*.hprof`、`decrypted_all*.txt`、`callsites*.tsv`、解包目录等大件全部
> 由 `.gitignore` 排除，见第 8 节。

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
| **4.6.5 接受的盐分支** | ✅ **已闭环：分支 3（MODERN-C）** | 算号器实测对拍 → [§7](docs/activation-algorithm.md) |
| **激活不持久的根因** | ✅ **已定位：`yunce.hostbuf.com` 未被屏蔽** | [`docs/persistence-findings.md`](docs/persistence-findings.md) |
| `huw` 是否含授权信息 | ⚠️ 存疑（「每次变」不足以证伪） | 同上 §5 |

---

## 7. 已知限制与未解决项

诚实列清楚，别把「没验完」写成「已确认」：

1. **4.6.5 到底接受哪个盐分支，没有闭环验证。** 版本号映射规则说 4.6.x → 分支 3（`Scfg*ZkvJZc,s,Y`），
   但社区长期流传、且实测可激活 4.x 的是分支 1（`FF3Go(*Xvbb5s2`）。两种说法都缺一次干净环境下的
   端到端提交验证 —— 建议用 `--all` 逐支粘贴，配合下面的观察点记录结果。
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
