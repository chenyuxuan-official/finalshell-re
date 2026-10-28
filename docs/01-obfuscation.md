# 01 · 混淆总览：FinalShell 4.6.5 的保护结构

> 本章是全仓的入口章节，只给"地图"与指针；具体推导过程分布在第 02–06 章。
> 各专题的推导过程见第 02–06 章；本章末尾列出仍待补齐的开放问题。

## 1. 一句话结论

`finalshell.jar`（4.6.5，约 46.9 MB）由 **Zelix KlassMaster（ZKM）** 做过商业级混淆：
类名/成员名被压成 1–2 字符（`a`…`z_`、`A0`…`Z_`、`huw`、`aW`、`DU`、`lr`），
字符串常量以加密表形式存放在静态字段里，运行时由专用解密器按索引还原。
因此**不能靠读业务代码理解逻辑**，必须先建立"名字 → 真实语义"的映射，再读解密后的字符串。

## 2. 四层保护与对应章节

| 层 | 表现 | 破解入口 | 详见 |
| :-- | :--- | :--- | :--- |
| 名字混淆 | 单字母类名与成员名、同名不同大小写类共存（`DU`/`Du`/`dU`/`com.DU`） | `javap -p -s` 逐份比对，按父类/接口/字段指纹定位真类 | [04-call-chain.md](04-call-chain.md) |
| 字符串加密 | `Lk` 内的静态密文数组 + `private static String b(int,int)` 解密器 | 定位主解密器，还原 `b(index,key)` 双密钥异或链 | [02-string-decrypt.md](02-string-decrypt.md) |
| 反射常量 | `com.c` 的 `a[]` / `b[]` 密文表 + 64 位 `key` 选择器 | 纯数据坐标反解：`index = key >>> 46`，`selector = (key >>> 42) & 63` | [03-zelix-key.md](03-zelix-key.md) |
| 配置与授权 | `config.json` 的 `huw` 字段、`aW`/`DU` 激活对话框 | Base64 → 72 字节二进制结构解析；Keccak-384 激活码算法 | [05-config-huw.md](05-config-huw.md)、[activation-algorithm.md](activation-algorithm.md) |

## 3. 复现前置

- **JDK 17**（`javap -p -c -s` 是主要取证手段），**Python 3.10+**（纯标准库，无第三方依赖）。
- 全程**只读**原 jar：先做副本（`finalshell.orig.jar`，SHA-256 见 [06-jar-patching.md](06-jar-patching.md)），
  所有导出物写在仓库目录内，不回写原始安装目录。

## 4. 开放问题（待补齐）

- ZKM 版本指纹与具体选项（`ZKM` 配置、是否开启 flow obfuscation / 字符串加密强度）。
- 混淆前后类名映射表的完整导出方式（`classes_list.txt` 的生成命令与字段说明）。
- 同类名不同大小写类的完整清单（`DU`/`Du`/`dU`、`lr`/`Lr`/`lR`/`LR` 之外的其它组）。
- 反编译工具选型对比（`javap` / CFR / Procyon / JADX 在同一批类上的可读性差异）。

## 5. 下一步

新手按 [INDEX.md](INDEX.md) 的阅读顺序；想直接动手复现，先跑 [../tools/finalshell_keygen.py](../tools/finalshell_keygen.py)
的 `--all` 与 `-v 4.6.5` 两种用法，再看第 06 章的 jar 补丁自测流程。
