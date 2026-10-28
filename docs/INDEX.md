# docs/ 目录索引

> FinalShell 4.6.5 逆向笔记的入口。**按"新手 → 进阶 → 动手"三档读**，不要从难到易硬啃。
> 所有章节均已完成；第 01 章末尾列出仍待补齐的开放问题。

## 一、全部文档

| 文档 | 一句话摘要 | 状态 |
| :--- | :--- | :--: |
| [01-obfuscation.md](01-obfuscation.md) | 混淆总览：ZKM 四层保护（名字/字符串/反射常量/配置授权）与四个专题章节的对应关系。 | 骨架 |
| [../tools/activate.py](../tools/activate.py) | **一键激活**：算号 + 屏蔽云端校验，一条命令搞定。 | 入口工具 |
| [activation-algorithm.md](activation-algorithm.md) | **核心结论**：离线激活码 = `Keccak384(前缀+机器码+后缀).hex()[12:28]`，4 个算法分支与版本判定。 | 完整 |
| [02-string-decrypt.md](02-string-decrypt.md) | `Lk` 的字符串解密结构：主解密器 `private static String b(int,int)` 的完整算法与最小复现步骤。 | 完整 |
| [03-zelix-key.md](03-zelix-key.md) | ZKM key 解析报告：`com.c` 双表结构、key 的位段布局、`aW` 的 21 个 key 验证表与踩坑点。 | 完整 |
| [04-call-chain.md](04-call-chain.md) | `DU` / `lr` 静态逆向：同名不同大小写类如何辨别，`lr.C` 逐段解读与激活校验方法候选排序。 | 完整 |
| [05-config-huw.md](05-config-huw.md) | `config.json` 的 `huw` 字段拆解：72 字节结构、由谁读写、为什么改它伪造不出会员状态。 | 完整 |
| [06-jar-patching.md](06-jar-patching.md) | jar 补丁工程自测报告：回滚基线（SHA-256）、纯 Python 补丁器、自测结果与注意事项。 | 完整 |
| [hosts-blocking.md](hosts-blocking.md) | 第三方算号器改写的 10 个域名归属、工作流、备份回退，以及手动等价操作。 | 完整 |

## 二、阅读顺序

### 档 1 · 新手（先建立全局观，约 40 分钟）

1. [01-obfuscation.md](01-obfuscation.md) —— 先知道"哪四层保护、每层对应哪章"，别急着看汇编。
2. [activation-algorithm.md](activation-algorithm.md) —— 全仓唯一"一句话就能验证"的结论，先跑通它建立信心。
3. [05-config-huw.md](05-config-huw.md) —— 破除最常见的误解：改 `config.json` 改不出会员。

### 档 2 · 进阶（想看懂证据链）

4. [02-string-decrypt.md](02-string-decrypt.md) —— 字符串是怎么被解出来的（一切后续反编译的前提）。
5. [03-zelix-key.md](03-zelix-key.md) —— key 位段布局 + `resolve_key.py` 用法 + 已知坑。
6. [04-call-chain.md](04-call-chain.md) —— 从"解密后的字符串"走到"激活校验发生在哪个方法"。

### 档 3 · 动手（要自己复现 / 复用工具）

7. [06-jar-patching.md](06-jar-patching.md) —— 补丁链路与回滚基线；**先做副本，再打补丁**。
8. [hosts-blocking.md](hosts-blocking.md) —— 只在需要复现算号器行为时读；注意里面的风险与回退机制。
9. 回到仓库根目录跑工具（见下）。

## 三、配套代码与数据

| 路径 | 说明 |
| :--- | :--- |
| `tools/finalshell_keygen.py` | 激活码生成器（Keccak-384），支持 `--all` 与 `-v <版本>`；实测通过。 |
| `tools/resolve_key.py` | 64 位 key → 类成员名反解（对应第 03 章）。 |
| `tools/fk_string_decrypt.py` | 字符串表解密（对应第 02 章）。 |
| `tools/keccak.py` | 原版 Keccak-384 实现（**非** `hashlib.sha3`，域分隔符不同）。 |
| `tools/DumpStringTable.java` | 运行时导出字符串表用的 agent 侧工具。 |
| `data/lk_string_table.json` | 已还原的 `Lk` 字符串表（小体积数据，随仓库入库）。 |
| `data/yt_string_table.json` | `yT` 族字符串表（生成中，可能为空文件）。 |

## 四、根目录原始报告（与 docs/02–06 同源）

`Lk_decrypt_analysis.md`、`key_resolve_report.md`、`DU_lr_analysis.md`、`huw_analysis.md`、
`REPORT-jar-patcher.md` 是**原始报告**，已原样复制为 `docs/02`–`docs/06`（仅在顶部加了来源说明），
原文件保留在仓库根目录，以防其它流程按旧路径引用。**修改内容请只改 docs/ 下的副本**，避免两份漂移。
