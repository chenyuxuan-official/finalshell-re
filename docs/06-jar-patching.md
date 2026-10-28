> 本章为原始分析报告（源文件：`REPORT-jar-patcher.md`，保留在仓库根目录以供其它流程引用）。

# final shell jar 修补工程 — 自测报告

## 1. 回滚基线（必做项）
| 项 | 值 |
|---|---|
| 源文件 | `<FINALSHELL_HOME>\finalshell.jar`（只读，未修改，未删除） |
| 副本 | `<REPO_ROOT>\finalshell.orig.jar`（49,174,505 B） |
| SHA-256 | `2FE4A3131E488C3B2C7E0BF59B1EDA9EC44DE1E12ECCEAF4989C4183A3228C67` |
| 一致性 | 副本与源文件哈希完全相同 |

回滚：任何时刻用 `finalshell.orig.jar` 重新生成补丁即可，原 jar 不在修补链路上。

## 2. jar_patcher.py（纯 Python，零依赖）
自实现的 class 文件解析器（常量池 tag 1/3/4/5/6/7/8/9–12/15–20，双槽 Long/Double、字段/方法/属性全量重建），
不依赖 ASM / javassist，不需要 JVM。

```
python jar_patcher.py --jar finalshell.orig.jar --class <类内部名> \
    --method "<方法名>:<描述符>" --value true|false|<int>|null --out out/x.jar
```
* `--class` 支持 `Lk` / `k/L`；`--method` 只给名字时若存在重载会报错并列出候选描述符。
* `--value` 按返回描述符自动选指令：`Z/B/C/S/I`→`iconst_*`/`bipush`/`sipush`/`ldc` + `ireturn`；
  `V`→`return`；引用→`aconst_null;areturn`；`J/F/D`→常量 0。
* 更新字段：`code_length`(u4)、`max_stack`(u2，重算)、`max_locals`(原值保留)、
  Code 属性 `attribute_length`(u4，整段重建)，`exception_table` 与 Code 子属性清空
  （原表条数、子属性个数会打印出来）。
* 输出打印：原字节码长度+hex、新字节码长度+hex、max_stack 变化、Code 属性长度变化。
* 安全约束：`--out` 与 `--jar` 相同直接报错；逐条目复制 jar，只有命中的 `.class` 被换。

## 3. 自测
### 3.1 全量用例（selftest.py，自动化）
扫描 jar 内 17373 个 class，筛出 449 个可修补的 `static ()Z` 方法，选用 `com/formdev/flatlaf/FlatLaf.isLafDark()Z`：

| 项 | 值 |
|---|---|
| 原始字节码 | 60 B `b803dbb8047c4c3b2b…99000e…03ac` |
| 新字节码 | 2 B `04ac`（`iconst_1; ireturn`） |
| max_stack | 2 → 1，max_locals 0 |
| Code 属性长度 | 61 → 14 |
| jar 变更条目 | 仅 `com/formdev/flatlaf/FlatLaf.class`（其余 17372 个字节级不变） |
| 新 class 重解析 | code = `04ac` ✔ |

`javap -c`（修补后 jar）：
```
public static boolean isLafDark();
  Code:
     0: iconst_1
     1: ireturn
```

### 3.2 JVM 级验证（`-Xverify:all`，不只是 javap）
```
java -Xverify:all -cp out;finalshell.orig.jar          Verify  ->  RESULT=false
java -Xverify:all -cp out;out/finalshell.selftest.jar  Verify  ->  RESULT=true
```
类格式与字节码校验全通过，无 VerifyError，行为按预期翻转。

### 3.3 其它用例
| 目标 | value | 结果 |
|---|---|---|
| `Ba.isCellEditable(II)Z`（实例方法、带参） | false | 20 B → `03ac`，max_locals 保持 5 ✔ |
| `CK.Z()Z` | true | 4 B → `04ac` ✔ |
| `CK.Z()Z` | 7 | 4 B → `1007ac`（`bipush 7; ireturn`）✔ |

## 4. 交付物
`finalshell.orig.jar`（基线）、`jar_patcher.py`、`selftest.py`、`Verify.java`、
`out/finalshell.selftest.jar`、`out/selftest.json`、本报告。

## 5. 注意事项
* 源 jar 内含重复条目 `module-info.class`，输出时按原顺序两写，读取取后者，JVM 侧已验证无影响。
* 清空 StackMapTable 合法前提：新方法体无跳转目标，隐式空栈映射表即可通过校验（`-Xverify:all` 已证实）。
* 目标方法若被 `final/synchronized` 修饰无需特殊处理；`abstract/native` 无 Code 属性会直接报错。
* 后续定位到目标方法（如 `Lk` 中的校验方法）后，只需换 `--class/--method` 参数即可。
