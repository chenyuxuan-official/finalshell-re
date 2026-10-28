> 本章为原始分析报告（源文件：`huw_analysis.md`，保留在仓库根目录以供其它流程引用）。

# FinalShell 4.6.5 `config.json` → `huw` 字段分析

分析目录：`<REPO_ROOT>`
原始样本：`<FINALSHELL_HOME>\config.json`（只读，全程未修改）
JDK 17 / Python 3.13；jar 已只读解包到 `extract\`（17,373 个 class）。

---

## 1. `huw` 的字节结构

```
b64 : VEFfWy9vPGkuSSRtS1oQNhtraxxjQypZIldPZ0sJawY1XTRHMQc4OBcgbgtNHB5n0pnMl/UkrpkwSyoeiZcKnUa8Tn/BbnQD
len(base64) = 96  →  raw = 72 字节（无 padding，标准 Base64）
hex : 54415f5b2f6f3c692e49246d4b5a10361b6b6b1c63432a5922574f674b096b06355d34473107383817206e0b4d1c1e67
      d299cc97f524ae99304b2a1e89970a9d46bc4e7fc16e7403
```

| 指标 | 值 |
|---|---|
| 原始长度 | 72 字节 = 9×8 = 4.5×16 |
| 可打印 ASCII 字节 | 45 / 72（62%） |
| ≥0x80 字节 | 10 / 72 |
| 控制字节 | 17 / 72 |
| 字节熵 | 5.69 bit/byte（随机应≈6.1） |
| 前 8 字节 | `TA_[/o<i`（ASCII） |

判断：

* **不是裸 AES-CBC 密文**。AES 分组 16 字节，72 不是 16 的整数倍；DES 分组 8 字节，72 正好 9 组。
* **没有独立的 IV/盐字段**。整段就是一个 base64 字符串，前 8 字节是 ASCII 可打印字符（`TA_[/o<i`，另两个复现样本是 `DU8hWCUF`、`ZGQ3MGw+`），随机盐不会长这样，更像**魔数/前缀**；因此不构成「salt|iv|ciphertext」的三段式。
* 熵 5.66–6.00、可打印率 62%、高字节只占 14% —— 这与「强分组密码密文」不符（应为均匀分布），更符合**自定义流式混淆（ASCII 明文 ⊕ ASCII 密钥/异或流）**；类里确实有 `Lk.i/Lk.Y` 这类 `([B[B)[B` 工具方法可承载该 XOR/混合变换。
* 结论：**8 字节前缀 + 64 字节载荷**的划分（64 = 4×AES 块 = 8×DES 块）在长度上自洽，但载荷本身统计特征不支持它是纯 AES/DES 密文。

## 2. `huw` 由哪个类读写（结构性搜索）

**静态字符串检索全部落空**，原因已定位：

1. 全量 14,271 个可解析 class 的原始字节里 grep `huw` / `config.json` / `rltime` / `user_name` → **0 命中**。jar 的字符串常量被逐类加密（ZKM/Stringer 风格：每个类自带 `private static String[] a/b` + `private static String a(int,int)` 解密函数，如 `to`、`lg`、`lr`、`Qr`）。
2. 因此改为在**运行时解密后的常量**上检索：加载 agent 反射遍历已加载类的 `String[] a/b` 静态字段，得到 4,488 个类 / 29,546 条明文常量（`decrypted_all3.txt`）。
   其中 `config.json` 只出现在 `dD`、`Yf`、`aJ`；`config.json` 的 54 个 key（含 `rltime`、`secret_key_list`、`sync_password`）全部集中在 `yT`(类名前 `yt`)。**但明文常量里没有 `huw`** → 该 key 不在 Java 常量池里，是运行时拼/由内存对象写出。
3. 调用图同样断链：扫描全部 class 的 `CONSTANT_Class` 引用，`to` / `lg` / `lr` / `Qr` 的 caller **只有它自己** —— 说明加解密工具是被**反射调用**的（根包 `Lk` 就是一个反射垫片：`Method.invoke` / `Field.get/set` / `InvocationTargetException`），静态 xref 天然查不到。

候选类清单（按可能性排序，均为实测存在）：

| # | 类 | 依据 |
|---|---|---|
| 1 | `dD` | 唯一拼接 `user.dir`/`user.home` + `/config.json` 路径并读写配置的类 |
| 2 | `yT`(yt) | 配置 Bean，227 个常量覆盖 config.json 全部 key（含 `sync_password`），`huw` 的宿主 |
| 3 | `Yf` | `config.json` + `_connect_config.json` 双配置读写 |
| 4 | `aJ` | 同上，另一处 `_connect_config.json` 读写点 |
| 5 | `to` | DES 工具：`R/b`(加/解密)、`t/x`(Cipher 工厂，DESKeySpec)，配置值加解密首选落点 |
| 6 | `lg` | `s/A`(byte[],byte[]) 加解密 + `e/W`(byte[]) 编解码 |
| 7 | `lr` | `u/J` 加解密 + `C`(MD5) |
| 8 | `Qr` | `x/C` 加解密 + `M/R`(字符串摘要) |
| 9 | `Fc` / `Ln` | 云端同步：同步密码设置/校验（"无法解密,请尝试更新到最新版"）、syn/ack 握手 |
| 10 | `Lk` | 反射调度器，掩盖真实调用链（`invoke`/`get`/`set`） |

## 3. `huw` 是硬件指纹还是会员信息？——都不是

**实测：每次启动都重新生成。** 把 jar + config 复制到隔离目录 `run\`，用同一 JDK 启动 `st` 主类三次，配置文件里的 `huw` 三次全不相同（长度恒为 72 字节、结构一致）：

| 样本 | base64 | 熵 | 可打印 |
|---|---|---|---|
| 原始 `<FINALSHELL_HOME>\config.json` | `VEFfWy9vPGkuSSRtS1oQ…` | 5.69 | 45/72 |
| 第 1 次启动 | `DU8hWCUFN1MTIjsbb1JE…` | 6.00 | 39/72 |
| 第 2 次启动 | `ZGQ3MGw+bQYMHBw4SWEr…` | 5.66 | 45/72 |

* **不是硬件指纹**：硬件指纹必稳定，此处每次启动都变。
* 顺带查明：配置路径锚定在 **jar/安装根目录**（`dD`：`user.dir`/`user.home` + `/config.json`），在 `run\` 里启动同样会回写安装目录的 `config.json`，并在 `backup\app_config\<毫秒时间戳>.json` 留快照（本机已产生 3 份，各 4067 字节）。实验后已把 `huw` 逐字节还原为原值（`VEFfWy9v…bnQD`，文件长度仍 4067），仅 mtime 变化。
* **不是会员等级/到期时间**：明文常量里全库检索 `激活/试用/到期/序列号/注册码/vip/member/购买/收费/价格/专业版` → **0 命中**；`expire` 只有 `command_input_cache_expire_time` 和 `Li` 的 `Server version expired,update to continued use.`（服务端版本过期提示）。配置里唯一带"凭据"性质的字段是 `sync_password`（用户自设的云端同步口令）。
* 但它有**稳定语义**：长度固定 72、前缀固定为可打印魔数、结构分两段（≈48 字节 ASCII 化区 + 24 字节高熵区）→ 典型的**每次运行随机生成的会话/混淆令牌**（宿主是配置 Bean，启动时写入，退出/下次启动被覆盖）。

## 4. 能否改 `config.json` 伪造会员状态？

**不能，而且不是"绕过难"的问题 —— 是这一层根本没有可伪造的会员状态。**

证据链：

1. **写入即覆盖**：任何对 `huw` 的手工修改，在下次启动时会被配置文件写回流程覆盖掉（上面三次实验即为该流程的实测复现；即使从复制目录启动，回写的仍是安装根目录的 `config.json`，另有 `backup\app_config\` 时间戳快照）。
2. **判定在内存**：`huw` 由配置 Bean（`yT`）在启动时构造并序列化，真实值只存在于进程内存的单例里，磁盘文件只是它的落盘副本，不是判定依据。
3. **没有本地会员判定**：Java 层不存在会员/授权分支（全库无相关常量），功能开关不依赖 `huw`；`huw` 也不参与任何"等级/到期"计算。
4. **真正的门在服务端 + 同步口令**：唯一的"权限"语义是云端同步（`Fc`/`Ln`/`F7`/`z2`），其授权是高强度口令派生的同步密码 → 数据在服务端握手（syn/ack）与本地解密双重校验，客户端侧只做解密校验（"同步密码错误"/"无法解密,请尝试更新到最新版"）；另有 `Li` 的 `Server version expired` 说明版本闸门在**服务端响应**。
5. jar 内无签名校验拦截 `config.json`（修改文件后程序正常启动、正常重写），所以"改文件被拒"也不是 jar 校验造成的 —— 是**值本身没有持久意义**。

**结论**：`huw` = 每次启动重生的一次性混淆令牌（8 字节可打印魔数前缀 + 64 字节载荷），既非硬件指纹也非会员凭证；改 `config.json` 既不能提权也不能伪造会员，因为它没有承载任何会员位，且会被启动流程重写。会员/授权类判定（若存在）发生在服务端响应与内存中的同步口令校验层，而不是这份 JSON。

---

### 复现命令

```powershell
# 1. 解码
python -c "import base64,json;print(base64.b64decode(json.load(open(r'<FINALSHELL_HOME>\config.json',encoding='utf-8'))['huw']).hex())"

# 2. 解包 + 常量解析（本目录已生成 cp_index.json）
python cparse.py extract

# 3. 加密类方法签名
javap -p -c -classpath extract to lg lr Qr

# 4. 启动两次对比 huw（隔离目录，不动 <FINALSHELL_HOME>）
java -cp finalshell.jar;lib-run/* st     # run\ 下执行，之后比对 run\config.json
```

产物：`decrypted_all3.txt`（4,488 类 / 29,546 条明文常量）、`cp_index.json`（全量 class 常量池索引）、`dis_{to,lg,lr,Qr}.txt`（反汇编）、`run/`（隔离运行副本）。
