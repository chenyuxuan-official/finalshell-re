# FinalShell 离线激活码算法（逆向自第三方算号器 `finashellpp.exe`）

> 本章是整个仓库的核心结论。算法**不是**网上流传的 `md5(机器码 + 盐)`，
> 而是 **Keccak-384**。这一个字之差，就是绝大多数人照着老公式算号失败的原因。

---

## 1. 一句话结论

```
激活码 = Keccak384( 前缀 + 机器码 + 后缀 ).hex()[12:28]
```

- `Keccak384` 是 **原版 Keccak**（Qt 的 `QCryptographicHash::Keccak_384`），
  **不是** NIST 的 `SHA3-384`。两者域分隔符不同（`0x01` vs `0x06`），结果完全不同。
- 输出 48 字节 → 转十六进制得 96 个字符 → 取第 12 位开始的 16 个字符。
- 机器码就是离线激活窗口里显示的那串，形如 `admin@0123456789abcdef` 或纯硬件哈希 `0123456789abcdef`。（本文示例机器码统一用脱敏值 `0123456789abcdef` / `admin@0123456789abcdef`；原始实测用的是作者本机机器码，已替换。）

---

## 2. 算法分支表

第三方算号器内置 4 组前后缀，并按输入的版本号自动选择。

**注意分支 0 是个例外**：它用的是 **MD5**、并且取的是 `[8:24]` 而不是 `[12:28]`。
其余三支才是 Keccak-384 + `[12:28]`。

| 分支 | 名称 | 哈希 | 前缀 | 后缀 | 取子串 |
| :--: | :--- | :--- | :--- | :--- | :--- |
| 0 | LEGACY | **MD5** | `2356` | `13593` | **`[8:24]`** |
| 1 | MODERN-A | Keccak-384 | *(空)* | `FF3Go(*Xvbb5s2` | `[12:28]` |
| 2 | MODERN-B | Keccak-384 | *(空)* | `b(xxkHn%z);x` | `[12:28]` |
| 3 | MODERN-C | Keccak-384 | *(空)* | `Scfg*ZkvJZc,s,Y` | `[12:28]` |

写成公式：

```text
分支 0 :  md5("2356" + 机器码 + "13593").hex()[8:24]
分支 1 :  keccak384(机器码 + "FF3Go(*Xvbb5s2").hex()[12:28]
分支 2 :  keccak384(机器码 + "b(xxkHn%z);x").hex()[12:28]
分支 3 :  keccak384(机器码 + "Scfg*ZkvJZc,s,Y").hex()[12:28]
```

### 版本号 → 分支的判定逻辑

还原自 exe 内 `0x1400050f0` 的判定函数，输入是 `(major, minor, patch)`：

```text
major == 4:
    minor == 5            -> 分支 2
    minor == 6            -> 分支 3
    其它                   -> 分支 1
major <= 2                -> 分支 0
major == 3:
    minor <= 8            -> 分支 0
    minor == 9:
        patch <= 5        -> 分支 0
        patch >  5        -> 分支 1
    minor >  9            -> 分支 1
major >= 5                -> 分支 1
```

---

## 3. 反汇编证据链

以下地址均为 `finashellpp.exe`（ImageBase `0x140000000`，`.text` 段 `0x140001000`）中的 RVA。

### 3.1 盐值常量位于 `.rdata`

| 文件偏移 | 虚拟地址 | 内容 | 长度 |
| :--- | :--- | :--- | :--: |
| `0x0acee` | `0x14000bcee` | `2356` | 4 |
| `0x0acf3` | `0x14000bcf3` | `13593` | 5 |
| `0x0acf9` | `0x14000bcf9` | `FF3Go(*Xvbb5s2` | 14 |
| `0x0ad08` | `0x14000bd08` | `b(xxkHn%z);x` | 12 |
| `0x0ad15` | `0x14000bd15` | `Scfg*ZkvJZc,s,Y` | 15 |

### 3.2 版本判定函数 `0x1400050f0`

```asm
; rcx -> int[3] {major, minor, patch}
1400050f0: mov  edx,[rcx]          ; major
1400050f2: cmp  edx,0x4
1400050f5: je   0x140005130        ; major == 4 分支
1400050f7: xor  eax,eax            ; 默认返回 0
1400050f9: cmp  edx,0x2
1400050fc: jle  0x140005108        ; major <= 2 -> 0
1400050fe: cmp  edx,0x3
140005101: mov  eax,0x1
140005106: je   0x140005110        ; major == 3 细分
140005108: ret                     ; major >= 5 -> 1

140005110: mov  edx,[rcx+4]        ; minor
140005113: xor  eax,eax
140005115: cmp  edx,0x8
140005118: jle  0x140005108        ; minor <= 8 -> 0
14000511a: cmp  edx,0x9
14000511d: mov  eax,0x1
140005122: jne  0x140005108        ; minor != 9 -> 1
140005124: xor  eax,eax
140005126: cmp  [rcx+8],0x5        ; patch
14000512a: setg al                 ; patch > 5 -> 1
14000512d: ret

140005130: mov  eax,[rcx+4]        ; minor
140005133: cmp  eax,0x5
140005136: je   0x140005150        ; minor == 5 -> 2
140005138: cmp  eax,0x6
14000513b: sete al
14000513e: movzx eax,al
140005141: lea  eax,[rax+rax+1]    ; minor == 6 -> 3，否则 -> 1
140005145: ret
140005150: mov  eax,0x2
140005155: ret
```

### 3.3 哈希计算函数 `0x1400051f0`

```asm
140005210: call [0x1400118a4]      ; QString -> QByteArray(UTF-8)
140005223: mov  r8d,0x9            ; Qt::Keccak_384  <-- 关键
14000523b: call [0x1400117ec]      ; QCryptographicHash::hash(view, alg)
14000524f: call [0x140011904]      ; QByteArray::toHex()
140005272: call [0x14001189c]      ; QString::fromLatin1()
```

Qt 6 的算法枚举：

```text
Md4=0  Md5=1  Sha1=2  Sha224=3  Sha256=4  Sha384=5  Sha512=6
Keccak_224=7  Keccak_256=8  Keccak_384=9  Keccak_512=10
RealSha3_224=11 ... RealSha3_512=15
```

`r8d = 9` → **`Keccak_384`**。

### 3.4 取子串（四个分支各一段）

**MODERN 三支**共用 `mid(12, 16)`：

```asm
140005cb8: mov  r9d,0x10           ; n = 16
140005cbe: mov  r8d,0x0c           ; pos = 12
140005cc4: mov  rdx,rbx            ; this = hex 字符串
140005cc7: call [0x14001194c]      ; QString::mid(12, 16)
```

前面还有长度判断 `cmp QWORD PTR [rsp+0x160],0x1b`（27），
Keccak-384 的 hex 长 96 > 27，所以总是走 `mid(12,16)` 这条路径。

**LEGACY 分支**走的是另一段，`pos = 8`：

```asm
140005be7: jg   0x140005c90        ; 长度 > 27 时跳到 LEGACY 的取子串
...
140005c90: mov  r9d,0x10           ; n = 16
140005c96: mov  r8d,0x8            ; pos = 8   <-- 注意是 8
140005c9c: mov  rdx,rbp
140005ca7: call [0x14001194c]      ; QString::mid(8, 16)
```

这就是为什么 LEGACY 得到的是 `[8:24]`：MD5 的 hex 恰好 32 个字符，从第 8 位取 16 个刚好是中段。

### 3.5 导入表佐证

```text
_ZN18QCryptographicHash4hashE14QByteArrayViewNS_9AlgorithmE   QCryptographicHash::hash
_ZN7QString6appendE20QBasicUtf8StringViewILb0EE               QString::append(string_view)
_ZNK10QByteArray5toHexEc                                      QByteArray::toHex
_ZN7QString10fromLatin1E14QByteArrayView                      QString::fromLatin1
```

---

## 4. 交叉验证

`Keccak384` 的纯 Python 实现可用标准测试向量自检：

```text
Keccak-384("") =
2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b
2dd2b21362337441ac12b515911957ff
```

再拿网上流传已久的两个「已知正确」激活码对拍：

| 机器码 | 分支 | `Keccak384(code+salt).hex()[12:28]` | 与流传值 |
| :--- | :--: | :--- | :--: |
| `0123456789abcdef` | 1 | `929ae2afb3b2d11a` | ✅ 一致 |
| `admin@0123456789abcdef` | 1 | `e27411494afa527b` | ✅ 一致 |

> 注：表中机器码为**脱敏示例值**（非真实机器码），第 3 列按同一算法用它重算；「与流传值一致」的结论来自原始实测。

这两组对上是**强证据**：网上那些"md5 算号器"之所以能出正确结果，
是因为它们内部实现的其实是 Keccak-384，只是被误标成了 md5。

---

## 5. 使用

```bash
# 指定版本，自动选分支
python tools/finalshell_keygen.py "admin@0123456789abcdef" -v 4.6.5

# 列出全部 4 个分支（逐个粘贴到客户端试）
python tools/finalshell_keygen.py "admin@0123456789abcdef" --all
```

---

## 6. 客户端侧的证据：Keccak 从哪来

这是本章最容易被忽略、但最关键的一环。

**`finalshell.jar` 里没有 Keccak 实现。** 搜遍 17373 个 class，
连 keccak-f 的 iota 轮常量（`0x8000000080008008` 等）都找不到，也没有任何名为
`Keccak*` 的类。所以客户端不可能自己实现 Keccak。

那它的 Keccak 从哪来？答案在 **`<FINALSHELL_HOME>\lib-run\bcprov.jar`**（8.3 MB，BouncyCastle）：

```text
org/bouncycastle/crypto/digests/KeccakDigest.class
org/bouncycastle/jcajce/provider/digest/Keccak$Digest224.class
org/bouncycastle/jcajce/provider/digest/Keccak$Digest256.class
org/bouncycastle/jcajce/provider/digest/Keccak$Digest288.class
org/bouncycastle/jcajce/provider/digest/Keccak$Digest384.class   <-- 就是它
org/bouncycastle/jcajce/provider/digest/Keccak$Digest512.class
```

这条线索被三处独立证据串起来：

1. `finalshell.jar` 的 `MANIFEST.MF` 里写着 `Class-Path: lib-run/bcprov.jar` —— 客户端启动就带上 BC。
2. `finalshell.jar` 里的 `al.class` 导入了 `java/security/Provider` 并调用 `addProvider` —— 它在**注册 BouncyCastle 作为 JCA Provider**。
3. `finalshell.jar` 里的 `uD.class` 是一个枚举，成员恰好是
   `KECCAK_224 / KECCAK_256 / KECCAK_384 / KECCAK_512 / SHA3_224 … SHAKE256`，
   还带 `int d`（rate）和 `outputLen` 字段 —— 这是 BC `KeccakDigest` 的构造参数表。

于是客户端校验收敛成一件事：

```java
MessageDigest md = MessageDigest.getInstance("KECCAK-384");   // BC provider
String hex = toHex(md.digest((machineCode + salt).getBytes("UTF-8")));
boolean ok = hex.substring(12, 28).equals(inputCode);
```

**这跟 `finashellpp.exe` 的算法逐字节一致** —— 一个是 C++ 调 Qt 的
`QCryptographicHash::Keccak_384`，一个是 Java 调 BouncyCastle 的
`Keccak.Digest384`，底层都是同一个 keccak-f[1600] 置换、同样的 `0x01` 填充。

这也解释了为什么第三方算号器只靠一个纯文本盐 + Keccak 就能离线出码，
而不需要联网或私钥。

> 顺带排除一个常见误判：`lr.C(byte[])` 里确实调用了 `DigestUtils.md5`，
> 但那是**另一条链路**（用机器码播种 Random 生成 DES key，供 `lr.u/lr.J` 做
> 同步密码加解密），与激活码校验无关。别被它带偏。

---

## 7. 实测确认（已闭环）

**4.6.5 走分支 3（MODERN-C），盐为 `Scfg*ZkvJZc,s,Y`。已实测对上。**

对拍记录：

| 输入 | 我们算的 | 算号器输出 | 结果 |
| :--- | :--- | :--- | :--: |
| `admin@0123456789abcdef` + 版本 `4.6.5` | `a68b68ba533b731c` | `a68b68ba533b731c` | ✅ |

> 注：本表机器码与派生值为**脱敏示例值重算结果**；原始实测记录用的是作者本机机器码，「已实测对上」的结论不变。

同时用客户端自带的 BouncyCastle 独立复算，逐字节一致：

```text
input        = 0123456789abcdefFF3Go(*Xvbb5s2
BC Keccak384 = b189fabd5b27929ae2afb3b2d11a0bb4 708e5ebd31d3744bf5c930a37898f62e 0d48c3c74c54aefa82d6f0fe85e37839
python       = b189fabd5b27929ae2afb3b2d11a0bb4 708e5ebd31d3744bf5c930a37898f62e 0d48c3c74c54aefa82d6f0fe85e37839
[12:28]      = 929ae2afb3b2d11a
```

复算程序见 `analysis/BcCheck.java`（依赖 `<FINALSHELL_HOME>\lib-run\bcprov.jar`）。

### 各版本对应关系（实测/推导汇总）

| FinalShell 版本 | 应填版本号 | 分支 | 盐 | 备注 |
| :--- | :--- | :--: | :--- | :--- |
| ≤ 3.9.5 | `3.9.5` | 0 | 前缀 `2356` + 后缀 `13593` | LEGACY |
| 3.9.6 ~ 4.4.x | `4.0.0` | 1 | `FF3Go(*Xvbb5s2` | 社区最常用 |
| 4.5.x | `4.5.0` | 2 | `b(xxkHn%z);x` | |
| **4.6.x** | **`4.6.5`** | **3** | **`Scfg*ZkvJZc,s,Y`** | **已实测** |

> 注意：算号器里的「版本号」输入框决定用哪组盐，不是你装的客户端版本。
> 填错版本号就会得到能算出来但客户端不认的码。

---

## 8. 为什么还要改 hosts

第三方算号器的界面上除了「授权码」，还有 **「添加/修改 Hosts」** 和 **「回退 Hosts」** 两个按钮。

原因是：**激活状态不落盘**。实测观察：

- 激活成功后 `<FINALSHELL_HOME>\` 下**不会**产生任何授权文件；
- `config.json` 也没有新增字段（`huw` 每次启动都会变，与授权无关，详见 `05-config-huw.md`）；
- 因此会员状态只活在进程内存里，客户端一旦联网拿回服务端结论，本地判定就可能被覆盖。

把 FinalShell 的验证/升级域名在 hosts 里指到 `127.0.0.1`，等于切断这条回退通道。
具体域名清单、备份/回退流程与风险说明见 [`hosts-blocking.md`](hosts-blocking.md)。

> 副作用提醒：改 hosts 是**全局**的，会影响本机对这些域名的所有访问；
> 且备份文件 `hosts.backup` 丢失后无法自动回退。做实验时建议只针对单个域名验证，
> 不要一键全量改写。
