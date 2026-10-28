# `finashellpp.exe` 静态逆向分析报告

- 样本：`<TOOL_DIR>\finashellpp.exe`
- 大小：62,976 字节（0xF600）
- SHA256：`0c2242e47715e880520452da644b47c7d870b117f2bd7100a37bb8a192c1afc1`
- MD5：`51d7f207c089a89fdbd11af1655fb482`
- imphash：`9ac4bc6de740add4c75ecbda839fcb21`
- 分析方式：**纯静态 / 只读**。样本未运行、未调试、未 dump、未注入；只以 `open(path,'rb')` 读字节。`<FINALSHELL_HOME>\` 只做了目录列举，未打开/未写入任何文件。
- 环境观察（如实记录）：分析期间系统里已存在一个同名 `finashellpp`（PID 31672）进程在运行，**不是本报告的分析脚本启动的**（本次未执行该 exe）；`<FINALSHELL_HOME>\finalshell.jar`、`config.json` 的 mtime 也是既存状态，非本次改动。

---

## 0. 一句话结论

这是一个用 **Qt 6.7 + MinGW-w64 (GCC 11.2.0)** 写的单窗口小工具，程序名/窗口标题 `finashell++`，做两件互不相关的事：

1. **（主功能）本地算号器**：用户输入 `版本号`（如 4.6.0）+ `机器码`，程序本地直接算出 16 位十六进制 `授权码`，**全程不联网、不读 `<FINALSHELL_HOME>` 下任何文件**（结论 a）。
2. **（辅助功能）改写 Windows hosts**：把 FinalShell 相关域名指向 `127.0.0.1`，并支持从 `.backup` 回退（结论 d，改的是系统文件而非 FinalShell 目录）。
3. 没有 `<FINALSHELL_HOME>` 下的 `finalshell.jar` 补丁、没有 `config.json` 写入、没有注册表写入、没有进程注入、没有网络请求（结论 b、c 均被排除）。

---

## 1. PE 结构

### 1.1 DOS / NT 头

| 项目 | 值 |
|------|-----|
| DOS 头 | `MZ`，`e_lfanew = 0x100`，DOS stub 64 字节（标准 MinGW stub：`This program cannot be run in DOS mode.`） |
| 签名 | `PE\0\0` |
| Machine | `0x8664`（AMD64） |
| NumberOfSections | 11 |
| TimeDateStamp | `0x6A88EB6B` → 2026-08-22 05:01:31Z（与文件 mtime 2026/8/22 13:01 一致，即"打包当时"的时间戳） |
| Characteristics | `0x0022` = `EXECUTABLE_IMAGE \| LARGE_ADDRESS_AWARE`（无 `RELOCS_STRIPPED`） |
| OptionalHeader.Magic | `0x020B`（PE32+） |
| Linker | 2.37（MinGW-w64 ld） |
| AddressOfEntryPoint | RVA `0x14B0`（image base `0x140000000` → `0x1400014B0`，位于 `.text` 内，是典型 `__tmainCRTStartup`） |
| ImageBase | `0x140000000` |
| SectionAlignment / FileAlignment | 0x1000 / 0x200 |
| SizeOfImage / SizeOfHeaders | 0x17000 / 0x400 |
| Checksum | `0x13664` |
| Subsystem | 2 = `WINDOWS_GUI`（无控制台） |
| DllCharacteristics | `0x0160` = `HIGH_ENTROPY_VA \| DYNAMIC_BASE \| NX_COMPAT`（有 ASLR、有 DEP；**无** CFG `0x4000`、无 SEH 保护位） |

### 1.2 数据目录

| 目录 | RVA / 大小 | 说明 |
|------|-----------|------|
| Export | 0 / 0 | **无导出表**（是 exe，不是 DLL） |
| Import | 0x11000 / 11976 | 8 个 DLL、209 个导入条目 |
| Resource | 0 / 0 | **完全没有资源节**（无 `.rsrc`）：无图标、无版本信息、**无 manifest** |
| Exception | 0xE000 / 1176 | `.pdata`（x64 展开信息） |
| BaseReloc | 0x16000 / 340 | `.reloc` |
| TLS | 0xBEA0 / 40 | 存在 TLS 目录，但 `AddressOfCallBacks = 0x140014038` 指向空表（`callbacks = []`），**无 TLS 回调** |
| Debug / LoadConfig / CLR / DelayImport | 0 / 0 | 均无（无 PDB 路径残留） |

### 1.3 节表（含熵）

| # | 节名 | RVA | 虚拟大小 | 原始偏移 | 原始大小 | 熵 | 含入口点 |
|---|------|-----|---------|---------|---------|----|---------|
| 0 | `.text` | 0x1000 | 0x8C80 | 0x400 | 0x8E00 | **5.833** | **是** |
| 1 | `.data` | 0xA000 | 0x140 | 0x9200 | 0x200 | 1.057 | |
| 2 | `.rdata` | 0xB000 | 0x1908 | 0x9400 | 0x1A00 | 4.259 | |
| 3 | `.qtversi` | 0xD000 | 0x10 | 0xAE00 | 0x200 | 0.159 | |
| 4 | `.pdata` | 0xE000 | 0x498 | 0xB000 | 0x600 | 3.473 | |
| 5 | `.xdata` | 0xF000 | 0x9E4 | 0xB600 | 0xA00 | 5.428 | |
| 6 | `.bss` | 0x10000 | 0x1A0 | — | 0 | 0.000 | |
| 7 | `.idata` | 0x11000 | 0x2EC8 | 0xC000 | 0x3000 | 5.125 | |
| 8 | `.CRT` | 0x14000 | 0x60 | 0xF000 | 0x200 | 0.287 | |
| 9 | `.tls` | 0x15000 | 0x10 | 0xF200 | 0x200 | -0.000 | |
| 10 | `.reloc` | 0x16000 | 0x154 | 0xF400 | 0x200 | 3.862 | |

### 1.4 加壳 / 混淆判定：**未加壳**

证据：

1. 节名是 MinGW-w64 GCC 的标准布局（`.text/.data/.rdata/.pdata/.xdata/.bss/.idata/.CRT/.tls/.reloc`）+ Qt 特有的 `.qtversi`（Qt 版本标记节）。**没有** `UPX0/UPX1/UPX2`、`.aspack`、`.themida`、`.vmp0` 等壳节名。
2. 入口点落在 `.text` 内（`0x1400014B0`），不在异常节；`.text` 熵 **5.83**，远低于压缩/加密节常见的 7.0+。
3. 无 overlay：最后一节结束偏移 `0xF600` == 文件大小 `0xF600`（无附加数据）。
4. 导入表完整可读（209 条），若加壳通常只剩 `LoadLibrary/GetProcAddress` 少量导入。
5. `.rdata` 里保留了大量 **GCC 注释字符串**：`GCC: (x86_64-posix-seh-rev3, Built by MinGW-W64 project) 11.2.0`（6 处），以及 `qt_version_tag_6_7`，说明是**原样发布的未混淆 Release 构建**。

---

## 2. 导入表（8 个 DLL / 209 条）

| DLL | 函数数 | 关键导入（节选） |
|-----|-------|------------------|
| `Qt6Core.dll` | 60 | `QCryptographicHash::hash(QByteArrayView, Algorithm)`、`QByteArray::toHex(char)`、`QString::mid(qsizetype,qsizetype)`、`QString::trimmed_helper`、`QString::toUtf8_helper`、`QString::fromUtf8/fromLatin1`、`QString::append`、`QRegularExpression`(ctor/match/captured/hasMatch)、`QString::split`、`QString::startsWith`、`QString::toIntegral_helper`、`QtPrivate::QStringList_contains`、`QFile`(ctor/open/close/copy/exists/remove)、`QTextStream`(ctor/readLine/atEnd/`operator<<`)、`QCoreApplication::setApplicationName/setOrganizationName`、`QDebug`、`QTimer::singleShotImpl` |
| `Qt6Gui.dll` | 4 | `QGuiApplication::clipboard`、`QClipboard::setText`、`QCursor` |
| `Qt6Widgets.dll` | 90 | `QApplication`、`QMainWindow`、`QLineEdit`(text/setText/clear/setReadOnly/setPlaceholderText/textChanged)、`QLabel`(setText/clear)、`QPushButton`、`QMessageBox::information/warning`、`QVBoxLayout/QHBoxLayout`、`QWidget::setStyleSheet` |
| `KERNEL32.dll` | 14 | `VirtualProtect`/`VirtualQuery`（MinGW 伪重定位自解码，启动期）、`GetCommandLineW`、`WideCharToMultiByte`、`Sleep`、临界区、`SetUnhandledExceptionFilter`、`TlsGetValue` |
| `msvcrt.dll` | 29 | `malloc/calloc/free/memcpy/memmove/strcmp/strlen/strncmp/fprintf/fwrite/exit/abort/signal/__initterm/_onexit` 等 CRT 启动件 |
| `SHELL32.dll` | 1 | `CommandLineToArgvW`（CRT 取 argv） |
| `libstdc++-6.dll` | 10 | `operator new/delete`、`std::bad_alloc` 相关 RTTI、`__gxx_personality_seh0` |
| `libgcc_s_seh-1.dll` | 1 | `_Unwind_Resume`（异常展开） |

**关键的"没有"**（作为行为判定的排除证据）：

- 没有 `CreateFileW/CreateFileA`、`WriteFile`、`MoveFile`、`CopyFile`、`DeleteFile`
- 没有 `WinExec`、`CreateProcess*`、`ShellExecute*`、`system`
- 没有 `RegOpenKey*` / `RegSetValue*` / `RegCreateKey*`
- 没有 `ws2_32.dll` / `wininet.dll` / `winhttp.dll` / `Qt6Network.dll`（同目录虽带了 `Qt6Network.dll`，但**本 exe 根本没导入它**）

文件读写全部通过 Qt 的 `QFile`/`QTextStream` 完成，所以只看 Win32 导入是看不到文件操作的——这也是本样本必须读字符串才能定位行为的原因。

---

## 3. 导出表 / 资源 / 其他

- **导出表**：无（`Export` 目录 RVA=0）。
- **资源目录**：无（`Resource` 目录 RVA=0，文件里连 `.rsrc` 节都不存在）→ 因此**没有 manifest，没有 `requestedExecutionLevel`**，程序不是"默认以管理员启动"的；改 hosts 失败时会弹"操作失败，请检查权限或日志。"（见 §6）。
- **TLS**：目录存在但回调数组为空。
- **PDB / 调试信息**：`Debug` 目录为 0，无路径泄露。

---

## 4. 字符串提取

- ASCII（≥4）：803 条 → `strings_ascii.txt`
- UTF-16LE：宽字符（中文 UI 文本）约 700 条 + 纯 ASCII 宽字符 23 条 → `strings_utf16.txt`、`facts.md`
  （两个提取脚本的切分粒度不同，条数会有少量差异，清单本身一致）

### 4.1 关键字符串清单（含虚拟地址，`0x140000000 + RVA`）

**（A）算号核心常量（都在 `.rdata`，紧邻排列）**

| 文件偏移 | 虚拟地址 | 内容 | 长度 | 角色 |
|---------|---------|------|------|------|
| 0x00A0EE | 0x14000BCEE | `2356` | 4 | LEGACY 前缀 |
| 0x00A0F3 | 0x14000BCF3 | `13593` | 5 | LEGACY 后缀 |
| 0x00A0F9 | 0x14000BCF9 | `FF3Go(*Xvbb5s2` | 14 | MODERN 盐 |
| 0x00A108 | 0x14000BD08 | `b(xxkHn%z);x` | 12 | V45 盐 |
| 0x00A115 | 0x14000BD15 | `Scfg*ZkvJZc,s,Y` | 15 | V46 盐 |
| 0x00A080 | 0x14000BC80 | `LEGACY` | 6 | 模式名 |
| 0x00A08E | 0x14000BC8E | `MODERN` | 6 | 模式名 |
| 0x00A09C | 0x14000BC9C | `V45` | 3 | 模式名 |
| 0x00A0A4 | 0x14000BCA4 | `V46` | 3 | 模式名 |
| 0x00A0B0 | 0x14000BCB0 | `^([0-9]+)\.([0-9]+)\.([0-9]+)$` | 30 | 版本号正则 |

**（B）hosts 改写相关**

| 文件偏移 | 虚拟地址 | 内容 |
|---------|---------|------|
| 0x009400 | 0x14000B000 | `C:/Windows/System32/drivers/etc/hosts` |
| 0x009426 | 0x14000B026 | `.backup`（备份后缀） |
| 0x00942E | 0x14000B02E | `default` |
| 0x009598 | 0x14000B198 | `127.0.0.1 `（注意末尾空格，长度 10） |
| 0x009590 | 0x14000B194 | `\s+`（切行/切字段正则） |
| 0x0095DF | 0x14000B1DF | `\n`（写回时行分隔符，0x0A 单字节） |
| 0x0094B3 | 0x14000B0B3 | `www.youtusoft.com` |
| 0x0094C5 | 0x14000B0C5 | `youtusoft.com` |
| 0x0094D3 | 0x14000B0D3 | `hostbuf.com` |
| 0x0094DF | 0x14000B0DF | `www.hostbuf.com` |
| 0x0094EF | 0x14000B0EF | `dkys.org` |
| 0x0094F8 | 0x14000B0F8 | `tcpspeed.com` |
| 0x009505 | 0x14000B105 | `www.wn1998.com` |
| 0x009514 | 0x14000B114 | `wn1998.com` |
| 0x00951F | 0x14000B11F | `pwlt.wn1998.com` |
| 0x00952F | 0x14000B12F | `backup.www.hostbuf.com` |

**（C）UI / 提示语（UTF-16）**

`finashell++`（窗口标题，长度 11）、`输入版本号和机器码，授权码会自动生成`、`版本号`、`请输入机器码`、`例如 4.6.0`、`4.6.0`、`请输入完整版本号，例如 4.6.0`、`机器码不能为空`、`授权码`、`生成结果将显示在这里`、`点击复制`、`点击此处复制`、`已复制`、`添加/修改 Hosts`、`回退 Hosts`、`Hosts 条目已更新。`、`已恢复原始 hosts 文件。`、`回退失败，备份文件不存在。`、`操作失败，请检查权限或日志。`、`成功`、`错误`、`invalid`
以及一条很长的 QSS 样式表（`#actionButton { background: #23a6a8; ... }`，主色 `#23a6a8`/`#168b8d`）。

**（D）Qt 元对象 / 类型信息**

`MainWindow`（`QMainWindow` 子类名）、`generateToken`、`copyToken`（两个槽名）、`7QObject/7QWidget/12QPaintDevice/11QMainWindow`。→ 说明源码里 `MainWindow` 有两个槽：生成与复制。

### 4.2 明确"搜不到"的关键词（同等重要的阴性证据）

| 关键词 | 结果 |
|--------|------|
| `finalshell`（小写全名，路径形态） | **不存在**。只有 `finashell++`（少一个 l，程序自己的名字） |
| `.jar` / `finalshell.jar` | **不存在** |
| `config.json` / `user_name` / `huw` | **不存在** |
| `http://` / `https://` / 任何 URL | **不存在** |
| `HKEY` / `Software\` / 注册表路径 | **不存在** |
| `md5` / `sha` / `keccak`（小写文本） | **不存在**（哈希算法只以**数字枚举常量**出现，见 §5.3，文本里没有任何算法名） |
| `<FINALSHELL_HOME>\` / `<FINALSHELL_HOME>/`（两种分隔符写法） / 任何盘符路径 | **不存在** |

---

## 5. 工作方式判定

### 5.1 逐项结论

| 假设 | 结论 | 判定依据 |
|------|------|---------|
| **(a) 本地算号器：机器码 → 激活码** | ✅ **成立（主功能）** | 见 §5.2、§6：UI 明确"输入版本号和机器码，授权码会自动生成"；`QCryptographicHash::hash` + `QByteArray::toHex` + `QString::mid` 的组合；4 组硬编码盐；结果直接 `QLabel::setText` 显示并可 `QClipboard::setText` 复制 |
| **(b) 直接改 `<FINALSHELL_HOME>` 下文件（jar 补丁 / config.json）** | ❌ **不成立** | 全文件搜不到 `finalshell`/`.jar`/`config.json`/`E:\` 任何路径；没有 `CreateFile/WriteFile/WinExec/ShellExecute`；`QFile` 的唯一写入目标是 hosts（§7） |
| **(c) 联网请求激活码** | ❌ **不成立** | 无 `ws2_32/wininet/winhttp/Qt6Network` 导入；无任何 URL/域名形式的 API 地址（唯一出现的域名全是 hosts 屏蔽列表）；无 socket 相关 Qt 类 |
| **(d) 其它** | ✅ **成立（辅助功能）** | 改写 `C:/Windows/System32/drivers/etc/hosts`，把 10 个域名指向 `127.0.0.1`，并支持 `.backup` 回退（§7） |

**所以准确描述是：(a) + (d)** —— 本地算号 + hosts 屏蔽官方校验/更新域名。两者组合成"离线激活"的完整链路：算号解决"要一个码"，hosts 解决"码被联网复核/被覆盖"。

### 5.2 算号链路的证据链（函数级）

| 地址 | 作用 | 关键指令/调用 |
|------|------|--------------|
| `0x140002950` | 读控件文本 / 清提示的小工具（含 `invalid` 字面量 0x14000B210；在 generate 槽里被调用两次，参数是 `版本号`、`机器码` 两个 QLineEdit 与各自的 `#error` 标签） | `QLineEdit::text` |
| `0x140003250` | **"生成"按钮槽（generateToken 的 lambda/包装）** | 先取版本号文本 → `call 0x140005320` 解析；`[rsp+0x2c]` 是解析成功标志，失败则 `call 0x140003140` 显示 `请输入完整版本号，例如 4.6.0`（0x14000B2F0，len 0x11）；再取机器码文本 → `QString::trimmed_helper` 去空白；长度为 0 则显示 `机器码不能为空`（0x14000B314）；否则 `call 0x140005670` 算号 → `QLabel::setText` 到"授权码"标签 |
| `0x140005320` | **版本号解析** | `QRegularExpression("^([0-9]+)\.([0-9]+)\.([0-9]+)$")` → `match` → 三次 `captured(i)` + `QString::toIntegral_helper` → 写入结构体 `{+0:major, +4:minor, +8:patch, +0xC:ok}` |
| `0x1400050f0` | **版本 → 模式（0/1/2/3）** | 见 §5.3 判定表 |
| `0x140005160` | 模式 → 名称字符串（`LEGACY`/`MODERN`/`V45`/`V46`） | 静态交叉引用未发现直接调用（疑被内联/未使用） |
| `0x140005670` | **算号主函数**，`(QString* ret, VersionStruct* v, QString const& machineCode)` | 按模式分支，四条路径见 §5.4 |
| `0x1400051f0` | **`keccak384_hex(QString const&) → QString`** | `QString::toUtf8_helper` → `QCryptographicHash::hash(view, 9)` → `QByteArray::toHex('\0')` → `QString::fromLatin1` |
| `0x140005a0e` | LEGACY 专用路径（内联 MD5） | `QString::fromUtf8("2356")` → `append(machineCode)` → `append("13593")` → `hash(view, 1)` → `toHex` → `fromLatin1` |

### 5.3 版本 → 模式 判定表（`0x1400050F0` 逐指令翻译）

```
major = v[0];  minor = v[1];  patch = v[2];
if (major == 4) {                     // 0x140005130
    if (minor == 5) return 2;         // V45  → 0x140005150
    if (minor == 6) return 3;         // V46
    return 1;                         // MODERN
}
if (major <= 2) return 0;             // LEGACY
if (major == 3) {                     // 0x140005110
    if (minor <= 8) return 0;         // LEGACY
    if (minor > 9)  return 1;         // MODERN
    return (patch > 5) ? 1 : 0;       // 3.9.p：p>5 走 MODERN
}
return 1;                             // major >= 5 → MODERN
```

| 版本示例 | 模式 | 算法 |
|---------|------|------|
| 2.9.9 / 3.8.0 / 3.9.5 | LEGACY | MD5 |
| 3.9.6 / 3.10.0 / 4.4.1 / 4.7.0 / 5.0.0 | MODERN | Keccak-384 + 盐 A |
| 4.5.x | V45 | Keccak-384 + 盐 B |
| **4.6.x（含目标的 4.6.5）** | **V46** | **Keccak-384 + 盐 C** |

### 5.4 四条分支的精确算法

记 `mc` = 用户输入的机器码经 `QString::trimmed()` 后的字符串，按 **UTF-8** 取字节（`QString::toUtf8`）；`hex()` = `QByteArray::toHex()` = **小写十六进制、无分隔符**。

| 模式 | 输入串 | 哈希 | 截断 | 代码位置 |
|------|--------|------|------|---------|
| LEGACY | `"2356" + mc + "13593"` | **MD5**（`Algorithm=1`） | `hex()[8 : 8+16]` | `0x140005A0E`（hash@`0x140005B4E`, mid@`0x140005C90`） |
| MODERN | `mc + "FF3Go(*Xvbb5s2"` | **Keccak-384**（`Algorithm=9`） | `hex()[12 : 12+16]` | `0x140005670`（hash@`0x140005B4E` 同函数内、mid@`0x140005CB8`） |
| V45 | `mc + "b(xxkHn%z);x"` | Keccak-384 | `hex()[12 : 12+16]` | `0x140005950`（mid@`0x140005CD8`） |
| V46 | `mc + "Scfg*ZkvJZc,s,Y"` | Keccak-384 | `hex()[12 : 12+16]` | `0x140005822`（mid@`0x140005CF8`） |

几个必须说清的细节（都是反汇编里读出来的，不是猜的）：

1. **哈希算法是数字枚举，不是文本**：`mov r8d,0x9` 传给 `QCryptographicHash::hash(QByteArrayView, Algorithm)`；`mov r8d,0x1` 是 MD5。Qt 6 的 `Algorithm` 枚举顺序为 `Md4=0, Md5=1, Sha1=2, Sha224=3, Sha256=4, Sha384=5, Sha512=6, Keccak_224=7, Keccak_256=8, Keccak_384=9, Keccak_512=10, RealSha3_*=11..14`，所以 **9 = Keccak_384**（原始 Keccak 填充 `0x01`，**不是** SHA3-384 的 `0x06`）。
2. **盐的拼接方向**：`QString::append` 的接收者是机器码那份拷贝（`r13` → 输入第 3 个参数），盐作为 `QBasicUtf8StringView{ptr,len}` 追加 → `mc` 在前、盐在后。LEGACY 例外，是 `前缀 + mc + 后缀`。
3. **截断是 `QString::mid(pos, len)`**：`mov r8d,0xC`（pos=12）、`mov r9d,0x10`（len=16）。有一段"若 digest 长度 ≤ 27 则 `mid(pos, -1)`"的兜底分支（`0x140005784/0x1400055xx` 处 `cmp QWORD PTR [obj+0x10],0x1b`），对 96/32 字符的摘要**永不触发**，属防御性代码。
4. **输入只做 `trimmed()`，不做大小写归一、不做分隔符剥离**：导入表里没有 `QString::toUpper/toLower/remove/replace/simplified`；`0x14000333C` 调用的是 `QString::trimmed_helper(QString const&)`。→ 机器码必须**原样**（含大小写）从 FinalShell 界面抄。
5. **输出就是纯 16 位小写 hex**，没有分组/插入 `-`、没有前后缀包装（`setText` 直接吃 `mid` 的结果）。

### 5.5 复现（已实现并可自检）

`keygen.py`（本目录）实现了上述四条分支：

```
python keygen.py --selftest          # Keccak-384 官方向量自检
python keygen.py 4.6.5 <机器码>       # 输出 mode=V46 / full_digest / token(16)
```

自检结果：`keccak384("")` 与 `keccak384("abc")` 命中官方 Keccak 向量；另外 `verify_keccak.py` 把填充换成 `0x06` 后与 `hashlib.sha3_384` 在 9 组长度（0/1/3/55/103/104/105/200/1000 字节，跨 RATE 边界）**逐字节一致**，证明海绵结构与置换实现正确，剩下唯一差异就是填充字节——即"Keccak 而非 SHA3"这一判定是可靠的。

示例（用来说明格式，不代表任何真实机器）：

```
version=4.6.5  mc=1A2B3C4D5E6F7788
  mode=V46
  full = 521113473f4edef78901a2ac3da46830e2f04b1af636d99dd9b017eeb024107ae69fdcb10b4071ff67cd6f5ab35634cc
  token= def78901a2ac3da4          # = full[12:28]

version=4.6.5  mc=1a2b3c4d5e6f7788   # 只改大小写，结果完全不同
  full = 9ddd992477962dcfb33539371132dd1c2a652ea66eb91975d0ff06baa8975ed53c6399cfe5338875656883c124bb5494
  token= 2dcfb33539371132

version=4.5.0  mc=1A2B3C4D5E6F7788  → V45   token=65f8fca34517ed09
version=3.9.5  mc=1A2B3C4D5E6F7788  → LEGACY token=17787699c8b02bd9   (md5 hex[8:24])
```

### 5.6 还缺什么才能"完全确认"

| 未确认项 | 为什么 | 怎么补 |
|---------|--------|--------|
| 算出的码在 FinalShell 4.6.5 上是否真的通过校验 | 按要求**没有运行**本 exe，也没有对 `<FINALSHELL_HOME>` 做任何激活尝试 | 人工把 token 填进 FinalShell 激活框试一次；或用 `javap`/反编译 `finalshell.jar` 里 `License` 相关类，比对"是否同一套 `keccak384(mc+salt)[12:28]`" |
| `Algorithm=9` 的 Qt 语义 | 依据 Qt 6 枚举顺序推断（未在本机 Qt 头文件里核对） | 用同目录 `Qt6Core.dll` 的调试符号/头文件 `qcryptographichash.h` 核对（Qt 6.7 中顺序与上述一致） |
| 机器码字符串的确切形态 | 程序只 `trimmed()`，因此"FinalShell 显示什么就吃什么" | 从 FinalShell 4.6.5 界面直接复制机器码（注意大小写） |
| `LEGACY/MODERN/V45/V46` 名称与官方术语的对应 | 只是作者的内部命名 | 无功能影响 |
| `0x140005160`（模式→名称）是否真被使用 | 未发现静态调用点 | 无功能影响 |

---

### 5.7 与目录内既有产物的相互印证（独立复算，结论一致）

本目录里已有更早一轮分析留下的产物，与本次从反汇编独立推导出的结论**完全一致**，可视为交叉验证：

| 既有文件 | 内容 | 与本次结论的关系 |
|---------|------|----------------|
| `finalshell_keygen.py` | 完整的 Python 算号器（含 `-v` 版本分支、`--all` 枚举分支） | 分支表、四条 `前缀/后缀`、`Keccak-384`、`hex[12:28]` 与我本报告 §5.3/§5.4 完全相同（唯一差别：它把 LEGACY 也写成 `[12:28]`，而按 `0x140005C90` 的 `r8d=0x8 / r9d=0x10`，LEGACY 实际是 **MD5 + `[8:24]`**） |
| `keccak.py` | 纯 Python Keccak（224/256/384/512），注释明确"原版 Keccak 0x01 而非 SHA-3 0x06" | 与我的 `keygen.py` 内实现同构，且都通过空串/`abc` 官方向量 |
| `BcCheck.java` / `BcCheck.class` | 用 **FinalShell 自带 `lib-run/bcprov.jar`** 的 `KeccakDigest(384)` 复算并打印 `[12:28]` | 这是对"Qt `Keccak_384` == BouncyCastle `KeccakDigest(384)`（原始 Keccak）"最直接的外部印证 |
| `finashellpp.disasm.txt` | 上一轮生成的 objdump 全量反汇编 | 与本次 `disasm.txt` 同源（本次加了 `--no-show-raw-insn` 便于脚本解析） |

两套独立推导得到同一公式，说明 §5.4 的算法还原是可靠的；剩下的不确定性只在"填进 FinalShell 是否被接受"这一层（§5.6）。

---

## 6. UI 结构（从导入 + 字符串 + QSS 重建）

- 窗口：`QMainWindow` 子类 `MainWindow`，标题 `finashell++`（`len=11`），主色 `#23a6a8`。
- 布局：`QVBoxLayout` + `QHBoxLayout`；控件 objectName 有 `title` / `subtitle` / `panel` / `fieldLabel` / `error` / `copyStatus` / `actionButton`（QSS 里逐个写死，可直接对上）。
- 两个 `QLineEdit`：
  - 版本号：placeholder `例如 4.6.0`，默认文本 `4.6.0`（所以默认走 V46）；
  - 机器码：placeholder `请输入机器码`，`setReadOnly(false)`；旁边一个只读的"授权码"输出区（`生成结果将显示在这里`）。
- 按钮：`生成`（→ `0x140003250`）、`复制`（→ `QClipboard::setText`，状态文字 `已复制`，**1500 ms**（`mov ecx,0x5dc`）后由 `QTimer::singleShotImpl` 复位为 `点击复制`）、`添加/修改 Hosts`、`回退 Hosts`。
- 版本号输入框默认文本为 `4.6.0`（`0x14000B42E`，5 字符），placeholder 为 `例如 4.6.0`（`0x14000B41C`）→ 打开即走 V46 模式。
- 槽名（Qt metaobject）：`generateToken`、`copyToken`。
- 反馈：成功/失败都走 `QMessageBox::information/warning` + 顶部 `#error` 标签。
- `QCoreApplication::setApplicationName/setOrganizationName` 有调用（`0x140002814/0x140002863`），推测用于 Qt 配置命名空间（不影响功能）。

---

## 7. 改文件行为（hosts）

### 7.1 目标路径

| 用途 | 路径 | 证据 |
|------|------|------|
| 主文件 | `C:/Windows/System32/drivers/etc/hosts` | 字符串 `0x14000B000`，被 `0x1400015B8 / 0x1400016A1 / 0x1400018F3` 引用 |
| 备份 | 上面的路径 + `.backup`（即 `...\etc\hosts.backup`） | `0x1400015B0` 做字符串拼接：hosts 路径 + `.backup`(0x14000B026) |

**没有**写入 `<FINALSHELL_HOME>` 下任何文件，也没有写注册表（无 `Reg*` 导入、无 `HKEY` 字符串）。

### 7.2 写入内容与流程

| 地址 | 行为 | 证据 |
|------|------|------|
| `0x140009A70` | **构造域名列表（10 项）**，`QStringList`（`mov r9d,0xa`） | 依次 `lea rdx` 到 0x14000B0B3…0x14000B12F 共 10 个域名 |
| `0x140002669` | 备份：`QFile::exists` + `QFile::copy(hosts, hosts.backup)`，失败提示 `Failed to create backup of hosts file.` | `0x140001957/0x140001967` 的 `exists/copy` |
| `0x140001A20` | 读 hosts（`open(0x11)` = `ReadOnly\|Text`），`QTextStream::atEnd/readLine` 逐行读；`QRegularExpression("\\s+")` 切字段；`QString::startsWith('#')`（`mov edx,0x23`）跳过注释行；用 `QtPrivate::QStringList_contains` 判断该行是否已属于屏蔽列表 → 得到"清理后的行集合" | `0x14000199D`（open 0x11）、`0x140001A0D`（readLine）、`0x140001D4E/0x140001D56`（`'#'` + startsWith） |
| `0x140001ECA` | 写回：`open(0x1A)` = `WriteOnly\|Truncate\|Text`，`QTextStream << QString << "\n"` 逐行输出 | `0x140001ECF`（`mov edx,0x1a`）、`0x140001F98`（`ls(QString)`）、`0x140001FCA`（`ls("\n")`，0x14000B1DF） |
| `0x140002180 / 0x1400022C1` | 新增条目构造：`"127.0.0.1 "`（0x14000B198，len 0xA）+ 域名 → `127.0.0.1 www.youtusoft.com` 这样的行，追加到写回内容 | 两处 `lea rax,[rip+...] # 0x14000b198` + `mov QWORD PTR [rsp+0xa0],0xa` |
| `0x140001749 / 0x1400017D4 / 0x14000184A` | 回退：`QFile::remove(hosts)` 后把 `.backup` 复制回 hosts；错误文案 `Failed to remove current hosts file.` / `Failed to restore backup to hosts.` / `Backup file does not exist. Cannot revert.` | `0x14000182E / 0x1400017C5 / 0x1400018A3` |
| `0x1400029C6 / 0x140002B08 / 0x140002D28` | 三个 UI 槽：成功 `Hosts 条目已更新。`/`已恢复原始 hosts 文件。`，失败 `操作失败，请检查权限或日志。`/`回退失败，备份文件不存在。` | 对应字符串 0x14000B218/0x14000B260/0x14000B238/0x14000B280 |

**被屏蔽的 10 个域名**（写入后形如 `127.0.0.1 <domain>`）：

```
www.youtusoft.com     youtusoft.com        hostbuf.com          www.hostbuf.com
dkys.org              tcpspeed.com         www.wn1998.com       wn1998.com
pwlt.wn1998.com       backup.www.hostbuf.com
```

这些正是 FinalShell 的作者站点/授权与更新域名族（`youtusoft` 为 FinalShell 官网，`hostbuf` 为其配套服务）。把它们打到 `127.0.0.1` 的效果是：FinalShell 的联网校验/更新/账号相关请求**连不上真实服务器**，配合本地算出的授权码即形成"离线授权"。

### 7.3 权限要求

程序**没有 manifest**（无 `.rsrc`），因此不是 `requireAdministrator`；非管理员运行时 `QFile::open(WriteOnly)` 会失败，程序弹的正是那句 `操作失败，请检查权限或日志。`。→ 实际使用必须"以管理员身份运行"。

### 7.4 副作用（技术层面）

- 覆盖式重写 hosts：会保留原文件的行（注释行原样保留），但**统一改成 `\n` 换行**、末尾格式可能变化；
- 只在 `hosts.backup` 不存在时才创建备份（`exists` 命中即跳过 `copy`），所以"回退"会退到**第一次**改写前的状态，而不是上一次；
- 屏蔽 `hostbuf.com` 会连带影响该域名下的其它服务访问（同一 hosts 文件对全系统生效）。

---

## 8. 交付物与证据文件索引

| 文件（`<REPO_ROOT>\analysis\`） | 说明 |
|--------------------------------------------|------|
| `exe_report.md` | 本报告 |
| `pe_analyze.py` | 纯标准库 PE 解析器（DOS/NT/节表+熵/导入/导出/资源/TLS/字符串），`python pe_analyze.py <exe> <outdir>` |
| `rawjson.json` | 解析出的完整结构化数据（头、节、导入、目录） |
| `sections.csv` / `imports.txt` / `exports.txt` / `resources.txt` | 节表 / 导入表 / 导出（空）/ 资源（空） |
| `strings_ascii.txt` / `strings_utf16.txt` | ASCII(≥4) 与 UTF-16LE(≥4) 全量字符串（含文件偏移） |
| `disasm.txt` | `objdump -d -M intel --no-show-raw-insn` 全量反汇编 |
| `objdump_h.txt` / `objdump_p.txt` | objdump 的节头/PE 头输出（交叉核对） |
| `xrefs.txt` / `xrefs.txt.json` | IAT 槽位 → `DLL!函数`，以及每个导入函数的所有调用点 |
| `iat_refs.py` | 生成任意导入函数的引用清单（含 `mov rax,[rip+IAT]` 这类间接用法） |
| `strings_xref.py` / `strings_xref.txt` | 按函数归组的字符串引用表（证据表，§5/§7 的地址都出自它） |
| `refs.py` / `callers.py` / `win.py` | 反汇编检索小工具（按目标地址找引用 / 找 caller / 抽地址区间） |
| `keygen.py` | 算法重实现（4 分支 + 模式判定 + Keccak-384 自实现 + 自检） |
| `verify_keccak.py` | 海绵结构交叉校验（填充换 0x06 与 `hashlib.sha3_384` 对比） |
| `facts.md` | 报告用数据块（节表/导入表/关键字符串地址/imphash 等） |

---

## 9. 一页速查

```
样本      finashellpp.exe  62,976 B  SHA256 0c2242e4...1afc1
性质      Qt6.7 + MinGW-w64 GCC 11.2.0 GUI 小工具，"finashell++"
未加壳    入口 0x140001000+.text 内，.text 熵 5.83，无 UPX/无 overlay/无 .rsrc/无 PDB
导入      8 DLL / 209 条；关键：QCryptographicHash::hash、QByteArray::toHex、QString::mid、
          QFile/QTextStream、QRegularExpression、QClipboard；无 CreateFile/WinExec/Reg*/网络
字符串    无 finalshell 路径、无 .jar、无 config.json、无 URL、无注册表 → 不碰 <FINALSHELL_HOME>
主功能    本地算号：版本号 + 机器码 → 16 位小写 hex 授权码
  4.6.x   token = keccak384_hex( mc + "Scfg*ZkvJZc,s,Y" )[12:28]      ← 目标 4.6.5
  4.5.x   token = keccak384_hex( mc + "b(xxkHn%z);x"   )[12:28]
  其余≥3.9.6 token = keccak384_hex( mc + "FF3Go(*Xvbb5s2" )[12:28]
  ≤3.8 / 3.9.p≤5 token = md5_hex( "2356" + mc + "13593" )[8:24]
  mc 仅 trimmed()，区分大小写
辅助功能  重写 C:/Windows/System32/drivers/etc/hosts，把 10 个 youtusoft/hostbuf/wn1998 等域名
          指向 127.0.0.1；备份 hosts.backup；可回退；需管理员权限
未运行    样本未执行，<FINALSHELL_HOME> 未改动；算法结论为静态还原 + 自实现交叉校验
```
