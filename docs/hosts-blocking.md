# Hosts 改写：那 10 个域名是谁的、为什么要打到 127.0.0.1

> 本文对应 `finashellpp.exe`（第三方算号器，Qt6 GUI）里「添加/修改 Hosts」与「回退 Hosts」两个按钮。
> 域名清单出处：该 exe `.rdata` `0x14000B0B3`–`0x14000B12F` 共 10 条字符串常量，
> 由 `0x140009A70` 处构造 `QStringList`（`mov r9d,0xa`）一次性装载。
> 其余常量：hosts 路径 `0x14000B000`、备份后缀 `.backup` `0x14000B026`、写回前缀 `127.0.0.1 ` `0x14000B198`。
> 反汇编细节见 [analysis/exe_report.md §7](../analysis/exe_report.md)。

---

## 1. 域名归属一览

FinalShell 的作者站点是 **hostbuf.com**；**youtusoft.com** 是同一作者的关联/早期主体；
**wn1998.com / tcpspeed.com / dkys.org** 是这套产品历史上轮换用过的域名。
这 10 条不是随机凑的，就是客户端里硬编码的「官网 / 授权校验 / 更新检查 / 账号」域名族。

| # | 域名 | 在 FinalShell 中的角色 | 归属 | 置信度 |
| :--: | :--- | :--- | :--- | :--- |
| 1 | `www.hostbuf.com` | **官网主站**（FinalShell 下载、版本公告） | hostbuf（作者自有） | 已确认 |
| 2 | `hostbuf.com` | 主域，官网/服务入口 | hostbuf（作者自有） | 已确认 |
| 3 | `backup.www.hostbuf.com` | 官网的备份/镜像子域，更新检查的备用地址 | hostbuf（作者自有） | 推测（子域命名与备份语义一致） |
| 4 | `www.youtusoft.com` | 关联公司站点，**授权/账号校验接口所在域** | 与 hostbuf 同一主体 | 推测（同作者关联主体，多份离线激活教程把它与 hostbuf 一起屏蔽） |
| 5 | `youtusoft.com` | 同上，主域 | 与 hostbuf 同一主体 | 推测 |
| 6 | `www.wn1998.com` | **历史域名**，早期版本官网/授权域 | 同作者早期域名 | 推测 |
| 7 | `wn1998.com` | 同上，主域 | 同作者早期域名 | 推测 |
| 8 | `pwlt.wn1998.com` | 历史域名下的**接口子域**（`pwlt` 疑为 license 相关的服务前缀） | 同作者早期域名 | 推测 |
| 9 | `tcpspeed.com` | **历史域名**，作者另一款网络加速类产品/早期品牌 | 同作者早期域名 | 推测 |
| 10 | `dkys.org` | **历史域名**，早期授权/更新域 | 同作者早期域名 | 推测 |

### 来源说明

- `www.hostbuf.com` / `hostbuf.com` 是 FinalShell 官网，搜索结果直接给出官网入口：[hostbuf.com](https://www.hostbuf.com/)、[Windows 版下载页](https://www.hostbuf.com/c/36.html)、[Linux 版下载页](https://www.hostbuf.com/c/37.html)——域名与产品一一对应，无需推测。
- 第三方离线激活教程给出的 hosts 规则与本文这 10 条**完全一致**（顺序都相同），可作为该清单用途的旁证：
  [\[FinalShell\] 离线激活 · blog.jiang.in](https://blog.jiang.in/archives/08affb34-5651-4850-b40a-9c33050981e8)、
  [分享 FinalShell 离线激活 屏蔽联网验证 host · linux.do](https://linux.do/t/topic/705016)。
- `youtusoft.com` 的 SEO/备案查询结果指向国内同一运营主体（[chinaz SEO 查询](https://seo.chinaz.com/http:/www.youtusoft.com/)、[youtusoft.cn 备案查询](https://ip.cn:8443/beian/youtusoft.cn.html)）。把它与 hostbuf 绑在同一主体的依据是「同作者关联公司 + 教程里成对出现」，**属于推测**：备案主体名与作者实名未必一致，只能确认「与 FinalShell 运营方相关」。
- `wn1998.com` / `tcpspeed.com` / `dkys.org` 没有公开的一手材料能证明与 FinalShell 的股权关系，判据是：**它们被写进 FinalShell 客户端的硬编码域名单**，且属于客户端早已不再使用、但仍留在屏蔽列表里的历史域名。**归属结论为推测**，唯一确定的事实是「客户端会向这些域发请求」。
- 站点可达性提示：分析机 `www.hostbuf.com` 解析到非公网地址，无法直接抓取页面正文；上述官网结论依据搜索引擎索引与下载页标题，而非页面快照。

---

## 2. 工具的工作流

```
                    ┌──────────────────────────────┐
                    │ 管理员运行 finashellpp.exe    │
                    └──────────────┬───────────────┘
                                   │ 点「添加/修改 Hosts」
                                   ▼
        ┌──────────────────────────────────────────────────┐
        │ 1. 若 hosts.backup 不存在 → copy(hosts, .backup)  │
        │ 2. 逐行读 hosts（跳过 '#' 注释行）                 │
        │ 3. 丢弃已属于屏蔽列表的行（QStringList::contains） │
        │ 4. 追加 10 行 "127.0.0.1 <domain>"                │
        │ 5. 以 WriteOnly|Truncate 整体写回                 │
        └──────────────────────────────────────────────────┘
                                   │
                                   ▼
        DNS 解析被本地表覆盖 → 10 个域全部指向 127.0.0.1（本机）
```

关键点：

1. **改写的是解析结果，不是程序逻辑**。hosts 优先于 DNS，客户端拿到的 IP 是 `127.0.0.1`，连接要么被拒绝（本机无监听），要么打到自己机器上的任意服务。
2. **不修改 FinalShell 的任何一个字节**。不碰 `<FINALSHELL_HOME>\`、不碰 jar、不写注册表（见 §6）。因此不存在文件完整性/签名校验的对抗问题。
3. **幂等**：重复点按钮不会叠加行，第 3 步会把已有的屏蔽行清掉再重新追加，所以文件不会越写越长。
4. **回退是「整体还原」**，不是「删掉这 10 行」——见 §3。

### 为什么这一步能让离线授权生效

FinalShell 的会员状态**不落盘**：激活成功后 `<FINALSHELL_HOME>\` 下不产生授权文件，`config.json` 也不新增任何字段（已实测确认）。这意味着

- 客户端每次启动/联网时，都要向服务端确认「这台机器是不是会员」；
- 本地算出的授权码只是让**本地判定**通过，一旦联网拿到服务端结果，服务端说不是会员，本地判定就被覆盖；
- 把授权/更新域打到 `127.0.0.1`，客户端拿不到服务端结论，只能退回本地判定 → 离线授权得以保持。

换句话说：**它没有破解校验逻辑，而是让校验的另一端消失**。这也是为什么「不产生授权文件、config.json 无新增字段」这条观察如此重要——如果会员状态是落盘的，改 hosts 就没意义了。

---

## 3. 备份与回退机制

### 3.1 备份

| 项 | 值 |
| :--- | :--- |
| 原文件 | `C:/Windows/System32/drivers/etc/hosts`（`0x14000B000`） |
| 备份文件 | 原路径 + `.backup` → `C:\Windows\System32\drivers\etc\hosts.backup`（后缀常量 `0x14000B026`，`0x1400015B0` 处拼接） |
| 创建时机 | **仅当 `hosts.backup` 不存在时**（`QFile::exists` 命中即跳过 `QFile::copy`） |
| 失败文案 | `Failed to create backup of hosts file.`（`0x14000B148`） |

**这条「仅首次备份」的特性很重要**：第二次、第三次改写都不会刷新备份，所以「回退」退回到的是**第一次改写之前**的原始状态，而不是「上一次操作之前」。如果你在两次操作之间手动编辑过 hosts（比如加了别的条目），回退会把那段手动编辑一起丢掉。

### 3.2 回退

回退不是「删掉自己加的行」，而是**删掉当前 hosts，再把备份整个复制回来**：

```
remove(hosts)  →  copy(hosts.backup, hosts)
```

对应的三个错误分支（也就是按钮会弹的三种失败）：

| 错误分支 | 触发条件 | 常量地址 | UI 提示 |
| :--- | :--- | :--- | :--- |
| **① 备份不存在** | `hosts.backup` 缺失（从未成功备份，或被清理工具/杀软删掉） | `0x14000B038` `Backup file does not exist. Cannot revert.` | `回退失败，备份文件不存在。` |
| **② 删除当前 hosts 失败** | 文件被占用（编辑器/安全软件持有句柄）、ACL 只读 | `0x14000B068` `Failed to remove current hosts file.` | `操作失败，请检查权限或日志。` |
| **③ 备份回写失败** | 复制回来时磁盘/权限出错（少见，通常发生在 ② 之后处于「hosts 已被删掉」的中间态） | `0x14000B090` `Failed to restore backup to hosts.` | `操作失败，请检查权限或日志。` |

写入方向另有两个错误分支（不在回退路径上，但同属这套流程）：

| 错误分支 | 触发条件 | 常量地址 |
| :--- | :--- | :--- |
| 读 hosts 失败 | `open(ReadOnly)` 失败，文件不存在或被锁 | `0x14000B170` `Cannot open hosts file for reading.` |
| 写 hosts 失败 | `open(WriteOnly\|Truncate)` 失败——**绝大多数情况就是没提权** | `0x14000B1A8` `Cannot open hosts file for writing. Check permissions.` |

**②→③ 是最危险的中间态**：`remove` 成功、`copy` 失败，此时系统里**没有 hosts 文件**（Windows 会用空表继续跑，所有本地解析规则消失），只能手工从 `hosts.backup` 复制回来，或用 `C:\Windows\System32\drivers\etc\hosts.bak`/系统还原点代偿。

---

## 4. 风险与副作用（用之前必读）

1. **不是只影响 FinalShell，是全系统生效。** hosts 是机器级解析表，浏览器、其它客户端、命令行工具、容器外的所有进程都会看到 `127.0.0.1`。
   - `hostbuf.com` 一旦被打掉，同域下的官网、文档、下载、公告全部不可达；
   - `youtusoft.com` 若还承载别的主体业务，也会一起断。
2. **备份文件丢失即失去自动回退能力。** `hosts.backup` 被安全软件清理、被「系统优化」工具删除、或被其它 hosts 管理工具覆盖后，按钮只会弹「备份不存在」，此时只能手工重建。**动手前请自己另存一份副本到仓库外的临时目录。**
3. **需要管理员权限。** 该 exe 没有 manifest（无 `.rsrc`，不是 `requireAdministrator`），所以不提权也能启动，但写 hosts 一定失败，报的就是 `Cannot open hosts file for writing.`。必须右键「以管理员身份运行」。
4. **换行/编码被统一改写。** 写回时以 `\n` 逐行输出，原文件若是 CRLF 或带 BOM，格式会变；注释行内容保留但排版可能变化。少数对 hosts 编码挑剔的软件会因此异常。
5. **会掩盖真实的 DNS 故障。** 排查网络问题时忘了自己改过 hosts，会得到完全误导的结论。
6. **可能触发安全软件告警。** 修改 hosts 是恶意软件常见行为，EDR/杀软对 `drivers\etc\hosts` 的写入有专门监控，操作可能被拦截或记录。
7. **没有白名单/粒度控制。** 工具是「全量 10 条一把梭」，不能只屏蔽其中一个域，也不能排除某个子域。

---

## 5. 手动等价操作（推荐：只测单个域名）

工具是全量改写；如果你只想**验证某个域名是否真的是校验入口**，请只针对单个域名做临时测试，测完立刻还原。下面两段都做了「先备份、只加一行、可一键撤回」。

### 5.1 PowerShell（管理员）

```powershell
# Run as Administrator. Single-domain test with explicit backup + rollback.
$hosts  = "$env:SystemRoot\System32\drivers\etc\hosts"
$backup = "$hosts.manual-backup"
$domain = "pwlt.wn1998.com"          # <- test ONE domain at a time

# 1) backup once, never overwrite an existing backup
if (-not (Test-Path $backup)) { Copy-Item $hosts $backup -Force }

# 2) skip if already blocked, then append exactly one line
$line = "127.0.0.1 $domain"
if (-not (Select-String -Path $hosts -SimpleMatch $line -Quiet)) {
    Add-Content -Path $hosts -Value $line -Encoding ASCII
}

# 3) flush resolver cache so the change takes effect immediately
ipconfig /flushdns | Out-Null

# --- verify -------------------------------------------------
Resolve-DnsName $domain -ErrorAction SilentlyContinue |
    Select-Object Name, IPAddress
# expect 127.0.0.1 (or nothing) instead of the real A record

# --- rollback (run this when the test is done) --------------
# Copy-Item $backup $hosts -Force
# ipconfig /flushdns | Out-Null
```

要点：`Add-Content` 是**追加一行**，不重写整个文件，因此不会碰你原有的条目和换行风格；回退是整文件覆盖，所以测完请确认备份是「测试前」的那份。

### 5.2 批处理（管理员）

```bat
@echo off
REM Run as Administrator. Single-domain block with a paired unblock script.
setlocal
set HOSTS=%SystemRoot%\System32\drivers\etc\hosts
set BACKUP=%HOSTS%.manual-backup
set DOMAIN=pwlt.wn1998.com

REM --- block one domain ---
if not exist "%BACKUP%" copy /Y "%HOSTS%" "%BACKUP%" >nul
findstr /I /C:"127.0.0.1 %DOMAIN%" "%HOSTS%" >nul 2>&1
if errorlevel 1 (
    echo 127.0.0.1 %DOMAIN%>>"%HOSTS%"
    echo [OK] blocked %DOMAIN%
) else (
    echo [SKIP] already blocked
)
ipconfig /flushdns >nul

REM --- verify: should print 127.0.0.1 ---
ping -n 1 %DOMAIN%

REM --- rollback: uncomment the next two lines when done ---
REM copy /Y "%BACKUP%" "%HOSTS%" >nul
REM ipconfig /flushdns >nul
endlocal
```

### 5.3 更细的验证手段

- **只测端口连通性，不改 hosts**：`Test-NetConnection <domain> -Port 443`，先确认域名当前是否真的在被客户端使用；
- **抓包确认请求目标**：在客户端里触发一次「检查更新 / 登录」，用 Wireshark/`Get-NetTCPConnection` 看实际连了哪个域；命中哪个就只测哪个；
- **进程级代理替代全局改写**：用 `Proxifier`/`Fiddler` 只对 `finalshell.exe` 的流量做阻断或 DNS 重定向，副作用远小于改 hosts；
- **还原前对比**：`fc /n "%HOSTS%" "%HOSTS%.manual-backup"` 确认差异只有你加的那一行。

---

## 6. 附：与「不落盘」结论的交叉验证

| 观察事实 | 推论 |
| :--- | :--- |
| 激活成功后 `<FINALSHELL_HOME>\` 下不产生任何授权文件 | 会员状态不写本地授权文件 |
| `config.json` 无新增字段 | 会员状态也不写配置 |
| 算号器**只**做「算码 + 改 hosts」两件事，不碰 jar、不写注册表（导入表无 `Reg*`、无 `HKEY` 字符串、无 `finalshell` 路径常量） | 作者的方案本身就是「本地算码 + 掐断联网」 |
| 屏蔽 10 个域后授权保持 | 会员判定在每次联网时被服务端复核，阻断后只能退回本地结果 |

结论：**改 hosts 有用，是因为它把「服务端复核」这一环从链路上摘掉了，而不是因为它绕过了某个校验算法。** 两者的区别在于可维护性——一旦客户端把校验域名换成未列入清单的新域，或者改为「必须联网才判定会员」，这套 hosts 方案立刻失效，而算法层面的结论（[activation-algorithm.md](activation-algorithm.md)）不受影响。
