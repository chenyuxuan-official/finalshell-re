# 激活为什么不持久 —— `yunce.hostbuf.com` 被漏掉了

> 本文记录一次**动态取证**的结论：第三方算号器屏蔽的 10 个域名里，
> 缺了真正承担校验的那一个，所以激活会在客户端联网后被服务端结论覆盖。

---

## 1. 取证过程

### 1.1 断点方案失败（记录一下，避免重复踩坑）

先假设 `huw` 的生成会走 DES 加密链路，于是在 `lr.u([B[B)[B` 下断点：

```bash
java -cp . JdiWatch 127.0.0.1 5005 lr u 60
# [*] bp lr.u([B[B)[B  @line 14
```

在客户端里改字体、开关标签页（都会触发 `config.json` 重写，
`<FINALSHELL_HOME>\backup\app_config\` 下确实持续产生新的快照，时间戳对得上），
但 `lr.u` **一次都没命中**。

结论：`huw` 不是经由 `lr.u` 加密生成的，这条路不通。

### 1.2 改装：直接读运行时的静态字段

`dD` 是一堆 `public static` 字段 + 一个 `static void W()`。用 JDI 读它的全部静态字段：

```bash
java -cp . JdiFields 127.0.0.1 5005 dD
```

拿到 27 组「键 → 值」的配置表（`dD.a` 是 ZKM 加密的键，`dD.b` 是明文键名）：

```text
{temp/speedtest/, temp, temp/edit, https://www.hostbuf.com/, null, /backup/,
 blur_image_cache/, knownhosts.json, fs.service, null, null, app_config,
 downloads/acce_config.json, conn, null, deletions.json, fileattribute.json,
 yunce.hostbuf.com,            <-- 注意
 user.home, update/,
 fw.d1sm.net,                  <-- 注意
 user.dir, sync, fs.service, config.json, /deleted/, null}
```

`dD` 的字段不是 `config.json` 的映射（那些是路径/URL 常量），但暴露了两个
**此前从未出现在任何 hosts 屏蔽清单里**的域名：

| 域名 | 语义 | 是否被算号器屏蔽 |
| :--- | :--- | :--: |
| `yunce.hostbuf.com` | "云测"，云端校验 | ❌ **没有** |
| `fw.d1sm.net` | 服务端地址 | ❌ **没有** |

### 1.3 网络侧验证

```powershell
# 1) 客户端进程正在发外网连接
Get-NetTCPConnection -OwningProcess <java_pid> | ? RemoteAddress -notmatch '^(127\.|0\.0\.0\.0|::)'
#    RemoteAddress  RemotePort State
#    45.56.98.223   443        CloseWait
#    45.56.98.223   443        CloseWait

# 2) 域名解析情况
Resolve-DnsName yunce.hostbuf.com -Type A
#    yunce.hostbuf.com -> 47.74.219.231      <-- 仍然解析到公网，没被拦

Resolve-DnsName www.hostbuf.com -Type A
#    www.hostbuf.com   -> 127.0.0.1         <-- 被算号器屏蔽了
```

**关键点：hosts 不做通配匹配。**

```hosts
127.0.0.1 hostbuf.com
127.0.0.1 www.hostbuf.com
```

这两行**不会**影响 `yunce.hostbuf.com` —— 它是独立的一条 DNS 记录，
必须单独写一行才能拦住。算号器只屏蔽了主域和 `www`，漏掉了子域。

---

## 2. 结论

第三方算号器屏蔽的 10 个域名是：

```text
www.youtusoft.com  youtusoft.com
hostbuf.com        www.hostbuf.com       backup.www.hostbuf.com
dkys.org           tcpspeed.com
www.wn1998.com     wn1998.com            pwlt.wn1998.com
```

而客户端实际用于云端校验的 `yunce.hostbuf.com` **不在其中**。

于是形成这样一条链路：

```text
本地算出激活码 → 客户端接受 → 会员状态进内存
                                    ↓
                     yunce.hostbuf.com 心跳（未被拦）
                                    ↓
                     服务端返回「该机器码授权无效 / 免费版」
                                    ↓
                          内存状态被覆盖，功能回退
```

这解释了两个实测现象：
1. 激活当时有效（界面显示已激活）；
2. `<FINALSHELL_HOME>\` 下不产生任何授权文件、`config.json` 也没有新增字段
   —— 因为状态本来就不打算落盘，靠每次启动向服务端要。

---

## 3. 修复

补一行即可（需要管理员权限）：

```powershell
$h = "$env:windir\System32\drivers\etc\hosts"
Copy-Item $h "$h.$(Get-Date -f yyyyMMddHHmmss)" -Force

Add-Content -Path $h -Value "`r`n127.0.0.1 yunce.hostbuf.com" -Encoding ASCII
Add-Content -Path $h -Value "127.0.0.1 fw.d1sm.net" -Encoding ASCII

ipconfig /flushdns
```

验证是否生效：

```powershell
Resolve-DnsName yunce.hostbuf.com -Type A   # 应返回 127.0.0.1
```

然后**重新激活一次**（激活码不变，还是那条 Keccak-384 的结果），
再重启客户端观察功能是否还在。

---

## 4. 判定「到底有没有持久化」的实验

想确认服务端到底会不会覆盖，可以做一个对照实验，两边都跑一遍：

| 组 | hosts 配置 | 重启后看 |
| :-- | :--- | :--- |
| A | 只屏蔽算号器原有的 10 条 | 功能是否掉回免费版 |
| B | 10 条 + `yunce.hostbuf.com` + `fw.d1sm.net` | 同上 |

如果 A 掉、B 不掉 → 说明覆盖确实来自 `yunce` 这条心跳。
如果两边都掉 → 说明还有别的校验点，继续用 `Get-NetTCPConnection` 盯连接、
或在 `Lk.Y` / `MessageDigest` 上下断点找加密入口。

---

## 5. 遗留问题

- `huw` 的真实语义仍未定位。它每次启动都变（三次启动实测），
  但**这不能证明它不含授权信息** —— 如果它是「固定明文 + 随机 IV」的密文，
  密文每次都变而明文稳定，是完全正常的。要证伪需要抓到一次赋值前后的对比。
- `45.56.98.223`（`li900-223.members.linode.com`）的用途未确认，
  从域名看更像测速节点，暂时判断与授权无关。
