## 节表

| # | 节名 | RVA | 虚拟大小 | 原始偏移 | 原始大小 | 熵 | 权限 | 含入口点 |
|---|------|-----|---------|---------|---------|----|------|---------|
| 0 | `.text` | 0x1000 | 0x8C80 | 0x400 | 0x8E00 | 5.833 | — | 是 |
| 1 | `.data` | 0xA000 | 0x140 | 0x9200 | 0x200 | 1.057 | — |  |
| 2 | `.rdata` | 0xB000 | 0x1908 | 0x9400 | 0x1A00 | 4.259 | — |  |
| 3 | `.qtversi` | 0xD000 | 0x10 | 0xAE00 | 0x200 | 0.159 | — |  |
| 4 | `.pdata` | 0xE000 | 0x498 | 0xB000 | 0x600 | 3.473 | — |  |
| 5 | `.xdata` | 0xF000 | 0x9E4 | 0xB600 | 0xA00 | 5.428 | — |  |
| 6 | `.bss` | 0x10000 | 0x1A0 | 0x0 | 0x0 | 0.000 | — |  |
| 7 | `.idata` | 0x11000 | 0x2EC8 | 0xC000 | 0x3000 | 5.125 | — |  |
| 8 | `.CRT` | 0x14000 | 0x60 | 0xF000 | 0x200 | 0.287 | — |  |
| 9 | `.tls` | 0x15000 | 0x10 | 0xF200 | 0x200 | -0.000 | — |  |
| 10 | `.reloc` | 0x16000 | 0x154 | 0xF400 | 0x200 | 3.862 | — |  |

## 导入表

| DLL | 函数数 | 说明 |
|-----|-------|------|
| `Qt6Core.dll` | 60 | — |
| `Qt6Gui.dll` | 4 | — |
| `Qt6Widgets.dll` | 90 | — |
| `libgcc_s_seh-1.dll` | 1 | — |
| `KERNEL32.dll` | 14 | — |
| `msvcrt.dll` | 29 | — |
| `SHELL32.dll` | 1 | — |
| `libstdc++-6.dll` | 10 | — |

总导入条目: 209

## 关键字符串（含虚拟地址）

| 0x009400 | 0x00014000B000 | `C:/Windows/System32/drivers/etc/hosts` |
| 0x009426 | 0x00014000B026 | `.backup` |
| 0x009468 | 0x00014000B068 | `Failed to remove current hosts file.` |
| 0x009490 | 0x00014000B090 | `Failed to restore backup to hosts.` |
| 0x0094B3 | 0x00014000B0B3 | `www.youtusoft.com` |
| 0x0094C5 | 0x00014000B0C5 | `youtusoft.com` |
| 0x0094D3 | 0x00014000B0D3 | `hostbuf.com` |
| 0x0094DF | 0x00014000B0DF | `www.hostbuf.com` |
| 0x0094EF | 0x00014000B0EF | `dkys.org` |
| 0x0094F8 | 0x00014000B0F8 | `tcpspeed.com` |
| 0x009505 | 0x00014000B105 | `www.wn1998.com` |
| 0x009514 | 0x00014000B114 | `wn1998.com` |
| 0x00951F | 0x00014000B11F | `pwlt.wn1998.com` |
| 0x00952F | 0x00014000B12F | `backup.www.hostbuf.com` |
| 0x009548 | 0x00014000B148 | `Failed to create backup of hosts file.` |
| 0x009570 | 0x00014000B170 | `Cannot open hosts file for reading.` |
| 0x009598 | 0x00014000B198 | `127.0.0.1` |
| 0x0095A8 | 0x00014000B1A8 | `Cannot open hosts file for writing. Check permissions.` |
| 0x00A0EE | 0x00014000BCEE | `2356` |
| 0x00A0F3 | 0x00014000BCF3 | `13593` |
| 0x00A0F9 | 0x00014000BCF9 | `FF3Go(*Xvbb5s2` |
| 0x00A108 | 0x00014000BD08 | `b(xxkHn%z);x` |
| 0x00A115 | 0x00014000BD15 | `Scfg*ZkvJZc,s,Y` |
| 0x00A24B | 0x00014000BE4B | `generateToken` |
| 0x00A25A | 0x00014000BE5A | `copyToken` |
| 0x00AB40 | 0x00014000C740 | `GCC: (x86_64-posix-seh-rev3, Built by MinGW-W64 project) 11.2.0` |
| 0x00AB80 | 0x00014000C780 | `GCC: (x86_64-posix-seh-rev3, Built by MinGW-W64 project) 11.2.0` |
| 0x00ABC0 | 0x00014000C7C0 | `GCC: (x86_64-posix-seh-rev3, Built by MinGW-W64 project) 11.2.0` |
| 0x00AC00 | 0x00014000C800 | `GCC: (x86_64-posix-seh-rev3, Built by MinGW-W64 project) 11.2.0` |
| 0x00AC40 | 0x00014000C840 | `GCC: (x86_64-posix-seh-rev3, Built by MinGW-W64 project) 11.2.0` |
| 0x00AC80 | 0x00014000C880 | `GCC: (x86_64-posix-seh-rev3, Built by MinGW-W64 project) 11.2.0` |
| 0x00CE46 | 0x000140011E46 | `_Z5qHash11QStringViewy` |
| 0x00CF36 | 0x000140011F36 | `_ZN11QTextStream8readLineEx` |
| 0x00CF56 | 0x000140011F56 | `_ZN11QTextStreamC1EP9QIODevice` |
| 0x00CF7A | 0x000140011F7A | `_ZN11QTextStreamD1Ev` |
| 0x00CF92 | 0x000140011F92 | `_ZN11QTextStreamlsEPKc` |
| 0x00CFAE | 0x000140011FAE | `_ZN11QTextStreamlsERK7QString` |
| 0x00CFCE | 0x000140011FCE | `_ZN11QTextStreamlsEc` |
| 0x00CFE6 | 0x000140011FE6 | `_ZN16QCoreApplication18setApplicationNameERK7QString` |
| 0x00D01E | 0x00014001201E | `_ZN16QCoreApplication19setOrganizationNameERK7QString` |
| 0x00D056 | 0x000140012056 | `_ZN18QCryptographicHash4hashE14QByteArrayViewNS_9AlgorithmE` |
| 0x00D096 | 0x000140012096 | `_ZN18QRegularExpressionC1ERK7QString6QFlagsINS_13PatternOptionEE` |
| 0x00D0DA | 0x0001400120DA | `_ZN18QRegularExpressionD1Ev` |
| 0x00D0F9 | 0x0001400120F9 | `_ZN23QRegularExpressionMatchD1Ev` |
| 0x00D11E | 0x00014001211E | `_ZN5QFile4copyERK7QStringS2_` |
| 0x00D17A | 0x00014001217A | `_ZN5QFile6existsERK7QString` |
| 0x00D19A | 0x00014001219A | `_ZN5QFile6removeERK7QString` |
| 0x00D1BA | 0x0001400121BA | `_ZN5QFileC1ERK7QString` |
| 0x00D3C6 | 0x0001400123C6 | `_ZN7QObject15doSetObjectNameERK7QString` |
| 0x00D44A | 0x00014001244A | `_ZN7QString10fromLatin1E14QByteArrayView` |
| 0x00D476 | 0x000140012476 | `_ZN7QString13toUtf8_helperERKS_` |
| 0x00D49A | 0x00014001249A | `_ZN7QString14trimmed_helperERKS_` |
| 0x00D4BE | 0x0001400124BE | `_ZN7QString14trimmed_helperERS_` |
| 0x00D4E2 | 0x0001400124E2 | `_ZN7QString17toIntegral_helperE11QStringViewPbi` |
| 0x00D516 | 0x000140012516 | `_ZN7QString6appendE20QBasicUtf8StringViewILb0EE` |
| 0x00D54A | 0x00014001254A | `_ZN7QString6appendERKS_` |
| 0x00D566 | 0x000140012566 | `_ZN7QString8fromUtf8E14QByteArrayView` |
| 0x00D5D6 | 0x0001400125D6 | `_ZN9QtPrivate12equalStringsE11QStringViewS0_` |
| 0x00D606 | 0x000140012606 | `_ZN9QtPrivate20QStringList_containsEPK5QListI7QStringE11QStringViewN2Qt15CaseSensitivityE` |
| 0x00D6AA | 0x0001400126AA | `_ZNK11QTextStream5atEndEv` |
| 0x00D6EA | 0x0001400126EA | `_ZNK18QRegularExpression5matchERK7QStringxNS_9MatchTypeE6QFlagsINS_11MatchOptionEE` |
| 0x00D742 | 0x000140012742 | `_ZNK23QRegularExpressionMatch8capturedEi` |
| 0x00D76E | 0x00014001276E | `_ZNK23QRegularExpressionMatch8hasMatchEv` |
| 0x00D79A | 0x00014001279A | `_ZNK7QString10startsWithE5QCharN2Qt15CaseSensitivityE` |
| 0x00D7D2 | 0x0001400127D2 | `_ZNK7QString5splitERK18QRegularExpression6QFlagsIN2Qt18SplitBehaviorFlagsEE` |
| 0x00D822 | 0x000140012822 | `_ZNKR7QString3midExx` |
| 0x00D852 | 0x000140012852 | `_ZN10QClipboard7setTextERK7QStringNS_4ModeE` |
| 0x00DB36 | 0x000140012B36 | `_ZN11QMessageBox11informationEP7QWidgetRK7QStringS4_6QFlagsINS_14StandardButtonEES6_` |
| 0x00DB8E | 0x000140012B8E | `_ZN11QMessageBox7warningEP7QWidgetRK7QStringS4_6QFlagsINS_14StandardButtonEES6_` |
| 0x00DBE2 | 0x000140012BE2 | `_ZN11QPushButtonC1ERK7QStringP7QWidget` |
| 0x00DD1E | 0x000140012D1E | `_ZN6QLabel7setTextERK7QString` |
| 0x00DD72 | 0x000140012D72 | `_ZN6QLabelC1ERK7QStringP7QWidget6QFlagsIN2Qt10WindowTypeEE` |
| 0x00DE82 | 0x000140012E82 | `_ZN7QWidget10setToolTipERK7QString` |
| 0x00E052 | 0x000140013052 | `_ZN7QWidget13keyPressEventEP9QKeyEvent` |
| 0x00E07E | 0x00014001307E | `_ZN7QWidget13setStyleSheetERK7QString` |
| 0x00E162 | 0x000140013162 | `_ZN7QWidget14setWindowTitleERK7QString` |
| 0x00E18E | 0x00014001318E | `_ZN7QWidget15keyReleaseEventEP9QKeyEvent` |
| 0x00E3F6 | 0x0001400133F6 | `_ZN9QLineEdit11textChangedERK7QString` |
| 0x00E442 | 0x000140013442 | `_ZN9QLineEdit18setPlaceholderTextERK7QString` |
| 0x00E48A | 0x00014001348A | `_ZN9QLineEdit7setTextERK7QString` |
| 0x0095F0 | 0x00014000B1F0 | `finashell++` |
| 0x009616 | 0x00014000B216 | `dHosts` |
| 0x00966A | 0x00014000B26A | `hosts` |
| 0x0097B0 | 0x00014000B3B0 | `finashell++` |
| 0x0098B8 | 0x00014000B4B8 | `Hosts` |
| 0x0098CA | 0x00014000B4CA | `Hosts` |
| 0x00A080 | 0x00014000BC80 | `LEGACY` |
| 0x00A08E | 0x00014000BC8E | `MODERN` |
| 0x00A0B0 | 0x00014000BCB0 | `^([0-9]+)\.([0-9]+)\.([0-9]+)$` |
| 0x009618 | 0x00014000B218 | `Hosts 条目已更新` |
| 0x009660 | 0x00014000B260 | `已恢复原始 hosts 文件` |
| 0x00969C | 0x00014000B29C | `点击此处复制` |
| 0x0096AA | 0x00014000B2AA | `点击复制` |
| 0x0096F0 | 0x00014000B2F0 | `请输入完整版本号` |
| 0x009714 | 0x00014000B314 | `机器码不能为空` |
| 0x009726 | 0x00014000B326 | `已复制` |
| 0x0097D8 | 0x00014000B3D8 | `输入版本号和机器码` |
| 0x0097EC | 0x00014000B3EC | `授权码会自动生成` |
| 0x009864 | 0x00014000B464 | `请输入机器码` |
| 0x0098AE | 0x00014000B4AE | `添加/修改 Hosts` |
| 0x0098C6 | 0x00014000B4C6 | `回退 Hosts` |

## 其它

- overlay 起点(最后一个节结束): 0xF600, 文件大小 0xF600 → 无 overlay
- imphash: `9ac4bc6de740add4c75ecbda839fcb21`
- ASCII 字符串(>=4): 803 条; UTF-16LE(>=4): 23 条; 中文宽字符: 699 条
- 文件 SHA256: `0c2242e47715e880520452da644b47c7d870b117f2bd7100a37bb8a192c1afc1`
- 文件 MD5: `51d7f207c089a89fdbd11af1655fb482`