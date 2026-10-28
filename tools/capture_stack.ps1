<#
.SYNOPSIS
  捕获 FinalShell 激活码校验时弹出的模态对话框栈（不需要 JDWP）。

.DESCRIPTION
  原理：Swing 弹出 JOptionPane 模态框时，AWT-EventQueue 线程会阻塞在
  JOptionPane.showMessageDialog 内部（二级事件循环里等结果）。此时循环
  jstack -l <pid>，一旦某次快照中 AWT-EventQueue 线程栈出现
  JOptionPane / showMessageDialog / JDialog，说明模态框此刻正开着 ——
  该栈里 showMessageDialog 上方的那一帧就是业务方法（激活码校验函数）。

  每次 jstack 结果追加到 jstack_dump.txt；命中时把该线程完整栈写到
  hit_stack.txt 并立即停止循环。

.PARAMETER IntervalMs     抓取间隔（毫秒），默认 1500
.PARAMETER Iterations     最多抓多少次，默认 40
.PARAMETER JstackPath     jstack.exe 路径
.PARAMETER Match          线程栈命中关键字（正则）
.PARAMETER OutDir         输出目录，默认脚本所在目录
.PARAMETER TargetPid      手动指定 PID（跳过自动查找）
.PARAMETER JarPattern     用于识别 finalshell 进程的命令行正则

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\capture_stack.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\capture_stack.ps1 -IntervalMs 800 -Iterations 120
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\capture_stack.ps1 -TargetPid 1234
#>
[CmdletBinding()]
param(
    [int]$IntervalMs = 1500,
    [int]$Iterations = 40,
    [string]$JstackPath = 'C:\Program Files\Java\latest\jdk-17\bin\jstack.exe',
    [string]$Match = 'JOptionPane|showMessageDialog|JDialog',
    [string]$OutDir = '',
    [int]$TargetPid = 0,
    [string]$JarPattern = 'finalshell\.jar',
    [string[]]$ExtraExclude = @()
)

$ErrorActionPreference = 'Stop'

# --- 路径与排除项（不在 param 默认值里用 $PSScriptRoot：-File 方式下有个别环境为空） ---
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $OutDir) { $OutDir = $scriptRoot }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$dumpFile = Join-Path $OutDir 'jstack_dump.txt'
$hitFile  = Join-Path $OutDir 'hit_stack.txt'

# 本目录里我们自己编译/运行的小工具进程（-cp finalshell.jar;lib-run/* 之类）必须排除，
# 否则会被误认成 finalshell 主进程。
$ExcludeCmdPatterns = @([regex]::Escape($scriptRoot), 'lib-run', 'JdiMon', 'Dumper', 'Probe', 'TestSwing') + $ExtraExclude

function Write-Log([string]$msg) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    Write-Host $line
    Add-Content -LiteralPath $dumpFile -Value $line -Encoding UTF8
}

# ---------- 1. 找 PID ----------
function Find-TargetPid {
    $cands = @(Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine -match $JarPattern })

    $filtered = @(foreach ($c in $cands) {
        $skip = $false
        foreach ($pat in $ExcludeCmdPatterns) {
            if ($pat -and $c.CommandLine -match $pat) { $skip = $true; break }
        }
        if (-not $skip) { $c }
    })

    if ($filtered.Count -eq 0) { return $null }

    # 优先真正的 finalshell 主进程（exe 路径里带 \finalshell\）
    $preferred = @($filtered | Where-Object { $_.ExecutablePath -match '\\finalshell\\' })
    if ($preferred.Count -gt 0) { return $preferred[0] }
    return $filtered[0]
}

# ---------- 2. 把一次 jstack 输出切成线程块（以 " 开头的行起头） ----------
function Get-ThreadBlocks([string[]]$lines) {
    $blocks = New-Object System.Collections.ArrayList
    $cur = $null
    foreach ($ln in $lines) {
        if ($ln -match '^"') {
            if ($null -ne $cur) { [void]$blocks.Add($cur.ToArray()) }
            $cur = New-Object System.Collections.ArrayList
            [void]$cur.Add($ln)
        }
        elseif ($null -ne $cur) {
            [void]$cur.Add($ln)
        }
    }
    if ($null -ne $cur) { [void]$blocks.Add($cur.ToArray()) }
    return $blocks
}

# ---------- 3. 主循环 ----------
Set-Content -LiteralPath $dumpFile -Value ("# jstack capture start {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Encoding UTF8

if ($TargetPid -eq 0) {
    $proc = Find-TargetPid
    if (-not $proc) {
        Write-Log "未找到 finalshell 进程（java.exe/javaw.exe 命令行含 '$JarPattern' 且不含排除项）。请先启动 FinalShell 并让它停在激活码提示框上。"
        Write-Host '未捕获' -ForegroundColor Yellow
        exit 2
    }
    $TargetPid = [int]$proc.ProcessId
    Write-Log ("目标 PID={0}" -f $TargetPid)
    Write-Log ("exe={0}" -f $proc.ExecutablePath)
    Write-Log ("cmdline={0}" -f $proc.CommandLine)
}
else {
    Write-Log ("使用手动指定 PID={0}" -f $TargetPid)
}

if (-not (Test-Path -LiteralPath $JstackPath)) {
    Write-Log "jstack 不存在: $JstackPath"
    Write-Host '未捕获' -ForegroundColor Yellow
    exit 3
}

$hit = $false
for ($i = 1; $i -le $Iterations; $i++) {
    Write-Log ("===== capture #{0}/{1} at {2} =====" -f $i, $Iterations, (Get-Date -Format 'HH:mm:ss.fff'))

    # jstack 的 stderr 经 2>&1 会变成 error 记录，临时放宽 EAP，避免 attach 失败直接终止脚本
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = (& $JstackPath -l $TargetPid 2>&1 | Out-String) }
    catch { $out = "jstack error: $($_.Exception.Message)" }
    finally { $ErrorActionPreference = $prevEap }

    Add-Content -LiteralPath $dumpFile -Value $out -Encoding UTF8

    if ($out -match 'Unable to open socket file|No such process|not exist|AttachNotSupported|Denied access|拒绝访问|Access is denied') {
        Write-Log 'jstack 失败（进程已退出或 attach 被拒），停止。'
        break
    }

    $blocks = Get-ThreadBlocks ($out -split "`r?`n")
    foreach ($b in $blocks) {
        if ($b[0] -notmatch 'AWT-EventQueue') { continue }
        $text = ($b -join "`n")
        if ($text -match $Match) {
            $hdr = @(
                ("# HIT at {0}  pid={1}  capture=#{2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $TargetPid, $i),
                '# AWT-EventQueue 线程正阻塞在模态框内；showMessageDialog 上方那一帧即业务校验方法',
                ''
            ) -join "`n"
            Set-Content -LiteralPath $hitFile -Value ($hdr + $text) -Encoding UTF8
            $hit = $true
            break
        }
    }

    if ($hit) { break }
    if ($i -lt $Iterations) { Start-Sleep -Milliseconds $IntervalMs }
}

if ($hit) {
    Write-Log "已捕获：AWT-EventQueue 命中模态框关键字 -> $hitFile"
    Write-Host "已捕获 -> $hitFile" -ForegroundColor Green
    Get-Content -LiteralPath $hitFile -Encoding UTF8 | Write-Host
    exit 0
}
else {
    Write-Log ("未捕获：{0} 次快照内 AWT-EventQueue 未出现模态框帧。" -f $Iterations)
    Write-Host '未捕获' -ForegroundColor Yellow
    exit 1
}
