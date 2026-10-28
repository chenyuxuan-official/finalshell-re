# -*- mode: powershell -*-
<#
.SYNOPSIS
    把 tools/gui.py 打包成单文件 exe（发 Release 用）。

.DESCRIPTION
    输出 tools/dist/FinalShell-Activator.exe，约 11 MB，内置 Python 运行时，
    目标机器不需要装 Python。

    首次使用需要：
        python -m pip install pyinstaller

.EXAMPLE
    cd <REPO_ROOT>\tools
    powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
#>

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

Write-Host '=== 环境检查 ===' -ForegroundColor Cyan
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { throw '找不到 python，请先安装 Python 3.8+' }
Write-Host "  python : $($py.Source)"
python -c "import tkinter" 2>$null
if ($LASTEXITCODE -ne 0) { throw 'tkinter 不可用（Linux 需要 apt install python3-tk）' }
python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host '  安装 PyInstaller ...' -ForegroundColor Yellow
    python -m pip install --quiet pyinstaller
}

Write-Host '=== 清理旧产物 ===' -ForegroundColor Cyan
Remove-Item -Recurse -Force build, dist, FinalShell-Activator.spec -ErrorAction SilentlyContinue

Write-Host '=== 打包 ===' -ForegroundColor Cyan
python -m PyInstaller `
    --noconfirm --clean --onefile --windowed `
    --name 'FinalShell-Activator' `
    --exclude-module numpy --exclude-module pandas --exclude-module matplotlib `
    --exclude-module PyQt5 --exclude-module PySide2 --exclude-module test `
    gui.py

$exe = Join-Path $PSScriptRoot 'dist\FinalShell-Activator.exe'
if (-not (Test-Path $exe)) { throw '打包失败：没找到输出文件' }

$item = Get-Item $exe
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
Write-Host ''
Write-Host '=== 完成 ===' -ForegroundColor Green
Write-Host ("  文件 : {0}" -f $item.FullName)
Write-Host ("  大小 : {0:N1} MB" -f ($item.Length / 1MB))
Write-Host ("  SHA256: {0}" -f $hash)
Write-Host ''
Write-Host '  发布到 GitHub Release：'
Write-Host '    gh release create v1.0.0 dist/FinalShell-Activator.exe --title "..." --notes-file RELEASE.md'
Write-Host '  或手动在网页上传 dist/FinalShell-Activator.exe'
