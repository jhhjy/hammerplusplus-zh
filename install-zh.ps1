<#
.SYNOPSIS
  把汉化后的 hammerplusplus_dll.dll 安装到游戏目录。

.DESCRIPTION
  安全约束（缺一不可）：
    1. 目标路径必须存在，且属于「已知状态」——比对 SHA-256（原版 或 任一历史汉化版）；
    2. 必须显式加 -Confirm 才真正动文件；不加时只做 dry-run（打印将做什么）；
    3. 覆盖前先自动备份成 hammerplusplus_dll.dll.bak-<时间戳>；
    4. 每一步都打印，写入后回读校验。

  注意：脚本绝不启动、绝不运行目标程序，只做文件复制。

.EXAMPLE
  pwsh -File install-zh.ps1              # 预演（不动文件）
  pwsh -File install-zh.ps1 -Confirm     # 真正安装
#>
[CmdletBinding()]
param(
  # 汉化 DLL（默认取工作区 hpp-zh 下的产物）
  [string]$Source = "$PSScriptRoot\hpp-zh\hammerplusplus_dll.dll",
  # 游戏目录中的目标 DLL（必须显式传；L4D2 一般是
  #   <Steam>\steamapps\common\Left 4 Dead 2\bin\hammerplusplus\bin\hammerplusplus_dll.dll）
  [Parameter(Mandatory = $true)][string]$Target,
  # 允许被覆盖的「当前状态」SHA-256（多个用逗号分隔）：
  #   1) 真正的原版
  #   2) 历史汉化产物（含一版有缺陷的：它误改了 tier0.dll 的导入名 Warning/Rectangle/Ellipse/Polygon，
  #      会导致「无法定位程序输入点」；允许直接覆盖修复，不必先手工还原）
  [string[]]$ExpectedOriginalSha256 = @(
    '782DFAB498614543A93CEBF9B0A06BEC2BB99730D8E31AE4C7517561579B22C6',
    '58C6451A8D635C832436D8088D059C7AF09AD3CF5DCC8E3E7073A2FB826B2E2D',
    '7C53D9A32D18A610C00410D5C7C9C58276783605CB684AD705DFBD93BE4A1FFF',
    'D43030D38C3E04F92F83C434AEE72DF8443769E325AD809D003829C2C5562B12'
  ),
  # 期望写入的汉化文件 SHA-256（留空则只打印实际值不校验；改动词典后必须同步更新）
  [string]$ExpectedPatchedSha256 = '2602E2325523F8FCFEDAE9F3CE929668FEF4F5B1E13BBAA92BA131F21A83793B',
  [switch]$Confirm
)

$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "[install-zh] $m" }
function Warn($m) { Write-Host "[install-zh] $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "[install-zh] 错误：$m" -ForegroundColor Red; exit 1 }

Write-Host '=========================================================='
Write-Host ' Hammer++ DLL 汉化安装'
Write-Host (' 模式：' + $(if ($Confirm) { '实际写入 (-Confirm)' } else { 'DRY-RUN（只打印，不动文件）' }))
Write-Host '=========================================================='

# ---- 1. 源文件检查
Step "汉化源文件：$Source"
if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { Die "汉化文件不存在：$Source" }
$srcItem = Get-Item -LiteralPath $Source
Step ("  大小：{0} 字节" -f $srcItem.Length)
$srcHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
Step "  SHA-256：$srcHash"
if ($srcItem.Length -eq 0) { Die '汉化文件为空' }
if ($ExpectedPatchedSha256) {
  if ($srcHash -ne $ExpectedPatchedSha256) {
    Die "汉化文件 SHA-256 与预期不符。`n  预期：$ExpectedPatchedSha256`n  实际：$srcHash"
  }
  Step '  SHA-256 与预期一致 ✅'
}

# ---- 2. 目标路径检查
Step "目标文件：$Target"
$targetDir = Split-Path -Parent $Target
if (-not (Test-Path -LiteralPath $targetDir -PathType Container)) { Die "目标目录不存在：$targetDir" }
if (-not (Test-Path -LiteralPath $Target -PathType Leaf)) { Die "目标文件不存在（不是预期文件）：$Target" }
$tgtItem = Get-Item -LiteralPath $Target
Step ("  当前大小：{0} 字节" -f $tgtItem.Length)
if ($tgtItem.Length -ne $srcItem.Length) {
  Warn ("  注意：目标与汉化源大小不同（{0} vs {1}）——若目标已被替换过，属异常" -f $tgtItem.Length, $srcItem.Length)
}
$tgtHash = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
Step "  当前 SHA-256：$tgtHash"

# ---- 3. 目标身份校验
$isOriginal = $ExpectedOriginalSha256 -contains $tgtHash
$isSamePatched = ($ExpectedPatchedSha256 -and $tgtHash -eq $ExpectedPatchedSha256)
if ($isSamePatched) {
  Step '  目标已是本汉化版，无需安装。'
  exit 0
}
if (-not $isOriginal) {
  Warn '  目标 SHA-256 既不是已知原版，也不是已知汉化版。'
  Warn ("  已知可覆盖状态：{0}" -f ($ExpectedOriginalSha256 -join ', '))
  Die '  为安全起见中止：拒绝覆盖身份不明的文件。如确认无误，请用 -ExpectedOriginalSha256 传入实际哈希。'
}
Step '  目标身份校验通过 ✅'

# ---- 4. 备份
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = "$Target.bak-$stamp"
Step "备份计划：$Target"
Step "       -> $backup"

# ---- 5. dry-run 或实际执行
if (-not $Confirm) {
  Write-Host ''
  Warn '当前为 DRY-RUN，未对任何文件做出修改。'
  Write-Host '将执行的操作：'
  Write-Host ("  1) Copy-Item '{0}' -> '{1}'   （备份当前文件）" -f $Target, $backup)
  Write-Host ("  2) Copy-Item '{0}' -> '{1}'   （写入汉化）" -f $Source, $Target)
  Write-Host ''
  Write-Host '确认无误后重新运行并加上 -Confirm 才会真正执行。'
  exit 0
}

Step '实际执行中……'
Copy-Item -LiteralPath $Target -Destination $backup -Force
if (-not (Test-Path -LiteralPath $backup)) { Die "备份失败：$backup 未生成" }
$bkHash = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
Step "  已备份当前文件 -> $backup"
Step "  备份 SHA-256：$bkHash （应与 $tgtHash 相同）"
if ($bkHash -ne $tgtHash) { Die '备份内容与原文件不一致，中止' }

Copy-Item -LiteralPath $Source -Destination $Target -Force
$afterHash = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
$afterLen = (Get-Item -LiteralPath $Target).Length
Step "  已写入汉化 -> $Target"
Step ("  写入后大小：{0} 字节" -f $afterLen)
Step "  写入后 SHA-256：$afterHash"
if ($afterHash -ne $srcHash) { Die "写入后校验失败：$afterHash != $srcHash" }
Write-Host ''
Write-Host '[install-zh] 安装完成 ✅' -ForegroundColor Green
Write-Host "[install-zh] 如需还原：pwsh -File restore-en.ps1 -Backup '$backup' -Confirm"
exit 0