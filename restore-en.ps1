<#
.SYNOPSIS
  把 Hammer++ 的 DLL 还原成原版（或指定的备份）。

.DESCRIPTION
  安全约束：
    1. 默认自动挑选目标文件旁边**最新**的 .bak-* 备份；也可用 -Backup 指定；
    2. 备份内容必须属于「已知状态」（原版或已知汉化版）——比对 SHA-256，否则拒绝；
    3. 必须显式加 -Confirm 才真正动文件；不加时只做 dry-run；
    4. 还原前先把**当前**文件另存为 .bak-before-restore-<时间戳>，保证可再回退；
    5. 写入后回读校验，不匹配即报错。

  脚本绝不启动、绝不运行目标程序，只做文件复制。

.EXAMPLE
  pwsh -File restore-en.ps1                 # 预演：列出将用哪个备份、将做什么
  pwsh -File restore-en.ps1 -Confirm        # 真正还原到最新备份
  pwsh -File restore-en.ps1 -Backup 'D:\...\hammerplusplus_dll.dll.bak-20261016-004133' -Confirm
#>
[CmdletBinding()]
param(
  # 目标 DLL（必须显式传；L4D2 一般是
  #   <Steam>\steamapps\common\Left 4 Dead 2\bin\hammerplusplus\bin\hammerplusplus_dll.dll）
  [Parameter(Mandatory = $true)][string]$Target,
  # 指定要还原的备份；留空则自动取 Target 旁边最新的 .bak-*
  [string]$Backup = '',
  # 允许作为「还原来源」的 SHA-256（原版 + 历史汉化版）
  [string[]]$KnownSha256 = @(
    '782DFAB498614543A93CEBF9B0A06BEC2BB99730D8E31AE4C7517561579B22C6',
    '58C6451A8D635C832436D8088D059C7AF09AD3CF5DCC8E3E7073A2FB826B2E2D',
    '7C53D9A32D18A610C00410D5C7C9C58276783605CB684AD705DFBD93BE4A1FFF',
    'D43030D38C3E04F92F83C434AEE72DF8443769E325AD809D003829C2C5562B12'
  ),
  # 期望「还原后」达到的 SHA-256（默认是真正的原版；留空则不校验）
  [string]$ExpectedRestoredSha256 = '782DFAB498614543A93CEBF9B0A06BEC2BB99730D8E31AE4C7517561579B22C6',
  # 是否只接受真正的原版作为还原来源（$false 时也允许从任一历史汉化版回退）
  [switch]$OriginalOnly,
  [switch]$Confirm
)

$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "[restore-en] $m" }
function Warn($m) { Write-Host "[restore-en] $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "[restore-en] 错误：$m" -ForegroundColor Red; exit 1 }

Write-Host '=========================================================='
Write-Host ' Hammer++ DLL 还原'
Write-Host (' 模式：' + $(if ($Confirm) { '实际写入 (-Confirm)' } else { 'DRY-RUN（只打印，不动文件）' }))
Write-Host '=========================================================='

# ---- 1. 目标检查
Step "目标文件：$Target"
if (-not (Test-Path -LiteralPath $Target -PathType Leaf)) { Die "目标文件不存在：$Target" }
$tgtHash = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
Step "  当前 SHA-256：$tgtHash"

# ---- 2. 选择备份
if (-not $Backup) {
  $dir = Split-Path -Parent $Target
  $leaf = Split-Path -Leaf $Target
  $cands = Get-ChildItem -LiteralPath $dir -Filter "$leaf.bak-*" -File -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending
  if (-not $cands -or $cands.Count -eq 0) { Die "未找到任何备份（$dir\$leaf.bak-*）。请用 -Backup 指定。" }
  $Backup = $cands[0].FullName
  Warn ("未指定 -Backup，自动选用最新备份（共 {0} 个）" -f $cands.Count)
}
Step "还原来源：$Backup"
if (-not (Test-Path -LiteralPath $Backup -PathType Leaf)) { Die "备份文件不存在：$Backup" }
$bkHash = (Get-FileHash -LiteralPath $Backup -Algorithm SHA256).Hash
$bkLen = (Get-Item -LiteralPath $Backup).Length
Step ("  大小：{0} 字节" -f $bkLen)
Step "  SHA-256：$bkHash"

# ---- 3. 备份身份校验
if ($bkHash -notin $KnownSha256) {
  Warn '  该备份不属于已知状态（既不是原版，也不是已知汉化版）。'
  Warn ("  已知状态：{0}" -f ($KnownSha256 -join ', '))
  Die '  为安全起见中止：拒绝用身份不明的文件覆盖目标。'
}
$isTrueOriginal = ($bkHash -eq '782DFAB498614543A93CEBF9B0A06BEC2BB99730D8E31AE4C7517561579B22C6')
if ($OriginalOnly -and -not $isTrueOriginal) {
  Die "已指定 -OriginalOnly，但所选备份不是真正的原版（$bkHash）。"
}
Step ("  备份身份校验通过：{0}" -f $(if ($isTrueOriginal) { '真正的原版 ✅' } else { '历史汉化版（回退到该版本）⚠' }))

if ($ExpectedRestoredSha256 -and $ExpectedRestoredSha256 -ne $bkHash) {
  Warn ("  注意：还原后的哈希将是 {0}，与 -ExpectedRestoredSha256（{1}）不同。" -f $bkHash, $ExpectedRestoredSha256)
}

# ---- 4. 现状备份 + 还原
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$safety = "$Target.bak-before-restore-$stamp"
Step "还原前先保存当前文件 -> $safety"

if (-not $Confirm) {
  Write-Host ''
  Warn '当前为 DRY-RUN，未对任何文件做出修改。'
  Write-Host '将执行的操作：'
  Write-Host ("  1) Copy-Item '{0}' -> '{1}'   （保存当前状态）" -f $Target, $safety)
  Write-Host ("  2) Copy-Item '{0}' -> '{1}'   （还原）" -f $Backup, $Target)
  Write-Host ''
  Write-Host '确认无误后重新运行并加上 -Confirm 才会真正执行。'
  exit 0
}

Step '实际执行中……'
Copy-Item -LiteralPath $Target -Destination $safety -Force
if ((Get-FileHash -LiteralPath $safety -Algorithm SHA256).Hash -ne $tgtHash) { Die '保存当前状态失败（哈希不一致），中止' }
Step "  已保存当前状态 -> $safety"

Copy-Item -LiteralPath $Backup -Destination $Target -Force
$afterHash = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
Step "  已还原 -> $Target"
Step "  还原后 SHA-256：$afterHash"
if ($afterHash -ne $bkHash) { Die "还原后校验失败：$afterHash != $bkHash" }

Write-Host ''
Write-Host '[restore-en] 还原完成 ✅' -ForegroundColor Green
if ($isTrueOriginal) {
  Write-Host '[restore-en] 当前为原版英文界面。'
} else {
  Warn '[restore-en] 当前为历史汉化版，而非原版；如需彻底回英文版，请再指定真正的原版备份运行一次。'
}
Write-Host "[restore-en] 若需再次安装汉化：pwsh -File install-zh.ps1 -Confirm"
exit 0