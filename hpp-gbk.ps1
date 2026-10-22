<#
.SYNOPSIS
  把 ANSI 字面量的中文译文编码成 GBK（代码页 936）字节，供 hpp-patch.mjs 写入。

.DESCRIPTION
  Node 没有内置 GBK 编码器，所以这一步交给 .NET。

  输入：hpp-zh\hpp-gbk-request.json
        { note, entries: [ { fileOff, maxUnits, text, zh, kind, id } ] }
  输出：hpp-zh\hpp-gbk-data.json
        { note, entries: [ { fileOff, maxUnits, text, zh, hex, bytes, overflow, unmappable } ] }

  对每条：
    - 用严格模式（EncoderExceptionFallback）编码，遇到 GBK 无法表示的字符不会静默变成 '?'；
    - 若严格模式失败，退回默认编码并在 unmappable=true 标记（补丁会据此报错，不静默写入）；
    - bytes > maxUnits 时置 overflow=true（补丁同样报错，不截断）。

.EXAMPLE
  pwsh -File hpp-gbk.ps1
#>
[CmdletBinding()]
param(
  [string]$Request = "$PSScriptRoot\hpp-zh\hpp-gbk-request.json",
  [string]$OutPath = "$PSScriptRoot\hpp-zh\hpp-gbk-data.json"
)

$ErrorActionPreference = 'Stop'
function Die($m) { Write-Host "[hpp-gbk] 错误：$m" -ForegroundColor Red; exit 1 }

Write-Host '=========================================================='
Write-Host ' GBK 编码（代码页 936）'
Write-Host '=========================================================='

if (-not (Test-Path -LiteralPath $Request)) { Die "请求文件不存在：$Request" }
$req = Get-Content -LiteralPath $Request -Raw -Encoding utf8 | ConvertFrom-Json
if (-not $req.entries) { Die '请求文件里没有 entries。' }
Write-Host ("[hpp-gbk] 待编码条目：{0} 条" -f @($req.entries).Count)

# 严格编码器：无法映射的字符会抛异常，而不是变成 '?'
$strict = [System.Text.Encoding]::GetEncoding(936, [System.Text.EncoderExceptionFallback]::new(), [System.Text.DecoderExceptionFallback]::new())
$lenient = [System.Text.Encoding]::GetEncoding(936)

$rows = @()
$overflow = 0
$unmappable = 0
foreach ($e in $req.entries) {
  $zh = [string]$e.zh
  $hex = ''
  $bytes = 0
  $isUnmappable = $false
  try {
    $b = $strict.GetBytes($zh)
  } catch {
    $isUnmappable = $true
    $b = $lenient.GetBytes($zh)
  }
  $hex = -join ($b | ForEach-Object { $_.ToString('x2') })
  $bytes = $b.Length
  $isOverflow = $bytes -gt [int]$e.maxUnits
  if ($isOverflow) { $overflow++ }
  if ($isUnmappable) {
    $unmappable++
    Write-Host ("[hpp-gbk] 无法用 GBK 表示: {0} -> {1}（@0x{2:x}）" -f ([string]$e.text), $zh, [int]$e.fileOff) -ForegroundColor Yellow
  }
  $rows += [ordered]@{
    fileOff    = [int]$e.fileOff
    maxUnits   = [int]$e.maxUnits
    text       = [string]$e.text
    zh         = $zh
    hex        = $hex
    bytes      = $bytes
    overflow   = $isOverflow
    unmappable = $isUnmappable
  }
}

$doc = [ordered]@{
  note       = '由 hpp-gbk.ps1 用 .NET Encoding.GetEncoding(936) 生成；hex 为 GBK 字节'
  generatedAt = (Get-Date).ToString('o')
  count      = $rows.Count
  overflow   = $overflow
  unmappable = $unmappable
  entries    = $rows
}
$doc | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutPath -Encoding utf8

Write-Host ("[hpp-gbk] 已写出：{0}" -f $OutPath)
Write-Host ("[hpp-gbk] 条目 {0}；超长 {1}；GBK 无法表示 {2}" -f $rows.Count, $overflow, $unmappable)
if ($overflow -gt 0) {
  Write-Host '[hpp-gbk] 存在超长条目 —— 补丁阶段会报错（按约定不截断）。' -ForegroundColor Yellow
}
exit 0