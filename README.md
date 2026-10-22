# Hammer++ 汉化（L4D2 版）

给 **Hammer++（Left 4 Dead 2 版，6.x）** 的 DLL 做中文汉化：菜单、对话框、字符串表里的英文条目换成中文。

本仓库**不包含** Hammer++ 的任何二进制（原版或修改版）——你需要自备安装好的一份，
工具会生成汉化后的 DLL 并帮你安全地装回去。

## 原理

Hammer++ 的原生 Win32 界面把文本放在三种资源里：`MENU`（UTF-16）、`DIALOG`（UTF-16）、
`STRINGTABLE`（UTF-16 / ANSI）。汉化采用**长度保持式改写**：

- 每个文本槽位的长度上限 `maxUnits` 已知（`hpp-worklist.json`）；
- 译文只写进该槽位内部，不足用空格补齐，终止符与结构字节原样保留；
- **文件长度与所有结构偏移都不变**，所以不用重排资源、不会破坏 PE 结构。

ANSI 槽位需要 GBK 字节（Node 没有内置 GBK 编码器），由 `hpp-gbk.ps1` 用 .NET 代码页 936 生成。

## 快速开始（与仓库内 worklist 对应的版本）

> 先把你游戏目录里的原版 `hammerplusplus_dll.dll` 复制到 `hpp-orig\`（文件名保持一致）。

```powershell
# 1) 生成汉化 DLL（自动读取仓库自带的 hpp-zh\hpp-gbk-data.json）
node hpp-patch.mjs

# 2) 自检（长度、偏移、UTF-16/GBK 长度上限）
node hpp-verify.mjs

# 3) 安装（-Target 换成你自己的路径；不加 -Confirm 只预演）
pwsh -File install-zh.ps1 -Target "<Steam>\steamapps\common\Left 4 Dead 2\bin\hammerplusplus\bin\hammerplusplus_dll.dll" -Confirm
```

装之前会校验目标文件的 SHA-256（只接受已知原版/已知汉化版），并自动备份成 `.bak-<时间戳>`。

## 如果要换一个 Hammer++ 版本

```powershell
# 抽取可翻译单元 → 请求 GBK → 再打补丁
node hpp-extract.mjs
node hpp-patch.mjs                 # 会生成 hpp-zh\hpp-gbk-request.json 并以退出码 2 结束
pwsh -File hpp-gbk.ps1             # 生成 hpp-zh\hpp-gbk-data.json
node hpp-patch.mjs
```

译文字典在 `hpp-zh-dict.json`（`{ "原文": "中文" }`，外加可选的 `exact` 精确条目）。
改完词典重新跑上面的流程即可；`hpp-verify.mjs` 会检查是否存在超长或越界写入。

## 还原

```powershell
pwsh -File restore-en.ps1 -Target "<同上>" -Confirm
```

默认挑目标旁边**最新**的 `.bak-*`，还原前还会把当前文件另存为 `.bak-before-restore-<时间戳>`。

## 目录

| 文件 | 作用 |
| --- | --- |
| `hpp-lib.mjs` | PE/资源解析、UTF-16 与槽位工具 |
| `hpp-extract.mjs` | 从原版 DLL 抽取菜单/对话框/字符串表单元 → `hpp-worklist.json` |
| `hpp-patch.mjs` | 长度保持式写入译文 → `hpp-zh\hammerplusplus_dll.dll` |
| `hpp-gbk.ps1` | ANSI 槽位的 GBK 编码（.NET 代码页 936） |
| `hpp-verify.mjs` | 自检：长度不变、槽位边界、译文长度上限 |
| `install-zh.ps1` / `restore-en.ps1` | 带 SHA-256 校验和自动备份的安装 / 还原 |
| `hpp-worklist.json` | 与当前版本对应的可翻译单元清单（含 fileOff / maxUnits / 原文） |
| `hpp-zh-dict.json` | 译文字典 |
| `docs\HammerPlusPlus-DLL结构笔记.md` | 逆向笔记：资源布局与改写约束 |

## 已知限制

- 只对白名单里的原版 SHA-256 生效，版本不同需按上面流程重新抽取；
- GBK 无法表示的字符会报错而不是静默变成 `?`；
- 译文超过槽位长度会报错并跳过该条，不会截断；
- 极少数菜单项的文本身与结构字段相邻，靠 `fileOff` 与字符集判定（见结构笔记），换版本时需复核。

## 免责声明

- 本项目只提供脚本、字典与结构说明，**不分发 Hammer++ 本体**；
- 修改的是你本机已安装的副本，风险自负，务必先备份（脚本会强制备份）；
- Hammer++ 版权归原作者，请遵守其许可。

## License

MIT（仅覆盖本仓库的脚本、字典与文档）
