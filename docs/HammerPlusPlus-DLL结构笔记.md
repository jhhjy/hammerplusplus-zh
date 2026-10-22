# Hammer++ DLL 结构笔记（改写前必读）

对象：`hammerplusplus_dll.dll`（Hammer++ 6.x，L4D2 版）
性质：**PE32（32 位）**，ImageBase `0x10000000`，文件长度 15,507,968 字节，**原生 Win32/MFC 界面**（无 vgui2）。

---

## 1. 节表与关键数据目录

| 节 | VA | VSize | 文件偏移 | RawSize |
| --- | --- | --- | --- | --- |
| `.text` | 0x1000 | 9082346 | 1024 | 9082368 |
| `.rdata` | 0x8ab000 | 1574842 | 9083392 | 1574912 |
| `.data` | 0xa2c000 | 2076012 | 10658304 | 427520 |
| `_RDATA` | 0xc27000 | 177136 | 11085824 | 177152 |
| `.fptable` | 0xc53000 | 128 | 11262976 | 512 |
| `.rsrc` | 0xc54000 | 3538144 | 11263488 | 3538432 |
| `.reloc` | 0xfb4000 | 705916 | 14801920 | 706048 |

**资源清单**：MENU 5 个 / DIALOG 92 个 / STRINGTABLE 65 块 / ACCELERATOR 3 个 / ICON 50 / BITMAP 14 / CURSOR 35 / AFX_DIALOG_LAYOUT 49 / VERSION 1 / 自定义类型 #240 8、#241 5。资源树共 374 条。

**导出**：仅 67 个按名导出，全是静态链接的 Embree C++ 修饰符号（`?add@ThreadPool@TaskScheduler@embree@@…`）。
**导入**：22 个 DLL（其中 `tier0.dll` 44 个函数、`vstdlib.dll` 12 个、`steam_api.dll` 4 个是本目录内可核对的）。

---

## 2. 三种文本资源的真实布局

### MENU（**不是** MENUEX）
```
资源起点：DWORD（头部残余）
每个菜单项：DWORD dwType | WORD wID | UTF-16LE 文本（NUL 结尾）| 对齐填充（0 或 2 字节）
```
要点：
- 文本槽位长度 **等于文本码元数**，前后都紧邻结构字节；**绝不能按"到下一个 NUL"量槽位**，会多算 2 字节并覆盖下一项的 `wID`。
- 结构字段（`dwType` 高位、`wID`）与文本处在同一段"非 NUL 码元串"里，必须严格剔除：**只接受 0x20–0x7E 与制表符**作为标签字符。
- 特例：某项 `wID` 的低字节若恰是可打印 ASCII（例如 `wID=0x0071` → `'q'`），会被并进标签（曾出现 `qTransform` → 真相 `Transform`）。判据：**fileOff 前一个码元为 `0x0000`** ⇒ 标签起点早了 2 字节，右移一个码元。

### STRINGTABLE
```
每块 16 槽：WORD len | WCHAR[len]      （没有 NUL！len=0 表示空槽）
stringId = (blockId - 1) * 16 + slot
```

### DIALOG（DLGTEMPLATEEX 与 legacy 并存）
```
EX:     WORD dlgVer(1) | WORD signature(0xFFFF) | DWORD helpID | DWORD exStyle | DWORD style
        | WORD cDlgItems | short x,y,cx,cy | menu | windowClass | title
        | (style & DS_SETFONT ? WORD pointSize|WORD weight|BYTE italic|BYTE charset|typeface)
        | 对齐 4 字节 | 控件数组
控件EX: DWORD helpID | DWORD exStyle | DWORD style | short x,y,cx,cy | DWORD id
        | class | title | WORD extraCount | creationData | 对齐 4 字节

legacy: DWORD style | DWORD exStyle | WORD cdit | short x,y,cx,cy | menu | class | title
        | (DS_SETFONT ? WORD pointSize) | 对齐 4 字节 | 控件数组
控件legacy: DWORD style | DWORD exStyle | short x,y,cx,cy | WORD id   ← id 是 WORD！
        | class | title | WORD extraCount | creationData | 对齐 4 字节
```
变长字段 `menu`/`windowClass`/`title` 三态：`0x0000`（无）| `0xFFFF` + `WORD` 序数 | UTF-16LE NUL 结尾串。

**曾导致 65 个模板被误拒的两处错误**：
1. legacy 控件 `id` 按 `DWORD` 读（应为 `WORD`）⇒ 20 个 legacy 模板整体失步；
2. 字体块结束后未对齐到 4 字节 ⇒ 45 个 EX 模板首控件起点偏 2 字节。
修正后 **92/92 模板唯一自洽**（控件数恰等于 `cDlgItems`，结束位置落在资源末尾 ±2 字节）。

> 曾被记为"无法解释的 4 字节差值"（dialog 100）：真相只是字体名 `Microsoft Sans Serif`（止于 +94 的 NUL）之后的 **2 字节对齐填充**（+94..+95）把首控件对齐到 +96。旧判据把字体名的尾巴 `Serif` 误当成了被截断的窗类名。
> 另有 MFC 占位符：控件 title 形如 `U+FFFF U+xxxx`（如 dialog 100 的 `FF FF AF 00`）**不是给人看的文字，绝不能翻译**。

---

## 3. ⚠️ 不可改写区（血的教训）

**事故**：`.rdata` 里有 4 个字符串看着像界面词，实际是本 DLL 从 `tier0.dll` **导入的函数名**：
`Warning`、`Rectangle`、`Ellipse`、`Polygon`。
字面量筛选把它们翻成中文（GBK）后**覆盖了导入名表**，加载期无法解析导入，弹出
「无法定位程序输入点」（GBK 字节在对话框里显示成方框 □□□□□），Hammer++ 直接无法启动。

**为什么当时没发现**：检查只覆盖了「PE 数据目录范围」，而**导入名表在 `.rdata`、不属于任何数据目录**。

**现在的三层防护**（`hpp-protect.mjs` + 抽取 + 补丁）：
1. `hpp-protect.mjs` 计算不可改写区：除资源目录外的 15 个数据目录、每个导入 DLL 的名字串、每个
   `IMAGE_IMPORT_BY_NAME`（Hint + 名字）、thunk 数组、导出名串/指针表、资源目录**结构**；
2. `hpp-extract.mjs` 在抽取阶段直接剔除相交候选（当前剔除 4 条）⇒ 它们不进入 worklist，也就不会被翻译；
3. `hpp-patch.mjs` 保留硬拦截 + **写前最终断言**（任何已规划槽位与保护区相交即中止，不写文件）。

**注意**：资源目录只保护**目录结构**，数据块（菜单/对话框/字符串表文本）正是改写目标，不能整段保护。

**最后一道防线**：`node check-imports.mjs`（已接入流水线第 6 步）——补丁后核对按名导入是否全部可解析，缺失即非零退出。

---

## 4. 改写铁律

1. **长度保持**：槽位内写入，**一个字节都不移动**（移动即破坏所有 RVA/偏移/重定位）。
2. UTF-16 单元：写入译文后用**空格 U+0020 补齐到 `maxUnits`**；已全量验证终止 NUL 位于槽位之外（`fileOff + maxUnits*2` 处），**不要在槽位内再写 NUL**（会静默吃掉最后一个字，例：`OK`→`确定` 变成「确」）。
3. ANSI 字面量：**默认用 GBK（代码页 936）**，但存在按 UTF-8 消费的情形——见第 5 节。
4. 放不下就换短译或不做，**绝不静默截断**（补丁会报错并列出条目）。
5. 资源里的 `U+FFFF U+xxxx` 占位符、控件内部名（`Spin1`/`Slider1`/`List1`）、字体名、窗类名、实体类名、键值名、控制台命令**一律不译**。

---

## 5. ⚠️ ANSI 字面量的编码不是统一的 GBK

**实证（2026-10-19 用户截图）**：窗口标题 `Face Edit Sheet` 用 GBK 写入后，界面显示成
「◇? ◇? 起 ◇?」——这是**GBK 字节被当作 UTF-8 解码**的典型结果（随机汉字 + 未定义字形方框）。

结论：这个 DLL 的 ANSI 字面量**存在按 UTF-8 消费的情形**（至少窗口标题这类），
不能一律按系统 ACP(936) 处理。

**机制**：词典用 `$utf8: ["原文", ...]` 声明哪些字面量按 UTF-8 写入
（`hpp-patch.mjs` 已支持；`hpp-verify.mjs` 会按 UTF-8 校验并检查空格填充与终止 NUL）。
UTF-8 中文 3 字节/字，槽位按字节计：`Face Edit Sheet`（15 字节）最多放 5 个汉字，
现用「贴面编辑」（12 字节）。

**待办**：其余 ANSI 字面量仍按 GBK 写入；若后续发现某些消息框乱码，把对应原文加进 `$utf8` 即可。

---

## 6. 静态标签的中文宽度预算（避免被控件截断）

Hammer++ 的对话框是原生 Win32 模板，**标签/按钮宽度按英文原文排**，中文更宽就会被**截断**
（这不是乱码，是显示不全）。

由截图实证反推的预算：

| 英文长度 | 可放汉字 | 实证 |
| --- | --- | --- |
| 14（`Texture scale:`） | 5 | 放 5 字正常 ✅ |
| 12（`Luxel scale:`） | 5 | 放 6 字被切 ❌ |
| 10（`VisGroups:`） | 4 | 放 5 字被切 ❌ |
| 7（`Justify`） | 2 | 放 4 字被切 ❌ |

简化公式：**汉字数 ≤ floor(英文长度 / 2) − 1**；带 `(&X)` 快捷键的还要再让 2 个字。

已修复（写在 `merge-dicts.mjs` 的 DECISIONS 里，重跑不丢）：

| 原文 | 旧译（被截断/乱码） | 现译 |
| --- | --- | --- |
| `Luxel scale:` | 光照元缩放： | **光照精度：** |
| `VisGroups:` | 可见性分组： | **可见性：** |
| `Justify` | 对齐方式 | **贴合** |
| `Treat as &one` | 视为整体(&O) | **视为(&O)** |
| `Face Edit Sheet` | 贴面编辑面板（GBK → 乱码） | **贴面编辑**（UTF-8） |

**QA 工具**：`node analyze-overflow.mjs`（用宽度代理列出可能被截断的标签，
输出 `hpp-zh/overflow-labels.json`）。剩余条目可分批改短，直接往 DECISIONS 加条目即可。
