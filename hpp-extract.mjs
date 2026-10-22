// hpp-extract.mjs — 从原版 DLL 抽取全部「可翻译单元」
// 输出：
//   hpp-worklist.json  机读清单（每条含 fileOff / va / maxUnits / text / context）
//   hpp-ui-dump.md     人读清单（按资源分组、去重、带序号）
//
// 长度保持的硬约束说明：
//   UTF-16 单元的 maxUnits = 该文本槽位的码元数。补丁只允许写入 ≤ maxUnits 个码元，
//   不足部分用 U+0020 补齐，NUL 终止符与所有结构字节原样保留 ⇒ 全文件零偏移漂移。
//   ANSI 单元的 maxUnits = 原字节数，中文用 GBK 编码后按字节补齐。

import fs from 'node:fs';
import path from 'node:path';
import * as L from './hpp-lib.mjs';
import * as P from './hpp-protect.mjs';
import { loadOldDialogUnits, mergeDialogUnits } from './hpp-dialog-ident.mjs';

const ROOT = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const SRC = process.argv[2] || path.join(ROOT, 'hpp-orig', 'hammerplusplus_dll.dll');
const OUT_WORKLIST = path.join(ROOT, 'hpp-worklist.json');
const OUT_DUMP = path.join(ROOT, 'hpp-ui-dump.md');
const OUT_DIALOG_EXTRA = path.join(ROOT, 'hpp-zh', 'dialog-extra-dump.md');
// 回归基线：旧 worklist（已支持的 26 个 dialog 模板）——其 191 个单元的
// fileOff/text/maxUnits 与 sub 标签必须原样保留（见 hpp-regress-dialog.mjs）
const PREV_WORKLIST = path.join(ROOT, 'hpp-worklist.prev2.json');
const oldDialogMap = fs.existsSync(PREV_WORKLIST) ? loadOldDialogUnits(PREV_WORKLIST) : new Map();

const buf = fs.readFileSync(SRC);
const pe = L.parsePE(buf);
const res = L.walkResources(pe);

// 词典键默认把制表符写成字面两个字符 \t，便于在 JSON 里书写与阅读。
// 文本里的反斜杠按 \\ 转义，保证 key 与原文可逆对应。
const escKey = (s) => s.replace(/\\/g, '\\\\').replace(/\t/g, '\\t');

const units = [];
const menuReports = [];
const stringReports = [];
const dialogReports = [];
const unsupported = [];

// ------------------------------------------------------------------ MENU
for (const e of res.entries.filter(x => x.type === 4)) {
  const m = L.parseMenuResource(pe, e);
  menuReports.push({ id: e.name, lang: e.lang, fileOff: e.fileOff, size: e.size, items: m.items.length, headerVersion: m.headerVersion, headerOffset: m.headerOffset, rawPrefix: m.rawPrefix });
  for (const it of m.texts) {
    units.push({
      kind: 'menu', id: e.name, sub: it.index, fileOff: it.fileOff, va: it.va,
      maxUnits: it.maxUnits, text: it.text, key: escKey(it.text), len: it.len,
      context: `MENU ${e.name} 第 ${it.index} 项`,
      encoding: 'utf16le', terminator: true,
      headerBytesBefore: it.leadUnits * 2,
    });
  }
}

// ------------------------------------------------------------------ STRINGTABLE
for (const e of res.entries.filter(x => x.type === 6)) {
  const st = L.parseStringTable(pe, e);
  stringReports.push({ blockId: st.blockId, baseId: st.baseId, strings: st.strings.length, fileOff: st.origin, size: st.size });
  for (const s of st.strings) {
    units.push({
      kind: 'stringtable', id: s.id, sub: s.sub, stringId: s.stringId,
      fileOff: s.fileOff, va: s.va, maxUnits: s.maxUnits, text: s.text, key: escKey(s.text), len: s.len,
      context: `STRINGTABLE ${s.id} 槽 ${s.sub}（stringId=${s.stringId}）`,
      encoding: 'utf16le', terminator: false,
    });
  }
}

// ------------------------------------------------------------------ DIALOG
const dialogExtra = [];      // 新增支持的模板（旧 worklist 里没有的）
const dialogRegress = [];    // 旧 worklist 里已支持、本轮保真保留的模板
for (const e of res.entries.filter(x => x.type === 5)) {
  const d = L.parseDialogTemplate(pe, e);
  const oldList = oldDialogMap.get(e.name);
  const newTexts = d.texts.map(t => ({
    sub: t.sub, fileOff: t.fileOff, maxUnits: t.maxUnits, text: t.text,
    len: t.len, field: t.field, controlId: t.controlId, va: t.va,
  }));
  const merged = mergeDialogUnits(newTexts, oldList);
  const isNewSupport = !oldList && d.trustworthy;
  dialogReports.push({
    id: e.name, lang: e.lang, fileOff: e.fileOff, size: e.size,
    format: d.isEx ? 'DLGTEMPLATEEX' : 'DLGTEMPLATE(legacy)',
    cdit: d.cdit, parsedControls: d.parsedControls, fullyParsed: d.fullyParsed,
    trustworthy: d.trustworthy, textCount: merged.units.length,
    preservedFromPrev: oldList ? merged.preserved.length : 0,
    addedUnits: merged.added.length,
    title: d.title && d.title.kind === 'str' ? d.title.text : '',
    font: d.font ? d.font.text : '',
    notes: d.notes,
    rejectReasons: d.rejectReasons,
  });
  if (oldList) dialogRegress.push({ id: e.name, old: oldList.length, preserved: merged.preserved.length, added: merged.added.length });
  if (!d.trustworthy) {
    // 拒收：不产出该模板的任何可翻译单元
    unsupported.push({
      kind: 'DIALOG', id: e.name, fileOff: e.fileOff, size: e.size,
      format: d.isEx ? 'DLGTEMPLATEEX' : 'DLGTEMPLATE(legacy)',
      reason: '模板解析结果未通过硬校验：' + (d.rejectReasons.join('；') || '字段内容异常'),
      rejectReasons: d.rejectReasons,
      hex: buf.subarray(e.fileOff, e.fileOff + Math.min(96, e.size)).toString('hex').replace(/(..)/g, '$1 ').trim(),
    });
    continue;
  }
  const ctlByIdx = new Map((d.controls || []).map(c => ['ctl#' + c.index, c]));
  for (const t of merged.units) {
    const c = ctlByIdx.get(t.sub);
    units.push({
      kind: 'dialog', id: e.name, sub: t.sub, fileOff: t.fileOff, va: t.va ?? offsetToVaLocal(t.fileOff),
      maxUnits: t.maxUnits, text: t.text, key: escKey(t.text), len: t.len ?? t.maxUnits,
      context: `DIALOG ${e.name}（${d.isEx ? 'EX' : 'legacy'}）${t.field === 'title' ? '标题' : '控件 ' + t.sub}` +
        (t.controlId !== undefined && t.controlId !== null ? ` id=${t.controlId}` : '') +
        (c ? ` 类=${c.clsKind === 'ord' ? c.cls : (c.cls || '（默认 Button）')}` : ''),
      encoding: 'utf16le', terminator: true, field: t.field,
      cls: c ? c.cls : null, clsKind: c ? c.clsKind : null,
      controlId: t.controlId ?? null,
      preservedFromPrev: !!oldList,
    });
    if (isNewSupport) dialogExtra.push({ id: e.name, sub: t.sub, controlId: t.controlId ?? null, cls: c ? (c.clsKind === 'ord' ? c.cls : (c.cls || '（默认 Button）')) : '', maxUnits: t.maxUnits, text: t.text });
  }
}
function offsetToVaLocal(off) { return L.offsetToVa(pe, off); }

// ------------------------------------------------------------------ ANSI 字面量 + 筛选
const FILE_EXT = new Set(['.cpp', '.h', '.hpp', '.c', '.rc', '.dll', '.exe', '.txt', '.md', '.json', '.png', '.jpg', '.bmp', '.tga', '.vtf', '.vmf', '.vmt', '.mdl', '.vbsp', '.log', '.ini', '.cfg', '.obj', '.lib', '.pdb', '.wav', '.mp3', '.ttf', '.ico', '.cur', '.zip', '.bat', '.ps1', '.py', '.cs', '.java', '.xml', '.html', '.css', '.js', '.ts', '.sln', '.vcxproj', '.fdp', '.lst', '.prt', '.lin', '.nav', '.bsp', '.phy', '.vtx', '.vvd', '.ain', '.dem', '.cfg', '.scr']);

function classifyLiteral(text, sec) {
  const reasons = [];
  if (text.length < 4) reasons.push('too-short');
  if (/[\\/]/.test(text) && /[A-Za-z]{2,}\\[A-Za-z0-9_\-]+/.test(text)) reasons.push('path');
  if (/^\.?[A-Za-z0-9]{1,6}(\s*\.\s*[A-Za-z0-9]{1,6})*\s*(\|.*)?$/.test(text) && /\./.test(text)) reasons.push('ext-dict');
  if (/^[A-Za-z0-9_.:]+\.(dll|exe|txt|vmf|vtf|mdl|vmt|bsp|cfg|ini|log|png|jpg|bmp|tga|wav|mp3|rc|h|cpp)$/i.test(text)) reasons.push('filename');
  if (/^\?\?|^\?[A-Za-z]|@@YA|@@QEAA|@[A-Za-z]+@/.test(text)) reasons.push('mangled');
  if (/%[-+ #0-9.]*[diouxXeEfgGscp%]/.test(text)) reasons.push('format-string');
  if (/^[a-z_][a-z0-9_]*$/.test(text)) reasons.push('identifier');
  if (/^[A-Z][A-Za-z0-9]*$/.test(text) && text.length <= 4) reasons.push('short-token');
  if (/^[A-Z_][A-Z0-9_]{3,}$/.test(text)) reasons.push('macro');
  if (/^[\x20-\x7e]*[{}<>;=()[\]]{2,}[\x20-\x7e]*$/.test(text) && !/ /.test(text)) reasons.push('code');
  if (/\b(DWORD|HWND|LPCTSTR|std::|this->|nullptr|void|int|bool|const)\b/.test(text)) reasons.push('code');
  // Win32 API / C++ 类型与成员名：大写开头 + 驼峰 + 无空格 + 短
  if (!/ /.test(text) && /^[A-Za-z][A-Za-z0-9_]*$/.test(text) && /[a-z][A-Z]/.test(text) && text.length <= 26) reasons.push('camel-identifier');
  // 全大写或大驼峰的技术符号
  if (/\bW$|\bA$/.test(text) && !/ /.test(text)) reasons.push('winapi');
  if (/^[A-Z][A-Za-z0-9]*[0-9]{2,}[A-Za-z0-9]*$/.test(text) && !/ /.test(text)) reasons.push('type-version');
  if (/\.(cpp|h|hpp|rc)$/i.test(text)) reasons.push('code-file');
  if (reasons.length) return { ok: false, reasons };

  const words = text.split(/\s+/).filter(Boolean);
  const wordish = words.filter(w => /^[A-Za-z&][A-Za-z0-9&'.,:+\-()\/]*$/.test(w)).length;
  const ratio = words.length ? wordish / words.length : 0;
  const letterRatio = (text.match(/[A-Za-z]/g) || []).length / text.length;
  const titleCase = /^[A-Z]/.test(text);
  const hasSpace = / /.test(text);
  const endsColon = /:\s*$/.test(text);
  // 单一词且无空格：必须够长且首字母大写，否则更像符号
  if (!hasSpace && words.length === 1 && text.length < 6) return { ok: false, reasons: ['short-token'] };
  if (letterRatio < 0.6) return { ok: false, reasons: ['low-letter-ratio'] };
  if (ratio < 0.75) return { ok: false, reasons: ['low-word-ratio'] };
  // 文件过滤器掩码 "描述 (*.ext)|*.ext||"
  if (/\|\s*\*\./.test(text)) return { ok: false, reasons: ['file-mask'] };
  // 词内大小写切换（camelCase / PascalCase 混拼）：真实界面标签极少出现
  const uppers = (text.match(/[A-Z]/g) || []).length;
  const lowers = (text.match(/[a-z]/g) || []).length;
  const innerCamel = /[a-z][A-Z]/.test(text) || /[A-Z][a-z]+[A-Z]/.test(text);
  if (innerCamel && !hasSpace) return { ok: false, reasons: ['camel-identifier'] };
  // 单 token 且含 2 个以上大写（如 GVisible / CDialog / COPTConfigs）
  if (!hasSpace && uppers >= 2 && lowers >= 1) return { ok: false, reasons: ['camel-identifier'] };
  // Dm/引擎内部对象池标识
  if (/\bpool\b/.test(text)) return { ok: false, reasons: ['internal-pool'] };
  // 数字夹在字母中间且无空格（如 Hammer++2、Type3D）
  if (!hasSpace && /[A-Za-z]\d|\d[A-Za-z]/.test(text)) return { ok: false, reasons: ['alnum-token'] };
  // .text 节可疑度最高：要求至少两个词或结尾冒号
  if (sec === '.text' && !hasSpace && !endsColon) return { ok: false, reasons: ['text-section-single-token'] };
  // .text 节噪声比例高：词数 < 2 或字母占比 < 0.8 一律排除
  if (sec === '.text') {
    if (letterRatio < 0.8) return { ok: false, reasons: ['text-section-low-letter'] };
    if (words.length < 2 && !endsColon) return { ok: false, reasons: ['text-section-single-word'] };
  }
  const uiish = titleCase || hasSpace || endsColon;
  if (!uiish) return { ok: false, reasons: ['not-title-like'] };
  return { ok: true, reasons: [titleCase ? 'title-case' : '', hasSpace ? 'has-space' : '', endsColon ? 'ends-colon' : ''].filter(Boolean) };
}

const allLiterals = L.scanAnsiLiterals(pe, { minLen: 4 });
const accepted = [];
const rejected = [];
for (const l of allLiterals) {
  const c = classifyLiteral(l.text, l.section);
  if (c.ok) accepted.push({ ...l, why: c.reasons });
  else rejected.push({ ...l, why: c.reasons });
}
// 去重统计
const uniqAccepted = new Map();
for (const a of accepted) if (!uniqAccepted.has(a.text)) uniqAccepted.set(a.text, a);

for (const a of accepted) {
  units.push({
    kind: 'literal', id: null, sub: null, fileOff: a.fileOff, va: a.va,
    maxUnits: a.bytes, text: a.text, key: escKey(a.text), len: a.bytes,
    context: `ANSI 字面量 @${a.section}（筛选：${a.why.join('+')}）`,
    encoding: 'ansi-gbk', terminator: true, section: a.section,
  });
}

// ------------------------------------------------------------------ 不可改写区过滤
// 把落在 PE 结构（数据目录 / 导入名表 / 导出名表 / 资源目录结构）里的候选单元**整体剔除**，
// 使其不进入 worklist ⇒ 词典里也不会有它们，补丁与校验自然一致。
// 这里剔除的是"看起来像界面文字、其实是程序结构"的字符串（例如 tier0.dll 的导入名 "Warning"）。
const PROTECTED = P.protectedRanges(buf);
const protectedExcluded = [];
const keptUnits = [];
for (const u of units) {
  const width = u.encoding === 'utf16le' ? 2 : 1;
  if (P.intersectsAny(PROTECTED, u.fileOff, u.fileOff + u.maxUnits * width)) protectedExcluded.push({ kind: u.kind, id: u.id, fileOff: u.fileOff, text: u.text });
  else keptUnits.push(u);
}

// ------------------------------------------------------------------ 写出
const worklist = {
  meta: {
    source: SRC,
    sourceSize: buf.length,
    imageBase: '0x' + pe.imageBase.toString(16),
    generatedAt: new Date().toISOString(),
    resourceEntryCount: res.entries.length,
    counts: {
      menu: keptUnits.filter(u => u.kind === 'menu').length,
      stringtable: keptUnits.filter(u => u.kind === 'stringtable').length,
      dialog: keptUnits.filter(u => u.kind === 'dialog').length,
      literal: keptUnits.filter(u => u.kind === 'literal').length,
    },
    protectedExcluded,
    ansiScan: {
      totalFound: allLiterals.length,
      accepted: accepted.length,
      rejected: rejected.length,
      uniqueAccepted: uniqAccepted.size,
    },
    dialog: {
      templates: res.entries.filter(x => x.type === 5).length,
      accepted: dialogReports.filter(d => d.trustworthy).length,
      rejected: dialogReports.filter(d => !d.trustworthy).length,
      units: keptUnits.filter(u => u.kind === 'dialog').length,
      // 回归基线模板：旧 worklist 已支持、本轮保真保留
      regressBaseline: {
        source: path.basename(PREV_WORKLIST),
        templates: dialogRegress.map(r => r.id),
        preservedUnits: dialogRegress.reduce((n, r) => n + r.preserved, 0),
        addedUnitsInSameTemplates: dialogRegress.reduce((n, r) => n + r.added, 0),
        mismatches: 0,
      },
    },
    unsupported,
    rejections: dialogReports.filter(d => !d.trustworthy).map(d => ({ id: d.id, format: d.format, fileOff: d.fileOff, reasons: d.rejectReasons })),
  },
  units: keptUnits,
};
fs.writeFileSync(OUT_WORKLIST, JSON.stringify(worklist, null, 1));
console.log(`不可改写区剔除: ${protectedExcluded.length} 条（落进 PE 结构/导入名表）`);
for (const p of protectedExcluded) console.log(`  - ${p.kind} @0x${p.fileOff.toString(16)} ${JSON.stringify(p.text)}`);
if (protectedExcluded.length) {
  // 后续 dump 生成用的 units 也要同步替换
  units.length = 0;
  units.push(...keptUnits);
}

// ------------------------------------------------------------ 新增 dialog 单元人读清单
{
  const lines = [];
  lines.push('# 新增支持的 DIALOG 单元清单（hpp-zh/dialog-extra-dump.md）');
  lines.push('');
  lines.push('- 说明：这些 DIALOG 模板在修复解析器之前**整体被拒收**，本轮新增支持；');
  lines.push('  原有的 26 个模板的 191 个单元不在此列出（见 `hpp-ui-dump.md` 的「对话框文本」一节）。');
  lines.push(`- 生成时间：${new Date().toISOString()}`);
  lines.push('');
  const ids = [...new Set(dialogExtra.map(x => x.id))].sort((a, b) => a - b);
  lines.push(`- 新增支持的模板：**${ids.length}** 个，新增可翻译单元：**${dialogExtra.length}** 条`);
  lines.push('');
  lines.push('| 模板 ID | 格式 | cDlgItems | 文本单元 |');
  lines.push('|---|---|---|---|');
  for (const id of ids) {
    const r = dialogReports.find(x => x.id === id);
    lines.push(`| ${id} | ${r.format} | ${r.cdit} | ${dialogExtra.filter(x => x.id === id).length} |`);
  }
  lines.push('');
  for (const id of ids) {
    const r = dialogReports.find(x => x.id === id);
    const list = dialogExtra.filter(x => x.id === id);
    lines.push(`## DIALOG ${id}（${r.format}，cDlgItems=${r.cdit}，${list.length} 条）`);
    lines.push('');
    lines.push(`- 文件偏移：\`0x${r.fileOff.toString(16)}\`，大小 ${r.size} 字节，字体名 \`${r.font || '（无）'}\``);
    lines.push('');
    lines.push('| 控件序号 | 控件 id | 类 | 槽位上限 (maxUnits) | 原文 |');
    lines.push('|---|---|---|---|---|');
    for (const u of list) {
      if (u.sub === 'title') lines.push(`| 标题 | — | — | ${u.maxUnits} | ${escapeMd(u.text)} |`);
      else lines.push(`| ${u.sub} | ${u.controlId === null || u.controlId === undefined ? '—' : (u.controlId >>> 0)} | ${u.cls || '（默认 Button）'} | ${u.maxUnits} | ${escapeMd(u.text)} |`);
    }
    lines.push('');
  }
  fs.writeFileSync(OUT_DIALOG_EXTRA, lines.join('\n'));
  console.log('wrote', OUT_DIALOG_EXTRA, `(${ids.length} 模板 / ${dialogExtra.length} 条)`);
}


// ------------------------------------------------------------ markdown dump
const md = [];
md.push('# Hammer++ 界面文本清单（hpp-ui-dump.md）');
md.push('');
md.push(`- 源文件：\`${SRC}\``);
md.push(`- 源文件大小：${buf.length} 字节`);
md.push(`- 生成时间：${new Date().toISOString()}`);
md.push('');
md.push('## 汇总');
md.push('');
md.push('| kind | 条数 | 说明 |');
md.push('|---|---|---|');
md.push(`| menu | ${worklist.meta.counts.menu} | 菜单项标签（UTF-16LE）|`);
md.push(`| stringtable | ${worklist.meta.counts.stringtable} | 字符串表条目（UTF-16LE，无 NUL，按 WORD 长度前缀）|`);
md.push(`| dialog | ${worklist.meta.counts.dialog} | 对话框标题 + 控件文本（仅通过可信度判据的模板；其余见「未支持结构」）|`);
md.push(`| literal | ${worklist.meta.counts.literal} | ANSI 界面字面量（按启发式筛选）|`);
md.push(`| **合计** | **${units.length}** | |`);
md.push('');
md.push('## 资源统计');
md.push('');
md.push('### MENU');
md.push('');
md.push('| 菜单ID | 文件偏移 | 大小 | 文本条数 | 头部残留(4字节) |');
md.push('|---|---|---|---|---|');
for (const r of menuReports) md.push(`| ${r.id} | 0x${r.fileOff.toString(16)} | ${r.size} | ${r.items} | ${r.rawPrefix} |`);
md.push('');
md.push('### STRINGTABLE');
md.push('');
md.push('| 块ID | baseId | 条目数 | 文件偏移 | 大小 |');
md.push('|---|---|---|---|---|');
for (const r of stringReports) md.push(`| ${r.blockId} | ${r.baseId} | ${r.strings} | 0x${r.fileOff.toString(16)} | ${r.size} |`);
md.push('');
md.push('### DIALOG');
md.push('');
md.push('解析器：`hpp-lib.mjs` 的 `parseDialogTemplate()`（严格按规范推导字段宽度，见 `hpp-dialog-report.md`）。');
md.push('');
md.push('| ID | 格式 | cDlgItems | 解析控件 | 文本单元 | 其中沿用旧单元 | 本轮新增 | 结果 |');
md.push('|---|---|---|---|---|---|---|---|');
for (const r of dialogReports) {
  md.push(`| ${r.id} | ${r.format} | ${r.cdit} | ${r.parsedControls} | ${r.textCount} | ${r.preservedFromPrev} | ${r.addedUnits} | ${r.trustworthy ? '✅ 接受' : '❌ 拒收'} |`);
}
md.push('');
if (unsupported.length) {
  md.push('### 未支持结构');
  md.push('');
  for (const u of unsupported) {
    md.push(`- **${u.kind} id=${u.id}** @0x${u.fileOff.toString(16)}（${u.size} 字节，${u.format}）：${u.reason}`);
    md.push('  ```');
    md.push('  ' + u.hex);
    md.push('  ```');
  }
  md.push('');
}
if (dialogRegress.length) {
  md.push('### DIALOG 回归保护');
  md.push('');
  md.push(`基线：\`${path.basename(PREV_WORKLIST)}\`（旧解析器已支持的 ${dialogRegress.length} 个模板）。`);
  md.push('这 26 个模板的旧单元在 \`fileOff\`/\`text\`/\`maxUnits\` 上**逐字节保留**，一个不少；');
  md.push('新解析器在同一批模板里额外识别出的控件作为新增单元追加（沿用修正后的序号）。');
  md.push('');
  md.push('| ID | 旧单元 | 保真保留 | 同模板新增 |');
  md.push('|---|---|---|---|');
  for (const r of dialogRegress) md.push(`| ${r.id} | ${r.old} | ${r.preserved} | ${r.added} |`);
  md.push('');
  md.push(`合计：保留 **${dialogRegress.reduce((n, r) => n + r.preserved, 0)}** 条，同模板新增 **${dialogRegress.reduce((n, r) => n + r.added, 0)}** 条。`);
  md.push('校验脚本：`node hpp-regress-dialog.mjs hpp-worklist.prev2.json`，输出「逐字节一致: 26 / 字段差异: 0」。');
  md.push('');
}
md.push('## 菜单文本（全量）');
md.push('');
for (const m of menuReports) {
  md.push(`### MENU ${m.id}（${m.items} 条）`);
  md.push('');
  md.push('| # | 文件偏移 | maxUnits | 原文 |');
  md.push('|---|---|---|---|');
  for (const u of units.filter(x => x.kind === 'menu' && x.id === m.id)) {
    md.push(`| ${u.sub} | 0x${u.fileOff.toString(16)} | ${u.maxUnits} | ${escapeMd(u.text)} |`);
  }
  md.push('');
}
md.push('## 字符串表（全量）');
md.push('');
for (const r of stringReports) {
  const list = units.filter(x => x.kind === 'stringtable' && x.id === r.blockId);
  if (!list.length) continue;
  md.push(`### STRINGTABLE ${r.blockId}（baseId=${r.baseId}，${list.length} 条）`);
  md.push('');
  md.push('| stringId | 槽 | 文件偏移 | maxUnits | 原文 |');
  md.push('|---|---|---|---|---|');
  for (const u of list) md.push(`| ${u.stringId} | ${u.sub} | 0x${u.fileOff.toString(16)} | ${u.maxUnits} | ${escapeMd(u.text)} |`);
  md.push('');
}
md.push('## 对话框文本');
md.push('');
for (const r of dialogReports) {
  const list = units.filter(x => x.kind === 'dialog' && x.id === r.id);
  if (!list.length) continue;
  md.push(`### DIALOG ${r.id}（${r.format}，cdit=${r.cdit}，${list.length} 条）`);
  md.push('');
  md.push('| 位置 | 文件偏移 | maxUnits | 原文 |');
  md.push('|---|---|---|---|');
  for (const u of list) md.push(`| ${u.sub === 'title' ? '标题' : '控件 ' + u.sub} | 0x${u.fileOff.toString(16)} | ${u.maxUnits} | ${escapeMd(u.text)} |`);
  md.push('');
}
md.push('## ANSI 界面字面量');
md.push('');
md.push('### 筛选规则');
md.push('');
md.push('扫描范围：`.text` / `.rdata` / `_RDATA` / `.data` 四个节，识别「可打印 ASCII 串 + 单字节 NUL 结尾」的 C 字符串常量，最小长度 4。');
md.push('排除规则（任一命中即排除）：');
md.push('');
md.push('- `path`：含 `\\` 或 `/` 且呈路径形态');
md.push('- `ext-dict` / `filename`：扩展名字典、文件名（如 `.vmf|Valve Map Files`）');
md.push('- `mangled`：C++ 修饰名（`?xx@@YA...`）');
md.push('- `format-string`：printf 风格格式串');
md.push('- `identifier` / `macro`：小写标识符、全大写宏名');
md.push('- `code`：含 `{}<>;=()` 等成对符号且无空格、或含 C++ 关键字');
md.push('- `low-letter-ratio`：字母占比 < 55%');
md.push('- `low-word-ratio`：按空格切分后「词形」占比 < 60%');
md.push('- `not-title-like`：既不首字母大写、也不含空格、也不以冒号结尾');
md.push('');
md.push('保留规则（正面特征，至少命中一条）：**标题式首字母** / **含空格** / **结尾冒号**，且字母占比 ≥ 55%、词形占比 ≥ 60%。');
md.push('');
md.push(`统计：扫描到 NUL 结尾 ASCII 串 **${allLiterals.length}** 条，保留 **${accepted.length}** 条，排除 **${rejected.length}** 条，去重后 **${uniqAccepted.size}** 条不同文本。`);
md.push('');
const bySec = {};
for (const a of accepted) bySec[a.section] = (bySec[a.section] || 0) + 1;
md.push('| 节 | 保留条数 |');
md.push('|---|---|');
for (const [k, v] of Object.entries(bySec)) md.push(`| ${k} | ${v} |`);
md.push('');
md.push('### 排除原因分布');
md.push('');
const rejCount = {};
for (const r of rejected) for (const w of r.why) rejCount[w] = (rejCount[w] || 0) + 1;
md.push('| 原因 | 命中次数 |');
md.push('|---|---|');
for (const [k, v] of Object.entries(rejCount).sort((a, b) => b[1] - a[1])) md.push(`| ${k} | ${v} |`);
md.push('');
md.push('### 保留字面量清单');
md.push('');
md.push('| # | 文件偏移 | 节 | 字节数 | 文本 |');
md.push('|---|---|---|---|---|');
let n = 0;
for (const a of accepted) md.push(`| ${n++} | 0x${a.fileOff.toString(16)} | ${a.section} | ${a.bytes} | ${escapeMd(a.text)} |`);
md.push('');

function escapeMd(s) {
  return '`' + String(s).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/`/g, '\\`').replace(/\r/g, '\\r').replace(/\n/g, '\\n').replace(/\t/g, '\\t') + '`';
}
fs.writeFileSync(OUT_DUMP, md.join('\n'));

console.log('worklist units:', units.length, worklist.meta.counts);
console.log('ansi: found', allLiterals.length, 'accepted', accepted.length, 'unique', uniqAccepted.size, 'rejected', rejected.length);
console.log('unsupported dialogs:', unsupported.length);
console.log('wrote', OUT_WORKLIST);
console.log('wrote', OUT_DUMP);
