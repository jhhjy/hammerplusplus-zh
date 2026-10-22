// hpp-patch.mjs — 长度保持式替换
//
// 设计要点（保证「绝不移位」）：
//   每个可翻译单元的槽位长度 = maxUnits（UTF-16 为码元数，ANSI 为字节数）。
//   补丁只在该槽位内部写字节：
//     - UTF-16 且需要终止符（菜单/对话框）：写入译文 → 空格补齐 → 末位写 U+0000；
//       若译文长度恰好等于 maxUnits，则末位就是终止符，不再补空格。
//     - UTF-16 无终止符（字符串表）：写入译文 → 空格补齐到 maxUnits。
//     - ANSI：写入 GBK 字节 → 空格补齐 → 保留原终止 NUL。
//   槽位之外一个字节都不动 ⇒ 文件长度不变、所有结构偏移不变。
//
// 用法：
//   node hpp-patch.mjs                 # 规划；若存在 ANSI 单元且无 GBK 数据，输出请求并退出码 2
//   node hpp-patch.mjs --gbk-file X    # 用 X 提供的 GBK 十六进制数据执行
//   node hpp-patch.mjs --ascii-only    # 无 GBK 时用 ASCII 近似（仅用于无 ANSI 条目的流程自测）

import fs from 'node:fs';
import path from 'node:path';
import * as L from './hpp-lib.mjs';

const ROOT = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const argv = process.argv.slice(2);
const opt = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
const flag = (n) => argv.includes(n);

const SRC = opt('--src', path.join(ROOT, 'hpp-orig', 'hammerplusplus_dll.dll'));
const WORKLIST = opt('--worklist', path.join(ROOT, 'hpp-worklist.json'));
const DICT = opt('--dict', path.join(ROOT, 'hpp-zh-dict.json'));
const OUTDIR = opt('--outdir', path.join(ROOT, 'hpp-zh'));
const OUTDLL = path.join(OUTDIR, path.basename(SRC));
const REPORT = path.join(OUTDIR, 'patch-report.md');
const GBK_REQUEST = path.join(OUTDIR, 'hpp-gbk-request.json');

const orig = fs.readFileSync(SRC);
const worklist = JSON.parse(fs.readFileSync(WORKLIST, 'utf8'));
const dict = JSON.parse(fs.readFileSync(DICT, 'utf8'));

// 字典形态：{ "原文": "中文" } 外加可选 "exact": [ {kind,id,fileOff,text} ]
const map = {};
const exactList = [];
for (const [k, v] of Object.entries(dict)) {
  if (k === 'exact') { exactList.push(...(Array.isArray(v) ? v : [])); continue; }
  if (k === '$comment' || k.startsWith('$')) continue;
  if (typeof v === 'string') map[k] = v;
}
const exactMap = new Map();
for (const e of exactList) exactMap.set(`${e.kind}|${e.id}|${e.fileOff}`, e.text);

// 词典可声明 $utf8: ["原文", ...] —— 这些 ANSI 字面量按 UTF-8 写入，其余按 GBK。
// 依据见 ANSI 分支注释：该 DLL 的 ANSI 字面量存在「按 UTF-8 消费」的情形（如窗口标题）。
const UTF8_TEXTS = new Set(Array.isArray(dict.$utf8) ? dict.$utf8 : []);

const units = worklist.units;

// ---------------------------------------------------------------- 不可改写区（关键安全网）
// 事故教训：.rdata 里有一处 "Warning" 并不是界面文字，而是本 DLL 从 tier0.dll
// **导入的函数名**（IMAGE_IMPORT_BY_NAME）。字面量筛选把它当日志/提示词翻成了「警告」，
// GBK 字节覆盖导入名表 → 加载期解析导入失败 → 「无法定位程序输入点」弹窗。
// 之前的检查只覆盖「PE 数据目录范围」，而导入名表在 .rdata、不在目录范围内，属检查盲区。
// 现在把下列区域全部算作**不可改写**，任何槽位与其相交一律拒绝：
//   16 个数据目录本身；每个导入 DLL 的名字串、Hint/Name 串与 thunk 数组；
//   导出目录的名字串/序号表/地址表；资源目录的目录结构与数据入口（数据块本身可改，即我们的目标）。
function computeProtected(buf) {
  const peOff = buf.readUInt32LE(0x3c);
  const coff = peOff + 4;
  const nSec = buf.readUInt16LE(coff + 2);
  const optSize = buf.readUInt16LE(coff + 16);
  const optOff = coff + 20;
  const secOff = optOff + optSize;
  const secs = [];
  for (let i = 0; i < nSec; i++) {
    const o = secOff + i * 40;
    secs.push({ va: buf.readUInt32LE(o + 12), vsize: buf.readUInt32LE(o + 8), rawPtr: buf.readUInt32LE(o + 20), rawSize: buf.readUInt32LE(o + 16) });
  }
  const r2o = (rva) => { for (const s of secs) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) return s.rawPtr + (rva - s.va); return -1; };
  const dirOff = optOff + 96;
  const R = [];
  const add = (off, len) => { if (off >= 0 && len > 0) R.push([off, off + len]); };
  const cstr = (off) => { let e = off; while (e < buf.length && buf[e] !== 0) e++; return e - off + 1; };

  const dirs = {};
  for (let i = 0; i < 16; i++) {
    const rva = buf.readUInt32LE(dirOff + i * 8), size = buf.readUInt32LE(dirOff + i * 8 + 4);
    dirs[i] = { rva, size, off: rva ? r2o(rva) : -1 };
    // 注意：资源目录（i=2）**不能整段保护** —— 菜单/对话框/字符串表的文本数据块就在其中，
    // 那是我们的改写目标。资源只需要保护「目录结构」，由下面的 walk 单独收集。
    if (i !== 2 && rva && size) add(dirs[i].off, size);
  }

  // 导入：DLL 名、Hint/Name 串、thunk 数组
  const imp = dirs[1];
  if (imp && imp.off >= 0) {
    let o = imp.off;
    for (let guard = 0; guard < 256; guard++) {
      const oft = buf.readUInt32LE(o), nameRva = buf.readUInt32LE(o + 12);
      if (!nameRva) break;
      const no = r2o(nameRva);
      add(no, cstr(no));
      if (oft) {
        const to = r2o(oft);
        add(to, 4 * (buf.readUInt32LE(to) ? 1 : 0)); // 至少保护首项
        let t = to, n = 0;
        while (buf.readUInt32LE(t) !== 0 && n < 4096) {
          const v = buf.readUInt32LE(t);
          if (!(v & 0x80000000)) { const fo = r2o(v); add(fo, 2 + cstr(fo + 2)); }
          t += 4; n++;
        }
        add(to, (n + 1) * 4);
      }
      o += 20;
    }
  }

  // 导出：名字串、序号表、地址表
  const ex = dirs[0];
  if (ex && ex.off >= 0) {
    const nNames = buf.readUInt32LE(ex.off + 24);
    const namePtrRva = buf.readUInt32LE(ex.off + 32);
    if (namePtrRva) {
      const npo = r2o(namePtrRva);
      add(npo, nNames * 4);
      for (let i = 0; i < nNames; i++) { const so = r2o(buf.readUInt32LE(npo + i * 4)); add(so, cstr(so)); }
    }
  }

  // 资源目录结构（不是数据块）：目录头 + 条目 + 数据入口
  const rsrc = dirs[2];
  if (rsrc && rsrc.off >= 0) {
    const base = rsrc.off;
    const seen = new Set();
    const walk = (off, depth) => {
      if (depth > 3 || seen.has(off) || off < 0 || off + 16 > buf.length) return;
      seen.add(off);
      const named = buf.readUInt16LE(off + 12), ided = buf.readUInt16LE(off + 14);
      const total = named + ided;
      add(off, 16 + total * 8);
      for (let i = 0; i < total; i++) {
        const e = off + 16 + i * 8;
        const nameOrId = buf.readUInt32LE(e), childRaw = buf.readUInt32LE(e + 4);
        if (nameOrId & 0x80000000) { const so = base + (nameOrId & 0x7fffffff); add(so, 2 + buf.readUInt16LE(so) * 2); }
        if (childRaw & 0x80000000) walk(base + (childRaw & 0x7fffffff), depth + 1);
        else add(base + (childRaw & 0x7fffffff), 16);
      }
    };
    walk(base, 1);
  }
  return R;
}

const PROTECTED = computeProtected(orig);
const intersects = (s, e) => PROTECTED.some(([ps, pe]) => s < pe && e > ps);

const planned = [];
const stats = {
  total: units.length,
  translateCandidates: 0,
  matched: 0,
  changed: 0,
  identical: 0,
  missing: [],
  tooLong: [],
  protectedSkipped: [],
  unsupportedDropped: worklist.meta.unsupported ? worklist.meta.unsupported.length : 0,
};
const gbkNeeded = [];
const perKind = {};

for (const u of units) {
  perKind[u.kind] = perKind[u.kind] || { total: 0, matched: 0, changed: 0, missing: 0 };
  perKind[u.kind].total++;
  // 不可改写区拦截：槽位若与 PE 结构（含导入名表）相交，一律跳过并记录
  const width = u.encoding === 'utf16le' ? 2 : 1;
  if (intersects(u.fileOff, u.fileOff + u.maxUnits * width)) {
    stats.protectedSkipped.push({ kind: u.kind, id: u.id, fileOff: u.fileOff, text: u.text });
    perKind[u.kind].protectedSkipped = (perKind[u.kind].protectedSkipped || 0) + 1;
    continue;
  }
  const key = `${u.kind}|${u.id}|${u.fileOff}`;
  let zh = exactMap.has(key) ? exactMap.get(key) : map[u.key !== undefined ? u.key : u.text];
  if (zh === undefined) zh = map[u.text];
  if (zh === undefined) {
    stats.missing.push({ kind: u.kind, id: u.id, fileOff: u.fileOff, text: u.text, maxUnits: u.maxUnits, reason: '字典无对应译文' });
    perKind[u.kind].missing++;
    continue;
  }
  stats.translateCandidates++;
  stats.matched++;
  perKind[u.kind].matched++;
  if (zh === u.text) { stats.identical++; continue; }

  if (u.encoding === 'utf16le') {
    // 【关键修正】已验证：485 个带终止符的 UTF-16 单元，其 fileOff + maxUnits*2 处
    // 恒为 0x0000 —— 终止 NUL 位于槽位之外，属于模板结构。因此：
    //   1) 可视容量就是 maxUnits（不能按 maxUnits-1 处理）；
    //   2) 绝不能在槽位最后一个码元再写一个 NUL：那会在译文长度正好等于 maxUnits 时
    //      悄悄吃掉最后一个字（例如 OK → 确定 只剩「确」）。
    // 原模板的 NUL 保持不变，字符串照常被正确终止。
    if (zh.length > u.maxUnits) {
      stats.tooLong.push({ kind: u.kind, id: u.id, fileOff: u.fileOff, text: u.text, zh, maxUnits: u.maxUnits, zhUnits: zh.length, reason: `译文 ${zh.length} 码元 > 槽位 ${u.maxUnits} 码元` });
      continue;
    }
    const body = zh.length < u.maxUnits ? zh + ' '.repeat(u.maxUnits - zh.length) : zh;
    const bytes = Buffer.alloc(u.maxUnits * 2, 0x20);
    Buffer.from(body, 'utf16le').copy(bytes, 0);
    planned.push({ unit: u, zh, body, bytes, kind: u.kind, fileOff: u.fileOff, len: bytes.length });
    stats.changed++;
    perKind[u.kind].changed++;
  } else {
    // ANSI 字面量：编码方式**逐条可覆盖**。
    //
    // 实证：`Face Edit Sheet`（窗口标题）按 GBK 写入后，界面显示成「◇? ◇? 起 ◇?」——
    // 这是 GBK 字节被当作 UTF-8 解码的典型结果（随机汉字 + 未定义字形方框）。
    // 说明该 DLL 里这类字面量是 UTF-8 消费的，而不是系统 ACP(936)。
    // 因此：词典里 `$utf8` 列出的原文用 UTF-8 写入（可直接在此完成），其余仍走 GBK。
    if (UTF8_TEXTS.has(u.text)) {
      const raw = Buffer.from(zh, 'utf8');
      if (raw.length > u.maxUnits) {
        stats.tooLong.push({ kind: u.kind, id: u.id, fileOff: u.fileOff, text: u.text, zh, maxUnits: u.maxUnits, zhBytes: raw.length, reason: `UTF-8 字节 ${raw.length} > 槽位 ${u.maxUnits} 字节` });
      } else {
        const bytes = Buffer.alloc(u.maxUnits, 0x20);
        raw.copy(bytes, 0);
        planned.push({ unit: u, zh, body: zh, bytes, kind: u.kind, fileOff: u.fileOff, len: bytes.length, ansi: true, utf8: true });
        stats.changed++;
        perKind[u.kind].changed++;
      }
      continue;
    }
    // 其余 ANSI：需要 GBK 字节，交给 PowerShell 编码
    gbkNeeded.push({ fileOff: u.fileOff, maxUnits: u.maxUnits, text: u.text, zh, kind: u.kind, id: u.id });
  }
}

// ---------------------------------------------------------------- GBK 阶段
let gbkData = null;
const gbkFile = opt('--gbk-file', null);
if (gbkFile) {
  gbkData = JSON.parse(fs.readFileSync(gbkFile, 'utf8'));
} else if (fs.existsSync(path.join(OUTDIR, 'hpp-gbk-data.json'))) {
  gbkData = JSON.parse(fs.readFileSync(path.join(OUTDIR, 'hpp-gbk-data.json'), 'utf8'));
}

if (gbkNeeded.length && !gbkData) {
  fs.mkdirSync(OUTDIR, { recursive: true });
  fs.writeFileSync(GBK_REQUEST, JSON.stringify({ note: '需用 PowerShell 的 [System.Text.Encoding]::GetEncoding(936) 编码 zh 字段为 hex', entries: gbkNeeded }, null, 1));
  console.log(`已规划 UTF-16 修改 ${stats.changed} 条；另有 ${gbkNeeded.length} 条 ANSI 单元需要 GBK 编码。`);
  console.log(`GBK 请求已写出：${GBK_REQUEST}`);
  console.log('请运行：pwsh -File hpp-gbk.ps1   （或 node hpp-patch.mjs --gbk-file ...）');
  // 仍然先输出仅 UTF-16 的中间结果，便于自证
  process.exitCode = 2;
}

if (gbkData) {
  const byOff = new Map(gbkData.entries.map(e => [e.fileOff, e]));
  for (const g of gbkNeeded) {
    const e = byOff.get(g.fileOff);
    if (!e || typeof e.hex !== 'string') {
      stats.tooLong.push({ kind: g.kind, id: g.id, fileOff: g.fileOff, text: g.text, zh: g.zh, maxUnits: g.maxUnits, zhUnits: null, reason: '缺少 GBK 编码结果' });
      continue;
    }
    const raw = Buffer.from(e.hex, 'hex');
    if (e.overflow) {
      stats.tooLong.push({ kind: g.kind, id: g.id, fileOff: g.fileOff, text: g.text, zh: g.zh, maxUnits: g.maxUnits, zhBytes: raw.length, reason: `GBK 字节 ${raw.length} > 槽位 ${g.maxUnits} 字节` });
      continue;
    }
    if (raw.length > g.maxUnits) {
      stats.tooLong.push({ kind: g.kind, id: g.id, fileOff: g.fileOff, text: g.text, zh: g.zh, maxUnits: g.maxUnits, zhBytes: raw.length, reason: `GBK 字节 ${raw.length} > 槽位 ${g.maxUnits} 字节` });
      continue;
    }
    const bytes = Buffer.alloc(g.maxUnits, 0x20);
    raw.copy(bytes, 0);
    planned.push({ unit: g, zh: g.zh, body: g.zh, bytes, kind: g.kind, fileOff: g.fileOff, len: bytes.length, ansi: true });
    stats.changed++;
    perKind[g.kind] = perKind[g.kind] || { total: 0, matched: 0, changed: 0, missing: 0 };
    perKind[g.kind].changed++;
  }
}

if (stats.tooLong.length) {
  console.error('错误：以下条目译文超长，按约定必须报错而不是静默截断：');
  for (const t of stats.tooLong) console.error(`  ${t.kind} id=${t.id} @0x${t.fileOff.toString(16)} 槽位=${t.maxUnits} 原文=${JSON.stringify(t.text)} 译文=${JSON.stringify(t.zh)} (${t.reason})`);
  process.exitCode = 1;
}

if (stats.protectedSkipped.length) {
  console.log(`已拦截落在「不可改写区」（PE 结构/导入名表/导出名表/资源目录结构）的槽位 ${stats.protectedSkipped.length} 条：`);
  for (const t of stats.protectedSkipped) console.log(`  ${t.kind} @0x${t.fileOff.toString(16)} 原文=${JSON.stringify(t.text)}`);
}

// 最终断言：任何已规划槽位都不得与不可改写区相交（双保险）
const violated = planned.filter((p) => intersects(p.fileOff, p.fileOff + p.bytes.length));
if (violated.length) {
  console.error(`致命：${violated.length} 个已规划槽位落在不可改写区内，已中止写文件：`);
  for (const v of violated) console.error(`  ${v.kind} @0x${v.fileOff.toString(16)} ${JSON.stringify(v.unit.text)}`);
  process.exit(1);
}

// ---------------------------------------------------------------- 应用
const out = Buffer.from(orig);
const touched = [];
for (const p of planned) {
  p.bytes.copy(out, p.fileOff);
  touched.push({ fileOff: p.fileOff, len: p.bytes.length, kind: p.kind, id: p.unit.id, text: p.unit.text, zh: p.zh, ansi: !!p.ansi });
}
fs.mkdirSync(OUTDIR, { recursive: true });
fs.writeFileSync(OUTDLL, out);

// ---------------------------------------------------------------- 校验 + 报告
const diffs = [];
for (let i = 0; i < orig.length; i++) if (orig[i] !== out[i]) diffs.push(i);
const diffMin = diffs.length ? diffs[0] : -1;
const diffMax = diffs.length ? diffs[diffs.length - 1] : -1;
// 合并连续差异区间
const ranges = [];
for (const d of diffs) {
  if (ranges.length && d === ranges[ranges.length - 1][1] + 1) ranges[ranges.length - 1][1] = d;
  else ranges.push([d, d]);
}

const md = [];
md.push('# 汉化补丁报告（patch-report.md）');
md.push('');
md.push(`- 源文件：\`${SRC}\``);
md.push(`- 输出文件：\`${OUTDLL}\``);
md.push(`- 字典：\`${DICT}\`（${Object.keys(map).length} 条映射${exactList.length ? ` + ${exactList.length} 条精确覆盖` : ''}）`);
md.push(`- 生成时间：${new Date().toISOString()}`);
md.push('');
md.push('## 结果总览');
md.push('');
md.push('| 指标 | 数值 |');
md.push('|---|---|');
md.push(`| 可翻译单元总数 | ${stats.total} |`);
md.push(`| 字典命中（有译文） | ${stats.matched} |`);
md.push(`| 实际改写条目 | ${stats.changed} |`);
md.push(`| 译文与原文相同（跳过） | ${stats.identical} |`);
md.push(`| 字典未命中（跳过） | ${stats.missing.length} |`);
md.push(`| **超长条目（报错）** | **${stats.tooLong.length}** |`);
md.push(`| 未支持结构（整体跳过） | ${stats.unsupportedDropped} |`);
md.push(`| 文件长度 | ${orig.length} → ${out.length}（${orig.length === out.length ? '不变 ✅' : '**已改变 ❌**'}）|`);
md.push(`| 差异字节数 | ${diffs.length} |`);
md.push(`| 差异偏移范围 | ${diffs.length ? `0x${diffMin.toString(16)} – 0x${diffMax.toString(16)}` : '无'} |`);
md.push(`| 差异连续区间数 | ${ranges.length} |`);
md.push('');
md.push('## 分类型统计');
md.push('');
md.push('| kind | 单元数 | 字典命中 | 实际改写 |');
md.push('|---|---|---|---|');
for (const [k, v] of Object.entries(perKind)) md.push(`| ${k} | ${v.total} | ${v.matched} | ${v.changed} |`);
md.push('');
if (stats.tooLong.length) {
  md.push('## ⚠ 超长条目（未写入，需修短译文）');
  md.push('');
  md.push('| kind | id | 文件偏移 | 槽位 | 原文 | 译文 | 原因 |');
  md.push('|---|---|---|---|---|---|---|');
  for (const t of stats.tooLong) md.push(`| ${t.kind} | ${t.id} | 0x${t.fileOff.toString(16)} | ${t.maxUnits} | ${JSON.stringify(t.text)} | ${JSON.stringify(t.zh)} | ${t.reason} |`);
  md.push('');
}
md.push('## 改写明细');
md.push('');
md.push('| # | kind | id | 文件偏移 | 字节数 | 原文 | 译文 |');
md.push('|---|---|---|---|---|---|---|');
let i = 0;
for (const t of touched) md.push(`| ${i++} | ${t.kind} | ${t.id} | 0x${t.fileOff.toString(16)} | ${t.len} | ${JSON.stringify(t.text)} | ${JSON.stringify(t.zh)} |`);
md.push('');
md.push('## 差异偏移区间（前 80 个）');
md.push('');
md.push('```');
for (const [a, b] of ranges.slice(0, 80)) md.push(`0x${a.toString(16)} - 0x${b.toString(16)}  (${b - a + 1} 字节)`);
if (ranges.length > 80) md.push(`... 共 ${ranges.length} 个区间`);
md.push('```');
md.push('');
md.push('## 长度保持证明');
md.push('');
md.push('- 每个补丁只写 `[fileOff, fileOff + maxUnits*字节宽)` 区间，区间长度等于原槽位长度。');
md.push('- 文件总长度不变；所有槽位之外的字节逐字节相同。');
md.push('- 由 `hpp-verify.mjs` 独立复核：重新解析全部资源并对比结构偏移。');
md.push('');
if (stats.missing.length) {
  md.push('## 字典未命中条目（未改写，属正常：样本字典只覆盖部分条目）');
  md.push('');
  md.push(`共 ${stats.missing.length} 条，前 40 条：`);
  md.push('');
  md.push('| kind | id | 文件偏移 | maxUnits | 原文 |');
  md.push('|---|---|---|---|---|');
  for (const m of stats.missing.slice(0, 40)) md.push(`| ${m.kind} | ${m.id} | 0x${m.fileOff.toString(16)} | ${m.maxUnits} | ${JSON.stringify(m.text)} |`);
  md.push('');
}
fs.writeFileSync(REPORT, md.join('\n'));

console.log('改写条目', stats.changed, '/ 命中', stats.matched, '/ 单元总数', stats.total);
console.log('超长条目', stats.tooLong.length, '未命中', stats.missing.length);
console.log('文件长度', orig.length, '->', out.length, orig.length === out.length ? '(不变 OK)' : '(已改变 ERROR)');
console.log('差异字节', diffs.length, '区间', ranges.length);
console.log('wrote', OUTDLL);
console.log('wrote', REPORT);
