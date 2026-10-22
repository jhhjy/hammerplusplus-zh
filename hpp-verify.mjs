// hpp-verify.mjs — 对打补丁后的 DLL 独立重新解析并逐条复核
//
// 复核项：
//   1. PE 头字段（machine / ImageBase / FileAlignment / SectionAlignment / 节数）与补丁前一致
//   2. 节表逐字段一致（含 VA / VSize / RawPtr / RawSize / 特征）
//   3. 16 个数据目录逐字段一致（可选校验 CheckSum）
//   4. 资源目录树完整可遍历，条目集合与补丁前一致（类型/名称/语言/大小/RVA）
//   5. 文件长度不变
//   6. 每个补丁单元：重新解析出的文本 == 预期中文；且槽位长度与补丁前一致
//   7. 所有结构偏移（RVA→文件偏移映射）与补丁前完全一致
//   8. 槽位之外的字节逐字节相同
//
// 任何一项不一致 ⇒ 打印定位信息并以非零码退出。

import fs from 'node:fs';
import path from 'node:path';
import * as L from './hpp-lib.mjs';

const ROOT = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const argv = process.argv.slice(2);
const opt = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
const flag = (n) => argv.includes(n);

const SRC = opt('--src', path.join(ROOT, 'hpp-orig', 'hammerplusplus_dll.dll'));
const PATCHED = opt('--patched', path.join(ROOT, 'hpp-zh', 'hammerplusplus_dll.dll'));
const WORKLIST = opt('--worklist', path.join(ROOT, 'hpp-worklist.json'));
const DICT = opt('--dict', path.join(ROOT, 'hpp-zh-dict.json'));
const CHECKSUM = flag('--checksum');

const failures = [];
const notes = [];
const fail = (msg, detail) => { failures.push({ msg, detail }); };

const a = fs.readFileSync(SRC);
const b = fs.readFileSync(PATCHED);
const pa = L.parsePE(a);
const pb = L.parsePE(b);
const worklist = JSON.parse(fs.readFileSync(WORKLIST, 'utf8'));
const dict = JSON.parse(fs.readFileSync(DICT, 'utf8'));

// ---------------------------------------------------------------- 1/5 文件与 PE 头
if (a.length !== b.length) fail('文件长度改变', `${a.length} -> ${b.length}`);
for (const k of ['machine', 'is64', 'imageBase', 'sectionAlignment', 'fileAlignment', 'sizeOfImage', 'sizeOfHeaders', 'numberOfSections']) {
  if (pa[k] !== pb[k]) fail(`PE 头字段 ${k} 不一致`, `${pa[k]} -> ${pb[k]}`);
}
if (a.readUInt32LE(pa.e_lfanew) !== b.readUInt32LE(pb.e_lfanew)) fail('PE 签名不一致');

// ---------------------------------------------------------------- 2 节表
if (pa.sections.length !== pb.sections.length) fail('节数不一致');
for (let i = 0; i < Math.min(pa.sections.length, pb.sections.length); i++) {
  const sa = pa.sections[i], sb = pb.sections[i];
  for (const k of ['name', 'virtualSize', 'virtualAddress', 'rawSize', 'rawPointer', 'characteristics']) {
    if (sa[k] !== sb[k]) fail(`节表 [${i}] ${sa.name} 字段 ${k} 不一致`, `${sa[k]} -> ${sb[k]}`);
  }
}

// ---------------------------------------------------------------- 3 数据目录
if (pa.dataDirectories.length !== pb.dataDirectories.length) fail('数据目录数量不一致');
for (let i = 0; i < Math.min(pa.dataDirectories.length, pb.dataDirectories.length); i++) {
  const da = pa.dataDirectories[i], db = pb.dataDirectories[i];
  if (da.rva !== db.rva || da.size !== db.size) fail(`数据目录 [${i}] 不一致`, `${JSON.stringify(da)} -> ${JSON.stringify(db)}`);
}

// 可选：CheckSum
if (CHECKSUM) {
  const ca = L.computeChecksum(a), cb = L.computeChecksum(b);
  const stored = b.readUInt32LE(pb.checksumOff);
  notes.push(`CheckSum：原始计算值 0x${ca.toString(16)}，补丁后计算值 0x${cb.toString(16)}，补丁后文件头存储值 0x${stored.toString(16)}${stored === 0 ? '（文件头 CheckSum 为 0，未设置，无需更新）' : ''}`);
  if (a.readUInt32LE(pa.checksumOff) !== b.readUInt32LE(pb.checksumOff)) fail('文件头 CheckSum 字段被改动');
}

// ---------------------------------------------------------------- 4 资源目录树
let ra, rb;
try { ra = L.walkResources(pa); } catch (e) { fail('补丁后资源目录无法遍历', e.message); }
try { rb = L.walkResources(pb); } catch (e) { fail('原始资源目录无法遍历', e.message); }
if (ra && rb) {
  if (ra.rva !== rb.rva || ra.size !== rb.size) fail('资源目录 RVA/大小不一致');
  if (ra.entries.length !== rb.entries.length) fail('资源条目数不一致', `${ra.entries.length} -> ${rb.entries.length}`);
  const keyOf = (e) => `${e.typeName}/${e.name}/${e.lang}`;
  const setA = new Map(ra.entries.map(e => [keyOf(e), e]));
  for (const e of rb.entries) {
    const o = setA.get(keyOf(e));
    if (!o) { fail('补丁后出现新增资源条目', keyOf(e)); continue; }
    for (const k of ['rva', 'size', 'codepage', 'reserved']) if (o[k] !== e[k]) fail(`资源 ${keyOf(e)} 字段 ${k} 不一致`, `${o[k]} -> ${e[k]}`);
  }
  notes.push(`资源目录遍历成功：${rb.entries.length} 个条目，与原始一致`);
}

// ---------------------------------------------------------------- 7 结构偏移映射一致
for (const rva of [ra.rva, pb.dataDirectories[2].rva, pa.sections[0].virtualAddress, pa.sections[5].virtualAddress, pa.sections[6].virtualAddress]) {
  const oa = L.rvaToOffset(pa, rva), ob = L.rvaToOffset(pb, rva);
  if (oa !== ob) fail(`RVA 0x${rva.toString(16)} 的文件偏移映射改变`, `0x${oa.toString(16)} -> 0x${ob.toString(16)}`);
}

// ---------------------------------------------------------------- 6 逐条复核文本
const EXPECT = new Map();
const exactMap = new Map();
for (const e of (dict.exact || [])) exactMap.set(`${e.kind}|${e.id}|${e.fileOff}`, e.text);
for (const u of worklist.units) {
  const key = `${u.kind}|${u.id}|${u.fileOff}`;
  let zh = exactMap.has(key) ? exactMap.get(key) : (dict[u.key] !== undefined ? dict[u.key] : dict[u.text]);
  if (zh === undefined || zh === u.text) continue;
  EXPECT.set(key, { unit: u, zh });
}

// 重新解析补丁后的资源，建立 文件偏移 -> 实际文本 映射
const actual = new Map();
const resB = L.walkResources(pb);
for (const e of resB.entries.filter(x => x.type === 4)) {
  for (const it of L.parseMenuResource(pb, e).texts) actual.set(`menu|${e.name}|${it.fileOff}`, it.text);
}
for (const e of resB.entries.filter(x => x.type === 6)) {
  for (const s of L.parseStringTable(pb, e).strings) actual.set(`stringtable|${e.name}|${s.fileOff}`, s.text);
}
for (const e of resB.entries.filter(x => x.type === 5)) {
  const d = L.parseDialogTemplate(pb, e);
  if (!d.fullyParsed) continue;
  for (const t of d.texts) actual.set(`dialog|${e.name}|${t.fileOff}`, t.text);
}
// ANSI 字面量：按槽位直接读取 GBK，再用 936 解码校验
function readSlotAsGbk(buf, off, len) {
  const raw = buf.subarray(off, off + len);
  // 去掉尾部空格填充（0x20）
  let e = raw.length;
  while (e > 0 && raw[e - 1] === 0x20) e--;
  return raw.subarray(0, e);
}

let checked = 0, textOk = 0;
const gbk = JSON.parse(fs.readFileSync(path.join(ROOT, 'hpp-zh', 'hpp-gbk-data.json'), 'utf8'));

// 直接从固定槽位读取 UTF-16 文本直到 NUL —— 这是最严格的校验：
// 因为我们保证「全文件零偏移漂移」，所以补丁后的文本必然从同一 fileOff 开始。
function readUtf16SlotAsText(buffer, off, maxUnits) {
  let s = '';
  for (let k = 0; k < maxUnits; k++) {
    const w = buffer.readUInt16LE(off + k * 2);
    if (w === 0) break;
    s += String.fromCharCode(w);
  }
  return s;
}

for (const [key, { unit, zh }] of EXPECT) {
  checked++;
  if (unit.encoding === 'utf16le') {
    const got = readUtf16SlotAsText(b, unit.fileOff, unit.maxUnits);
    // 槽位容量就是 maxUnits（已全量验证：终止 NUL 位于槽位之外，属于模板结构，
    // 因此补丁只在槽位内写「译文 + 空格填充」，不再写内层 NUL）。
    const want = zh + ' '.repeat(Math.max(0, unit.maxUnits - zh.length));
    if (got !== want) { fail(`文本不符预期`, `${key} @0x${unit.fileOff.toString(16)} 期望=${JSON.stringify(want)} 实际=${JSON.stringify(got)}`); continue; }
    // 终止符单元必须仍然被 NUL 终止（原始模板那一个 NUL 不得被改动）
    if (unit.terminator !== false) {
      const at = unit.fileOff + unit.maxUnits * 2;
      if (at + 2 <= b.length && b.readUInt16LE(at) !== 0) { fail('槽位外终止 NUL 被破坏', `${key} @0x${at.toString(16)}`); continue; }
    }
    // 额外交叉验证：若该单元能被资源解析器重新发现，其文本也必须吻合
    const viaParser = actual.get(key);
    if (viaParser !== undefined && !viaParser.startsWith(zh)) {
      fail('资源解析器重解析结果与直读不符', `${key} @0x${unit.fileOff.toString(16)} 解析=${JSON.stringify(viaParser)}`);
      continue;
    }
  } else {
    const slot = readSlotAsGbk(b, unit.fileOff, unit.maxUnits);
    const hex = slot.toString('hex');
    // $utf8 声明过的条目按 UTF-8 写入（实测该 DLL 有「ANSI 字面量按 UTF-8 消费」的情形，
    // 例如窗口标题 Face Edit Sheet：用 GBK 会显示成「◇? ◇? 起 ◇?」）
    const utf8List = Array.isArray(dict.$utf8) ? dict.$utf8 : [];
    if (utf8List.includes(unit.text)) {
      // readSlotAsGbk 读到 NUL 为止（不含空格填充），故期望值也只比到译文本身
      const utf8Bytes = Buffer.from(zh, 'utf8');
      const wantHex = utf8Bytes.toString('hex');
      if (hex !== wantHex) {
        fail('UTF-8 槽位字节与译文编码不符', `${key} 期望=${wantHex} 实际=${hex}`);
        continue;
      }
      // 填充必须是空格；槽位之后那个原始 NUL 必须仍在
      let padBad = false;
      for (let i = unit.fileOff + utf8Bytes.length; i < unit.fileOff + unit.maxUnits; i++) {
        if (b[i] !== 0x20) { fail('UTF-8 槽位填充不是空格', `${key} @0x${i.toString(16)} = 0x${b[i].toString(16)}`); padBad = true; break; }
      }
      if (padBad) continue;
      if (b[unit.fileOff + unit.maxUnits] !== 0) { fail('UTF-8 槽位终止 NUL 被破坏', key); continue; }
    } else {
      const rec = gbk.entries.find(x => x.fileOff === unit.fileOff);
      if (!rec) { fail('缺少 GBK 记录', key); continue; }
      if (hex !== rec.hex) { fail('ANSI 槽位字节与 GBK 编码结果不符', `${key} 期望=${rec.hex} 实际=${hex}`); continue; }
    }
  }
  textOk++;
}

// ---------------------------------------------------------------- 8 槽位之外逐字节相同
const slotRanges = [];
for (const { unit } of EXPECT.values()) {
  const width = unit.encoding === 'utf16le' ? 2 : 1;
  slotRanges.push([unit.fileOff, unit.fileOff + unit.maxUnits * width - 1]);
}
slotRanges.sort((x, y) => x[0] - y[0]);
const inside = (i) => slotRanges.some(([s, e]) => i >= s && i <= e);
let outsideDiffs = 0;
const outsideSamples = [];
for (let i = 0; i < a.length; i++) {
  if (a[i] !== b[i] && !inside(i)) {
    outsideDiffs++;
    if (outsideSamples.length < 10) outsideSamples.push('0x' + i.toString(16));
  }
}
if (outsideDiffs) fail('存在落在补丁槽位之外的字节差异', `${outsideDiffs} 字节，示例 ${outsideSamples.join(', ')}`);

// 已写入的槽位必须确实发生变化（防止「声称改了却没改」）
let unchangedSlots = 0;
for (const { unit } of EXPECT.values()) {
  const width = unit.encoding === 'utf16le' ? 2 : 1;
  let d = false;
  for (let i = unit.fileOff; i < unit.fileOff + unit.maxUnits * width; i++) if (a[i] !== b[i]) { d = true; break; }
  if (!d) unchangedSlots++;
}
if (unchangedSlots) notes.push(`注意：${unchangedSlots} 个槽位字节未发生变化（译文与原文字节恰好相同的可能）`);

// ---------------------------------------------------------------- 报告
console.log('==== hpp-verify 结果 ====');
console.log(`原始文件   : ${SRC} (${a.length} 字节)`);
console.log(`补丁后文件 : ${PATCHED} (${b.length} 字节)`);
console.log(`PE 头 / 节表 / 数据目录 : ${failures.some(f => /PE 头|节表|数据目录|签名/.test(f.msg)) ? '不一致 ❌' : '一致 ✅'}`);
console.log(`资源目录树              : ${ra && rb ? '可遍历且一致 ✅' : '❌'}`);
console.log(`文件长度                : ${a.length === b.length ? '不变 ✅' : '已改变 ❌'}`);
console.log(`逐条文本复核            : ${textOk}/${checked} 通过${textOk === checked ? ' ✅' : ' ❌'}`);
console.log(`槽位外字节差异          : ${outsideDiffs} ${outsideDiffs === 0 ? '✅' : '❌'}`);
for (const n of notes) console.log('备注: ' + n);
if (failures.length) {
  console.log('');
  console.log(`!! 共 ${failures.length} 项不一致：`);
  for (const f of failures.slice(0, 50)) console.log(`  - ${f.msg}${f.detail ? ' :: ' + f.detail : ''}`);
  if (failures.length > 50) console.log(`  ... 其余 ${failures.length - 50} 项省略`);
  process.exit(1);
}
console.log('');
console.log('全部校验通过：能解出预期中文、所有结构偏移与补丁前一致、PE 头/节表/资源目录未被破坏、文件长度未变。');
process.exit(0);
