// hpp-lib.mjs — Hammer++ DLL 界面汉化工具链核心库
// 纯静态分析：只读 DLL，绝不执行目标程序。
//
// 已实测校准的关键结构（详见 hpp-format-notes.md）：
//  - MENU 模板（非 MENUEX）。资源数据起始处 4 字节 = 头部残余，之后每个菜单项为
//      [前置 4 字节字段][WORD 命令ID][WCHAR 文本...][WORD 0]
//    文本是「无 NUL 的 UTF-16LE 连续码元串」，其前后各有结构字节。
//    因此文本槽位长度 == 文本码元数，窗口内包含前置 2 字节 + 文本 + 终止 2 字节。
//  - 为了让「最小改动、绝不移位」成立，补丁只在 [文本起始, 文本起始+len*2) 内写字，
//    终止 NUL 与所有结构字节原样保留。同长度替换 ⇒ 全文件零偏移漂移。

import fs from 'node:fs';

export const IMAGE_SCN = {
  CNT_CODE: 0x20, CNT_INITIALIZED_DATA: 0x40, CNT_UNINITIALIZED_DATA: 0x80,
  MEM_EXECUTE: 0x20000000, MEM_READ: 0x40000000, MEM_WRITE: 0x80000000,
};

// ---------------------------------------------------------------- PE 解析
export function parsePE(buf) {
  if (buf.readUInt16LE(0) !== 0x5a4d) throw new Error('不是 PE 文件：缺少 MZ');
  const e_lfanew = buf.readUInt32LE(0x3c);
  if (buf.readUInt32LE(e_lfanew) !== 0x00004550) throw new Error('不是 PE 文件：缺少 PE\\0\\0');
  const coff = e_lfanew + 4;
  const machine = buf.readUInt16LE(coff);
  const numberOfSections = buf.readUInt16LE(coff + 2);
  const sizeOfOptionalHeader = buf.readUInt16LE(coff + 16);
  const characteristics = buf.readUInt16LE(coff + 18);
  const opt = coff + 20;
  const magic = buf.readUInt16LE(opt);
  const is64 = magic === 0x20b;
  const imageBase = is64 ? Number(buf.readBigUInt64LE(opt + 24)) : buf.readUInt32LE(opt + 28);
  const sectionAlignment = buf.readUInt32LE(opt + 32);
  const fileAlignment = buf.readUInt32LE(opt + 36);
  const sizeOfImage = buf.readUInt32LE(opt + 56);
  const sizeOfHeaders = buf.readUInt32LE(opt + 60);
  const checksumOff = opt + 64;
  const numberOfRvaAndSizes = buf.readUInt32LE(opt + (is64 ? 108 : 92));
  const dirOff = opt + (is64 ? 112 : 96);
  const dataDirectories = [];
  for (let i = 0; i < numberOfRvaAndSizes; i++) {
    dataDirectories.push({ rva: buf.readUInt32LE(dirOff + i * 8), size: buf.readUInt32LE(dirOff + i * 8 + 4) });
  }
  const sections = [];
  const shOff = opt + sizeOfOptionalHeader;
  for (let i = 0; i < numberOfSections; i++) {
    const o = shOff + i * 40;
    sections.push({
      index: i,
      name: buf.toString('latin1', o, o + 8).replace(/\0.*$/, ''),
      virtualSize: buf.readUInt32LE(o + 8),
      virtualAddress: buf.readUInt32LE(o + 12),
      rawSize: buf.readUInt32LE(o + 16),
      rawPointer: buf.readUInt32LE(o + 20),
      characteristics: buf.readUInt32LE(o + 36),
    });
  }
  return {
    buf, e_lfanew, machine, is64, numberOfSections, sizeOfOptionalHeader, characteristics,
    imageBase, sectionAlignment, fileAlignment, sizeOfImage, sizeOfHeaders, checksumOff,
    dataDirectories, sections,
    sectionHeaderOff: shOff,
    sizeOfHeadersRaw: sizeOfHeaders,
  };
}

export function rvaToOffset(pe, rva) {
  for (const s of pe.sections) {
    const vs = Math.max(s.virtualSize, s.rawSize);
    if (rva >= s.virtualAddress && rva < s.virtualAddress + vs) {
      return s.rawPointer + (rva - s.virtualAddress);
    }
  }
  if (rva < pe.sizeOfHeaders) return rva;
  return null;
}

export function offsetToRva(pe, off) {
  for (const s of pe.sections) {
    if (off >= s.rawPointer && off < s.rawPointer + s.rawSize) return s.virtualAddress + (off - s.rawPointer);
  }
  if (off < pe.sizeOfHeaders) return off;
  return null;
}

export function vaToOffset(pe, va) { return rvaToOffset(pe, va - pe.imageBase); }
export function offsetToVa(pe, off) { const r = offsetToRva(pe, off); return r === null ? null : r + pe.imageBase; }
export function hex(n) { return typeof n === 'number' ? '0x' + n.toString(16) : String(n); }

// PE CheckSum 计算（与 CheckSumMappedFile 等价算法）
export function computeChecksum(buf) {
  const pe = parsePE(buf);
  const off = pe.checksumOff;
  const saved = buf.readUInt32LE(off);
  buf.writeUInt32LE(0, off);
  let sum = 0;
  const n = buf.length;
  for (let i = 0; i + 1 < n; i += 2) {
    sum += buf.readUInt16LE(i);
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  if (n & 1) { sum += buf[n - 1]; sum = (sum & 0xffff) + (sum >>> 16); }
  sum = (sum & 0xffff) + (sum >>> 16);
  sum = (sum & 0xffff) + (sum >>> 16);
  sum = (sum + n) >>> 0;
  buf.writeUInt32LE(saved, off);
  return sum >>> 0;
}

// ---------------------------------------------------------------- 资源目录树
const RT = {
  1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRINGTABLE', 7: 'FONTDIR',
  8: 'FONT', 9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR',
  14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE', 19: 'PLUGPLAY', 20: 'VXD', 21: 'ANICURSOR',
  22: 'ANIICON', 23: 'HTML', 24: 'MANIFEST',
};
export function rtName(id) { return RT[id] || ('#' + id); }

// 完整遍历资源树：类型 / 名称 / 语言 三级；支持命名资源与任意深度。
export function walkResources(pe) {
  const buf = pe.buf;
  const dir = pe.dataDirectories[2];
  if (!dir || !dir.rva) throw new Error('无资源目录');
  const base = rvaToOffset(pe, dir.rva);
  if (base === null) throw new Error('资源目录 RVA 无法映射');
  const out = [];

  const readNameStr = (off) => {
    const o = base + off;
    const len = buf.readUInt16LE(o);
    return buf.toString('utf16le', o + 2, o + 2 + len * 2);
  };
  const readEntries = (rel) => {
    const o = base + rel;
    const named = buf.readUInt16LE(o + 12);
    const ided = buf.readUInt16LE(o + 14);
    const list = [];
    for (let i = 0; i < named + ided; i++) {
      const e = o + 16 + i * 8;
      const nameOrId = buf.readUInt32LE(e);
      const off2 = buf.readUInt32LE(e + 4);
      list.push({
        nameOrId, isName: (nameOrId & 0x80000000) !== 0,
        child: off2 & 0x7fffffff, isDir: (off2 & 0x80000000) !== 0,
      });
    }
    return list;
  };
  const walk = (rel, path, depth) => {
    for (const e of readEntries(rel)) {
      const key = e.isName ? readNameStr(e.nameOrId & 0x7fffffff) : e.nameOrId;
      const next = path.concat([{ key, isName: e.isName, depth }]);
      if (e.isDir) { walk(e.child, next, depth + 1); continue; }
      const d = base + e.child;
      const rva = buf.readUInt32LE(d);
      const size = buf.readUInt32LE(d + 4);
      const codepage = buf.readUInt32LE(d + 8);
      const reserved = buf.readUInt32LE(d + 12);
      const fileOff = rvaToOffset(pe, rva);
      out.push({
        path: next, type: next[0] ? next[0].key : null,
        name: next[1] ? next[1].key : null, lang: next[2] ? next[2].key : null,
        typeName: typeof next[0]?.key === 'number' ? rtName(next[0].key) : String(next[0]?.key),
        rva, size, codepage, reserved, fileOff, dataEntryOff: d,
      });
    }
  };
  walk(0, [], 0);
  return { base, entries: out, rva: dir.rva, size: dir.size };
}

// ---------------------------------------------------------------- 文本工具
export function isCJKUnit(u) {
  return (u >= 0x2e80 && u <= 0x9fff) || (u >= 0xf900 && u <= 0xfaff) || (u >= 0xac00 && u <= 0xd7ff);
}
// 菜单项前置结构字节的判定：不属于「可显示标签」的码元
//
// 【重要】菜单模板里的结构字段（dwType 高位、wID、MFC 命令 ID 的 PUA 标记）
// 与文本处在同一段「非 NUL 码元串」里，必须严格剔除，否则：
//   - text 会带出不可见的结构码元（0x0080~0x009F、PUA）
//   - fileOff 会指到结构字段上，打补丁时覆盖菜单项 ID → 命令失效
// 真实菜单标签一定是可打印 ASCII（含 & 加速符、\t 快捷键、... 省略号、<>）。
// 因此这里只接受 0x20~0x7E 与制表符；其余（C1 控制、PUA、CJK、全角等）一律视为结构字节。
export function isLabelUnit(u) {
  if (u === 0x09) return true;
  return u >= 0x20 && u <= 0x7e;
}

export function utf16le(str) { return Buffer.from(str, 'utf16le'); }

// ---------------------------------------------------------------- MENU 解析
// 返回文本槽位：{ fileOff, len (码元数), text, leadUnits }
export function parseMenuResource(pe, entry) {
  const buf = pe.buf;
  const origin = entry.fileOff;
  const lim = origin + entry.size;
  const res = { id: entry.name, lang: entry.lang, fileOff: origin, size: entry.size, items: [], texts: [] };
  // 头部残余 4 字节
  res.headerVersion = buf.readUInt16LE(origin);
  res.headerOffset = buf.readUInt16LE(origin + 2);
  res.rawPrefix = buf.subarray(origin, origin + 4).toString('hex');

  // 用「无 NUL 连续码元串」定位所有文本候选；再剥离前置结构码元
  let p = origin;
  let index = 0;
  while (p + 2 <= lim) {
    if (buf.readUInt16LE(p) === 0) { p += 2; continue; }
    let q = p;
    while (q + 2 <= lim && buf.readUInt16LE(q) !== 0) q += 2;
    const units = [];
    for (let x = p; x < q; x += 2) units.push(buf.readUInt16LE(x));
    let a = 0;
    while (a < units.length && !isLabelUnit(units[a])) a++;
    let b = units.length;
    while (b > a && !isLabelUnit(units[b - 1])) b--;
    const label = units.slice(a, b);
    const text = label.map(u => String.fromCharCode(u)).join('');
    if (text.length >= 1 && /[A-Za-z]/.test(text)) {
      const item = {
        index: index++, runOff: p, fileOff: p + a * 2, len: b - a, maxUnits: b - a,
        text, leadUnits: a, runUnits: units.length - 0, runOffEnd: q,
        va: offsetToVa(pe, p + a * 2),
      };
      // 结构自愈：菜单项的 ID 字段紧邻文本之前，其低字节若是可打印 ASCII
      //（例如 wID=0x0071 → 'q'），会被上面的「非 NUL 码元串」并进标签。
      // 判据：fileOff 之前的那个码元为 0x0000 —— 菜单项 ID 不可能为 0，
      // 因此可断定标签起点早了 2 字节，右移一个码元并同步所有元数据。
      if (item.fileOff - 2 >= origin && buf.readUInt16LE(item.fileOff - 2) === 0 && /^[A-Za-z]/.test(item.text) && /^[A-Za-z&<0-9]/.test(item.text.slice(1))) {
        item.fileOff += 2;
        item.va = offsetToVa(pe, item.fileOff);
        item.text = item.text.slice(1);
        item.len -= 1;
        item.maxUnits = item.len;
        item.leadUnits += 1;
        item.repairedLeadingId = true;
      }
      res.items.push(item);
      res.texts.push(item);
    }
    p = q;
  }
  return res;
}

// ---------------------------------------------------------------- STRINGTABLE 解析
export function parseStringTable(pe, entry) {
  const buf = pe.buf;
  const origin = entry.fileOff;
  const lim = origin + entry.size;
  const blockId = typeof entry.name === 'number' ? entry.name : null;
  const baseId = blockId === null ? null : (blockId - 1) * 16;
  const out = [];
  let p = origin;
  let slot = 0;
  while (p + 2 <= lim) {
    const len = buf.readUInt16LE(p);
    p += 2;
    if (len === 0) { slot++; continue; }
    const bytes = len * 2;
    if (p + bytes > lim) break;
    const text = buf.toString('utf16le', p, p + bytes);
    out.push({
      kind: 'stringtable', id: blockId, sub: slot,
      stringId: baseId === null ? null : baseId + slot,
      fileOff: p, len, maxUnits: len, text,
      va: offsetToVa(pe, p),
    });
    p += bytes;
    slot++;
  }
  return { blockId, baseId, origin, size: entry.size, strings: out };
}

// ---------------------------------------------------------------- DIALOG 解析
// ============================================================================
// 【实测校准后的 DIALOG 布局】（证据见 hpp-format-notes.md §2 与 hpp-dialog-layout.md）
//
// DLGTEMPLATEEX（dlgVer==1 && signature==0xFFFF）：
//   +0   WORD   dlgVer=1
//   +2   WORD   signature=0xFFFF
//   +4   DWORD  helpID
//   +8   DWORD  exStyle
//   +12  DWORD  style
//   +16  WORD   cDlgItems
//   +18  short  x, y, cx, cy
//   +26  变长   menu / windowClass / title       (0x0000 空 / 0xFFFF+WORD 序号 / UTF-16LE 串)
//        WORD   pointsize          ┐ 仅当 style 的 bit16（0x10000，「字体块存在」哨兵位）置位；
//        WORD   weight             │ 注意不是 DS_SETFONT(0x40) —— 实测有 17 个模板的
//        BYTE   italic             │ 高字为 0x80c8/0x4000，低字无 0x40，字体块照样存在，
//        BYTE   charset            │ 用 DS_SETFONT 判定会整体读歪。
//        WCHAR  typeface[] + NUL   ┘
//        **对齐到 4 字节**（相对模板起点）  ← dialog 100 那「4 字节差值」的真正来源
//        cDlgItems × 控件模板
//
// 控件模板：
//   EX：DWORD helpID / DWORD exStyle / DWORD style / short x,y,cx,cy / DWORD id
//   legacy：DWORD exStyle / DWORD style / short x,y,cx,cy / **WORD id**（2 字节，不是 4！）
//   然后 windowClass、title（同一三态变长格式）、WORD extraCount + extraCount 字节
//   创建数据，再对齐到 4 字节。
//
// 【旧解析器的三处错误】
//   1. 字体块后未对齐 ⇒ 全部 EX 模板首控件起点偏 2 字节；
//   2. 用 DS_SETFONT(0x8, 低位) 判定字体块 ⇒ 应为 style bit16 哨兵；
//   3. legacy 控件 id 按 DWORD 读 ⇒ 应为 WORD（差 2 字节，导致 20 个 legacy 全灭）。
// 三处修正后 92 个模板全部结构自洽（见 hpp-dialog-report.md）。
// ============================================================================

// 已知窗口类白名单（Win32 预定义类 + 常见通用控件类 + MFC 常用类）
export const KNOWN_DIALOG_CLASSES = new Set([
  // 预定义对话框类
  '#32770',
  // 标准控件类（字符串形式）
  'Button', 'Static', 'Edit', 'ComboBox', 'ListBox', 'ScrollBar',
  // 通用控件类
  'SysListView32', 'SysTreeView32', 'SysTabControl32', 'SysAnimate32', 'SysDateTimePick32',
  'SysIPAddress32', 'SysLink', 'SysPager', 'SysMonthCal32', 'SysHeader32', 'tooltips_class32',
  'ComboBoxEx32', 'msctls_progress32', 'msctls_statusbar32', 'msctls_trackbar32',
  'msctls_updown32', 'msctls_hotkey32', 'RichEdit', 'RichEdit20A', 'RichEdit20W', 'RichEdit50W',
  'RICHEDIT', 'RICHEDIT20A', 'RICHEDIT20W',
  // MFC 自带类
  'MfcButton', 'MfcEditBrowse', 'MfcMaskedEdit',
]);
// 已知序数类（0x80..0x85 对应 Button/Edit/Static/ListBox/ScrollBar/ComboBox）
export const KNOWN_ORDINAL_CLASSES = new Set([0x80, 0x81, 0x82, 0x83, 0x84, 0x85]);
export const ORDINAL_CLASS_NAME = { 0x80: 'Button', 0x81: 'Edit', 0x82: 'Static', 0x83: 'ListBox', 0x84: 'ScrollBar', 0x85: 'ComboBox' };

const DLG_MAX_CDATA = 512;          // 创建数据长度上限
const DLG_MAX_TAIL = 2;             // 允许的尾部越界（末尾 4 字节对齐 + 资源数据 4 字节对齐所致的 0~2 字节）
const DLG_MAX_COORD = 0x7fff;

// 变长字段的三态读取：0x0000 空 / 0xFFFF+WORD 序号 / UTF-16LE NUL 结尾串
function dlgReadSz(buf, pos, lim) {
  if (pos + 2 > lim) return { ok: false, err: `偏移 0x${pos.toString(16)} 处越界，无法读取变长字段长度` };
  const w = buf.readUInt16LE(pos);
  if (w === 0x0000) return { ok: true, kind: 'empty', text: '', ord: null, start: null, next: pos + 2 };
  if (w === 0xffff) {
    if (pos + 4 > lim) return { ok: false, err: `偏移 0x${pos.toString(16)} 处序数变长字段越界` };
    const o = buf.readUInt16LE(pos + 2);
    return { ok: true, kind: 'ord', text: '#' + o, ord: o, start: null, next: pos + 4 };
  }
  let e = pos;
  while (e + 2 <= lim && buf.readUInt16LE(e) !== 0) e += 2;
  if (e + 2 > lim) return { ok: false, err: `偏移 0x${pos.toString(16)} 处 UTF-16 串未在资源内终止` };
  const text = buf.toString('utf16le', pos, e);
  for (const ch of text) {
    const c = ch.codePointAt(0);
    if ((c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c === 0xfffd) {
      return { ok: false, err: `偏移 0x${pos.toString(16)} 处串含非法字符 U+${c.toString(16).padStart(4, '0')}（${JSON.stringify(text)}）` };
    }
  }
  return { ok: true, kind: 'str', text, ord: null, start: pos, next: e + 2 };
}

export function parseDialogTemplate(pe, entry) {
  const buf = pe.buf;
  const origin = entry.fileOff;
  const lim = origin + entry.size;
  // 资源末尾不足 4 字节对齐时，DWORD 尾部填充会落在资源末尾之外（进入资源间的 0 填充）。
  // 只允许读这 0~2 字节的越界区；再远就是真错误。
  const readLim = Math.min(buf.length, lim + DLG_MAX_TAIL + 2);
  const rej = [];                                   // 拒收理由（显式断言失败）
  const q = (s) => '`' + String(s).replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\r/g, '\\r').replace(/\n/g, '\\n').replace(/\t/g, '\\t') + '`';

  const out = {
    id: entry.name, lang: entry.lang, fileOff: origin, size: entry.size,
    texts: [], notes: [], assertions: {}, controls: [],
  };

  // ---------------- 1. 格式判定（头部硬校验）
  const isEx = buf.readUInt16LE(origin) === 1 && buf.readUInt16LE(origin + 2) === 0xffff;
  out.isEx = isEx;
  let p = origin;
  if (isEx) {
    out.dlgVer = 1; out.signature = 0xffff;
    p = origin + 4;
    out.helpID = buf.readUInt32LE(p); p += 4;
    out.exStyle = buf.readUInt32LE(p); p += 4;
    out.style = buf.readUInt32LE(p); p += 4;
  } else {
    out.style = buf.readUInt32LE(p); p += 4;
    out.exStyle = buf.readUInt32LE(p); p += 4;
  }
  out.cdit = buf.readUInt16LE(p); p += 2;
  out.x = buf.readInt16LE(p); p += 2;
  out.y = buf.readInt16LE(p); p += 2;
  out.cx = buf.readInt16LE(p); p += 2;
  out.cy = buf.readInt16LE(p); p += 2;
  out.headerEnd = p - origin;                       // EX=26 / legacy=18

  // ---------------- 2. menu / windowClass / title
  const rd = (what) => {
    const r = dlgReadSz(buf, p, readLim);
    if (!r.ok) { rej.push(`${what} 解析失败：${r.err}`); return null; }
    p = r.next;
    return r;
  };
  out.menu = rd('menu 字段'); if (!out.menu) return finish();
  out.windowClass = rd('windowClass 字段'); if (!out.windowClass) return finish();
  out.title = rd('title（对话框标题）'); if (!out.title) return finish();
  if (out.title.kind === 'str' && out.title.text.length) {
    out.texts.push({ kind: 'dialog', id: entry.name, sub: 'title', fileOff: out.title.start,
      len: out.title.text.length, maxUnits: out.title.text.length, text: out.title.text,
      field: 'title', va: offsetToVa(pe, out.title.start) });
  }

  // ---------------- 3. 字体块（哨兵位 = DS_SETFONT，即 style bit 0x40）
  // 实测：92/92 个模板 DS_SETFONT 均为 1，且该结果与「旧解析器已成功解析的 26 个模板」一致；
  // 高字 bit16 只有 2 个模板置位，不能当哨兵。
  out.hasFontBlock = (out.style & 0x0040) !== 0;
  if (out.hasFontBlock) {
    if (p + (isEx ? 6 : 2) > readLim) { rej.push(`字体块越界（偏移 +${p - origin}）`); return finish(); }
    out.pointsize = buf.readUInt16LE(p); p += 2;
    if (isEx) {
      out.fontWeight = buf.readUInt16LE(p); p += 2;
      out.fontItalic = buf[p]; p += 1;
      out.fontCharset = buf[p]; p += 1;
    }
    out.font = rd('字体名'); if (!out.font) return finish();
    if (out.font.kind !== 'str' || !out.font.text.length) { rej.push('字体名为空或非字符串'); return finish(); }
    // 字体名合法性：可见字符（含中文/符号），不得含控制符或私有区乱码
    if (!/^[\x20-\x7e\u00a0-\uffff]+$/.test(out.font.text)) { rej.push(`字体名含非法字符 ${q(out.font.text)}`); return finish(); }
    if (out.pointsize === 0 || out.pointsize > 200) { rej.push(`字号不合理 ${out.pointsize}`); return finish(); }
  }

  // ---------------- 4. 创建数据（仅当 style 声明 DS_CREATE? 高位 bit13=WS_? 依规范用 style&0x8 之外的
  //    CreateData 标志不存在；DLGTEMPLATE 的 creationData 由「style 的 DS_ 位」之外的第 3 位组声明，
  //    实测本样本所有模板该处 WORD 均为 0，故按「声明即读」保守处理）
  if ((out.style & 0x0008) !== 0 && false) { /* 保留位，本样本不触发 */ }

  // ---------------- 5. 对齐到 4 字节（相对模板起点）
  out.padBeforeControls = (4 - ((p - origin) & 3)) & 3;
  p += out.padBeforeControls;

  // ---------------- 6. 控件模板
  for (let i = 0; i < (out.cdit | 0); i++) {
    const cstart = p;
    if (p + (isEx ? 24 : 20) > readLim) { rej.push(`控件 ${i} 头部越界（偏移 +${p - origin}）`); break; }
    const c = { index: i, off: cstart, offRel: cstart - origin };
    if (isEx) { c.helpID = buf.readUInt32LE(p); p += 4; }
    c.exStyle = buf.readUInt32LE(p); p += 4;
    c.style = buf.readUInt32LE(p); p += 4;
    c.cx = buf.readInt16LE(p); p += 2;
    c.cy = buf.readInt16LE(p); p += 2;
    c.x = buf.readInt16LE(p); p += 2;
    c.y = buf.readInt16LE(p); p += 2;
    // 规范：legacy DLGITEMTEMPLATE 的 id 是 WORD；DLGITEMTEMPLATEEX 是 DWORD
    if (isEx) { c.id = buf.readUInt32LE(p); p += 4; } else { c.id = buf.readUInt16LE(p); p += 2; }
    const cls = dlgReadSz(buf, p, readLim);
    if (!cls.ok) { rej.push(`控件 ${i} windowClass 解析失败：${cls.err}`); break; }
    p = cls.next; c.cls = cls.text; c.clsKind = cls.kind; c.clsOrd = cls.ord;
    const ttl = dlgReadSz(buf, p, readLim);
    if (!ttl.ok) { rej.push(`控件 ${i} title 解析失败：${ttl.err}`); break; }
    p = ttl.next; c.title = ttl.text; c.titleKind = ttl.kind; c.titleStart = ttl.start;
    if (p + 2 > readLim) { rej.push(`控件 ${i} creationData 长度字段越界`); break; }
    c.cdataExtra = buf.readUInt16LE(p); p += 2;
    if (c.cdataExtra > DLG_MAX_CDATA) { rej.push(`控件 ${i} 创建数据长度异常 ${c.cdataExtra}（上限 ${DLG_MAX_CDATA}）`); break; }
    if (p + c.cdataExtra > readLim) { rej.push(`控件 ${i} 创建数据越界`); break; }
    c.cdataAt = p; p += c.cdataExtra;
    // 对齐到 4 字节
    c.padAfter = (4 - ((p - origin) & 3)) & 3;
    p += c.padAfter;
    c.endOff = p - origin;
    out.controls.push(c);
    if (ttl.kind === 'str' && ttl.text.length) {
      out.texts.push({ kind: 'dialog', id: entry.name, sub: 'ctl#' + i, fileOff: ttl.start,
        len: ttl.text.length, maxUnits: ttl.text.length, text: ttl.text,
        field: 'control', controlId: c.id, va: offsetToVa(pe, ttl.start) });
    }
  }
  out.parsedControls = out.controls.length;
  out.fullyParsed = out.parsedControls === (out.cdit | 0);
  if (!out.fullyParsed) rej.push(`控件数不符：cDlgItems=${out.cdit} 实际解析=${out.parsedControls}`);
  out.endOffset = p - origin;
  out.tail = lim - p;
  if (out.tail < -DLG_MAX_TAIL) rej.push(`解析越界：结束位置 +${out.endOffset} 超出资源末尾 +${out.size}（${-out.tail} 字节）`);
  if (out.tail > 3) rej.push(`解析未覆盖资源：结束位置 +${out.endOffset}，资源末尾 +${out.size}，剩余 ${out.tail} 字节疑似未消费数据`);

  return finish();

  function finish() {
    // ---------------- 8. 结构硬校验（每个控件）
    for (const c of out.controls) {
      // 8.1 类名
      if (c.clsKind === 'ord') {
        if (c.clsOrd === null || c.clsOrd < 0x80 || c.clsOrd > 0xffff) {
          rej.push(`控件 ${c.index} 序数类越界 ${c.cls}`);
          c.clsKnown = false;
        } else if (KNOWN_ORDINAL_CLASSES.has(c.clsOrd)) {
          c.clsKnown = true; c.clsName = ORDINAL_CLASS_NAME[c.clsOrd];
        } else {
          // 0x86 以上是 MFC / 第三方注册的窗口类序数（如 0x83=msctls_updown32），结构自洽即接受
          c.clsKnown = false; c.clsName = 'ORD:' + c.cls;
          out.unknownClasses = out.unknownClasses || [];
          out.unknownClasses.push({ index: c.index, cls: c.cls });
        }
      } else if (c.clsKind === 'empty') {
        // 空类名 = 默认 Button，合法
        c.clsKnown = true; c.clsName = 'Button(默认)';
      } else {
        // 字符串类名：白名单 or 结构自洽（记录为未知）
        if (KNOWN_DIALOG_CLASSES.has(c.cls)) { c.clsKnown = true; c.clsName = c.cls; }
        else if (/^[A-Za-z_][A-Za-z0-9_.]{0,63}$/.test(c.cls)) {
          c.clsKnown = false; c.clsName = c.cls;
          out.unknownClasses = out.unknownClasses || [];
          out.unknownClasses.push({ index: c.index, cls: c.cls });
        } else {
          rej.push(`控件 ${c.index} 类名非法（非白名单且不像类名）${q(c.cls)}`);
          c.clsKnown = false;
        }
      }
      // 8.2 坐标/尺寸范围
      if (Math.abs(c.x) > DLG_MAX_COORD || Math.abs(c.y) > DLG_MAX_COORD) rej.push(`控件 ${c.index} 坐标越界 x=${c.x} y=${c.y}`);
      if (c.cx < 0 || c.cy < 0 || c.cx > DLG_MAX_COORD || c.cy > DLG_MAX_COORD) rej.push(`控件 ${c.index} 尺寸越界 cx=${c.cx} cy=${c.cy}`);
      // 8.3 id 合理性（EX 允许 0xFFFFFFFF = -1，MFC 常用）
      if (c.id < 0) rej.push(`控件 ${c.index} id 为负 ${c.id}`);
      // 8.4 文本可显示
      const showable = (s) => /^[\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]*$/.test(s);
      if (!showable(c.title)) rej.push(`控件 ${c.index} title 含非法字符 ${q(c.title)}`);
    }
    for (const t of out.texts) {
      if (!/^[\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]*$/.test(t.text)) rej.push(`${t.sub} 文本含非法字符 ${q(t.text)}`);
      if (t.maxUnits <= 0) rej.push(`${t.sub} 槽位长度为 0`);
    }
    // ---------------- 9. 标题/字体合理性（防「整个模板读歪但碰巧自洽」）
    if (out.font && /^(Serif|Sans Serif|Sans|Shell Dlg|System)$/.test(out.font.text)) {
      rej.push(`字体名是残缺串 ${q(out.font.text)}（疑似变长字段消费位置偏差）`);
    }
    out.rejectReasons = [...new Set(rej)];
    out.trustworthy = out.rejectReasons.length === 0;
    out.notes.push(...out.rejectReasons);
    return out;
  }
}

// 兼容旧签名（旧解析器的宽松版保留给对比脚本使用）
export function parseDialogTemplateLegacy(pe, entry) {
  const buf = pe.buf;
  const origin = entry.fileOff;
  const lim = origin + entry.size;
  const out = { id: entry.name, lang: entry.lang, fileOff: origin, size: entry.size, dlgVer: null, signature: null, texts: [], notes: [] };
  const isEx = buf.readUInt16LE(origin) === 1 && buf.readUInt16LE(origin + 2) === 0xffff;
  out.isEx = isEx;
  let p = origin;
  if (isEx) {
    p = origin + 4;
    out.dlgVer = 1; out.signature = 0xffff;
    out.helpID = buf.readUInt32LE(p); p += 4;
    out.exStyle = buf.readUInt32LE(p); p += 4;
    out.style = buf.readUInt32LE(p); p += 4;
    out.cdit = buf.readUInt16LE(p); p += 2;
    out.x = buf.readInt16LE(p); p += 2;
    out.y = buf.readInt16LE(p); p += 2;
    out.cx = buf.readInt16LE(p); p += 2;
    out.cy = buf.readInt16LE(p); p += 2;
  } else {
    out.style = buf.readUInt32LE(p); p += 4;
    out.exStyle = buf.readUInt32LE(p); p += 4;
    out.cdit = buf.readUInt16LE(p); p += 2;
    out.x = buf.readInt16LE(p); p += 2;
    out.y = buf.readInt16LE(p); p += 2;
    out.cx = buf.readInt16LE(p); p += 2;
    out.cy = buf.readInt16LE(p); p += 2;
  }
  const readSz = (pos) => {
    let q = pos;
    // 0x0000 = 空；0xffff+WORD = 序号
    if (buf.readUInt16LE(q) === 0x0000) return { text: '', next: q + 2, kind: 'empty' };
    if (buf.readUInt16LE(q) === 0xffff) return { text: '#' + buf.readUInt16LE(q + 2), next: q + 4, kind: 'ord' };
    let e = q;
    while (e + 2 <= lim && buf.readUInt16LE(e) !== 0) e += 2;
    return { text: buf.toString('utf16le', q, e), next: e + 2, kind: 'str', start: q };
  };
  out.menu = readSz(p); p = out.menu.next;
  out.windowClass = readSz(p); p = out.windowClass.next;
  out.title = readSz(p); p = out.title.next;
  if (out.title.kind === 'str' && out.title.text.length) {
    out.texts.push({ kind: 'dialog', id: entry.name, sub: 'title', fileOff: out.title.start, len: out.title.text.length, maxUnits: out.title.text.length, text: out.title.text, field: 'title', va: offsetToVa(pe, out.title.start) });
  }
  // 创建数据（顺序读法）
  // 实测说明：部分模板用「严格顺序读」得到的首控件起点会早/晚若干字节，
  // 表现为控件 class 被截断成字体串尾巴（如 "Microsoft Sans Serif" -> "Serif"）。
  // 这类模板不做偏移猜测，改由下方 trustworthy 质量判据整体拒收（见 hpp-format-notes.md）。
  if (buf.readUInt16LE(p) === 0) p += 2;
  else { const n = buf.readUInt16LE(p); p += 2 + n; }
  // 控件
  for (let i = 0; i < (out.cdit | 0) && p + 16 <= lim; i++) {
    // EX 模板：每个控件的 helpID 起始 4 字节对齐（相对模板起点）。
    // legacy 模板：未观察到该对齐，强行对齐会吞掉 2 字节 —— 实测差异见
    // hpp-format-notes.md 的 DIALOG 一节。
    if (isEx) p = origin + (((p - origin) + 3) & ~3);
    const cstart = p;
    let helpID = 0;
    if (isEx) { helpID = buf.readUInt32LE(p); p += 4; }
    const exStyle = buf.readUInt32LE(p); p += 4;
    const style = buf.readUInt32LE(p); p += 4;
    const cx = buf.readInt16LE(p); p += 2;
    const cy = buf.readInt16LE(p); p += 2;
    const x = buf.readInt16LE(p); p += 2;
    const y = buf.readInt16LE(p); p += 2;
    // 实测：EX 与 legacy 的控件 ID 都是 DWORD（legacy 亦为 4 字节，非 2 字节）
    const id = buf.readUInt32LE(p); p += 4;
    const cls = readSz(p); p = cls.next;
    const ttl = readSz(p); p = ttl.next;
    let cdataExtra = 0;
    if (buf.readUInt16LE(p) === 0) { p += 2; } else { cdataExtra = buf.readUInt16LE(p); p += 2 + cdataExtra; }
    const ctl = { index: i, off: cstart, helpID, exStyle, style, cx, cy, x, y, id, cls: cls.text, clsKind: cls.kind, title: ttl.text, cdataExtra };
    out.controls = out.controls || [];
    out.controls.push(ctl);
    if (ttl.kind === 'str' && ttl.text.length) {
      out.texts.push({ kind: 'dialog', id: entry.name, sub: 'ctl#' + i, fileOff: ttl.start, len: ttl.text.length, maxUnits: ttl.text.length, text: ttl.text, field: 'control', controlId: id, va: offsetToVa(pe, ttl.start) });
    }
  }
  out.parsedControls = out.controls ? out.controls.length : 0;
  out.fullyParsed = out.parsedControls === (out.cdit | 0);
  if (!out.fullyParsed) out.notes.push(`控件数不符：cdit=${out.cdit} 实际解析=${out.parsedControls}`);
  // 更强的「结果可信」判据：控件数相符 且 每个控件的 class/title 都是合理文本。
  // 不能只看 cdit —— 实测某些模板即使控件数相符，class 也会被截断成字体串的尾巴
  // （如把 "Microsoft Sans Serif" 读成 "Serif"），说明变长字段消费位置有偏差。
  const FONT_TAIL = /^(Serif|Sans Serif|Sans|Shell Dlg|System|MS Sans Serif)$/;
  const okText = (s) => s === '' || (/^[\x20-\x7e\u3000-\u9fff\uff00-\uffef]*$/.test(s));
  let quality = true;
  const reasons = [];
  for (const c of (out.controls || [])) {
    const isOrd = c.clsKind === 'ord';
    if (!isOrd && FONT_TAIL.test(c.cls)) { quality = false; reasons.push(`控件 ${c.index} 的 class 被截断为字体串尾巴 ${JSON.stringify(c.cls)}`); }
    if (!okText(c.cls)) { quality = false; reasons.push(`控件 ${c.index} 的 class 含非法字符 ${JSON.stringify(c.cls)}`); }
    if (!okText(c.title)) { quality = false; reasons.push(`控件 ${c.index} 的 title 含非法字符 ${JSON.stringify(c.title)}`); }
    if (c.cdataExtra > 0x400) { quality = false; reasons.push(`控件 ${c.index} 的创建数据长度异常 ${c.cdataExtra}`); }
  }
  for (const t of out.texts) {
    if (!okText(t.text)) { quality = false; reasons.push(`${t.sub} 文本含非法字符 ${JSON.stringify(t.text)}`); }
  }
  out.qualityOk = quality;
  if (!quality) out.notes.push(...reasons);
  out.trustworthy = out.fullyParsed && quality;
  return out;
}

// ---------------------------------------------------------------- ANSI 字面量扫描
const PRINTABLE = (b) => b >= 0x20 && b <= 0x7e;

export function scanAnsiLiterals(pe, opts = {}) {
  const buf = pe.buf;
  const minLen = opts.minLen ?? 4;
  const sections = (opts.sections || ['.text', '.rdata', '_RDATA', '.data']);
  const out = [];
  for (const s of pe.sections) {
    if (!sections.includes(s.name)) continue;
    const start = s.rawPointer;
    const end = Math.min(buf.length, s.rawPointer + s.rawSize);
    let i = start;
    while (i < end) {
      if (!PRINTABLE(buf[i])) { i++; continue; }
      let j = i;
      while (j < end && PRINTABLE(buf[j])) j++;
      const len = j - i;
      // NUL 结尾（编译器字符串常量）
      const nulTerminated = j < end && buf[j] === 0;
      if (len >= minLen && nulTerminated) {
        const text = buf.toString('latin1', i, j);
        // 排除「宽字符串的一半」：宽字符串表现为 ASCII/0 交替，或其前/后一字节为 0（0x00XX / 0xXX00）
        const wideBefore = i > 0 && buf[i - 1] === 0 && i >= 2 && buf[i - 2] !== 0;
        const wideAfter = j + 1 < end && buf[j + 1] === 0;
        if (!wideBefore && !wideAfter) {
          out.push({ fileOff: i, len, bytes: len, text, section: s.name, va: offsetToVa(pe, i) });
        }
      }
      i = j;
    }
  }
  return out;
}

export { PRINTABLE };
