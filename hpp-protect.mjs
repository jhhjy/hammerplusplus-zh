// hpp-protect.mjs — 「不可改写区」计算
//
// 事故教训：`.rdata` 里有一处 "Warning" 不是界面文字，而是本 DLL 从 tier0.dll
// **导入的函数名**（IMAGE_IMPORT_BY_NAME）。字面量筛选把它当界面词翻成「警告」，
// GBK 字节覆盖了导入名 → 加载期解析导入失败 → 弹「无法定位程序输入点」。
// 之前的检查只覆盖「PE 数据目录范围」，而导入名表在 .rdata、不在目录范围内。
//
// 本模块把下列区域算作**不可改写**：
//   1) 除资源目录外的 15 个数据目录（导出/导入/IAT/重定位/TLS/loadconfig/debug…）；
//   2) 每个导入 DLL 的名字串、每个 IMAGE_IMPORT_BY_NAME（Hint+名字）、thunk 数组；
//   3) 导出目录的名字串、名字指针表、序号表；
//   4) 资源目录的结构（目录头 + 条目 + 数据入口）。
// 资源目录中的**数据块不保护** —— 菜单/对话框/字符串表的文本就在那里，那正是改写目标。

export function protectedRanges(buf) {
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
  const r2o = (rva) => {
    for (const s of secs) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) return s.rawPtr + (rva - s.va);
    return -1;
  };
  const dirOff = optOff + 96;
  const R = [];
  const add = (off, len) => { if (off >= 0 && len > 0) R.push([off, off + len]); };
  const cstr = (off) => { let e = off; while (e < buf.length && buf[e] !== 0) e++; return e - off + 1; };

  const dirs = {};
  for (let i = 0; i < 16; i++) {
    const rva = buf.readUInt32LE(dirOff + i * 8);
    const size = buf.readUInt32LE(dirOff + i * 8 + 4);
    dirs[i] = { rva, size, off: rva ? r2o(rva) : -1 };
    if (i !== 2 && rva && size) add(dirs[i].off, size); // 资源目录单独处理
  }

  // 导入表
  const imp = dirs[1];
  if (imp && imp.off >= 0) {
    let o = imp.off;
    for (let guard = 0; guard < 512; guard++) {
      const oft = buf.readUInt32LE(o);
      const nameRva = buf.readUInt32LE(o + 12);
      if (!nameRva) break;
      const no = r2o(nameRva);
      add(no, cstr(no));
      if (oft) {
        const to = r2o(oft);
        let t = to, n = 0;
        while (n < 8192 && buf.readUInt32LE(t) !== 0) {
          const v = buf.readUInt32LE(t);
          if (!(v & 0x80000000)) { const fo = r2o(v); add(fo, 2 + cstr(fo + 2)); }
          t += 4; n++;
        }
        add(to, (n + 1) * 4);
      }
      o += 20;
    }
  }

  // 导出表
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

  // 资源目录结构（不含数据块）
  const rsrc = dirs[2];
  if (rsrc && rsrc.off >= 0) {
    const base = rsrc.off;
    const seen = new Set();
    const walk = (off, depth) => {
      if (depth > 4 || seen.has(off) || off < 0 || off + 16 > buf.length) return;
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

export function intersectsAny(ranges, start, end) {
  for (const [s, e] of ranges) if (start < e && end > s) return true;
  return false;
}
