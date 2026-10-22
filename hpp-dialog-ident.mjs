// hpp-dialog-ident.mjs — dialog 槽位身份（sub 标签）修复层 + 旧单元保真合并
//
// 背景：旧解析器对 EX 模板少了「字体块后 4 字节对齐」，首控件起点偏 2 字节 ⇒
//   · 控件序号整体错位（文本本身、fileOff、maxUnits 大多仍正确）；
//   · 少数模板还把「字体名/标题串的尾巴」误判成控件（幻影单元）。
//
// 策略（保证回归 + 增加覆盖）：
//   1. 旧 worklist（prev2）里已支持的 26 个模板，其 191 个单元**原样保留**（连同旧 sub 标签），
//      逐个校验它们在新解析中仍能按 (fileOff, text, maxUnits) 对上 —— 保证逐字节一致；
//   2. 新解析器在同一模板里额外找出的单元，按修正后的 ctl#N 追加；
//   3. 全新支持的模板一律使用修正后的 ctl#N。
//
// 本模块不做任何字节级改动，只决定「产出哪些单元、用什么 sub 标签」。

import fs from 'node:fs';

export function loadOldDialogUnits(prevPath) {
  const j = JSON.parse(fs.readFileSync(prevPath, 'utf8'));
  const map = new Map(); // id -> [{sub,fileOff,maxUnits,text,field}]
  for (const u of j.units) {
    if (u.kind !== 'dialog') continue;
    if (!map.has(u.id)) map.set(u.id, []);
    map.get(u.id).push({ sub: u.sub, fileOff: u.fileOff, maxUnits: u.maxUnits, text: u.text, field: u.field, controlId: u.controlId ?? null });
  }
  return map;
}

const same = (a, b) => a.fileOff === b.fileOff && a.maxUnits === b.maxUnits && a.text === b.text;

// oldList: 旧单元数组（可为 undefined）；newTexts: 新解析器的 texts
// 返回 { units, preserved, added, unmatchedOld, relabeled }
export function mergeDialogUnits(newTexts, oldList) {
  if (!oldList || !oldList.length) {
    return { units: newTexts.map(t => ({ ...t })), preserved: [], added: newTexts.map(t => ({ ...t })), unmatchedOld: [], relabeled: [] };
  }
  const used = new Set();
  const preserved = [];
  const relabeled = [];
  for (const o of oldList) {
    const i = newTexts.findIndex((t, k) => !used.has(k) && same(o, t));
    if (i >= 0) {
      used.add(i);
      const t = newTexts[i];
      preserved.push({ ...o });
      if (o.sub !== t.sub) relabeled.push({ id: null, from: t.sub, to: o.sub, fileOff: o.fileOff, text: o.text });
    }
  }
  const unmatchedOld = oldList.filter(o => !preserved.some(p => same(p, o)));
  const added = newTexts.filter((t, k) => !used.has(k));
  return { units: [...preserved.map(p => ({ ...p })), ...added.map(t => ({ ...t }))], preserved, added, unmatchedOld, relabeled };
}
