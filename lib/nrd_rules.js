export const NRD_RULE_BASE = 900000;

export function buildBlockRules(text) {
  const lines = (text || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const types = ["main_frame", "sub_frame"];
  const action = { type: "block" };
  const rules = [];
  lines.forEach((line, idx) => {
    const isRegex = line.length >= 2 && line.startsWith("/") && line.lastIndexOf("/") > 0;
    if (isRegex) {
      const last = line.lastIndexOf("/");
      const body = line.slice(1, last);
      const flags = line.slice(last + 1);
      try { new RegExp(body, flags); } catch (e) { return; }
      rules.push({
        id: NRD_RULE_BASE + idx,
        priority: 1,
        action,
        condition: { regexFilter: body, resourceTypes: types, isUrlFilterCaseSensitive: !/i/.test(flags) },
      });
    } else {
      rules.push({
        id: NRD_RULE_BASE + idx,
        priority: 1,
        action,
        condition: { urlFilter: line, resourceTypes: types, isUrlFilterCaseSensitive: false },
      });
    }
  });
  return rules;
}

export async function clearAllDynamicRules(dnr) {
  try {
    const existing = await dnr.getDynamicRules();
    const ids = existing.map((r) => r.id);
    if (ids.length) await dnr.updateDynamicRules({ removeRuleIds: ids });
  } catch (e) {}
}

export async function clearBlockRules(dnr) {
  const removeIds = [];
  for (let i = 0; i < 256; i++) removeIds.push(NRD_RULE_BASE + i);
  try { await dnr.updateDynamicRules({ removeRuleIds: removeIds }); } catch (e) {}
}

export async function syncBlockRules(dnr, text) {
  if (!dnr || !dnr.updateDynamicRules) return;
  const addRules = buildBlockRules(text);
  const removeIds = [];
  for (let i = 0; i < 256; i++) removeIds.push(NRD_RULE_BASE + i);
  try {
    await dnr.updateDynamicRules({ removeRuleIds: removeIds, addRules });
  } catch (e) {
    try { await dnr.updateDynamicRules({ removeRuleIds: removeIds, addRules: [] }); } catch (_) {}
    for (const r of addRules) {
      try { await dnr.updateDynamicRules({ addRules: [r] }); } catch (_) {}
    }
  }
}
