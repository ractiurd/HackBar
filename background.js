import { syncBlockRules, clearAllDynamicRules } from "./lib/nrd_rules.js";
import { initGsScanner } from "./lib/gs_scanner.js";

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel
    .setPanelBehavior({ openPanelOnActionClick: true })
    .catch((e) => console.error(e));
});

chrome.action.onClicked.addListener((tab) => {
  if (tab && tab.id) {
    chrome.sidePanel.open({ tabId: tab.id }).catch((e) => console.error(e));
  }
});

const dnr = chrome.declarativeNetRequest;

async function applyBlockRules() {
  if (!dnr) return;
  await clearAllDynamicRules(dnr);
  const r = await chrome.storage.local.get(["nrdBlock"]);
  await syncBlockRules(dnr, (r && r.nrdBlock) || "");
}

applyBlockRules();

// initialise the GhoulSight XSS scanner (message router + listeners)
initGsScanner();

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.nrdBlock || !dnr) return;
  syncBlockRules(dnr, changes.nrdBlock.newValue || "");
});
