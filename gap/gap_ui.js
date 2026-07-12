// gap/gap_ui.js
// GAP category UI for the HackBar.
// GAP — original by /XNL-h4ck3r (@xnl_h4ck3r): https://github.com/xnl-h4ck3r/GAP-Burp-Extension

import { runGAP, DEFAULT_EXCLUSIONS, DEFAULT_STOP_WORDS } from "./gap_core.js";

const el = (tag, cls, txt) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (txt != null) e.textContent = txt;
  return e;
};

// ---- state ----
const S = {
  url: "",
  html: "",
  header: "",
  contentType: "",
  mimeType: "",
  result: null,
  scanning: false,
  q: "",
  opts: {
    modeLinks: true,
    modeParams: true,
    modeWords: false,
    useExclusions: true,
    exclusions: DEFAULT_EXCLUSIONS,
    relativeLinks: true,
    inScopeOnly: false,
    prefixOrigin: true,
    unPrefixed: false,
    paramFromLinks: true,
    paramJson: true,
    paramXml: true,
    paramInput: true,
    paramJsVars: true,
    paramPathWords: true,
    susParams: true,
    wordMin: 3,
    wordMax: 0,
    wordPlurals: true,
    wordLower: true,
    wordDigits: false,
    wordPaths: true,
    wordComments: true,
    wordImgAlt: true,
    wordParams: true,
    stopWords: DEFAULT_STOP_WORDS,
  },
  sizes: { col: 0.5, r1: 230, r2: 300 },
  refs: {},
};

const STORE_KEY = "gap_settings_v1";
const SIZE_KEY = "gap_sizes_v1";
let saveTimer = null;
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { chrome.storage.local.set({ [STORE_KEY]: S.opts }); } catch (e) {}
  }, 350);
}
function persistSizes() {
  try { chrome.storage.local.set({ [SIZE_KEY]: S.sizes }); } catch (e) {}
}
function load(cb) {
  try {
    chrome.storage.local.get([STORE_KEY, SIZE_KEY], (r) => {
      if (r && r[STORE_KEY]) S.opts = Object.assign(S.opts, r[STORE_KEY]);
      if (r && r[SIZE_KEY]) S.sizes = Object.assign(S.sizes, r[SIZE_KEY]);
      if (cb) cb();
    });
  } catch (e) { if (cb) cb(); }
}

function applySizes(node) {
  const s = S.sizes;
  node.style.setProperty("--gc1", s.col.toFixed(3) + "fr");
  node.style.setProperty("--gc2", (1 - s.col).toFixed(3) + "fr");
  node.style.setProperty("--gr1", Math.round(s.r1) + "px");
  node.style.setProperty("--gr2", Math.round(s.r2) + "px");
}

// ---- ctx provided by panel.js ----
let CTX = null;

function setStatus(t, k) { if (CTX && CTX.setStatus) CTX.setStatus(t, k); }
function copyText(t, b) { if (CTX && CTX.copyText) return CTX.copyText(t, b); }

function mimeFromContentType(ct) {
  ct = (ct || "").toLowerCase();
  if (ct.includes("json")) return "JSON";
  if (ct.includes("xml")) return "XML";
  if (ct.includes("html")) return "HTML";
  if (ct.includes("javascript") || ct.includes("ecmascript")) return "JAVASCRIPT";
  if (ct.includes("text/plain")) return "PLAIN";
  if (ct.includes("css")) return "CSS";
  return "";
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function scanPage() {
  if (S.scanning) return;
  let tab;
  try { tab = await getActiveTab(); }
  catch (e) { return setStatus("GAP: cannot access tab — " + e.message, "err"); }
  if (!tab || !tab.url || !/^https?:/i.test(tab.url)) {
    return setStatus("GAP: open an http(s) page to scan", "err");
  }
  S.scanning = true;
  S.url = tab.url;
  setScanState(true);
  setStatus("GAP scanning " + new URL(tab.url).hostname + "…", "info");

  let resp;
  try {
    const nrd = CTX && CTX.noRedirect ? CTX.noRedirect() : false;
    resp = await fetch(tab.url, { credentials: "include", cache: "no-store", redirect: nrd ? "manual" : "follow" });
  } catch (e) {
    S.scanning = false; setScanState(false);
    return setStatus("GAP fetch failed — " + e.message + " (try the live DOM button)", "err");
  }

  let body = "";
  try { body = await resp.text(); } catch (e) {}
  const ct = resp.headers.get("content-type") || "";
  S.html = body;
  S.header = "";
  S.contentType = ct;
  S.mimeType = mimeFromContentType(ct);

  // If the fetch body is empty/opaque (e.g. manual redirect), fall back to the
  // live tab DOM so the tool still produces results.
  if ((!body || body.length < 32) && typeof tab.id === "number") {
    try {
      const [r] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => "<!doctype html>" + document.documentElement.outerHTML,
      });
      if (r && r.result) { S.html = r.result; S.mimeType = "HTML"; }
    } catch (e) {}
  }

  runAndRender();
}

// Scan the live DOM of the current tab instead of re-fetching the URL.
async function scanDom() {
  if (S.scanning) return;
  let tab;
  try { tab = await getActiveTab(); }
  catch (e) { return setStatus("GAP: cannot access tab — " + e.message, "err"); }
  if (!tab || typeof tab.id !== "number") return setStatus("GAP: no active tab", "err");
  S.scanning = true;
  setScanState(true);
  setStatus("GAP reading live DOM…", "info");
  try {
    const [r] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => "<!doctype html>" + document.documentElement.outerHTML,
    });
    S.html = (r && r.result) || "";
    S.url = tab.url || "";
    S.contentType = "text/html";
    S.mimeType = "HTML";
    S.header = "";
  } catch (e) {
    S.scanning = false; setScanState(false);
    return setStatus("GAP DOM read failed — " + e.message, "err");
  }
  runAndRender();
}

function runAndRender() {
  const o = S.opts;
  const result = runGAP({
    html: S.html, header: S.header, url: S.url,
    contentType: S.contentType, mimeType: S.mimeType,
    modes: { links: o.modeLinks, params: o.modeParams, words: o.modeWords },
    useExclusions: o.useExclusions, exclusions: o.exclusions,
    relativeLinks: o.relativeLinks, inScopeOnly: o.inScopeOnly,
    prefixOrigin: o.prefixOrigin, unPrefixed: o.unPrefixed,
    paramFromLinks: o.paramFromLinks, paramJson: o.paramJson, paramXml: o.paramXml,
    paramInput: o.paramInput, paramJsVars: o.paramJsVars, paramPathWords: o.paramPathWords,
    susParams: o.susParams,
    wordMin: o.wordMin, wordMax: o.wordMax, wordPlurals: o.wordPlurals,
    wordLower: o.wordLower, wordDigits: o.wordDigits, wordPaths: o.wordPaths,
    wordComments: o.wordComments, wordImgAlt: o.wordImgAlt, wordParams: o.wordParams,
    stopWords: o.stopWords,
  });
  S.result = result;
  S.scanning = false;
  setScanState(false);
  const n = (result.links.length || 0) + (result.params.length || 0) + (result.words.length || 0);
  setStatus("GAP done — " + result.links.length + " links, " + result.params.length + " params, " + result.words.length + " words" + (result.skipped ? " (content skipped)" : ""), n ? "ok" : "warn");
  renderResults();
}

function setScanState(on) {
  const r = S.refs;
  if (r.scanBtn) { r.scanBtn.disabled = on; r.scanBtn.textContent = on ? "Scanning…" : "Scan page"; }
  if (r.domBtn) r.domBtn.disabled = on;
}

/* ===================== rendering ===================== */

export function renderGap(ctx) {
  CTX = ctx || CTX;
  load(() => {
    renderShell();
  });
}

function renderShell() {
  const { plist, subcats } = CTX;
  subcats.style.display = "none";
  plist.innerHTML = "";
  S.refs = {};

  // ---- toolbar ----
  const bar = el("div", "af-bar gap-bar");

  const scanBtn = el("button", "btn go");
  scanBtn.textContent = "Scan page";
  scanBtn.title = "Fetch the current page response and run GAP on it";
  scanBtn.addEventListener("click", scanPage);
  const domBtn = el("button", "btn");
  domBtn.textContent = "Live DOM";
  domBtn.title = "Run GAP on the current tab's live rendered DOM";
  domBtn.addEventListener("click", scanDom);
  const optsBtn = el("button", "btn ghost small");
  optsBtn.textContent = "Options " + "\u25bc";
  optsBtn.title = "Show / hide GAP options";
  const copyBtn = el("button", "btn ghost small");
  copyBtn.textContent = "Copy all";
  copyBtn.title = "Copy every link, param and word";
  copyBtn.addEventListener("click", () => {
    const r = S.result;
    if (!r) return setStatus("Nothing to copy yet", "warn");
    const parts = [];
    if (S.opts.modeLinks && r.links.length) parts.push("# LINKS\n" + r.links.join("\n"));
    if (S.opts.modeParams && r.params.length) parts.push("# PARAMS\n" + r.params.join("\n"));
    if (S.opts.modeWords && r.words.length) parts.push("# WORDS\n" + r.words.join("\n"));
    copyText(parts.join("\n\n"), copyBtn);
  });
  const saveBtn = el("button", "btn ghost small");
  saveBtn.textContent = "Save";
  saveBtn.title = "Download links, params and words as text files";
  saveBtn.addEventListener("click", saveAll);

  const url = el("span", "gap-url");
  url.textContent = S.url ? "\u21b8 " + S.url : "no page scanned yet";
  url.title = S.url || "";

  bar.append(scanBtn, domBtn, optsBtn, url, el("span", "grow"), copyBtn, saveBtn);
  S.refs.scanBtn = scanBtn;
  S.refs.domBtn = domBtn;
  S.refs.urlEl = url;
  plist.appendChild(bar);

  // ---- options (collapsible) ----
  const optWrap = el("div", "gap-opts hidden");
  S.refs.optWrap = optWrap;
  optsBtn.addEventListener("click", () => {
    optWrap.classList.toggle("hidden");
    optsBtn.textContent = "Options " + (optWrap.classList.contains("hidden") ? "\u25bc" : "\u25b2");
  });

  const mkChk = (label, key, tip) => {
    const lab = el("label", "chk");
    const c = el("input");
    c.type = "checkbox";
    c.checked = !!S.opts[key];
    if (tip) lab.title = tip;
    c.addEventListener("change", () => { S.opts[key] = c.checked; persist(); });
    lab.append(c, document.createTextNode(label));
    return lab;
  };
  const mkNum = (key, ph, size) => {
    const i = el("input", "gap-num");
    i.type = "number";
    i.value = S.opts[key];
    i.size = size || 2;
    i.placeholder = ph;
    i.addEventListener("input", () => { S.opts[key] = parseInt(i.value, 10) || 0; persist(); });
    return i;
  };

  // Links
  const lk = el("div", "gap-optgroup");
  lk.appendChild(secTitle("Links"));
  lk.appendChild(mkChk("Find links", "modeLinks", "Enable Links mode"));
  lk.appendChild(mkChk("Relative (./ ../)", "relativeLinks", "Include links starting with ./ or ../"));
  lk.appendChild(mkChk("Prefix with origin", "prefixOrigin", "Prefix relative paths with the page origin"));
  lk.appendChild(mkChk("In-scope only", "inScopeOnly", "Only show links on the same origin"));
  lk.appendChild(mkChk("Keep un-prefixed", "unPrefixed", "Also keep the original relative link"));
  lk.appendChild(mkChk("Exclusions", "useExclusions", "Filter out static assets / CDNs"));
  const exclTa = el("textarea", "af-wl gap-excl");
  exclTa.rows = 3;
  exclTa.value = S.opts.exclusions;
  exclTa.title = "Comma separated values — links containing these are excluded";
  exclTa.addEventListener("input", () => { S.opts.exclusions = exclTa.value; persist(); });
  lk.appendChild(exclTa);

  // Params
  const pm = el("div", "gap-optgroup");
  pm.appendChild(secTitle("Parameters"));
  pm.appendChild(mkChk("Find params", "modeParams", "Enable Parameters mode"));
  pm.appendChild(mkChk("Params from links", "paramFromLinks", "Pull query param names from links found"));
  pm.appendChild(mkChk("JSON keys", "paramJson"));
  pm.appendChild(mkChk("XML attributes", "paramXml"));
  pm.appendChild(mkChk("HTML input name/id", "paramInput"));
  pm.appendChild(mkChk("JS var/let/const", "paramJsVars"));
  pm.appendChild(mkChk("Path words", "paramPathWords"));
  pm.appendChild(mkChk("Flag \u201csus\u201d params", "susParams", "Highlight params often tied to vuln classes"));

  // Words
  const wd = el("div", "gap-optgroup");
  wd.appendChild(secTitle("Words"));
  wd.appendChild(mkChk("Find words", "modeWords", "Enable Words mode (wordlist generation)"));
  const wl = el("div", "gap-wlen");
  wl.appendChild(document.createTextNode("length "));
  wl.appendChild(mkNum("wordMin", "min"));
  wl.appendChild(document.createTextNode(" to "));
  wl.appendChild(mkNum("wordMax", "max (0=\u221e)"));
  wd.appendChild(wl);
  wd.appendChild(mkChk("Plurals / singulars", "wordPlurals"));
  wd.appendChild(mkChk("Lowercase variants", "wordLower"));
  wd.appendChild(mkChk("Include digits", "wordDigits"));
  wd.appendChild(mkChk("Path words", "wordPaths"));
  wd.appendChild(mkChk("HTML comments", "wordComments"));
  wd.appendChild(mkChk("IMG alt", "wordImgAlt"));
  wd.appendChild(mkChk("Include params", "wordParams"));
  const swLabel = el("div", "gap-swlabel");
  swLabel.textContent = "Stop words";
  const swTa = el("textarea", "af-wl gap-sw");
  swTa.rows = 2;
  swTa.value = S.opts.stopWords;
  swTa.addEventListener("input", () => { S.opts.stopWords = swTa.value; persist(); });
  wd.append(swLabel, swTa);

  optWrap.append(lk, pm, wd);
  plist.appendChild(optWrap);

  // ---- result boxes: Params | Words on top, Links full-width below ----
  const boxes = el("div", "gap-boxes");
  S.refs.box = {};
  S.refs.boxes = boxes;
  [["params", "Params", "modeParams"], ["words", "Words", "modeWords"], ["links", "Links", "modeLinks"]].forEach(
    ([key, title, modeKey]) => {
      const box = el("div", "gap-box");
      box.dataset.key = key;
      const h = el("div", "gap-box-h");
      const tt = el("span", "gap-box-t");
      tt.textContent = title;
      const cnt = el("span", "gap-box-c");
      cnt.textContent = "0";
      const cp = el("button", "gap-box-cp");
      cp.type = "button";
      cp.title = "Copy all " + title.toLowerCase();
      cp.textContent = "\u2398";
      h.append(tt, cnt, el("span", "grow"), cp);
      const list = el("div", "gap-box-list");
      box.append(h, list);
      boxes.appendChild(box);
      S.refs.box[key] = { list, cnt, cp, modeKey, title };
    }
  );

  // drag handles — column split (Params|Words) + row split (above Links)
  const hsplit = el("div", "gap-hsplit");
  hsplit.title = "drag to resize Params / Words  ·  dblclick to reset";
  const vsplit = el("div", "gap-vsplit");
  vsplit.title = "drag to resize rows  ·  dblclick to reset";
  boxes.append(hsplit, vsplit);
  wireResize(hsplit, vsplit, boxes);

  applySizes(boxes);
  plist.appendChild(boxes);
  renderResults();
}

function wireResize(hsplit, vsplit, boxes) {
  const endDrag = (move, up) => {
    document.removeEventListener("mousemove", move);
    document.removeEventListener("mouseup", up);
  };

  // column split
  const colMove = (ev) => {
    const rect = boxes.getBoundingClientRect();
    let ratio = (ev.clientX - rect.left) / rect.width;
    ratio = Math.max(0.12, Math.min(0.88, ratio));
    S.sizes.col = ratio;
    applySizes(boxes);
  };
  hsplit.addEventListener("mousedown", (e) => {
    e.preventDefault();
    document.addEventListener("mousemove", colMove);
    document.addEventListener("mouseup", function up() { endDrag(colMove, up); persistSizes(); });
  });
  hsplit.addEventListener("dblclick", () => { S.sizes.col = 0.5; applySizes(boxes); persistSizes(); });

  // row split (redistribute between top row and Links, keeping their total)
  let rowTotal = 0;
  const rowMove = (ev) => {
    const rect = boxes.getBoundingClientRect();
    let h1 = ev.clientY - rect.top - 4;
    h1 = Math.max(90, Math.min(rowTotal - 110, h1));
    S.sizes.r1 = Math.round(h1);
    S.sizes.r2 = Math.round(rowTotal - h1);
    applySizes(boxes);
  };
  vsplit.addEventListener("mousedown", (e) => {
    e.preventDefault();
    rowTotal = S.sizes.r1 + S.sizes.r2;
    document.addEventListener("mousemove", rowMove);
    document.addEventListener("mouseup", function up() { endDrag(rowMove, up); persistSizes(); });
  });
  vsplit.addEventListener("dblclick", () => { S.sizes.r1 = 230; S.sizes.r2 = 300; applySizes(boxes); persistSizes(); });
}

// Collapse full-URL + relative duplicates of the same endpoint into one row.
function dedupLinks(arr) {
  const seen = new Set();
  const out = [];
  for (const a of arr) {
    let key = a;
    try { key = new URL(a, S.url).href; } catch (e) {}
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out;
}

function flash(node) {
  const o = node.style.background;
  node.style.background = "var(--sel)";
  setTimeout(() => { node.style.background = o; }, 160);
}

function renderResults() {
  const box = S.refs.box;
  if (!box) return;
  const q = S.q ? S.q.toLowerCase() : "";
  const filter = (arr) => (q ? arr.filter((s) => s.toLowerCase().includes(q)) : arr);

  const render = (key, rowFn) => {
    const b = box[key];
    b.list.innerHTML = "";
    if (!S.opts[b.modeKey]) {
      b.cnt.textContent = "off";
      b.cp.disabled = true;
      b.cp.onclick = null;
      b.list.appendChild(empty(cap(key) + " mode is off \u2014 enable in Options."));
      return;
    }
    b.cp.disabled = false;
    if (!S.result) {
      b.cnt.textContent = "0";
      b.cp.onclick = null;
      b.list.appendChild(empty("Press \u201cScan page\u201d."));
      return;
    }
    let items = key === "links" ? dedupLinks(S.result.links) : S.result[key];
    items = filter(items);
    b.cnt.textContent = String(items.length);
    if (!items.length) {
      b.cp.onclick = null;
      b.list.appendChild(empty(q ? "No match." : "None found."));
      return;
    }
    b.cp.onclick = () => copyText(items.join("\n"), b.cp);
    const frag = document.createDocumentFragment();
    items.forEach((it) => frag.appendChild(rowFn(it)));
    b.list.appendChild(frag);
  };

  // Links — dim host, bright path; click=copy, dblclick=open
  render("links", (raw) => {
    const row = el("div", "gap-lrow");
    row.title = "click: copy  \u00b7  dblclick: open\n" + raw;
    const main = el("span", "gap-lmain");
    let host = "", rest = raw;
    try {
      const u = new URL(raw, S.url);
      host = u.protocol + "//" + u.host;
      rest = (u.pathname || "") + (u.search || "") + (u.hash || "");
    } catch (e) {}
    if (host && rest) {
      const h = el("span", "gap-lhost");
      h.textContent = host;
      const p = el("span", "gap-lpath");
      p.textContent = rest === "" ? "/" : rest;
      main.append(h, p);
    } else {
      main.textContent = raw;
    }
    row.appendChild(main);
    row.addEventListener("click", () => { copyText(raw); flash(row); });
    row.addEventListener("dblclick", (e) => {
      e.stopPropagation();
      try { chrome.tabs.create({ url: raw }); } catch (er) {}
    });
    return row;
  });

  // Params — name + sus vuln tag
  render("params", (item) => {
    const row = el("div", "gap-prow");
    const sus = item.includes("  [");
    row.classList.toggle("gap-sus", sus);
    if (sus) {
      const idx = item.indexOf("  [");
      const name = item.slice(0, idx);
      const types = item.slice(idx + 3).replace("]", "");
      const nm = el("span", "gap-pname");
      nm.textContent = name;
      const ty = el("span", "gap-ptypes");
      ty.textContent = types;
      row.append(nm, ty);
      row.title = name + " \u2014 " + types;
    } else {
      const nm = el("span", "gap-pname");
      nm.textContent = item;
      row.appendChild(nm);
      row.title = item;
    }
    row.addEventListener("click", () => { copyText(item); flash(row); });
    return row;
  });

  // Words — plain wordlist entries
  render("words", (word) => {
    const row = el("div", "gap-wrow");
    row.textContent = word;
    row.title = word;
    row.addEventListener("click", () => { copyText(word); flash(row); });
    return row;
  });
}

function saveAll() {
  if (!S.result) return setStatus("Nothing to save yet", "warn");
  const r = S.result;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const host = (() => { try { return new URL(S.url).hostname; } catch (e) { return "page"; } })();
  const dl = (name, arr) => {
    if (!arr || !arr.length) return;
    const blob = new Blob([arr.join("\n") + "\n"], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "gap-" + name + "-" + host + "-" + stamp + ".txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };
  let n = 0;
  if (S.opts.modeLinks) { dl("links", r.links); n++; }
  if (S.opts.modeParams) {
    dl("params", r.params);
    if (r.sus && r.sus.length) dl("susparams", r.sus);
    n++;
  }
  if (S.opts.modeWords) { dl("words", r.words); n++; }
  setStatus(n ? "Saved " + n + " file(s)" : "No enabled modes to save", n ? "ok" : "warn");
}

export function applySearch(q) {
  S.q = (q || "").trim();
  if (CTX && CTX.isActive && CTX.isActive()) renderResults();
}

function secTitle(t) {
  const h = el("div", "gap-sec");
  h.textContent = t;
  return h;
}
function empty(t) {
  const e = el("div", "pempty");
  e.textContent = t;
  return e;
}
function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
