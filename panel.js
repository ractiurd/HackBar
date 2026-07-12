import { TRANSFORMS } from "./lib/encoder.js";
import { HASHES } from "./lib/hasher.js";
import { PAYLOADS } from "./lib/payloads.js";
import { SQL_TREE, WAF_TREE } from "./lib/sql.js";
import { EXTRA_DIOS_TREE } from "./lib/dios_extra.js";
import { BYPASS_TREE } from "./lib/inject.js";
import { ADMIN_PATHS } from "./lib/admin_finder.js";
import { renderGap, applySearch as gapApplySearch } from "./gap/gap_ui.js";

const $ = (s) => document.querySelector(s);

const cattabs = $("#cattabs");
const subcats = $("#subcats");
const plist = $("#plist");
const search = $("#search");

const urlField = $("#url");
const body = $("#body");
const ck = $("#ck");
const post = $("#post");
const cookie = $("#cookie");
const postWrap = $("#post-wrap");
const cookieWrap = $("#cookie-wrap");
const statusEl = $("#status");
const btnBack = $("#btn-back");
const btnFwd = $("#btn-fwd");
const btnInc = $("#btn-inc");
const btnDec = $("#btn-dec");
const nrd = $("#nrd");
const nrdEdit = $("#nrd-edit");
const nrdPop = $("#nrd-pop");
const nrdBlockEl = $("#nrd-block");
const nrdCnt = $("#nrd-cnt");
let noRedirect = false;
let nrdBlockState = "";

/* GhoulSight header toggle + settings pane */
const gs = $("#gs");
const gsApikey = $("#gs-apikey");
const gsServer = $("#gs-server");
const gsHeaders = $("#gs-headers");
const gsCookies = $("#gs-cookies");
const gsFollow = $("#gs-follow");
const gsCrawl = $("#gs-crawl");
const gsSave = $("#gs-save");
const gsSaveMsg = $("#gs-savemsg");
const tabNrd = $("#tab-nrd");
const tabGs = $("#tab-gs");
const paneNrd = $("#pane-nrd");
const paneGs = $("#pane-gs");
let gsScanning = false;
let gsSettings = { apiKey: "", serverUrl: "", headers: "", collectCookies: false, followLinks: true, activeCrawl: false };

const CATS = ["SQL", "WAF", "Bypass", "Custom", "XSS", "HTMLi", "LFI", "SSRF", "XXE", "CMDi", "SSTI", "Redirect", "Encoder", "Hasher", "Extract", "Fuzzer", "GAP", "Links"];

const T = Object.fromEntries(TRANSFORMS.map((x) => [x.label, x.fn]));
const H = Object.fromEntries(HASHES.map((x) => [x.label, x.fn]));
const CODECS = [
  { name: "URL", enc: T["URL enc"], dec: T["URL dec"] },
  { name: "B64", enc: T["Base64 enc"], dec: T["Base64 dec"] },
  { name: "HEX", enc: T["Hex enc"], dec: T["Hex dec"] },
  { name: "HTML", enc: T["HTML enc"], dec: T["HTML dec"] },
  { name: "UNI", enc: T["Unicode enc"], dec: T["Unicode dec"] },
];

const SINGLE = [
  { l: "SHA256", f: H["SHA-256"] },
  { l: "UPPER", f: (s) => s.toUpperCase() },
  { l: "lower", f: (s) => s.toLowerCase() },
];

function qBtn(label, fn) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "qbtn";
  b.textContent = label;
  b.title = label + "  (applies to selected text)";
  b.addEventListener("click", () => {
    applyTransform(fn);
    flash(b);
    setStatus(label + " applied", "info");
  });
  return b;
}

function buildQuick() {
  const bar = $("#quickbar");
  CODECS.forEach((c) => {
    const wrap = document.createElement("span");
    wrap.className = "qcodec";

    const dec = document.createElement("button");
    dec.type = "button";
    dec.className = "qdec";
    dec.innerHTML = "&laquo;";
    dec.title = c.name + " decode  (« = <<)";
    dec.addEventListener("click", () => {
      applyTransform(c.dec);
      flash(wrap);
      setStatus(c.name + " decoded", "info");
    });

    const nm = document.createElement("span");
    nm.className = "qnm";
    nm.textContent = c.name;

    const enc = document.createElement("button");
    enc.type = "button";
    enc.className = "qenc";
    enc.innerHTML = "&raquo;";
    enc.title = c.name + " encode  (» = >>)";
    enc.addEventListener("click", () => {
      applyTransform(c.enc);
      flash(wrap);
      setStatus(c.name + " encoded", "info");
    });

    wrap.append(dec, nm, enc);
    bar.appendChild(wrap);
  });
  SINGLE.forEach((s) => bar.appendChild(qBtn(s.l, s.f)));
}
let activeCat = "SQL";
let activeGroup = null;
let focused = urlField;

/* ---------- URL HISTORY (back / forward) ---------- */
const urlHistory = [];   // list of visited URLs
let urlHistIdx = -1;     // current position in urlHistory
let navFromHistory = false; // true while we're moving via ‹ › (so it doesn't fork)

function histPush(url) {
  const v = (url || "").trim();
  if (!v) return;
  if (navFromHistory) return;            // navigating — keep list intact
  // ignore duplicates of the current entry
  if (urlHistIdx >= 0 && urlHistory[urlHistIdx] === v) return;
  // if we navigated back then entered a new URL, drop the forward branch
  if (urlHistIdx < urlHistory.length - 1) urlHistory.length = urlHistIdx + 1;
  urlHistory.push(v);
  urlHistIdx = urlHistory.length - 1;
  updateHistButtons();
}

function histGo(delta) {
  const next = urlHistIdx + delta;
  if (next < 0 || next >= urlHistory.length) return;
  navFromHistory = true;
  urlHistIdx = next;
  urlField.value = urlHistory[next];
  updateHistButtons();
  // execute the restored URL like a browser would
  execute().finally(() => (navFromHistory = false));
}

function updateHistButtons() {
  if (btnBack) btnBack.disabled = urlHistIdx <= 0;
  if (btnFwd) btnFwd.disabled = urlHistIdx >= urlHistory.length - 1;
}

/* ---------- NUMBER BUMP (+1 / −1) ----------
   Finds the selected number in the focused field (or the last number if no
   selection), increments/decrements it, re-selects it, then executes. */
function bumpNumber(delta) {
  const ta = focused || urlField;
  const text = ta.value;
  if (text == null) return;
  let start = ta.selectionStart || 0;
  let end = ta.selectionEnd || 0;
  const hasSel = end > start;
  // regex to find a run of digits (optional leading minus)
  const re = /-?\d+/g;
  let match;
  let target = null;
  // pick the number that overlaps the selection, else the last number in the text
  while ((match = re.exec(text)) !== null) {
    const ms = match.index;
    const me = ms + match[0].length;
    if (hasSel && ms < end && me > start) { target = { s: ms, e: me, num: match[0] }; break; }
    target = { s: ms, e: me, num: match[0] }; // keep updating → last number
  }
  if (!target) {
    setStatus("No number found to bump", "err");
    return;
  }
  // strip leading minus only if value is negative after change
  let n = parseInt(target.num, 10) + delta;
  // allow negative results, but if original had no minus and we'd go negative, clamp at 0
  if (n < 0 && !target.num.startsWith("-")) n = 0;
  const rep = String(n);
  ta.value = text.slice(0, target.s) + rep + text.slice(target.e);
  // re-select the new number so repeated +/− keep working on the same slot
  ta.selectionStart = target.s;
  ta.selectionEnd = target.s + rep.length;
  ta.focus();
  setStatus("→ " + rep, "info");
  execute();
}

[urlField, body, ck].forEach((f) => f.addEventListener("focus", () => (focused = f)));

const isAlb3a = (it) => {
  const p = (it.payload || "").toLowerCase();
  return p.includes("alb3a") || p.includes("6c6233615f54726f7373");
};
const cleanItems = (items) => items.filter((it) => !isAlb3a(it));

function groupsFor(cat) {
  if (cat === "SQL") {
    const core = SQL_TREE.filter((g) => !g.group.startsWith("DIOS · Set"));
    const setItems = SQL_TREE.filter((g) => g.group.startsWith("DIOS · Set")).flatMap((g) => g.items);
    const find = (name) => (EXTRA_DIOS_TREE.find((g) => g.group === name) || { items: [] }).items;
    const ractiurd = find("DIOS · Ractiurd");
    const mysqlExtra = find("DIOS · MySQL");
    const rest = EXTRA_DIOS_TREE.filter((g) => g.group !== "DIOS · Ractiurd" && g.group !== "DIOS · MySQL");
    return core.concat(
      { group: "DIOS · MySQL", items: cleanItems([...ractiurd, ...setItems, ...mysqlExtra]) },
      ...rest.map((g) => ({ group: g.group, items: cleanItems(g.items) }))
    );
  }
  if (cat === "WAF") return WAF_TREE;
  if (cat === "Bypass") return BYPASS_TREE;
  if (cat === "Encoder") return [{ group: "Encode / Decode", items: TRANSFORMS }];
  if (cat === "Hasher") return [{ group: "Hashes", items: HASHES }];
  const arr = PAYLOADS[cat] || [];
  const map = {};
  arr.forEach((it) => {
    const g = it.tag || "General";
    (map[g] = map[g] || []).push(it);
  });
  return Object.keys(map).map((g) => ({ group: g, items: map[g] }));
}

function buildCattabs() {
  cattabs.innerHTML = "";
  CATS.forEach((cat) => {
    const b = document.createElement("button");
    b.className = "ctab" + (cat === activeCat ? " active" : "");
    b.textContent = cat;
    b.addEventListener("click", () => selectCat(cat));
    cattabs.appendChild(b);
  });
}

function selectCat(cat) {
  activeCat = cat;
  $$(".ctab", cattabs).forEach((b) => b.classList.toggle("active", b.textContent === cat));
  if (cat === "Extract") {
    renderExtract();
    return;
  }
  if (cat === "Fuzzer") {
    renderFuzzer();
    return;
  }
  if (cat === "Custom") {
    renderCustom();
    return;
  }
  if (cat === "GAP") {
    renderGap({ plist, subcats, setStatus, copyText, isActive: () => activeCat === "GAP", noRedirect: () => noRedirect });
    return;
  }
  const groups = groupsFor(cat);
  activeGroup = groups.length ? groups[0].group : null;
  renderSubcats();
  renderPlist();
}

function renderSubcats() {
  const groups = groupsFor(activeCat);
  subcats.innerHTML = "";
  if (groups.length <= 1) {
    subcats.style.display = "none";
    return;
  }
  subcats.style.display = "";
  groups.forEach((g) => {
    const row = document.createElement("div");
    row.className = "scat" + (g.group === activeGroup ? " active" : "");
    row.innerHTML = `${g.group} <span class="cnt">(${g.items.length})</span>`;
    row.addEventListener("click", () => {
      activeGroup = g.group;
      $$(".scat", subcats).forEach((s) => s.classList.remove("active"));
      row.classList.add("active");
      renderPlist();
    });
    subcats.appendChild(row);
  });
}

function renderPlist() {
  const q = search.value.trim().toLowerCase();
  const groups = groupsFor(activeCat);
  let items;
  if (q) {
    items = [];
    groups.forEach((g) => g.items.forEach((it) => items.push(it)));
    items = items.filter(
      (it) =>
        (it.name || it.label || "").toLowerCase().includes(q) ||
        (it.payload || "").toLowerCase().includes(q)
    );
  } else {
    const g = groups.find((x) => x.group === activeGroup) || groups[0];
    items = g ? g.items : [];
  }

  plist.innerHTML = "";
  if (!items.length) {
    const e = document.createElement("div");
    e.className = "pempty";
    e.textContent = q ? "No payloads match your filter." : "No payloads.";
    plist.appendChild(e);
    return;
  }

  items.forEach((it) => {
    const row = document.createElement("div");
    row.className = "pitem";
    if (activeCat === "Links") row.title = "open in a new tab";
    const nm = document.createElement("span");
    nm.className = "nm";
    nm.textContent = it.name || it.label;
    row.appendChild(nm);
    const preview = it.payload != null ? it.payload : it.gen ? it.gen(3) : it.fn ? (it.sample || "\u21ba on selection") : "";
    if (preview && preview !== nm.textContent) {
      const pl = document.createElement("span");
      pl.className = "pl";
      pl.textContent = preview + (it.gen ? "  \u27f3" : activeCat === "Links" ? "  \u2197" : "");
      pl.title = preview;
      row.appendChild(pl);
    }
    row.addEventListener("click", () => {
      if (activeCat === "Links") { openLink(it.payload); flash(row); return; }
      if (it.gen) runGenerator(it);
      else if (it.payload != null) insertAtCursor(focused, it.payload);
      else applyTransform(it.fn);
      flash(row);
    });
    plist.appendChild(row);
  });
}

function openLink(url) {
  if (!url) return;
  chrome.tabs.create({ url }).catch((e) => setStatus("Open failed: " + e.message, "err"));
  setStatus("Opened " + url, "info");
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  if (btn) {
    const o = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => (btn.textContent = o), 800);
  }
}

let extractedUrls = [];

async function extractUrls() {
  setStatus("Extracting…", "info");
  let tab;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch (e) {
    return setStatus("Cannot access tab: " + e.message, "err");
  }
  if (!tab || typeof tab.id !== "number") return setStatus("No active tab", "err");
  let res;
  try {
    [res] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const out = [];
        const seen = new Set();
        const add = (raw) => {
          if (!raw) return;
          try {
            const u = new URL(raw, location.href);
            if (u.search && u.search.length > 1) {
              const full = u.origin + u.pathname + u.search;
              if (!seen.has(full)) {
                seen.add(full);
                out.push(full);
              }
            }
          } catch (e) {}
        };
        document.querySelectorAll("a[href]").forEach((a) => add(a.getAttribute("href")));
        document.querySelectorAll("form[action]").forEach((f) => add(f.getAttribute("action")));
        document.querySelectorAll("[src]").forEach((el) => add(el.getAttribute("src")));
        return out;
      },
    });
  } catch (e) {
    return setStatus("Extract failed: " + e.message, "err");
  }
  extractedUrls = (res && res.result) || [];
  setStatus(
    extractedUrls.length + " parameterized links found",
    extractedUrls.length ? "ok" : "warn"
  );
  renderExtract();
}

function renderExtract() {
  subcats.style.display = "none";
  plist.innerHTML = "";

  const bar = document.createElement("div");
  bar.className = "ext-bar";

  const btn = document.createElement("button");
  btn.className = "btn go";
  btn.textContent = "Extract parameterized links";
  btn.addEventListener("click", extractUrls);

  const cnt = document.createElement("span");
  cnt.className = "ext-count";
  cnt.textContent = extractedUrls.length
    ? extractedUrls.length + " links"
    : "click to pull every URL with a query string from the current page";

  const copyAll = document.createElement("button");
  copyAll.className = "btn ghost small";
  copyAll.textContent = "Copy all";
  copyAll.disabled = extractedUrls.length === 0;
  copyAll.addEventListener("click", () => copyText(extractedUrls.join("\n"), copyAll));

  bar.append(btn, cnt, copyAll);
  plist.appendChild(bar);

  const list = document.createElement("div");
  list.className = "ext-list";
  if (!extractedUrls.length) {
    const e = document.createElement("div");
    e.className = "pempty";
    e.textContent = "No parameterized links yet.";
    list.appendChild(e);
  } else {
    extractedUrls.forEach((u) => {
      const row = document.createElement("div");
      row.className = "ext-item";
      const a = document.createElement("span");
      a.className = "ext-url";
      a.textContent = u;
      a.title = u;
      const c = document.createElement("button");
      c.className = "ext-copy";
      c.textContent = "Copy";
      c.addEventListener("click", () => copyText(u, c));
      row.append(a, c);
      list.appendChild(row);
    });
  }
  plist.appendChild(list);
}

/* ---------- FUZZER ----------
   A directory / value fuzzer (ffuf / wfuzz style). The target URL may
   contain the literal token FUZZ; every wordlist entry replaces it. If no
   FUZZ token is present, words are appended to the base URL (legacy
   admin-finder behaviour). An optional "Match" field scans each response
   body for keywords (or /regex/) and surfaces hits with a snippet. */
let fuzzState = {
  target: "",
  wordlist: null,
  matcher: "",
  matcherLabels: [],
  running: false,
  abort: false,
  results: [],
  found: [],
  matched: [],
  total: 0,
  done: 0,
  targetInput: null,
  matcherInput: null,
  wordlistEl: null,
  fillEl: null,
  counterEl: null,
  resultsEl: null,
};

function fuzzStatusClass(s, redir) {
  if (redir) return "warn";
  if (s === 200) return "ok";
  if (s >= 300 && s < 400) return "warn";
  if (s === 401 || s === 403) return "info";
  if (s === 404) return "miss";
  return "err";
}

// Normalise a base URL for legacy append mode (no FUZZ token present).
function fuzzNormalizeBase(raw) {
  let v = (raw || "").trim();
  if (!v) return "";
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) v = "http://" + v;
  try {
    const u = new URL(v);
    let base = u.origin;
    if (u.pathname && u.pathname !== "/" && !/\.[a-z0-9]{1,8}$/i.test(u.pathname)) {
      base = (u.origin + u.pathname).replace(/\/+$/, "");
    }
    return base;
  } catch (e) {
    return v.replace(/\/+$/, "");
  }
}

function fuzzOpen(url) {
  chrome.tabs.create({ url }).catch((e) => setStatus("Open failed: " + e.message, "err"));
}

function fuzzSave(urls) {
  if (!urls || !urls.length) return;
  const blob = new Blob([urls.join("\n")], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "fuzzer-found.txt";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  setStatus("Saved " + urls.length + " URL(s)", "ok");
}

// Parse the "Match" field into matchers: plain terms (substring, ci) and
// /pattern/flags regexes (same syntax as the NoRedirect block-list).
function fuzzParseMatchers(raw) {
  const out = [];
  (raw || "").split(/[\r\n,]+/).forEach((t) => {
    const s = t.trim();
    if (!s) return;
    if (s.length >= 2 && s.startsWith("/") && s.lastIndexOf("/") > 0) {
      const last = s.lastIndexOf("/");
      try { out.push({ re: new RegExp(s.slice(1, last), s.slice(last + 1)), raw: s }); } catch (e) {}
    } else {
      out.push({ term: s.toLowerCase(), raw: s });
    }
  });
  return out;
}

// Run matchers against a response body; returns { hits, snippet } or null.
// hits is a boolean[] aligned to the matchers array (one column per matcher).
function fuzzRunMatchers(text, matchers) {
  if (!matchers.length || !text) return null;
  const lower = text.toLowerCase();
  const hits = matchers.map((m) => (m.re ? m.re.test(text) : lower.indexOf(m.term) >= 0));
  if (!hits.some(Boolean)) return null;
  let firstIdx = -1;
  for (let i = 0; i < matchers.length; i++) {
    if (!hits[i]) continue;
    const m = matchers[i];
    if (m.re) { const mm = m.re.exec(text); if (mm) firstIdx = mm.index; }
    else firstIdx = lower.indexOf(m.term);
    break;
  }
  let snippet = "";
  if (firstIdx >= 0) {
    const start = Math.max(0, firstIdx - 40);
    snippet = (start > 0 ? "\u2026" : "") + text.slice(start, firstIdx + 80).replace(/\s+/g, " ").trim() + "\u2026";
  }
  return { hits, snippet };
}

function fuzzFmtSize(n) {
  if (n == null || n < 0 || isNaN(n)) return "\u2014";
  if (n < 1024) return n + "B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + "KB";
  return (n / (1024 * 1024)).toFixed(2) + "MB";
}

// Grid template for the results table: URL (flex) | one column per matcher
// label | Size | Status | open. Used by both the header and every row so the
// columns line up (Burp Intruder style).
function fuzzCols(labels) {
  const matchCols = labels.length ? labels.map(() => "58px").join(" ") + " " : "";
  return "minmax(90px,1fr) " + matchCols + "52px 46px 44px";
}

// Sort order: status 200 first, then other real statuses ascending, then
// ERR(0) last; within the same status, matched rows before non-matched.
function fuzzStatusGroup(s) {
  if (s === 200) return 0;
  if (s === 0) return 2;
  return 1;
}
function fuzzHasMatch(r) {
  return !!(r.hits && r.hits.some(Boolean));
}
function fuzzCmp(a, b) {
  const ga = fuzzStatusGroup(a.status), gb = fuzzStatusGroup(b.status);
  if (ga !== gb) return ga - gb;
  if (a.status !== b.status) return a.status - b.status;
  const ma = fuzzHasMatch(a) ? 0 : 1, mb = fuzzHasMatch(b) ? 0 : 1;
  return ma - mb;
}

function fuzzResultRow(r, labels) {
  const row = document.createElement("div");
  row.className = "af-trow";
  row.style.gridTemplateColumns = fuzzCols(labels);
  row._r = r;

  const url = document.createElement("span");
  url.className = "af-tcell-url";
  url.textContent = r.word || r.url;
  url.title = r.url;
  row.appendChild(url);

  labels.forEach((label, i) => {
    const c = document.createElement("span");
    const matched = r.hits && r.hits[i];
    c.className = "af-tcell-match " + (matched ? "yes" : "no");
    c.textContent = matched ? "\u2713" : "\u00b7";
    if (matched && r.snippet) c.title = label + ": " + r.snippet;
    row.appendChild(c);
  });

  const size = document.createElement("span");
  size.className = "af-tcell-size";
  size.textContent = fuzzFmtSize(r.size);
  if (r.size >= 0) size.title = r.size + " bytes";
  row.appendChild(size);

  const st = document.createElement("span");
  st.className = "af-tcell-status " + fuzzStatusClass(r.status, r.redir);
  st.textContent = r.redir ? (r.status ? String(r.status) : "RDR") : (r.status === 0 ? "ERR" : String(r.status));
  row.appendChild(st);

  const openWrap = document.createElement("span");
  openWrap.className = "af-tcell-open";
  const open = document.createElement("button");
  open.className = "af-open";
  open.textContent = "open";
  open.addEventListener("click", () => fuzzOpen(r.url));
  openWrap.appendChild(open);
  row.appendChild(openWrap);

  return row;
}

function renderFuzzer() {
  subcats.style.display = "none";
  if (fuzzState.wordlist == null) fuzzState.wordlist = ADMIN_PATHS.join("\n");
  renderFuzzerShell();
  if (!fuzzState.target && fuzzState.targetInput) fuzzPrefillTarget(fuzzState.targetInput);
}

async function fuzzPrefillTarget(input) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      const b = fuzzNormalizeBase(tab.url);
      if (b) {
        fuzzState.target = b;
        if (input) input.value = b;
      }
    }
  } catch (e) {}
}

function fuzzLoadFile(fileInput, wlLabel, wl) {
  const file = fileInput.files && fileInput.files[0];
  fileInput.value = "";
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    setStatus("Wordlist too large (>2 MB)", "err");
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result || "");
    fuzzState.wordlist = text;
    if (wl) wl.value = text;
    const c = text.split(/\r?\n/).filter((s) => s.trim()).length;
    if (wlLabel) wlLabel.textContent = c + " words";
    setStatus("Loaded custom wordlist \u2014 " + c + " words from " + file.name, "ok");
  };
  reader.onerror = () => setStatus("Failed to read " + file.name, "err");
  reader.readAsText(file);
}

function renderFuzzerShell() {
  plist.innerHTML = "";

  const bar = document.createElement("div");
  bar.className = "af-bar";

  const input = document.createElement("input");
  input.className = "af-url";
  input.spellcheck = false;
  input.placeholder = "target url  (put FUZZ where the wordlist goes \u2014 http://example.com/FUZZ  or  ?id=FUZZ)";
  input.value = fuzzState.target || "";
  input.addEventListener("input", () => (fuzzState.target = input.value));
  fuzzState.targetInput = input;

  const start = document.createElement("button");
  start.className = "btn go";
  start.textContent = "Start";
  start.disabled = fuzzState.running;
  start.addEventListener("click", fuzzScan);

  const stop = document.createElement("button");
  stop.className = "btn";
  stop.textContent = "Stop";
  stop.disabled = !fuzzState.running;
  stop.addEventListener("click", () => {
    fuzzState.abort = true;
    setStatus("Stopping\u2026", "warn");
  });

  const clear = document.createElement("button");
  clear.className = "btn ghost small";
  clear.textContent = "Clear";
  clear.addEventListener("click", () => {
    fuzzState.results = [];
    fuzzState.found = [];
    fuzzState.matched = [];
    fuzzState.done = 0;
    fuzzState.total = 0;
    setStatus("Fuzzer results cleared", "info");
    renderFuzzerShell();
  });

  const save = document.createElement("button");
  save.className = "btn ghost small";
  save.textContent = "Save found";
  save.disabled = !fuzzState.found.length;
  save.addEventListener("click", () => fuzzSave(fuzzState.found.map((f) => f.url)));

  bar.append(input, start, stop, clear, save);
  plist.appendChild(bar);

  // matcher row \u2014 optional keywords / regex to hunt for in responses
  const mBar = document.createElement("div");
  mBar.className = "af-bar af-mbar";
  const mLabel = document.createElement("span");
  mLabel.className = "af-mlabel";
  mLabel.textContent = "Match";
  mLabel.title = "Comma/newline separated keywords to find in the response body. Wrap one in /../ for regex. Hits are flagged \u2605 with a context snippet.";
  const matcher = document.createElement("input");
  matcher.className = "af-url af-match-input";
  matcher.spellcheck = false;
  matcher.placeholder = "match in response  (e.g.  root, admin, /\"user\":\"[^\"]+\"/)";
  matcher.value = fuzzState.matcher || "";
  matcher.addEventListener("input", () => (fuzzState.matcher = matcher.value));
  fuzzState.matcherInput = matcher;
  mBar.append(mLabel, matcher);
  plist.appendChild(mBar);

  const wlBar = document.createElement("div");
  wlBar.className = "af-wlbar";
  const wlToggle = document.createElement("button");
  wlToggle.className = "btn ghost small";
  wlToggle.textContent = "Wordlist";
  const wlLabel = document.createElement("span");
  wlLabel.className = "af-wllabel";
  const wlCount = (fuzzState.wordlist || "").split(/\r?\n/).filter((s) => s.trim()).length;
  wlLabel.textContent = wlCount + " words";
  const importWl = document.createElement("button");
  importWl.className = "btn ghost small";
  importWl.textContent = "Import file";
  importWl.title = "Load a custom wordlist from your filesystem (.txt, one word per line)";
  const wlFile = document.createElement("input");
  wlFile.type = "file";
  wlFile.accept = ".txt,.lst,.csv,text/plain";
  wlFile.style.display = "none";
  wlFile.addEventListener("change", () => fuzzLoadFile(wlFile, wlLabel, wl));

  const resetWl = document.createElement("button");
  resetWl.className = "btn ghost small";
  resetWl.textContent = "Reset";
  resetWl.addEventListener("click", () => {
    fuzzState.wordlist = ADMIN_PATHS.join("\n");
    renderFuzzerShell();
  });
  wlBar.append(wlToggle, wlLabel, importWl, resetWl);
  plist.appendChild(wlBar);
  plist.appendChild(wlFile);

  const wlWrap = document.createElement("div");
  wlWrap.className = "af-wlwrap hidden";
  const wl = document.createElement("textarea");
  wl.className = "af-wl";
  wl.spellcheck = false;
  wl.value = fuzzState.wordlist || "";
  wl.rows = 7;
  wl.addEventListener("input", () => {
    fuzzState.wordlist = wl.value;
    const c = wl.value.split(/\r?\n/).filter((s) => s.trim()).length;
    wlLabel.textContent = c + " words";
  });
  wlToggle.addEventListener("click", () => {
    wlWrap.classList.toggle("hidden");
    if (!wlWrap.classList.contains("hidden")) wl.focus();
  });
  importWl.addEventListener("click", () => {
    if (wlWrap.classList.contains("hidden")) wlWrap.classList.remove("hidden");
    wlFile.click();
  });
  fuzzState.wordlistEl = wl;
  wlWrap.appendChild(wl);
  plist.appendChild(wlWrap);

  const progWrap = document.createElement("div");
  progWrap.className = "af-progwrap";
  const prog = document.createElement("div");
  prog.className = "af-prog";
  const fill = document.createElement("div");
  fill.className = "af-prog-fill";
  const pct = fuzzState.total ? Math.round((fuzzState.done / fuzzState.total) * 100) : 0;
  fill.style.width = pct + "%";
  if (fuzzState.running) fill.classList.add("run");
  prog.appendChild(fill);
  const counter = document.createElement("span");
  counter.className = "af-counter";
  counter.textContent = fuzzState.total
    ? fuzzState.done + "/" + fuzzState.total + "  \u00b7  " + fuzzState.found.length + " found  \u00b7  " +
      fuzzState.matched.length + " matched  \u00b7  " +
      fuzzState.results.filter((r) => r.ok && r.status !== 404).length + " hits"
    : "put FUZZ in the target, load a wordlist, press Start";
  progWrap.append(prog, counter);
  fuzzState.fillEl = fill;
  fuzzState.counterEl = counter;
  plist.appendChild(progWrap);

  const rc = document.createElement("div");
  rc.className = "af-res-cap";
  rc.textContent = fuzzState.results.length ? "Responses \u2014 " + fuzzState.results.length : "Responses";
  plist.appendChild(rc);

  const labels = fuzzState.matcherLabels || [];
  const table = document.createElement("div");
  table.className = "af-table";

  // sticky header: URL | one column per match keyword | Size | Status
  const head = document.createElement("div");
  head.className = "af-thead";
  head.style.gridTemplateColumns = fuzzCols(labels);
  const hCells = ["URL"].concat(labels, ["Size", "Status", ""]);
  hCells.forEach((t) => {
    const c = document.createElement("span");
    c.textContent = t;
    head.appendChild(c);
  });
  table.appendChild(head);

  if (!fuzzState.results.length) {
    const e = document.createElement("div");
    e.className = "pempty";
    e.style.gridColumn = "1 / -1";
    e.textContent = "No scan yet \u2014 set a target and press Start.";
    table.appendChild(e);
  } else {
    fuzzState.results.slice().sort(fuzzCmp).forEach((r) => table.appendChild(fuzzResultRow(r, labels)));
  }
  fuzzState.resultsEl = table;
  plist.appendChild(table);
}

function fuzzAppendRow(r) {
  const table = fuzzState.resultsEl;
  if (!table) return;
  const empty = table.querySelector(".pempty");
  if (empty) empty.remove();
  const newRow = fuzzResultRow(r, fuzzState.matcherLabels || []);
  // insert in sorted order: before the first existing row that should come after r
  const rows = table.querySelectorAll(".af-trow");
  let inserted = false;
  for (const existing of rows) {
    if (existing._r && fuzzCmp(r, existing._r) < 0) {
      table.insertBefore(newRow, existing);
      inserted = true;
      break;
    }
  }
  if (!inserted) table.appendChild(newRow);
  if (fuzzState.fillEl) {
    const pct = fuzzState.total ? Math.round((fuzzState.done / fuzzState.total) * 100) : 0;
    fuzzState.fillEl.style.width = pct + "%";
  }
  if (fuzzState.counterEl) {
    const hits = fuzzState.results.filter((x) => x.ok && x.status !== 404).length;
    fuzzState.counterEl.textContent =
      fuzzState.done + "/" + fuzzState.total + "  \u00b7  " + fuzzState.found.length + " found  \u00b7  " +
      fuzzState.matched.length + " matched  \u00b7  " + hits + " hits";
  }
}

async function fuzzScan() {
  const targetRaw = (fuzzState.targetInput ? fuzzState.targetInput.value : fuzzState.target).trim();
  if (!targetRaw) {
    setStatus("Enter a target URL first", "err");
    return;
  }
  const wl = (fuzzState.wordlistEl ? fuzzState.wordlistEl.value : fuzzState.wordlist) || "";
  const words = wl.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  if (!words.length) {
    setStatus("Wordlist is empty", "err");
    return;
  }
  const matchers = fuzzParseMatchers(fuzzState.matcherInput ? fuzzState.matcherInput.value : fuzzState.matcher);

  // FUZZ token present \u2192 replace it per word; otherwise append words to base.
  const useFuzz = /FUZZ/.test(targetRaw);
  let base = targetRaw;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(base)) base = "http://" + base;
  if (!useFuzz) {
    const norm = fuzzNormalizeBase(base);
    if (!norm) { setStatus("Invalid target URL", "err"); return; }
    base = norm;
  }
  fuzzState.target = targetRaw;
  if (fuzzState.targetInput) fuzzState.targetInput.value = targetRaw;

  fuzzState.running = true;
  fuzzState.abort = false;
  fuzzState.results = [];
  fuzzState.found = [];
  fuzzState.matched = [];
  fuzzState.matcherLabels = matchers.map((m) => m.raw);
  fuzzState.total = words.length;
  fuzzState.done = 0;
  renderFuzzerShell();
  setStatus(
    "Fuzzing " + words.length + " word(s)" + (useFuzz ? " (FUZZ)" : " (append)") +
    (matchers.length ? " \u00b7 matching " + matchers.length + " term(s)" : "") + "\u2026",
    "info"
  );

  const queue = words.slice();
  const CONCURRENCY = 8;
  const needBody = matchers.length > 0;
  const worker = async () => {
    while (queue.length && !fuzzState.abort) {
      const word = queue.shift();
      let url;
      if (useFuzz) {
        url = base.split("FUZZ").join(word);
      } else {
        url = base + (word.startsWith("/") ? word : "/" + word);
      }
      let status = 0;
      let ok = false;
      let redir = false;
      let matchInfo = null;
      let size = -1;
      const allow = !nrdBlocked(url);
      const redirectMode = (noRedirect || !allow) ? "manual" : "follow";
      try {
        const res = await fetch(url, { method: "GET", redirect: redirectMode, credentials: "omit", cache: "no-store" });
        if (res.type === "opaqueredirect") { redir = true; status = 0; ok = true; }
        else { status = res.status; ok = true; if (status >= 300 && status < 400) redir = true; }
        const cl = res.headers.get("content-length");
        if (cl) { const n = parseInt(cl, 10); if (!isNaN(n)) size = n; }
        if (needBody && ok && status !== 204 && status !== 304) {
          try {
            const body = await res.text();
            size = body.length;
            matchInfo = fuzzRunMatchers(body, matchers);
          } catch (e) {}
        }
      } catch (e) {
        status = 0;
      }
      fuzzState.done++;
      const r = {
        url, word, status, ok, redir, size,
        hits: matchInfo ? matchInfo.hits : null,
        snippet: matchInfo ? matchInfo.snippet : "",
      };
      fuzzState.results.push(r);
      if (ok && status === 200) fuzzState.found.push(r);
      if (matchInfo) fuzzState.matched.push(r);
      fuzzAppendRow(r);
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  fuzzState.running = false;
  const hits = fuzzState.results.filter((r) => r.ok && r.status !== 404).length;
  if (fuzzState.abort) setStatus("Stopped \u2014 " + fuzzState.done + "/" + fuzzState.total + " done", "warn");
  else setStatus(
    "Done \u2014 " + fuzzState.found.length + " found, " + fuzzState.matched.length + " matched, " + hits + " hits",
    (fuzzState.found.length || fuzzState.matched.length) ? "ok" : "info"
  );
  renderFuzzerShell();
}

/* ---------- CUSTOM PAYLOADS (user library) ----------
   A dynamic category where the user saves their own DIOS / queries /
   payloads for later reuse. Persisted in chrome.storage.local under
   "customPayloads". Items are grouped (auto-detected or user-named),
   and can be inserted, copied, edited and deleted. */
let customPayloads = [];     // [{id, name, payload, group, created, used}]
let custEditingId = null;    // id being edited (null = adding new)
let custBulkMode = false;    // bulk-add: blank-line separated blocks
let custAdding = false;      // form view open
let custActiveGroup = null;  // selected group in the sidebar
const custEls = {};

function custSave() { chrome.storage.local.set({ customPayloads }); }

function custLoad(cb) {
  chrome.storage.local.get(["customPayloads"], (r) => {
    customPayloads = Array.isArray(r && r.customPayloads) ? r.customPayloads : [];
    if (cb) cb();
  });
}

function initCustom() {
  custLoad(() => { if (activeCat === "Custom") renderCustom(); });
}

// Smart group detection — suggests a category from payload content.
function custSmartGroup(p) {
  const s = (p || "").toLowerCase();
  if (!s.trim()) return "General";
  if (/union[\s/*]+select|group_concat|information_schema|@@version|version\(\)|current_user\(\)|database\(\)|\bdios\b|load_file|into\s+outfile|0x[0-9a-f]{6}|concat_ws|make_set/.test(s)) return "SQLi";
  if (/'[\s]*or[\s]+'?1'?='?1|or[\s]+1=1|admin'--|admin'#|or[\s]+''='|or[\s]+true--|'or'1=1/.test(s)) return "Auth Bypass";
  if (/<[\/]?(script|svg|img|iframe|details|body|input|video|audio|marquee|math|embed|object|a|form|style|meta|link|keygen)\b|onerror|onload|onfocus|ontoggle|onpointer|alert\(|prompt\(|confirm\(|javascript:|srcdoc|fromcharcode/.test(s)) return "XSS";
  if (/\.\.[\/\\]|etc\/passwd|etc\/shadow|win\.ini|boot\.ini|php:\/\/|file:\/\/|expect:\/\/|data:\/\/|phar:\/\/|zip:\/\/|\.\.;\/|proc\/self/.test(s)) return "LFI";
  if (/169\.254\.169\.254|metadata\.google|gopher:\/\/|dict:\/\/|127\.0\.0\.1|\[::1\]|localhost|0x7f000001|imds|169\.254\.170\.2|100\.100\.100\.200/.test(s)) return "SSRF";
  if (/<!entity|<!doctype|system\s+"file:|xml\s+version|&\w+;/.test(s)) return "XXE";
  if (/(;|\||&&|\|\|)\s*(cat|id|whoami|ls|nc|wget|curl|uname|ping|nslookup)\b|\/bin\/(ba)?sh|nc\s+-e|\$\(|`[^`]+`/.test(s)) return "CMDi";
  if (/\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|<%=?.*?%>|\*\{.*?\}|\[\[\$\{.*?\}\]\]|#set\s*\(|_self\.env|registerUndefinedFilterCallback|__globals__|__mro__|__builtins__|getClass\(\)\.forName|getRuntime|ProcessBuilder|freemarker\.template/.test(s)) return "SSTI";
  if (/^[a-z0-9+\/\s]+={0,2}$/i.test(s.trim()) && s.trim().replace(/\s/g, "").length % 4 === 0 && s.trim().length >= 12) return "Encoded";
  if (/^[0-9a-f\s]+$/i.test(s.trim()) && s.trim().replace(/\s/g, "").length % 2 === 0 && s.trim().length >= 4) return "Hex";
  return "General";
}

// Smart name — derive a short label from the payload when none is given.
function custSmartName(p) {
  const s = (p || "").replace(/\s+/g, " ").trim();
  if (!s) return "untitled";
  if (s.length <= 36) return s;
  return s.slice(0, 33) + "\u2026";
}

function custGroups() {
  const map = {};
  customPayloads.forEach((it) => { (map[it.group] = map[it.group] || []).push(it); });
  return Object.keys(map).sort().map((g) => ({ group: g, items: map[g] }));
}

function custUse(it) {
  it.used = (it.used || 0) + 1;
  it.touched = Date.now();
  custSave();
}

function custRefreshSmart() {
  if (!custEls.smart) return;
  const p = custEls.payload ? custEls.payload.value : "";
  custEls.smart.textContent = p.trim() ? "auto: " + custSmartGroup(p) : "auto-group";
}

function custResetForm() {
  custEditingId = null;
  if (custEls.name) custEls.name.value = "";
  if (custEls.group) { custEls.group.value = ""; custEls.group.dataset.touched = ""; }
  if (custEls.payload) custEls.payload.value = "";
  if (custEls.addBtn) custEls.addBtn.textContent = "Add";
  if (custEls.cancelBtn) custEls.cancelBtn.classList.add("hidden");
  custRefreshSmart();
}

function custStartEdit(id) {
  const it = customPayloads.find((x) => x.id === id);
  if (!it) return;
  custEditingId = id;
  custAdding = false;
  custActiveGroup = it.group;
  renderCustSubcats();
  renderCustItems();
  if (custEls.payload) custEls.payload.focus();
  plist.scrollTop = 0;
}

function custDelete(id) {
  const idx = customPayloads.findIndex((x) => x.id === id);
  if (idx < 0) return;
  const removed = customPayloads.splice(idx, 1)[0];
  custResetForm();
  custSave();
  setStatus("Deleted " + (removed.name || "payload"), "warn");
  renderCustom();
}

function custAddOrUpdate() {
  const name = (custEls.name ? custEls.name.value : "").trim();
  const groupInput = (custEls.group ? custEls.group.value : "").trim();
  const payload = custEls.payload ? custEls.payload.value : "";
  if (!payload.trim()) { setStatus("Payload is empty", "err"); return; }
  if (custBulkMode && custEditingId == null) { custBulkAdd(groupInput); return; }
  const group = groupInput || custSmartGroup(payload);
  const finalName = name || custSmartName(payload);
  if (custEditingId != null) {
    const it = customPayloads.find((x) => x.id === custEditingId);
    if (it) { it.name = finalName; it.group = group; it.payload = payload; }
    setStatus("Updated " + finalName, "ok");
  } else {
    customPayloads.push({ id: Date.now() + Math.random(), name: finalName, group, payload, created: Date.now(), used: 0 });
    setStatus("Saved " + finalName, "ok");
  }
  custEditingId = null;
  custAdding = false;
  custActiveGroup = group;
  custSave();
  renderCustom();
}

// Bulk add: blocks separated by a blank line; an optional leading
// "# name" line names the block; the rest is the payload.
function custBulkAdd(forceGroup) {
  const raw = custEls.payload ? custEls.payload.value : "";
  const blocks = raw.split(/\n\s*\n/).map((b) => b.replace(/^\n+|\n+$/g, "")).filter(Boolean);
  let n = 0;
  let firstGroup = null;
  blocks.forEach((block, i) => {
    let name = "";
    let payload = block;
    const lines = block.split("\n");
    if (lines.length && /^\s*#\s+/.test(lines[0])) {
      name = lines[0].replace(/^\s*#\s+/, "").trim();
      payload = lines.slice(1).join("\n").trim();
    }
    if (!payload) return;
    const group = forceGroup && forceGroup.trim() ? forceGroup.trim() : custSmartGroup(payload);
    if (!firstGroup) firstGroup = group;
    customPayloads.push({
      id: Date.now() + Math.random() + i,
      name: name || custSmartName(payload),
      group,
      payload,
      created: Date.now(),
      used: 0,
    });
    n++;
  });
  if (n) {
    custSave();
    custAdding = false;
    custBulkMode = false;
    custEditingId = null;
    custActiveGroup = firstGroup;
    setStatus("Imported " + n + " payload(s)", "ok");
  } else {
    setStatus("No blocks found \u2014 separate payloads with a blank line", "err");
  }
  renderCustom();
}

function custExport() {
  if (!customPayloads.length) { setStatus("Nothing to export", "warn"); return; }
  const blob = new Blob([JSON.stringify(customPayloads, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "hackbar-custom-payloads.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  setStatus("Exported " + customPayloads.length + " payload(s)", "ok");
}

function custImportFile(input) {
  const file = input.files && input.files[0];
  input.value = "";
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) { setStatus("File too large (>2 MB)", "err"); return; }
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(String(reader.result || ""));
      const arr = Array.isArray(data) ? data : (Array.isArray(data.customPayloads) ? data.customPayloads : null);
      if (!arr) throw new Error("bad format");
      let n = 0;
      arr.forEach((raw) => {
        if (!raw || typeof raw !== "object") return;
        const payload = typeof raw.payload === "string" ? raw.payload : (typeof raw.value === "string" ? raw.value : "");
        if (!payload.trim()) return;
        customPayloads.push({
          id: Date.now() + Math.random() + n,
          name: String(raw.name || custSmartName(payload)),
          group: String(raw.group || raw.tag || custSmartGroup(payload)),
          payload,
          created: raw.created || Date.now(),
          used: raw.used || 0,
        });
        n++;
      });
      custSave();
      setStatus("Imported " + n + " payload(s) from " + file.name, "ok");
      renderCustom();
    } catch (e) {
      setStatus("Import failed: " + e.message, "err");
    }
  };
  reader.onerror = () => setStatus("Failed to read " + file.name, "err");
  reader.readAsText(file);
}

function custClearAll() {
  if (!customPayloads.length) return;
  if (!window.confirm("Delete ALL custom payloads? This cannot be undone.")) return;
  customPayloads = [];
  custActiveGroup = null;
  custAdding = false;
  custEditingId = null;
  custSave();
  setStatus("All custom payloads deleted", "warn");
  renderCustom();
}

function custRow(it) {
  const row = document.createElement("div");
  row.className = "pitem";
  row.title = it.payload;

  const nm = document.createElement("span");
  nm.className = "nm";
  nm.textContent = it.name;
  row.appendChild(nm);

  const pl = document.createElement("span");
  pl.className = "pl";
  pl.textContent = it.payload.replace(/\s+/g, " ").trim();
  row.appendChild(pl);

  // hover-only management actions (edit / delete) — identical row shape
  // to the built-in categories when not hovering.
  const pact = document.createElement("span");
  pact.className = "pact";
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "p-edit";
  edit.title = "Edit";
  edit.textContent = "\u270e";
  edit.addEventListener("click", (e) => { e.stopPropagation(); custStartEdit(it.id); });
  const del = document.createElement("button");
  del.type = "button";
  del.className = "p-del";
  del.title = "Delete (click twice to confirm)";
  del.textContent = "\u2715";
  let armed = false;
  let timer = null;
  del.addEventListener("click", (e) => {
    e.stopPropagation();
    if (armed) { clearTimeout(timer); custDelete(it.id); return; }
    armed = true;
    del.textContent = "?";
    del.classList.add("armed");
    timer = setTimeout(() => { armed = false; del.textContent = "\u2715"; del.classList.remove("armed"); }, 2500);
  });
  pact.append(edit, del);
  row.appendChild(pact);

  row.addEventListener("click", () => {
    insertAtCursor(focused, it.payload);
    custUse(it);
    flash(row);
    setStatus("Inserted " + it.name, "ok");
  });

  return row;
}

function custSelectGroup(g) {
  custActiveGroup = g;
  custAdding = false;
  custEditingId = null;
  renderCustSubcats();
  renderCustItems();
}

function custOpenAdd() {
  custAdding = true;
  custEditingId = null;
  renderCustSubcats();
  renderCustItems();
  if (custEls.payload) custEls.payload.focus();
}

function custCloseForm() {
  custAdding = false;
  custEditingId = null;
  renderCustSubcats();
  renderCustItems();
}

function renderCustom() {
  const groups = custGroups();
  const stillValid = groups.some((g) => g.group === custActiveGroup);
  if (!stillValid) custActiveGroup = groups.length ? groups[0].group : null;
  renderCustSubcats();
  renderCustItems();
}

/* left sidebar: "Add" entry + group list + footer tools — same column the
   other categories use, so the layout matches XSS / SQL / Bypass. */
function renderCustSubcats() {
  subcats.style.display = "";
  subcats.innerHTML = "";

  const addRow = document.createElement("div");
  addRow.className = "scat cust-add" + (custAdding || custEditingId != null ? " active" : "");
  addRow.textContent = "\uff0b Add payload";
  addRow.title = "Add a new custom payload";
  addRow.addEventListener("click", custOpenAdd);
  subcats.appendChild(addRow);

  custGroups().forEach((g) => {
    const onGroup = g.group === custActiveGroup && !custAdding && custEditingId == null;
    const row = document.createElement("div");
    row.className = "scat" + (onGroup ? " active" : "");
    row.innerHTML = g.group + ' <span class="cnt">(' + g.items.length + ')</span>';
    row.addEventListener("click", () => custSelectGroup(g.group));
    subcats.appendChild(row);
  });

  const stat = document.createElement("div");
  stat.className = "cust-side-stat";
  stat.textContent = customPayloads.length + " saved";
  subcats.appendChild(stat);
}

/* right pane: either the focused add/edit form, or a .pitem list of the
   active group (search flattens across all groups). */
function renderCustItems() {
  plist.innerHTML = "";

  if (custAdding || custEditingId != null) {
    renderCustForm();
    return;
  }

  if (!customPayloads.length) {
    const e = document.createElement("div");
    e.className = "pempty";
    e.textContent = "No custom payloads yet \u2014 click \u201cAdd payload\u201d in the sidebar.";
    plist.appendChild(e);
    return;
  }

  const q = search.value.trim().toLowerCase();
  let items;
  if (q) {
    items = customPayloads.filter((it) =>
      (it.name || "").toLowerCase().includes(q) ||
      (it.payload || "").toLowerCase().includes(q) ||
      (it.group || "").toLowerCase().includes(q));
  } else {
    const g = custGroups().find((x) => x.group === custActiveGroup) || custGroups()[0];
    items = g ? g.items : [];
  }

  if (!items.length) {
    const e = document.createElement("div");
    e.className = "pempty";
    e.textContent = q ? "No custom payloads match your filter." : "This group is empty.";
    plist.appendChild(e);
    return;
  }
  items.forEach((it) => plist.appendChild(custRow(it)));
}

function renderCustForm() {
  const form = document.createElement("div");
  form.className = "cust-form";

  const head = document.createElement("div");
  head.className = "cust-head";
  const title = document.createElement("span");
  title.className = "cust-title";
  title.textContent = custEditingId != null
    ? "Edit payload"
    : (custBulkMode ? "Bulk add \u2014 blank line separates payloads" : "New custom payload");
  const smart = document.createElement("span");
  smart.className = "cust-smart";
  smart.textContent = "auto-group";
  head.append(title, smart);
  custEls.smart = smart;

  const grid = document.createElement("div");
  grid.className = "cust-grid";
  const nameI = document.createElement("input");
  nameI.className = "cust-in";
  nameI.spellcheck = false;
  nameI.placeholder = custBulkMode ? "(ignored in bulk \u2014 use '# name')" : "name (optional \u2192 auto-named)";
  const groupI = document.createElement("input");
  groupI.className = "cust-in cust-in-g";
  groupI.spellcheck = false;
  groupI.placeholder = "group (optional \u2192 auto-detected)";
  groupI.addEventListener("input", () => { groupI.dataset.touched = "1"; });
  const editingIt = custEditingId != null ? customPayloads.find((x) => x.id === custEditingId) : null;
  if (editingIt) {
    nameI.value = editingIt.name;
    groupI.value = editingIt.group;
    groupI.dataset.touched = "1";
  } else if (custActiveGroup) {
    groupI.value = custActiveGroup;
    groupI.dataset.touched = "1";
  }
  grid.append(nameI, groupI);
  custEls.name = nameI;
  custEls.group = groupI;

  const payloadTa = document.createElement("textarea");
  payloadTa.className = "cust-payload";
  payloadTa.spellcheck = false;
  payloadTa.rows = 4;
  payloadTa.placeholder = custBulkMode
    ? "# My DIOS name\nunion select 1,2,3,...\n\n# Another payload\n' or 1=1--"
    : "paste your DIOS / payload / query \u2026  (Ctrl+Enter to save)";
  if (editingIt) payloadTa.value = editingIt.payload;
  payloadTa.addEventListener("input", custRefreshSmart);
  payloadTa.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); custAddOrUpdate(); }
  });
  custEls.payload = payloadTa;

  const actions = document.createElement("div");
  actions.className = "cust-actions";
  const addBtn = document.createElement("button");
  addBtn.className = "btn go small";
  addBtn.type = "button";
  addBtn.textContent = custEditingId != null ? "Save" : "Add";
  addBtn.addEventListener("click", custAddOrUpdate);
  const bulkBtn = document.createElement("button");
  bulkBtn.className = "btn ghost small";
  bulkBtn.type = "button";
  bulkBtn.textContent = "Bulk " + (custBulkMode ? "\u25cf" : "\u25cb");
  bulkBtn.title = "Toggle bulk-add mode";
  bulkBtn.addEventListener("click", () => {
    const saved = { name: nameI.value, group: groupI.value, payload: payloadTa.value };
    custBulkMode = !custBulkMode;
    renderCustItems();
    if (custEls.name) custEls.name.value = saved.name;
    if (custEls.group) { custEls.group.value = saved.group; custEls.group.dataset.touched = saved.group ? "1" : ""; }
    if (custEls.payload) custEls.payload.value = saved.payload;
    custRefreshSmart();
  });
  const cancelBtn = document.createElement("button");
  cancelBtn.className = "btn ghost small";
  cancelBtn.type = "button";
  cancelBtn.textContent = "Cancel";
  cancelBtn.addEventListener("click", custCloseForm);
  actions.append(addBtn, bulkBtn, cancelBtn);
  custEls.addBtn = addBtn;
  custEls.cancelBtn = cancelBtn;

  form.append(head, grid, payloadTa, actions);
  plist.appendChild(form);
  custRefreshSmart();
}

function flash(el) {
  el.style.background = "var(--sel)";
  setTimeout(() => (el.style.background = ""), 180);
}

function insertAtCursor(ta, text) {
  const s = ta.selectionStart;
  const e = ta.selectionEnd;
  ta.value = ta.value.slice(0, s) + text + ta.value.slice(e);
  ta.selectionStart = ta.selectionEnd = s + text.length;
  ta.focus();
}

function runGenerator(it) {
  const raw = window.prompt(it.prompt || "Number of columns", it.def || "5");
  if (raw === null) return;
  const n = Math.max(1, Math.min(1000, parseInt(raw, 10) || 0));
  if (n < 1) {
    setStatus("Invalid column count", "err");
    return;
  }
  insertAtCursor(focused, it.gen(n));
  setStatus(`Inserted ${it.name} (${n} columns)`, "ok");
}

function applyTransform(fn) {
  const ta = focused;
  const s = ta.selectionStart;
  const e = ta.selectionEnd;
  const sel = ta.value.slice(s, e);
  const input = sel || ta.value;
  Promise.resolve(fn(input)).then((res) => {
    if (sel) {
      ta.value = ta.value.slice(0, s) + res + ta.value.slice(e);
      ta.selectionStart = s;
      ta.selectionEnd = s + res.length;
    } else {
      ta.value = res;
      ta.selectionStart = 0;
      ta.selectionEnd = res.length;
    }
    ta.focus();
  });
}

const $$ = (s, r = document) => [...r.querySelectorAll(s)];

search.addEventListener("input", () => {
  if (activeCat === "Extract") renderExtract();
  else if (activeCat === "Custom") { if (!(custAdding || custEditingId != null)) renderCustItems(); }
  else if (activeCat === "GAP") gapApplySearch(search.value);
  else if (activeCat === "Admin") return;
  else renderPlist();
});

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = "status" + (kind ? " " + kind : "");
}

/* ---------- LOAD / SPLIT / EXECUTE ---------- */
async function loadUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      urlField.value = tab.url;
      histPush(tab.url);
      setStatus("URL loaded", "info");
      urlField.focus();
    }
  } catch (e) {
    setStatus("Load failed: " + e.message, "err");
  }
}

function splitUrl() {
  const f = focused || urlField;
  if (!f.value) return setStatus("Nothing to split", "warn");
  f.value = f.value.replace(/&/g, "\n&").replace(/\?/g, "\n?");
  f.focus();
}

async function execute() {
  let target = (urlField.value || "").replace(/[\r\n]+/g, "").trim();
  if (!target) return setStatus("No URL to execute", "err");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) target = "http://" + target;
  histPush(target);

  let tab;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch (e) {
    return setStatus("Cannot access tab: " + e.message, "err");
  }
  if (!tab || typeof tab.id !== "number") return setStatus("No active tab", "err");

  await applyCookies(target);
  if (post.checked) await execPost(tab.id, target, body.value || "");
  else await execGet(tab.id, target);
}

/* ---------- NO REDIRECT ---------- */
async function probeRedirect(target) {
  try {
    const res = await fetch(target, { method: "GET", redirect: "manual", credentials: "include", cache: "no-store" });
    if (res.type === "opaqueredirect") return { redirect: true, status: 0, location: null };
    let location = null;
    try { location = res.headers.get("location"); } catch (e) {}
    if (res.status >= 300 && res.status < 400) return { redirect: true, status: res.status, location };
    return { redirect: false, status: res.status };
  } catch (e) {
    return { redirect: false, status: 0, error: e.message };
  }
}

function nrInterstitial(target, code, dest) {
  const mk = (tag, txt) => { const e = document.createElement(tag); if (txt != null) e.textContent = txt; return e; };
  document.open();
  document.write("<!doctype html><html><head><meta charset='utf-8'><title>NoRedirect</title></head><body><div id='nr-root'></div></body></html>");
  document.close();
  document.body.style.cssText = "margin:0;background:#0e1119;color:#cdd6f0;font:14px/1.6 'Segoe UI',Arial,sans-serif";
  const root = document.getElementById("nr-root");
  const box = mk("div"); box.style.cssText = "max-width:680px;margin:40px auto;padding:0 16px";
  const k = mk("div", "HACKBAR \u00b7 NOREDIRECT"); k.style.cssText = "color:#8b94ad;font-size:12px;letter-spacing:1px;text-transform:uppercase";
  const h = mk("h1", "Redirect blocked (HTTP " + code + ")"); h.style.cssText = "color:#fbbf24;font-size:20px;margin:4px 0 10px";
  const p = mk("p", "The server tried to redirect this request. Following was prevented by NoRedirect.");
  const kl = mk("div", "REQUESTED URL"); kl.style.cssText = "color:#8b94ad;font-size:12px;letter-spacing:1px;text-transform:uppercase;margin-top:14px";
  const u = mk("div", target); u.style.cssText = "font-family:Consolas,monospace;background:#161b29;border:1px solid #313b57;padding:10px 12px;border-radius:8px;word-break:break-all";
  box.append(k, h, p, kl, u);
  if (dest) {
    const kd = mk("div", "REDIRECT TARGET"); kd.style.cssText = "color:#8b94ad;font-size:12px;letter-spacing:1px;text-transform:uppercase;margin-top:12px";
    const ud = mk("div", dest); ud.style.cssText = "font-family:Consolas,monospace;background:#161b29;border:1px solid #313b57;padding:10px 12px;border-radius:8px;word-break:break-all;color:#4ade80";
    const a = mk("a", "follow it anyway \u2192"); a.href = dest; a.style.cssText = "color:#7c93ff;display:inline-block;margin-top:12px";
    box.append(kd, ud, a);
  } else {
    const nr = mk("div", "redirect target not readable (cross-origin)"); nr.style.cssText = "font-family:Consolas,monospace;background:#161b29;border:1px solid #313b57;padding:10px 12px;border-radius:8px;color:#7c93ff;margin-top:8px";
    box.append(nr);
  }
  const tip = mk("p", "Toggle NoRedirect off in the HackBar to follow redirects normally."); tip.style.cssText = "color:#525d78;font-size:12px;margin-top:18px";
  box.append(tip);
  root.appendChild(box);
}

async function showNoRedirectInterstitial(tabId, target, info) {
  const code = info.status || "3xx";
  let dest = info.location || "";
  if (dest) { try { dest = new URL(dest, target).href; } catch (e) {} }
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: nrInterstitial,
      args: [target, String(code), dest],
    });
  } catch (e) {}
}

function nrdClientGuard() {
  try {
    var stop = function () {
      try { console.warn("[HackBar NoRedirect] client-side redirect blocked"); } catch (e) {}
    };
    var proto = window.Location && window.Location.prototype;
    if (proto) {
      ["assign", "replace"].forEach(function (m) { try { proto[m] = stop; } catch (e) {} });
      try {
        var d = Object.getOwnPropertyDescriptor(proto, "href");
        if (d && d.set) Object.defineProperty(proto, "href", { get: d.get, set: stop, configurable: true });
      } catch (e) {}
    }
    try { window.open = function () { return null; }; } catch (e) {}
    var strip = function () {
      try {
        document.querySelectorAll('meta[http-equiv]').forEach(function (m) {
          if (/^\s*refresh\s*$/i.test(m.getAttribute("http-equiv") || "")) m.remove();
        });
      } catch (e) {}
    };
    strip();
    try {
      var obs = new MutationObserver(strip);
      if (document.documentElement) obs.observe(document.documentElement, { childList: true, subtree: true });
    } catch (e) {}
  } catch (e) {}
}
function injectRedirectGuard(tabId) {
  chrome.scripting.executeScript({
    target: { tabId, allFrames: true },
    world: "MAIN",
    injectImmediately: true,
    func: nrdClientGuard,
  }).catch(() => {});
}

async function execGet(tabId, target) {
  const blocked = nrdBlocked(target);
  if (noRedirect || blocked) {
    const src = blocked ? "Block-list" : "NoRedirect";
    setStatus(src + ": probing " + target + " …", "info");
    const info = await probeRedirect(target);
    if (info.redirect) {
      await showNoRedirectInterstitial(tabId, target, info);
      let dest = info.location || "";
      if (dest) { try { dest = new URL(dest, target).href; } catch (e) {} }
      setStatus(src + " \u2192 " + target + (dest ? "  \u21d2  " + dest : "") + "  (" + (info.status || "3xx") + ")", "warn");
      return;
    }
    try {
      await chrome.tabs.update(tabId, { url: target });
      injectRedirectGuard(tabId);
      setStatus("GET \u2192 " + target + "  (redirects blocked)", "ok");
    } catch (e) {
      setStatus("Error: " + e.message, "err");
    }
    return;
  }
  try {
    await chrome.tabs.update(tabId, { url: target });
    setStatus("GET \u2192 " + target, "ok");
  } catch (e) {
    setStatus("Error: " + e.message, "err");
  }
}

async function execPost(tabId, target, postData) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: submitPostForm,
      args: [target, postData],
    });
    setStatus("POST → " + target, "ok");
  } catch (e) {
    setStatus("POST failed: " + e.message, "err");
  }
}

function submitPostForm(target, postData) {
  const form = document.createElement("form");
  form.method = "POST";
  form.action = target;
  form.enctype = "application/x-www-form-urlencoded";
  form.style.display = "none";
  if (postData && postData.trim()) {
    postData.split("&").forEach((pair) => {
      if (!pair) return;
      const i = pair.indexOf("=");
      const k = i === -1 ? pair : pair.slice(0, i);
      const v = i === -1 ? "" : pair.slice(i + 1);
      const inp = document.createElement("input");
      inp.type = "hidden";
      inp.name = decodeURIComponent(k.replace(/\+/g, " "));
      inp.value = decodeURIComponent(v.replace(/\+/g, " "));
      form.appendChild(inp);
    });
  }
  document.body.appendChild(form);
  form.submit();
}

async function applyCookies(target) {
  if (!cookie.checked || !ck.value.trim()) return;
  let u;
  try {
    u = new URL(target);
  } catch (e) {
    return;
  }
  for (const part of ck.value.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (!name) continue;
    try {
      await chrome.cookies.set({ url: target, name, value, path: "/", secure: u.protocol === "https:" });
    } catch (e) {
      setStatus("Cookie failed: " + e.message, "warn");
    }
  }
}

$("#btn-load").addEventListener("click", loadUrl);
$("#btn-split").addEventListener("click", splitUrl);
$("#btn-exec").addEventListener("click", execute);
if (btnBack) btnBack.addEventListener("click", () => histGo(-1));
if (btnFwd) btnFwd.addEventListener("click", () => histGo(1));
if (btnInc) btnInc.addEventListener("click", () => bumpNumber(1));
if (btnDec) btnDec.addEventListener("click", () => bumpNumber(-1));

function setNoRedirect(v) {
  noRedirect = !!v;
  nrd.classList.toggle("on", noRedirect);
  chrome.storage.local.set({ noRedirect });
}
nrd.addEventListener("click", () => {
  setNoRedirect(!noRedirect);
  setStatus("NoRedirect " + (noRedirect ? "ON \u2014 redirects will be blocked" : "off"), noRedirect ? "warn" : "info");
});

function nrdBlockCount() {
  return (nrdBlockState || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean).length;
}
function nrdBlocked(target) {
  if (!nrdBlockState) return false;
  const t = (target || "").toLowerCase();
  for (const raw of nrdBlockState.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (line.length >= 2 && line.startsWith("/") && line.lastIndexOf("/") > 0) {
      const last = line.lastIndexOf("/");
      try { if (new RegExp(line.slice(1, last), line.slice(last + 1)).test(target)) return true; } catch (e) {}
      continue;
    }
    if (t.includes(line.toLowerCase())) return true;
  }
  return false;
}
let nrdWriteTimer = null;
function setNrdBlock(v) {
  nrdBlockState = v || "";
  if (nrdCnt) nrdCnt.textContent = String(nrdBlockCount());
  clearTimeout(nrdWriteTimer);
  nrdWriteTimer = setTimeout(() => chrome.storage.local.set({ nrdBlock: nrdBlockState }), 350);
}
function toggleNrdPop(force) {
  const show = force != null ? force : nrdPop.classList.contains("hidden");
  nrdPop.classList.toggle("hidden", !show);
  if (show && nrdBlockEl) nrdBlockEl.focus();
}
nrdEdit.addEventListener("click", (e) => { e.stopPropagation(); toggleNrdPop(); });
$("#nrd-close").addEventListener("click", () => toggleNrdPop(false));
nrdBlockEl.addEventListener("input", () => setNrdBlock(nrdBlockEl.value));
document.addEventListener("click", (e) => {
  if (nrdPop.classList.contains("hidden")) return;
  if (nrdPop.contains(e.target) || e.target === nrdEdit) return;
  toggleNrdPop(false);
});

function initNoRedirect() {
  chrome.storage.local.get(["noRedirect", "nrdBlock"], (r) => {
    if (r && r.noRedirect) {
      noRedirect = true;
      nrd.classList.add("on");
      setStatus("NoRedirect ON", "warn");
    }
    nrdBlockState = (r && r.nrdBlock) || "";
    if (nrdBlockEl) nrdBlockEl.value = nrdBlockState;
    if (nrdCnt) nrdCnt.textContent = String(nrdBlockCount());
  });
}

/* ---------- GHOULSIGHT (XSS scanner) ---------- */
function gsApplyOn() { if (gs) gs.classList.toggle("on", gsScanning); }

function gsLoadSettings() {
  chrome.storage.local.get(["gs_apiKey", "gs_serverUrl", "gs_headers", "gs_collectCookies", "gs_followLinks", "gs_activeCrawl", "gs_isScanning"], (r) => {
    gsSettings.apiKey = (r && r.gs_apiKey) || "";
    gsSettings.serverUrl = (r && r.gs_serverUrl) || "";
    gsSettings.headers = (r && r.gs_headers) || "";
    gsSettings.collectCookies = !!(r && r.gs_collectCookies);
    gsSettings.followLinks = r && r.gs_followLinks != null ? !!r.gs_followLinks : true;
    gsSettings.activeCrawl = !!(r && r.gs_activeCrawl);
    if (gsApikey) gsApikey.value = gsSettings.apiKey;
    if (gsServer) gsServer.value = gsSettings.serverUrl;
    if (gsHeaders) gsHeaders.value = gsSettings.headers;
    if (gsCookies) gsCookies.checked = gsSettings.collectCookies;
    if (gsFollow) gsFollow.checked = gsSettings.followLinks;
    if (gsCrawl) gsCrawl.checked = gsSettings.activeCrawl;
    // reflect a still-running background scan in the UI
    if (r && r.gs_isScanning) {
      gsScanning = true;
      gsApplyOn();
      gsStartPolling(); // resume live stats updates
    } else {
      gsResetSummary();
    }
  });
}

let gsSaveDebounce = null;
function gsPersistSettings(announce) {
  clearTimeout(gsSaveDebounce);
  gsSaveDebounce = setTimeout(() => {
    chrome.storage.local.set({
      gs_apiKey: gsSettings.apiKey,
      gs_serverUrl: gsSettings.serverUrl,
      gs_headers: gsSettings.headers,
      gs_collectCookies: gsSettings.collectCookies,
      gs_followLinks: gsSettings.followLinks,
      gs_activeCrawl: gsSettings.activeCrawl,
    });
    // notify the background scanner about header/config changes
    chrome.runtime.sendMessage({
      action: "gs_settingsUpdated",
      apiKey: gsSettings.apiKey,
      serverUrl: gsSettings.serverUrl,
      headers: gsSettings.headers,
    }).catch(() => {});
    if (announce && gsSaveMsg) {
      gsSaveMsg.textContent = "✓ saved";
      setTimeout(() => { if (gsSaveMsg) gsSaveMsg.textContent = "settings saved automatically"; }, 1600);
    }
  }, 300);
}

async function gsToggle() {
  if (gsScanning) {
    chrome.runtime.sendMessage({ action: "gs_stopScan" }).catch(() => {});
    gsScanning = false;
    gsApplyOn();
    gsStopPolling();
    gsResetSummary();
    setStatus("GhoulSight OFF", "info");
    return;
  }
  // starting — validate config
  if (!gsSettings.apiKey || !gsSettings.serverUrl) {
    setStatus("Set GhoulSight API key + server URL first (☰)", "err");
    if (!nrdPop.classList.contains("hidden")) { /* keep open */ } else { toggleNrdPop(true); }
    switchGsPane(true);
    return;
  }
  let tab;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch (e) {
    setStatus("Cannot access tab: " + e.message, "err");
    return;
  }
  if (!tab || !tab.url || !/^https?:/i.test(tab.url)) {
    setStatus("Open a http(s) page to scan", "err");
    return;
  }
  chrome.runtime.sendMessage({
    action: "gs_startScan",
    tabId: tab.id,
    url: tab.url,
    collectCookies: gsSettings.collectCookies,
    followLinks: gsSettings.followLinks,
    activeCrawl: gsSettings.activeCrawl,
    apiKey: gsSettings.apiKey,
    serverUrl: gsSettings.serverUrl,
    headers: gsSettings.headers,
  }, () => {
    gsScanning = true;
    gsApplyOn();
    gsResetSummary();
    gsStartPolling();
    setStatus("GhoulSight scanning " + new URL(tab.url).hostname + "…", "ok");
  });
}

/* ---------- GhoulSight stats polling (reliable cross-context via storage) ---------- */
let gsPollTimer = null;

// apply a stats snapshot to the summary strip
function gsApplyStats(s) {
  s = s || {};
  const setN = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = String(n || 0); };
  setN("gs-s-sent", s.sent);
  setN("gs-s-jobs", s.jobs);
  setN("gs-s-dedup", s.deduped);
  setN("gs-s-poc", s.poc);
  const sm = document.getElementById("gs-summary");
  if (sm) sm.classList.toggle("on", gsScanning);
}

function gsResetSummary() {
  gsApplyStats({ sent: 0, jobs: 0, deduped: 0, poc: 0 });
}

// read stats from storage (reliable) + ask the scanner for a fresh snapshot
function gsPullStats() {
  chrome.storage.local.get(["gs_stats"], (r) => {
    if (r && r.gs_stats) gsApplyStats(r.gs_stats);
  });
  // also ask the live scanner directly — covers the gap before the next
  // throttled storage write lands
  chrome.runtime.sendMessage({ action: "gs_getStats" }, (resp) => {
    if (chrome.runtime.lastError) return; // scanner may be asleep; storage covers us
    if (resp && resp.stats) gsApplyStats(resp.stats);
  }).catch(() => {});
}

function gsStartPolling() {
  gsStopPolling();
  gsPullStats();
  gsPollTimer = setInterval(gsPullStats, 1000); // 1s while scanning
}

function gsStopPolling() {
  if (gsPollTimer) { clearInterval(gsPollTimer); gsPollTimer = null; }
}

// react to storage changes immediately too (covers background-driven updates)
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.gs_stats) return;
  if (gsScanning) gsApplyStats(changes.gs_stats.newValue);
});

// popover tab switching
function switchGsPane(showGs) {
  if (showGs) {
    tabGs.classList.add("active"); tabNrd.classList.remove("active");
    paneGs.classList.remove("hidden"); paneNrd.classList.add("hidden");
  } else {
    tabNrd.classList.add("active"); tabGs.classList.remove("active");
    paneNrd.classList.remove("hidden"); paneGs.classList.add("hidden");
  }
}

// wire up the GhoulSight UI
if (gs) gs.addEventListener("click", gsToggle);
if (tabNrd) tabNrd.addEventListener("click", () => switchGsPane(false));
if (tabGs) tabGs.addEventListener("click", () => switchGsPane(true));
if (gsApikey) gsApikey.addEventListener("input", () => { gsSettings.apiKey = gsApikey.value.trim(); gsPersistSettings(false); });
if (gsServer) gsServer.addEventListener("input", () => { gsSettings.serverUrl = gsServer.value.trim(); gsPersistSettings(false); });
if (gsHeaders) gsHeaders.addEventListener("input", () => { gsSettings.headers = gsHeaders.value; gsPersistSettings(false); });
if (gsCookies) gsCookies.addEventListener("change", () => { gsSettings.collectCookies = gsCookies.checked; gsPersistSettings(true); });
if (gsFollow) gsFollow.addEventListener("change", () => { gsSettings.followLinks = gsFollow.checked; gsPersistSettings(true); });
if (gsCrawl) gsCrawl.addEventListener("change", () => { gsSettings.activeCrawl = gsCrawl.checked; gsPersistSettings(true); });
if (gsSave) gsSave.addEventListener("click", () => {
  gsSettings.apiKey = (gsApikey ? gsApikey.value : "").trim();
  gsSettings.serverUrl = (gsServer ? gsServer.value : "").trim();
  gsSettings.headers = gsHeaders ? gsHeaders.value : "";
  gsSettings.collectCookies = gsCookies ? gsCookies.checked : false;
  gsSettings.followLinks = gsFollow ? gsFollow.checked : true;
  gsSettings.activeCrawl = gsCrawl ? gsCrawl.checked : false;
  gsPersistSettings(true);
  setStatus("GhoulSight settings saved", "ok");
});

// live status / vuln callbacks from the background scanner
chrome.runtime.onMessage.addListener((message) => {
  if (!message || typeof message.action !== "string") return;
  if (message.action === "gs_updateStatus") {
    if (gsScanning && message.status && !/passive crawling|active crawl/i.test(message.status)) {
      setStatus("GhoulSight: " + message.status, "info");
    }
  } else if (message.action === "gs_vulnerabilityFound") {
    const v = message.vulnerability || {};
    setStatus("GhoulSight found XSS on " + (v.parameter || "?") + " — popup opened", "ok");
    gsApplyStats({ poc: (parseInt(document.getElementById("gs-s-poc")?.textContent, 10) || 0) + 1 });
  } else if (message.action === "gs_stats") {
    // best-effort push; the storage poll is authoritative but this covers gaps
    if (gsScanning && message.stats) gsApplyStats(message.stats);
  }
});

gsResetSummary();
gsLoadSettings();


const URL_STEP = 44;
const URL_MIN = 60;
function resizeUrl(delta) {
  const el = urlField;
  const cur = el.clientHeight || 84;
  const max = Math.max(URL_MIN + URL_STEP, Math.floor(window.innerHeight * 0.8));
  const h = Math.max(URL_MIN, Math.min(max, cur + delta));
  el.style.height = h + "px";
}
$("#url-up").addEventListener("click", () => resizeUrl(URL_STEP));
$("#url-dn").addEventListener("click", () => resizeUrl(-URL_STEP));

post.addEventListener("change", () => {
  postWrap.classList.toggle("hidden", !post.checked);
  if (post.checked) body.focus();
});
cookie.addEventListener("change", () => {
  cookieWrap.classList.toggle("hidden", !cookie.checked);
  if (cookie.checked) ck.focus();
});

document.addEventListener("keydown", (e) => {
  const t = e.target;
  const typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA");
  if (e.altKey && !e.ctrlKey && !e.metaKey) {
    const k = e.key.toLowerCase();
    if (k === "a") { e.preventDefault(); loadUrl(); }
    else if (k === "s" && !typing) { e.preventDefault(); splitUrl(); }
    else if (k === "x" && !typing) { e.preventDefault(); execute(); }
    else if (k === "r" && e.shiftKey) { e.preventDefault(); toggleNrdPop(); }
    else if (k === "r") { e.preventDefault(); nrd.click(); }
    else if (k === "g") { e.preventDefault(); gs.click(); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); histGo(-1); }
    else if (e.key === "ArrowRight") { e.preventDefault(); histGo(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); bumpNumber(1); }
    else if (e.key === "ArrowDown") { e.preventDefault(); bumpNumber(-1); }
  }
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    e.preventDefault();
    execute();
  }
});

buildCattabs();
buildQuick();
selectCat("SQL");
urlField.style.height = "84px";
initNoRedirect();
initCustom();
setStatus("Ready", "info");
