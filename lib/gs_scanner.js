/*
 * GhoulSight XSS scanner — merged into HackBar's background service worker.
 * Ported from ghoulsight/background.js. All message actions and storage keys
 * are namespaced with the "gs_" prefix so they cannot collide with HackBar's
 * own logic (which uses noRedirect, nrdBlock, etc.).
 *
 * Lifecycle:
 *   panel toggles the scanner on/off  ->  gs_startScan / gs_stopScan messages
 *   content script reports pages      ->  gs_contentScanComplete / gs_newPageLoaded
 *   found vulns are POSTed to the user's GhoulSight server and, on a PoC
 *   callback, a result popup window is opened.
 */

// ---- module state (reset per scan) -----------------------------------------
let gsIsScanning = false;
let gsCurrentScanId = null;
let gsPendingRequests = new Map();
let gsRequestQueue = [];
let gsActiveRequests = 0;
const GS_MAX_CONCURRENT = 3;

const gsScanData = { urls: new Set(), parameters: new Set(), forms: new Set(), vulnerabilities: [] };

// dedup sets
let gsScannedUrls = new Set();
let gsScannedForms = new Set();

// live scan statistics, broadcast to the side panel for the summary strip
const gsStats = { sent: 0, jobs: 0, poc: 0, deduped: 0, queued: 0 };

let gsCurrentDomain = "";
let gsApiKey = "";
let gsServerUrl = "";
let gsHeaders = "";
let gsCollectCookies = false;
let gsActiveCrawl = false;
let gsCrawlQueue = [];
let gsProcessingCrawl = false;
let gsCapturedHeaders = new Map();

// ---- helpers ---------------------------------------------------------------
function gsLog(...a) { /* silent by default; uncomment to debug: console.log("[GhoulSight]", ...a); */ }

function gsSaveScanData() {
  chrome.storage.local.set({
    gs_scanData: {
      urls: Array.from(gsScanData.urls),
      parameters: Array.from(gsScanData.parameters),
      forms: Array.from(gsScanData.forms),
      vulnerabilities: gsScanData.vulnerabilities,
    },
  });
}

function gsBroadcast(message) {
  // fan out to any open side panel / popup views
  chrome.runtime.sendMessage(message).catch(() => {});
}

// push the current stats snapshot to the side panel's summary strip.
// We use TWO channels because MV3 sendMessage from the service worker to the
// side panel is lossy under high frequency:
//   1. best-effort gs_stats message (immediate but may drop)
//   2. throttled write to chrome.storage.local (reliable; panel polls this)
let gsStatsTimer = null;
function gsPersistStats() {
  if (gsStatsTimer) return; // a write is already scheduled — coalesce
  gsStatsTimer = setTimeout(() => {
    gsStatsTimer = null;
    chrome.storage.local.set({ gs_stats: { ...gsStats, ts: Date.now() } }).catch(() => {});
  }, 400);
}

function gsBroadcastStats() {
  gsStats.queued = gsRequestQueue.length + gsActiveRequests;
  gsBroadcast({ action: "gs_stats", stats: { ...gsStats } }); // best-effort push
  gsPersistStats();                                          // reliable storage write
}

// ---- message router --------------------------------------------------------
export function initGsScanner() {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || typeof message.action !== "string" || !message.action.startsWith("gs_")) {
      return false; // not ours
    }
    switch (message.action) {
      case "gs_getStats":
        // panel requests an immediate snapshot (used on toggle + each poll)
        gsStats.queued = gsRequestQueue.length + gsActiveRequests;
        sendResponse({ stats: { ...gsStats } });
        return false;

      case "gs_startScan":
        gsStartScan(message).then(() => sendResponse({ success: true })).catch((e) => {
          gsLog("startScan error", e);
          sendResponse({ success: false, error: String(e) });
        });
        return true;

      case "gs_stopScan":
        gsStopScan();
        sendResponse({ success: true });
        return false;

      case "gs_contentScanComplete":
        gsHandleContentScan(message.data, message.tabId);
        return false;

      case "gs_settingsUpdated":
        if (message.headers !== undefined) gsHeaders = message.headers;
        return false;

      case "gs_newPageLoaded":
        if (gsIsScanning && gsShouldScanPage(message.url)) {
          chrome.tabs.sendMessage(message.tabId, {
            action: "gs_scanPage",
            collectCookies: gsCollectCookies,
          }).catch(() => {});
        }
        return false;

      case "gs_pathReflection":
        if (gsIsScanning && message.testURL) {
          gsScanData.urls.add(message.testURL);
          gsSaveScanData();
          gsBroadcast({
            action: "gs_updateStats",
            urls: Array.from(gsScanData.urls),
            parameters: Array.from(gsScanData.parameters),
            forms: Array.from(gsScanData.forms),
            vulnerabilities: gsScanData.vulnerabilities,
          });
          gsSendPathReflectionToServer(message, sender && sender.tab ? sender.tab.id : undefined);
        }
        return false;
    }
    return false;
  });

  // passive crawling — scan pages as the user browses during an active scan
  if (chrome.webNavigation) {
    chrome.webNavigation.onCompleted.addListener((details) => {
      if (gsIsScanning && details.frameId === 0 && gsShouldScanPage(details.url)) {
        chrome.tabs.sendMessage(details.tabId, {
          action: "gs_scanPage",
          collectCookies: gsCollectCookies,
        }).catch(() => {
          // content script may not be injected yet — inject then retry
          chrome.scripting.executeScript({
            target: { tabId: details.tabId },
            files: ["lib/gs_content.js"],
          }).then(() => {
            setTimeout(() => {
              chrome.tabs.sendMessage(details.tabId, {
                action: "gs_scanPage",
                collectCookies: gsCollectCookies,
              }).catch(() => {});
            }, 500);
          }).catch(() => {});
        });
      }
    });
  }

  // capture request headers for replay-accurate XSS testing
  if (chrome.webRequest) {
    chrome.webRequest.onBeforeSendHeaders.addListener(
      (details) => {
        const headersObj = {};
        if (details.requestHeaders) {
          for (const h of details.requestHeaders) headersObj[h.name] = h.value;
        }
        gsCapturedHeaders.set(details.url, headersObj);
        return { requestHeaders: details.requestHeaders };
      },
      { urls: ["<all_urls>"] },
      ["requestHeaders", "extraHeaders"]
    );
  }

  // tidy up on suspend
  chrome.runtime.onSuspend?.addListener(() => {
    if (gsIsScanning) gsStopScan();
  });
}

// ---- should this page be scanned? -----------------------------------------
function gsShouldScanPage(url) {
  try {
    return new URL(url).hostname === gsCurrentDomain;
  } catch {
    return false;
  }
}

// ---- start / stop ----------------------------------------------------------
async function gsStartScan(config) {
  gsIsScanning = true;
  gsCurrentScanId = Date.now();
  gsCurrentDomain = new URL(config.url).hostname;
  gsApiKey = config.apiKey;
  gsServerUrl = config.serverUrl;
  gsCollectCookies = config.collectCookies;
  gsActiveCrawl = config.activeCrawl || false;
  gsHeaders = config.headers || "";

  // wipe old scan data
  await chrome.storage.local.remove(["gs_scanData", "gs_vulnId"]);
  const allData = await chrome.storage.local.get(null);
  const keysToRemove = Object.keys(allData).filter((k) => k.startsWith("gs_vuln_"));
  if (keysToRemove.length) await chrome.storage.local.remove(keysToRemove);

  gsScanData.urls.clear();
  gsScanData.parameters.clear();
  gsScanData.forms.clear();
  gsScanData.vulnerabilities = [];
  gsPendingRequests.clear();
  gsRequestQueue = [];
  gsActiveRequests = 0;
  gsCrawlQueue = [];
  gsProcessingCrawl = false;
  gsScannedUrls.clear();
  gsScannedForms.clear();

  // reset live stats for the new scan session
  gsStats.sent = 0;
  gsStats.jobs = 0;
  gsStats.poc = 0;
  gsStats.deduped = 0;
  gsStats.queued = 0;
  gsBroadcastStats();

  // clear captured headers from previous domains, keep current
  if (gsCapturedHeaders.size > 0) {
    const toDel = [];
    for (const [u] of gsCapturedHeaders.entries()) {
      try {
        if (new URL(u).hostname !== gsCurrentDomain) toDel.push(u);
      } catch {
        toDel.push(u);
      }
    }
    toDel.forEach((u) => gsCapturedHeaders.delete(u));
  }

  await chrome.storage.local.set({
    gs_isScanning: true,
    gs_currentDomain: gsCurrentDomain,
    gs_activeCrawl: gsActiveCrawl,
  });

  gsSaveScanData();

  gsBroadcast({
    action: "gs_updateStatus",
    status: gsActiveCrawl
      ? "Active crawling active — visiting links automatically (Depth 1)"
      : "Passive crawling active — browse pages to collect data",
    target: gsCurrentDomain,
  });

  // inject the content script into the starting tab, then kick off the scan
  chrome.scripting.executeScript({
    target: { tabId: config.tabId },
    files: ["lib/gs_content.js"],
  }).then(() => {
    setTimeout(() => {
      chrome.tabs.sendMessage(config.tabId, {
        action: "gs_scanPage",
        collectCookies: gsCollectCookies,
      }).catch(() => {});
    }, 500);
  }).catch((e) => gsLog("inject start tab failed", e));
}

function gsStopScan() {
  gsIsScanning = false;
  gsCurrentScanId = null;

  // Cancel any in-flight polling jobs: mark them stopped + clear their timers.
  for (const [, job] of gsPendingRequests) {
    if (job && typeof job === "object") {
      job.stopped = true;
      if (job.timer) clearTimeout(job.timer);
    }
  }
  gsPendingRequests.clear();
  gsRequestQueue = [];
  gsActiveRequests = 0;
  gsCrawlQueue = [];
  gsProcessingCrawl = false;

  chrome.storage.local.set({ gs_isScanning: false });
  chrome.storage.local.remove(["gs_scanData", "gs_vulnId", "gs_stats"]);
  chrome.storage.local.get(null).then((allData) => {
    const keysToRemove = Object.keys(allData).filter((k) => k.startsWith("gs_vuln_"));
    if (keysToRemove.length) chrome.storage.local.remove(keysToRemove);
  }).catch(() => {});

  gsBroadcast({ action: "gs_updateStatus", status: "Scan stopped" });
}

// ---- content scan handling -------------------------------------------------
async function gsHandleContentScan(data, tabId) {
  if (!gsIsScanning || !data) return;

  data.urls.forEach((u) => gsScanData.urls.add(u));
  data.parameters.forEach((p) => gsScanData.parameters.add(p));
  data.forms.forEach((f) => gsScanData.forms.add(f));

  gsBroadcast({
    action: "gs_updateStats",
    urls: Array.from(gsScanData.urls),
    parameters: Array.from(gsScanData.parameters),
    forms: Array.from(gsScanData.forms),
    vulnerabilities: gsScanData.vulnerabilities,
  });
  gsSaveScanData();

  for (const url of data.urls) await gsScanUrl(url, tabId);

  if (gsActiveCrawl) {
    if (!gsProcessingCrawl) {
      // depth-0 page: queue same-domain links found here
      data.urls.forEach((url) => {
        const sig = gsParamSignature(url);
        const alreadyInQueue = gsCrawlQueue.some((it) => gsParamSignature(it.url) === sig);
        if (!alreadyInQueue && !gsScannedUrls.has(sig) && gsShouldScanPage(url)) {
          gsCrawlQueue.push({ url, depth: 1 });
        }
      });
      if (gsCrawlQueue.length > 0) gsProcessNextCrawlItem(tabId);
    } else {
      // depth-1 page finished — advance the queue
      setTimeout(() => gsProcessNextCrawlItem(tabId), 1000);
    }
  }
}

function gsNormalizeUrl(url) {
  try {
    const u = new URL(url);
    return u.origin + u.pathname;
  } catch {
    return url;
  }
}

// gsParamSignature returns a URL's "injection-point signature": the origin +
// pathname + sorted parameter NAMES (values stripped). Two URLs that differ
// only in parameter VALUES share a signature, so they're scanned once — XSS
// testing injects its own payload, so the original value is irrelevant.
//   search.php?id=hello   -> example.com/search.php?id
//   search.php?id=hello3  -> example.com/search.php?id   (deduped)
//   search.php?id=1&q=2   -> example.com/search.php?id,q
// URLs with no query fall back to path-only.
function gsParamSignature(url) {
  try {
    const u = new URL(url);
    const names = Array.from(u.searchParams.keys());
    if (names.length === 0) return u.origin + u.pathname;
    names.sort();
    return u.origin + u.pathname + "?" + names.join(",");
  } catch {
    return url;
  }
}

// gsSeenSignature returns true if a URL's injection-point signature has
// already been scanned (or queued). Marks it seen if not.
function gsSeenSignature(url) {
  const sig = gsParamSignature(url);
  if (gsScannedUrls.has(sig)) {
    gsStats.deduped++;
    gsBroadcastStats();
    return true;
  }
  gsScannedUrls.add(sig);
  return false;
}

async function gsProcessNextCrawlItem(tabId) {
  if (!gsIsScanning || !gsActiveCrawl) return;
  if (gsCrawlQueue.length === 0) {
    gsBroadcast({ action: "gs_updateStatus", status: "Active Crawl complete — all Depth 1 pages visited." });
    return;
  }
  gsProcessingCrawl = true;
  const nextItem = gsCrawlQueue.shift();
  gsBroadcast({
    action: "gs_updateStatus",
    status: "Active Crawl: visiting " + nextItem.url + " (" + gsCrawlQueue.length + " remaining)",
  });
  if (typeof tabId === "number") {
    chrome.tabs.update(tabId, { url: nextItem.url }).catch(() => {});
  }
}

// ---- scan an individual URL -----------------------------------------------
async function gsScanUrl(url, tabId) {
  // smart dedup: skip URLs whose injection-point signature (path + param
  // names, values stripped) has already been scanned. ?id=hello and ?id=hello3
  // share a signature, so only the first is tested.
  if (gsSeenSignature(url)) return;

  // only test URLs with query params (XSS injection points) — unless we have
  // form/POST data for them
  try {
    const urlObj = new URL(url);
    if (urlObj.searchParams.toString() === "") {
      let hasFormData = false;
      for (const form of Array.from(gsScanData.forms)) {
        if (typeof form === "object" && form.action && form.data) {
          const formActionUrl = new URL(form.action, url).href;
          if (formActionUrl === url || form.action === url) { hasFormData = true; break; }
        }
      }
      if (!hasFormData) return;
    }
  } catch {
    return;
  }

  // cookies?
  let cookies = "";
  if (gsCollectCookies && chrome.cookies) {
    try {
      const cookieList = await chrome.cookies.getAll({ url });
      cookies = cookieList.map((c) => c.name + "=" + c.value).join("; ");
    } catch {}
  }

  const urlHeaders = gsLookupHeaders(url);
  let capturedHeadersStr = "";
  if (urlHeaders) {
    capturedHeadersStr = Object.entries(urlHeaders).map(([n, v]) => n + ": " + v).join("\n");
  }

  // matching form data for this URL
  let form_data = "";
  for (const form of Array.from(gsScanData.forms)) {
    if (typeof form === "object" && form.action && form.data) {
      const formActionUrl = new URL(form.action, url).href;
      if (formActionUrl === url || form.action === url) { form_data = form.data; break; }
    }
  }

  if (form_data && gsScannedForms.has(form_data)) return;

  gsScannedUrls.add(url);
  if (form_data) gsScannedForms.add(form_data);

  const request = {
    id: Date.now() + Math.random(),
    url,
    tabId,
    cookies,
    headers: capturedHeadersStr,
    parameters: Array.from(gsScanData.parameters),
    form_data,
    timestamp: Date.now(),
  };
  gsStats.sent++;
  gsBroadcastStats();
  gsRequestQueue.push(request);
  gsProcessQueue();
}

function gsLookupHeaders(url) {
  // 1. exact match
  if (gsCapturedHeaders.has(url)) return gsCapturedHeaders.get(url);
  // 2. base URL match
  try {
    const baseUrl = new URL(url).origin + new URL(url).pathname;
    for (const [capturedUrl, headers] of gsCapturedHeaders.entries()) {
      try {
        const cu = new URL(capturedUrl);
        if (cu.origin + cu.pathname === baseUrl) return headers;
      } catch {}
    }
  } catch {}
  // 3. any same-domain URL
  for (const [capturedUrl, headers] of gsCapturedHeaders.entries()) {
    try {
      if (new URL(capturedUrl).hostname === gsCurrentDomain && Object.keys(headers).length > 0) return headers;
    } catch {}
  }
  // 4. sensible defaults
  return {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    Connection: "keep-alive",
    "Upgrade-Insecure-Requests": "1",
  };
}

function gsProcessQueue() {
  if (!gsIsScanning) return;
  while (gsActiveRequests < GS_MAX_CONCURRENT && gsRequestQueue.length > 0) {
    const request = gsRequestQueue.shift();
    gsSendAPIRequest(request);
    gsActiveRequests++;
  }
  gsBroadcast({
    action: "gs_updateStatus",
    status: "Passive crawling active (" + gsActiveRequests + " scanning, " + gsRequestQueue.length + " queued)",
  });
}

// ---- send to user's GhoulSight server -------------------------------------
// Async submit + poll flow: the connection is held open only for the brief
// submit call and each poll — never for the whole scan duration.
//
//   POST /api/v1/scan/job        -> { job_id }   (connection closes immediately)
//   GET  /api/v1/scan/job?id=X   -> { status: "queued" | "running" | "completed", found?, poc? }
//
// Polling is adaptive: 1 min for the first few polls, then 3 min, capped at
// GS_MAX_POLLS total so a forgotten job can't poll forever.
const GS_POLL_INITIAL_MS = 60 * 1000;     // first polls: 1 minute
const GS_POLL_BACKOFF_MS = 3 * 60 * 1000; // later polls: 3 minutes
const GS_POLL_INITIAL_COUNT = 4;          // how many polls stay at the initial interval
const GS_MAX_POLLS = 30;                  // ~90 min ceiling before giving up

function gsBuildFetchHeaders() {
  const fetchHeaders = { "Content-Type": "application/json", "X-API-Key": gsApiKey };
  if (gsHeaders && gsHeaders.trim()) {
    try {
      const lines = gsHeaders.split(/[\n;]+/).filter((h) => h.trim());
      for (const line of lines) {
        const colonIndex = line.indexOf(":");
        if (colonIndex > 0) {
          const name = line.substring(0, colonIndex).trim();
          const value = line.substring(colonIndex + 1).trim();
          if (name) fetchHeaders[name] = value;
        }
      }
    } catch {}
  }
  return fetchHeaders;
}

async function gsSendAPIRequest(request) {
  const requestId = request.id;
  const form_data = request.form_data || "";

  const apiRequest = {
    url: request.url,
    modes: ["r"],
    threads: 10,
    timeout: 30,
    smart_scan: true,
    verbose: true,
    cookies: request.cookies,
    form_data,
  };
  if (gsCollectCookies && request.headers) apiRequest.headers = request.headers;
  if (request.isPathReflection) {
    apiRequest.path_reflection = {
      original_url: request.originalURL,
      probe_payload: request.probePayload,
      reflection_type: request.reflectionType,
    };
  }

  const submitUrl = gsServerUrl.replace(/\/$/, "") + "/api/v1/scan/job";
  const fetchHeaders = gsBuildFetchHeaders();

  // Track this job's polling timer so a scan stop can cancel it.
  const jobState = { timer: null, stopped: false };
  gsPendingRequests.set(requestId, jobState);

  let jobId = null;
  try {
    const response = await fetch(submitUrl, {
      method: "POST",
      headers: fetchHeaders,
      body: JSON.stringify(apiRequest),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      throw new Error("submit failed (" + response.status + "): " + errText.slice(0, 120));
    }
    const data = await response.json();
    jobId = data && data.job_id;
    if (!jobId) throw new Error("server did not return a job_id");
    gsStats.jobs++;
    gsBroadcastStats();
  } catch (error) {
    gsPendingRequests.delete(requestId);
    gsActiveRequests--;
    gsProcessQueue();
    gsBroadcast({ action: "gs_updateStatus", status: "Submit error: " + error.message });
    return;
  }

  // Submit succeeded — the request slot can be freed for the next URL while
  // this job is polled in the background.
  gsActiveRequests--;
  gsProcessQueue();

  // Begin adaptive polling.
  gsPollJob(requestId, jobId, request, jobState, 1);
}

// gsPollJob fetches the status of an async scan job once and schedules the
// next poll if it's not finished. Handles "completed" by opening the result
// popup when a PoC was found.
function gsPollJob(requestId, jobId, request, jobState, pollCount) {
  if (jobState.stopped || !gsIsScanning) {
    gsPendingRequests.delete(requestId);
    return;
  }

  const pollUrl = gsServerUrl.replace(/\/$/, "") + "/api/v1/scan/job?id=" + encodeURIComponent(jobId);
  const fetchHeaders = gsBuildFetchHeaders();
  // GET must NOT send Content-Type/json with no body in MV3 — drop it.
  delete fetchHeaders["Content-Type"];

  fetch(pollUrl, { method: "GET", headers: fetchHeaders })
    .then((r) => r.json())
    .then((data) => {
      if (jobState.stopped) { gsPendingRequests.delete(requestId); return; }

      const status = data && data.status;
      if (status === "completed") {
        gsPendingRequests.delete(requestId);
        if (data.found && data.poc) {
          // Reuse the existing PoC-handling path so the popup opens exactly
          // as it did with the synchronous endpoint.
          gsHandleJobPoC(data.poc, data.target || request.url, request);
        } else {
          gsLog("job", jobId, "completed, no XSS");
        }
        return;
      }
      if (status === "not_found") {
        gsPendingRequests.delete(requestId);
        gsBroadcast({ action: "gs_updateStatus", status: "Job expired/unknown on server" });
        return;
      }
      // still queued or running — schedule the next poll (adaptive backoff)
      if (pollCount >= GS_MAX_POLLS) {
        gsPendingRequests.delete(requestId);
        gsBroadcast({ action: "gs_updateStatus", status: "Gave up polling job " + jobId + " after " + pollCount + " tries" });
        return;
      }
      const delay = pollCount <= GS_POLL_INITIAL_COUNT ? GS_POLL_INITIAL_MS : GS_POLL_BACKOFF_MS;
      jobState.timer = setTimeout(() => gsPollJob(requestId, jobId, request, jobState, pollCount + 1), delay);
    })
    .catch((error) => {
      if (jobState.stopped) { gsPendingRequests.delete(requestId); return; }
      // transient poll error — retry once more after the adaptive delay
      if (pollCount >= GS_MAX_POLLS) {
        gsPendingRequests.delete(requestId);
        gsBroadcast({ action: "gs_updateStatus", status: "Poll error, gave up: " + error.message });
        return;
      }
      const delay = pollCount <= GS_POLL_INITIAL_COUNT ? GS_POLL_INITIAL_MS : GS_POLL_BACKOFF_MS;
      jobState.timer = setTimeout(() => gsPollJob(requestId, jobId, request, jobState, pollCount + 1), delay);
    });
}

// gsHandleJobPoC builds a vulnerability record from a poll response's PoC and
// triggers the popup — same outcome as the old sync handler.
function gsHandleJobPoC(pocUrl, targetUrl, originalRequest) {
  pocUrl = (pocUrl || "").trim().replace(/\n\s*\n/g, "\n").replace(/\r/g, "");
  if (!pocUrl) return;
  gsStats.poc++;
  gsBroadcastStats();
  const vulnerability = {
    id: Date.now(),
    url: targetUrl || originalRequest.url,
    poc: pocUrl,
    parameter: gsExtractParameterFromPoC(pocUrl),
    timestamp: new Date().toISOString(),
    apiCalls: "",
  };
  gsScanData.vulnerabilities.push(vulnerability);
  gsSaveScanData();
  gsBroadcast({ action: "gs_vulnerabilityFound", vulnerability });

  const storageKey = "gs_vuln_" + vulnerability.id;
  const storageData = {};
  storageData[storageKey] = vulnerability;
  chrome.storage.local.set(storageData, () => {
    chrome.windows.create({
      url: chrome.runtime.getURL("lib/gs_result.html?id=" + vulnerability.id),
      type: "popup",
      width: 660,
      height: 560,
      focused: true,
    }, () => { if (chrome.runtime.lastError) gsLog("create window error", chrome.runtime.lastError); });
  });
}

async function gsSendPathReflectionToServer(reflectionData, tabId) {
  let cookies = "";
  if (gsCollectCookies && chrome.cookies) {
    try {
      const cookieList = await chrome.cookies.getAll({ url: reflectionData.testURL });
      cookies = cookieList.map((c) => c.name + "=" + c.value).join("; ");
    } catch {}
  }
  const urlHeaders = gsLookupHeaders(reflectionData.testURL);
  let capturedHeadersStr = "";
  if (urlHeaders) {
    capturedHeadersStr = Object.entries(urlHeaders).map(([n, v]) => n + ": " + v).join("\n");
  }
  const request = {
    id: Date.now() + Math.random(),
    url: reflectionData.testURL,
    tabId,
    cookies,
    headers: capturedHeadersStr,
    parameters: [],
    form_data: "",
    timestamp: Date.now(),
    isPathReflection: true,
    originalURL: reflectionData.originalURL,
    probePayload: reflectionData.probePayload,
    reflectionType: reflectionData.reflectionType,
  };
  gsRequestQueue.push(request);
  gsProcessQueue();
}

// gsHandleRequestTimeout is retained for safety; with the async submit+poll
// flow the per-job polling cap (GS_MAX_POLLS) replaces the global timeout, so
// this is only a defensive cleanup if anything still references it.
function gsHandleRequestTimeout(requestId) {
  const job = gsPendingRequests.get(requestId);
  if (job && typeof job === "object") {
    job.stopped = true;
    if (job.timer) clearTimeout(job.timer);
  }
  gsPendingRequests.delete(requestId);
  gsProcessQueue();
}

// ---- handle the PoC callback from the server ------------------------------
function gsHandleAPIResponse(responseText, originalRequest) {
  let pocUrl = "";
  let apiCallInfo = "";

  try {
    const jsonData = JSON.parse(responseText);
    if (jsonData.PoC) pocUrl = jsonData.PoC;
    if (jsonData["API Call"]) apiCallInfo = jsonData["API Call"];
  } catch {
    const lines = responseText.split("\n");
    lines.forEach((line, index) => {
      if (line.startsWith("PoC:")) {
        const pocLines = [line.substring(4)];
        for (let i = index + 1; i < lines.length; i++) {
          const next = lines[i];
          if (next.startsWith("API Call:") || next.startsWith("PoC:")) break;
          pocLines.push(next);
        }
        pocUrl = pocLines.join("\n");
      } else if (line.startsWith("API Call:")) {
        apiCallInfo = line.substring(9);
      }
    });
  }

  if (pocUrl) {
    pocUrl = pocUrl.trim().replace(/\n\s*\n/g, "\n").replace(/\r/g, "");
    const vulnerability = {
      id: Date.now(),
      url: originalRequest.url,
      poc: pocUrl,
      parameter: gsExtractParameterFromPoC(pocUrl),
      timestamp: new Date().toISOString(),
      apiCalls: apiCallInfo,
    };
    gsScanData.vulnerabilities.push(vulnerability);
    gsSaveScanData();

    gsBroadcast({ action: "gs_vulnerabilityFound", vulnerability });

    // store + open the result popup
    const storageKey = "gs_vuln_" + vulnerability.id;
    const storageData = {};
    storageData[storageKey] = vulnerability;
    chrome.storage.local.set(storageData, () => {
      chrome.windows.create({
        url: chrome.runtime.getURL("lib/gs_result.html?id=" + vulnerability.id),
        type: "popup",
        width: 660,
        height: 560,
        focused: true,
      }, () => {
        if (chrome.runtime.lastError) gsLog("create window error", chrome.runtime.lastError);
      });
    });
  }
}

function gsExtractParameterFromPoC(pocUrl) {
  try {
    const params = new URLSearchParams(new URL(pocUrl).search);
    return params.keys().next().value || "unknown";
  } catch {
    return "unknown";
  }
}
