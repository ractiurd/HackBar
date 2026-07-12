/*
 * GhoulSight content script (merged into HackBar).
 * Runs on every page. When a scan is active it collects URLs / params / forms
 * and reports them back to the background service worker for XSS testing.
 * Ported from ghoulsight/content.js — dead core.js injection removed.
 */
(() => {
  let gsScanning = false;
  let gsDomain = "";

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.action) return;
    switch (message.action) {
      case "gs_scanPage":
        gsScanning = true;
        gsDomain = window.location.hostname;
        gsScanCurrentPage(message.collectCookies, sender);
        break;
      case "gs_checkScanStatus":
        sendResponse({ isScanning: gsScanning });
        break;
      case "gs_stopScan":
        gsScanning = false;
        break;
    }
    return true;
  });

  async function gsScanCurrentPage(collectCookies, sender) {
    const scanData = { urls: new Set(), parameters: new Set(), forms: new Set() };
    const currentUrlObj = new URL(window.location.href);
    if (currentUrlObj.searchParams.toString() !== "") {
      scanData.urls.add(window.location.href);
    }
    gsExtractURLs(scanData);
    gsExtractParameters(scanData);
    gsExtractForms(scanData);
    gsDetectPathReflection();
    chrome.runtime.sendMessage({
      action: "gs_contentScanComplete",
      data: {
        urls: Array.from(scanData.urls),
        parameters: Array.from(scanData.parameters),
        forms: Array.from(scanData.forms),
      },
      tabId: sender && sender.tab ? sender.tab.id : undefined,
    });
  }

  /* ---- path-based reflection detection ---- */
  function gsDetectPathReflection() {
    const currentUrl = window.location.href;
    const urlObj = new URL(currentUrl);
    const path = urlObj.pathname;
    if (!path || path === "/") return;
    gsTestPathReflection(currentUrl, path, "ghoulsight");
  }

  function gsTestPathReflection(currentUrl, originalPath, probePayload) {
    try {
      const urlObj = new URL(currentUrl);
      const baseURL = urlObj.origin;
      let testPath;
      const segments = originalPath.split("/").filter((s) => s);
      if (segments.length === 0) testPath = "/" + probePayload;
      else if (segments.length === 1) testPath = "/" + segments[0] + "/" + probePayload;
      else testPath = "/" + segments.slice(0, -1).join("/") + "/" + probePayload;
      const testURL = baseURL + testPath;

      fetch(testURL, { method: "GET", credentials: "include" })
        .then((r) => r.text())
        .then((body) => {
          const variations = [probePayload, encodeURIComponent(probePayload), encodeURI(probePayload)];
          let reflected = false;
          for (const v of variations) {
            if (body.includes(v)) { reflected = true; break; }
          }
          if (reflected) {
            chrome.runtime.sendMessage({
              action: "gs_pathReflection",
              originalURL: currentUrl,
              testURL: testURL,
              probePayload: probePayload,
              reflectionType: "path-based",
            }).catch(() => {});
          }
        })
        .catch(() => {});
    } catch (e) {}
  }

  /* ---- collectors ---- */
  function gsExtractURLs(scanData) {
    const grab = (sel, attr) => {
      document.querySelectorAll(sel).forEach((el) => {
        try {
          const val = el[attr];
          if (!val || val.startsWith("javascript:")) return;
          const url = new URL(val, window.location.href);
          if (url.hostname === gsDomain && url.searchParams.toString() !== "") {
            scanData.urls.add(url.href);
          }
        } catch (e) {}
      });
    };
    grab("a[href]", "href");
    grab("script[src]", "src");
    grab("iframe[src]", "src");
  }

  function gsExtractParameters(scanData) {
    try {
      const currentUrl = new URL(window.location.href);
      currentUrl.searchParams.forEach((_, key) => scanData.parameters.add(key));
    } catch (e) {}
    scanData.urls.forEach((urlString) => {
      try {
        const url = new URL(urlString);
        url.searchParams.forEach((_, key) => scanData.parameters.add(key));
      } catch (e) {}
    });
  }

  function gsExtractForms(scanData) {
    const formsAll = document.getElementsByTagName("form");
    for (let i = 0; i < formsAll.length; i++) {
      let formAction = formsAll[i].action ? formsAll[i].action : document.location.href;
      const inputs = Array.from(formsAll[i].elements).filter((el) =>
        ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) &&
        !["button", "submit", "reset", "image"].includes(el.type) &&
        !el.disabled && el.name
      );
      let post = "";
      inputs.forEach((input) => (post += input.name + "=" + (input.value || "") + "&"));
      scanData.forms.add({ action: formAction, data: post.slice(0, -1) });
      try {
        const url = new URL(formAction, window.location.href);
        if (url.hostname === gsDomain) scanData.urls.add(url.href);
      } catch (e) {}
    }
  }

  /* ---- passive fetch interception (only while scanning) ---- */
  if (!window.__gsFetchPatched) {
    window.__gsFetchPatched = true;
    const originalFetch = window.fetch;
    window.fetch = function (...args) {
      const result = originalFetch.apply(this, args);
      if (gsScanning) {
        result.then(() => {
          try {
            const url = args[0] instanceof Request ? args[0].url : args[0];
            if (url && typeof url === "string") {
              const urlObj = new URL(url, window.location.href);
              if (urlObj.hostname === gsDomain) {
                chrome.runtime.sendMessage({ action: "gs_newUrlFound", url: urlObj.href }).catch(() => {});
              }
            }
          } catch (e) {}
        }).catch(() => {});
      }
      return result;
    };
  }

  document.addEventListener("submit", (e) => {
    if (gsScanning && e.target.tagName === "FORM") {
      setTimeout(() => {
        if (window.location.hostname === gsDomain) {
          chrome.runtime.sendMessage({
            action: "gs_newPageLoaded",
            url: window.location.href,
          }).catch(() => {});
        }
      }, 1000);
    }
  });
})();
