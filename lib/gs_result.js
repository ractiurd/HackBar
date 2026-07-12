/* GhoulSight result window — shows a confirmed XSS finding (ported from
 * ghoulsight/result-window.js). Loads vuln data from chrome.storage by id. */
class GsResultWindow {
  constructor() {
    this.vulnerability = null;
    this.init();
  }
  async init() {
    const urlParams = new URLSearchParams(window.location.search);
    const vulnId = urlParams.get("id");
    const executeBtn = document.getElementById("executeBtn");
    const copyBtn = document.getElementById("copyBtn");
    if (executeBtn) executeBtn.addEventListener("click", () => this.executePoC());
    if (copyBtn) copyBtn.addEventListener("click", () => this.copyPoC());
    if (!vulnId) {
      this.showStatus("No vulnerability ID provided", "error");
      return;
    }
    await this.loadVulnerability(vulnId);
  }
  async loadVulnerability(id) {
    try {
      const storageKey = "gs_vuln_" + id;
      const data = await chrome.storage.local.get(storageKey);
      if (!data[storageKey]) {
        this.showStatus("Vulnerability data not found", "error");
        return;
      }
      this.vulnerability = data[storageKey];
      this.renderVulnerability();
    } catch (error) {
      this.showStatus("Failed to load vulnerability data", "error");
    }
  }
  renderVulnerability() {
    const vuln = this.vulnerability;
    document.getElementById("targetUrl").textContent = vuln.url || "Unknown";
    document.getElementById("parameter").textContent = vuln.parameter || "Unknown";
    document.getElementById("apiCalls").textContent = vuln.apiCalls || "N/A";
    document.getElementById("pocCode").textContent = vuln.poc || "No PoC available";
    if (vuln.timestamp) {
      const date = new Date(vuln.timestamp);
      document.getElementById("timestamp").textContent = date.toLocaleString();
    }
    document.getElementById("pocType").textContent = this.detectPoCType(vuln.poc);
  }
  detectPoCType(poc) {
    if (!poc) return "Unknown";
    if (poc.startsWith("data:text/html")) return "HTML Form";
    if (poc.includes("<svg")) return "SVG Injection";
    if (poc.includes("<img")) return "IMG Tag";
    if (poc.includes("<script")) return "Script Tag";
    if (poc.includes("javascript:")) return "JS Protocol";
    return "Custom Payload";
  }
  async executePoC() {
    if (!this.vulnerability || !this.vulnerability.poc) {
      this.showStatus("No PoC available to execute", "error");
      return;
    }
    const poc = this.vulnerability.poc;
    try {
      this.showStatus("Opening PoC in new tab...", "info");
      const tab = await chrome.tabs.create({ url: poc, active: true });
      if (tab) this.showStatus("✓ PoC opened successfully! Check the new tab.", "success");
      else this.showStatus("Failed to open tab. Please allow popups.", "error");
    } catch (error) {
      this.showStatus("Error: " + error.message, "error");
    }
  }
  copyPoC() {
    if (!this.vulnerability || !this.vulnerability.poc) {
      this.showStatus("No PoC to copy", "error");
      return;
    }
    navigator.clipboard.writeText(this.vulnerability.poc)
      .then(() => {
        const btn = document.getElementById("copyBtn");
        const originalText = btn.innerHTML;
        btn.innerHTML = "✓ Copied!";
        this.showStatus("PoC copied to clipboard", "success");
        setTimeout(() => { btn.innerHTML = originalText; }, 2000);
      })
      .catch(() => this.showStatus("Failed to copy", "error"));
  }
  showStatus(message, type = "info") {
    const status = document.getElementById("status");
    status.textContent = message;
    status.className = "status show " + type;
    setTimeout(() => status.classList.remove("show"), 5000);
  }
}
document.addEventListener("DOMContentLoaded", () => new GsResultWindow());
