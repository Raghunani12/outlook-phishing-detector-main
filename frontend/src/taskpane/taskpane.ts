/* global document, Office, console, fetch, DOMParser */

// const BACKEND_URL = "http://127.0.0.1:8000/api/analyze";
// const DEBUG_URL   = "http://127.0.0.1:8000/api/debug";
const BACKEND_URL = "https://outlook-phishing-detector-main-production.up.railway.app/api/analyze";
const DEBUG_URL   = "https://outlook-phishing-detector-main-production.up.railway.app/api/debug";
const FETCH_TIMEOUT_MS = 35_000;

// ---------------------------------------------------------------------------
// INIT
// ---------------------------------------------------------------------------

Office.onReady((info) => {
  if (info.host === Office.HostType.Outlook) {
    const btn = document.getElementById("analyze-btn");
    if (btn) btn.onclick = runEmailSecurityScan;
  }
});

// ---------------------------------------------------------------------------
// MAIN SCAN
// ---------------------------------------------------------------------------

async function runEmailSecurityScan(): Promise<void> {
  const analyzeBtn = document.getElementById("analyze-btn") as HTMLButtonElement | null;
  const loader     = document.getElementById("loading-indicator");
  const dashboard  = document.getElementById("results-dashboard");

  if (!analyzeBtn || !loader || !dashboard) return;

  analyzeBtn.disabled = true;
  loader.classList.remove("hidden");
  dashboard.classList.add("hidden");
  setStatus("Connecting to Outlook…");

  try {
    const item = Office.context?.mailbox?.item;
    if (!item) throw new Error("No email is open. Please open a message first.");

    // --- 1. Sender ---
    setStatus("Reading sender…");
    const senderEmail = safeGet(() => (item as any).from?.emailAddress) ?? "unknown@unknown";
    console.log("[PhishingShield] sender:", senderEmail);

    // --- 2. Dual-Layer Headers Retrieval (Mailbox 1.8+ with 1.6 Fallback) ---
    setStatus("Fetching email headers…");
    const rawHeaders = await fetchRawHeadersAsync(item);
    console.log("[PhishingShield] headers length:", rawHeaders.length);
    if (rawHeaders.length > 0) {
      console.log("[PhishingShield] headers preview:", rawHeaders.substring(0, 300));
    } else {
      console.warn("[PhishingShield] WARNING: Empty headers — SPF/DKIM/DMARC will show as unknown.");
    }

    // --- 3. Parallel Body Extraction (HTML + Plain Text) ---
    setStatus("Extracting deep layout structures…");
    const bodyData = await fetchEmailBodyContent(item);
    console.log(`[PhishingShield] Body extracted -> HTML length: ${bodyData.html.length}, Text length: ${bodyData.text.length}`);

    // --- 4. Utmost Deep URL Inspection ---
    setStatus("Parsing buttons, hidden paths, and anchors…");
    const urls = extractUrlsUtmost(bodyData.html, bodyData.text);
    console.log("[PhishingShield] Absolute URLs discovered:", urls);

    // --- 5. Analyze ---
    setStatus("Scanning targets with VirusTotal & AI…");
    const payload = { sender_email: senderEmail, headers: rawHeaders, urls };
    const response = await fetchWithTimeout(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }, FETCH_TIMEOUT_MS);

    if (!response.ok) {
      let detail = response.statusText;
      try { const e = await response.json(); detail = e?.detail ?? detail; } catch { /* ignore */ }
      throw new Error(`Backend error ${response.status}: ${detail}`);
    }

    const data = await response.json();
    console.log("[PhishingShield] result:", JSON.stringify(data, null, 2));
    renderDashboard(data);

  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[PhishingShield] error:", msg);
    renderError(msg);
  } finally {
    analyzeBtn.disabled = false;
    loader.classList.add("hidden");
    setStatus("");
  }
}

// ---------------------------------------------------------------------------
// OFFICE.JS HELPERS
// ---------------------------------------------------------------------------

function fetchRawHeadersAsync(item: Office.MessageRead): Promise<string> {
  return new Promise((resolve) => {
    // 1. Try Mailbox 1.8+ Internet Headers API (Fixes the undefined bug)
    if (typeof (item as any).getAllInternetHeadersAsync === "function") {
      (item as any).getAllInternetHeadersAsync((result: Office.AsyncResult<string>) => {
        if (result.status === Office.AsyncResultStatus.Succeeded) {
          resolve(result.value ?? "");
        } else {
          tryLegacyHeaders(item, resolve);
        }
      });
    } else {
      tryLegacyHeaders(item, resolve);
    }
  });
}

function tryLegacyHeaders(item: Office.MessageRead, resolve: (val: string) => void) {
  if (typeof (item as any).getAllHeadersAsync === "function") {
    (item as any).getAllHeadersAsync((result: Office.AsyncResult<string>) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value ?? "");
      } else {
        console.warn("[PhishingShield] Both header retrieval methods failed.");
        resolve("");
      }
    });
  } else {
    console.warn("[PhishingShield] Header APIs are unsupported in this client environment.");
    resolve("");
  }
}

/**
 * Grabs both HTML and Text in parallel without discarding either, allowing 
 * for exhaustive content scraping.
 */
function fetchEmailBodyContent(item: Office.MessageRead): Promise<{ html: string; text: string }> {
  return new Promise((resolve) => {
    if (!item.body?.getAsync) {
      resolve({ html: "", text: "" });
      return;
    }

    item.body.getAsync(Office.CoercionType.Html, (htmlResult) => {
      const htmlVal = htmlResult.status === Office.AsyncResultStatus.Succeeded 
        ? (htmlResult.value ?? "") 
        : "";

      item.body.getAsync(Office.CoercionType.Text, (textResult) => {
        const textVal = textResult.status === Office.AsyncResultStatus.Succeeded 
          ? (textResult.value ?? "") 
          : "";

        resolve({ html: htmlVal, text: textVal });
      });
    });
  });
}

// ---------------------------------------------------------------------------
// UTMOST URL EXTRACTION ENGINE
// ---------------------------------------------------------------------------

function extractUrlsUtmost(htmlStr: string, textStr: string): string[] {
  const seen = new Set<string>();
  const uniqueUrls: string[] = [];

  const registerUrl = (urlCandidate: string) => {
    if (!urlCandidate) return;
    
    // Decode common HTML entities to catch raw textual variants safely
    let cleaned = urlCandidate
      .replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
      .replace(/&quot;/gi, '"').replace(/&#39;/gi, "'").replace(/&nbsp;/gi, " ");
    
    // Clean trailing punctuation artifacts from raw string matches
    cleaned = cleaned.replace(/[)\]>.,;:'"]+$/, "").trim();
    
    if (!cleaned || seen.has(cleaned)) return;
    
    try {
      new URL(cleaned); // Absolute structural verification validation check
      seen.add(cleaned);
      uniqueUrls.push(cleaned);
    } catch {
      // Skip malformed schemes
    }
  };

  // STRATEGY 1: DOM Document parsing (Extracts links safely behind buttons, image mappings, and elements)
  if (htmlStr && htmlStr.trim().length > 0) {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(htmlStr, "text/html");
      
      // Target elements containing executable/navigable references
      const anchors = doc.querySelectorAll("a[href], area[href]");
      anchors.forEach((el) => {
        const href = el.getAttribute("href");
        if (href && (href.startsWith("http://") || href.startsWith("https://"))) {
          registerUrl(href);
        }
      });
    } catch (domErr) {
      console.error("[PhishingShield] DOMParser error, using backup attribute scanner:", domErr);
      // Backup regex running directly on the HTML attributes BEFORE stripping them
      const hrefRegexMatches = htmlStr.match(/href=["'](https?:\/\/[^"']+)["']/gi);
      if (hrefRegexMatches) {
        hrefRegexMatches.forEach(m => {
          const innerUrl = m.match(/href=["']([^"']+)["']/i);
          if (innerUrl && innerUrl[1]) registerUrl(innerUrl[1]);
        });
      }
    }
  }

  // STRATEGY 2: Generic text pattern scanner (Extracts normal written out plaintext links)
  const corpus = textStr || htmlStr;
  if (corpus) {
    const textUrls = corpus.match(/https?:\/\/[^\s<>"'{}|\\^`\[\]]+/gi) ?? [];
    textUrls.forEach((url) => registerUrl(url));
  }

  return uniqueUrls;
}

// ---------------------------------------------------------------------------
// UTILITIES
// ---------------------------------------------------------------------------

function safeGet<T>(fn: () => T): T | undefined {
  try { return fn(); } catch { return undefined; }
}

function setStatus(msg: string): void {
  const el = document.getElementById("loading-indicator");
  if (el) el.innerText = msg || "⏳ Analyzing…";
}

async function fetchWithTimeout(url: string, options: RequestInit, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } catch (e: unknown) {
    if (e instanceof Error && e.name === "AbortError") {
      throw new Error(`Request timed out after ${ms / 1000}s. Is the Python backend running on port 8000?`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// ERROR RENDERER
// ---------------------------------------------------------------------------

function renderError(message: string): void {
  const dashboard = document.getElementById("results-dashboard");
  const banner    = document.getElementById("verdict-banner");
  const vText     = document.getElementById("verdict-text");
  const score     = document.getElementById("risk-score");
  const aiText    = document.getElementById("ai-verdict-text");
  const rContainer= document.getElementById("threat-reasons-container");
  const rList     = document.getElementById("reasons-list");

  if (banner)  banner.className = "verdict-card bg-danger";
  if (vText)   vText.innerText  = "⚠️ SCAN ERROR";
  if (score)   score.innerText  = "ERR";
  if (aiText)  aiText.innerText = "Scan could not complete.";

  if (rContainer && rList) {
    rContainer.classList.remove("hidden");
    rList.innerHTML = `
      <li style="color:#a80000;font-weight:bold;">${escHtml(message)}</li>
      <li style="font-size:11px;list-style:none;margin-top:6px;color:#555;">
        Common causes:<br>
        • Python backend not running on port 8000<br>
        • No email is open in Outlook<br>
        • Mailbox API permission issue
      </li>`;
  }

  if (dashboard) dashboard.classList.remove("hidden");
}

// ---------------------------------------------------------------------------
// DASHBOARD RENDERER
// ---------------------------------------------------------------------------

function renderDashboard(data: Record<string, unknown>): void {
  const dashboard  = document.getElementById("results-dashboard");
  const banner     = document.getElementById("verdict-banner");
  const vText      = document.getElementById("verdict-text");
  const scoreEl    = document.getElementById("risk-score");
  const aiText     = document.getElementById("ai-verdict-text");
  const rContainer = document.getElementById("threat-reasons-container");
  const rList      = document.getElementById("reasons-list");

  if (!dashboard || !banner || !vText || !scoreEl) return;

  // Verdict
  banner.className = "verdict-card";
  const verdict = String(data.verdict ?? "UNKNOWN");
  if (verdict === "SAFE") {
    banner.classList.add("bg-safe");    vText.innerText = "✓ SECURE";
  } else if (verdict === "SUSPICIOUS") {
    banner.classList.add("bg-suspicious"); vText.innerText = "⚠ SUSPICIOUS";
  } else {
    banner.classList.add("bg-danger");  vText.innerText = "🛑 PHISHING THREAT";
  }
  scoreEl.innerText = String(data.risk_score ?? "–");

  // AI
  if (aiText) {
    aiText.innerText = String(data.ai_analysis ?? "") || "No AI feedback generated.";
  }

  // Reasons
  const reasons = Array.isArray(data.reasons) ? data.reasons as string[] : [];
  if (rList && rContainer) {
    rList.innerHTML = "";
    if (reasons.length > 0) {
      rContainer.classList.remove("hidden");
      reasons.forEach(r => {
        const li = document.createElement("li");
        li.innerText = r;
        rList.appendChild(li);
      });
    } else {
      rContainer.classList.add("hidden");
    }
  }

  // Auth
  const details = (data.details ?? {}) as Record<string, unknown>;
  const auth = (details.authentication_results ?? {}) as Record<string, string>;
  setField("meta-spf",  fmtAuth(auth.spf));
  setField("meta-dkim", fmtAuth(auth.dkim));
  setField("meta-dmarc",fmtAuth(auth.dmarc));

  // Headers received indicator
  const headersOk = Boolean(details.headers_received);
  setField("meta-headers-ok", headersOk ? "✓ Received" : "✗ Empty (auth results may be inaccurate)");
  const hEl = document.getElementById("meta-headers-ok");
  if (hEl) hEl.style.color = headersOk ? "#107c41" : "#a80000";

  // DNS
  const dns = (details.dns_policies ?? {}) as Record<string, unknown>;
  setField("dns-has-spf",      dns.has_spf   ? "✓ YES" : "✗ NO");
  setField("dns-spf-policy",   String(dns.spf_policy   ?? "–").toUpperCase());
  setField("dns-has-dmarc",    dns.has_dmarc ? "✓ YES" : "✗ NO");
  setField("dns-dmarc-policy", String(dns.dmarc_policy ?? "–").toUpperCase());

  // URLs List Generation
  const urlContainer = document.getElementById("url-list-container");
  if (urlContainer) {
    urlContainer.innerHTML = "";
    const urlAnalysis = (details.url_analysis ?? {}) as Record<string, Record<string, unknown>>;
    const urls = Object.keys(urlAnalysis);
    if (urls.length === 0) {
      urlContainer.innerText = "No URLs detected in this email.";
    } else {
      urls.forEach(url => {
        const rep = urlAnalysis[url];
        const mal = Number(rep.malicious_count ?? 0);
        const sus = Number(rep.suspicious_count ?? 0);
        const st  = String(rep.status ?? "unknown");
        let badge = "";
        if (mal > 0)       badge = `<span style="color:#a80000;font-weight:bold;">🛑 MALICIOUS (${mal})</span>`;
        else if (sus > 0)  badge = `<span style="color:#d83b01;font-weight:bold;">⚠ SUSPICIOUS (${sus})</span>`;
        else if (st === "analyzed") badge = `<span style="color:#107c41;">✓ CLEAN</span>`;
        else               badge = `<span style="color:#605e5c;">${escHtml(st)}</span>`;
        const div = document.createElement("div");
        div.className = "url-item";
        div.innerHTML = `🔗 <span style="word-break:break-all;">${escHtml(url)}</span><br>VT: ${badge}`;
        urlContainer.appendChild(div);
      });
    }
  }

  // Meta
  setField("meta-domain",         String(details.sender_domain  ?? "–"));
  setField("meta-urls-extracted",  String(details.urls_extracted ?? "0"));

  dashboard.classList.remove("hidden");
}

// ---------------------------------------------------------------------------
// DOM / FORMAT HELPERS
// ---------------------------------------------------------------------------

function setField(id: string, text: string): void {
  const el = document.getElementById(id);
  if (el) el.innerText = text;
}

function escHtml(s: string): string {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function fmtAuth(val?: string): string {
  const v = (val ?? "unknown").toLowerCase();
  const label = v.toUpperCase();
  if (v === "pass")             return `✓ ${label}`;
  if (v === "fail")             return `✗ ${label}`;
  if (v === "softfail")         return `~ ${label}`;
  if (v === "none")             return `– ${label}`;
  if (v === "present_unverified") return `? SIG PRESENT`;
  if (v === "unknown")          return `? ${label}`;
  return label;
}