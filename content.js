(() => {
  const EXT = {
    alertId: "__sbes_springboot_alert__",
    lastFingerprint: "",
    lastDetected: false,
    scanTimer: null,
    urlTimer: null,
    observer: null,
    fontSizePx: 12
  };

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, c => ({
      "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
    }[c]));
  }

  function getPageSample() {
    const title = document.title || "";
    const body = document.body?.innerText || "";
    const html = document.documentElement?.outerHTML || "";
    const links = [...document.querySelectorAll("a[href]")].slice(0, 250).map(a => a.href);
    const scripts = [...document.scripts].slice(0, 150).map(s => s.src || "");
    const resources = performance.getEntriesByType("resource").slice(-250).map(x => x.name);

    return {
      title: title.slice(0, 1000),
      body: body.slice(0, 180000),
      html: html.slice(0, 180000),
      links,
      scripts,
      resources,
      url: location.href
    };
  }

  function detectSpringBoot(sample) {
    const title = sample.title || "";
    const body = sample.body || "";
    const html = sample.html || "";
    const all = `${title}\n${body}\n${html}\n${sample.url}\n${(sample.links || []).join("\n")}\n${(sample.scripts || []).join("\n")}\n${(sample.resources || []).join("\n")}`;

    const signals = [];

    // Strong Spring Boot / Whitelabel signatures.
    if (/Whitelabel Error Page/i.test(all)) {
      signals.push({
        id: "whitelabel",
        label: "Spring Boot Whitelabel Error Page",
        strength: 100
      });
    }

    if (/This application has no configured error view,\s*so you are seeing this as a fallback/i.test(all)) {
      signals.push({
        id: "whitelabel-fallback",
        label: "Spring Boot default error fallback",
        strength: 100
      });
    }

    if (/There was an unexpected error\s*\(type=.*status=\d+/i.test(all)) {
      signals.push({
        id: "boot-error",
        label: "Spring Boot default error response",
        strength: 95
      });
    }

    if (/\borg\.springframework\.boot\b/i.test(all)) {
      signals.push({
        id: "spring-package",
        label: "org.springframework.boot marker",
        strength: 100
      });
    }

    if (/\borg\.springframework\.web\b/i.test(all)) {
      signals.push({
        id: "spring-web-package",
        label: "org.springframework.web marker",
        strength: 85
      });
    }

    if (/\bSpring Boot\b/i.test(all)) {
      signals.push({
        id: "spring-boot-text",
        label: "Spring Boot marker",
        strength: 80
      });
    }

    if (/springdoc|swagger-ui|v3\/api-docs|v2\/api-docs/i.test(all)) {
      signals.push({
        id: "springdoc",
        label: "SpringDoc / OpenAPI marker",
        strength: 70
      });
    }

    if (/(^|[/\s"'=])\/actuator(?:[/\s"'?#]|$)/i.test(all)) {
      signals.push({
        id: "actuator",
        label: "Actuator endpoint reference",
        strength: 92
      });
    }

    // JSON-shaped Actuator response.
    if (/"_links"\s*:\s*\{|"_links"\s*:/i.test(body) &&
        /"(health|info|env|metrics|beans|mappings|configprops|loggers|prometheus|threaddump)"\s*:/i.test(body)) {
      signals.push({
        id: "actuator-json",
        label: "Actuator endpoint JSON",
        strength: 100
      });
    }

    // Common Spring Boot error / framework markers.
    if (/org\.springframework|DispatcherServlet|HandlerMethod|BasicErrorController|WhiteLabel/i.test(all)) {
      signals.push({
        id: "spring-framework",
        label: "Spring Framework runtime marker",
        strength: 75
      });
    }

    // Strongest signal wins. Dedupe by id.
    const unique = [];
    const seen = new Set();
    for (const s of signals) {
      if (!seen.has(s.id)) {
        seen.add(s.id);
        unique.push(s);
      }
    }
    unique.sort((a, b) => b.strength - a.strength);

    if (!unique.length) {
      return {
        detected: false,
        confidence: 0,
        label: "",
        signals: [],
        url: sample.url
      };
    }

    const top = unique[0].strength;
    const strong = top >= 90 || unique.length >= 2;
    if (!strong) {
      return {
        detected: false,
        confidence: top,
        label: "",
        signals: unique.slice(0, 3),
        url: sample.url
      };
    }

    return {
      detected: true,
      confidence: Math.min(100, Math.max(top, unique.length >= 3 ? 98 : unique.length >= 2 ? 94 : top)),
      label: unique[0].label,
      signals: unique.slice(0, 4),
      url: sample.url
    };
  }

  function removeAlert() {
    const old = document.getElementById(EXT.alertId);
    if (old) old.remove();
  }

  // v1.6 uses toolbar-only technology indication.
  function showAlert() {
    removeAlert();
  }

  async function sendDetection(result) {
    EXT.lastDetected = !!result.detected;
    EXT.lastFingerprint = JSON.stringify(result);

    try {
      await chrome.runtime.sendMessage({
        type: "springboot_detected",
        detected: !!result.detected,
        result
      });
    } catch {}

    // The service worker shows the red "SB" toolbar badge.
    removeAlert();
  }

  async function loadUiSettings() {
    try {
      const result = await chrome.storage.local.get("settings");
      const px = Number(result?.settings?.fontSizePx);
      if (Number.isFinite(px)) EXT.fontSizePx = Math.min(24, Math.max(10, px));
    } catch {}
  }

  function runDetection() {
    try {
      const result = detectSpringBoot(getPageSample());
      const serialized = JSON.stringify(result);

      if (serialized !== EXT.lastFingerprint) {
        sendDetection(result);
      }

      return result;
    } catch {
      return { detected:false, confidence:0, signals:[], url:location.href };
    }
  }

  function scheduleDetection() {
    clearTimeout(EXT.scanTimer);
    EXT.scanTimer = setTimeout(runDetection, 180);
  }

  async function readBodyLimited(response, maxBytes) {
    if (!response.body) {
      try { return (await response.text()).slice(0, Math.floor(maxBytes / 2)); } catch { return ""; }
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let total = 0;
    let text = "";

    try {
      while (total < maxBytes) {
        const {done, value} = await reader.read();
        if (done) break;
        const remaining = maxBytes - total;
        const slice = value.byteLength > remaining ? value.slice(0, remaining) : value;
        total += slice.byteLength;
        text += decoder.decode(slice, {stream: total < maxBytes});
        if (total >= maxBytes) break;
      }
    } catch {}

    try { await reader.cancel(); } catch {}
    return text;
  }

  async function pageProbe(message) {
    const target = new URL(message.url);
    if (target.origin !== location.origin) {
      throw new Error("PAGE_BRIDGE_ORIGIN_MISMATCH");
    }

    const response = await fetch(target.toString(), {
      method: message.method,
      redirect: "follow",
      cache: "no-store",
      credentials: "include",
      headers: {
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        ...(message.headers || {})
      }
    });

    const contentType = (response.headers.get("content-type") || "").toLowerCase();
    const contentLength = Number(response.headers.get("content-length") || "0") || null;
    let body = "";

    if (message.method === "GET" && response.status !== 204) {
      body = await readBodyLimited(
        response,
        Math.min(Number(message.maxBodyBytes) || 98304, 384 * 1024)
      );
    }

    return {
      ok: true,
      status: response.status,
      contentType,
      contentLength,
      finalUrl: response.url || target.toString(),
      body
    };
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "bridge_ping") {
      sendResponse({ok:true});
      return;
    }

    if (message.type === "page_probe") {
      pageProbe(message)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({
          ok: false,
          error: String(error?.message || error || "PAGE_PROBE_ERROR")
        }));
      return true;
    }
  });

  loadUiSettings().finally(scheduleDetection);

  if (EXT.observer) {
    try { EXT.observer.disconnect(); } catch {}
  }

  EXT.observer = new MutationObserver(() => {
    scheduleDetection();
  });

  try {
    EXT.observer.observe(document.documentElement || document, {
      subtree: true,
      childList: true,
      characterData: true
    });
  } catch {}

  // Lightweight URL change detector for SPA navigations.
  let lastUrl = location.href;
  EXT.urlTimer = setInterval(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      removeAlert();
      EXT.lastFingerprint = "";
      scheduleDetection();
    }
  }, 1000);

  // Passive detection after page load can catch late-rendered framework errors.
  window.addEventListener("load", scheduleDetection, { once: true });
})();
