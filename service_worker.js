importScripts("wordlist.js");

const DEFAULTS = {
  autoScan: true,
  autoMode: "smart",
  concurrency: 6,
  delayMs: 120,
  timeoutMs: 7000,
  maxBodyBytes: 384 * 1024,
  includeAdvanced: false,
  scanHttpVariant: false,
  maxResults: 250,
  persistResults: true,
  showOnlyFindings: false,
  usePageBridge: true,
  fontSizePx: 16,
  uiFontSizePx: 16,
  secretScan: true,
  secretScanMaxMatches: 40
};

const stateByTab = new Map();
const activeScans = new Map();
const autoTimers = new Map();

const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function normalizeSettings(s) {
  return { ...DEFAULTS, ...(s || {}) };
}

async function getSettings() {
  const v = await chrome.storage.local.get("settings");
  const normalized = normalizeSettings(v.settings);

  if (!v.settings || v.settings.uiFontSizePx == null) {
    const legacy = Number(v.settings?.fontSizePx);
    const px = (legacy && legacy !== 12) ? legacy : 16;
    normalized.fontSizePx = px;
    normalized.uiFontSizePx = px;
    await chrome.storage.local.set({ settings: normalized });
  } else {
    normalized.fontSizePx = normalized.uiFontSizePx;
  }

  return normalized;
}

function isScannableUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function now() {
  return Date.now();
}

function normalizePath(path) {
  let p = path.trim();
  if (!p) return "/";
  if (!p.startsWith("/")) p = "/" + p;
  p = p.replace(/\/{2,}/g, "/");
  return p;
}

function expandTemplate(path) {
  const values = {
    "{cache}": ["default", "cacheManager", "redis"],
    "{name}": ["spring.cloud.gateway.requests", "http.server.requests", "jvm.memory.used", "jvm.threads.live"],
    "{property}": ["server.port", "spring.application.name", "server.servlet.context-path"],
    "{prefix}": ["server", "management", "spring"],
    "{indicator}": ["db", "diskSpace", "ping", "livenessState", "readinessState"],
    "{component}": ["db", "diskSpace", "livenessState", "readinessState"],
    "{subcomponent}": ["db", "diskSpace"],
    "{requiredMetricName}": ["spring.cloud.gateway.requests", "http.server.requests", "jvm.memory.used"],
    "{id}": ["0", "1", "default"],
    "{*path}": ["db", "diskSpace", "livenessState", "readinessState"]
  };

  let paths = [path];
  for (const [token, replacements] of Object.entries(values)) {
    const next = [];
    for (const p of paths) {
      if (!p.includes(token)) {
        next.push(p);
        continue;
      }
      for (const rep of replacements) {
        next.push(p.replaceAll(token, rep));
      }
    }
    paths = [...new Set(next)];
  }
  return [...new Set(paths)];
}

function classifyEntry(raw) {
  const upper = raw.toUpperCase();
  let method = "GET";
  let special = null;

  const methodMatch = raw.match(/^(TRACE|OPTIONS|CONNECT|PATCH|HEAD|PUT|DELETE)\s+(.+)$/i);
  if (methodMatch) {
    method = methodMatch[1].toUpperCase();
    raw = methodMatch[2].trim();
    special = "method";
  }

  // Header-based lines in the uploaded list are intentionally handled only
  // in advanced mode; they are not enabled by default.
  if (raw.toLowerCase().startsWith("header:")) {
    special = "header";
  }

  return { raw, method, special };
}

function parseEntryPath(raw) {
  let s = raw.trim();

  // Host-port shorthand from the wordlist, e.g. 9090/health.
  const portPrefix = s.match(/^(\d{2,5})\/(.+)$/);
  if (portPrefix) {
    return { port: Number(portPrefix[1]), path: "/" + portPrefix[2] };
  }

  // Query-only variants are appended to the current root.
  if (s.startsWith("?")) return { path: "/" + s };
  if (s.startsWith("&")) return { path: "/" + s };

  return { path: normalizePath(s) };
}

function isLikelyAdvanced(raw, special) {
  if (special === "method") return !["GET", "HEAD", "OPTIONS"].includes(classifyEntry(raw).method);
  return /%0a|%0d|%0b|%09|%2e|%25|;|\\|\.\.|\/\*|\*\*|#|%3b|%3f|%5c/i.test(raw);
}

function isRiskyPath(path) {
  return /(\/env(?:\/|$)|\/configprops(?:\/|$)|\/heapdump(?:\/|$)|\/logfile(?:\/|$)|\/jolokia(?:\/|$)|\/shutdown(?:\/|$)|\/restart(?:\/|$)|\/refresh(?:\/|$)|\/execute(?:\/|$)|\/eval(?:\/|$)|\/command(?:\/|$)|\/cmd(?:\/|$))/i.test(path);
}

function makeTarget(base, entry) {
  const parsed = parseEntryPath(entry);
  const u = new URL(base);

  if (parsed.port) {
    u.port = String(parsed.port);
  }
  // Keep query-only variants intact.
  if (parsed.path.startsWith("/?") || parsed.path.startsWith("/&")) {
    u.pathname = u.pathname || "/";
    u.search = parsed.path.slice(1);
    return u.toString();
  }

  u.pathname = parsed.path.split("?")[0];
  const qIndex = parsed.path.indexOf("?");
  if (qIndex >= 0) u.search = parsed.path.slice(qIndex);
  else u.search = "";

  u.hash = "";
  return u.toString();
}


function redactSecret(value) {
  const s = String(value || "");
  if (!s) return "";
  if (s.length <= 10) return "••••••";
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function uniqueFindings(items) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = `${item.type}|${item.location}|${item.redacted}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(item);
    }
  }
  return out;
}

function scanSensitiveText(text, path, contentType = "") {
  if (!text || typeof text !== "string") return [];

  const source = text.slice(0, 900000);
  const findings = [];

  const rules = [
    {
      type: "AWS Access Key ID",
      severity: "high",
      re: /\bAKIA[0-9A-Z]{16}\b/g
    },
    {
      type: "AWS Secret Access Key",
      severity: "critical",
      re: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secretAccessKey|secret_key)\s*[:=]\s*["']?([A-Za-z0-9\/+=]{35,})["']?/gi,
      capture: 1
    },
    {
      type: "GitHub Token",
      severity: "critical",
      re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g
    },
    {
      type: "GitHub Fine-grained Token",
      severity: "critical",
      re: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/g
    },
    {
      type: "Slack Token",
      severity: "high",
      re: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g
    },
    {
      type: "Private Key",
      severity: "critical",
      re: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g
    },
    {
      type: "JWT",
      severity: "high",
      re: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g
    },
    {
      type: "Bearer Token",
      severity: "high",
      re: /\bBearer\s+[A-Za-z0-9._~+\/=-]{20,}\b/gi,
      capture: 0
    },
    {
      type: "Basic Authorization Credential",
      severity: "high",
      re: /\bBasic\s+[A-Za-z0-9+\/=]{16,}\b/gi,
      capture: 0
    },
    {
      type: "Database URI with Credentials",
      severity: "critical",
      re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|amqp):\/\/[^\/\s:@]+:[^@\s]+@/gi,
      capture: 0
    },
    {
      type: "Password-like Configuration",
      severity: "high",
      re: /(?:^|["'\s])(?:password|passwd|pwd|client_secret|clientSecret|api[_-]?key|secret|token|access[_-]?token|private[_-]?key)\s*[:=]\s*["']([^"'\r\n]{8,})["']/gmi,
      capture: 1
    },
    {
      type: "Spring datasource credential",
      severity: "critical",
      re: /(?:spring\.datasource\.(?:url|username|password)|SPRING_DATASOURCE_(?:URL|USERNAME|PASSWORD))\s*[:=]\s*["']?([^\s"',]{6,})["']?/gi,
      capture: 1
    },
    {
      type: "Cloud credential configuration",
      severity: "high",
      re: /(?:aws_access_key_id|aws_secret_access_key|azure_client_secret|google_application_credentials|gcp_project|client_secret|private_key_id)\s*[:=]\s*["']?([^\s"',]{8,})["']?/gi,
      capture: 1
    }
  ];

  for (const rule of rules) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let match;
    let count = 0;
    while ((match = re.exec(source)) && count < 12) {
      const raw = String(rule.capture ? match[rule.capture] : match[0] || "").trim();
      if (!raw) continue;

      // Avoid flagging obvious placeholders/example values.
      if (/^(changeme|change-me|example|example\.com|your[_-]?secret|your[_-]?token|dummy|test|placeholder)$/i.test(raw)) {
        continue;
      }

      const idx = Math.max(0, match.index);
      const from = Math.max(0, idx - 70);
      const to = Math.min(source.length, idx + Math.max(80, raw.length + 70));
      let context = source.slice(from, to).replace(/\s+/g, " ").trim();

      // Redact the matched value inside the context.
      context = context.replace(raw, redactSecret(raw));

      findings.push({
        type: rule.type,
        severity: rule.severity,
        location: path,
        redacted: redactSecret(raw),
        context,
        contentType
      });

      count++;
      if (re.lastIndex === match.index) re.lastIndex++;
    }
  }

  return uniqueFindings(findings);
}

function secretSeverityBoost(results) {
  let severity = "info";
  for (const r of results || []) {
    if (r.severity === "critical") return "critical";
    if (r.severity === "high") severity = "high";
    else if (r.severity === "medium" && severity === "info") severity = "medium";
  }
  return severity;
}

function severityFor(path, status, signature) {
  const p = path.toLowerCase();
  if (/(\/env|\/configprops|\/heapdump|\/logfile)(\/|$)/i.test(p) && status >= 200 && status < 300)
    return "critical";
  if (/(\/jolokia|\/gateway\/routes|\/mappings|\/beans|\/threaddump|\/httptrace|\/sessions|\/loggers)(\/|$)/i.test(p) && status >= 200 && status < 300)
    return "high";
  if (signature === "spring-actuator" && status >= 200 && status < 300)
    return "high";
  if (/(\/prometheus|\/metrics|\/swagger|\/openapi|\/api-docs)(\/|$)/i.test(p) && status >= 200 && status < 300)
    return "medium";
  if (/(\/health|\/info|\/version|\/status)(\/|$)/i.test(p) && status >= 200 && status < 300)
    return "low";
  if (status === 401 || status === 403) return "info";
  return "info";
}

function signatureFor(path, contentType, text) {
  const t = (text || "").slice(0, 250000);
  const p = path.toLowerCase();

  if (contentType.includes("application/json") || t.trim().startsWith("{") || t.trim().startsWith("[")) {
    if (/"_links"\s*:|"_links"\s*\{|actuator/i.test(t) && /(health|env|beans|mappings|metrics|info|configprops)/i.test(p)) return "spring-actuator";
    if (/propertySources|activeProfiles|systemProperties|systemEnvironment/i.test(t)) return "spring-env";
    if (/"contexts"\s*:.*"beans"\s*:|beanFactory|dependencies/i.test(t)) return "spring-beans";
    if (/"mappings"\s*:|dispatcherServlet|handlerMethods/i.test(t)) return "spring-mappings";
    if (/"threads"\s*:|threadName|threadState/i.test(t)) return "spring-threaddump";
    if (/timestamp.*type.*status.*value|jolokia/i.test(t)) return "jolokia";
    if (/openapi"\s*:|swagger"\s*:|paths"\s*:/i.test(t)) return "openapi";
  }
  if (/text\/plain|text\/html/.test(contentType) && /#\s*(HELP|TYPE)\s+\S+|jvm_|spring_/i.test(t)) return "prometheus";
  if (/application\/octet-stream|application\/gzip|application\/x-hprof/i.test(contentType) && /heapdump|hprof/i.test(p)) return "heapdump";
  if (/whitelabel error page|org\.springframework\.boot|spring boot/i.test(t)) return "spring-fingerprint";
  return null;
}

async function readBodyLimited(response, maxBytes, abortController) {
  const reader = response.body?.getReader();
  if (!reader) {
    try { return (await response.text()).slice(0, Math.floor(maxBytes / 2)); } catch { return ""; }
  }
  const chunks = [];
  let total = 0;
  const decoder = new TextDecoder();
  let text = "";
  try {
    while (total < maxBytes) {
      const {done, value} = await reader.read();
      if (done) break;
      total += value.byteLength;
      const take = Math.min(value.byteLength, maxBytes - (total - value.byteLength));
      if (take > 0) text += decoder.decode(value.slice(0, take), {stream: total < maxBytes});
      if (total >= maxBytes) {
        try { await reader.cancel(); } catch {}
        if (abortController) abortController.abort();
        break;
      }
    }
  } catch {}
  try { await reader.cancel(); } catch {}
  return text;
}

function responseLooksLikeRedirectedLogin(finalUrl, requestedUrl, text) {
  if (!finalUrl || finalUrl === requestedUrl) return false;
  return /login|signin|sign-in|auth/i.test(finalUrl) && /login|sign in|sign-in|password/i.test(text.slice(0, 5000));
}


async function ensureContentBridge(tabId) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: "bridge_ping" });
    return true;
  } catch {
    try {
      await chrome.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        files: ["content.js"]
      });
      await chrome.tabs.sendMessage(tabId, { type: "bridge_ping" });
      return true;
    } catch {
      return false;
    }
  }
}


async function browserFrameProbe(tabId, url, settings) {
  const timeoutMs = Math.max(2500, settings.timeoutMs + 1500);
  const started = performance.now();

  try {
    const result = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      args: [url, timeoutMs, Math.min(settings.maxBodyBytes, 256 * 1024)],
      func: async (targetUrl, waitMs, maxBytes) => {
        const old = document.getElementById("__sbes_probe_frame__");
        if (old) old.remove();

        const frame = document.createElement("iframe");
        frame.id = "__sbes_probe_frame__";
        frame.setAttribute("aria-hidden", "true");
        frame.style.cssText = [
          "position:fixed",
          "width:1px",
          "height:1px",
          "opacity:0",
          "pointer-events:none",
          "left:-10000px",
          "top:-10000px",
          "border:0"
        ].join(";");
        document.documentElement.appendChild(frame);

        const result = await new Promise(resolve => {
          let done = false;
          const finish = value => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            try { frame.remove(); } catch {}
            resolve(value);
          };

          const timer = setTimeout(() => finish({
            ok: false,
            error: "BROWSER_FRAME_TIMEOUT"
          }), waitMs);

          frame.onload = () => {
            try {
              const doc = frame.contentDocument;
              if (!doc) {
                finish({ok:false, error:"NO_FRAME_DOCUMENT"});
                return;
              }

              const bodyText = (doc.body?.innerText || "").slice(0, maxBytes);
              const html = (doc.documentElement?.outerHTML || "").slice(0, maxBytes);
              const content = bodyText || html;

              const ct =
                doc.contentType ||
                (doc.contentType === "" ? "text/html" : "text/html");

              const markers = {
                actuatorLinks: /"_links"\s*:/i.test(content),
                springBoot: /org\.springframework\.boot|spring boot|whitelabel error page/i.test(content),
                env: /propertySources|activeProfiles|systemProperties|systemEnvironment/i.test(content),
                beans: /"contexts"\s*:.*"beans"\s*:|beanFactory/i.test(content),
                mappings: /"mappings"\s*:|dispatcherServlet|handlerMethods/i.test(content),
                threads: /"threads"\s*:|threadName|threadState/i.test(content),
                jolokia: /jolokia/i.test(content),
                openapi: /"openapi"\s*:|"swagger"\s*:|"paths"\s*:/i.test(content),
                prometheus: /#\s*(HELP|TYPE)\s+\S+|jvm_|spring_/i.test(content)
              };

              const finalUrl = frame.contentWindow?.location?.href || targetUrl;
              const signature =
                markers.env ? "spring-env" :
                markers.beans ? "spring-beans" :
                markers.mappings ? "spring-mappings" :
                markers.threads ? "spring-threaddump" :
                markers.jolokia ? "jolokia" :
                markers.openapi ? "openapi" :
                markers.prometheus ? "prometheus" :
                markers.actuatorLinks ? "spring-actuator" :
                markers.springBoot ? "spring-fingerprint" : null;

              finish({
                ok: true,
                status: 200,
                contentType: ct,
                finalUrl,
                signature,
                body: content
              });
            } catch (e) {
              finish({ok:false, error:String(e?.message || e)});
            }
          };

          frame.onerror = () => finish({
            ok:false,
            error:"BROWSER_FRAME_LOAD_ERROR"
          });

          frame.src = targetUrl;
        });

        return result;
      }
    });

    return {
      ...(result?.[0]?.result || {ok:false,error:"FRAME_SCRIPT_NO_RESULT"}),
      durationMs: Math.round(performance.now() - started)
    };
  } catch (e) {
    return {
      ok: false,
      error: String(e?.message || e || "BROWSER_FRAME_SCRIPT_ERROR"),
      durationMs: Math.round(performance.now() - started)
    };
  }
}

async function pageProbe(tabId, url, method, settings, headers = {}) {
  const bridge = await ensureContentBridge(tabId);
  if (!bridge) throw new Error("CONTENT_BRIDGE_UNAVAILABLE");

  const timeoutMs = Math.max(1500, settings.timeoutMs);
  const timer = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("PAGE_PROBE_TIMEOUT")), timeoutMs)
  );

  const request = chrome.tabs.sendMessage(tabId, {
    type: "page_probe",
    url,
    method,
    timeoutMs,
    maxBodyBytes: Math.min(settings.maxBodyBytes, 384 * 1024),
    headers
  });

  return await Promise.race([request, timer]);
}

async function probe(url, path, method, settings, tabId, headers = {}) {
  const started = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), settings.timeoutMs);

  try {
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      return {
        skipped: true,
        reason: `Unsafe method ${method} not executed`,
        durationMs: Math.round(performance.now() - started)
      };
    }

    let responseData = null;
    let transport = "service-worker";

    // Same-origin probing is executed from the active tab. This preserves the
    // browser's already-established connection/session and avoids turning a
    // loaded self-signed HTTPS page into a false "no finding" result.
    try {
      const tabUrl = await chrome.tabs.get(tabId).then(t => t.url);
      const targetOrigin = new URL(url).origin;
      const tabOrigin = new URL(tabUrl).origin;

      if (settings.usePageBridge !== false && targetOrigin === tabOrigin) {
        responseData = await pageProbe(tabId, url, method, settings, headers);
        transport = "page";
      }
    } catch {
      responseData = null;
    }

    // Browser-frame fallback: uses the already-opened browser origin/context.
    // Particularly useful for HTTPS targets whose certificate has already been
    // accepted interactively in the active tab.
    if (!responseData && settings.usePageBridge !== false) {
      const frameResult = await browserFrameProbe(tabId, url, settings);
      if (frameResult?.ok) {
        responseData = frameResult;
        transport = "browser-frame";
      }
    }

    // Final fallback for targets not handled by the page context.
    if (!responseData) {
      const opts = {
        method,
        redirect: "follow",
        cache: "no-store",
        credentials: "include",
        signal: controller.signal,
        headers: {
          "Cache-Control": "no-cache",
          "Pragma": "no-cache",
          ...headers
        }
      };

      const response = await fetch(url, opts);
      const contentType = (response.headers.get("content-type") || "").toLowerCase();
      const contentLength = Number(response.headers.get("content-length") || "0") || null;
      let body = "";

      if (method === "GET" && response.status !== 204 && settings.maxBodyBytes > 0) {
        body = await readBodyLimited(
          response,
          isRiskyPath(path) ? Math.min(settings.maxBodyBytes, 96 * 1024) : settings.maxBodyBytes,
          controller
        );
      }

      responseData = {
        ok: true,
        status: response.status,
        contentType,
        contentLength,
        finalUrl: response.url || url,
        body
      };
    }

    const status = Number(responseData.status);
    const body = responseData.body || "";
    const contentType = String(responseData.contentType || "").toLowerCase();
    const finalUrl = responseData.finalUrl || url;
    const sig = signatureFor(path, contentType, body);
    const severity = severityFor(path, status, sig);
    const loginRedirect = responseLooksLikeRedirectedLogin(finalUrl, url, body);

    const relevantStatus =
      (status >= 200 && status < 400) ||
      status === 401 || status === 403 || status === 405;

    if (!relevantStatus) {
      return null;
    }

    if (loginRedirect && severity !== "info") {
      return {
        url, path, method, status: status,
        severity: "info",
        title: "Redirected to authentication",
        signature: "auth-redirect",
        contentType, contentLength: responseData.contentLength || null,
        finalUrl,
        durationMs: Math.round(performance.now() - started),
        transport
      };
    }

    const isKnownSensitive =
      /actuator|management|monitor|prometheus|swagger|openapi|api-docs|health|metrics|heapdump|logfile|jolokia|gateway|configprops|mappings|beans|threaddump|env/i.test(path);

    if (status === 200 && !sig && !isKnownSensitive) {
      return null;
    }

    const secretFindings = settings.secretScan
      ? scanSensitiveText(body, path, contentType).slice(0, settings.secretScanMaxMatches || 40)
      : [];

    const combinedSeverity = secretFindings.length
      ? secretSeverityBoost(secretFindings)
      : severity;

    return {
      url,
      path,
      method,
      status,
      severity: SEVERITY_ORDER[combinedSeverity] > SEVERITY_ORDER[severity] ? combinedSeverity : severity,
      title: secretFindings.length
        ? `Sensitive secret/configuration exposure (${secretFindings.length})`
        : titleFor(path, sig, status),
      signature: sig || "http-hit",
      signature: sig || "http-hit",
      contentType,
      contentLength: responseData.contentLength || null,
      finalUrl,
      durationMs: Math.round(performance.now() - started),
      transport,
      secretFindings,
      excerpt: body.replace(/\s+/g, " ").trim().slice(0, isRiskyPath(path) ? 420 : 300)
    };
  } catch (error) {
    return {
      error: true,
      url,
      path,
      method,
      errorCode: String(error?.message || error || "NETWORK_ERROR"),
      durationMs: Math.round(performance.now() - started)
    };
  } finally {
    clearTimeout(timer);
  }
}

function titleFor(path, sig, status) {
  if (sig === "spring-env") return "Spring environment/configuration exposure";
  if (sig === "spring-beans") return "Spring bean metadata exposure";
  if (sig === "spring-mappings") return "Spring route/mapping exposure";
  if (sig === "spring-threaddump") return "Thread dump exposure";
  if (sig === "jolokia") return "Jolokia management endpoint exposure";
  if (sig === "openapi") return "OpenAPI/Swagger exposure";
  if (sig === "heapdump") return "Potential heap dump exposure";
  if (sig === "prometheus") return "Prometheus/metrics exposure";
  if (sig === "spring-actuator") return "Spring Boot Actuator exposure";
  if (status === 401 || status === 403) return "Endpoint discovered but access controlled";
  if (status === 405) return "Endpoint discovered (method not allowed)";
  return "Potential endpoint exposure";
}

async function fingerprintTab(tabId, url) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const html = document.documentElement?.outerHTML?.slice(0, 600000) || "";
        const links = performance.getEntriesByType("resource").map(x => x.name).slice(-300);
        const text = (document.body?.innerText || "").slice(0, 120000);
        const probes = [
          /org\.springframework\.boot/i,
          /spring boot/i,
          /springdoc/i,
          /whitelabel error page/i,
          /\/actuator(\/|$)/i,
          /swagger-ui/i
        ];
        const matches = probes.filter(r => r.test(html) || r.test(text) || links.some(x => r.test(x))).map(r => r.source);
        return {
          detected: matches.length > 0,
          markers: matches,
          resources: links.filter(x => /actuator|swagger|openapi|springdoc/i.test(x)).slice(0, 30)
        };
      }
    });
    return results?.[0]?.result || { detected: false, markers: [], resources: [] };
  } catch {
    return { detected: false, markers: [], resources: [] };
  }
}


async function currentPageEvidence(tabId, tabUrl) {
  try {
    const result = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: () => {
        const href = location.href;
        const u = new URL(href);
        const path = u.pathname + u.search;
        const text = (document.body?.innerText || "").slice(0, 180000);
        const html = (document.documentElement?.outerHTML || "").slice(0, 180000);
        const content = text || html;

        const actuatorPath =
          /(?:^|\/)(actuator|management|monitoring)(?:\/|$)/i.test(u.pathname) ||
          /\/(?:env|health|beans|metrics|info|configprops|mappings|prometheus|heapdump|logfile|jolokia|threaddump)(?:\/|$)/i.test(u.pathname);

        const jsonLike = content.trim().startsWith("{") || content.trim().startsWith("[");
        const markers = {
          actuatorLinks: /"_links"\s*:/i.test(content),
          springBoot: /org\.springframework\.boot|spring boot/i.test(content),
          env: /propertySources|activeProfiles|systemProperties|systemEnvironment/i.test(content),
          beans: /"contexts"\s*:.*"beans"\s*:|beanFactory/i.test(content),
          mappings: /"mappings"\s*:|dispatcherServlet|handlerMethods/i.test(content),
          threads: /"threads"\s*:|threadName|threadState/i.test(content),
          jolokia: /jolokia/i.test(content),
          openapi: /"openapi"\s*:|"swagger"\s*:|"paths"\s*:/i.test(content),
          prometheus: /#\s*(HELP|TYPE)\s+\S+|jvm_|spring_/i.test(content)
        };

        const signature =
          markers.env ? "spring-env" :
          markers.beans ? "spring-beans" :
          markers.mappings ? "spring-mappings" :
          markers.threads ? "spring-threaddump" :
          markers.jolokia ? "jolokia" :
          markers.openapi ? "openapi" :
          markers.prometheus ? "prometheus" :
          (markers.actuatorLinks && actuatorPath) || (markers.springBoot && actuatorPath) ? "spring-actuator" :
          markers.springBoot ? "spring-fingerprint" : null;

        return {
          url: href,
          path,
          actuatorPath,
          jsonLike,
          signature,
          excerpt: content.replace(/\s+/g, " ").trim().slice(0, 420)
        };
      }
    });

    const e = results?.[0]?.result;
    if (!e?.actuatorPath) return null;
    if (!e.signature && !e.jsonLike) return null;

    const sig = e.signature || "spring-actuator";
    return {
      url: e.url,
      path: e.path,
      method: "PAGE",
      status: 200,
      severity: severityFor(e.path, 200, sig),
      title: titleFor(e.path, sig, 200) + " (current page)",
      signature: sig,
      contentType: e.jsonLike ? "application/json (rendered document)" : "text/html (rendered document)",
      finalUrl: e.url,
      durationMs: 0,
      transport: "page-document",
      evidence: "current-page",
      excerpt: e.excerpt
    };
  } catch {
    return null;
  }
}


function buildCoreSmokeTargets(baseUrl) {
  const core = [
    "/actuator",
    "/actuator/",
    "/actuator/health",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/mappings",
    "/actuator/loggers",
    "/actuator/prometheus",
    "/actuator/gateway/routes",
    "/env",
    "/health",
    "/info",
    "/metrics",
    "/prometheus",
    "/swagger-ui.html",
    "/swagger-ui",
    "/v3/api-docs",
    "/v2/api-docs",
    "/openapi.json"
  ];
  return core.map(path => ({
    url: makeTarget(baseUrl, path),
    path,
    method: "GET",
    source: "CORE_SMOKE",
    advanced: false,
    core: true
  }));
}

function buildTargets(baseUrl, settings) {
  const entries = [];
  const source = globalThis.SPRINGBOOT_WORDLIST || [];

  for (const entry of source) {
    const meta = classifyEntry(entry);
    const rawPath = meta.raw;

    if (meta.special === "header") continue;
    if (isLikelyAdvanced(rawPath, meta.special) && !settings.includeAdvanced) continue;

    const parsed = parseEntryPath(rawPath);
    for (const p of expandTemplate(parsed.path)) {
      // Reconstruct port-prefixed paths correctly.
      const effectiveEntry = parsed.port ? `${parsed.port}${p}` : p;
      const target = makeTarget(baseUrl, effectiveEntry);
      entries.push({
        url: target,
        path: new URL(target).pathname + new URL(target).search,
        method: ["GET", "HEAD", "OPTIONS"].includes(meta.method) ? meta.method : "GET",
        source: entry,
        advanced: isLikelyAdvanced(rawPath, meta.special)
      });
    }
  }

  const dedup = new Map();
  for (const item of entries) {
    const key = `${item.method} ${item.url}`;
    if (!dedup.has(key)) dedup.set(key, item);
  }
  return [...dedup.values()];
}

function scorePriority(item) {
  const p = item.path.toLowerCase();
  let score = 0;
  if (/\/actuator\/?(env|configprops|heapdump|logfile|jolokia|beans|mappings|gateway|threaddump)/i.test(p)) score += 100;
  if (/\/(env|configprops|heapdump|logfile|jolokia|beans|mappings|gateway|threaddump)/i.test(p)) score += 90;
  if (/\/actuator\/?(health|info|metrics|prometheus|swagger-ui|swagger-ui\.html)/i.test(p)) score += 40;
  if (/swagger|openapi|api-docs/i.test(p)) score += 30;
  if (/^\/(health|info|metrics|prometheus|env)$/i.test(p)) score += 20;
  if (item.advanced) score -= 40;
  return score;
}

async function sleep(ms) {
  if (ms > 0) await new Promise(r => setTimeout(r, ms));
}

async function runPool(items, settings, onResult, scanId, tabId) {
  let index = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(settings.concurrency, items.length || 1)) }, async () => {
    while (true) {
      const i = index++;
      if (i >= items.length) return;
      if (!activeScans.has(scanId)) return;

      const item = items[i];
      const result = await probe(item.url, item.path, item.method, settings, tabId);
      if (result) {
        result.source = item.source;
        result.advanced = item.advanced;
        result.foundAt = now();
        onResult(result);
      }
      await sleep(settings.delayMs);
      await updateProgress(scanId, tabId, i + 1, items.length);
    }
  });
  await Promise.all(workers);
}

async function updateProgress(scanId, tabId, done, total) {
  const pct = total ? Math.round((done / total) * 100) : 100;
  const current = activeScans.get(scanId);
  if (!current) return;
  current.done = done;
  current.total = total;
  current.progress = pct;
  current.updatedAt = now();
  stateByTab.set(tabId, current);
  broadcast(tabId, { type: "scan_progress", state: current });
}

function broadcast(tabId, message) {
  chrome.runtime.sendMessage({ tabId, ...message }).catch(() => {});
}

async function persist(tabId) {
  const st = stateByTab.get(tabId);
  if (!st) return;
  const settings = await getSettings();
  if (!settings.persistResults) return;
  const all = (await chrome.storage.local.get("history")).history || [];
  const filtered = all.filter(x => x.tabId !== tabId);
  filtered.unshift({
    tabId,
    target: st.target,
    finishedAt: st.finishedAt || now(),
    results: st.results || [],
    fingerprint: st.fingerprint || null,
    stats: st.stats || {},
    techDetected: Boolean(st.techDetected),
    techFingerprint: st.techFingerprint || null
  });
  await chrome.storage.local.set({ history: filtered.slice(0, 30) });
}

function summarize(results) {
  const stats = { total: results.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of results) stats[r.severity] = (stats[r.severity] || 0) + 1;
  return stats;
}

async function startScan(tabId, scanType = "smart") {
  const tab = await chrome.tabs.get(tabId);
  if (!tab?.url || !isScannableUrl(tab.url)) {
    throw new Error("The active tab is not an HTTP(S) page.");
  }

  const settings = await getSettings();
  const effectiveSettings = { ...settings };
  if (scanType === "full") effectiveSettings.includeAdvanced = true;
  if (activeScans.has(tabId)) {
    activeScans.delete(tabId);
  }

  const scanId = `${tabId}:${now()}:${Math.random().toString(36).slice(2)}`;
  const target = new URL(tab.url);
  target.hash = "";
  const base = target.origin;

  let items = buildTargets(base, effectiveSettings);
  const wantsFull = scanType === "full";
  if (!wantsFull) {
    items = items
      .sort((a, b) => scorePriority(b) - scorePriority(a) || a.url.localeCompare(b.url))
      .slice(0, 160);
  } else {
    items = items.slice(0, 2400);
  }

  const fingerprint = await fingerprintTab(tabId, tab.url);
  const pageEvidence = await currentPageEvidence(tabId, tab.url);

  const likelySpringBoot =
    !!fingerprint?.detected ||
    !!pageEvidence?.signature ||
    /whitelabel error page|spring boot|org\.springframework\.boot/i.test(
      String(pageEvidence?.excerpt || "")
    );

  if (likelySpringBoot) {
    const core = buildCoreSmokeTargets(base);
    const merged = new Map();
    for (const item of [...core, ...items]) {
      const key = `${item.method} ${item.url}`;
      if (!merged.has(key)) merged.set(key, item);
    }
    items = [...merged.values()];
  }

  const st = {
    scanId,
    tabId,
    target: base,
    startedAt: now(),
    finishedAt: null,
    done: 0,
    total: items.length,
    progress: 0,
    running: true,
    scanType,
    results: pageEvidence ? [pageEvidence] : [],
    fingerprint,
    transportErrors: 0,
    lastError: null,
    stats: summarize(pageEvidence ? [pageEvidence] : [])
  };
  activeScans.set(scanId, st);
  stateByTab.set(tabId, st);
  chrome.action.setBadgeText({ tabId, text: "…" }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#2563eb" }).catch(() => {});
  broadcast(tabId, { type: "scan_started", state: st });

  const push = (result) => {
    const cur = stateByTab.get(tabId);
    if (!cur) return;
    if (result?.error) {
      cur.transportErrors = (cur.transportErrors || 0) + 1;
      cur.lastError = {
        path: result.path,
        method: result.method,
        errorCode: result.errorCode,
        transport: result.transport || "unknown"
      };
      stateByTab.set(tabId, cur);
      broadcast(tabId, { type: "transport_error", state: cur });
      return;
    }
    cur.results.push(result);
    cur.results.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.status - a.status);
    cur.results = cur.results.slice(0, settings.maxResults);
    cur.stats = summarize(cur.results);
    stateByTab.set(tabId, cur);
    activeScans.set(scanId, cur);
    chrome.action.setBadgeText({ tabId, text: String(cur.stats.critical + cur.stats.high).slice(0, 3) }).catch(() => {});
    const color = cur.stats.critical ? "#dc2626" : cur.stats.high ? "#ea580c" : cur.stats.medium ? "#ca8a04" : "#2563eb";
    chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
    broadcast(tabId, { type: "result", result, state: cur });
  };

  await runPool(items, effectiveSettings, push, scanId, tabId);

  const end = stateByTab.get(tabId);
  if (end) {
    end.running = false;
    end.finishedAt = now();
    end.progress = 100;
    end.stats = summarize(end.results);
    stateByTab.set(tabId, end);
    activeScans.delete(scanId);
    broadcast(tabId, { type: "scan_finished", state: end });
    await persist(tabId);
  }
}

async function maybeAutoScan(tabId, changeInfo, tab) {
  if (changeInfo.status !== "complete" || !tab?.url || !isScannableUrl(tab.url)) return;
  const settings = await getSettings();
  if (!settings.autoScan) return;

  if (autoTimers.has(tabId)) clearTimeout(autoTimers.get(tabId));
  const timer = setTimeout(() => {
    autoTimers.delete(tabId);
    startScan(tabId, settings.autoMode === "full" ? "full" : "smart").catch(() => {});
  }, 1400);
  autoTimers.set(tabId, timer);
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  }
  maybeAutoScan(tabId, changeInfo, tab);
});
chrome.tabs.onRemoved.addListener((tabId) => {
  if (autoTimers.has(tabId)) clearTimeout(autoTimers.get(tabId));
  autoTimers.delete(tabId);
  stateByTab.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (message.type === "start_scan") {
        const tabId = message.tabId ?? sender.tab?.id;
        await startScan(tabId, message.scanType || "smart");
        sendResponse({ ok: true });
        return;
      }
      if (message.type === "ui_font_changed") {
        const current = await getSettings();
        const px = Math.min(24, Math.max(12, Number(message.uiFontSizePx ?? message.fontSizePx) || 16));
        await chrome.storage.local.set({
          settings: { ...current, fontSizePx: px, uiFontSizePx: px }
        });
        chrome.runtime.sendMessage({
          type: "ui_font_changed",
          fontSizePx: px,
          uiFontSizePx: px
        }).catch(() => {});
        sendResponse({ ok: true });
        return;
      }

      if (message.type === "springboot_detected") {
        const tabId = sender.tab?.id ?? message.tabId;
        if (tabId != null) {
          const fp = stateByTab.get(tabId) || {
            tabId,
            target: sender.tab?.url || "",
            startedAt: now(),
            results: [],
            stats: summarize([])
          };
          fp.techDetected = Boolean(message.detected);
          fp.techFingerprint = message.result || null;
          stateByTab.set(tabId, fp);

          if (message.detected) {
            chrome.action.setBadgeText({ tabId, text: "SB" }).catch(() => {});
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#dc2626" }).catch(() => {});
          } else {
            // Do not clear an exposure-count badge.
            if (!fp.stats || !(fp.stats.critical + fp.stats.high)) {
              chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
            }
          }
        }
        sendResponse({ ok: true });
        return;
      }
      if (message.type === "get_state") {
        const st = stateByTab.get(message.tabId);
        sendResponse({ ok: true, state: st || null });
        return;
      }
      if (message.type === "set_auto_scan") {
        const current = await getSettings();
        await chrome.storage.local.set({ settings: { ...current, autoScan: Boolean(message.enabled), autoMode: message.mode || current.autoMode } });
        sendResponse({ ok: true });
        return;
      }
      if (message.type === "get_settings") {
        sendResponse({
          ok: true,
          settings: await getSettings(),
          wordlistCount: globalThis.SPRINGBOOT_WORDLIST.length,
          wordlistSourceLines: String(globalThis.SPRINGBOOT_WORDLIST_RAW || "").split("\n").length
        });
        return;
      }
      if (message.type === "fingerprint") {
        if (sender.tab?.id) {
          const fp = await fingerprintTab(sender.tab.id, sender.tab.url);
          const st = stateByTab.get(sender.tab.id);
          if (st) {
            st.fingerprint = fp;
            stateByTab.set(sender.tab.id, st);
          }
          sendResponse({ ok: true, fingerprint: fp });
        } else {
          sendResponse({ ok: false });
        }
        return;
      }
      if (message.type === "stop_scan") {
        const st = stateByTab.get(message.tabId);
        if (st?.scanId) {
          activeScans.delete(st.scanId);
          st.running = false;
          st.finishedAt = now();
          st.progress = st.total ? Math.min(99, Math.round((st.done / st.total) * 100)) : 0;
          stateByTab.set(message.tabId, st);
          broadcast(message.tabId, { type: "scan_stopped", state: st });
          await persist(message.tabId);
        }
        sendResponse({ ok: true });
        return;
      }
      if (message.type === "clear_history") {
        await chrome.storage.local.set({ history: [] });
        stateByTab.delete(message.tabId);
        chrome.action.setBadgeText({ tabId: message.tabId, text: "" }).catch(() => {});
        sendResponse({ ok: true });
        return;
      }
      if (message.type === "export_results") {
        const st = stateByTab.get(message.tabId);
        sendResponse({ ok: true, state: st || null });
        return;
      }
      sendResponse({ ok: false, error: "Unknown message" });
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();
  return true;
});

chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get("settings");
  await chrome.storage.local.set({ settings: normalizeSettings(current.settings) });
});
