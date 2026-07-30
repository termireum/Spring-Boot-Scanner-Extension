
let tabId = null;
let state = null;
let settings = null;
let collapsed = false;

const $ = id => document.getElementById(id);

function fmt(n) {
  return new Intl.NumberFormat().format(n || 0);
}

function applyFontSize(px) {
  const value = Math.min(24, Math.max(12, Number(px) || 16));
  const factor = value / 13;
  document.documentElement.style.setProperty("--ui-font-size", `${value}px`);
  document.documentElement.style.setProperty("--ui-font-factor", String(factor));
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

function severityRank(s) {
  return ({critical:5,high:4,medium:3,low:2,info:1}[s] || 0);
}

function renderTechnology(s) {
  const tech = s?.techFingerprint;
  const detected = Boolean(s?.techDetected || tech?.detected);

  $("techTitle").textContent = detected ? "Spring Boot detected" : "Technology not confirmed";
  $("techReason").textContent = detected
    ? (tech?.label || "Spring Boot fingerprint detected")
    : "No strong Spring Boot marker found";
  $("confidence").textContent = detected ? `${Number(tech?.confidence || 0)}%` : "—";

  const dot = $("statusDot");
  dot.style.background = detected ? "#ef4444" : "#334155";
  dot.style.boxShadow = detected
    ? "0 0 0 5px rgba(239,68,68,.14)"
    : "0 0 0 5px rgba(51,65,85,.14)";

  const signals = tech?.signals || s?.fingerprint?.markers || [];
  $("signals").innerHTML = (signals.length ? signals.slice(0,6) : []).map(x => {
    const label = typeof x === "string" ? x : x.label;
    return `<span class="signal-chip">${escapeHtml(label)}</span>`;
  }).join("") || `<span class="signal-chip">Passive fingerprint pending</span>`;

  const detailSignals = tech?.signals || [];
  const root = $("signalDetails");
  if (!detailSignals.length) {
    root.className = "signal-details empty-box";
    root.textContent = "No strong technology signals yet.";
  } else {
    root.className = "signal-details";
    root.innerHTML = detailSignals.slice(0,8).map(x => `
      <div class="signal-detail">
        <b>${escapeHtml(x.label || "Signal")}</b>
        <span>Confidence contribution: ${escapeHtml(x.strength ?? "—")}%</span>
      </div>
    `).join("");
  }
}

function renderOverview(s) {
  const target = s?.target || "";
  $("target").textContent = target || "No active HTTP(S) tab";

  try {
    const u = new URL(target);
    $("origin").textContent = u.hostname + (u.port ? `:${u.port}` : "");
    $("protocol").textContent = u.protocol.replace(":", "").toUpperCase();
  } catch {
    $("origin").textContent = "—";
    $("protocol").textContent = "—";
  }

  const st = s?.stats || {};
  $("critical").textContent = st.critical || 0;
  $("high").textContent = st.high || 0;
  $("medium").textContent = st.medium || 0;
  $("low").textContent = st.low || 0;
  $("hits").textContent = st.total || 0;

  const secrets = (s?.results || []).reduce((n,r) => n + (r.secretFindings?.length || 0), 0);
  $("secretsCount").textContent = secrets;

  $("wordlistCount").textContent = "915 unique / 1,064 lines";
  $("requestCount").textContent = fmt(s?.total || 0);
  $("phase").textContent = s?.phase || "Idle";
  $("transportErrors").textContent = fmt(s?.transportErrors || 0);

  const lastError = $("lastError");
  if (s?.lastError) {
    lastError.classList.remove("hidden");
    lastError.textContent = `Transport diagnostic: ${s.lastError.errorCode} · ${s.lastError.path || "unknown path"}`;
  } else {
    lastError.classList.add("hidden");
  }

  const p = Math.min(100, Math.max(0, Number(s?.progress || 0)));
  $("progressBar").style.width = `${p}%`;
  $("progressPercent").textContent = `${p}%`;

  if (s?.running) {
    $("progressText").textContent =
      `${s.phase === "deep" ? "Deep scan" : "Fast sweep"} · ${fmt(s.done)} / ${fmt(s.total)}`;
  } else if (s?.phase === "stopped") {
    $("progressText").textContent = "Scan stopped";
  } else if (s) {
    $("progressText").textContent = `Complete · ${fmt(s.total)} probes`;
  } else {
    $("progressText").textContent = "Idle";
  }

  $("scanPriority").disabled = Boolean(s?.running);
  $("scanFull").disabled = Boolean(s?.running);
  $("stop").classList.toggle("hidden", !s?.running);
}

function filteredFindings() {
  const filter = $("severityFilter").value;
  const rows = [...(state?.results || [])];

  rows.sort((a,b) =>
    severityRank(b.severity) - severityRank(a.severity) ||
    (b.status || 0) - (a.status || 0)
  );

  return rows.filter(r => filter === "all" || r.severity === filter);
}

function renderResults() {
  const root = $("results");
  if (collapsed) {
    root.innerHTML = "";
    $("resultMeta").textContent = "Collapsed";
    return;
  }

  const rows = filteredFindings();
  $("resultMeta").textContent = `${fmt(rows.length)} visible · ${fmt(state?.results?.length || 0)} total`;

  if (!rows.length) {
    root.innerHTML = `<div class="empty-box">No findings for the selected filter.</div>`;
    return;
  }

  root.innerHTML = rows.map((r, i) => {
    const excerpt = r.excerpt || "";
    const secretCount = r.secretFindings?.length || 0;

    return `
      <article class="finding">
        <div class="finding-top">
          <span class="badge ${escapeHtml(r.severity)}">${escapeHtml(r.severity)}</span>
          <div class="finding-title">${escapeHtml(r.title)}</div>
        </div>

        <div class="finding-path">${escapeHtml(r.path || r.url)}</div>

        <div class="finding-meta">
          <span>HTTP ${escapeHtml(r.status)}</span>
          <span>${escapeHtml(r.method || "GET")}</span>
          <span>${escapeHtml(r.contentType || "unknown")}</span>
          <span>${escapeHtml(r.durationMs || 0)} ms</span>
          <span>${escapeHtml(r.transport || "unknown")}</span>
          ${secretCount ? `<span>${secretCount} secret matches</span>` : ""}
        </div>

        ${excerpt ? `
          <div class="finding-excerpt" id="excerpt-${i}">
            ${escapeHtml(excerpt)}
          </div>` : ""}

        <button class="finding-toggle" data-url="${escapeHtml(r.finalUrl || r.url)}">
          Open endpoint in new tab ↗
        </button>
      </article>
    `;
  }).join("");

  [...root.querySelectorAll(".finding-toggle")].forEach(btn => {
    btn.addEventListener("click", () => {
      const url = btn.dataset.url;
      if (url) chrome.tabs.create({url});
    });
  });
}

function renderSecrets() {
  const root = $("secretResults");
  const matches = [];

  for (const r of (state?.results || [])) {
    for (const s of (r.secretFindings || [])) {
      matches.push({
        severity:s.severity || r.severity || "high",
        type:s.type || "Sensitive value",
        location:s.location || r.path,
        context:s.context || ""
      });
    }
  }

  $("secretState").textContent = settings?.secretScan === false ? "Disabled" : "Enabled";

  if (!matches.length) {
    root.innerHTML = `<div class="empty-box">No secrets or sensitive credentials detected.</div>`;
    return;
  }

  root.innerHTML = matches.slice(0,40).map(s => `
    <article class="secret-item">
      <div class="secret-head">
        <span class="badge ${escapeHtml(s.severity)}">${escapeHtml(s.severity)}</span>
        <span class="secret-type">${escapeHtml(s.type)}</span>
      </div>
      <div class="secret-path">${escapeHtml(s.location)}</div>
      <div class="secret-context">${escapeHtml(s.context)}</div>
    </article>
  `).join("");
}

function renderPageEvidence() {
  const fp = state?.techFingerprint || state?.fingerprint;
  const root = $("pageEvidence");

  if (!fp) {
    root.innerHTML = `<div class="empty-box">No current-page evidence.</div>`;
    return;
  }

  const resources = (fp.resources || []).slice(0,6);

  root.innerHTML = `
    <div class="evidence-card">
      <div class="evidence-grid">
        <div><div class="e-label">URL</div><div class="e-value">${escapeHtml(fp.url || state?.target || "—")}</div></div>
        <div><div class="e-label">Confidence</div><div class="e-value">${escapeHtml(fp.confidence ?? "—")}%</div></div>
        <div><div class="e-label">Detection</div><div class="e-value">${escapeHtml(fp.label || "Spring Boot fingerprint")}</div></div>
        <div><div class="e-label">Signals</div><div class="e-value">${fmt((fp.signals || fp.markers || []).length)}</div></div>
      </div>
      ${fp.excerpt ? `<div class="evidence-excerpt">${escapeHtml(fp.excerpt)}</div>` : ""}
      ${resources.length ? `<div class="evidence-excerpt">${resources.map(escapeHtml).join("<br>")}</div>` : ""}
    </div>
  `;
}

function render(s) {
  state = s || null;
  renderTechnology(state);
  renderOverview(state);
  renderResults();
  renderSecrets();
  renderPageEvidence();

  const auto = settings?.autoScan;
  $("autoScan").checked = Boolean(auto);
  $("autoMode").value = settings?.autoMode || "smart";
  $("modeText").textContent = auto
    ? `Automatic scan · ${settings?.autoMode === "full" ? "Full wordlist" : "Smart priority"}`
    : "Automatic scan is disabled";
}

async function load() {
  const tabs = await chrome.tabs.query({active:true,currentWindow:true});
  tabId = tabs[0]?.id || null;

  const settingsResponse = await chrome.runtime.sendMessage({type:"get_settings"});
  if (settingsResponse?.ok) {
    settings = settingsResponse.settings;
    applyFontSize(settings.uiFontSizePx ?? settings.fontSizePx ?? 16);
  }

  const stateResponse = tabId
    ? await chrome.runtime.sendMessage({type:"get_state",tabId})
    : null;

  render(stateResponse?.state || null);

  if (tabId) {
    try {
      const fp = await chrome.runtime.sendMessage({type:"fingerprint"});
      if (fp?.ok && fp.fingerprint?.detected) {
        await chrome.runtime.sendMessage({
          type:"springboot_detected",
          tabId,
          detected:true,
          result:fp.fingerprint
        });
        const fresh = await chrome.runtime.sendMessage({type:"get_state",tabId});
        render(fresh?.state || null);
      }
    } catch {}
  }
}

async function start(type) {
  if (!tabId) return;
  const result = await chrome.runtime.sendMessage({
    type:"start_scan",
    tabId,
    scanType:type
  });
  if (!result?.ok) {
    $("progressText").textContent = result?.error || "Unable to start scan";
  }
}

$("scanPriority").addEventListener("click", () => start("smart"));
$("scanFull").addEventListener("click", () => start("full"));

$("stop").addEventListener("click", async () => {
  if (tabId) await chrome.runtime.sendMessage({type:"stop_scan",tabId});
});

$("autoScan").addEventListener("change", async () => {
  await chrome.runtime.sendMessage({
    type:"set_auto_scan",
    tabId,
    enabled:$("autoScan").checked,
    mode:$("autoMode").value
  });
  const res = await chrome.runtime.sendMessage({type:"get_settings"});
  settings = res.settings;
  render(state);
});

$("autoMode").addEventListener("change", async () => {
  await chrome.runtime.sendMessage({
    type:"set_auto_scan",
    tabId,
    enabled:$("autoScan").checked,
    mode:$("autoMode").value
  });
  const res = await chrome.runtime.sendMessage({type:"get_settings"});
  settings = res.settings;
  render(state);
});

$("severityFilter").addEventListener("change", renderResults);

$("collapseFindings").addEventListener("click", () => {
  collapsed = !collapsed;
  $("collapseFindings").textContent = collapsed ? "Expand" : "Collapse";
  renderResults();
});

$("refresh").addEventListener("click", load);
$("settingsTop").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("settingsBottom").addEventListener("click", () => chrome.runtime.openOptionsPage());

function downloadText(name, text, type) {
  const blob = new Blob([text], {type});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 800);
}

$("exportJson").addEventListener("click", () => {
  if (!state) return;
  downloadText("springboot-scan.json", JSON.stringify(state,null,2), "application/json");
});

$("exportCsv").addEventListener("click", () => {
  const rows = state?.results || [];
  const headers = ["severity","status","method","path","title","signature","contentType","contentLength","finalUrl","transport","excerpt"];
  const csv = [
    headers.join(","),
    ...rows.map(r => headers.map(h => `"${String(r[h] ?? "").replaceAll('"','""')}"`).join(","))
  ].join("\n");
  downloadText("springboot-scan.csv", csv, "text/csv");
});

$("clear").addEventListener("click", async () => {
  if (!tabId) return;
  await chrome.runtime.sendMessage({type:"clear_history",tabId});
  state = null;
  render(null);
});

chrome.runtime.onMessage.addListener(message => {
  if (message.type === "ui_font_changed") {
    applyFontSize(message.uiFontSizePx ?? message.fontSizePx ?? 16);
    return;
  }

  if (message.tabId !== tabId) return;

  if (["scan_started","scan_progress","result","scan_finished","transport_error"].includes(message.type)) {
    render(message.state || state);
  }
});

load();
