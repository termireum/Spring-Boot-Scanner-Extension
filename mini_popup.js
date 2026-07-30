
let tabId = null;
let state = null;

const $ = id => document.getElementById(id);

function fmt(n) {
  return new Intl.NumberFormat().format(n || 0);
}

function render(s) {
  state = s || null;

  const url = s?.target || "";
  $("target").textContent = url || "No active HTTP(S) tab";

  const tech = s?.techFingerprint;
  const detected = Boolean(s?.techDetected || tech?.detected);

  $("techBadge").textContent = detected ? "SPRING BOOT" : "UNKNOWN";
  $("techBadge").className = detected ? "badge ok" : "badge neutral";

  $("techReason").textContent = detected
    ? (tech?.label || "Spring Boot fingerprint detected")
    : "No strong Spring Boot technology signal detected";

  $("statusDot").style.background =
    s?.running ? "#60a5fa" : detected ? "#ef4444" : "#334155";

  const stats = s?.stats || {};
  $("findingCount").textContent = fmt(stats.total);
  $("criticalCount").textContent = fmt(stats.critical);

  const secretCount = (s?.results || []).reduce(
    (n, r) => n + (r.secretFindings?.length || 0), 0
  );
  $("secretCount").textContent = fmt(secretCount);

  const progress = Number(s?.progress || 0);
  $("bar").style.width = `${progress}%`;

  if (s?.running) {
    $("progressText").textContent =
      `${s.phase === "deep" ? "Deep scan" : "Scanning"} ${fmt(s.done)} / ${fmt(s.total)}`;
  } else {
    $("progressText").textContent =
      s?.phase === "stopped" ? "Stopped" :
      s ? `Complete · ${fmt(s.total)} probes` : "Idle";
  }

  $("entries").textContent = "915 unique";
  $("scanSmart").disabled = Boolean(s?.running);
  $("scanFull").disabled = Boolean(s?.running);
  $("stop").classList.toggle("hidden", !s?.running);
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({active:true,currentWindow:true});
  return tabs[0];
}

async function refresh() {
  const tab = await getActiveTab();
  tabId = tab?.id || null;

  const result = tabId
    ? await chrome.runtime.sendMessage({type:"get_state", tabId})
    : null;

  render(result?.state || null);

  // Ask content script for the latest detector state if the service worker
  // doesn't have it yet.
  if (tabId && !result?.state?.techDetected) {
    const fp = await chrome.runtime.sendMessage({type:"fingerprint"});
    if (fp?.ok && fp.fingerprint?.detected) {
      const r = await chrome.runtime.sendMessage({
        type:"springboot_detected",
        tabId,
        detected:true,
        result:fp.fingerprint
      });
      if (r?.ok) {
        const stateResult = await chrome.runtime.sendMessage({type:"get_state",tabId});
        render(stateResult?.state || null);
      }
    }
  }
}

async function start(type) {
  if (!tabId) return;
  const r = await chrome.runtime.sendMessage({
    type:"start_scan",
    tabId,
    scanType:type
  });
  if (!r?.ok) {
    $("progressText").textContent = r?.error || "Unable to start scan";
  }
}

$("scanSmart").addEventListener("click", () => start("smart"));
$("scanFull").addEventListener("click", () => start("full"));
$("stop").addEventListener("click", async () => {
  if (tabId) await chrome.runtime.sendMessage({type:"stop_scan",tabId});
});
$("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("export").addEventListener("click", async () => {
  if (!state) return;
  const blob = new Blob([JSON.stringify(state,null,2)], {type:"application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "springboot-scan.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

chrome.runtime.onMessage.addListener(message => {
  if (message.tabId !== tabId) return;
  if (["scan_started","scan_progress","result","scan_finished"].includes(message.type)) {
    render(message.state);
  }
});

refresh();
