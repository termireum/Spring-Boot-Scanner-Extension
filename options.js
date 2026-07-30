const $ = (id) => document.getElementById(id);

function applyPreview(px) {
  const value = Math.min(24, Math.max(12, Number(px) || 16));
  document.documentElement.style.setProperty("--preview-font-size", `${value}px`);
}

async function loadSettings() {
  const r = await chrome.runtime.sendMessage({type:"get_settings"});
  if (!r?.ok) return;

  const s = r.settings;
  $("autoMode").value = s.autoMode || "smart";
  $("fontSizePx").value = String(s.uiFontSizePx ?? s.fontSizePx ?? 16);
  $("secretScan").checked = s.secretScan !== false;
  $("concurrency").value = s.concurrency ?? 24;
  $("delayMs").value = s.delayMs ?? 0;
  $("timeoutMs").value = s.timeoutMs ?? 3000;
  $("advanced").checked = !!s.includeAdvanced;
  $("persist").checked = s.persistResults !== false;

  applyPreview(Number($("fontSizePx").value) || 16);
}

$("fontSizePx").addEventListener("change", () => {
  applyPreview(Number($("fontSizePx").value));
});

$("save").addEventListener("click", async () => {
  const currentResponse = await chrome.runtime.sendMessage({type:"get_settings"});
  const current = currentResponse?.settings || {};
  const px = Math.min(24, Math.max(12, Number($("fontSizePx").value) || 16));

  const next = {
    ...current,
    autoMode: $("autoMode").value,
    fontSizePx: px,
    uiFontSizePx: px,
    secretScan: $("secretScan").checked,
    concurrency: Math.min(32, Math.max(1, Number($("concurrency").value) || 24)),
    delayMs: Math.min(2000, Math.max(0, Number($("delayMs").value) || 0)),
    timeoutMs: Math.min(30000, Math.max(1000, Number($("timeoutMs").value) || 3000)),
    includeAdvanced: $("advanced").checked,
    persistResults: $("persist").checked
  };

  await chrome.storage.local.set({settings: next});
  applyPreview(px);
  $("saved").textContent = `Saved at ${px}px`;

  try {
    chrome.runtime.sendMessage({
      type:"ui_font_changed",
      fontSizePx:px,
      uiFontSizePx:px
    }).catch(()=>{});
  } catch {}

  setTimeout(() => $("saved").textContent = "", 1800);
});

loadSettings();
