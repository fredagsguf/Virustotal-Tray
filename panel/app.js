/* The panel only draws VT_DATA. The tray owns the API. */

const panel = document.getElementById("panel");

const state = {
  data: window.VT_DATA || { updatedAt: "", apiKeySet: false, activity: "", notice: "", scans: [] },
  filter: localStorage.getItem("vt-tray-filter") || localStorage.getItem("vt-hotbar-filter") || "all",
  selectedId: localStorage.getItem("vt-tray-scan") || localStorage.getItem("vt-hotbar-scan") || "",
  lastTop: "",
  command: "",
  commandSeq: 0,
  closing: false,
  detailsOpen: false,
  settingsOpen: false,
  lookupValue: "",
};

const ICON = {
  key: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M5.5 7a3.5 3.5 0 1 1 6.2 2.2l-1.1 1.1-.5 2.5-1.5-1.5-1.5 1.5-1-1 1.5-1.5-1.5-1.5 2.5-.5 1.1-1.1A3.48 3.48 0 0 1 5.5 7Z" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  arrow: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 8h8M9 5l3 3-3 3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  file: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M9 2.5H5.5A1.5 1.5 0 0 0 4 4v8a1.5 1.5 0 0 0 1.5 1.5h5A1.5 1.5 0 0 0 12 12V6.5L9 2.5Z" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M9 2.5V6.5H12M8 9.5v3M6.5 11H9.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  chevron: '<svg class="chev" width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M4 6l4 4 4-4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  gear: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M10.3 3.3h3.4l.3 1.7c.4.2.8.4 1.2.6l1.6-.6 1.7 2.9-1.3 1.1c.1.3.1.7.1 1s0 .7-.1 1l1.3 1.1-1.7 2.9-1.6-.6c-.4.2-.8.4-1.2.6l-.3 1.7h-3.4l-.3-1.7c-.4-.2-.8-.4-1.2-.6l-1.6.6-1.7-2.9 1.3-1.1c-.1-.3-.1-.7-.1-1s0-.7.1-1L5.5 7.9l1.7-2.9 1.6.6c.4-.2.8-.4 1.2-.6l.3-1.7Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><circle cx="12" cy="12" r="2.2" stroke="currentColor" stroke-width="1.8"/></svg>',
};

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

function scans() {
  return Array.isArray(state.data.scans) ? state.data.scans : [];
}

function statsOf(scan) {
  const stats = scan.stats || {};
  const keys = ["malicious", "suspicious", "undetected", "harmless", "timeout", "failure"];
  const total = keys.reduce((sum, key) => sum + (Number(stats[key]) || 0), 0);
  return {
    malicious: Number(stats.malicious) || 0,
    suspicious: Number(stats.suspicious) || 0,
    total,
  };
}

function verdict(scan) {
  if (!scan) return "pending";
  if (scan.status === "error") return "error";
  if (scan.status !== "completed" && !(scan.phase === "queued" && statsOf(scan).total > 0)) return "pending";
  const stats = statsOf(scan);
  if (stats.malicious > 0) return "malicious";
  if (stats.suspicious > 0) return "suspicious";
  return "clean";
}

function ratioText(scan) {
  if (scan.status === "error") return "Error";
  if (scan.status !== "completed" && !(scan.phase === "queued" && statsOf(scan).total > 0)) return "…";
  const stats = statsOf(scan);
  if (!stats.total) return "0";
  return (stats.malicious || stats.suspicious) + "/" + stats.total;
}

function verdictHeadline(scan) {
  const kind = verdict(scan);
  if (kind === "error") return "Scan failed";
  if (kind === "pending") {
    if (scan.status === "hashing") return "Hashing";
    if (scan.status === "checking") return "Checking";
    if (scan.status === "uploading") return "Uploading";
    return "Scanning";
  }
  const stats = statsOf(scan);
  if (kind === "malicious") {
    const n = stats.malicious;
    return n + " engine" + (n === 1 ? "" : "s") + " flagged";
  }
  if (kind === "suspicious") return stats.suspicious + " flagged as suspicious";
  return "Clean";
}

function formatSize(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return "";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10 * 1024 ? 1 : 0) + " KB";
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0) + " MB";
  return (n / (1024 * 1024 * 1024)).toFixed(1) + " GB";
}

function formatAgo(iso) {
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return "";
  const ms = Date.now() - then;
  if (ms < 0) return "just now";
  const minutes = Math.floor(ms / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return minutes + "m ago";
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + "h ago";
  const days = Math.floor(hours / 24);
  return days + "d ago";
}

function visibleScans() {
  return scans().filter((scan) => {
    const kind = verdict(scan);
    if (state.filter === "flagged") return kind === "malicious" || kind === "suspicious";
    if (state.filter === "clean") return kind === "clean";
    return true;
  });
}

function scanId(scan) {
  return String((scan && (scan.id || scan.sha256)) || "");
}

function scanKind(scan) {
  return (scan && scan.kind) || "file";
}

function selectedScan() {
  return scans().find((scan) => scanId(scan) === state.selectedId) || null;
}

function meterWidth(scan) {
  const kind = verdict(scan);
  if (kind === "pending") return 36;
  if (kind === "error") return 0;
  if (kind === "clean") return 100;
  const stats = statsOf(scan);
  if (!stats.total) return 0;
  return Math.max(6, Math.min(100, ((stats.malicious || stats.suspicious) / stats.total) * 100));
}

function sourceText(scan) {
  if (scan.source === "uploaded") return "Uploaded";
  if (scan.source === "submitted") return "Submitted";
  if (scan.source === "known") return "Already on VirusTotal";
  if (scan.source === "rescan") return "Rescanned";
  return "";
}

function statusLine(scan) {
  if (scan.status === "error") return scan.error || "Scan failed";
  if (scan.status === "hashing") return "Hashing";
  if (scan.status === "checking") return "Checking VirusTotal";
  if (scan.status === "uploading") return "Uploading";
  if (scan.status === "scanning" && scan.phase === "queued") return "Rescan queued";
  if (scan.status === "scanning") return "Waiting for engines";
  const parts = [];
  const source = sourceText(scan);
  if (scan.threatLabel) parts.push(scan.threatLabel);
  else if (source) parts.push(source);
  if (scan.typeDescription) parts.push(scan.typeDescription);
  if (scanKind(scan) === "file") {
    const size = formatSize(scan.size);
    if (size) parts.push(size);
  }
  const ago = formatAgo(scan.scannedAt);
  if (ago) parts.push(ago);
  return parts.join(" · ");
}

function resultMeta(scan) {
  if (scan.status === "error") return scan.error || "Scan failed";
  return statusLine(scan);
}

function headerStatus() {
  if (state.data.activity) return state.data.activity;
  if (!state.data.apiKeySet) return "API key needed";
  return "";
}

function syncLookupFilled(input) {
  const form = input && input.closest(".lookup");
  if (form) form.classList.toggle("has-value", !!(input.value || "").trim());
}

function ask(command) {
  state.closing = false;
  state.command = command;
  applyTitle();
}

function applyTitle() {
  if (state.closing) document.title = "VirusTotal Tray - close";
  else if (state.command) document.title = state.command;
  else document.title = "VirusTotal Tray";
}

function render() {
  const scroll = panel.scrollTop;
  const previousLookup = document.getElementById("lookup");
  const lookupValue = previousLookup ? previousLookup.value : (state.lookupValue || "");
  state.lookupValue = lookupValue;
  const lookupFocused = previousLookup && document.activeElement === previousLookup;
  const lookupStart = previousLookup ? previousLookup.selectionStart : null;
  const lookupEnd = previousLookup ? previousLookup.selectionEnd : null;
  const list = visibleScans();
  const current = selectedScan();
  const kind = current ? verdict(current) : "pending";
  const parts = [];
  const allScans = scans();
  const status = headerStatus();

  parts.push(`<header class="top"><div class="brand"><img class="mark" alt="" src="assets/favicon.svg?v=4"><div class="titles"><h1>VirusTotal</h1>`);
  if (status) parts.push(`<p class="status">${esc(status)}</p>`);
  parts.push(`</div></div><div class="head-actions"><button class="icon-btn" type="button" data-action="key" title="API key" aria-label="API key">${ICON.key}</button><button class="icon-btn${state.settingsOpen ? " on" : ""}" type="button" data-action="settings" title="Settings" aria-label="Settings" aria-pressed="${state.settingsOpen ? "true" : "false"}">${ICON.gear}</button></div></header>`);

  if (state.settingsOpen) {
    const watch = !!state.data.watchDownloads;
    const notify = !!state.data.notifyFlagged;
    parts.push(`<section class="settings"><div class="setting"><div><p class="setting-title">Watch Downloads</p><p class="setting-copy">Scan new files saved to your Downloads folder. Sent files join the VirusTotal community dataset.</p></div><button class="toggle" type="button" role="switch" data-action="watch" aria-checked="${watch ? "true" : "false"}" aria-label="Watch Downloads"><span></span></button></div>`);
    parts.push(`<div class="setting"><div><p class="setting-title">Notify when flagged</p><p class="setting-copy">Show a notification if a downloaded file is malicious or suspicious.</p></div><button class="toggle" type="button" role="switch" data-action="notify" aria-checked="${notify ? "true" : "false"}" aria-disabled="${watch ? "false" : "true"}" aria-label="Notify when flagged"><span></span></button></div></section>`);
  } else {
  parts.push(`<div class="entry"><form class="lookup${lookupValue.trim() ? " has-value" : ""}"><input id="lookup" type="text" placeholder="Paste a URL or IP address" spellcheck="false" autocomplete="off" aria-label="URL or IP address"><button class="lookup-go" type="submit" aria-label="Scan URL or IP">${ICON.arrow}</button></form><button class="file-btn" type="button" data-action="scan" title="Scan a file (S)">${ICON.file}<span>File</span></button></div>`);

  if (!state.data.apiKeySet) {
    parts.push(`<div class="callout"><span>Add a VirusTotal API key to scan.</span><button class="link-btn" type="button" data-action="key">Add key</button></div>`);
  } else if (state.data.notice) {
    parts.push(`<div class="callout alert"><span>${esc(state.data.notice)}</span><button class="link-btn" type="button" data-action="key">Replace key</button></div>`);
  }

  if (current) {
    const width = meterWidth(current);
    const copyLabel = scanKind(current) === "url" ? "Copy URL" : scanKind(current) === "ip" ? "Copy IP" : "Copy hash";
    const idOk = scanId(current) && !scanId(current).startsWith("too-large-");
    const settled = current.status === "completed" || (current.phase === "queued" && statsOf(current).total > 0);

    parts.push(`<section class="result"><div class="verdict-row"><h2 class="verdict ${esc(kind)}">${esc(verdictHeadline(current))}</h2>${settled ? `<span class="ratio-head ${esc(kind)}">${esc(ratioText(current))}</span>` : ""}</div>`);
    parts.push(`<p class="target-name">${esc(current.name || scanId(current))}</p>`);
    parts.push(`<p class="target-meta">${esc(resultMeta(current))}</p>`);
    parts.push(`<div class="meter ${esc(kind)}"><span style="width:${width}%"></span></div>`);
    parts.push(`<div class="action-row">`);
    if (settled && idOk) parts.push(`<button class="text-btn accent" type="button" data-action="open">Open report</button>`);
    if (settled && idOk) parts.push(`<button class="text-btn" type="button" data-action="rescan">Rescan</button>`);
    if (idOk) parts.push(`<button class="text-btn" type="button" data-action="copy">${copyLabel}</button>`);
    parts.push(`</div>`);

    const hits = Array.isArray(current.hits) ? current.hits : [];
    if (hits.length) {
      parts.push(`<div class="detections"><h3>Detections</h3><div class="hits">`);
      hits.slice(0, 12).forEach((hit) => {
        const cat = hit.category === "suspicious" ? "suspicious" : "malicious";
        parts.push(`<div class="hit"><span class="hit-engine">${esc(hit.engine || "Engine")}</span><b class="${cat}">${esc(hit.result || cat)}</b></div>`);
      });
      parts.push(`</div></div>`);
    }

    const hasHash = /^[a-f0-9]{64}$/.test(current.sha256 || "");
    const hasPath = !!current.path;
    if (hasHash || hasPath) {
      parts.push(`<details class="more"${state.detailsOpen ? " open" : ""}><summary>${ICON.chevron}<span>Details</span></summary><div class="more-body">`);
      if (hasHash) parts.push(`<p class="hash">${esc(current.sha256)}</p>`);
      if (hasPath) parts.push(`<p class="path">${esc(current.path)}</p>`);
      parts.push(`</div></details>`);
    }
    parts.push(`</section>`);
  }

  parts.push(`<section class="recent"><div class="recent-head"><h3>Recent</h3>`);
  if (allScans.length >= 2) {
    parts.push(`<div class="seg">${["all", "flagged", "clean"].map((filter) => {
      const label = filter.charAt(0).toUpperCase() + filter.slice(1);
      return `<button class="seg-btn${state.filter === filter ? " on" : ""}" type="button" data-filter="${filter}">${label}</button>`;
    }).join("")}</div>`);
  }
  parts.push(`</div>`);

  if (!allScans.length) {
    parts.push(`<p class="empty">Paste a URL or IP above, choose a file, or drop files on VirusTotal Tray.exe.</p>`);
  } else if (!list.length) {
    parts.push(`<p class="empty">${state.filter === "flagged" ? "No flagged scans." : "No clean scans."}</p>`);
  } else {
    parts.push(`<div class="list">`);
    list.forEach((scan) => {
      const rowKind = verdict(scan);
      const selected = scanId(scan) === state.selectedId ? " selected" : "";
      parts.push(`<button class="row${selected}" type="button" data-id="${esc(scanId(scan))}"><span class="row-main"><span class="dot ${esc(rowKind)}" aria-hidden="true"></span><span class="row-name">${esc(scan.name || scanId(scan))}</span><span class="row-ratio ${esc(rowKind)}">${esc(ratioText(scan))}</span></span><span class="row-sub">${esc(statusLine(scan))}</span></button>`);
    });
    parts.push(`</div>`);
  }
  parts.push(`</section>`);
  }

  parts.push(`<p class="footer">Submissions are shared with the VirusTotal community.</p>`);

  panel.innerHTML = parts.join("");
  panel.scrollTop = scroll;
  const lookup = document.getElementById("lookup");
  if (lookup) {
    lookup.value = lookupValue;
    syncLookupFilled(lookup);
    if (lookupFocused || state.focusLookup) {
      lookup.focus();
      if (lookupFocused && lookupStart != null) lookup.setSelectionRange(lookupStart, lookupEnd);
      else lookup.setSelectionRange(lookup.value.length, lookup.value.length);
    }
  }
  state.focusLookup = false;
  applyTitle();
}

function selectBy(delta) {
  const list = visibleScans();
  if (!list.length) return;
  const index = list.findIndex((scan) => scanId(scan) === state.selectedId);
  const next = list[(Math.max(0, index) + delta + list.length) % list.length];
  state.selectedId = scanId(next);
  localStorage.setItem("vt-tray-scan", state.selectedId);
  render();
}

function followLatest() {
  const top = scans()[0];
  const id = top ? scanId(top) : "";
  if (!state.seenTop) {
    if (!state.data.updatedAt && !id) return;
    state.seenTop = true;
    state.lastTop = id;
    if (state.selectedId && scans().some((scan) => scanId(scan) === state.selectedId)) return;
    state.selectedId = id;
    return;
  }
  if (id && id !== state.lastTop) {
    state.lastTop = id;
    state.selectedId = id;
    localStorage.setItem("vt-tray-scan", id);
  }
}

panel.addEventListener("click", (event) => {
  const action = event.target.closest("[data-action]");
  if (action) {
    const name = action.dataset.action;
    if (name === "settings") {
      state.settingsOpen = !state.settingsOpen;
      render();
    } else if (name === "watch") {
      const next = !state.data.watchDownloads;
      state.data.watchDownloads = next;
      render();
      ask("VirusTotal Tray - watch:" + (next ? "1" : "0"));
    } else if (name === "notify") {
      if (!state.data.watchDownloads) return;
      const next = !state.data.notifyFlagged;
      state.data.notifyFlagged = next;
      render();
      ask("VirusTotal Tray - notify:" + (next ? "1" : "0"));
    } else if (name === "scan") ask("VirusTotal Tray - pick");
    else if (name === "key") ask("VirusTotal Tray - key");
    else if (name === "copy" && state.selectedId) ask("VirusTotal Tray - copy:" + state.selectedId);
    else if (name === "open" && state.selectedId) ask("VirusTotal Tray - open:" + state.selectedId);
    else if (name === "rescan" && state.selectedId) ask("VirusTotal Tray - rescan:" + state.selectedId);
    return;
  }
  const filter = event.target.closest("[data-filter]");
  if (filter) {
    state.filter = filter.dataset.filter;
    localStorage.setItem("vt-tray-filter", state.filter);
    render();
    return;
  }
  const row = event.target.closest("[data-id]");
  if (!row) return;
  state.selectedId = row.dataset.id;
  localStorage.setItem("vt-tray-scan", state.selectedId);
  render();
});

panel.addEventListener("input", (event) => {
  if (event.target.id === "lookup") syncLookupFilled(event.target);
});

panel.addEventListener("toggle", (event) => {
  if (event.target.classList && event.target.classList.contains("more")) {
    state.detailsOpen = event.target.open;
  }
}, true);

panel.addEventListener("submit", (event) => {
  const form = event.target.closest(".lookup");
  if (!form) return;
  event.preventDefault();
  const input = form.querySelector("input");
  const text = (input.value || "").replace(/[\r\n]/g, "").trim();
  if (!text) {
    input.focus();
    return;
  }
  ask("VirusTotal Tray - url:" + text);
  input.value = "";
  syncLookupFilled(input);
});

window.addEventListener("keydown", (event) => {
  if (event.target.closest("input, textarea")) {
    if (event.key === "Escape") {
      event.preventDefault();
      event.target.blur();
    }
    return;
  }
  const key = event.key;
  if (key === "h" || key === "ArrowLeft") { event.preventDefault(); selectBy(-1); }
  else if (key === "l" || key === "ArrowRight") { event.preventDefault(); selectBy(1); }
  else if (key === "j" || key === "ArrowDown") { event.preventDefault(); panel.scrollBy({ top: 56 }); }
  else if (key === "k" || key === "ArrowUp") { event.preventDefault(); panel.scrollBy({ top: -56 }); }
  else if (key === "s" || key === "S") { event.preventDefault(); ask("VirusTotal Tray - pick"); }
  else if (key === "u" || key === "U") {
    event.preventDefault();
    const input = document.getElementById("lookup");
    if (input) input.focus();
  }
  else if (key === "Escape") {
    if (state.settingsOpen) {
      state.settingsOpen = false;
      render();
      return;
    }
    state.closing = true;
    state.command = "";
    applyTitle();
    window.close();
  }
});

function loadScript(file) {
  return new Promise((resolve) => {
    const script = document.createElement("script");
    script.src = file + "?t=" + Date.now();
    script.onload = () => { script.remove(); resolve(true); };
    script.onerror = () => { script.remove(); resolve(false); };
    document.head.appendChild(script);
  });
}

async function poll() {
  if (await loadScript("data.js") && window.VT_DATA) {
    const updated = window.VT_DATA.updatedAt || "";
    if (updated !== panel.dataset.updated) {
      panel.dataset.updated = updated;
      state.data = window.VT_DATA;
      followLatest();
      render();
    } else if ((window.VT_DATA.activity || "") !== (state.data.activity || "")) {
      state.data = window.VT_DATA;
      render();
    }
  }
  if (await loadScript("command.js") && window.VT_COMMAND) {
    const command = window.VT_COMMAND;
    if (command.seq && command.seq !== state.commandSeq) {
      state.commandSeq = command.seq;
      if (command.action === "idle") state.command = "";
      if (command.action === "focus") state.focusLookup = true;
      if (command.action === "next") selectBy(1);
      else render();
    }
  }
}

setInterval(poll, 800);
setInterval(() => { if (scans().length) render(); }, 30000);
render();
poll();
