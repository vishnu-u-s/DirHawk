/**
 * DirHawk — Frontend Application (app.js)
 * Vanilla JS, auto-saves to localStorage, real-time via Socket.IO
 */

const API = "http://localhost:5000";
const socket = io(API, { transports: ["websocket", "polling"] });

// ── State ─────────────────────────────────────────────────────────────────────
let state = {
  scanning: false,
  aiRunning: false,
  mode: "normal",
  ai_scope: "all",
  checked: 0, open: 0, sensitive: 0, count403: 0, targets: 0,
  currentScanDirs: [],
  seenUrls: new Set(),
};

// ── Auto-persist settings ─────────────────────────────────────────────────────
const PERSIST_KEYS = ["targetsInput", "timeoutInput", "workersInput", "aiUrl", "wordlistPath",
                      "proxyHost", "proxyPort", "proxyUser"];

function saveSettings() {
  const data = {};
  PERSIST_KEYS.forEach(k => {
    const el = document.getElementById(k);
    if (el) data[k] = el.value;
  });
  data.mode     = state.mode;
  data.ai_scope = state.ai_scope;
  data.aiModel  = document.getElementById("aiModel").value;
  // Save proxy type
  data.proxyType = document.getElementById("proxyTypeSocks5").classList.contains("active") ? "socks5" :
                   document.getElementById("proxyTypeHttp").classList.contains("active")   ? "http"   : "none";
  localStorage.setItem("dirhawk_settings", JSON.stringify(data));
}

function loadSettings() {
  try {
    const data = JSON.parse(localStorage.getItem("dirhawk_settings") || "{}");
    PERSIST_KEYS.forEach(k => {
      const el = document.getElementById(k);
      if (el && data[k] !== undefined) el.value = data[k];
    });
    if (data.mode)     setMode(data.mode);
    if (data.ai_scope) setAiScope(data.ai_scope);
    if (data.aiModel)  document.getElementById("aiModel").value = data.aiModel;
    // Restore proxy type and indicator
    const pType = data.proxyType || "none";
    setProxyType(pType);
  } catch(e) {}
}

// Auto-save on any input change
PERSIST_KEYS.forEach(k => {
  const el = document.getElementById(k);
  if (el) el.addEventListener("input", saveSettings);
});


// ── Terminal ──────────────────────────────────────────────────────────────────
const terminal = document.getElementById("terminal");

function log(msg, cls = "t-info") {
  const line = document.createElement("div");
  line.className = `t-line ${cls}`;
  line.textContent = msg;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;

  // Persist log to localStorage (last 500 lines)
  const logs = JSON.parse(localStorage.getItem("dirhawk_log") || "[]");
  logs.push({ msg, cls, ts: new Date().toISOString() });
  if (logs.length > 500) logs.splice(0, logs.length - 500);
  localStorage.setItem("dirhawk_log", JSON.stringify(logs));
}

function clearTerminal() {
  terminal.innerHTML = "";
  localStorage.removeItem("dirhawk_log");
  resetStats();
  // Minimal prompt — does NOT write to localStorage
  const el = document.createElement("div");
  el.className = "t-line t-muted";
  el.textContent = "  ────── Terminal cleared. Ready for new scan. ──────";
  terminal.appendChild(el);
}

function restoreLog() {
  try {
    const logs = JSON.parse(localStorage.getItem("dirhawk_log") || "[]");
    if (logs.length > 0) {
      logs.forEach(({ msg, cls }) => {
        const line = document.createElement("div");
        line.className = `t-line ${cls}`;
        line.textContent = msg;
        terminal.appendChild(line);
      });
      terminal.scrollTop = terminal.scrollHeight;
    }
  } catch(e) {}
}

function exportTerminal() {
  const lines = [...terminal.querySelectorAll(".t-line")].map(l => l.textContent).join("\n");
  const blob = new Blob([lines], { type: "text/plain" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
  a.download = `dirhawk_log_${Date.now()}.txt`; a.click();
}


// ── Stats ─────────────────────────────────────────────────────────────────────
function updateStats(patch = {}) {
  Object.assign(state, patch);
  document.getElementById("statChecked").textContent  = state.checked;
  document.getElementById("statOpen").textContent      = state.open;
  document.getElementById("statSensitive").textContent = state.sensitive;
  document.getElementById("stat403").textContent       = state.count403;
  document.getElementById("statTargets").textContent   = state.targets;
}

function resetStats() {
  updateStats({ checked: 0, open: 0, sensitive: 0, count403: 0 });
  state.currentScanDirs = [];
  state.seenUrls = new Set();
}


// ── Status Indicator ──────────────────────────────────────────────────────────
function setStatus(s) {
  const dot = document.getElementById("statusDot");
  const txt = document.getElementById("statusText");
  dot.className = `status-dot ${s}`;
  txt.textContent = s.toUpperCase();
  state.scanning = s === "scanning";
  state.aiRunning = s === "ai";
  document.getElementById("startBtn").disabled = state.scanning || state.aiRunning;
  document.getElementById("stopBtn").disabled  = !state.scanning;
  document.getElementById("stopAiBtn").style.display = state.aiRunning ? "" : "none";
}


// ── Mode Toggle ───────────────────────────────────────────────────────────────
function setMode(m) {
  state.mode = m;
  document.getElementById("modeNormal").classList.toggle("active", m === "normal");
  document.getElementById("modeAI").classList.toggle("active", m === "ai");
  document.getElementById("aiPanel").classList.toggle("visible", m === "ai");
  saveSettings();
}

// ── AI Scope Toggle ───────────────────────────────────────────────────────────
function setAiScope(scope) {
  state.ai_scope = scope;
  document.getElementById("aiScopeAll").classList.toggle("active", scope === "all");
  document.getElementById("aiScopeSensitive").classList.toggle("active", scope === "sensitive");
  saveSettings();
}

// ── Stop AI ───────────────────────────────────────────────────────────────────
async function stopAI() {
  await fetch(`${API}/api/ai-stop`, { method: "POST" });
  log("[!] Stop AI requested...", "t-warn");
}


// ── Proxy ─────────────────────────────────────────────────────────────────────
function setProxyType(type) {
  document.getElementById("proxyTypeNone").classList.toggle("active",   type === "none");
  document.getElementById("proxyTypeSocks5").classList.toggle("active", type === "socks5");
  document.getElementById("proxyTypeHttp").classList.toggle("active",   type === "http");
  document.getElementById("proxyFields").style.display = type === "none" ? "none" : "block";
  updateProxyIndicator(buildProxyString());
  saveSettings();
}

function buildProxyString() {
  const isSocks5 = document.getElementById("proxyTypeSocks5").classList.contains("active");
  const isHttp   = document.getElementById("proxyTypeHttp").classList.contains("active");
  if (!isSocks5 && !isHttp) return "";
  const scheme = isSocks5 ? "socks5" : "http";
  const host   = (document.getElementById("proxyHost").value || "").trim();
  const port   = (document.getElementById("proxyPort").value || "").trim();
  const user   = (document.getElementById("proxyUser").value || "").trim();
  const pass   = (document.getElementById("proxyPass").value || "").trim();
  if (!host || !port) return "";
  const auth = user ? `${encodeURIComponent(user)}:${encodeURIComponent(pass)}@` : "";
  return `${scheme}://${auth}${host}:${port}`;
}

function updateProxyIndicator(proxyStr) {
  const el = document.getElementById("proxyStatus");
  if (!el) return;
  if (proxyStr && proxyStr.trim()) {
    el.className = "proxy-status on";
    el.textContent = "● " + proxyStr.trim();
  } else {
    el.className = "proxy-status off";
    el.textContent = "● Direct";
  }
}

// Auto-update indicator when proxy fields change
["proxyHost","proxyPort","proxyUser","proxyPass"].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener("input", () => {
    updateProxyIndicator(buildProxyString());
    saveSettings();
  });
});

document.getElementById("testProxyBtn").addEventListener("click", async () => {
  const proxy = buildProxyString();
  const indicator = document.getElementById("proxyStatus");
  if (!proxy) { log("[!] Configure proxy host and port first.", "t-warn"); return; }

  // ── Testing state ─────────────────────────────────────────────────────────
  indicator.className = "proxy-status testing";
  indicator.textContent = "⬤ Testing…";
  log(`[~] Testing proxy: ${proxy}`, "t-info");

  try {
    const r = await fetch(`${API}/api/test-proxy`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proxy }),
    });
    const d = await r.json();
    if (d.success) {
      indicator.className = "proxy-status alive";
      indicator.textContent = "⬤ Reachable";
      log(`[✓] ${d.message}`, "t-found");
    } else {
      indicator.className = "proxy-status dead";
      indicator.textContent = "⬤ Not reachable";
      log(`[✗] ${d.message}`, "t-error");
    }
  } catch(e) {
    indicator.className = "proxy-status dead";
    indicator.textContent = "⬤ Not reachable";
    log(`[ERR] ${e}`, "t-error");
  }
});


// ── File Inputs ───────────────────────────────────────────────────────────────
document.getElementById("targetsFile").addEventListener("change", e => {
  const file = e.target.files[0]; if (!file) return;
  const reader = new FileReader();
  reader.onload = ev => {
    document.getElementById("targetsInput").value = ev.target.result.trim();
    saveSettings();
    log(`[✓] Loaded targets from ${file.name}`, "t-found");
  };
  reader.readAsText(file);
});

document.getElementById("wordlistFile").addEventListener("change", e => {
  const file = e.target.files[0]; if (!file) return;
  document.getElementById("wordlistPath").value = file.name;
  log(`[~] Custom wordlist: ${file.name} (upload path not yet set — use CLI --wordlist for custom files)`, "t-warn");
  saveSettings();
});


// ── Load Models ───────────────────────────────────────────────────────────────
async function loadModels() {
  const aiUrl = document.getElementById("aiUrl").value.trim();
  const aiKey = document.getElementById("aiKey").value.trim();
  const proxy = buildProxyString();
  if (!aiUrl || !aiKey) { log("[!] AI URL and API Key required.", "t-warn"); return; }
  log("[AI] Fetching available models...", "t-ai");

  try {
    const r = await fetch(`${API}/api/models`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ai_url: aiUrl, ai_key: aiKey, proxy }),
    });
    const d = await r.json();
    if (d.error) { log(`[ERR] ${d.error}`, "t-error"); return; }

    const sel = document.getElementById("aiModel");
    sel.innerHTML = '<option value="">— select model —</option>';
    d.models.forEach(m => {
      const opt = document.createElement("option");
      opt.value = m; opt.textContent = m;
      sel.appendChild(opt);
    });
    log(`[AI] ${d.models.length} models loaded.`, "t-found");
    saveSettings();
  } catch(e) { log(`[ERR] ${e}`, "t-error"); }
}


// ── Start Scan ────────────────────────────────────────────────────────────────
async function startScan() {
  const targetsRaw = document.getElementById("targetsInput").value.trim();
  if (!targetsRaw) { log("[!] Enter at least one target.", "t-warn"); return; }

  const targets = targetsRaw.split("\n").map(t => t.trim()).filter(Boolean);
  if (targets.length === 0) { log("[!] No valid targets.", "t-warn"); return; }

  const payload = {
    targets:     targets.join("\n"),
    proxy:       buildProxyString(),
    mode:        state.mode,
    ai_scope:    state.ai_scope,
    timeout:     parseInt(document.getElementById("timeoutInput").value) || 10,
    max_workers: parseInt(document.getElementById("workersInput").value) || 10,
    ai_url:      document.getElementById("aiUrl").value.trim(),
    ai_key:      document.getElementById("aiKey").value.trim(),
    ai_model:    document.getElementById("aiModel").value.trim(),
  };

  if (state.mode === "ai") {
    if (!payload.ai_url || !payload.ai_key || !payload.ai_model) {
      log("[!] AI mode requires URL, API Key, and Model.", "t-warn"); return;
    }
  }

  // ── Auto-clear terminal before each new scan ────────────────────────────
  terminal.innerHTML = "";
  localStorage.removeItem("dirhawk_log");
  resetStats();
  updateStats({ targets: targets.length });
  setStatus("scanning");
  log("", "t-info");
  log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, "t-header");
  log(`  🦅 Scan started — ${targets.length} target(s)  [${state.mode.toUpperCase()} mode]`, "t-header");
  log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, "t-header");
  if (payload.proxy) log(`  Proxy: ${payload.proxy}`, "t-info");
  targets.forEach(t => log(`  Target: ${t}`, "t-info"));
  log("", "t-info");

  try {
    const r = await fetch(`${API}/api/scan`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const d = await r.json();
    if (d.error) { log(`[ERR] ${d.error}`, "t-error"); setStatus("error"); }
  } catch(e) {
    log(`[ERR] Could not connect to DirHawk server: ${e}`, "t-error");
    setStatus("error");
  }
}


// ── Stop Scan ─────────────────────────────────────────────────────────────────
document.getElementById("stopBtn").addEventListener("click", async () => {
  await fetch(`${API}/api/stop`, { method: "POST" });
});


// ── Socket.IO Events ──────────────────────────────────────────────────────────
socket.on("connect", () => log("[✓] Connected to DirHawk server.", "t-found"));
socket.on("disconnect", () => log("[!] Server disconnected.", "t-warn"));

socket.on("progress", data => {
  // Overwrite last progress line (don't flood terminal)
  const last = terminal.lastElementChild;
  if (last && last.classList.contains("t-progress-live")) {
    last.textContent = "  " + (data.msg || "");
  } else {
    const line = document.createElement("div");
    line.className = "t-line t-progress t-progress-live";
    line.textContent = "  " + (data.msg || "");
    terminal.appendChild(line);
  }
  terminal.scrollTop = terminal.scrollHeight;

  // Update checked count from message if possible
  const m = (data.msg || "").match(/^\[(\d+)\]/);
  if (m) updateStats({ checked: parseInt(m[1]) });
});

// Forbidden (403) ─────────────────────────────────────────────────────────────
socket.on("forbidden", data => {
  const last = terminal.lastElementChild;
  if (last && last.classList.contains("t-progress-live")) last.remove();
  const line = document.createElement("div");
  line.className = "t-line t-warn";
  line.innerHTML =
    `  <span style="color:var(--yellow)">[403 BLOCKED]</span> ` +
    `<span style="color:var(--text-muted)">${data.url}</span>` +
    `  <a href="${data.url}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">↗</a>`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
  updateStats({ count403: state.count403 + 1 });
});

socket.on("found", data => {
  // ── Client-side dedup ────────────────────────────────────────────────────
  const normUrl = data.url.replace(/\/$/, "") + "/";
  if (state.seenUrls.has(normUrl)) return;
  state.seenUrls.add(normUrl);
  // ─────────────────────────────────────────────────────────────────────────

  // Remove live progress line
  const liveLines = terminal.querySelectorAll(".t-progress-live");
  liveLines.forEach(l => l.remove());

  state.currentScanDirs.push(data);
  const isS = data.is_sensitive;
  const cls = isS ? "t-sensitive" : "t-found";
  const tag = isS ? "[SENSITIVE]" : "[OPEN DIR]";

  // ── Main entry line with arrow link ──────────────────────────────────────
  const row = document.createElement("div");
  row.className = `t-line ${cls}`;
  row.innerHTML =
    `  <span>${tag}</span> ` +
    `<span style="color:inherit">${data.url}</span>` +
    `<span style="color:var(--text-muted)">  (${data.file_count} items)</span>` +
    `  <a href="${data.url}" target="_blank" rel="noopener" ` +
    `   title="Open in new tab" ` +
    `   style="color:var(--accent);text-decoration:none;font-size:13px;margin-left:4px;">↗</a>`;
  terminal.appendChild(row);

  if (data.reason) log(`    ↳ ${data.reason}`, "t-warn");

  updateStats({
    open: state.open + 1,
    sensitive: isS ? state.sensitive + 1 : state.sensitive,
  });

  // ── View files link ───────────────────────────────────────────────────────
  if (data.files && data.files.length > 0) {
    const link = document.createElement("div");
    link.className = "t-line t-info";
    link.innerHTML = `    <span style="color:var(--accent);cursor:pointer;text-decoration:underline" onclick='showDirModal(${JSON.stringify(data)})'>▶ View ${data.file_count} files</span>`;
    terminal.appendChild(link);
  }

  terminal.scrollTop = terminal.scrollHeight;
});

socket.on("saved", data => {
  log(`  [✓] Saved → ${data.path}`, "t-saved");
  loadHistory();
});

socket.on("done", data => {
  log("", "t-info");
  log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, "t-done");
  log(`  ✔ Scan complete: ${data.domain}`, "t-done");
  log(`  Open dirs:  ${data.summary.open_dirs_found}`, "t-found");
  log(`  Sensitive:  ${data.summary.sensitive_dirs_found}`, "t-sensitive");
  log(`  Checked:    ${data.summary.total_checked}`, "t-info");
  log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, "t-done");
});

socket.on("scan_complete", data => {
  setStatus("done");
  log("", "t-info");
  log(`  🏁 All ${data.total_targets} target(s) scanned.`, "t-done");
  log(`  Open: ${data.total_open_dirs} | Sensitive: ${data.total_sensitive} | 403 Blocked: ${data.total_403}`, "t-found");
  if (state.mode === "ai") {
    setStatus("ai");
    log(`  🤖 AI analysis starting (scope: ${state.ai_scope})...`, "t-ai");
  }
  loadHistory();
});

socket.on("stopped", data => {
  setStatus("idle");
  log(`[!] ${data.msg}`, "t-warn");
});

// ── AI per-directory events ───────────────────────────────────────────────────
socket.on("ai_dir_start", data => {
  const line = document.createElement("div");
  line.className = "t-line ai-verdict checking";
  line.id = `ai-checking-${btoa(data.url).replace(/[^a-zA-Z0-9]/g,'').slice(0,20)}`;
  line.textContent = `  [AI ${data.current}/${data.total}] Analyzing: ${data.url}`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
});

socket.on("ai_dir_result", data => {
  // Replace the checking line with the result
  const id = `ai-checking-${btoa(data.url).replace(/[^a-zA-Z0-9]/g,'').slice(0,20)}`;
  const prev = document.getElementById(id);
  const isS = data.is_sensitive;
  const verdict = data.ai_verdict || "";
  const div = document.createElement("div");
  div.className = `t-line ai-verdict ${isS ? 'sensitive' : 'clean'}`;
  div.innerHTML =
    `  ${isS ? '⚠' : '✓'} [AI ${data.current}/${data.total}] ` +
    `<a href="${data.url}" target="_blank" rel="noopener" ` +
    `style="color:inherit;text-decoration:underline">${data.url}</a>` +
    `  <span style="opacity:0.8">↗</span><br>` +
    `  &nbsp;&nbsp;${verdict}`;
  if (prev) prev.replaceWith(div);
  else terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
});

socket.on("ai_stopped", data => {
  setStatus("idle");
  log(`[!] ${data.msg}`, "t-warn");
  loadHistory();
});

socket.on("ai_complete", data => {
  setStatus("done");
  log("", "t-info");
  log(`  ═══════════════ AI COMPLETE ═══════════════`, "t-ai");
  log(`  ${data.msg}`, "t-ai");
  log(`  ════════════════════════════════════════════`, "t-ai");
  loadHistory();
});

socket.on("error", data => {
  log(`[ERR] ${data.msg || JSON.stringify(data)}`, "t-error");
});

socket.on("bulk_progress", data => {
  log("", "t-info");
  log(`  [${data.current}/${data.total}] → ${data.target}`, "t-header");
});

socket.on("ai_start", data => log(`\n  [AI] ${data.msg}`, "t-ai"));
socket.on("ai_progress", data => log(`  [AI] ${data.msg}`, "t-ai"));
socket.on("ai_done", data => {
  log("\n  ═══════════════ AI ANALYSIS ═══════════════", "t-ai");
  // Render AI response block
  const block = document.createElement("div");
  block.className = "ai-block";
  block.textContent = data.response;
  terminal.appendChild(block);
  terminal.scrollTop = terminal.scrollHeight;
});

socket.on("ai_analysis", data => {
  const block = document.createElement("div");
  block.className = "ai-block";
  block.textContent = data.analysis;
  terminal.appendChild(block);
  terminal.scrollTop = terminal.scrollHeight;
});


// ── History ───────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const r = await fetch(`${API}/api/results`);
    const items = await r.json();
    renderHistory(items);
  } catch(e) {
    // Server not running or no results yet
  }
}

function renderHistory(items) {
  const list = document.getElementById("resultsList");
  if (!items || items.length === 0) {
    list.innerHTML = '<div class="empty-results">No scans yet.<br/>Results auto-save here.</div>';
    return;
  }
  list.innerHTML = items.map(item => `
    <div class="result-item" onclick="loadResultDetail('${item.filename}')">
      <div class="result-domain">${item.domain}</div>
      <div class="result-meta">
        <span class="open">▲ ${item.open_dirs} open</span>
        <span class="sensitive">⚑ ${item.sensitive_dirs} sensitive</span>
        ${item.found_403 ? `<span style="color:var(--yellow)">🚫 ${item.found_403} blocked</span>` : ''}
      </div>
      <div class="result-date">${formatDate(item.started_at)}</div>
      <button class="result-delete" title="Delete this scan" onclick="deleteHistory(event,'${item.filename}')">✕</button>
    </div>
  `).join("");
}

async function deleteHistory(e, filename) {
  e.stopPropagation();
  if (!confirm(`Delete scan: ${filename}?`)) return;
  try {
    const r = await fetch(`${API}/api/results/${filename}`, { method: "DELETE" });
    const d = await r.json();
    if (d.status === "deleted") {
      log(`[✓] Deleted: ${filename}`, "t-saved");
      loadHistory();
    }
  } catch(e) { log(`[ERR] Delete failed: ${e}`, "t-error"); }
}

async function loadResultDetail(filename) {
  document.querySelectorAll(".result-item").forEach(el => el.classList.remove("active"));
  event.currentTarget.classList.add("active");

  try {
    const r = await fetch(`${API}/api/results/${filename}`);
    const data = await r.json();

    // ── Clear terminal — show ONLY this scan's data ───────────────────────
    terminal.innerHTML = "";
    localStorage.removeItem("dirhawk_log");

    // ── Update stats from historical data ─────────────────────────────────
    const s = data.summary || {};
    updateStats({
      checked:  s.total_checked       || 0,
      open:     s.open_dirs_found     || 0,
      sensitive:s.sensitive_dirs_found|| 0,
      count403: (data.found_403 || []).length,
      targets:  1,
    });

    // ── Populate currentScanDirs so MD export works ───────────────────────
    state.currentScanDirs = (data.open_dirs || []).map(d => ({
      url:          d.url,
      file_count:   d.files ? d.files.length : 0,
      files:        d.files || [],
      is_sensitive: d.is_sensitive,
      reason:       d.sensitive_reason || "",
    }));
    state.seenUrls = new Set(state.currentScanDirs.map(d => d.url));

    // ── Print to terminal ─────────────────────────────────────────────────
    log("", "t-info");
    log(`  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, "t-header");
    log(`  [HISTORY] ${data.domain}  —  ${formatDate(data.started_at)}`, "t-header");
    log(`  Checked: ${s.total_checked || 0} | Open: ${s.open_dirs_found || 0} | Sensitive: ${s.sensitive_dirs_found || 0} | 403: ${(data.found_403||[]).length}`, "t-info");
    log(`  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, "t-header");

    (data.open_dirs || []).forEach(d => {
      const cls = d.is_sensitive ? "t-sensitive" : "t-found";
      const tag = d.is_sensitive ? "[SENSITIVE]" : "[OPEN DIR]";
      const row = document.createElement("div");
      row.className = `t-line ${cls}`;
      row.innerHTML =
        `  <span>${tag}</span> ` +
        `<span style="color:inherit">${d.url}</span>` +
        `<span style="color:var(--text-muted)">  (${(d.files||[]).length} items)</span>` +
        `  <a href="${d.url}" target="_blank" rel="noopener" ` +
        `style="color:var(--accent);text-decoration:none;font-size:13px">↗</a>`;
      terminal.appendChild(row);
      if (d.sensitive_reason) log(`    ↳ ${d.sensitive_reason}`, "t-warn");
    });

    if ((data.found_403 || []).length > 0) {
      log(``, "t-info");
      log(`  [403 BLOCKED — ${data.found_403.length} entries]`, "t-warn");
      (data.found_403).forEach(url => {
        const row = document.createElement("div");
        row.className = "t-line t-warn";
        row.innerHTML =
          `  <span style="color:var(--yellow)">[403]</span> ` +
          `<span style="color:var(--text-muted)">${url}</span>` +
          `  <a href="${url}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">↗</a>`;
        terminal.appendChild(row);
      });
    }

    terminal.scrollTop = terminal.scrollHeight;
  } catch(e) { log(`[ERR] ${e}`, "t-error"); }
}


function formatDate(iso) {
  if (!iso) return "";
  try {
    return new Date(iso).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });
  } catch { return iso; }
}


// ── Dir Modal ─────────────────────────────────────────────────────────────────
function showDirModal(data) {
  document.getElementById("modalTitle").textContent = data.url;
  const body = document.getElementById("modalBody");
  if (!data.files || data.files.length === 0) {
    body.innerHTML = "<p style='color:var(--text-muted)'>No file entries parsed.</p>";
  } else {
    body.innerHTML = data.files.map(f => `
      <div class="dir-entry">
        <span class="${f.is_dir ? "dir-icon" : "file-icon"}">${f.is_dir ? "📁" : "📄"}</span>
        <a href="${f.url}" target="_blank" rel="noopener">${f.name}</a>
      </div>
    `).join("");
  }
  document.getElementById("modal").classList.add("open");
}

function closeModal(e) {
  if (e.target.id === "modal") document.getElementById("modal").classList.remove("open");
}

// ── Download Markdown Report ──────────────────────────────────────────────────
function downloadMarkdown() {
  if (state.currentScanDirs.length === 0) {
    log("[!] No scan results to export. Run a scan first.", "t-warn");
    return;
  }

  const now = new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });
  const sensitive = state.currentScanDirs.filter(d => d.is_sensitive);
  const open     = state.currentScanDirs.filter(d => !d.is_sensitive);

  let md = `# DirHawk Scan Report\n`;
  md += `**Generated:** ${now}  \n`;
  md += `**Total Found:** ${state.currentScanDirs.length} | `;
  md += `**Open:** ${open.length} | **Sensitive:** ${sensitive.length}\n\n`;
  md += `---\n\n`;

  // ── Sensitive Directories ───────────────────────────────────────────────
  md += `## 🔴 Sensitive Directories (${sensitive.length})\n\n`;
  if (sensitive.length > 0) {
    md += `| # | URL | Items | Reason |\n`;
    md += `|---|-----|-------|--------|\n`;
    sensitive.forEach((d, i) => {
      const reason = d.reason || d.sensitive_reason || "keyword match";
      md += `| ${i + 1} | [${d.url}](${d.url}) | ${d.file_count} | ${reason} |\n`;
    });
    md += `\n`;

    // File listings for sensitive dirs
    md += `### File Listings\n\n`;
    sensitive.forEach((d, i) => {
      md += `#### ${i + 1}. ${d.url}\n\n`;
      if (d.files && d.files.length > 0) {
        d.files.forEach(f => {
          const icon = f.is_dir ? "📁" : "📄";
          md += `- ${icon} [${f.name}](${f.url})\n`;
        });
      } else {
        md += `_No file listing available_\n`;
      }
      md += `\n`;
    });
  } else {
    md += `_No sensitive directories found._\n\n`;
  }

  md += `---\n\n`;

  // ── Open Directories ─────────────────────────────────────────────────────
  md += `## 🟢 Open Directories (${open.length})\n\n`;
  if (open.length > 0) {
    md += `| # | URL | Items |\n`;
    md += `|---|-----|-------|\n`;
    open.forEach((d, i) => {
      md += `| ${i + 1} | [${d.url}](${d.url}) | ${d.file_count} |\n`;
    });
    md += `\n`;
  } else {
    md += `_No non-sensitive open directories found._\n\n`;
  }

  md += `---\n\n`;
  md += `*Report generated by DirHawk v1.0 — Use responsibly on authorized targets only.*\n`;

  // ── Trigger download ──────────────────────────────────────────────────────
  const blob = new Blob([md], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  a.download = `dirhawk_report_${ts}.md`;
  a.click();
  log(`[✓] MD report downloaded: dirhawk_report_${ts}.md`, "t-saved");
}


document.addEventListener("DOMContentLoaded", () => {
  loadSettings();
  restoreLog();
  loadHistory();
});
