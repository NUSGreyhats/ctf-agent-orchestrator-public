/* CTF Solver - Frontend
 *
 * Supports 2 challenge modes: single and parallel.
 * Each challenge has one or more "runs" — per-agent WebSocket streams.
 */

const $ = (sel) => document.querySelector(sel);

// === Global State ===
let currentChallengeId = null;
let autoScroll = true;
let stepCount = 0;
let defaultAgent = null;
let defaultFlagFormat = "";
let currentTheme = "dark";
let chatViewMode = "split";
let csrfToken = null;
let agentCatalog = [];
let agentByName = new Map();

const pendingTools = new Map();

// Run tracking — one WS per run, one feed per run
let currentRuns = [];               // run objects for current challenge
let activeRunId = null;             // which run tab is active
let currentChallengeMode = "single";
let wsConnections = new Map();      // run_id -> WebSocket
let globalWs = null;
let historyLoadingRuns = new Set(); // run_ids currently replaying saved chat history
const INITIAL_TRANSCRIPT_EVENTS = 200;
const TRANSCRIPT_PAGE_EVENTS = 200;
const TRANSCRIPT_RENDER_BATCH = 25;
const LIVE_RENDER_BATCH = 50;
const MAX_TOOL_OUTPUT_DISPLAY_CHARS = 50000;
let historyLoadToken = 0;
let runHistoryState = new Map();
let historyRenderDepth = 0;
let statsRenderPending = false;
let pendingScrollRuns = new Set();
let scrollFramePending = false;
let queuedRunEvents = [];
let queuedRunEventFrame = false;
let renderedEventNodes = new Map();
let transcriptSearchResults = [];
let transcriptSearchActiveIndex = -1;
let metadataLastSyncAt = null;
let metadataSyncTimer = null;
let fileBrowserPath = "";
let fileBrowserRequestToken = 0;

// Per-run counters
let runToolCounts = new Map();
let runStepCounts = new Map();

// Per-run statistics
let runStats = new Map();
let statsUseSnapshot = false;
let statsRefreshTimer = null;

// Timer & cost
let timerInterval = null;
let challengeFlagFormat = "";
let challengeFlagFormats = [];
let currentFlagQuestions = [];
let lastThinkingEl = null;

// === Views ===
const views = {
  login: $("#login-view"),
  dashboard: $("#dashboard-view"),
  detail: $("#detail-view"),
  usage: $("#usage-view"),
  settings: $("#settings-view"),
};

function showView(name) {
  Object.values(views).forEach((v) => v.classList.add("hidden"));
  views[name].classList.remove("hidden");
}

// === Agent Helpers ===
function primaryAgentName() {
  return agentCatalog[0]?.name || "claude";
}

function getAgentMeta(name) {
  return agentByName.get(name) || agentCatalog[0] || {
    name: "claude",
    label: "Claude",
    models: [],
    default_model: "opus",
    effort_levels: [],
    default_effort: "",
    auth_connect_command: "claude auth login",
    autonomous_default: false,
    badge_mode: "model",
  };
}

function isParallelMode(mode) {
  return mode === "parallel";
}

function getAgentAutonomousDefault(agentName) {
  return Boolean(getAgentMeta(agentName).autonomous_default);
}

// === Agent UI Renderers ===
let enabledAgents = [];
let agentModels = {};
let agentEfforts = {};

function renderAgentSelect(selectEl) {
  selectEl.innerHTML = agentCatalog.map((agent) =>
    `<option value="${esc(agent.name)}">${esc(agent.label)}</option>`
  ).join("");
}

function createAgentRow(agentName, model, effort) {
  const row = document.createElement("div");
  row.className = "agent-row";

  const providerSel = document.createElement("select");
  providerSel.className = "agent-row-provider";
  providerSel.innerHTML = agentCatalog.map((a) =>
    `<option value="${esc(a.name)}" ${a.name === agentName ? "selected" : ""}>${esc(a.label)}</option>`
  ).join("");

  const modelSel = document.createElement("select");
  modelSel.className = "agent-row-model";

  const effortSel = document.createElement("select");
  effortSel.className = "agent-row-effort";

  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "agent-row-remove";
  removeBtn.textContent = "\u00d7";
  removeBtn.title = "Remove";

  function updateDropdowns() {
    const meta = getAgentMeta(providerSel.value);
    const models = meta.models || [];
    modelSel.innerHTML = models.map((m) =>
      `<option value="${esc(m.value)}">${esc(m.label)}</option>`
    ).join("") || '<option value="">Provider default</option>';
    if (model && models.some((m) => m.value === model)) {
      modelSel.value = model;
      model = "";
    }
    const efforts = meta.effort_levels || [];
    if (efforts.length) {
      effortSel.innerHTML = efforts.map((e) =>
        `<option value="${esc(e.value)}">${esc(e.label)}</option>`
      ).join("");
      effortSel.classList.remove("hidden");
      if (effort && efforts.some((e) => e.value === effort)) {
        effortSel.value = effort;
        effort = "";
      } else if (meta.default_effort) {
        effortSel.value = meta.default_effort;
      }
    } else {
      effortSel.innerHTML = "";
      effortSel.classList.add("hidden");
    }
  }

  providerSel.addEventListener("change", () => { model = ""; effort = ""; updateDropdowns(); });
  removeBtn.addEventListener("click", () => row.remove());

  row.append(providerSel, modelSel, effortSel, removeBtn);
  updateDropdowns();
  return row;
}

function addAgentRow(container, agentName, model, effort) {
  const name = agentName || primaryAgentName();
  const m = model || agentModels[name] || "";
  const e = effort || agentEfforts[name] || "";
  container.appendChild(createAgentRow(name, m, e));
}

function populateAgentList(container, btnId) {
  container.innerHTML = "";
  if (enabledAgents.length > 0) {
    for (const name of enabledAgents) {
      addAgentRow(container, name, agentModels[name] || "", agentEfforts[name] || "");
    }
  } else {
    addAgentRow(container);
  }
}

function getAgentRows(container) {
  return Array.from(container.querySelectorAll(".agent-row")).map((row) => ({
    agent: row.querySelector(".agent-row-provider").value,
    model: row.querySelector(".agent-row-model").value,
    effort: row.querySelector(".agent-row-effort")?.value || "",
  }));
}

function renderUsageShell() {
  $("#usage-grid").innerHTML = agentCatalog.map((agent) => `
    <div class="usage-card" id="usage-${esc(agent.name)}">
      <div class="usage-card-header">
        <span class="usage-agent-name">${esc(agent.label)}</span>
        <span id="${esc(agent.name)}-auth-badge" class="badge badge-pending">not connected</span>
      </div>
      <div id="${esc(agent.name)}-auth-info" class="usage-auth-info"></div>
      <div id="${esc(agent.name)}-stats" class="usage-stats"></div>
      <div id="${esc(agent.name)}-challenge-stats" class="usage-challenge-stats"></div>
    </div>
  `).join("");
}

async function loadAgentCatalog() {
  const res = await api("/api/agents");
  if (!res) return false;
  const data = await res.json();
  agentCatalog = data.agents || [];
  agentByName = new Map(agentCatalog.map((agent) => [agent.name, agent]));
  renderUsageShell();
  return true;
}

// === API ===
async function api(path, opts = {}) {
  const headers = { ...opts.headers };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  if (!(opts.body instanceof FormData)) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) { window.location.reload(); return null; }
  return res;
}

function newestConnectionSync(connections) {
  let newest = null;
  for (const conn of connections || []) {
    const value = conn.last_sync;
    if (!value) continue;
    const ts = parseServerTimestamp(value);
    if (Number.isNaN(ts.getTime())) continue;
    if (!newest || ts > newest) newest = ts;
  }
  return newest;
}

function parseServerTimestamp(value) {
  if (value instanceof Date) return value;
  if (typeof value !== "string") return new Date(value);
  const trimmed = value.trim();
  if (!trimmed) return new Date(NaN);
  // Legacy backend timestamps were UTC but had no timezone suffix.
  const hasTimezone = /(?:z|[+-]\d{2}:?\d{2})$/i.test(trimmed);
  return new Date(hasTimezone ? trimmed : `${trimmed}Z`);
}

function setMetadataLastSync(value) {
  if (!value) return;
  const ts = parseServerTimestamp(value);
  if (Number.isNaN(ts.getTime())) return;
  metadataLastSyncAt = ts;
  renderMetadataSyncAge();
  if (!metadataSyncTimer) {
    metadataSyncTimer = setInterval(renderMetadataSyncAge, 30 * 1000);
  }
}

function formatRelativeTime(ts) {
  const diffMs = Date.now() - ts.getTime();
  if (diffMs < 0) return "just now";
  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function renderMetadataSyncAge() {
  const el = $("#metadata-sync-age");
  if (!el) return;
  if (!metadataLastSyncAt) {
    el.textContent = "CTF metadata not synced yet";
    return;
  }
  el.textContent = `CTF metadata updated ${formatRelativeTime(metadataLastSyncAt)}`;
  el.title = metadataLastSyncAt.toLocaleString();
}

// === Login ===
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pw = $("#login-password").value;
  const loginRes = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: pw }),
  });
  if (loginRes.ok) {
    const data = await loginRes.json();
    csrfToken = data.csrf_token;
    if (await loadAgentCatalog()) {
      showView("dashboard");
      connectGlobalWS();
      await handleDeepLink();
      loadDefaultAgent();
    }
  } else {
    const err = await loginRes.json().catch(() => ({}));
    $("#login-error").textContent = err.error || "Invalid password";
    $("#login-error").classList.remove("hidden");
  }
});

$("#btn-logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  disconnectAllWS();
  disconnectGlobalWS();
  csrfToken = null;
  currentChallengeId = null;
  showView("login");
});

// === Default Agent / Settings ===
async function loadDefaultAgent() {
  const res = await api("/api/settings");
  if (!res) return;
  const settings = await res.json();
  defaultAgent = settings.default_agent || primaryAgentName();
  if (!agentByName.has(defaultAgent)) defaultAgent = primaryAgentName();
  defaultFlagFormat = settings.default_flag_format || "";
  currentTheme = settings.theme || "dark";
  chatViewMode = settings.chat_view_mode || "split";
  enabledAgents = settings.enabled_agents && settings.enabled_agents.length
    ? settings.enabled_agents
    : [defaultAgent];
  agentModels = settings.agent_models || {};
  agentEfforts = settings.agent_efforts || {};
  applyTheme(currentTheme);
}

function applyTheme(theme) {
  document.body.classList.toggle("light", theme === "light");
}


// === Agent Auth Check ===
async function checkAgentAuth() {
  const res = await api("/api/usage");
  if (!res) return;
  const data = await res.json();
  const usage = data.agents || {};
  const missing = agentCatalog
    .filter((agent) => !usage[agent.name])
    .map((agent) => ({
      name: agent.label,
      command: agent.auth_connect_command,
    }));

  if (missing.length === 0) return;

  const container = $("#auth-warning-items");
  container.innerHTML = missing.map((m) => `
    <div class="auth-warning-item">
      <span class="auth-warning-agent">${esc(m.name)}</span>
      <code class="auth-warning-cmd">${esc(m.command)}</code>
    </div>
  `).join("");

  $("#auth-warning-overlay").classList.remove("hidden");
}

$("#auth-warning-close").addEventListener("click", () => {
  $("#auth-warning-overlay").classList.add("hidden");
});
$("#auth-warning-dismiss").addEventListener("click", () => {
  $("#auth-warning-overlay").classList.add("hidden");
});
$("#auth-warning-overlay").addEventListener("click", (e) => {
  if (e.target === $("#auth-warning-overlay"))
    $("#auth-warning-overlay").classList.add("hidden");
});

// === Dashboard ===
async function loadChallenges() {
  const res = await api("/api/challenges");
  if (!res) return;
  const challenges = await res.json();
  const list = $("#challenges-list");
  const empty = $("#empty-state");

  if (!challenges.length) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");

  // Group challenges by category, sort by points (status priority) within
  const groups = {};
  for (const c of challenges) {
    const cat = c.category || "Uncategorized";
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(c);
  }
  const sortedCats = Object.keys(groups).sort();

  let html = "";
  for (const cat of sortedCats) {
    html += `<div class="dash-category-group">
      <div class="dash-category-header">${esc(cat)}</div>
      <div class="dash-card-grid">`;
    for (const c of groups[cat]) {
      const mode = c.mode || "single";
      const runs = c.runs || [];
      const runCount = runs.length;
      const isPending = c.status === "pending";

      const modeLabel = mode.replace(/_/g, " ");
      const totalDuration = runs.reduce((sum, r) => sum + (r.duration_ms || 0), 0);

      const solvesNum = c.solves ?? 0;
      const ptsStr = c.points ? `${c.points} pts` : "";
      const solvesStr = `${solvesNum} solve${solvesNum !== 1 ? "s" : ""}`;
      const challengeInfo = [ptsStr, solvesStr].filter(Boolean).join(" \u00b7 ");

      let agentLabel = "";
      if (isParallelMode(mode)) {
        agentLabel = `${runCount} run${runCount !== 1 ? "s" : ""}`;
      } else if (runs.length > 0) {
        const run = runs[0];
        const agentMeta = getAgentMeta(run.agent);
        agentLabel = agentMeta.badge_mode === "label"
          ? agentMeta.label
          : (run.model || agentMeta.default_model);
      }
      const runInfo = [
        modeLabel,
        agentLabel,
        `${c.files.length} file${c.files.length !== 1 ? "s" : ""}`,
      ].filter(Boolean).join(" \u00b7 ");

      const dur = formatDuration(totalDuration);

      html += `
      <div class="challenge-card status-${c.status}" data-id="${c.id}">
        <span class="badge badge-${c.status}">${c.status}</span>
        <span class="card-name">${esc(c.name)}</span>
        <span class="card-info-line">${esc(challengeInfo)}</span>
        <span class="card-info-line card-info-dim">${esc(runInfo)}</span>
        ${dur ? `<span class="card-info-line card-info-dim">${esc(dur)}</span>` : ""}
        ${isPending ? `<button class="btn-card-start" data-id="${c.id}">&#9654; Start</button>` : ""}
        <button class="btn-card-delete" data-id="${c.id}" title="Delete">&times;</button>
      </div>`;
    }
    html += `</div></div>`;
  }
  list.innerHTML = html;

  list.querySelectorAll(".challenge-card").forEach((card) =>
    card.addEventListener("click", (e) => {
      if (e.target.closest(".btn-card-delete") || e.target.closest(".btn-card-start")) return;
      if (exportMode) { toggleExportCard(card); return; }
      openChallenge(card.dataset.id);
    })
  );
  list.querySelectorAll(".btn-card-delete").forEach((btn) =>
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!confirm("Delete this challenge?")) return;
      await api(`/api/challenges/${btn.dataset.id}`, { method: "DELETE" });
      loadChallenges();
    })
  );
  list.querySelectorAll(".btn-card-start").forEach((btn) =>
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const cid = btn.dataset.id;
      const endpoint = `/api/challenges/${cid}/solve`;
      const res = await api(endpoint, { method: "POST" });
      if (res && res.ok) loadChallenges();
    })
  );
}

// Auto-refresh dashboard every 5s
setInterval(() => {
  if (!views.dashboard.classList.contains("hidden") && !exportMode) loadChallenges();
}, 5000);

// === Export Mode ===
let exportMode = false;
const exportSelected = new Set();
let pendingExportIds = [];
let pendingExportFromSelection = false;

function enterExportMode() {
  exportMode = true;
  exportSelected.clear();
  $("#challenges-list").classList.add("export-mode");
  $("#export-bar").classList.remove("hidden");
  $("#btn-export-mode").textContent = "Cancel Export";
  updateExportCount();
}

function exitExportMode() {
  exportMode = false;
  exportSelected.clear();
  $("#challenges-list").classList.remove("export-mode");
  $("#export-bar").classList.add("hidden");
  $("#btn-export-mode").textContent = "Export";
  document.querySelectorAll(".challenge-card.export-selected").forEach(
    (c) => c.classList.remove("export-selected")
  );
}

function updateExportCount() {
  const n = exportSelected.size;
  $("#export-count").textContent = `${n} selected`;
  $("#btn-export-download").disabled = n === 0;
}

function toggleExportCard(card) {
  const id = card.dataset.id;
  if (exportSelected.has(id)) {
    exportSelected.delete(id);
    card.classList.remove("export-selected");
  } else {
    exportSelected.add(id);
    card.classList.add("export-selected");
  }
  updateExportCount();
}

$("#btn-export-mode").addEventListener("click", () => {
  if (exportMode) exitExportMode();
  else enterExportMode();
});

$("#btn-export-cancel").addEventListener("click", () => exitExportMode());

$("#btn-export-select-all").addEventListener("click", () => {
  const cards = $("#challenges-list").querySelectorAll(".challenge-card");
  const allSelected = exportSelected.size === cards.length && cards.length > 0;
  if (allSelected) {
    exportSelected.clear();
    cards.forEach((c) => c.classList.remove("export-selected"));
    $("#btn-export-select-all").textContent = "Select All";
  } else {
    cards.forEach((c) => {
      exportSelected.add(c.dataset.id);
      c.classList.add("export-selected");
    });
    $("#btn-export-select-all").textContent = "Deselect All";
  }
  updateExportCount();
});

function openExportOptions(ids, fromSelection = false) {
  pendingExportIds = ids;
  pendingExportFromSelection = fromSelection;
  const count = ids.length;
  $("#export-options-summary").textContent =
    `${count} challenge${count !== 1 ? "s" : ""} selected`;
  $("#export-include-streams").checked = true;
  $("#export-include-files").checked = true;
  $("#export-options-overlay").classList.remove("hidden");
}

function closeExportOptions() {
  $("#export-options-overlay").classList.add("hidden");
  pendingExportIds = [];
  pendingExportFromSelection = false;
}

function selectedExportOptions() {
  return {
    streams: $("#export-include-streams").checked,
    files: $("#export-include-files").checked,
  };
}

function exportOptionsParams(options) {
  const params = new URLSearchParams();
  params.set("streams", options.streams ? "1" : "0");
  params.set("files", options.files ? "1" : "0");
  return params.toString();
}

async function downloadExport(ids, options) {
  showToast(`Exporting ${ids.length} challenge${ids.length > 1 ? "s" : ""}...`);
  if (ids.length === 1) {
    const qs = exportOptionsParams(options);
    return fetch(`/api/challenges/${ids[0]}/export?${qs}`, {
      credentials: "same-origin",
    });
  }
  return api("/api/challenges/export", {
    method: "POST",
    body: JSON.stringify({ ids, ...options }),
  });
}

async function runPendingExport() {
  if (!pendingExportIds.length) return;
  const options = selectedExportOptions();
  if (!options.streams && !options.files) {
    showToast("Select at least one export content type", "error");
    return;
  }
  const ids = [...pendingExportIds];
  const shouldExitExportMode = pendingExportFromSelection;
  $("#btn-export-confirm").disabled = true;
  try {
    const resp = await downloadExport(ids, options);
    if (!resp || !resp.ok) { showToast("Export failed"); return; }
    const blob = await resp.blob();
    const cd = resp.headers.get("content-disposition") || "";
    const m = cd.match(/filename="([^"]+)"/);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = m ? m[1] : (ids.length === 1 ? "export.zip" : "ctf_export.zip");
    a.click();
    URL.revokeObjectURL(a.href);
    showToast("Export downloaded");
    closeExportOptions();
    if (shouldExitExportMode) exitExportMode();
  } catch (e) {
    showToast("Export failed: " + e.message, "error");
  } finally {
    $("#btn-export-confirm").disabled = false;
  }
}

$("#btn-export-download").addEventListener("click", () => {
  if (!exportSelected.size) return;
  openExportOptions([...exportSelected], true);
});

$("#export-options-close").addEventListener("click", closeExportOptions);
$("#export-options-overlay").addEventListener("click", (e) => {
  if (e.target === $("#export-options-overlay")) closeExportOptions();
});
$("#btn-export-confirm").addEventListener("click", runPendingExport);

// === Agent list for New Challenge ===
$("#btn-add-challenge-agent").addEventListener("click", () => {
  addAgentRow($("#challenge-agent-list"));
});

// === Add Challenge Dropdown ===
let savedConnections = [];

async function loadConnections() {
  const res = await api("/api/connections");
  if (!res) return;
  savedConnections = await res.json();
  setMetadataLastSync(newestConnectionSync(savedConnections));
  renderSyncConnections();
}

function renderSyncConnections() {
  const container = $("#sync-connections");
  const divider = $("#sync-divider");
  if (!savedConnections.length) {
    container.innerHTML = "";
    divider.classList.add("hidden");
    return;
  }
  divider.classList.remove("hidden");
  container.innerHTML = savedConnections.map((conn) => `
    <button class="dropdown-item dropdown-item-sync" data-conn-id="${esc(conn.id)}">
      Sync: ${esc(conn.label)}
    </button>
  `).join("");
  container.querySelectorAll(".dropdown-item-sync").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      $("#add-challenge-menu").classList.add("hidden");
      triggerSync(btn.dataset.connId);
    });
  });
}

async function triggerSync(connId) {
  showToast("Syncing...", "info");
  const res = await api("/api/connections/sync", {
    method: "POST",
    body: JSON.stringify({ id: connId }),
  });
  if (!res) return;
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    showToast(err.error || "Sync failed", "error");
    return;
  }
  const data = await res.json();
  setMetadataLastSync(data.last_sync);
  const savedConn = savedConnections.find((c) => c.id === connId);
  if (savedConn && data.last_sync) savedConn.last_sync = data.last_sync;
  if (!data.challenges.length) {
    showToast(`No new challenges (${data.total} total on platform)`, "info");
    return;
  }
  if (data.new > 0) {
    showToast(`Found ${data.new} new unsolved challenge${data.new !== 1 ? "s" : ""}`, "success");
  } else if (data.skipped_solved > 0) {
    showToast(
      `No new unsolved challenges; ${data.skipped_solved} solved challenge${data.skipped_solved !== 1 ? "s" : ""} available in preview`,
      "info",
    );
  }

  // Open import modal in preview phase with the fetched challenges
  importPluginConfig = savedConnections.find((c) => c.id === connId)?.config || {};
  importFetchedChallenges = data.challenges;
  const pluginName = data.connection.plugin;

  // Set up import modal
  await loadPlugins();
  const pluginSel = $("#import-plugin");
  pluginSel.value = pluginName;

  $("#import-phase-config").classList.add("hidden");
  $("#import-phase-loading").classList.add("hidden");
  $("#import-phase-preview").classList.remove("hidden");

  // Set up preview controls using saved agent settings
  populateAgentList($("#import-agent-list"));
  $("#import-autonomous").checked = getAgentAutonomousDefault(primaryAgentName());
  $("#import-flag").value = defaultFlagFormat;

  renderImportPreview();
  $("#import-overlay").classList.remove("hidden");
}

// === Auto-sync polling (every 5 minutes) ===
let _syncPollTimer = null;

async function pollConnections() {
  try {
    const res = await api("/api/connections/poll");
    if (!res || !res.ok) return;
    const data = await res.json();
    const bar = $("#sync-notify-bar");
    setMetadataLastSync(data.last_sync);

    if (data.new_total > 0) {
      bar.innerHTML = `<span class="sync-notify-text">!! ${data.new_total} new challenge${data.new_total !== 1 ? "s" : ""} to sync !!</span><button class="sync-notify-close" title="Dismiss">&times;</button>`;
      bar.classList.remove("hidden");
      bar.querySelector(".sync-notify-close").addEventListener("click", (e) => {
        e.stopPropagation();
        bar.classList.add("hidden");
      });
    } else {
      bar.classList.add("hidden");
    }

    if (data.updates && data.updates.length) {
      loadChallenges();
    }
  } catch (_) {}
}

function startSyncPoll() {
  if (_syncPollTimer) return;
  _syncPollTimer = setInterval(pollConnections, 5 * 60 * 1000);
  setTimeout(pollConnections, 5000);
}

// Start polling once we're logged in
const _origLoadChallenges = loadChallenges;
loadChallenges = async function() {
  await _origLoadChallenges();
  startSyncPoll();
};

// Click notification bar to open sync dropdown
document.addEventListener("click", (e) => {
  if (e.target.id === "sync-notify-bar") {
    $("#add-challenge-menu").classList.remove("hidden");
  }
});

$("#btn-add-challenge").addEventListener("click", (e) => {
  e.stopPropagation();
  loadConnections();
  $("#add-challenge-menu").classList.toggle("hidden");
});
document.addEventListener("click", () => {
  $("#add-challenge-menu").classList.add("hidden");
});
$("#add-challenge-menu").addEventListener("click", (e) => {
  e.stopPropagation();
  $("#add-challenge-menu").classList.add("hidden");
});

// === New Challenge Modal ===
$("#btn-new-challenge").addEventListener("click", () => {
  populateAgentList($("#challenge-agent-list"));
  $("#challenge-autonomous").checked = getAgentAutonomousDefault(primaryAgentName());
  $("#challenge-flag").value = defaultFlagFormat;
  $("#modal-overlay").classList.remove("hidden");
  $("#challenge-name").focus();
});
$("#modal-close").addEventListener("click", closeModal);
$("#modal-overlay").addEventListener("click", (e) => {
  if (e.target === $("#modal-overlay")) closeModal();
});

function closeModal() {
  $("#modal-overlay").classList.add("hidden");
  $("#challenge-form").reset();
  pendingChallengeUploads = [];
  $("#file-list").innerHTML = "";
}

// === File Upload / Drop Zone ===
const dropZone = $("#drop-zone");
const fileInput = $("#challenge-files");
let pendingChallengeUploads = [];

dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("dragover"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", async (e) => {
  e.preventDefault(); dropZone.classList.remove("dragover");
  pendingChallengeUploads = await collectUploadsFromDataTransfer(e.dataTransfer);
  updateFileList();
});
fileInput.addEventListener("change", () => {
  pendingChallengeUploads = Array.from(fileInput.files).map((file) => ({
    file,
    path: uploadPathForFile(file),
  }));
  updateFileList();
});

function normalizeUploadPath(path) {
  return (path || "").replace(/\\/g, "/").split("/").filter(Boolean).join("/");
}

function uploadPathForFile(file, fallbackPath = "") {
  return normalizeUploadPath(file.webkitRelativePath || fallbackPath || file.name) || file.name;
}

async function collectUploadsFromDataTransfer(dataTransfer) {
  const items = Array.from(dataTransfer.items || []);
  const entries = items
    .map((item) => item.webkitGetAsEntry ? item.webkitGetAsEntry() : null)
    .filter(Boolean);

  if (!entries.length) {
    return Array.from(dataTransfer.files || []).map((file) => ({
      file,
      path: uploadPathForFile(file),
    }));
  }

  const uploads = [];
  for (const entry of entries) {
    uploads.push(...await collectUploadsFromEntry(entry));
  }
  return uploads;
}

async function collectUploadsFromEntry(entry, prefix = "") {
  if (entry.isFile) {
    return new Promise((resolve, reject) => {
      entry.file(
        (file) => resolve([{
          file,
          path: uploadPathForFile(file, `${prefix}${file.name}`),
        }]),
        reject,
      );
    });
  }

  if (!entry.isDirectory) return [];

  const children = await readAllDirectoryEntries(entry);
  const uploads = [];
  for (const child of children) {
    uploads.push(...await collectUploadsFromEntry(
      child,
      `${prefix}${entry.name}/`,
    ));
  }
  return uploads;
}

async function readAllDirectoryEntries(entry) {
  const reader = entry.createReader();
  const entries = [];
  while (true) {
    const batch = await new Promise((resolve, reject) =>
      reader.readEntries(resolve, reject)
    );
    if (!batch.length) return entries;
    entries.push(...batch);
  }
}

function updateFileList() {
  $("#file-list").innerHTML = pendingChallengeUploads
    .map(({ path }) => `<span>${esc(path)}</span>`).join("");
}

// === Create Challenge Submit ===
$("#challenge-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const agents = getAgentRows($("#challenge-agent-list"));
  const mode = agents.length > 1 ? "parallel" : "single";
  const fd = new FormData();
  fd.append("name", $("#challenge-name").value);
  fd.append("description", $("#challenge-desc").value);
  fd.append("flag_format", $("#challenge-flag").value);
  fd.append("mode", mode);
  fd.append("autonomous", $("#challenge-autonomous").checked ? "true" : "false");
  fd.append("agents", JSON.stringify(agents));

  for (const upload of pendingChallengeUploads) {
    fd.append("files", upload.file, upload.path);
  }

  const res = await api("/api/challenges", { method: "POST", body: fd });
  if (res.ok) {
    const data = await res.json();
    closeModal(); loadChallenges();
    if (data.id) {
      openChallenge(data.id);
    } else if (data.created) {
      openChallenge(data.created[0].id);
    }
    return;
  }
  const err = await res.json().catch(() => ({}));
  showToast(err.error || "Failed to create challenge", "error");
});

// === Bulk Upload ===
const bulkOverlay = $("#bulk-overlay");
const bulkFileInput = $("#bulk-file");
const bulkDropZone = $("#bulk-drop-zone");
let bulkPreviewToken = null;
let bulkPreviewChallenges = [];

function showBulkPhase(phase) {
  ["upload", "loading", "preview"].forEach((p) =>
    $("#bulk-phase-" + p).classList.toggle("hidden", p !== phase)
  );
}

function resetBulkModal() {
  bulkPreviewToken = null;
  bulkPreviewChallenges = [];
  bulkFileInput.value = "";
  $("#bulk-file-name").innerHTML = "";
  $("#bulk-challenge-list").innerHTML = "";
  const pausedCb = $("#bulk-paused");
  if (pausedCb) pausedCb.checked = false;
  showBulkPhase("upload");
}

$("#btn-bulk-upload").addEventListener("click", () => {
  resetBulkModal();
  populateAgentList($("#bulk-agent-list"));
  $("#bulk-autonomous").checked = getAgentAutonomousDefault(primaryAgentName());
  $("#bulk-flag").value = defaultFlagFormat;
  bulkOverlay.classList.remove("hidden");
});
$("#bulk-close").addEventListener("click", closeBulkModal);
bulkOverlay.addEventListener("click", (e) => {
  if (e.target === bulkOverlay) closeBulkModal();
});

function closeBulkModal() {
  bulkOverlay.classList.add("hidden");
  resetBulkModal();
}

$("#btn-add-bulk-agent").addEventListener("click", () => {
  addAgentRow($("#bulk-agent-list"));
});

bulkDropZone.addEventListener("dragover", (e) => { e.preventDefault(); bulkDropZone.classList.add("dragover"); });
bulkDropZone.addEventListener("dragleave", () => bulkDropZone.classList.remove("dragover"));
bulkDropZone.addEventListener("drop", (e) => {
  e.preventDefault(); bulkDropZone.classList.remove("dragover");
  if (e.dataTransfer.files.length) triggerBulkPreview(e.dataTransfer.files[0]);
});
bulkFileInput.addEventListener("change", () => {
  if (bulkFileInput.files.length) triggerBulkPreview(bulkFileInput.files[0]);
});

async function triggerBulkPreview(file) {
  $("#bulk-file-name").innerHTML = `<span>${esc(file.name)}</span>`;
  showBulkPhase("loading");

  const fd = new FormData();
  fd.append("zipfile", file);
  const res = await api(
    "/api/challenges/bulk-preview",
    { method: "POST", body: fd },
  );
  if (!res || !res.ok) {
    showBulkPhase("upload");
    const err = res ? await res.json().catch(() => ({})) : {};
    showToast(err.error || "Preview failed", "error");
    return;
  }

  const data = await res.json();
  bulkPreviewToken = data.preview_token;
  bulkPreviewChallenges = data.challenges || [];
  renderBulkPreview(bulkPreviewChallenges);
  showBulkPhase("preview");
}

function renderBulkPreview(challengesPreview) {
  const list = $("#bulk-challenge-list");
  list.innerHTML = challengesPreview.map((c, i) => {
    const fileLabel = c.files.length
      ? `${c.files.length} file${c.files.length !== 1 ? "s" : ""}: ${c.files.slice(0, 4).map(esc).join(", ")}${c.files.length > 4 ? ", ..." : ""}`
      : "No files";
    return `
    <div class="bulk-ch-row" data-index="${i}">
      <div class="bulk-ch-row-header">
        <input type="checkbox" class="bulk-ch-enabled" checked title="Include this challenge">
        <input type="text" class="bulk-ch-name" value="${esc(c.name)}" placeholder="Challenge name">
        <span class="bulk-ch-files-label">${esc(fileLabel)}</span>
      </div>
      <div class="bulk-ch-row-body">
        <div class="bulk-ch-col">
          <div class="bulk-field-label">Description</div>
          <textarea class="bulk-ch-desc" rows="2">${esc(c.description || "")}</textarea>
        </div>
        <div class="bulk-ch-col bulk-ch-col-flag">
          <div class="bulk-field-label">Flag Format</div>
          <input type="text" class="bulk-ch-flag" placeholder="Inherits default">
        </div>
      </div>
    </div>`;
  }).join("");

  list.querySelectorAll(".bulk-ch-enabled").forEach((cb) =>
    cb.addEventListener("change", () => {
      cb.closest(".bulk-ch-row").classList.toggle(
        "bulk-ch-disabled",
        !cb.checked,
      );
      updateBulkSubmitLabel();
    })
  );

  const pausedCb = $("#bulk-paused");
  if (pausedCb) {
    pausedCb.removeEventListener("change", updateBulkSubmitLabel);
    pausedCb.addEventListener("change", updateBulkSubmitLabel);
  }
  updateBulkSubmitLabel();
}

function updateBulkSubmitLabel() {
  const selected = document.querySelectorAll(".bulk-ch-enabled:checked").length;
  const btn = $("#btn-bulk-submit");
  if (!btn) return;
  const startNow = !$("#bulk-paused") || !$("#bulk-paused").checked;
  const verb = startNow ? "Create & Solve" : "Create";
  btn.textContent = `${verb} ${selected} Challenge${selected !== 1 ? "s" : ""}`;
}

$("#btn-bulk-submit").addEventListener("click", async () => {
  if (!bulkPreviewToken) return;

  const agentRows = getAgentRows($("#bulk-agent-list"));
  const mode = agentRows.length > 1 ? "parallel" : "single";
  const rows = document.querySelectorAll(".bulk-ch-row");
  const challengeConfigs = Array.from(rows).map((row, i) => ({
    folder_name: bulkPreviewChallenges[i].folder_name,
    name: row.querySelector(".bulk-ch-name").value.trim(),
    description: row.querySelector(".bulk-ch-desc").value.trim(),
    flag_format: row.querySelector(".bulk-ch-flag").value.trim(),
    enabled: row.querySelector(".bulk-ch-enabled").checked,
  }));

  const btn = $("#btn-bulk-submit");
  btn.disabled = true;
  btn.textContent = "Creating...";
  try {
    const res = await api("/api/challenges/bulk", {
      method: "POST",
      body: JSON.stringify({
        preview_token: bulkPreviewToken,
        flag_format: $("#bulk-flag").value.trim(),
        mode: mode,
        agents: JSON.stringify(agentRows),
        model: "",
        effort: "",
        autonomous: $("#bulk-autonomous").checked,
        paused: $("#bulk-paused") ? $("#bulk-paused").checked : false,
        challenges: challengeConfigs,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToast(err.error || "Upload failed", "error");
      return;
    }
    const data = await res.json();
    showToast(`Created ${data.created.length} challenge(s)`, "success");
    closeBulkModal();
    loadChallenges();
  } finally {
    btn.disabled = false;
    updateBulkSubmitLabel();
  }
});

// === Detail View ===
async function openChallenge(id) {
  history.replaceState(null, "", `#/challenge/${id}`);
  currentChallengeId = id;
  stepCount = 0;
  pendingTools.clear();
  foundFlags.clear();
  flagDetails.clear();
  runToolCounts.clear();
  runStepCounts.clear();
  runStats.clear();
  statsUseSnapshot = false;
  if (statsRefreshTimer) {
    clearTimeout(statsRefreshTimer);
    statsRefreshTimer = null;
  }
  $("#manual-flag-input").value = "";
  $("#flags-list").innerHTML = "";
  $("#flags-section").classList.add("hidden");

  const res = await api("/api/challenges");
  if (!res) return;
  const challenges = await res.json();
  const c = challenges.find((x) => x.id === id);
  if (!c) return;

  currentChallengeMode = c.mode || "single";
  currentRuns = c.runs || [];

  $("#detail-name").textContent = c.name;
  updateStatusBadge(c.status);

  // Mode badge
  const modeBadge = $("#detail-mode");
  modeBadge.textContent = currentChallengeMode.replace(/_/g, " ");

  // Model badge: show first run's model for single modes, run count for parallel
  const modelBadge = $("#detail-model");
  if (isParallelMode(currentChallengeMode)) {
    modelBadge.textContent = `${currentRuns.length} runs`;
    modelBadge.className = "badge badge-model";
  } else if (currentRuns.length > 0) {
    const run = currentRuns[0];
    const agentMeta = getAgentMeta(run.agent);
    if (agentMeta.badge_mode === "label") {
      modelBadge.textContent = agentMeta.label;
      modelBadge.className = `badge badge-agent-${run.agent}`;
    } else {
      modelBadge.textContent = run.model || agentMeta.default_model;
      modelBadge.className = "badge badge-model";
    }
  } else {
    modelBadge.textContent = "";
  }

  $("#detail-desc").textContent = c.description || "No description";
  challengeFlagFormat = c.flag_format || "";
  challengeFlagFormats = (c.flag_formats && c.flag_formats.length)
    ? c.flag_formats
    : (challengeFlagFormat ? [challengeFlagFormat] : []);
  $("#detail-flag-format").textContent = challengeFlagFormats.length
    ? `Flag: ${challengeFlagFormats.join(", ")}`
    : "";
  renderFlagFormats();
  $("#detail-files").textContent = c.files.length ? `Files: ${c.files.join(", ")}` : "No files";

  const errorBanner = $("#error-banner");
  if (c.error) {
    errorBanner.textContent = c.error;
    errorBanner.classList.remove("hidden");
  } else {
    errorBanner.classList.add("hidden");
  }

  // Reset timer / cost
  lastThinkingEl = null;
  $("#detail-timer").textContent = "";
  foundFlags.clear(); flagDetails.clear(); $("#flags-list").innerHTML = ""; $("#flags-section").classList.add("hidden");
  clearTranscriptSearch();
  currentFlagQuestions = c.flag_questions || [];

  // Restore persisted flags
  const df = c.detected_flags || {};
  const flagMeta = c.detected_flag_meta || {};
  for (const [f, status] of Object.entries(df)) {
    showFlagBanner(f, flagMeta[f] || findFlagDetail(flagMeta, f) || {});
    if (status === "correct" || status === "wrong") setFlagStatus(f, status);
  }

  if (c.status === "solving") startTimer();
  else stopTimer();

  updateButtons(c.status);
  initRunTabs(currentRuns);
  $("#stats-panel").innerHTML = "";
  $("#files-tree").innerHTML = "";
  $("#files-breadcrumb").innerHTML = "";
  $("#file-counter").textContent = "0";
  fileBrowserPath = "";
  fileBrowserRequestToken++;
  updateCounters();
  showView("detail");
  switchTab("tab-info");
  updateSteerRunSelect();
  updateFilesRunSelect();
  connectAllRuns(id, currentRuns);
  // Seed stats from run metadata so the panel isn't blank for providers
  // that don't emit usage events (e.g. Codex without codex_usage).
  for (const run of currentRuns) {
    const s = getRunStats(run.id);
    if (run.duration_ms) s.durationMs = run.duration_ms;
  }
  renderStats();
  loadChallengeStatsSnapshot(id);
}

function updateStatusBadge(status) {
  const b = $("#detail-status");
  b.textContent = status;
  b.className = `badge badge-${status}`;
}

function updateButtons(status) {
  $("#btn-start").classList.toggle("hidden", status !== "pending");
  $("#btn-retry").classList.toggle("hidden", status !== "failed" && status !== "completed");
  $("#btn-resume").classList.toggle("hidden", status !== "failed" && status !== "completed");
  $("#btn-unsolve").classList.toggle("hidden", status !== "solved");

  $("#btn-stop").classList.toggle("hidden", status !== "solving");
}

function updateCounters() {
  $("#step-counter").textContent = stepCount ? `${stepCount} steps` : "";
}

function durationMs(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function runTimerMs(run) {
  if (!run) return 0;
  let total = durationMs(run.duration_ms);
  if (run.status === "solving" && run._timerStartedAt) {
    total += Math.max(0, Date.now() - run._timerStartedAt);
  }
  return total;
}

function currentChallengeTimerMs() {
  return currentRuns.reduce((sum, run) => sum + runTimerMs(run), 0);
}

function activateRunTimer(run, reset = false) {
  if (!run) return;
  if (reset) run.duration_ms = 0;
  run.status = "solving";
  run._timerStartedAt = Date.now();
}

function freezeRunTimer(run) {
  if (!run || !run._timerStartedAt) return;
  run.duration_ms = runTimerMs(run);
  delete run._timerStartedAt;
}

function syncRunTimerState() {
  const now = Date.now();
  for (const run of currentRuns) {
    if (run.status === "solving") {
      if (!run._timerStartedAt) run._timerStartedAt = now;
    } else {
      freezeRunTimer(run);
    }
  }
}

function markRunsSolving(runId = "", options = {}) {
  for (const run of currentRuns) {
    if (runId && run.id !== runId) continue;
    if (run.status === "solved") continue;
    activateRunTimer(run, !!options.reset);
  }
}

function applyRunStatusEvent(event, fallbackRunId) {
  const rid = event.run_id || fallbackRunId;
  const run = currentRuns.find((r) => r.id === rid);
  if (!run) return;
  if (event.duration_ms !== undefined && event.duration_ms !== null) {
    run.duration_ms = durationMs(event.duration_ms);
  }
  if (event.status) run.status = event.status;
  if (run.status === "solving") {
    run._timerStartedAt = Date.now();
  } else {
    delete run._timerStartedAt;
  }
}

// === Detail Buttons ===
$("#btn-back").addEventListener("click", () => {
  disconnectAllWS(); stopTimer(); currentChallengeId = null;
  history.replaceState(null, "", "#");
  showView("dashboard"); loadChallenges();
});

$("#btn-start").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  const res = await api(`/api/challenges/${currentChallengeId}/solve`, { method: "POST" });
  if (res && res.ok) {
    markRunsSolving();
    updateStatusBadge("solving"); updateButtons("solving"); startTimer();
  }
});

$("#btn-retry").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  initRunTabs([]);
  $("#error-banner").classList.add("hidden");
  foundFlags.clear(); flagDetails.clear(); $("#flags-list").innerHTML = ""; $("#flags-section").classList.add("hidden");
  stepCount = 0;
  lastThinkingEl = null;
  pendingTools.clear(); runToolCounts.clear(); runStepCounts.clear(); runStats.clear(); statsUseSnapshot = false; updateCounters();
  const res = await api(`/api/challenges/${currentChallengeId}/solve`, { method: "POST" });
  if (res && res.ok) {
    markRunsSolving("", { reset: true });
    updateStatusBadge("solving"); updateButtons("solving"); startTimer();
    // Re-open to pick up new runs from the server
    openChallenge(currentChallengeId);
  }
});

$("#btn-resume").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  const res = await api(`/api/challenges/${currentChallengeId}/solve?resume=1`, { method: "POST" });
  if (res && res.ok) {
    markRunsSolving();
    updateStatusBadge("solving"); updateButtons("solving"); startTimer();
    openChallenge(currentChallengeId);
  }
});

$("#btn-unsolve").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  const res = await api(`/api/challenges/${currentChallengeId}/unsolve`, { method: "POST" });
  if (res && res.ok) {
    openChallenge(currentChallengeId);
  }
});

$("#btn-stop").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  const res = await api(`/api/challenges/${currentChallengeId}/stop`, { method: "POST" });
  if (res && res.ok) {
    const data = await res.json().catch(() => ({}));
    if (data.status) {
      updateStatusBadge(data.status);
      updateButtons(data.status);
      if (["solved", "failed", "completed"].includes(data.status)) stopTimer();
    }
    openChallenge(currentChallengeId);
  }
});

$("#btn-add-flag-format").addEventListener("click", addFlagFormatAndScan);
$("#flag-format-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    addFlagFormatAndScan();
  }
});
$("#btn-add-manual-flag").addEventListener("click", addManualFlag);
$("#manual-flag-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    addManualFlag();
  }
});


$("#btn-delete").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  if (!confirm("Delete this challenge?")) return;
  await api(`/api/challenges/${currentChallengeId}`, { method: "DELETE" });
  disconnectAllWS(); stopTimer(); currentChallengeId = null;
  history.replaceState(null, "", "#");
  showView("dashboard"); loadChallenges();
});

// === WebSocket Per-Run ===
function setWsStatus(status) {
  const el = $("#ws-status");
  if (!el) return;
  el.className = `ws-indicator ws-${status}`;
  el.title = status === "connected" ? "Connected"
    : status === "reconnecting" ? "Reconnecting..." : "Disconnected";
}

function connectAllRuns(challengeId, runs) {
  disconnectAllWS();
  if (!runs || !runs.length) {
    setWsStatus("disconnected");
    return;
  }
  const token = historyLoadToken;
  (async () => {
    for (const run of runs) {
      if (token !== historyLoadToken || currentChallengeId !== challengeId) return;
      await loadInitialRunHistoryAndConnect(challengeId, run, token);
    }
  })();
}

function connectGlobalWS() {
  if (globalWs && globalWs.readyState <= WebSocket.OPEN) return;
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  globalWs = new WebSocket(`${proto}//${location.host}/ws/events`);
  globalWs.onmessage = (e) => {
    const event = JSON.parse(e.data);
    if (event.type === "flag_found") {
      if (event.challenge_id === currentChallengeId && event.flag) {
        showFlagBanner(event.flag, event.meta || {});
      }
      showFlagFoundToast(
        event.challenge_name || "Challenge",
        event.agent || "Agent",
        event.flag || "???",
        event.challenge_id
      );
    }
    if (event.type === "flag_result" && event.flag) {
      if (event.challenge_id === currentChallengeId) {
        if (event.flag_questions) {
          currentFlagQuestions = event.flag_questions;
          updateFlagTargetSelects();
        }
        setFlagStatus(event.flag, event.correct ? "correct" : "wrong", event.meta || null);
      }
    }
    if (event.type === "challenge_status" && event.challenge_id) {
      updateDashboardChallengeStatus(event.challenge_id, event.status);
    }
  };
  globalWs.onclose = () => {
    globalWs = null;
    if (csrfToken) setTimeout(connectGlobalWS, 3000);
  };
}

function disconnectGlobalWS() {
  if (!globalWs) return;
  globalWs.onclose = null;
  globalWs.close();
  globalWs = null;
}

function updateDashboardChallengeStatus(challengeId, status) {
  const card = document.querySelector(`[data-id="${challengeId}"]`);
  if (!card) return;
  const badge = card.querySelector(".badge");
  if (!badge) return;
  badge.textContent = status;
  badge.className = "badge badge-" + status;
}

function isTranscriptEvent(event) {
  return !["run_status", "challenge_status", "run_added", "flag_found"].includes(event.type);
}

function rememberTranscriptEvent(runId, event) {
  if (!isTranscriptEvent(event)) return;
  const state = runHistoryState.get(runId) || {
    total: 0,
    nextBefore: null,
    hasMore: false,
    loading: false,
  };
  state.total = (state.total || 0) + 1;
  runHistoryState.set(runId, state);
}

function yieldToBrowser() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function fetchRunEvents(challengeId, runId, params = {}) {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) qs.set(key, String(value));
  }
  const res = await api(
    `/api/challenges/${encodeURIComponent(challengeId)}/runs/${encodeURIComponent(runId)}/events?${qs}`
  );
  if (!res || !res.ok) {
    throw new Error(`failed to load transcript (${res ? res.status : "network"})`);
  }
  return res.json();
}

function transcriptNodeKey(runId, eventIndex) {
  return `${runId}:${eventIndex}`;
}

function markRenderedEventNodes(runId, eventIndex, feed, startNode) {
  if (!Number.isInteger(eventIndex) || !feed) return;
  const nodes = [];
  let node = startNode ? startNode.nextSibling : feed.firstChild;
  while (node) {
    if (node.nodeType === Node.ELEMENT_NODE) {
      node.dataset.runId = runId;
      node.dataset.eventIndex = String(eventIndex);
      nodes.push(node);
    }
    node = node.nextSibling;
  }
  if (nodes.length) {
    renderedEventNodes.set(transcriptNodeKey(runId, eventIndex), nodes[0]);
  }
}

function renderRunEventWithIndex(runId, event, eventIndex = null) {
  const feed = document.getElementById(`feed-${runId}`) || document.getElementById("feed-__default__");
  const marker = feed ? feed.lastChild : null;
  renderRunEvent(runId, event);
  markRenderedEventNodes(runId, eventIndex, feed, marker);
}

async function renderEventsChunked(runId, events, options = {}) {
  if (!events || !events.length) return;
  const feed = document.getElementById(`feed-${runId}`) || document.getElementById("feed-__default__");
  if (!feed) return;

  const prepend = options.prepend === true;
  let insertMarker = null;
  let appendMarker = null;
  let previousHeight = 0;
  let previousTop = 0;
  if (prepend) {
    previousHeight = feed.scrollHeight;
    previousTop = feed.scrollTop;
    const historyControls = feed.querySelector(".history-load-controls");
    const insertBefore = historyControls ? historyControls.nextSibling : feed.firstChild;
    insertMarker = document.createComment("older-history-insert");
    appendMarker = document.createComment("older-history-append");
    feed.insertBefore(insertMarker, insertBefore);
    feed.appendChild(appendMarker);
  }

  historyRenderDepth++;
  try {
    for (let i = 0; i < events.length; i += TRANSCRIPT_RENDER_BATCH) {
      const chunk = events.slice(i, i + TRANSCRIPT_RENDER_BATCH);
      for (let j = 0; j < chunk.length; j++) {
        const eventIndex = Number.isInteger(options.startIndex)
          ? options.startIndex + i + j
          : null;
        renderRunEventWithIndex(runId, chunk[j], eventIndex);
      }
      if (!prepend && i + TRANSCRIPT_RENDER_BATCH < events.length) await yieldToBrowser();
    }
  } finally {
    historyRenderDepth--;
    if (prepend && insertMarker?.parentNode && appendMarker?.parentNode) {
      const fragment = document.createDocumentFragment();
      let node = appendMarker.nextSibling;
      while (node) {
        const next = node.nextSibling;
        fragment.appendChild(node);
        node = next;
      }
      appendMarker.remove();
      feed.insertBefore(fragment, insertMarker);
      insertMarker.remove();
      feed.scrollTop = previousTop + (feed.scrollHeight - previousHeight);
    }
    flushDeferredStats();
  }
}

function updateHistoryLoadButton(runId) {
  const feed = document.getElementById(`feed-${runId}`);
  if (!feed) return;
  const state = runHistoryState.get(runId);
  let controls = feed.querySelector(".history-load-controls");
  if (!state?.hasMore) {
    if (controls) controls.remove();
    return;
  }
  if (!controls) {
    controls = document.createElement("div");
    controls.className = "history-load-controls";

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn-ghost btn-sm history-load-btn";
    btn.addEventListener("click", () => loadOlderRunEvents(runId));

    const allBtn = document.createElement("button");
    allBtn.type = "button";
    allBtn.className = "btn-ghost btn-sm history-load-all-btn";
    allBtn.addEventListener("click", () => loadAllRunEvents(runId));

    controls.append(btn, allBtn);
    feed.insertBefore(controls, feed.firstChild);
  }
  const btn = controls.querySelector(".history-load-btn");
  const allBtn = controls.querySelector(".history-load-all-btn");
  if (btn) {
    btn.disabled = !!state.loading;
    btn.textContent = state.loadingAll
      ? "Loading older messages..."
      : state.loading ? "Loading older messages..." : "Load older messages";
  }
  if (allBtn) {
    allBtn.disabled = !!state.loading;
    allBtn.textContent = state.loadingAll ? "Loading all messages..." : "Load All Messages";
  }
}

async function loadHistoryPage(runId, state, challengeId, token, limit) {
  const data = await fetchRunEvents(challengeId, runId, {
    before: state.nextBefore,
    limit,
  });
  if (token !== historyLoadToken || currentChallengeId !== challengeId) return false;
  state.total = Math.max(state.total || 0, data.total || 0);
  state.nextBefore = data.next_before;
  state.hasMore = !!data.has_more;
  await renderEventsChunked(runId, data.events || [], {
    prepend: true,
    startIndex: data.start || 0,
  });
  return true;
}

async function loadOlderRunEvents(runId) {
  const state = runHistoryState.get(runId);
  if (!state || !state.hasMore || state.loading || !currentChallengeId) return;
  const challengeId = currentChallengeId;
  const token = historyLoadToken;
  state.loading = true;
  state.loadingAll = false;
  updateHistoryLoadButton(runId);
  historyLoadingRuns.add(runId);
  try {
    await loadHistoryPage(runId, state, challengeId, token, TRANSCRIPT_PAGE_EVENTS);
  } catch (err) {
    console.warn("Failed to load older transcript events", err);
    showToast("Failed to load older messages", "error");
  } finally {
    state.loading = false;
    state.loadingAll = false;
    historyLoadingRuns.delete(runId);
    updateHistoryLoadButton(runId);
  }
}

async function loadAllRunEvents(runId) {
  const state = runHistoryState.get(runId);
  if (!state || !state.hasMore || state.loading || !currentChallengeId) return;
  const challengeId = currentChallengeId;
  const token = historyLoadToken;
  state.loading = true;
  state.loadingAll = true;
  updateHistoryLoadButton(runId);
  historyLoadingRuns.add(runId);
  try {
    while (
      state.hasMore &&
      token === historyLoadToken &&
      currentChallengeId === challengeId
    ) {
      const loaded = await loadHistoryPage(runId, state, challengeId, token, 500);
      if (!loaded || !state.hasMore) break;
      await yieldToBrowser();
    }
  } catch (err) {
    console.warn("Failed to load full transcript", err);
    showToast("Failed to load all messages", "error");
  } finally {
    state.loading = false;
    state.loadingAll = false;
    historyLoadingRuns.delete(runId);
    updateHistoryLoadButton(runId);
  }
}

async function loadRunEventsThrough(runId, eventIndex) {
  let state = runHistoryState.get(runId);
  while (
    state &&
    state.hasMore &&
    !state.loading &&
    Number.isInteger(state.nextBefore) &&
    state.nextBefore > eventIndex
  ) {
    await loadOlderRunEvents(runId);
    state = runHistoryState.get(runId);
  }
}

async function loadInitialRunHistoryAndConnect(challengeId, run, token) {
  const runId = run.id;
  const state = {
    total: 0,
    nextBefore: null,
    hasMore: false,
    loading: true,
    loadingAll: false,
  };
  runHistoryState.set(runId, state);
  historyLoadingRuns.add(runId);
  updateHistoryLoadButton(runId);

  try {
    const data = await fetchRunEvents(challengeId, runId, {
      limit: INITIAL_TRANSCRIPT_EVENTS,
    });
    if (token !== historyLoadToken || currentChallengeId !== challengeId) return;

    state.total = data.total || 0;
    state.nextBefore = data.next_before;
    state.hasMore = !!data.has_more;
    state.loading = false;
    await renderEventsChunked(runId, data.events || [], {
      startIndex: data.start || 0,
    });
    updateHistoryLoadButton(runId);
    connectRunWS(challengeId, runId, run.agent, { after: state.total || 0 });
  } catch (err) {
    console.warn("Failed to load initial transcript history", err);
    if (token !== historyLoadToken || currentChallengeId !== challengeId) return;
    state.loading = false;
    historyLoadingRuns.delete(runId);
    updateHistoryLoadButton(runId);
    showToast("Failed to load transcript history; live updates still connected", "error");
    connectRunWS(challengeId, runId, run.agent, { history: false });
  }
}

async function searchTranscript() {
  const input = $("#transcript-search-input");
  const resultsEl = $("#transcript-search-results");
  const clearBtn = $("#btn-transcript-search-clear");
  if (!input || !resultsEl || !currentChallengeId) return;
  const query = input.value.trim();
  transcriptSearchResults = [];
  transcriptSearchActiveIndex = -1;
  if (!query) {
    resultsEl.classList.add("hidden");
    clearTranscriptSearchHighlight();
    if (clearBtn) clearBtn.classList.add("hidden");
    return;
  }

  resultsEl.classList.remove("hidden");
  resultsEl.innerHTML = '<div class="transcript-search-summary">Searching...</div>';
  if (clearBtn) clearBtn.classList.remove("hidden");
  const qs = new URLSearchParams({ q: query, limit: "100" });
  const res = await api(`/api/challenges/${currentChallengeId}/transcript-search?${qs}`);
  if (!res || !res.ok) {
    resultsEl.innerHTML = '<div class="transcript-search-summary">Search failed</div>';
    return;
  }
  renderTranscriptSearchResults(await res.json());
}

function renderTranscriptSearchResults(data) {
  const resultsEl = $("#transcript-search-results");
  if (!resultsEl) return;
  transcriptSearchResults = data.matches || [];
  transcriptSearchActiveIndex = -1;
  if (!transcriptSearchResults.length) {
    resultsEl.innerHTML = '<div class="transcript-search-summary">No matches</div>';
    return;
  }
  const suffix = data.truncated ? " shown, refine search for more" : "";
  resultsEl.innerHTML = `
    <div class="transcript-search-summary">${transcriptSearchResults.length} match${transcriptSearchResults.length !== 1 ? "es" : ""}${suffix}</div>
    ${transcriptSearchResults.map((match, idx) => `
      <button class="transcript-search-result" data-index="${idx}">
        <span class="transcript-search-result-meta">${esc(runLabelForSearch(match.run_id, match.run_label))} &middot; event ${match.event_index} &middot; ${esc(match.event_type || "event")}</span>
        <span class="transcript-search-result-preview">${esc(match.preview || "")}</span>
      </button>
    `).join("")}
  `;
  resultsEl.querySelectorAll(".transcript-search-result").forEach((btn) => {
    btn.addEventListener("click", () => {
      focusTranscriptSearchResult(Number(btn.dataset.index));
    });
  });
}

function runLabelForSearch(runId, fallback) {
  const run = currentRuns.find((r) => r.id === runId);
  if (!run) return fallback || runId;
  const meta = getAgentMeta(run.agent);
  return meta.label || run.agent || fallback || runId;
}

function clearTranscriptSearchHighlight() {
  document.querySelectorAll(".transcript-search-hit").forEach((el) =>
    el.classList.remove("transcript-search-hit")
  );
}

async function focusTranscriptSearchResult(index) {
  const result = transcriptSearchResults[index];
  if (!result) return;
  transcriptSearchActiveIndex = index;
  await focusTranscriptEvent(result.run_id, result.event_index);
}

async function focusTranscriptEvent(runId, eventIndex) {
  if (!isSplitView() && activeRunId !== runId) switchRunTab(runId);

  let node = renderedEventNodes.get(transcriptNodeKey(runId, eventIndex));
  if (!node) {
    await loadRunEventsThrough(runId, eventIndex);
    node = renderedEventNodes.get(transcriptNodeKey(runId, eventIndex));
  }
  if (!node) {
    showToast("Transcript event is not loaded yet", "info");
    return;
  }
  clearTranscriptSearchHighlight();
  node.classList.add("transcript-search-hit");
  node.scrollIntoView({ block: "center", behavior: "smooth" });
}

function clearTranscriptSearch() {
  const input = $("#transcript-search-input");
  const resultsEl = $("#transcript-search-results");
  const clearBtn = $("#btn-transcript-search-clear");
  if (input) input.value = "";
  if (resultsEl) resultsEl.classList.add("hidden");
  if (clearBtn) clearBtn.classList.add("hidden");
  transcriptSearchResults = [];
  transcriptSearchActiveIndex = -1;
  clearTranscriptSearchHighlight();
}

function enqueueRunEvent(runId, event, afterRender) {
  queuedRunEvents.push({ runId, event, afterRender });
  if (queuedRunEventFrame) return;
  queuedRunEventFrame = true;
  requestAnimationFrame(flushQueuedRunEvents);
}

function renderQueuedRunItem(item) {
  const state = runHistoryState.get(item.runId);
  const eventIndex = isTranscriptEvent(item.event) && state
    ? state.total || 0
    : null;
  renderRunEventWithIndex(item.runId, item.event, eventIndex);
  if (item.afterRender) item.afterRender(item.event);
}

function flushQueuedRunEventsNow(runId) {
  if (!queuedRunEvents.length) return;
  const remaining = [];
  for (const item of queuedRunEvents) {
    if (runId == null || item.runId === runId) renderQueuedRunItem(item);
    else remaining.push(item);
  }
  queuedRunEvents = remaining;
  if (!queuedRunEvents.length) queuedRunEventFrame = false;
}

function flushQueuedRunEvents() {
  queuedRunEventFrame = false;
  const batch = queuedRunEvents.splice(0, LIVE_RENDER_BATCH);
  for (const item of batch) {
    renderQueuedRunItem(item);
  }
  if (queuedRunEvents.length) {
    queuedRunEventFrame = true;
    requestAnimationFrame(flushQueuedRunEvents);
  }
}

function connectRunWS(challengeId, runId, agentLabel, options = {}) {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams();
  if (Number.isInteger(options.after)) {
    params.set("after", String(options.after));
  } else if (options.history === false) {
    params.set("history", "0");
  }
  const qs = params.toString();
  const ws = new WebSocket(
    `${proto}//${location.host}/ws/${encodeURIComponent(challengeId)}/${encodeURIComponent(runId)}${qs ? `?${qs}` : ""}`
  );
  let hydrating = true;
  historyLoadingRuns.add(runId);
  ws.onopen = () => {
    setWsStatus("connected");
  };
  ws.onmessage = (e) => {
    const event = JSON.parse(e.data);
    enqueueRunEvent(runId, event, (rendered) => {
      if (hydrating && rendered.type === "run_status") {
        hydrating = false;
        finishHistoryLoad(runId);
      } else {
        rememberTranscriptEvent(runId, rendered);
      }
    });
  };
  ws.onclose = () => {
    historyLoadingRuns.delete(runId);
    flushQueuedRunEventsNow(runId);
    if (currentChallengeId !== challengeId) return;
    // Don't reconnect if the run is in a terminal state
    const run = currentRuns.find(r => r.id === runId);
    if (run && ["solved", "completed", "failed"].includes(run.status)) return;
    // Check if any other connection is still open
    let anyOpen = false;
    for (const [rid, conn] of wsConnections) {
      if (rid !== runId && conn.readyState === WebSocket.OPEN) {
        anyOpen = true;
        break;
      }
    }
    if (!anyOpen) setWsStatus("reconnecting");
    setTimeout(() => {
      if (currentChallengeId === challengeId) {
        const state = runHistoryState.get(runId);
        connectRunWS(challengeId, runId, agentLabel, state ? { after: state.total || 0 } : undefined);
      }
    }, 2000);
  };
  wsConnections.set(runId, ws);
}

function disconnectAllWS() {
  historyLoadToken++;
  historyLoadingRuns.clear();
  runHistoryState.clear();
  renderedEventNodes.clear();
  queuedRunEvents = [];
  queuedRunEventFrame = false;
  if (statsRefreshTimer) {
    clearTimeout(statsRefreshTimer);
    statsRefreshTimer = null;
  }
  pendingScrollRuns.clear();
  scrollFramePending = false;
  for (const [, ws] of wsConnections) {
    ws.onclose = null;
    ws.close();
  }
  wsConnections.clear();
  setWsStatus("disconnected");
}

// === Scroll ===
function getActiveFeed() {
  if (!activeRunId) return null;
  return document.getElementById(`feed-${activeRunId}`);
}

function setupFeedScroll(feedEl) {
  if (!feedEl) return;
  feedEl.addEventListener("scroll", () => {
    autoScroll = feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight < 50;
    updateScrollBtn();
  });
}

function updateScrollBtn() {
  const btn = $("#btn-scroll-bottom");
  if (btn) btn.classList.toggle("hidden", autoScroll);
}

function scrollBottom() {
  const f = getActiveFeed();
  if (autoScroll && f) f.scrollTop = f.scrollHeight;
}

function flushPendingScrolls() {
  scrollFramePending = false;
  if (!autoScroll) {
    updateScrollBtn();
    pendingScrollRuns.clear();
    return;
  }
  if (isSplitView()) {
    for (const rid of pendingScrollRuns) {
      const f = document.getElementById(`feed-${rid}`);
      if (f) f.scrollTop = f.scrollHeight;
    }
  } else if (pendingScrollRuns.has(activeRunId)) {
    scrollBottom();
  }
  pendingScrollRuns.clear();
  updateScrollBtn();
}

function scrollBottomIfActive(runId) {
  if (historyLoadingRuns.has(runId)) return;
  if (!isSplitView() && runId !== activeRunId) return;
  pendingScrollRuns.add(runId);
  if (!scrollFramePending) {
    scrollFramePending = true;
    requestAnimationFrame(flushPendingScrolls);
  }
}

function finishHistoryLoad(runId) {
  historyLoadingRuns.delete(runId);
  requestAnimationFrame(() => {
    if (!autoScroll) {
      updateScrollBtn();
      return;
    }
    const f = document.getElementById(`feed-${runId}`);
    if (f && (isSplitView() || runId === activeRunId)) {
      f.scrollTop = f.scrollHeight;
    }
    updateScrollBtn();
  });
}

// === Run Tabs ===
function isSplitView() {
  return chatViewMode === "split" && currentRuns.length > 1;
}

function runTabLabel(run, agentMeta) {
  const base = agentMeta.label || run.agent;
  const parts = [];
  if (run.model) parts.push(run.model);
  if (run.effort) parts.push(run.effort);
  return parts.length ? `${base} (${parts.join(", ")})` : base;
}

function initRunTabs(runs) {
  currentRuns = runs;
  const tabBar = $("#run-tabs");
  const feedsEl = $("#run-feeds");

  // Clear existing feeds but keep the scroll button
  tabBar.innerHTML = "";
  const scrollBtn = feedsEl.querySelector("#btn-scroll-bottom");
  feedsEl.innerHTML = "";
  if (scrollBtn) feedsEl.appendChild(scrollBtn);

  // Remove split mode classes
  feedsEl.classList.remove("split-mode");
  delete feedsEl.dataset.panes;
  tabBar.classList.remove("hidden");

  if (!runs.length) {
    // Create a default placeholder feed
    activeRunId = "__default__";
    const btn = document.createElement("button");
    btn.className = "run-tab active";
    btn.dataset.run = "__default__";
    btn.innerHTML = '<span class="run-tab-dot dot-running"></span>Main';
    tabBar.appendChild(btn);

    const feed = document.createElement("div");
    feed.id = "feed-__default__";
    feed.className = "panel-body run-feed active";
    feedsEl.insertBefore(feed, scrollBtn);
    setupFeedScroll(feed);
    return;
  }

  activeRunId = runs[0].id;
  const useSplit = chatViewMode === "split" && runs.length > 1;

  const globalSteer = $("#steer-bar");
  if (useSplit) {
    feedsEl.classList.add("split-mode");
    feedsEl.dataset.panes = String(runs.length);
    tabBar.classList.add("hidden");
    globalSteer.classList.add("hidden");
  } else {
    globalSteer.classList.remove("hidden");
  }

  for (const run of runs) {
    const agentMeta = getAgentMeta(run.agent);
    const label = runTabLabel(run, agentMeta);
    const dotClass = run.status === "solving" ? "dot-running"
      : run.status === "solved" ? "dot-solved"
      : run.status === "failed" ? "dot-error"
      : run.status === "completed" ? "dot-done"
      : run.status === "pending" ? "dot-pending"
      : "dot-running";

    if (!useSplit) {
      const btn = document.createElement("button");
      btn.className = `run-tab${run.id === activeRunId ? " active" : ""}`;
      btn.dataset.run = run.id;
      btn.innerHTML = `<span class="run-tab-dot ${dotClass}"></span>${esc(label)}`;
      btn.addEventListener("click", () => switchRunTab(run.id));
      tabBar.appendChild(btn);
    }

    if (useSplit) {
      const pane = document.createElement("div");
      pane.className = "split-pane";
      pane.innerHTML = `<div class="split-pane-header"><span class="run-tab-dot ${dotClass}"></span>${esc(label)}</div>`;
      const feed = document.createElement("div");
      feed.id = `feed-${run.id}`;
      feed.className = "panel-body run-feed active";
      pane.appendChild(feed);

      const steer = document.createElement("div");
      steer.className = "steer-bar split-steer";
      steer.innerHTML = `<input type="text" class="split-steer-input" placeholder="Guide ${esc(label)}..." autocomplete="off"><button class="btn-primary btn-sm split-steer-btn">Send</button>`;
      const steerInput = steer.querySelector(".split-steer-input");
      const steerBtn = steer.querySelector(".split-steer-btn");
      const sendFn = () => sendSteerToRun(run.id, steerInput);
      steerBtn.addEventListener("click", sendFn);
      steerInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendFn(); }
      });
      pane.appendChild(steer);

      feedsEl.insertBefore(pane, scrollBtn);
      setupFeedScroll(feed);
    } else {
      const feed = document.createElement("div");
      feed.id = `feed-${run.id}`;
      feed.className = `panel-body run-feed${run.id === activeRunId ? " active" : ""}`;
      feedsEl.insertBefore(feed, scrollBtn);
      setupFeedScroll(feed);
    }
  }
}

function switchRunTab(runId) {
  activeRunId = runId;
  document.querySelectorAll(".run-tab").forEach((t) => t.classList.remove("active"));
  document.querySelectorAll(".run-feed").forEach((f) => f.classList.remove("active"));
  const btn = document.querySelector(`[data-run="${runId}"]`);
  if (btn) btn.classList.add("active");
  const feed = document.getElementById(`feed-${runId}`);
  if (feed) { feed.classList.add("active"); autoScroll = true; scrollBottom(); }
  updateSteerRunSelect();
}

function addRunTab(run) {
  const tabBar = $("#run-tabs");
  const feedsEl = $("#run-feeds");
  const scrollBtn = feedsEl.querySelector("#btn-scroll-bottom");

  const agentMeta = getAgentMeta(run.agent);
  const label = runTabLabel(run, agentMeta);
  const dotClass = run.status === "solving" ? "dot-running"
    : run.status === "solved" ? "dot-solved"
    : run.status === "failed" ? "dot-error"
    : run.status === "completed" ? "dot-done"
    : run.status === "pending" ? "dot-pending"
    : "dot-running";

  const useSplit = isSplitView();

  if (!useSplit) {
    const btn = document.createElement("button");
    btn.className = "run-tab";
    btn.dataset.run = run.id;
    btn.innerHTML = `<span class="run-tab-dot ${dotClass}"></span>${esc(label)}`;
    btn.addEventListener("click", () => switchRunTab(run.id));
    tabBar.appendChild(btn);

    const feed = document.createElement("div");
    feed.id = `feed-${run.id}`;
    feed.className = "panel-body run-feed";
    feedsEl.insertBefore(feed, scrollBtn);
    setupFeedScroll(feed);
  } else {
    const pane = document.createElement("div");
    pane.className = "split-pane";
    pane.innerHTML = `<div class="split-pane-header"><span class="run-tab-dot ${dotClass}"></span>${esc(label)}</div>`;
    const feed = document.createElement("div");
    feed.id = `feed-${run.id}`;
    feed.className = "panel-body run-feed active";
    pane.appendChild(feed);

    const steer = document.createElement("div");
    steer.className = "steer-bar split-steer";
    steer.innerHTML = `<input type="text" class="split-steer-input" placeholder="Guide ${esc(label)}..." autocomplete="off"><button class="btn-primary btn-sm split-steer-btn">Send</button>`;
    const steerInput = steer.querySelector(".split-steer-input");
    const steerBtn = steer.querySelector(".split-steer-btn");
    const sendFn = () => sendSteerToRun(run.id, steerInput);
    steerBtn.addEventListener("click", sendFn);
    steerInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendFn(); }
    });
    pane.appendChild(steer);

    feedsEl.insertBefore(pane, scrollBtn);
    setupFeedScroll(feed);
  }
}

function updateRunTabDot(runId, status) {
  const dotMap = {
    solved: "dot-solved",
    failed: "dot-error",
    error: "dot-error",
    solving: "dot-running",
    completed: "dot-done",
    pending: "dot-pending",
  };
  const cls = `run-tab-dot ${dotMap[status] || "dot-done"}`;

  // Tab button dot
  const btn = document.querySelector(`[data-run="${runId}"]`);
  if (btn) {
    const dot = btn.querySelector(".run-tab-dot");
    if (dot) dot.className = cls;
  }
  // Split pane header dot
  const feed = document.getElementById(`feed-${runId}`);
  if (feed) {
    const pane = feed.closest(".split-pane");
    if (pane) {
      const dot = pane.querySelector(".run-tab-dot");
      if (dot) dot.className = cls;
    }
  }
}

// === Steer Run Select ===
function updateSteerRunSelect() {
  const label = $("#steer-run-select");
  if (isParallelMode(currentChallengeMode) && currentRuns.length > 1) {
    const activeRun = currentRuns.find((r) => r.id === activeRunId);
    if (activeRun) {
      const meta = getAgentMeta(activeRun.agent);
      label.textContent = meta.label || activeRun.agent;
      label.classList.remove("hidden");
    } else {
      label.classList.add("hidden");
    }
  } else {
    label.classList.add("hidden");
  }
}

// === Files Run Select ===
function updateFilesRunSelect() {
  const sel = $("#files-run-select");
  if (currentRuns.length > 0) {
    sel.classList.remove("hidden");
    sel.innerHTML = '<option value="">Challenge files</option>' +
      currentRuns.map((r) => {
        const meta = getAgentMeta(r.agent);
        const label = `${meta.label || r.agent} workspace`;
        return `<option value="${esc(r.id)}">${esc(label)}</option>`;
      }).join("");
    if (!isParallelMode(currentChallengeMode) && currentRuns.length === 1) {
      sel.value = currentRuns[0].id;
    }
  } else {
    sel.classList.add("hidden");
    sel.innerHTML = "";
  }
}

// === Markdown ===
function renderMarkdown(text) {
  let h = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Fenced code blocks
  h = h.replace(/```(\w*)\n([\s\S]*?)```/g,
    '<pre class="md-codeblock"><code>$2</code></pre>');

  // Inline code
  h = h.replace(/`([^`\n]+)`/g, '<code class="md-code">$1</code>');

  // Bold
  h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  // Italic
  h = h.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');

  // Headers
  h = h.replace(/^### (.+)$/gm, '<div class="md-h3">$1</div>');
  h = h.replace(/^## (.+)$/gm, '<div class="md-h2">$1</div>');
  h = h.replace(/^# (.+)$/gm, '<div class="md-h1">$1</div>');

  // Unordered lists
  h = h.replace(/^[*-] (.+)$/gm, '<li>$1</li>');

  // Numbered lists
  h = h.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');

  // Wrap consecutive <li> in <ul>
  h = h.replace(/((?:<li>.*<\/li>\n?)+)/g, '<ul class="md-list">$1</ul>');

  // Paragraphs (double newline)
  h = h.replace(/\n\n/g, '</p><p>');
  h = '<p>' + h + '</p>';
  h = h.replace(/<p><\/p>/g, '');

  // Clean up <p> wrapping block elements
  h = h.replace(/<p>(<(?:pre|ul|div|h\d)[^>]*>)/g, '$1');
  h = h.replace(/(<\/(?:pre|ul|div|h\d)>)<\/p>/g, '$1');

  return h;
}

// === Copy to Clipboard ===
function copyToClipboard(text, btnEl) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btnEl.textContent;
    btnEl.textContent = "Copied!";
    btnEl.classList.add("copied");
    setTimeout(() => { btnEl.textContent = orig; btnEl.classList.remove("copied"); }, 1200);
  });
}

function renderFlagFormats() {
  const list = $("#flag-format-list");
  if (!list) return;
  list.innerHTML = "";
  if (!challengeFlagFormats.length) {
    const empty = document.createElement("div");
    empty.className = "flag-format-empty";
    empty.textContent = "No custom formats";
    list.appendChild(empty);
    return;
  }
  for (const fmt of challengeFlagFormats) {
    const pill = document.createElement("span");
    pill.className = "flag-format-pill";
    pill.textContent = fmt;
    list.appendChild(pill);
  }
}

async function addFlagFormatAndScan() {
  if (!currentChallengeId) return;
  const input = $("#flag-format-input");
  const btn = $("#btn-add-flag-format");
  const format = input.value.trim();
  if (!format) return;

  btn.disabled = true;
  const oldText = btn.textContent;
  btn.textContent = "Scanning...";
  const res = await api(`/api/challenges/${currentChallengeId}/flag-formats`, {
    method: "POST",
    body: JSON.stringify({ format }),
  });
  btn.disabled = false;
  btn.textContent = oldText;
  if (!res) return;
  const data = await res.json();
  if (data.error) {
    showToast(data.error, "error");
    return;
  }

  input.value = "";
  challengeFlagFormat = data.flag_format || challengeFlagFormat;
  challengeFlagFormats = data.flag_formats || challengeFlagFormats;
  $("#detail-flag-format").textContent = challengeFlagFormats.length
    ? `Flag: ${challengeFlagFormats.join(", ")}`
    : "";
  renderFlagFormats();

  const detected = data.detected || [];
  for (const item of detected) {
    if (!item.flag) continue;
    showFlagBanner(item.flag, item.meta || {});
    if (item.status === "correct" || item.status === "wrong") {
      setFlagStatus(item.flag, item.status, item.meta || null);
    }
  }
  const suffix = data.auto_submit && detected.length ? " and queued auto-submit" : "";
  showToast(`Format ${data.added ? "added" : "already exists"}; ${detected.length} flag${detected.length === 1 ? "" : "s"} found${suffix}.`);
}

async function addManualFlag() {
  if (!currentChallengeId) return;
  const input = $("#manual-flag-input");
  const btn = $("#btn-add-manual-flag");
  const flag = input.value.trim();
  if (!flag) return;

  btn.disabled = true;
  const oldText = btn.textContent;
  btn.textContent = "Adding...";
  const res = await api(`/api/challenges/${currentChallengeId}/flags`, {
    method: "POST",
    body: JSON.stringify({ flag }),
  });
  btn.disabled = false;
  btn.textContent = oldText;
  if (!res) return;
  const data = await res.json();
  if (data.error) {
    showToast(data.error, "error");
    return;
  }

  input.value = "";
  const storedFlag = data.flag || flag;
  showFlagBanner(storedFlag, data.meta || {});
  if (data.status === "correct" || data.status === "wrong") {
    setFlagStatus(storedFlag, data.status, data.meta || null);
  }
  showToast(data.added ? "Flag added" : "Flag already exists");
}

function makeCopyBtn(getText) {
  const btn = document.createElement("button");
  btn.className = "btn-copy";
  btn.textContent = "Copy";
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    copyToClipboard(typeof getText === "function" ? getText() : getText, btn);
  });
  return btn;
}

// === Flag Detection ===
function flagLookupKey(flag) {
  return String(flag || "").toLowerCase();
}

function checkForFlag(text) {
  const patterns = [
    /picoCTF\{[^}]+\}/gi,
    /flag\{[^}]+\}/gi,
    /FLAG\{[^}]+\}/gi,
    /CTF\{[^}]+\}/gi,
    /HTB\{[^}]+\}/gi,
  ];
  for (const fmt of challengeFlagFormats) {
    const prefix = String(fmt || "").replace(/\{.*/, "").trim();
    if (prefix.length >= 2) {
      patterns.push(
        new RegExp(prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
          + "\\{[^}]+\\}", "gi")
      );
    }
  }
  for (const pat of patterns) {
    pat.lastIndex = 0;
    let m;
    while ((m = pat.exec(text)) !== null) {
      const candidate = m[0];
      if (challengeFlagFormats.some((fmt) => flagLookupKey(candidate) === flagLookupKey(fmt))) {
        continue;
      }
      return candidate;
    }
  }
  return null;
}

const foundFlags = new Map();
const flagDetails = new Map();

function knownFlagFor(flag) {
  const wanted = flagLookupKey(flag);
  for (const existing of foundFlags.keys()) {
    if (flagLookupKey(existing) === wanted) return existing;
  }
  return null;
}

function selectorEscape(value) {
  if (window.CSS && CSS.escape) return CSS.escape(value);
  return String(value).replace(/["\\]/g, "\\$&");
}

function findFlagDetail(metaMap, flag) {
  const wanted = flagLookupKey(flag);
  for (const [key, value] of Object.entries(metaMap || {})) {
    if (flagLookupKey(key) === wanted) return value;
  }
  return null;
}

function mergeFlagDetail(flag, meta = {}) {
  const displayFlag = knownFlagFor(flag) || flag;
  const existing = flagDetails.get(displayFlag) || {};
  const merged = { ...existing, ...meta };
  const sources = [...(existing.sources || [])];
  for (const source of meta.sources || []) {
    const key = `${source.type || ""}:${source.run_id || ""}:${source.event_index ?? ""}`;
    if (!sources.some((item) => `${item.type || ""}:${item.run_id || ""}:${item.event_index ?? ""}` === key)) {
      sources.push(source);
    }
  }
  const submissions = [...(existing.submissions || [])];
  for (const sub of meta.submissions || []) {
    const key = `${sub.at || ""}:${sub.flag_id ?? ""}:${sub.submitted_flag || ""}:${sub.correct}`;
    if (!submissions.some((item) => `${item.at || ""}:${item.flag_id ?? ""}:${item.submitted_flag || ""}:${item.correct}` === key)) {
      submissions.push(sub);
    }
  }
  merged.sources = sources;
  merged.submissions = submissions;
  flagDetails.set(displayFlag, merged);
  return merged;
}

function flagQuestionLabel(question, idx) {
  const label = question.question || question.identifier || `Question ${idx + 1}`;
  const solved = question.solved ? " (solved)" : "";
  return `${idx + 1}. ${label}${solved}`;
}

function selectFlagTargetValue(detail = {}) {
  if (detail.flag_id !== undefined && detail.flag_id !== null && detail.flag_id !== "") {
    return `flag_id:${detail.flag_id}`;
  }
  if (detail.question) return `question:${detail.question}`;
  const unsolved = currentFlagQuestions.filter((q) => !q.solved);
  if (unsolved.length === 1) {
    const idx = currentFlagQuestions.indexOf(unsolved[0]);
    const flagId = unsolved[0].flag_id;
    return flagId !== undefined && flagId !== null && flagId !== ""
      ? `flag_id:${flagId}`
      : `question:${idx + 1}`;
  }
  return "";
}

function selectedFlagTarget(item) {
  const select = item.querySelector(".flag-target-select");
  if (!select) return {};
  const value = select.value;
  if (!value) return { missing: true };
  if (value.startsWith("flag_id:")) return { flag_id: value.slice("flag_id:".length) };
  if (value.startsWith("question:")) return { question: Number(value.slice("question:".length)) };
  return {};
}

function updateFlagTargetSelects() {
  document.querySelectorAll(".flag-item").forEach((item) => {
    const flag = item.dataset.flag;
    const detail = flagDetails.get(flag) || {};
    const oldSelect = item.querySelector(".flag-target-select");
    if (!currentFlagQuestions.length) {
      if (oldSelect) oldSelect.remove();
      const markBtn = item.querySelector(".btn-flag-mark");
      if (markBtn) markBtn.textContent = "Mark Solved";
      return;
    }
    const select = oldSelect || document.createElement("select");
    select.className = "flag-target-select";
    const selected = oldSelect?.value || selectFlagTargetValue(detail);
    select.innerHTML = '<option value="">Choose target...</option>' + currentFlagQuestions.map((q, idx) => {
      const flagId = q.flag_id;
      const value = flagId !== undefined && flagId !== null && flagId !== ""
        ? `flag_id:${esc(flagId)}`
        : `question:${idx + 1}`;
      return `<option value="${value}">${esc(flagQuestionLabel(q, idx))}</option>`;
    }).join("");
    select.value = Array.from(select.options).some((opt) => opt.value === selected) ? selected : "";
    if (!oldSelect) item.querySelector(".flag-actions")?.prepend(select);
    const markBtn = item.querySelector(".btn-flag-mark");
    if (markBtn) markBtn.textContent = "Mark Slot";
  });
}

function primaryFlagSource(detail = {}) {
  const sources = detail.sources || [];
  return sources.find((source) =>
    source.run_id && Number.isInteger(source.event_index)
  ) || sources[0] || null;
}

function flagSourceText(detail = {}) {
  const source = primaryFlagSource(detail);
  if (!source) return "Source not recorded";
  if (source.type === "manual") return "Manual entry";
  const pieces = [];
  if (source.agent) pieces.push(source.agent);
  if (source.type === "teammate_broadcast") pieces.push("breakthrough");
  else if (source.type) pieces.push(source.type);
  if (Number.isInteger(source.event_index)) pieces.push(`event ${source.event_index}`);
  return pieces.join(" · ") || "Source recorded";
}

function flagSubmissionText(detail = {}) {
  const submissions = detail.submissions || [];
  if (!submissions.length) return "";
  const last = submissions[submissions.length - 1];
  const status = last.correct ? "correct" : "wrong";
  const target = last.question ? `q${last.question}` : (last.flag_id ? `flag_id ${last.flag_id}` : "");
  return [`Last submit: ${status}`, target, last.message || ""].filter(Boolean).join(" · ");
}

async function focusFlagSource(detail = {}) {
  const source = primaryFlagSource(detail);
  if (!source || !source.run_id || !Number.isInteger(source.event_index)) {
    showToast("No transcript source recorded for this flag", "info");
    return;
  }
  await focusTranscriptEvent(source.run_id, source.event_index);
}

function refreshFlagItem(item, flag) {
  const detail = flagDetails.get(flag) || {};
  const sourceEl = item.querySelector(".flag-source");
  if (sourceEl) sourceEl.textContent = flagSourceText(detail);
  const submitEl = item.querySelector(".flag-submit-meta");
  if (submitEl) {
    const text = flagSubmissionText(detail);
    submitEl.textContent = text;
    submitEl.classList.toggle("hidden", !text);
  }
  const jumpBtn = item.querySelector(".btn-flag-source");
  const source = primaryFlagSource(detail);
  if (jumpBtn) jumpBtn.disabled = !(source?.run_id && Number.isInteger(source.event_index));
  updateFlagTargetSelects();
}

function showFlagBanner(flag, meta = {}) {
  const existing = knownFlagFor(flag);
  if (existing) {
    mergeFlagDetail(existing, meta);
    const item = document.querySelector(`.flag-item[data-flag="${selectorEscape(existing)}"]`);
    if (item) refreshFlagItem(item, existing);
    return;
  }

  const section = $("#flags-section");
  const list = $("#flags-list");
  section.classList.remove("hidden");

  const item = document.createElement("div");
  item.className = "flag-item";
  item.dataset.flag = flag;
  const main = document.createElement("div");
  main.className = "flag-main";
  const span = document.createElement("span");
  span.className = "flag-text";
  span.textContent = flag;
  const source = document.createElement("span");
  source.className = "flag-source";
  const submitMeta = document.createElement("span");
  submitMeta.className = "flag-submit-meta hidden";
  main.append(span, source, submitMeta);

  const actions = document.createElement("div");
  actions.className = "flag-actions";
  const copyBtn = document.createElement("button");
  copyBtn.className = "btn-flag-action";
  copyBtn.textContent = "Copy";
  copyBtn.addEventListener("click", () => copyToClipboard(flag, copyBtn));
  actions.appendChild(copyBtn);

  const jumpBtn = document.createElement("button");
  jumpBtn.className = "btn-flag-action btn-flag-source";
  jumpBtn.textContent = "Jump";
  jumpBtn.addEventListener("click", () => focusFlagSource(flagDetails.get(flag) || {}));
  actions.appendChild(jumpBtn);

  const submitBtn = document.createElement("button");
  submitBtn.className = "btn-flag-action btn-flag-submit";
  submitBtn.textContent = "Submit";
  submitBtn.addEventListener("click", async () => {
    if (!currentChallengeId) return;
    const target = selectedFlagTarget(item);
    if (target.missing) {
      showToast("Choose which flag target to submit to", "error");
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = "Submitting...";
    const res = await api("/api/plugins/submit-flag", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: currentChallengeId,
        flag,
        run_id: activeRunId || currentRuns[0]?.id || "",
        ...target,
      }),
    });
    if (!res) { submitBtn.disabled = false; submitBtn.textContent = "Submit"; return; }
    const data = await res.json();
    if (data.error) {
      showToast(data.error, "error");
      submitBtn.disabled = false;
      submitBtn.textContent = "Submit";
      return;
    }
    const resultFlag = data.flag || flag;
    if (data.meta) mergeFlagDetail(resultFlag, data.meta);
    if (data.flag_questions) {
      currentFlagQuestions = data.flag_questions;
      updateFlagTargetSelects();
    }
    if (data.correct) {
      setFlagStatus(resultFlag, "correct");
      if (data.status === "solved" || data.all_questions_solved || !currentFlagQuestions.length) {
        showToast("Flag correct!", "success");
        updateStatusBadge("solved");
        updateButtons("solved");
        stopTimer();
      } else {
        showToast("Flag correct for selected target", "success");
      }
    } else {
      setFlagStatus(resultFlag, "wrong");
      submitBtn.textContent = data.message || "Wrong";
      submitBtn.disabled = false;
      setTimeout(() => { submitBtn.textContent = "Submit"; }, 2000);
    }
  });
  actions.appendChild(submitBtn);

  const markBtn = document.createElement("button");
  markBtn.className = "btn-flag-action btn-flag-mark";
  markBtn.textContent = currentFlagQuestions.length ? "Mark Slot" : "Mark Solved";
  markBtn.addEventListener("click", async () => {
    if (!currentChallengeId) return;
    const target = selectedFlagTarget(item);
    if (target.missing) {
      showToast("Choose which flag target to mark", "error");
      return;
    }
    const res = await api(`/api/challenges/${currentChallengeId}/mark-solved`, {
      method: "POST",
      body: JSON.stringify({
        flag,
        run_id: activeRunId || currentRuns[0]?.id || "",
        ...target,
      }),
    });
    if (res && res.ok) {
      const data = await res.json();
      if (data.meta) mergeFlagDetail(data.flag || flag, data.meta);
      if (data.flag_questions) {
        currentFlagQuestions = data.flag_questions;
        updateFlagTargetSelects();
      }
      setFlagStatus(flag, "correct");
      if (data.status === "solved" || data.all_questions_solved || !currentFlagQuestions.length) {
        showToast("Challenge marked as solved", "success");
        updateStatusBadge("solved");
        updateButtons("solved");
        stopTimer();
      } else {
        showToast("Flag target marked correct", "success");
      }
    }
  });
  actions.appendChild(markBtn);

  item.append(main, actions);
  list.appendChild(item);
  foundFlags.set(flag, "pending");
  mergeFlagDetail(flag, meta);
  refreshFlagItem(item, flag);
}

function setFlagStatus(flag, status, meta = null) {
  const displayFlag = knownFlagFor(flag) || flag;
  if (meta) mergeFlagDetail(displayFlag, meta);
  foundFlags.set(displayFlag, status);
  const wanted = flagLookupKey(flag);
  const items = document.querySelectorAll(".flag-item");
  items.forEach((item) => {
    if (flagLookupKey(item.dataset.flag) !== wanted) return;
    item.classList.remove("flag-correct", "flag-wrong");
    if (status === "correct") item.classList.add("flag-correct");
    else if (status === "wrong") item.classList.add("flag-wrong");
    refreshFlagItem(item, item.dataset.flag);
  });
}

// === Timer ===
function startTimer() {
  syncRunTimerState();
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(updateTimer, 1000);
  updateTimer();
}

function stopTimer() {
  if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
  for (const run of currentRuns) freezeRunTimer(run);
  updateTimer();
}

function updateTimer() {
  const elapsed = Math.floor(currentChallengeTimerMs() / 1000);
  if (!elapsed) {
    $("#detail-timer").textContent = "";
    return;
  }
  const m = Math.floor(elapsed / 60);
  const s = elapsed % 60;
  const h = Math.floor(m / 60);
  const display = h > 0
    ? `${h}:${String(m % 60).padStart(2, "0")}:${String(s).padStart(2, "0")}`
    : `${m}:${String(s).padStart(2, "0")}`;
  $("#detail-timer").textContent = display;
}


// === Toasts ===
function showToast(message, type = "info") {
  const container = $("#toast-container");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add("toast-visible"));
  setTimeout(() => {
    toast.classList.remove("toast-visible");
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function showFlagFoundToast(challengeName, agent, flag, challengeId) {
  const container = $("#toast-container");
  const toast = document.createElement("div");
  toast.className = "toast toast-flag";
  toast.innerHTML = `<strong>Flag found!</strong> ${esc(agent)} found a flag in <em>${esc(challengeName)}</em><br><code>${esc(flag)}</code><br><span class="toast-flag-action">Click to open</span>`;
  toast.style.cursor = "pointer";
  toast.addEventListener("click", () => {
    toast.remove();
    if (challengeId) openChallenge(challengeId);
  });
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add("toast-visible"));
  setTimeout(() => {
    toast.classList.remove("toast-visible");
    setTimeout(() => toast.remove(), 300);
  }, 15000);
}

// === Run Event Rendering ===
function renderRunEvent(runId, event) {
  // Get or create the feed for this run
  let feed = document.getElementById(`feed-${runId}`);
  if (!feed) {
    // Might arrive before tabs are set up; use default feed
    feed = document.getElementById("feed-__default__");
  }
  if (!feed) return;

  // --- Run-level status: update only this run's tab dot ---
  if (event.type === "flag_found") return;

  if (event.type === "run_status") {
    const rid = event.run_id || runId;
    updateRunTabDot(rid, event.status);
    applyRunStatusEvent(event, rid);
    if (event.duration_ms !== undefined && event.duration_ms !== null) {
      getRunStats(rid).durationMs = durationMs(event.duration_ms);
    }
    if (event.error) {
      $("#error-banner").textContent = event.error;
      $("#error-banner").classList.remove("hidden");
    }
    renderStats();
    updateTimer();
    return;
  }

  // --- New run added (new run added) ---
  if (event.type === "run_added" && event.run) {
    const r = event.run;
    if (currentRuns.some((x) => x.id === r.id)) return;
    currentRuns.push(r);
    if (r.status === "solving") activateRunTimer(r);
    addRunTab(r);
    if (currentChallengeId) {
      runHistoryState.set(r.id, {
        total: 0,
        nextBefore: null,
        hasMore: false,
        loading: false,
      });
      connectRunWS(currentChallengeId, r.id, r.agent, { history: false });
    }
    // Refresh selectors and header with new run
    updateSteerRunSelect();
    updateFilesRunSelect();
    // Update model badge for new agent
    const agentMeta = getAgentMeta(r.agent);
    const modelBadge = $("#detail-model");
    if (modelBadge) {
      modelBadge.textContent = r.model || agentMeta.default_model;
    }
    switchRunTab(r.id);
    return;
  }

  // --- Challenge-level status: update badge, buttons, timer ---
  if (event.type === "challenge_status") {
    updateStatusBadge(event.status);
    updateButtons(event.status);
    if (event.status === "solving") startTimer();
    if (["solved", "failed", "completed"].includes(event.status)) {
      stopTimer();

      if (views.detail.classList.contains("hidden")) {
        const msgs = { solved: "Challenge solved!", failed: "Challenge failed", completed: "Agent finished" };
        const types = { solved: "success", failed: "error", completed: "info" };
        showToast(msgs[event.status] || event.status, types[event.status] || "info");
      }
    }
    return;
  }

  // --- Legacy "status" type for backward compat with saved logs ---
  if (event.type === "status") {
    updateRunTabDot(runId, event.status);
    updateStatusBadge(event.status);
    updateButtons(event.status);
    return;
  }

  // --- Subagent lifecycle (within a single run) ---
  if (event.type === "system" && event.subtype === "task_started") {
    appendMsg(feed, `Subagent started: ${event.description || "task"}`, "system-msg", event.ts);
    scrollBottomIfActive(runId);
    return;
  }
  if (event.type === "system" && event.subtype === "task_notification") {
    appendMsg(feed, `Subagent ${event.status || "finished"}: ${event.description || "task"}`, "system-msg", event.ts);
    scrollBottomIfActive(runId);
    return;
  }

  // --- Error ---
  if (event.type === "error") {
    appendMsg(feed, event.message, "error-msg", event.ts);
    scrollBottomIfActive(runId); return;
  }

  // --- System messages ---
  if (event.type === "system") {
    if (event.subtype === "init") return;
    const systemMessage = event.message || event.data || "";
    if (event.subtype === "teammate_broadcast" && systemMessage) {
      appendMsg(feed, systemMessage, "teammate-broadcast-msg", event.ts);
      const flag = checkForFlag(systemMessage);
      if (flag) showFlagBanner(flag);
      scrollBottomIfActive(runId); return;
    }
    if (systemMessage) {
      appendMsg(feed, systemMessage, "system-msg", event.ts);
    }
    scrollBottomIfActive(runId); return;
  }

  // --- User steer ---
  if (event.type === "user_steer" || event.type === "user_prompt") {
    const bubble = document.createElement("div");
    bubble.className = "chat-bubble chat-user";
    if (event.ts != null) {
      const ts = document.createElement("span");
      ts.className = "msg-ts";
      ts.textContent = fmtElapsed(event.ts);
      bubble.appendChild(ts);
    }
    const label = document.createElement("div");
    label.className = "chat-label";
    label.textContent = event.type === "user_steer" ? "You" : "Prompt";
    const body = document.createElement("div");
    body.className = "chat-body";
    body.textContent = event.message;
    bubble.append(label, body);
    feed.appendChild(bubble);
    scrollBottomIfActive(runId); return;
  }

  // --- Rate limit ---
  if (event.type === "rate_limit_event") {
    const info = event.rate_limit_info;
    if (info && info.utilization > 0.5) {
      appendMsg(feed, `Rate limit: ${Math.round(info.utilization * 100)}% used`, "rate-limit-msg", event.ts);
      scrollBottomIfActive(runId);
    }
    return;
  }

  // --- Assistant message ---
  if (event.type === "assistant" && event.message) {
    if (event.message.usage) updateRunStats(runId, event);
    renderAssistant(feed, event.message, runId, event.ts);
    scrollBottomIfActive(runId); return;
  }

  // --- User (tool results) ---
  if (event.type === "user" && event.message) {
    renderToolResults(event, feed);
    scrollBottomIfActive(runId); return;
  }

  // --- Raw text ---
  if (event.type === "raw" && event.text) {
    appendMsg(feed, event.text, "raw-msg", event.ts);
    const flag = checkForFlag(event.text);
    if (flag) showFlagBanner(flag);
    scrollBottomIfActive(runId); return;
  }

  // --- Codex usage ---
  if (event.type === "codex_usage") {
    updateRunStats(runId, event);
    return;
  }

  // --- Result ---
  if (event.type === "result") {
    updateRunStats(runId, event);
    if (event.result) {
      const block = document.createElement("div");
      block.className = "result-block";
      block.innerHTML = `<div class="result-label">Result</div><div class="result-text"></div>`;
      block.querySelector(".result-text").innerHTML = renderMarkdown(event.result);
      feed.appendChild(block);
      const flag = checkForFlag(event.result);
      if (flag) showFlagBanner(flag);
      scrollBottomIfActive(runId);
    }
    return;
  }
}

// === Assistant Message Rendering ===

// Track consecutive tool calls for collapsing
let _pendingToolEls = [];

function _flushToolGroup(feed) {
  if (!_pendingToolEls.length) return;
  const group = document.createElement("div");
  group.className = "chat-tool-group";

  if (_pendingToolEls.length > 2) {
    // Show first, collapse middle, show last
    group.appendChild(_pendingToolEls[0]);
    const collapsed = document.createElement("div");
    collapsed.className = "chat-tool-collapsed";
    const expandBtn = document.createElement("button");
    expandBtn.className = "btn-ghost btn-xs chat-tool-expand";
    expandBtn.textContent = `${_pendingToolEls.length - 2} more tool call${_pendingToolEls.length - 2 !== 1 ? "s" : ""}`;
    expandBtn.addEventListener("click", () => {
      collapsed.classList.add("chat-tool-expanded");
      expandBtn.classList.add("hidden");
    });
    for (let i = 1; i < _pendingToolEls.length - 1; i++) {
      collapsed.appendChild(_pendingToolEls[i]);
    }
    group.appendChild(expandBtn);
    group.appendChild(collapsed);
    group.appendChild(_pendingToolEls[_pendingToolEls.length - 1]);
  } else {
    for (const el of _pendingToolEls) group.appendChild(el);
  }

  feed.appendChild(group);
  _pendingToolEls = [];
}

function renderAssistant(feed, msg, runId, eventTs) {
  if (!msg.content || !msg.content.length) return;

  for (const block of msg.content) {
    if (block.type === "thinking" && block.thinking) {
      _flushToolGroup(feed);
      if (lastThinkingEl) lastThinkingEl.removeAttribute("open");

      const bubble = document.createElement("div");
      bubble.className = "chat-bubble chat-assistant chat-thinking-bubble";

      const details = document.createElement("details");
      details.className = "step-thinking";
      details.open = true;
      const summary = document.createElement("summary");
      const label = document.createElement("span");
      label.className = "thinking-label";
      label.textContent = "Thinking";
      const preview = document.createElement("span");
      preview.className = "thinking-preview";
      preview.textContent = " " + truncate(block.thinking, 100);
      if (eventTs != null) {
        const tsEl = document.createElement("span");
        tsEl.className = "msg-ts";
        tsEl.textContent = fmtElapsed(eventTs);
        summary.append(label, preview, tsEl);
      } else {
        summary.append(label, preview);
      }
      details.appendChild(summary);
      const body = document.createElement("div");
      body.className = "thinking-body";
      body.textContent = block.thinking;
      details.appendChild(body);
      bubble.appendChild(details);
      lastThinkingEl = details;

      feed.appendChild(bubble);
      stepCount++;
      updateCounters();
    }
    else if (block.type === "text" && block.text) {
      _flushToolGroup(feed);

      const bubble = document.createElement("div");
      bubble.className = "chat-bubble chat-assistant";

      if (eventTs != null) {
        const ts = document.createElement("span");
        ts.className = "msg-ts";
        ts.textContent = fmtElapsed(eventTs);
        bubble.appendChild(ts);
      }

      const div = document.createElement("div");
      div.className = "chat-body";
      div.innerHTML = renderMarkdown(block.text);
      div.querySelectorAll(".md-codeblock").forEach((pre) => {
        pre.style.position = "relative";
        pre.appendChild(makeCopyBtn(() => pre.textContent));
      });
      bubble.appendChild(div);
      feed.appendChild(bubble);

      const flag = checkForFlag(block.text);
      if (flag) showFlagBanner(flag);

      stepCount++;
      updateCounters();
    }
    else if (block.type === "tool_use") {
      const toolEl = buildToolUse(block);
      _pendingToolEls.push(toolEl);
      pendingTools.set(block.id, toolEl);
      if (runId && !statsUseSnapshot) { getRunStats(runId).toolCalls++; renderStats(); }
      else if (runId && historyRenderDepth === 0) scheduleStatsSnapshotRefresh();
    }
  }

  // Flush remaining tool calls (they may be followed by a tool_result later)
  _flushToolGroup(feed);
}

// === Tool Use Rendering ===
function buildToolUse(block) {
  const wrapper = document.createElement("div");
  wrapper.className = "step-tool";
  wrapper.id = `tool-${block.id}`;

  // Bar
  const bar = document.createElement("div");
  bar.className = "tool-bar";

  const icon = document.createElement("span");
  icon.className = `tool-icon ${iconClass(block.name)}`;
  icon.textContent = iconLetter(block.name);

  const name = document.createElement("span");
  name.className = "tool-name";
  name.textContent = block.name;

  const desc = document.createElement("span");
  desc.className = "tool-desc";
  desc.textContent = toolSummary(block.name, block.input);

  const status = document.createElement("span");
  status.className = "tool-status tool-status-running";
  status.textContent = "running";

  bar.append(icon, name, desc, status);

  // Detail (expandable)
  const detail = document.createElement("div");
  detail.className = "tool-detail";

  const inputText = toolInputDisplay(block.name, block.input);
  if (inputText) {
    const sec = document.createElement("div");
    sec.className = "tool-input-section";
    sec.textContent = inputText;
    detail.appendChild(sec);
  }

  const outSec = document.createElement("div");
  outSec.className = "tool-output-section";
  outSec.textContent = "Waiting for output...";
  detail.appendChild(outSec);

  bar.addEventListener("click", () => detail.classList.toggle("open"));
  wrapper.append(bar, detail);

  wrapper._statusEl = status;
  wrapper._outputEl = outSec;
  return wrapper;
}

function setToolOutput(toolEl, output, isError) {
  const hasOutput = !!output;
  const fullOutput = hasOutput ? output : "(no output)";
  const truncated = hasOutput && output.length > MAX_TOOL_OUTPUT_DISPLAY_CHARS;
  const visibleOutput = truncated
    ? `${output.slice(0, MAX_TOOL_OUTPUT_DISPLAY_CHARS)}\n\n[Output truncated in the UI: ${output.length - MAX_TOOL_OUTPUT_DISPLAY_CHARS} more characters. Copy still uses the full output.]`
    : fullOutput;

  toolEl._outputEl.textContent = visibleOutput;
  toolEl._outputEl.classList.toggle("tool-output-error", !!isError);
  if (!hasOutput) return;

  toolEl._outputEl.style.position = "relative";
  toolEl._outputEl.appendChild(makeCopyBtn(output));
  if (truncated) {
    const fullBtn = document.createElement("button");
    fullBtn.type = "button";
    fullBtn.className = "btn-xs tool-output-full";
    fullBtn.textContent = "Show full output";
    fullBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      toolEl._outputEl.textContent = fullOutput;
      toolEl._outputEl.appendChild(makeCopyBtn(output));
    });
    toolEl._outputEl.appendChild(fullBtn);
  }
}

function renderToolResults(event, feed) {
  const msg = event.message;
  if (!msg || !msg.content) return;

  for (const block of msg.content) {
    if (block.type !== "tool_result") continue;

    let toolEl = pendingTools.get(block.tool_use_id);
    if (!toolEl) {
      // Synthetic tool card for completed tool results without a prior start event
      const synthetic = {
        id: block.tool_use_id || `tool-${Date.now()}`,
        name: block.name || "tool",
        input: block.input || {},
      };
      toolEl = buildToolUse(synthetic);
      feed.appendChild(toolEl);
      pendingTools.set(synthetic.id, toolEl);
    }

    let output = "";
    // Extract content text from agent tool results
    if (event.tool_use_result && event.tool_use_result.content) {
      output = event.tool_use_result.content
        .map((c) => c.text || "").filter(Boolean).join("\n");
    }
    if (!output && event.tool_use_result) {
      const r = event.tool_use_result;
      if (r.stdout) output = r.stdout;
      if (r.stderr) output += (output ? "\n" : "") + r.stderr;
      if (r.matches) output = r.matches.join(", ");
    }
    if (!output && typeof block.content === "string") output = block.content;
    if (!output && Array.isArray(block.content))
      output = block.content.map((c) => c.text || c.tool_name || JSON.stringify(c)).join("\n");

    const isError = block.is_error === true;
    toolEl._statusEl.className = `tool-status ${isError ? "tool-status-error" : "tool-status-done"}`;
    toolEl._statusEl.textContent = isError ? "error" : "done";
    setToolOutput(toolEl, output, isError);

    pendingTools.delete(block.tool_use_id);
  }
}

// === Stats Sidebar ===
function emptyRunStatsState() {
  return {
    inputTokens: 0, outputTokens: 0,
    cacheReadTokens: 0, cacheCreationTokens: 0,
    toolCalls: 0, turns: 0,
    costUsd: 0, durationMs: 0, durationApiMs: 0,
    modelUsage: null,
    resultSeen: false,
    codexSeen: false,
    lastResultUsage: null,
    lastCodexUsage: null,
    lastResultCostUsd: null,
    lastResultTurns: null,
    lastDurationApiMs: null,
    lastModelUsage: {},
  };
}

function getRunStats(runId) {
  if (!runStats.has(runId)) {
    runStats.set(runId, emptyRunStatsState());
  }
  return runStats.get(runId);
}

function statNumber(obj, ...keys) {
  if (!obj || typeof obj !== "object") return 0;
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  return 0;
}

function normalizeUsage(raw) {
  const details = raw?.input_token_details || raw?.inputTokenDetails || {};
  return {
    inputTokens: statNumber(raw, "input_tokens", "inputTokens", "prompt_tokens", "promptTokens"),
    outputTokens: statNumber(raw, "output_tokens", "outputTokens", "completion_tokens", "completionTokens"),
    cacheReadTokens: statNumber(
      raw,
      "cache_read_input_tokens",
      "cacheReadInputTokens",
      "cached_input_tokens",
      "cachedInputTokens"
    ) || statNumber(details, "cached_tokens", "cachedTokens"),
    cacheCreationTokens: statNumber(raw, "cache_creation_input_tokens", "cacheCreationInputTokens"),
  };
}

function usageDelta(current, previous) {
  const prev = previous || {};
  const delta = {};
  for (const [key, value] of Object.entries(current)) {
    const prior = prev[key] || 0;
    delta[key] = value <= 0 ? 0 : value >= prior ? value - prior : value;
  }
  return delta;
}

function addUsageToStats(s, usage) {
  s.inputTokens += usage.inputTokens || 0;
  s.outputTokens += usage.outputTokens || 0;
  s.cacheReadTokens += usage.cacheReadTokens || 0;
  s.cacheCreationTokens += usage.cacheCreationTokens || 0;
}

function positiveDelta(current, previous) {
  if (!current || current <= 0) return 0;
  if (previous == null) return current;
  return current >= previous ? current - previous : current;
}

function normalizeModelUsage(raw) {
  const normalized = {};
  if (!raw || typeof raw !== "object") return normalized;
  for (const [model, usage] of Object.entries(raw)) {
    if (!usage || typeof usage !== "object") continue;
    normalized[model] = {
      inputTokens: statNumber(usage, "inputTokens", "input_tokens"),
      outputTokens: statNumber(usage, "outputTokens", "output_tokens"),
      cacheReadInputTokens: statNumber(
        usage,
        "cacheReadInputTokens",
        "cache_read_input_tokens",
        "cachedInputTokens",
        "cached_input_tokens"
      ),
      cacheCreationInputTokens: statNumber(
        usage,
        "cacheCreationInputTokens",
        "cache_creation_input_tokens"
      ),
      costUSD: statNumber(usage, "costUSD", "cost_usd"),
      webSearchRequests: statNumber(usage, "webSearchRequests", "web_search_requests"),
    };
  }
  return normalized;
}

function addModelUsageDelta(s, current) {
  if (!current || !Object.keys(current).length) return;
  if (!s.modelUsage) s.modelUsage = {};
  if (!s.lastModelUsage) s.lastModelUsage = {};
  for (const [model, usage] of Object.entries(current)) {
    const prev = s.lastModelUsage[model] || {};
    const target = s.modelUsage[model] || {
      inputTokens: 0,
      outputTokens: 0,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
      costUSD: 0,
      webSearchRequests: 0,
    };
    for (const [key, value] of Object.entries(usage)) {
      target[key] = (target[key] || 0) + positiveDelta(value, prev[key]);
    }
    s.modelUsage[model] = target;
    s.lastModelUsage[model] = usage;
  }
}

function normalizeStatsSnapshot(raw) {
  return {
    ...emptyRunStatsState(),
    inputTokens: Number(raw?.inputTokens || 0),
    outputTokens: Number(raw?.outputTokens || 0),
    cacheReadTokens: Number(raw?.cacheReadTokens || 0),
    cacheCreationTokens: Number(raw?.cacheCreationTokens || 0),
    toolCalls: Number(raw?.toolCalls || 0),
    turns: Number(raw?.turns || 0),
    costUsd: Number(raw?.costUsd || 0),
    durationMs: Number(raw?.durationMs || 0),
    durationApiMs: Number(raw?.durationApiMs || 0),
    modelUsage: raw?.modelUsage && Object.keys(raw.modelUsage).length ? raw.modelUsage : null,
  };
}

async function loadChallengeStatsSnapshot(challengeId, options = {}) {
  const res = await api(`/api/challenges/${encodeURIComponent(challengeId)}/stats`).catch(() => null);
  if (!res || !res.ok) {
    if (!options.silent) console.warn("Failed to load challenge stats snapshot");
    return;
  }
  const data = await res.json();
  if (currentChallengeId !== challengeId) return;

  runStats.clear();
  for (const [runId, stats] of Object.entries(data.runs || {})) {
    runStats.set(runId, normalizeStatsSnapshot(stats));
  }
  statsUseSnapshot = true;
  renderStats();
}

function scheduleStatsSnapshotRefresh(delay = 5000) {
  if (!statsUseSnapshot || !currentChallengeId || statsRefreshTimer) return;
  const challengeId = currentChallengeId;
  statsRefreshTimer = setTimeout(() => {
    statsRefreshTimer = null;
    if (currentChallengeId === challengeId) {
      loadChallengeStatsSnapshot(challengeId, { silent: true });
    }
  }, delay);
}

function updateRunStats(runId, event) {
  const s = getRunStats(runId);
  if (statsUseSnapshot) {
    if (historyRenderDepth === 0) scheduleStatsSnapshotRefresh();
    return;
  }

  if (event.type === "result") {
    s.resultSeen = true;
    if (event.usage) {
      const usage = normalizeUsage(event.usage);
      addUsageToStats(s, usageDelta(usage, s.lastResultUsage));
      s.lastResultUsage = usage;
    }
    const cost = statNumber(event, "total_cost_usd", "costUsd");
    if (cost) {
      s.costUsd += positiveDelta(cost, s.lastResultCostUsd);
      s.lastResultCostUsd = cost;
    }
    const turns = statNumber(event, "num_turns", "turns");
    if (turns) {
      s.turns += positiveDelta(turns, s.lastResultTurns);
      s.lastResultTurns = turns;
    }
    if (event.duration_ms) s.durationMs = Math.max(s.durationMs || 0, event.duration_ms);
    const durationApiMs = statNumber(event, "duration_api_ms");
    if (durationApiMs) {
      s.durationApiMs += positiveDelta(durationApiMs, s.lastDurationApiMs);
      s.lastDurationApiMs = durationApiMs;
    }
    if (event.model_usage) addModelUsageDelta(s, normalizeModelUsage(event.model_usage));
  } else if (event.type === "codex_usage" && event.usage) {
    s.codexSeen = true;
    const usage = normalizeUsage(event.usage);
    addUsageToStats(s, usageDelta(usage, s.lastCodexUsage));
    s.lastCodexUsage = usage;
  } else if (event.type === "assistant" && event.message?.usage && !s.resultSeen && !s.codexSeen) {
    addUsageToStats(s, normalizeUsage(event.message.usage));
  }
  renderStats();
}

function fmtTokens(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "k";
  return String(n);
}

function fmtDuration(ms) {
  if (!ms) return "-";
  if (ms < 60_000) return (ms / 1000).toFixed(1) + "s";
  const m = Math.floor(ms / 60_000);
  const s = Math.round((ms % 60_000) / 1000);
  return `${m}m ${s}s`;
}

function fmtCost(usd) {
  if (!usd) return "-";
  return "$" + usd.toFixed(4);
}

function flushDeferredStats() {
  if (historyRenderDepth > 0 || !statsRenderPending) return;
  statsRenderPending = false;
  renderStats();
}

function renderStats() {
  if (historyRenderDepth > 0) {
    statsRenderPending = true;
    return;
  }
  const panel = $("#stats-panel");
  if (!panel) return;
  panel.innerHTML = "";

  if (!runStats.size) {
    panel.innerHTML = '<div style="padding:1rem;color:var(--text-dim);font-size:0.8rem">No statistics yet</div>';
    return;
  }

  // --- Total section ---
  {
    const tot = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, tools: 0, turns: 0 };
    for (const s of runStats.values()) {
      tot.input += s.inputTokens;
      tot.output += s.outputTokens;
      tot.cacheRead += s.cacheReadTokens;
      tot.cacheWrite += s.cacheCreationTokens;
      tot.cost += s.costUsd;
      tot.tools += s.toolCalls;
      tot.turns += s.turns;
    }
    const section = document.createElement("div");
    section.className = "stats-run-section";
    const header = document.createElement("div");
    header.className = "stats-run-header";
    header.textContent = "Total";
    section.appendChild(header);
    const grid = document.createElement("div");
    grid.className = "stats-grid";
    const rows = [
      ["Input", fmtTokens(tot.input)],
      ["Output", fmtTokens(tot.output)],
    ];
    if (tot.cacheRead) rows.push(["Cache read", fmtTokens(tot.cacheRead)]);
    if (tot.cacheWrite) rows.push(["Cache write", fmtTokens(tot.cacheWrite)]);
    rows.push(["Total tokens", fmtTokens(tot.input + tot.output)]);
    if (tot.tools) rows.push(["Tool calls", String(tot.tools)]);
    if (tot.turns) rows.push(["Turns", String(tot.turns)]);
    if (tot.cost) rows.push(["Cost", fmtCost(tot.cost)]);
    for (const [lbl, val] of rows) {
      const item = document.createElement("div");
      item.className = "stat-item";
      item.innerHTML = `<span class="stat-label">${esc(lbl)}</span><span class="stat-value">${esc(val)}</span>`;
      grid.appendChild(item);
    }
    section.appendChild(grid);
    panel.appendChild(section);
  }

  for (const [runId, s] of runStats) {
    const run = currentRuns.find(r => r.id === runId);
    const agent = run ? run.agent : "unknown";
    const agentMeta = getAgentMeta(agent);
    const label = run ? (agentMeta.label || agent) : runId.slice(0, 8);

    const section = document.createElement("div");
    section.className = "stats-run-section";

    const header = document.createElement("div");
    header.className = "stats-run-header";
    const dot = document.createElement("span");
    dot.className = `run-tab-dot dot-${run?.status === "solving" ? "running" : run?.status === "solved" ? "solved" : "pending"}`;
    header.append(dot);
    header.append(document.createTextNode(label));
    if (run?.model) {
      const modelSpan = document.createElement("span");
      modelSpan.style.cssText = "font-weight:400;color:var(--text-dim);font-size:0.65rem";
      modelSpan.textContent = ` (${run.model})`;
      header.appendChild(modelSpan);
    }
    section.appendChild(header);

    const grid = document.createElement("div");
    grid.className = "stats-grid";

    const totalTokens = s.inputTokens + s.outputTokens;
    const stats = [
      ["Input", fmtTokens(s.inputTokens)],
      ["Output", fmtTokens(s.outputTokens)],
    ];
    if (s.cacheReadTokens) stats.push(["Cache read", fmtTokens(s.cacheReadTokens)]);
    if (s.cacheCreationTokens) stats.push(["Cache write", fmtTokens(s.cacheCreationTokens)]);
    stats.push(["Total tokens", fmtTokens(totalTokens)]);
    if (s.toolCalls) stats.push(["Tool calls", String(s.toolCalls)]);
    if (s.turns) stats.push(["Turns", String(s.turns)]);
    if (s.costUsd) stats.push(["Cost", fmtCost(s.costUsd)]);
    if (s.durationMs) stats.push(["Duration", fmtDuration(s.durationMs)]);
    if (s.durationApiMs) stats.push(["API time", fmtDuration(s.durationApiMs)]);

    for (const [lbl, val] of stats) {
      const item = document.createElement("div");
      item.className = "stat-item";
      item.innerHTML = `<span class="stat-label">${esc(lbl)}</span><span class="stat-value">${esc(val)}</span>`;
      grid.appendChild(item);
    }
    section.appendChild(grid);

    if (s.modelUsage) {
      for (const [model, mu] of Object.entries(s.modelUsage)) {
        const msec = document.createElement("div");
        msec.className = "stats-model-section";
        const mh = document.createElement("div");
        mh.className = "stats-model-header";
        mh.textContent = model;
        msec.appendChild(mh);
        const mg = document.createElement("div");
        mg.className = "stats-grid";
        const mstats = [];
        if (mu.inputTokens) mstats.push(["Input", fmtTokens(mu.inputTokens)]);
        if (mu.outputTokens) mstats.push(["Output", fmtTokens(mu.outputTokens)]);
        if (mu.cacheReadInputTokens) mstats.push(["Cache read", fmtTokens(mu.cacheReadInputTokens)]);
        if (mu.cacheCreationInputTokens) mstats.push(["Cache write", fmtTokens(mu.cacheCreationInputTokens)]);
        if (mu.webSearchRequests) mstats.push(["Web searches", String(mu.webSearchRequests)]);
        if (mu.costUSD != null) mstats.push(["Cost", fmtCost(mu.costUSD)]);
        for (const [lbl, val] of mstats) {
          const item = document.createElement("div");
          item.className = "stat-item";
          item.innerHTML = `<span class="stat-label">${esc(lbl)}</span><span class="stat-value">${esc(val)}</span>`;
          mg.appendChild(item);
        }
        msec.appendChild(mg);
        section.appendChild(msec);
      }
    }

    panel.appendChild(section);
  }
}

// === Helpers ===
function iconClass(n) {
  const m = { Bash:"tool-icon-bash", Read:"tool-icon-read", Write:"tool-icon-write",
    Edit:"tool-icon-edit", Grep:"tool-icon-grep", Glob:"tool-icon-glob", Agent:"tool-icon-agent" };
  return m[n] || "tool-icon-other";
}

function iconLetter(n) {
  const m = { Bash:"$", Read:"R", Write:"W", Edit:"E", Grep:"?", Glob:"*", Agent:"A" };
  return m[n] || n.charAt(0);
}

function toolSummary(name, input) {
  if (!input) return "";
  switch (name) {
    case "Bash": return input.description || truncate(input.command || "", 50);
    case "Read": return shortPath(input.file_path || "");
    case "Write": return shortPath(input.file_path || "");
    case "Edit": return shortPath(input.file_path || "");
    case "Grep": return `"${input.pattern || ""}" ${shortPath(input.path || "")}`;
    case "Glob": return input.pattern || "";
    case "ToolSearch": return input.query || "";
    case "Agent": return input.description || truncate(input.prompt || "", 50);
    case "Skill": return input.skill_name || JSON.stringify(input);
    default: return truncate(JSON.stringify(input), 50);
  }
}

function toolInputDisplay(name, input) {
  if (!input) return "";
  switch (name) {
    case "Bash": return input.command || "";
    case "Read": return input.file_path || "";
    case "Write": return `${input.file_path || ""}\n---\n${truncate(input.content || "", 2000)}`;
    case "Edit": return `${input.file_path || ""}\n- ${input.old_string || ""}\n+ ${input.new_string || ""}`;
    case "Grep": return `pattern: ${input.pattern || ""}\npath: ${input.path || ""}`;
    case "Glob": return `pattern: ${input.pattern || ""}`;
    case "Agent": return `${input.description || ""}\n${input.prompt || ""}`;
    case "Skill": return JSON.stringify(input, null, 2);
    default: return JSON.stringify(input, null, 2);
  }
}

function shortPath(p) {
  if (!p) return "";
  const parts = p.split("/");
  return parts.length <= 3 ? p : ".../" + parts.slice(-2).join("/");
}

function truncate(s, n) { return !s ? "" : s.length > n ? s.slice(0, n) + "..." : s; }

function formatDuration(ms) {
  if (!ms) return "";
  const totalSec = Math.floor(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  if (m >= 60) {
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m`;
  }
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function appendMsg(container, text, cls, ts) {
  const div = document.createElement("div");
  div.className = cls;
  div.textContent = text;
  if (ts != null) {
    const tsEl = document.createElement("span");
    tsEl.className = "msg-ts";
    tsEl.textContent = fmtElapsed(ts);
    div.appendChild(tsEl);
  }
  container.appendChild(div);
}

function esc(str) {
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
}

function fmtElapsed(seconds) {
  if (seconds == null) return "";
  const s = Math.floor(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m < 60) return `${m}m${rem ? ` ${rem}s` : ""}`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function makeTimestamp(event) {
  if (event.ts == null) return null;
  const el = document.createElement("span");
  el.className = "msg-ts";
  el.textContent = fmtElapsed(event.ts);
  return el;
}

// === Sidebar Tabs ===
document.querySelectorAll(".sidebar-tab").forEach((tab) => {
  tab.addEventListener("click", () => switchTab(tab.dataset.tab));
});

function switchTab(tabId) {
  document.querySelectorAll(".sidebar-tab").forEach((t) => t.classList.remove("active"));
  document.querySelectorAll(".sidebar-content").forEach((c) => c.classList.remove("active"));
  const btn = document.querySelector(`[data-tab="${tabId}"]`);
  if (btn) btn.classList.add("active");
  const content = document.getElementById(tabId);
  if (content) content.classList.add("active");
  if (tabId === "tab-files") loadFiles();
}

// === Files Browser ===
function normalizeFileBrowserPath(path) {
  return String(path || "")
    .replace(/\\/g, "/")
    .split("/")
    .filter((part) => part && part !== "." && part !== "..")
    .join("/");
}

function parentFileBrowserPath(path) {
  const parts = normalizeFileBrowserPath(path).split("/").filter(Boolean);
  parts.pop();
  return parts.join("/");
}

function fileTypeLabel(type) {
  if (type === "image") return "IMG";
  if (type === "text") return "TXT";
  if (type === "binary") return "BIN";
  return "FILE";
}

function renderFilesBreadcrumb(path) {
  const breadcrumb = $("#files-breadcrumb");
  if (!breadcrumb) return;
  const cleanPath = normalizeFileBrowserPath(path);
  breadcrumb.innerHTML = "";

  const root = document.createElement("button");
  root.type = "button";
  root.className = "file-crumb";
  root.textContent = "root";
  root.addEventListener("click", () => loadFiles(""));
  breadcrumb.appendChild(root);

  let acc = "";
  for (const part of cleanPath.split("/").filter(Boolean)) {
    const sep = document.createElement("span");
    sep.className = "file-crumb-sep";
    sep.textContent = "/";
    breadcrumb.appendChild(sep);

    acc = acc ? `${acc}/${part}` : part;
    const crumbPath = acc;
    const crumb = document.createElement("button");
    crumb.type = "button";
    crumb.className = "file-crumb";
    crumb.textContent = part;
    crumb.title = crumbPath;
    crumb.addEventListener("click", () => loadFiles(crumbPath));
    breadcrumb.appendChild(crumb);
  }
}

function createFileRow(entry) {
  const item = document.createElement("button");
  item.type = "button";
  item.className = `file-item ${entry.kind === "directory" ? "file-folder" : ""}`;

  const icon = document.createElement("span");
  icon.className = `file-icon file-icon-${entry.kind === "directory" ? "directory" : entry.type}`;
  icon.textContent = entry.kind === "directory" ? "DIR" : fileTypeLabel(entry.type);

  const name = document.createElement("span");
  name.className = "file-name";
  name.textContent = entry.name;
  name.title = entry.path;

  const size = document.createElement("span");
  size.className = "file-size";
  size.textContent = entry.kind === "directory" ? "" : formatSize(entry.size || 0);

  item.append(icon, name, size);
  if (entry.kind === "directory") {
    item.addEventListener("click", () => loadFiles(entry.path));
  } else {
    item.addEventListener("click", () => viewFile(entry.path));
  }
  return item;
}

async function loadFiles(path = fileBrowserPath) {
  if (!currentChallengeId) return;
  const challengeId = currentChallengeId;
  const token = ++fileBrowserRequestToken;
  const nextPath = normalizeFileBrowserPath(path);

  const params = new URLSearchParams();
  params.set("browse", "1");
  params.set("dir", nextPath);
  const runSelect = $("#files-run-select");
  if (runSelect && runSelect.value) {
    params.set("run_id", runSelect.value);
  }
  const url = `/api/challenges/${challengeId}/files?${params.toString()}`;
  const res = await api(url);
  if (!res) return;
  if (token !== fileBrowserRequestToken || challengeId !== currentChallengeId) {
    return;
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    showToast(err.error || "Failed to load files", "error");
    return;
  }
  const data = await res.json();
  const entries = data.entries || [];

  fileBrowserPath = normalizeFileBrowserPath(data.path || nextPath);
  renderFilesBreadcrumb(fileBrowserPath);
  $("#file-counter").textContent = entries.length;
  const tree = $("#files-tree");
  tree.innerHTML = "";

  if (fileBrowserPath) {
    tree.appendChild(createFileRow({
      kind: "directory",
      name: "..",
      path: parentFileBrowserPath(fileBrowserPath),
    }));
  }

  if (!entries.length) {
    const empty = document.createElement("div");
    empty.className = "file-empty";
    empty.textContent = "No files in this folder";
    tree.appendChild(empty);
    return;
  }

  for (const entry of entries) {
    tree.appendChild(createFileRow(entry));
  }
}

$("#btn-refresh-files").addEventListener("click", () => loadFiles());

// Listen for files run select change
const filesRunSelect = $("#files-run-select");
if (filesRunSelect) {
  filesRunSelect.addEventListener("change", () => {
    fileBrowserPath = "";
    loadFiles("");
  });
}

// Auto-refresh files while solving
setInterval(() => {
  if (
    currentChallengeId &&
    !views.detail.classList.contains("hidden") &&
    $("#tab-files").classList.contains("active")
  ) {
    loadFiles();
  }
}, 8000);

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

// === File Viewer ===
function encodeFilePath(path) {
  return String(path).split("/").map(encodeURIComponent).join("/");
}

async function viewFile(path) {
  if (!currentChallengeId) return;
  const encodedPath = encodeFilePath(path);
  let url = `/api/challenges/${currentChallengeId}/files/${encodedPath}`;
  const runSelect = $("#files-run-select");
  if (runSelect && runSelect.value) {
    url += `?run_id=${encodeURIComponent(runSelect.value)}`;
  }
  const res = await api(url);
  if (!res) return;
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    showToast(err.error || "Failed to open file", "error");
    return;
  }
  const data = await res.json();

  $("#file-viewer-name").textContent = data.name;
  $("#file-viewer-size").textContent = formatSize(data.size);

  const body = $("#file-viewer-content");
  body.innerHTML = "";

  if (data.type === "image") {
    const wrapper = document.createElement("div");
    wrapper.className = "file-viewer-image";
    const img = document.createElement("img");
    img.src = `data:${data.mime};base64,${data.data}`;
    img.alt = data.name;
    wrapper.appendChild(img);
    body.appendChild(wrapper);
  } else if (data.type === "text") {
    const pre = document.createElement("pre");
    pre.className = "file-viewer-code";
    pre.innerHTML = highlightSyntax(data.content, data.ext);
    body.appendChild(pre);
  } else {
    const pre = document.createElement("pre");
    pre.className = "file-viewer-hex";
    pre.textContent = data.hexdump;
    body.appendChild(pre);
  }

  // Set download link (include run_id if selected)
  const dlBtn = $("#file-viewer-download");
  let dlUrl = `/api/challenges/${currentChallengeId}/download/${encodedPath}`;
  const dlRunSelect = $("#files-run-select");
  if (dlRunSelect && dlRunSelect.value) {
    dlUrl += `?run_id=${encodeURIComponent(dlRunSelect.value)}`;
  }
  dlBtn.href = dlUrl;
  dlBtn.download = data.name;

  $("#file-viewer-overlay").classList.remove("hidden");
}

$("#file-viewer-close").addEventListener("click", () => {
  $("#file-viewer-overlay").classList.add("hidden");
});
$("#file-viewer-overlay").addEventListener("click", (e) => {
  if (e.target === $("#file-viewer-overlay"))
    $("#file-viewer-overlay").classList.add("hidden");
});

// === Syntax Highlighting ===
function highlightSyntax(code, ext) {
  const escaped = code
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  const langExts = {
    py: "python", js: "js", ts: "js", c: "c", cpp: "c", h: "c",
    rs: "rust", go: "go", java: "java", rb: "ruby", sh: "bash",
    bash: "bash", zsh: "bash", sql: "sql", json: "json",
  };
  const lang = langExts[(ext || "").replace(".", "")] || "";

  if (!lang) return escaped;

  let result = escaped;

  // Comments
  if (["python", "bash", "ruby"].includes(lang)) {
    result = result.replace(/(#[^\n]*)/g, '<span class="syn-comment">$1</span>');
  } else if (["c", "js", "rust", "go", "java"].includes(lang)) {
    result = result.replace(/(\/\/[^\n]*)/g, '<span class="syn-comment">$1</span>');
  }

  // Strings
  result = result.replace(/(&quot;[^&]*?&quot;|"[^"]*?"|'[^']*?'|`[^`]*?`)/g,
    '<span class="syn-string">$1</span>');

  // Numbers
  result = result.replace(/\b(0x[\da-fA-F]+|\d+\.?\d*)\b/g,
    '<span class="syn-number">$1</span>');

  // Keywords
  const keywords = {
    python: "def|class|import|from|return|if|elif|else|for|while|try|except|finally|with|as|yield|lambda|pass|break|continue|raise|and|or|not|in|is|True|False|None|async|await",
    js: "function|const|let|var|return|if|else|for|while|try|catch|finally|throw|class|import|export|from|async|await|new|this|true|false|null|undefined|switch|case|default|break|continue",
    c: "int|char|void|return|if|else|for|while|do|switch|case|break|continue|struct|typedef|enum|const|static|extern|unsigned|signed|long|short|float|double|sizeof|NULL|include|define",
    rust: "fn|let|mut|const|if|else|for|while|loop|match|return|struct|enum|impl|trait|use|pub|mod|self|super|crate|where|async|await|move|ref|type|true|false|Some|None|Ok|Err",
    bash: "if|then|else|elif|fi|for|while|do|done|case|esac|function|return|local|export|source|echo|exit|test|set",
  };
  const kw = keywords[lang] || keywords.js;
  if (kw) {
    result = result.replace(
      new RegExp(`\\b(${kw})\\b`, "g"),
      '<span class="syn-keyword">$1</span>'
    );
  }

  return result;
}

// === Keyboard Shortcuts ===
document.addEventListener("keydown", (e) => {
  // Ignore when typing in inputs
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA"
      || e.target.tagName === "SELECT") return;

  // Only in detail view
  if (views.detail.classList.contains("hidden")) return;

  if (e.key === "Escape") {
    // Close file viewer if open, otherwise go back
    if (!$("#file-viewer-overlay").classList.contains("hidden")) {
      $("#file-viewer-overlay").classList.add("hidden");
    } else {
      disconnectAllWS(); currentChallengeId = null;
      history.replaceState(null, "", "#");
      showView("dashboard"); loadChallenges();
    }
    e.preventDefault();
  }
  if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
    $("#steer-input").focus();
    e.preventDefault();
  }
  // Sidebar tabs: 1-3
  if (e.key === "1") switchTab("tab-info");
  if (e.key === "2") switchTab("tab-stats");
  if (e.key === "3") switchTab("tab-files");

  // Left/Right arrows to switch run tabs
  if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
    if (!currentRuns.length) return;
    const idx = currentRuns.findIndex((r) => r.id === activeRunId);
    if (idx === -1) return;
    let newIdx;
    if (e.key === "ArrowLeft") {
      newIdx = idx > 0 ? idx - 1 : currentRuns.length - 1;
    } else {
      newIdx = idx < currentRuns.length - 1 ? idx + 1 : 0;
    }
    switchRunTab(currentRuns[newIdx].id);
    e.preventDefault();
  }
});

// === Scroll to Bottom Button ===
$("#btn-scroll-bottom").addEventListener("click", () => {
  autoScroll = true;
  const f = getActiveFeed();
  if (f) f.scrollTop = f.scrollHeight;
  updateScrollBtn();
});

// === Expand/Collapse All Tools ===
$("#btn-toggle-tools").addEventListener("click", () => {
  const feed = getActiveFeed();
  if (!feed) return;
  const details = feed.querySelectorAll(".tool-detail");
  const anyOpen = Array.from(details).some((d) => d.classList.contains("open"));
  details.forEach((d) => d.classList.toggle("open", !anyOpen));
  $("#btn-toggle-tools").textContent = anyOpen ? "Expand all" : "Collapse all";
});

$("#btn-transcript-search").addEventListener("click", searchTranscript);
$("#btn-transcript-search-clear").addEventListener("click", clearTranscriptSearch);
$("#transcript-search-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    searchTranscript();
  } else if (e.key === "Escape") {
    clearTranscriptSearch();
  }
});

// === Export Report ===
$("#btn-export").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  openExportOptions([currentChallengeId], false);
});

// === Mobile Sidebar Toggle ===
$("#btn-sidebar-toggle").addEventListener("click", () => {
  const sidebar = document.querySelector(".panel-sidebar");
  if (sidebar) sidebar.classList.toggle("sidebar-open");
});

// === Steer ===
async function sendSteerToRun(runId, inputEl) {
  const msg = inputEl.value.trim();
  if (!msg || !currentChallengeId) return;
  inputEl.value = "";
  const res = await api(`/api/challenges/${currentChallengeId}/steer`, {
    method: "POST",
    body: JSON.stringify({ message: msg, run_id: runId }),
  });
  if (res && res.ok) {
    markRunsSolving(runId);
    updateStatusBadge("solving");
    updateButtons("solving");
    startTimer();
    $("#error-banner").classList.add("hidden");
  }
}

async function sendSteer() {
  const input = $("#steer-input");
  const msg = input.value.trim();
  if (!msg || !currentChallengeId) return;
  input.value = "";

  const body = { message: msg };
  // Send to whichever run tab is currently active
  if (activeRunId && activeRunId !== "__default__") {
    body.run_id = activeRunId;
  }

  const res = await api(`/api/challenges/${currentChallengeId}/steer`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (res && res.ok) {
    markRunsSolving(body.run_id || "");
    updateStatusBadge("solving");
    updateButtons("solving");
    startTimer();
    $("#error-banner").classList.add("hidden");
  }
}

$("#btn-steer").addEventListener("click", sendSteer);
$("#steer-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendSteer(); }
});

// === User Broadcast ===
$("#btn-broadcast").addEventListener("click", sendBroadcast);
$("#broadcast-msg").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendBroadcast(); }
});
async function sendBroadcast() {
  const msg = $("#broadcast-msg").value.trim();
  if (!msg || !currentChallengeId) return;
  const res = await api(`/api/challenges/${currentChallengeId}/broadcast`, {
    method: "POST",
    body: JSON.stringify({ message: msg }),
  });
  if (res && res.ok) {
    $("#broadcast-msg").value = "";
    showToast("Broadcast sent", "success");
  }
}

// === Usage Page ===
$("#btn-usage").addEventListener("click", () => {
  showView("usage");
  loadUsage();
});
$("#btn-usage-back").addEventListener("click", () => {
  showView("dashboard");
  loadChallenges();
});
$("#btn-usage-refresh").addEventListener("click", loadUsage);

async function loadUsage() {
  const res = await api("/api/usage");
  if (!res) return;
  const data = await res.json();
  renderUsage(data);
}

function renderUsage(data) {
  const usage = data.agents || {};
  const cs = data.challenges || {};

  agentCatalog.forEach((agent) => {
    const badge = $(`#${agent.name}-auth-badge`);
    const info = $(`#${agent.name}-auth-info`);
    const stats = $(`#${agent.name}-stats`);
    const challengeStats = $(`#${agent.name}-challenge-stats`);
    const entry = usage[agent.name];

    if (entry) {
      badge.textContent = "connected";
      badge.className = "badge badge-solved";
      info.innerHTML = (entry.auth_rows || [])
        .map((row) => kvRow(row.label, row.value))
        .join("");
      stats.innerHTML = (entry.stat_rows || [])
        .map((row) => kvRow(row.label, row.value, row.bar))
        .join("");
    } else {
      badge.textContent = "not connected";
      badge.className = "badge badge-pending";
      info.innerHTML = `<span class="text-muted">Run <code>${esc(agent.auth_connect_command)}</code> to connect</span>`;
      stats.innerHTML = "";
    }

    challengeStats.innerHTML = renderChallengeStats(cs[agent.name]);
  });

  const dailySection = $("#usage-daily");
  const dailyEntry = agentCatalog
    .map((agent) => ({ agent, usage: usage[agent.name] }))
    .find(({ usage: entry }) => entry && entry.daily_activity && entry.daily_activity.length);
  if (dailyEntry) {
    dailySection.classList.remove("hidden");
    $("#usage-daily-title").textContent = dailyEntry.usage.daily_activity_title || `Daily Activity (${dailyEntry.agent.label})`;
    renderDailyChart(dailyEntry.usage.daily_activity);
  } else {
    dailySection.classList.add("hidden");
  }
}

function kvRow(key, value, bar) {
  let html = `<span class="usage-kv"><span class="usage-k">${esc(String(key))}</span> ${esc(String(value))}`;
  if (bar !== undefined && bar !== null) {
    const pct = Math.min(Math.max(Number(bar), 0), 100);
    const cls = pct >= 90 ? "bar-danger" : pct >= 70 ? "bar-warn" : "bar-ok";
    html += `<span class="usage-bar"><span class="usage-bar-fill ${cls}" style="width:${pct}%"></span></span>`;
  }
  html += `</span>`;
  return html;
}

function renderChallengeStats(stats) {
  if (!stats || stats.total === 0) return '<span class="text-muted">No challenges yet</span>';
  const avgMs = stats.total > 0 ? Math.round(stats.total_duration_ms / stats.total) : 0;
  return [
    kvRow("Challenges", stats.total),
    kvRow("Solved", stats.solved),
    kvRow("Failed", stats.failed),
    kvRow("Avg duration", formatDuration(avgMs)),
    kvRow("Total time", formatDuration(stats.total_duration_ms)),
  ].join("");
}

function renderDailyChart(activity) {
  const chart = $("#daily-chart");
  const maxMsg = Math.max(...activity.map((d) => d.messageCount), 1);
  chart.innerHTML = activity.map((d) => {
    const pct = Math.round((d.messageCount / maxMsg) * 100);
    const label = d.date.slice(5); // MM-DD
    return `<div class="daily-bar-wrap" title="${d.date}: ${d.messageCount} messages, ${d.sessionCount} sessions, ${d.toolCallCount} tools">
      <div class="daily-bar" style="height:${Math.max(pct, 4)}%"></div>
      <span class="daily-label">${label}</span>
      <span class="daily-value">${d.messageCount}</span>
    </div>`;
  }).join("");
}

// === Import from Platform ===
let importPlugins = [];
let importPluginConfig = {};
let importFetchedChallenges = [];

async function loadPlugins() {
  const res = await api("/api/plugins");
  if (!res) return;
  importPlugins = await res.json();
  const sel = $("#import-plugin");
  sel.innerHTML = importPlugins.map((p) =>
    `<option value="${esc(p.name)}">${esc(p.label)}</option>`
  ).join("");
  if (importPlugins.length) renderImportConfigFields(importPlugins[0]);
}

function renderImportConfigFields(plugin) {
  const container = $("#import-config-fields");
  container.innerHTML = (plugin.config_schema || []).map((f) => {
    if (f.type === "checkbox") {
      return `
    <div class="form-group">
      <label class="checkbox-label" for="import-cfg-${esc(f.name)}">
        <input type="checkbox" id="import-cfg-${esc(f.name)}" ${f.default ? "checked" : ""}>
        <span>${esc(f.label)}</span>
      </label>
    </div>`;
    }
    return `
    <div class="form-group">
      <label for="import-cfg-${esc(f.name)}">${esc(f.label)}</label>
      <input type="${esc(f.type)}" id="import-cfg-${esc(f.name)}"
        placeholder="${esc(f.placeholder || "")}"
        value="${esc(f.default || "")}"
        ${f.required ? "required" : ""}>
    </div>`;
  }).join("");
}

function getImportConfig() {
  const plugin = importPlugins.find((p) => p.name === $("#import-plugin").value);
  if (!plugin) return {};
  const config = {};
  for (const f of plugin.config_schema || []) {
    const el = document.getElementById(`import-cfg-${f.name}`);
    if (!el) continue;
    config[f.name] = f.type === "checkbox" ? el.checked : el.value;
  }
  return config;
}

$("#btn-import").addEventListener("click", async () => {
  await loadPlugins();
  if (!importPlugins.length) {
    showToast("No platform plugins available", "error");
    return;
  }
  // Reset state
  importFetchedChallenges = [];
  $("#import-phase-config").classList.remove("hidden");
  $("#import-phase-loading").classList.add("hidden");
  $("#import-phase-preview").classList.add("hidden");
  $("#import-status").classList.add("hidden");
  // Set up preview controls using saved agent settings
  populateAgentList($("#import-agent-list"));
  $("#import-autonomous").checked = getAgentAutonomousDefault(primaryAgentName());
  $("#import-flag").value = defaultFlagFormat;
  $("#import-overlay").classList.remove("hidden");
});

$("#import-close").addEventListener("click", () => {
  $("#import-overlay").classList.add("hidden");
});
$("#import-overlay").addEventListener("click", (e) => {
  if (e.target === $("#import-overlay")) $("#import-overlay").classList.add("hidden");
});

$("#import-plugin").addEventListener("change", () => {
  const plugin = importPlugins.find((p) => p.name === $("#import-plugin").value);
  if (plugin) renderImportConfigFields(plugin);
});

$("#btn-import-test").addEventListener("click", async () => {
  const statusEl = $("#import-status");
  statusEl.textContent = "Testing...";
  statusEl.className = "import-status";
  statusEl.classList.remove("hidden");

  const res = await api("/api/plugins/test", {
    method: "POST",
    body: JSON.stringify({
      plugin: $("#import-plugin").value,
      config: getImportConfig(),
    }),
  });
  if (!res) return;
  const data = await res.json();
  if (data.ok) {
    statusEl.textContent = data.message;
    statusEl.className = "import-status import-status-ok";
  } else {
    statusEl.textContent = data.error || "Connection failed";
    statusEl.className = "import-status import-status-error";
  }
});

$("#btn-import-fetch").addEventListener("click", async () => {
  importPluginConfig = getImportConfig();
  $("#import-phase-config").classList.add("hidden");
  $("#import-phase-loading").classList.remove("hidden");

  const res = await api("/api/plugins/fetch", {
    method: "POST",
    body: JSON.stringify({
      plugin: $("#import-plugin").value,
      config: importPluginConfig,
    }),
  });

  if (!res || !res.ok) {
    const err = res ? await res.json().catch(() => ({})) : {};
    showToast(err.error || "Fetch failed", "error");
    $("#import-phase-loading").classList.add("hidden");
    $("#import-phase-config").classList.remove("hidden");
    return;
  }

  importFetchedChallenges = await res.json();
  renderImportPreview();
  $("#import-phase-loading").classList.add("hidden");
  $("#import-phase-preview").classList.remove("hidden");
});

function renderImportPreview() {
  const list = $("#import-challenge-list");

  // Group by category, sort by points within each category
  const indexed = importFetchedChallenges.map((c, i) => ({ ...c, _idx: i }));
  const groups = {};
  for (const c of indexed) {
    const cat = c.category || "misc";
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(c);
  }
  for (const cat of Object.keys(groups)) {
    groups[cat].sort((a, b) => (a.points || 0) - (b.points || 0));
  }
  const sortedCats = Object.keys(groups).sort();

  let html = "";
  for (const cat of sortedCats) {
    html += `<div class="import-category-group">
      <div class="import-category-header">${esc(cat)}</div>
      <div class="import-card-grid">`;
    for (const c of groups[cat]) {
      const fileLabel = c.files.length
        ? `${c.files.length} file${c.files.length !== 1 ? "s" : ""}`
        : "No files";
      const solvedClass = c.solved ? "import-ch-solved" : "";
      const questionCount = (c.flag_questions || []).length;
      html += `
      <div class="import-card ${solvedClass}" data-index="${c._idx}">
        <div class="import-card-top">
          <input type="checkbox" class="import-ch-enabled" ${c.solved ? "" : "checked"}>
          <input type="text" class="bulk-ch-name" value="${esc(c.name)}">
        </div>
        <div class="import-card-meta">
          ${c.points ? `<span class="import-card-badge">${c.points} pts</span>` : ""}
          <span class="import-card-badge">${c.solves ?? 0} solve${c.solves !== 1 ? "s" : ""}</span>
          <span class="import-card-badge">${esc(fileLabel)}</span>
          ${questionCount ? `<span class="import-card-badge">${questionCount} question${questionCount !== 1 ? "s" : ""}</span>` : ""}
          ${c.solved ? '<span class="badge badge-solved">solved</span>' : ""}
        </div>
        <textarea class="bulk-ch-desc" rows="2" placeholder="Description">${esc(c.description || "")}</textarea>
      </div>`;
    }
    html += `</div></div>`;
  }

  list.innerHTML = html;
  updateImportSkipSolved();
}

function updateImportSkipSolved() {
  const skip = $("#import-skip-solved").checked;
  const cards = document.querySelectorAll("#import-challenge-list .import-card");
  cards.forEach((card) => {
    const idx = parseInt(card.dataset.index, 10);
    const ch = importFetchedChallenges[idx];
    const cb = card.querySelector(".import-ch-enabled");
    if (ch && ch.solved && skip) {
      cb.checked = false;
      card.classList.add("bulk-ch-disabled");
    }
  });
}

$("#btn-add-import-agent").addEventListener("click", () => {
  addAgentRow($("#import-agent-list"));
});

$("#btn-import-select-all").addEventListener("click", () => {
  document.querySelectorAll("#import-challenge-list .import-ch-enabled").forEach((cb) => { cb.checked = true; });
});
$("#btn-import-deselect-all").addEventListener("click", () => {
  document.querySelectorAll("#import-challenge-list .import-ch-enabled").forEach((cb) => { cb.checked = false; });
});

$("#import-skip-solved").addEventListener("change", () => {
  const cards = document.querySelectorAll("#import-challenge-list .import-card");
  const skip = $("#import-skip-solved").checked;
  cards.forEach((card) => {
    const idx = parseInt(card.dataset.index, 10);
    const ch = importFetchedChallenges[idx];
    const cb = card.querySelector(".import-ch-enabled");
    if (ch && ch.solved) {
      cb.checked = !skip;
      card.classList.toggle("bulk-ch-disabled", skip);
    }
  });
});

$("#btn-import-submit").addEventListener("click", async () => {
  const cards = document.querySelectorAll("#import-challenge-list .import-card");
  const selected = Array.from(cards).map((card) => {
    const idx = parseInt(card.dataset.index, 10);
    const ch = importFetchedChallenges[idx];
    return {
      enabled: card.querySelector(".import-ch-enabled").checked,
      remote_id: ch.remote_id,
      name: card.querySelector(".bulk-ch-name").value.trim(),
      description: card.querySelector(".bulk-ch-desc").value.trim(),
      category: ch.category,
      points: ch.points || 0,
      solves: ch.solves || 0,
      tags: ch.tags || [],
      flag_questions: ch.flag_questions || [],
      files: ch.files,
    };
  });

  const btn = $("#btn-import-submit");
  btn.disabled = true;
  btn.textContent = "Importing...";

  try {
    const agentRows = getAgentRows($("#import-agent-list"));
    const mode = agentRows.length > 1 ? "parallel" : "single";
    const res = await api("/api/plugins/import", {
      method: "POST",
      body: JSON.stringify({
        plugin: $("#import-plugin").value,
        config: importPluginConfig,
        challenges: selected,
        mode: mode,
        agents: JSON.stringify(agentRows),
        model: "",
        effort: "",
        flag_format: $("#import-flag").value.trim(),
        autonomous: $("#import-autonomous").checked,
        paused: $("#import-paused").checked,
      }),
    });

    if (!res || !res.ok) {
      const err = res ? await res.json().catch(() => ({})) : {};
      showToast(err.error || "Import failed", "error");
      return;
    }
    const data = await res.json();
    const entries = data.created || [];
    const successes = entries.filter((e) => e.id && e.status !== "error" && e.status !== "skipped");
    const skipped = entries.filter((e) => e.status === "skipped");
    const errors = entries.filter((e) => e.status === "error");
    const warnings = entries.filter((e) => e.warning);
    if (successes.length) {
      showToast(`Imported ${successes.length} challenge(s)`, "success");
    }
    if (warnings.length) {
      showToast(`${warnings.length} challenge(s) imported with missing files`, "info");
    }
    if (skipped.length) {
      showToast(`${skipped.length} challenge(s) skipped: ${skipped[0].error}`, "info");
    }
    if (errors.length) {
      showToast(`${errors.length} challenge(s) failed: ${errors[0].error}`, "error");
    }
    if (!successes.length && !skipped.length && !errors.length) {
      showToast("No challenges imported", "info");
    }
    $("#import-overlay").classList.add("hidden");
    loadChallenges();
  } finally {
    btn.disabled = false;
    btn.textContent = "Import Selected";
  }
});

// === Settings View ===
function formatVpnBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

// (Manager settings removed — no manager in new collaborative model)

function updateSettingsVpnStatus(data) {
  const badge = $("#settings-vpn-status");
  const toggleBtn = $("#btn-settings-vpn-toggle");
  if (data.up) {
    badge.textContent = "up";
    badge.className = "badge badge-solved";
    toggleBtn.textContent = "Stop";
  } else {
    badge.textContent = "down";
    badge.className = "badge badge-pending";
    toggleBtn.textContent = "Start";
  }
  const peerEl = $("#settings-vpn-peer");
  if (data.peer) {
    peerEl.classList.remove("hidden");
    $("#settings-vpn-peer-key").textContent = data.peer.public_key || "—";
    $("#settings-vpn-peer-endpoint").textContent = data.peer.endpoint || "—";
    const rx = parseInt(data.peer.transfer_rx || 0);
    const tx = parseInt(data.peer.transfer_tx || 0);
    $("#settings-vpn-peer-transfer").textContent = `${formatVpnBytes(rx)} rx / ${formatVpnBytes(tx)} tx`;
  } else {
    peerEl.classList.add("hidden");
  }
}

$("#btn-settings").addEventListener("click", async () => {
  const res = await api("/api/settings");
  if (!res) return;
  const s = await res.json();

  // General
  $("#settings-flag-format").value = s.default_flag_format || "";
  $("#settings-theme").value = s.theme || "dark";
  $("#settings-chat-view").value = s.chat_view_mode || "split";
  $("#settings-max-platform-import-size").value = s.max_platform_import_size_gb || 2;
  $("#settings-auto-submit").checked = !!s.auto_submit_flags;

  // Agents
  const agentList = $("#settings-agent-list");
  const savedEnabled = s.enabled_agents && s.enabled_agents.length ? s.enabled_agents : [defaultAgent];
  const savedModels = s.agent_models || {};
  const savedEfforts = s.agent_efforts || {};
  agentList.innerHTML = agentCatalog.map((agent) => {
    const checked = savedEnabled.includes(agent.name) ? "checked" : "";
    const modelOptions = (agent.models || []).map((m) =>
      `<option value="${esc(m.value)}" ${savedModels[agent.name] === m.value ? "selected" : ""}>${esc(m.label)}</option>`
    ).join("");
    const efforts = agent.effort_levels || [];
    const effortHtml = efforts.length
      ? `<select class="settings-agent-effort" data-agent="${esc(agent.name)}">${efforts.map((e) =>
          `<option value="${esc(e.value)}" ${savedEfforts[agent.name] === e.value ? "selected" : ""}>${esc(e.label)}</option>`
        ).join("")}</select>`
      : "";
    return `<div class="settings-agent-row">
      <label class="checkbox-label">
        <input type="checkbox" class="settings-agent-cb" value="${esc(agent.name)}" ${checked}>
        <span>${esc(agent.label)}</span>
      </label>
      <select class="settings-agent-model" data-agent="${esc(agent.name)}">${modelOptions}</select>
      ${effortHtml}
    </div>`;
  }).join("");

  // Discord
  $("#settings-discord-enabled").checked = !!s.discord_enabled;
  $("#settings-discord-token").value = s.discord_bot_token || "";
  const discordChannel = $("#settings-discord-channel");
  if (s.discord_channel_id) {
    // Preserve saved value; user can hit Refresh to populate the dropdown
    if (!discordChannel.querySelector(`option[value="${s.discord_channel_id}"]`)) {
      const opt = document.createElement("option");
      opt.value = s.discord_channel_id;
      opt.textContent = `Channel ${s.discord_channel_id}`;
      opt.selected = true;
      discordChannel.appendChild(opt);
    } else {
      discordChannel.value = s.discord_channel_id;
    }
  }

  // VPN
  const vpnRes = await api("/api/vpn");
  if (vpnRes) {
    const vpnData = await vpnRes.json();
    if (!vpnData.installed) {
      $("#settings-vpn-not-installed").classList.remove("hidden");
      $("#settings-vpn-panel").classList.add("hidden");
    } else {
      $("#settings-vpn-not-installed").classList.add("hidden");
      $("#settings-vpn-panel").classList.remove("hidden");
      updateSettingsVpnStatus(vpnData);
    }
  }

  showView("settings");
});

$("#btn-settings-back").addEventListener("click", () => {
  showView("dashboard");
  loadChallenges();
});

$("#btn-settings-save").addEventListener("click", async () => {
  const selectedAgents = Array.from(document.querySelectorAll(".settings-agent-cb:checked")).map((cb) => cb.value);
  const models = {};
  document.querySelectorAll(".settings-agent-model").forEach((sel) => {
    if (sel.value) models[sel.dataset.agent] = sel.value;
  });
  const efforts = {};
  document.querySelectorAll(".settings-agent-effort").forEach((sel) => {
    if (sel.value) efforts[sel.dataset.agent] = sel.value;
  });

  const body = {
    default_flag_format: $("#settings-flag-format").value.trim(),
    theme: $("#settings-theme").value,
    chat_view_mode: $("#settings-chat-view").value,
    max_platform_import_size_gb: Number($("#settings-max-platform-import-size").value || 2),
    auto_submit_flags: $("#settings-auto-submit").checked,
    enabled_agents: selectedAgents,
    agent_models: models,
    agent_efforts: efforts,
    default_agent: selectedAgents[0] || defaultAgent,
    discord_enabled: $("#settings-discord-enabled").checked,
    discord_bot_token: $("#settings-discord-token").value.trim(),
    discord_channel_id: $("#settings-discord-channel").value.trim(),
  };
  const res = await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
  if (res && res.ok) {
    const saved = await res.json();
    defaultFlagFormat = saved.default_flag_format || "";
    currentTheme = saved.theme || "dark";
    chatViewMode = saved.chat_view_mode || "split";
    enabledAgents = saved.enabled_agents && saved.enabled_agents.length
      ? saved.enabled_agents : [defaultAgent];
    agentModels = saved.agent_models || {};
    agentEfforts = saved.agent_efforts || {};
    defaultAgent = saved.default_agent || enabledAgents[0];
    applyTheme(currentTheme);
    showToast("Settings saved", "success");
  }
});

// Discord channel fetch
$("#btn-discord-fetch-channels").addEventListener("click", async () => {
  const token = $("#settings-discord-token").value.trim();
  if (!token) { showToast("Enter bot token first", "error"); return; }
  const sel = $("#settings-discord-channel");
  const saved = sel.value;
  sel.innerHTML = '<option value="">Loading...</option>';
  const res = await api("/api/discord/channels", { method: "POST", body: JSON.stringify({ token }) });
  if (!res) { sel.innerHTML = '<option value="">Failed</option>'; return; }
  const data = await res.json();
  const channels = data.channels || [];
  sel.innerHTML = '<option value="">— Select channel —</option>' +
    channels.map((c) => `<option value="${esc(c.id)}" ${c.id === saved ? "selected" : ""}>${esc(c.guild)} / ${esc(c.name)}</option>`).join("");
  if (saved && !sel.value) sel.value = saved;
});

// Discord test button
$("#btn-discord-test").addEventListener("click", async () => {
  const result = $("#discord-test-result");
  result.textContent = "Testing...";
  const res = await api("/api/discord/test", { method: "POST", body: JSON.stringify({
    token: $("#settings-discord-token").value.trim(),
    channel_id: $("#settings-discord-channel").value.trim(),
  })});
  if (!res) { result.textContent = "Request failed"; return; }
  const data = await res.json();
  result.textContent = data.ok ? "Connected!" : (data.error || "Failed");
});

// VPN controls within settings
$("#btn-settings-vpn-toggle").addEventListener("click", async () => {
  const badge = $("#settings-vpn-status");
  const action = badge.textContent === "up" ? "down" : "up";
  const res = await api("/api/vpn/toggle", {
    method: "POST",
    body: JSON.stringify({ action }),
  });
  if (res && res.ok) {
    const data = await res.json();
    const vpnRes = await api("/api/vpn");
    if (vpnRes) updateSettingsVpnStatus(await vpnRes.json());
    showToast(`VPN ${data.up ? "started" : "stopped"}`, "success");
  }
});

$("#btn-settings-vpn-configure").addEventListener("click", async () => {
  const clientKey = $("#settings-vpn-key").value.trim();
  const clientNetworks = $("#settings-vpn-networks").value.trim();
  const dnsForward = $("#settings-vpn-dns").checked;

  if (!clientKey) {
    showToast("Public key required", "error");
    return;
  }

  const res = await api("/api/vpn/configure", {
    method: "POST",
    body: JSON.stringify({
      client_public_key: clientKey,
      client_networks: clientNetworks,
      dns_forward: dnsForward,
    }),
  });
  if (!res) return;
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    showToast(err.error || "Configuration failed", "error");
    return;
  }
  const data = await res.json();
  $("#settings-vpn-config-text").textContent = data.client_config;
  $("#settings-vpn-client-config").classList.remove("hidden");

  const vpnRes = await api("/api/vpn");
  if (vpnRes) updateSettingsVpnStatus(await vpnRes.json());
  showToast("VPN configured and started", "success");
});

$("#btn-settings-vpn-copy").addEventListener("click", () => {
  const text = $("#settings-vpn-config-text").textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = $("#btn-settings-vpn-copy");
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy"; }, 1200);
  });
});

// (Manager sidebar tab removed — agents collaborate via WORKING_NOTES and BREAKTHROUGHS.md)

// === Deep Linking ===
function getDeepLinkChallengeId() {
  const match = location.hash.match(/^#\/challenge\/([a-f0-9]+)$/);
  return match ? match[1] : null;
}

async function handleDeepLink() {
  const challengeId = getDeepLinkChallengeId();
  if (challengeId) {
    openChallenge(challengeId);
  } else {
    showView("dashboard");
    loadChallenges();
  }
}

window.addEventListener("hashchange", () => {
  if (!csrfToken) return; // not logged in
  const challengeId = getDeepLinkChallengeId();
  if (challengeId && challengeId !== currentChallengeId) {
    openChallenge(challengeId);
  } else if (!challengeId && currentChallengeId) {
    disconnectAllWS(); stopTimer(); currentChallengeId = null;
    showView("dashboard"); loadChallenges();
  }
});

// === Init ===
(async () => {
  // Page is served behind HTTP Basic Auth — session is already valid.
  const [csrfRes, catalogOk] = await Promise.all([
    fetch("/api/csrf-token"),
    loadAgentCatalog(),
  ]);
  if (csrfRes.ok) {
    const data = await csrfRes.json();
    csrfToken = data.csrf_token;
  }
  if (!catalogOk) return;

  connectGlobalWS();
  await handleDeepLink();
  loadDefaultAgent();
  loadConnections();
})();
