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

// Per-run counters
let runToolCounts = new Map();
let runStepCounts = new Map();

// Per-run statistics
let runStats = new Map();

// Timer & cost
let timerStart = null;
let timerInterval = null;
let challengeFlagFormat = "";
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

// === Login ===
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pw = $("#login-password").value;
  // Try Basic Auth first (sets session cookie for future requests)
  const basicRes = await fetch("/api/challenges", {
    headers: { "Authorization": "Basic " + btoa("user:" + pw) },
  });
  if (basicRes.ok) {
    const csrfRes = await fetch("/api/csrf-token");
    if (csrfRes.ok) {
      const data = await csrfRes.json();
      csrfToken = data.csrf_token;
    }
    if (await loadAgentCatalog()) {
      showView("dashboard");
      connectGlobalWS();
      await handleDeepLink();
      loadDefaultAgent();
    }
  } else {
    $("#login-error").textContent = "Invalid password";
    $("#login-error").classList.remove("hidden");
  }
});

$("#btn-logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
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
  if (!views.dashboard.classList.contains("hidden")) loadChallenges();
}, 5000);

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
  if (!data.challenges.length) {
    showToast(`No new challenges (${data.total} total on platform)`, "info");
    return;
  }
  showToast(`Found ${data.new} new challenge${data.new !== 1 ? "s" : ""}`, "success");

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
  runToolCounts.clear();
  runStepCounts.clear();
  runStats.clear();
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
  $("#detail-flag-format").textContent = c.flag_format ? `Flag: ${c.flag_format}` : "";
  $("#detail-files").textContent = c.files.length ? `Files: ${c.files.join(", ")}` : "No files";
  challengeFlagFormat = c.flag_format || "";

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
  foundFlags.clear(); $("#flags-list").innerHTML = ""; $("#flags-section").classList.add("hidden");

  // Restore persisted flags
  const df = c.detected_flags || {};
  for (const [f, status] of Object.entries(df)) {
    showFlagBanner(f);
    if (status === "correct" || status === "wrong") setFlagStatus(f, status);
  }

  if (c.status === "solving") startTimer();
  else stopTimer();

  updateButtons(c.status);
  initRunTabs(currentRuns);
  $("#stats-panel").innerHTML = "";
  $("#files-tree").innerHTML = "";
  updateCounters();
  showView("detail");
  switchTab("tab-info");
  updateSteerRunSelect();
  updateFilesRunSelect();
  connectAllRuns(id, currentRuns);
  loadFiles();
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
    updateStatusBadge("solving"); updateButtons("solving"); startTimer();
  }
});

$("#btn-retry").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  initRunTabs([]);
  $("#error-banner").classList.add("hidden");
  foundFlags.clear(); $("#flags-list").innerHTML = ""; $("#flags-section").classList.add("hidden");
  stepCount = 0;
  lastThinkingEl = null;
  pendingTools.clear(); runToolCounts.clear(); runStepCounts.clear(); runStats.clear(); updateCounters();
  const res = await api(`/api/challenges/${currentChallengeId}/solve`, { method: "POST" });
  if (res && res.ok) {
    updateStatusBadge("solving"); updateButtons("solving"); startTimer();
    // Re-open to pick up new runs from the server
    openChallenge(currentChallengeId);
  }
});

$("#btn-resume").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  const res = await api(`/api/challenges/${currentChallengeId}/solve?resume=1`, { method: "POST" });
  if (res && res.ok) {
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
  for (const run of runs) {
    connectRunWS(challengeId, run.id, run.agent);
  }
}

function connectGlobalWS() {
  if (globalWs && globalWs.readyState <= WebSocket.OPEN) return;
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  globalWs = new WebSocket(`${proto}//${location.host}/ws/events`);
  globalWs.onmessage = (e) => {
    const event = JSON.parse(e.data);
    if (event.type === "flag_found") {
      showFlagFoundToast(
        event.challenge_name || "Challenge",
        event.agent || "Agent",
        event.flag || "???",
        event.challenge_id
      );
    }
    if (event.type === "flag_result" && event.flag) {
      setFlagStatus(event.flag, event.correct ? "correct" : "wrong");
    }
    if (event.type === "challenge_status" && event.challenge_id) {
      updateDashboardChallengeStatus(event.challenge_id, event.status);
    }
  };
  globalWs.onclose = () => {
    setTimeout(connectGlobalWS, 3000);
  };
}

function updateDashboardChallengeStatus(challengeId, status) {
  const card = document.querySelector(`[data-id="${challengeId}"]`);
  if (!card) return;
  const badge = card.querySelector(".badge");
  if (!badge) return;
  badge.textContent = status;
  badge.className = "badge badge-" + status;
}

function connectRunWS(challengeId, runId, agentLabel) {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/ws/${challengeId}/${runId}`);
  ws.onopen = () => {
    setWsStatus("connected");
  };
  ws.onmessage = (e) => renderRunEvent(runId, JSON.parse(e.data));
  ws.onclose = () => {
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
        connectRunWS(challengeId, runId, agentLabel);
      }
    }, 2000);
  };
  wsConnections.set(runId, ws);
}

function disconnectAllWS() {
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

function scrollBottomIfActive(runId) {
  if (isSplitView()) {
    const f = document.getElementById(`feed-${runId}`);
    if (autoScroll && f) f.scrollTop = f.scrollHeight;
    return;
  }
  if (runId === activeRunId) scrollBottom();
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
function checkForFlag(text) {
  const patterns = [
    /flag\{[^}]+\}/gi,
    /FLAG\{[^}]+\}/g,
    /CTF\{[^}]+\}/g,
    /HTB\{[^}]+\}/g,
    /picoCTF\{[^}]+\}/g,
  ];
  if (challengeFlagFormat) {
    const prefix = challengeFlagFormat.replace(/\{.*/, "");
    if (prefix.length >= 2) {
      patterns.push(
        new RegExp(prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
          + "\\{[^}]+\\}", "g")
      );
    }
  }
  for (const pat of patterns) {
    const m = text.match(pat);
    if (m) return m[0];
  }
  return null;
}

const foundFlags = new Map();

function showFlagBanner(flag) {
  if (foundFlags.has(flag)) return;

  const section = $("#flags-section");
  const list = $("#flags-list");
  section.classList.remove("hidden");

  const item = document.createElement("div");
  item.className = "flag-item";
  item.dataset.flag = flag;
  const span = document.createElement("span");
  span.className = "flag-text";
  span.textContent = flag;

  const copyBtn = document.createElement("button");
  copyBtn.className = "btn-flag-action";
  copyBtn.textContent = "Copy";
  copyBtn.addEventListener("click", () => copyToClipboard(flag, copyBtn));
  item.append(span, copyBtn);

  const submitBtn = document.createElement("button");
  submitBtn.className = "btn-flag-action btn-flag-submit";
  submitBtn.textContent = "Submit";
  submitBtn.addEventListener("click", async () => {
    if (!currentChallengeId) return;
    submitBtn.disabled = true;
    submitBtn.textContent = "Submitting...";
    const res = await api("/api/plugins/submit-flag", {
      method: "POST",
      body: JSON.stringify({ challenge_id: currentChallengeId, flag }),
    });
    if (!res) { submitBtn.disabled = false; submitBtn.textContent = "Submit"; return; }
    const data = await res.json();
    if (data.error) {
      submitBtn.classList.add("hidden");
      return;
    }
    if (data.correct) {
      setFlagStatus(flag, "correct");
      showToast("Flag correct!", "success");
      updateStatusBadge("solved");
      updateButtons("solved");
      stopTimer();
    } else {
      setFlagStatus(flag, "wrong");
      submitBtn.textContent = data.message || "Wrong";
      submitBtn.disabled = false;
      setTimeout(() => { submitBtn.textContent = "Submit"; }, 2000);
    }
  });
  item.appendChild(submitBtn);

  const markBtn = document.createElement("button");
  markBtn.className = "btn-flag-action";
  markBtn.textContent = "Mark Solved";
  markBtn.addEventListener("click", async () => {
    if (!currentChallengeId) return;
    const res = await api(`/api/challenges/${currentChallengeId}/mark-solved`, {
      method: "POST",
      body: JSON.stringify({ flag }),
    });
    if (res && res.ok) {
      setFlagStatus(flag, "correct");
      showToast("Challenge marked as solved", "success");
      updateStatusBadge("solved");
      updateButtons("solved");
      stopTimer();
    }
  });
  item.appendChild(markBtn);

  list.appendChild(item);
  foundFlags.set(flag, "pending");
}

function setFlagStatus(flag, status) {
  foundFlags.set(flag, status);
  const items = document.querySelectorAll(`.flag-item[data-flag="${CSS.escape(flag)}"]`);
  items.forEach((item) => {
    item.classList.remove("flag-correct", "flag-wrong");
    if (status === "correct") item.classList.add("flag-correct");
    else if (status === "wrong") item.classList.add("flag-wrong");
  });
}

// === Timer ===
function startTimer() {
  stopTimer();
  timerStart = Date.now();
  timerInterval = setInterval(updateTimer, 1000);
  updateTimer();
}

function stopTimer() {
  if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
}

function updateTimer() {
  if (!timerStart) return;
  const elapsed = Math.floor((Date.now() - timerStart) / 1000);
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
    const run = currentRuns.find(r => r.id === rid);
    if (run) run.status = event.status;
    if (event.error) {
      $("#error-banner").textContent = event.error;
      $("#error-banner").classList.remove("hidden");
    }
    return;
  }

  // --- New run added (new run added) ---
  if (event.type === "run_added" && event.run) {
    const r = event.run;
    if (currentRuns.some((x) => x.id === r.id)) return;
    currentRuns.push(r);
    addRunTab(r);
    if (currentChallengeId) {
      connectRunWS(currentChallengeId, r.id, r.agent);
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
    if (event.subtype === "teammate_broadcast" && event.message) {
      appendMsg(feed, event.message, "teammate-broadcast-msg", event.ts);
      scrollBottomIfActive(runId); return;
    }
    if (event.message) appendMsg(feed, event.message, "system-msg", event.ts);
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
      if (runId) getRunStats(runId).toolCalls++;
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
    toolEl._outputEl.textContent = output || "(no output)";
    if (isError) toolEl._outputEl.classList.add("tool-output-error");

    // Add copy button to output
    if (output) {
      const copyBtn = makeCopyBtn(output);
      toolEl._outputEl.style.position = "relative";
      toolEl._outputEl.appendChild(copyBtn);
    }

    pendingTools.delete(block.tool_use_id);
  }
}

// === Stats Sidebar ===
function getRunStats(runId) {
  if (!runStats.has(runId)) {
    runStats.set(runId, {
      inputTokens: 0, outputTokens: 0,
      cacheReadTokens: 0, cacheCreationTokens: 0,
      toolCalls: 0, turns: 0,
      costUsd: 0, durationMs: 0, durationApiMs: 0,
      modelUsage: null,
    });
  }
  return runStats.get(runId);
}

function updateRunStats(runId, event) {
  const s = getRunStats(runId);
  if (event.type === "result") {
    if (event.usage) {
      s.inputTokens = event.usage.input_tokens || 0;
      s.outputTokens = event.usage.output_tokens || 0;
      s.cacheReadTokens = event.usage.cache_read_input_tokens || 0;
      s.cacheCreationTokens = event.usage.cache_creation_input_tokens || 0;
    }
    if (event.total_cost_usd) s.costUsd = event.total_cost_usd;
    if (event.num_turns) s.turns = event.num_turns;
    if (event.duration_ms) s.durationMs = event.duration_ms;
    if (event.duration_api_ms) s.durationApiMs = event.duration_api_ms;
    if (event.model_usage) s.modelUsage = event.model_usage;
  } else if (event.type === "codex_usage" && event.usage) {
    s.inputTokens += event.usage.input_tokens || 0;
    s.outputTokens += event.usage.output_tokens || 0;
    s.cacheReadTokens += event.usage.cached_input_tokens || 0;
  } else if (event.type === "assistant" && event.message?.usage) {
    const u = event.message.usage;
    s.inputTokens += u.input_tokens || 0;
    s.outputTokens += u.output_tokens || 0;
    s.cacheReadTokens += u.cache_read_input_tokens || 0;
    s.cacheCreationTokens += u.cache_creation_input_tokens || 0;
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

function renderStats() {
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
}

// === Files Browser ===
async function loadFiles() {
  if (!currentChallengeId) return;
  let url = `/api/challenges/${currentChallengeId}/files`;
  const runSelect = $("#files-run-select");
  if (runSelect && runSelect.value) {
    url += `?run_id=${encodeURIComponent(runSelect.value)}`;
  }
  const res = await api(url);
  if (!res) return;
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    showToast(err.error || "Failed to load files", "error");
    return;
  }
  const files = await res.json();

  $("#file-counter").textContent = files.length;
  const tree = $("#files-tree");
  tree.innerHTML = "";

  // Group by directory
  const dirs = new Map();
  for (const f of files) {
    const parts = f.path.split("/");
    const dir = parts.length > 1 ? parts.slice(0, -1).join("/") : ".";
    if (!dirs.has(dir)) dirs.set(dir, []);
    dirs.get(dir).push(f);
  }

  for (const [dir, dirFiles] of dirs) {
    if (dirs.size > 1 || dir !== ".") {
      const label = document.createElement("div");
      label.className = "file-dir-label";
      label.textContent = dir === "." ? "root" : dir;
      tree.appendChild(label);
    }
    for (const f of dirFiles) {
      const item = document.createElement("div");
      item.className = "file-item";

      const icon = document.createElement("span");
      icon.className = `file-icon file-icon-${f.type}`;
      icon.textContent = f.type === "image" ? "\uD83D\uDDBC" : f.type === "text" ? "\uD83D\uDCC4" : "\uD83D\uDD37";

      const name = document.createElement("span");
      name.className = "file-name";
      name.textContent = f.path.split("/").pop();
      name.title = f.path;

      const size = document.createElement("span");
      size.className = "file-size";
      size.textContent = formatSize(f.size);

      item.append(icon, name, size);
      item.addEventListener("click", () => viewFile(f.path));
      tree.appendChild(item);
    }
  }
}

$("#btn-refresh-files").addEventListener("click", loadFiles);

// Listen for files run select change
const filesRunSelect = $("#files-run-select");
if (filesRunSelect) {
  filesRunSelect.addEventListener("change", loadFiles);
}

// Auto-refresh files while solving
setInterval(() => {
  if (currentChallengeId && !views.detail.classList.contains("hidden")) {
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

// === Export Report ===
$("#btn-export").addEventListener("click", () => {
  const feed = getActiveFeed();
  if (!feed) return;
  const lines = [];
  const name = $("#detail-name").textContent;
  const status = $("#detail-status").textContent;
  lines.push(`# ${name}`, `**Status:** ${status}`, "");

  feed.querySelectorAll(".step").forEach((step) => {
    const ts = step.querySelector(".step-timestamp");
    const prefix = ts ? `[${ts.textContent}] ` : "";

    const thinking = step.querySelector(".thinking-body");
    if (thinking) {
      lines.push(`${prefix}**Thinking:**`, thinking.textContent, "");
      return;
    }

    const text = step.querySelector(".step-text");
    if (text) {
      lines.push(`${prefix}**Assistant:**`, text.textContent, "");
      return;
    }

    const tool = step.querySelector(".tool-detail");
    if (tool) {
      const summary = tool.querySelector("summary");
      lines.push(`${prefix}**Tool:** ${summary ? summary.textContent.trim() : "unknown"}`, "");
      const output = tool.querySelector(".tool-output-section");
      if (output) {
        const pre = output.querySelector("pre");
        lines.push("```", (pre || output).textContent.trim(), "```", "");
      }
    }
  });

  const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${name.replace(/[^a-zA-Z0-9]/g, "_")}_report.md`;
  a.click();
  URL.revokeObjectURL(url);
  showToast("Report exported");
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
    const successes = entries.filter((e) => e.status !== "error");
    const errors = entries.filter((e) => e.status === "error");
    const warnings = entries.filter((e) => e.warning);
    if (successes.length) {
      showToast(`Imported ${successes.length} challenge(s)`, "success");
    }
    if (warnings.length) {
      showToast(`${warnings.length} challenge(s) imported with missing files`, "info");
    }
    if (errors.length) {
      showToast(`${errors.length} challenge(s) failed: ${errors[0].error}`, "error");
    }
    if (!successes.length && !errors.length) {
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
})();
