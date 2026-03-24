/* CTF Solver - Frontend
 *
 * Supports 4 challenge modes: single, single_managed, parallel, parallel_managed.
 * Each challenge has one or more "runs" — per-agent WebSocket streams.
 */

const $ = (sel) => document.querySelector(sel);

// === Global State ===
let currentChallengeId = null;
let autoScroll = true;
let toolCount = 0;
let stepCount = 0;
let defaultAgent = null;
let defaultFlagFormat = "";
let currentTheme = "dark";
let csrfToken = null;
let agentCatalog = [];
let agentByName = new Map();

const pendingTools = new Map();

// Run tracking — one WS per run, one feed per run
let currentRuns = [];               // run objects for current challenge
let activeRunId = null;             // which run tab is active
let currentChallengeMode = "single";
let wsConnections = new Map();      // run_id -> WebSocket

// Per-run counters (future use for per-tab badges)
let runToolCounts = new Map();
let runStepCounts = new Map();

// Timer & cost
let timerStart = null;
let timerInterval = null;
let totalCostUsd = 0;
let totalTokens = 0;
let challengeFlagFormat = "";
let lastThinkingEl = null;

// === Views ===
const views = {
  login: $("#login-view"),
  dashboard: $("#dashboard-view"),
  detail: $("#detail-view"),
  usage: $("#usage-view"),
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
  return mode === "parallel" || mode === "parallel_managed";
}

function isManagedMode(mode) {
  return mode === "single_managed" || mode === "parallel_managed";
}

function getAgentAutonomousDefault(agentName) {
  return Boolean(getAgentMeta(agentName).autonomous_default);
}

// === Agent UI Renderers ===
function renderAgentToggleButtons() {
  const container = $("#default-agent-buttons");
  container.innerHTML = agentCatalog.map((agent) => `
    <button class="agent-toggle-btn" data-agent="${esc(agent.name)}">${esc(agent.label)}</button>
  `).join("");
  container.querySelectorAll(".agent-toggle-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      defaultAgent = btn.dataset.agent;
      updateAgentToggleUI();
      await api("/api/settings", {
        method: "PUT",
        body: JSON.stringify({ default_agent: defaultAgent }),
      });
    });
  });
}

function renderAgentSelect(selectEl) {
  selectEl.innerHTML = agentCatalog.map((agent) =>
    `<option value="${esc(agent.name)}">${esc(agent.label)}</option>`
  ).join("");
}

function renderAgentCheckboxes(container) {
  container.innerHTML = agentCatalog.map((agent) => `
    <label class="checkbox-label agent-checkbox-item">
      <input type="checkbox" value="${esc(agent.name)}" checked>
      <span>${esc(agent.label)}</span>
    </label>
  `).join("");
}

function getCheckedAgents(container) {
  return Array.from(container.querySelectorAll("input[type=checkbox]:checked"))
    .map((cb) => cb.value);
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
  renderAgentToggleButtons();
  renderAgentSelect($("#challenge-agent"));
  renderAgentSelect($("#bulk-agent"));
  renderAgentCheckboxes($("#parallel-agent-checkboxes"));
  renderAgentCheckboxes($("#bulk-parallel-checkboxes"));
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
  if (res.status === 401) { showView("login"); csrfToken = null; return null; }
  return res;
}

// === Login ===
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: $("#login-password").value }),
  });
  if (res.ok) {
    const data = await res.json();
    csrfToken = data.csrf_token;
    if (await loadAgentCatalog()) {
      loadDefaultAgent();
      checkAgentAuth();
      await handleDeepLink();
    }
  } else {
    const data = await res.json().catch(() => ({}));
    $("#login-error").textContent = data.error || "Invalid password";
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
  applyTheme(currentTheme);
  updateAgentToggleUI();
  const defaultFlagInput = $("#default-flag-format");
  if (defaultFlagInput) defaultFlagInput.value = defaultFlagFormat;
}

function applyTheme(theme) {
  document.body.classList.toggle("light", theme === "light");
  const btn = $("#btn-theme-toggle");
  if (btn) btn.textContent = theme === "light" ? "Dark" : "Light";
}

function updateAgentToggleUI() {
  document.querySelectorAll(".agent-toggle-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.agent === defaultAgent);
  });
}

const defaultFlagInput = $("#default-flag-format");
if (defaultFlagInput) {
  defaultFlagInput.addEventListener("change", async () => {
    defaultFlagFormat = defaultFlagInput.value.trim();
    await api("/api/settings", {
      method: "PUT",
      body: JSON.stringify({ default_flag_format: defaultFlagFormat }),
    });
  });
}

const themeToggleBtn = $("#btn-theme-toggle");
if (themeToggleBtn) {
  themeToggleBtn.addEventListener("click", async () => {
    currentTheme = currentTheme === "dark" ? "light" : "dark";
    applyTheme(currentTheme);
    await api("/api/settings", {
      method: "PUT",
      body: JSON.stringify({ theme: currentTheme }),
    });
  });
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
  list.innerHTML = challenges.map((c) => {
    const mode = c.mode || "single";
    const runs = c.runs || [];
    const runCount = runs.length;
    const isPending = c.status === "pending";
    const isShelved = c.status === "shelved";
    const steerCount = c.manager && c.manager.steer_count ? c.manager.steer_count : 0;
    const steerBadge = steerCount ? `<span class="card-steers">${steerCount} steer${steerCount !== 1 ? "s" : ""}</span>` : "";

    // Mode badge
    const modeLabel = mode.replace(/_/g, " ");
    const modeBadge = `<span class="badge badge-mode">${esc(modeLabel)}</span>`;

    // Agent / model display
    let agentDisplay = "";
    if (isParallelMode(mode)) {
      agentDisplay = `<span class="card-agent">${runCount} run${runCount !== 1 ? "s" : ""}</span>`;
    } else if (runs.length > 0) {
      const run = runs[0];
      const agentMeta = getAgentMeta(run.agent);
      if (agentMeta.badge_mode === "label") {
        agentDisplay = `<span class="card-agent card-agent-${run.agent}">${esc(agentMeta.label)}</span>`;
      } else {
        agentDisplay = `<span class="card-agent">${esc(run.model || agentMeta.default_model)}</span>`;
      }
    }

    // Total duration across all runs
    const totalDuration = runs.reduce((sum, r) => sum + (r.duration_ms || 0), 0);

    return `
    <div class="challenge-card status-${c.status}" data-id="${c.id}">
      <span class="badge badge-${c.status}">${c.status}</span>
      <span class="card-name">${esc(c.name)}</span>
      <span class="card-desc">${esc(c.description || "")}</span>
      ${modeBadge}
      ${agentDisplay}
      <span class="card-files">${c.files.length} file${c.files.length !== 1 ? "s" : ""}</span>
      <span class="card-duration">${formatDuration(totalDuration)}</span>
      ${steerBadge}
      ${isPending ? `<button class="btn-card-start" data-id="${c.id}">&#9654; Start</button>` : ""}
      ${isShelved ? `<button class="btn-card-start" data-id="${c.id}">&#9654; Un-shelve</button>` : ""}
      <button class="btn-card-delete" data-id="${c.id}" title="Delete">&times;</button>
    </div>`;
  }).join("");

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
      const ch = challenges.find((x) => x.id === cid);
      const endpoint = ch && ch.status === "shelved"
        ? `/api/challenges/${cid}/unshelve`
        : `/api/challenges/${cid}/solve`;
      const res = await api(endpoint, { method: "POST" });
      if (res && res.ok) loadChallenges();
    })
  );
}

// Auto-refresh dashboard every 5s
setInterval(() => {
  if (!views.dashboard.classList.contains("hidden")) loadChallenges();
}, 5000);

// === Mode Selector Logic (New Challenge) ===
function updateModeOptions() {
  const mode = $("#challenge-mode").value;
  const singleGroup = $("#single-agent-group");
  const parallelGroup = $("#parallel-agent-group");

  if (isParallelMode(mode)) {
    singleGroup.classList.add("hidden");
    parallelGroup.classList.remove("hidden");
  } else {
    singleGroup.classList.remove("hidden");
    parallelGroup.classList.add("hidden");
    updateModelOptions();
  }
}

function updateModelOptions() {
  const agent = $("#challenge-agent").value;
  const modelGroup = $("#model-group");
  const effortGroup = $("#effort-group");
  const sel = $("#challenge-model");
  const effortSel = $("#challenge-effort");

  modelGroup.classList.remove("hidden");
  const meta = getAgentMeta(agent);
  sel.disabled = false;
  sel.innerHTML = (meta.models || []).map((m) =>
    `<option value="${m.value}">${esc(m.label)}</option>`
  ).join("");
  sel.value = meta.default_model;

  const effortLevels = meta.effort_levels || [];
  if (!effortLevels.length) {
    effortGroup.classList.add("hidden");
    effortSel.disabled = true;
    effortSel.innerHTML = '<option value="">Provider default</option>';
  } else {
    effortGroup.classList.remove("hidden");
    effortSel.disabled = false;
    effortSel.innerHTML = effortLevels.map((e) =>
      `<option value="${e.value}">${esc(e.label)}</option>`
    ).join("");
    effortSel.value = meta.default_effort || "";
  }
}

$("#challenge-mode").addEventListener("change", () => {
  updateModeOptions();
});

$("#challenge-agent").addEventListener("change", () => {
  updateModelOptions();
  const agent = $("#challenge-agent").value;
  $("#challenge-autonomous").checked = getAgentAutonomousDefault(agent);
});

// === New Challenge Modal ===
$("#btn-new-challenge").addEventListener("click", () => {
  $("#challenge-mode").value = "single";
  $("#challenge-agent").value = defaultAgent;
  updateModeOptions();
  updateModelOptions();
  $("#challenge-autonomous").checked = getAgentAutonomousDefault(defaultAgent);
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
  updateModeOptions();
  updateModelOptions();
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

// Initial mode/model setup
updateModeOptions();

// === Create Challenge Submit ===
$("#challenge-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const mode = $("#challenge-mode").value;
  const fd = new FormData();
  fd.append("name", $("#challenge-name").value);
  fd.append("description", $("#challenge-desc").value);
  fd.append("flag_format", $("#challenge-flag").value);
  fd.append("mode", mode);
  fd.append("autonomous", $("#challenge-autonomous").checked ? "true" : "false");

  if (isParallelMode(mode)) {
    const agents = getCheckedAgents($("#parallel-agent-checkboxes"));
    fd.append("agents", agents.join(","));
  } else {
    fd.append("agents", $("#challenge-agent").value);
    fd.append("model", $("#challenge-model").disabled ? "" : $("#challenge-model").value);
    fd.append("effort", $("#challenge-effort").disabled ? "" : $("#challenge-effort").value);
  }

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

function updateBulkModeOptions() {
  const mode = $("#bulk-mode").value;
  const singleGroup = $("#bulk-single-group");
  const parallelGroup = $("#bulk-parallel-group");

  if (isParallelMode(mode)) {
    singleGroup.classList.add("hidden");
    parallelGroup.classList.remove("hidden");
  } else {
    singleGroup.classList.remove("hidden");
    parallelGroup.classList.add("hidden");
    updateBulkModels();
  }
}

function updateBulkModels() {
  const agent = $("#bulk-agent").value;
  const modelGroup = $("#bulk-model-group");
  const effortGroup = $("#bulk-effort-group");
  const sel = $("#bulk-model");
  const effortSel = $("#bulk-effort");

  modelGroup.classList.remove("hidden");
  const meta = getAgentMeta(agent);
  sel.disabled = false;
  sel.innerHTML = (meta.models || []).map((m) =>
    `<option value="${m.value}">${esc(m.label)}</option>`
  ).join("");
  sel.value = meta.default_model;

  const effortLevels = meta.effort_levels || [];
  if (!effortLevels.length) {
    effortGroup.classList.add("hidden");
    effortSel.disabled = true;
    effortSel.innerHTML = '<option value="">Provider default</option>';
  } else {
    effortGroup.classList.remove("hidden");
    effortSel.disabled = false;
    effortSel.innerHTML = effortLevels.map((e) =>
      `<option value="${e.value}">${esc(e.label)}</option>`
    ).join("");
    effortSel.value = meta.default_effort || "";
  }
}

$("#btn-bulk-upload").addEventListener("click", () => {
  resetBulkModal();
  $("#bulk-mode").value = "single";
  $("#bulk-agent").value = defaultAgent;
  updateBulkModeOptions();
  updateBulkModels();
  $("#bulk-autonomous").checked = getAgentAutonomousDefault(defaultAgent);
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

$("#bulk-mode").addEventListener("change", updateBulkModeOptions);
$("#bulk-agent").addEventListener("change", () => {
  updateBulkModels();
  const agent = $("#bulk-agent").value;
  $("#bulk-autonomous").checked = getAgentAutonomousDefault(agent);
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

  const mode = $("#bulk-mode").value;
  const rows = document.querySelectorAll(".bulk-ch-row");
  const challengeConfigs = Array.from(rows).map((row, i) => ({
    folder_name: bulkPreviewChallenges[i].folder_name,
    name: row.querySelector(".bulk-ch-name").value.trim(),
    description: row.querySelector(".bulk-ch-desc").value.trim(),
    flag_format: row.querySelector(".bulk-ch-flag").value.trim(),
    enabled: row.querySelector(".bulk-ch-enabled").checked,
  }));

  let agents, model, effort;
  if (isParallelMode(mode)) {
    agents = getCheckedAgents($("#bulk-parallel-checkboxes")).join(",");
    model = "";
    effort = "";
  } else {
    agents = $("#bulk-agent").value;
    model = $("#bulk-model").disabled ? "" : $("#bulk-model").value;
    effort = $("#bulk-effort").disabled ? "" : $("#bulk-effort").value;
  }

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
        agents: agents,
        model: model,
        effort: effort,
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
  toolCount = 0;
  stepCount = 0;
  pendingTools.clear();
  foundFlags.clear();
  runToolCounts.clear();
  runStepCounts.clear();
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
  totalCostUsd = 0;
  totalTokens = 0;
  lastThinkingEl = null;
  $("#detail-timer").textContent = "";
  $("#detail-cost").textContent = "";
  foundFlags.clear(); $("#flags-list").innerHTML = ""; $("#flags-section").classList.add("hidden");
  if (c.status === "solving") startTimer();
  else stopTimer();

  updateButtons(c.status);
  initRunTabs(currentRuns);
  $("#tool-log").innerHTML = "";
  $("#files-tree").innerHTML = "";
  updateCounters();
  showView("detail");
  switchTab("tab-info");
  connectAllRuns(id, currentRuns);
  loadFiles();
  loadManagerState();
  updateSteerRunSelect();
  updateFilesRunSelect();
}

function updateStatusBadge(status) {
  const b = $("#detail-status");
  b.textContent = status;
  b.className = `badge badge-${status}`;
}

function updateButtons(status) {
  $("#btn-retry").classList.toggle("hidden", status !== "failed");
  $("#btn-unsolve").classList.toggle("hidden", status !== "solved");
  $("#btn-unshelve").classList.toggle("hidden", status !== "shelved");
  $("#btn-stop").classList.toggle("hidden", status !== "solving");
}

function updateCounters() {
  $("#step-counter").textContent = stepCount ? `${stepCount} steps` : "";
  $("#tool-counter").textContent = toolCount;
}

// === Detail Buttons ===
$("#btn-back").addEventListener("click", () => {
  disconnectAllWS(); stopTimer(); currentChallengeId = null;
  history.replaceState(null, "", "#");
  showView("dashboard"); loadChallenges();
});

$("#btn-retry").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  initRunTabs([]);
  $("#tool-log").innerHTML = "";
  $("#error-banner").classList.add("hidden");
  foundFlags.clear(); $("#flags-list").innerHTML = ""; $("#flags-section").classList.add("hidden");
  toolCount = 0; stepCount = 0; totalCostUsd = 0; totalTokens = 0;
  lastThinkingEl = null;
  $("#detail-cost").textContent = "";
  pendingTools.clear(); runToolCounts.clear(); runStepCounts.clear(); updateCounters();
  const res = await api(`/api/challenges/${currentChallengeId}/solve`, { method: "POST" });
  if (res && res.ok) {
    updateStatusBadge("solving"); updateButtons("solving"); startTimer();
    // Re-open to pick up new runs from the server
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
  await api(`/api/challenges/${currentChallengeId}/stop`, { method: "POST" });
});

$("#btn-unshelve").addEventListener("click", async () => {
  if (!currentChallengeId) return;
  const res = await api(`/api/challenges/${currentChallengeId}/unshelve`, { method: "POST" });
  if (res && res.ok) {
    updateStatusBadge("solving"); updateButtons("solving"); startTimer();
    $("#error-banner").classList.add("hidden");
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

function connectRunWS(challengeId, runId, agentLabel) {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/ws/${challengeId}/${runId}`);
  ws.onopen = () => {
    setWsStatus("connected");
  };
  ws.onmessage = (e) => renderRunEvent(runId, JSON.parse(e.data));
  ws.onclose = () => {
    if (currentChallengeId === challengeId) {
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
    }
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
  if (runId === activeRunId) scrollBottom();
}

// === Run Tabs ===
function initRunTabs(runs) {
  currentRuns = runs;
  const tabBar = $("#run-tabs");
  const feedsEl = $("#run-feeds");

  // Clear existing feeds but keep the scroll button
  tabBar.innerHTML = "";
  const scrollBtn = feedsEl.querySelector("#btn-scroll-bottom");
  feedsEl.innerHTML = "";
  if (scrollBtn) feedsEl.appendChild(scrollBtn);

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

  for (const run of runs) {
    const agentMeta = getAgentMeta(run.agent);
    const label = agentMeta.label || run.agent;

    const btn = document.createElement("button");
    btn.className = `run-tab${run.id === activeRunId ? " active" : ""}`;
    btn.dataset.run = run.id;
    const dotClass = run.status === "solving" ? "dot-running"
      : run.status === "solved" ? "dot-solved"
      : run.status === "failed" ? "dot-error" : "dot-running";
    btn.innerHTML = `<span class="run-tab-dot ${dotClass}"></span>${esc(label)}`;
    btn.addEventListener("click", () => switchRunTab(run.id));
    tabBar.appendChild(btn);

    const feed = document.createElement("div");
    feed.id = `feed-${run.id}`;
    feed.className = `panel-body run-feed${run.id === activeRunId ? " active" : ""}`;
    feedsEl.insertBefore(feed, scrollBtn);
    setupFeedScroll(feed);
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
}

function updateRunTabDot(runId, status) {
  const btn = document.querySelector(`[data-run="${runId}"]`);
  if (!btn) return;
  const dot = btn.querySelector(".run-tab-dot");
  if (!dot) return;
  if (status === "solved") {
    dot.className = "run-tab-dot dot-solved";
  } else if (status === "failed" || status === "error") {
    dot.className = "run-tab-dot dot-error";
  } else if (status === "solving") {
    dot.className = "run-tab-dot dot-running";
  } else {
    dot.className = "run-tab-dot dot-done";
  }
}

// === Steer Run Select ===
function updateSteerRunSelect() {
  const sel = $("#steer-run-select");
  if (isParallelMode(currentChallengeMode) && currentRuns.length > 1) {
    sel.classList.remove("hidden");
    sel.innerHTML = '<option value="">All runs</option>' +
      currentRuns.map((r) => {
        const meta = getAgentMeta(r.agent);
        return `<option value="${esc(r.id)}">${esc(meta.label || r.agent)}</option>`;
      }).join("");
  } else {
    sel.classList.add("hidden");
    sel.innerHTML = "";
  }
}

// === Files Run Select ===
function updateFilesRunSelect() {
  const sel = $("#files-run-select");
  if (isParallelMode(currentChallengeMode) && currentRuns.length > 1) {
    sel.classList.remove("hidden");
    sel.innerHTML = '<option value="">All files</option>' +
      currentRuns.map((r) => {
        const meta = getAgentMeta(r.agent);
        return `<option value="${esc(r.id)}">${esc(meta.label || r.agent)}</option>`;
      }).join("");
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

const foundFlags = new Set();

function showFlagBanner(flag) {
  if (foundFlags.has(flag)) return;
  foundFlags.add(flag);

  const section = $("#flags-section");
  const list = $("#flags-list");
  section.classList.remove("hidden");

  const item = document.createElement("div");
  item.className = "flag-item";
  const span = document.createElement("span");
  span.className = "flag-text";
  span.textContent = flag;
  const btn = document.createElement("button");
  btn.className = "btn-copy-flag";
  btn.textContent = "Copy";
  btn.addEventListener("click", () => copyToClipboard(flag, btn));
  item.append(span, btn);
  list.appendChild(item);
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

function updateCost() {
  if (totalCostUsd > 0) {
    $("#detail-cost").textContent = `$${totalCostUsd.toFixed(4)}`;
  }
  if (totalTokens > 0) {
    const k = (totalTokens / 1000).toFixed(1);
    const costText = totalCostUsd > 0
      ? `$${totalCostUsd.toFixed(4)} / ${k}k tok`
      : `${k}k tok`;
    $("#detail-cost").textContent = costText;
  }
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

// === Run Event Rendering ===
function renderRunEvent(runId, event) {
  // Get or create the feed for this run
  let feed = document.getElementById(`feed-${runId}`);
  if (!feed) {
    // Might arrive before tabs are set up; use default feed
    feed = document.getElementById("feed-__default__");
  }
  if (!feed) return;

  // --- Status events: update run tab dot + challenge-level status ---
  if (event.type === "status") {
    updateRunTabDot(runId, event.status);
    updateStatusBadge(event.status);
    updateButtons(event.status);
    if (event.status === "solving") startTimer();
    if (event.status === "solved" || event.status === "failed" || event.status === "shelved") {
      stopTimer();
      if (event.status === "shelved") loadManagerState();
      // Toast if not viewing this challenge
      if (views.detail.classList.contains("hidden")) {
        const msgs = { solved: "Challenge solved!", failed: "Challenge failed", shelved: "Challenge shelved by manager" };
        const types = { solved: "success", failed: "error", shelved: "info" };
        showToast(msgs[event.status] || event.status, types[event.status] || "info");
      }
    }
    if (event.error) {
      $("#error-banner").textContent = event.error;
      $("#error-banner").classList.remove("hidden");
    }
    return;
  }

  // --- Subagent lifecycle (within a single run) ---
  if (event.type === "system" && event.subtype === "task_started") {
    appendMsg(feed, `Subagent started: ${event.description || "task"}`, "system-msg");
    scrollBottomIfActive(runId);
    return;
  }
  if (event.type === "system" && event.subtype === "task_notification") {
    appendMsg(feed, `Subagent ${event.status || "finished"}: ${event.description || "task"}`, "system-msg");
    scrollBottomIfActive(runId);
    return;
  }

  // --- Error ---
  if (event.type === "error") {
    appendMsg(feed, event.message, "error-msg");
    scrollBottomIfActive(runId); return;
  }

  // --- System messages ---
  if (event.type === "system") {
    if (event.subtype === "init") return;
    if (event.message) appendMsg(feed, event.message, "system-msg");
    scrollBottomIfActive(runId); return;
  }

  // --- User steer ---
  if (event.type === "user_steer") {
    const div = document.createElement("div");
    div.className = "user-steer-msg";
    div.innerHTML = `<div class="user-steer-label">You</div>`;
    const text = document.createElement("div");
    text.textContent = event.message;
    div.appendChild(text);
    feed.appendChild(div);
    scrollBottomIfActive(runId); return;
  }

  // --- Rate limit ---
  if (event.type === "rate_limit_event") {
    const info = event.rate_limit_info;
    if (info && info.utilization > 0.5) {
      appendMsg(feed, `Rate limit: ${Math.round(info.utilization * 100)}% used`, "rate-limit-msg");
      scrollBottomIfActive(runId);
    }
    return;
  }

  // --- Assistant message ---
  if (event.type === "assistant" && event.message) {
    renderAssistant(feed, event.message, runId);
    scrollBottomIfActive(runId); return;
  }

  // --- User (tool results) ---
  if (event.type === "user" && event.message) {
    renderToolResults(event, feed);
    scrollBottomIfActive(runId); return;
  }

  // --- Raw text ---
  if (event.type === "raw" && event.text) {
    appendMsg(feed, event.text, "raw-msg");
    const flag = checkForFlag(event.text);
    if (flag) showFlagBanner(flag);
    scrollBottomIfActive(runId); return;
  }

  // --- Result ---
  if (event.type === "result") {
    if (event.total_cost_usd) { totalCostUsd = event.total_cost_usd; updateCost(); }
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
function renderAssistant(feed, msg, runId) {
  if (!msg.content || !msg.content.length) return;

  // Track tokens
  if (msg.usage) {
    totalTokens += (msg.usage.input_tokens || 0) + (msg.usage.output_tokens || 0);
    updateCost();
  }

  const step = document.createElement("div");
  step.className = "step";
  let hasContent = false;

  for (const block of msg.content) {
    if (block.type === "thinking" && block.thinking) {
      // Collapse previous thinking block
      if (lastThinkingEl) lastThinkingEl.removeAttribute("open");

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
      summary.appendChild(label);
      summary.appendChild(preview);
      details.appendChild(summary);
      const body = document.createElement("div");
      body.className = "thinking-body";
      body.textContent = block.thinking;
      details.appendChild(body);
      step.appendChild(details);
      lastThinkingEl = details;
      hasContent = true;
    }
    else if (block.type === "text" && block.text) {
      const div = document.createElement("div");
      div.className = "step-text";
      div.innerHTML = renderMarkdown(block.text);
      // Add copy buttons to code blocks
      div.querySelectorAll(".md-codeblock").forEach((pre) => {
        pre.style.position = "relative";
        pre.appendChild(makeCopyBtn(() => pre.textContent));
      });
      step.appendChild(div);

      const flag = checkForFlag(block.text);
      if (flag) showFlagBanner(flag);

      hasContent = true;
    }
    else if (block.type === "tool_use") {
      const toolEl = buildToolUse(block);
      step.appendChild(toolEl);
      pendingTools.set(block.id, toolEl);
      addToolLogEntry(block);
      toolCount++;
      updateCounters();
      hasContent = true;
    }
  }

  if (hasContent) {
    // Add timestamp
    if (timerStart) {
      const elapsed = Math.floor((Date.now() - timerStart) / 1000);
      const ts = document.createElement("span");
      ts.className = "step-timestamp";
      const m = Math.floor(elapsed / 60);
      const s = elapsed % 60;
      ts.textContent = `${m}:${String(s).padStart(2, "0")}`;
      step.prepend(ts);
    }
    feed.appendChild(step);
    stepCount++;
    updateCounters();
  }
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
      addToolLogEntry(synthetic);
      toolCount++;
      updateCounters();
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

    updateToolLogStatus(block.tool_use_id, isError);
    pendingTools.delete(block.tool_use_id);
  }
}

// === Tool Log Sidebar ===
function addToolLogEntry(block) {
  const log = $("#tool-log");
  const item = document.createElement("div");
  item.className = "tool-log-item";
  item.id = `tlog-${block.id}`;

  const dot = document.createElement("span");
  dot.className = "tool-log-status dot-running";

  const nameEl = document.createElement("span");
  nameEl.className = "tool-log-name";
  nameEl.textContent = block.name;

  const descEl = document.createElement("span");
  descEl.className = "tool-log-desc";
  descEl.textContent = toolSummary(block.name, block.input);

  item.append(dot, nameEl, descEl);

  // Click to scroll to tool in main feed
  item.addEventListener("click", () => {
    const el = document.getElementById(`tool-${block.id}`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.querySelector(".tool-detail")?.classList.add("open");
      el.style.outline = "1px solid var(--accent)";
      setTimeout(() => el.style.outline = "", 1500);
    }
  });

  log.appendChild(item);
  log.scrollTop = log.scrollHeight;
}

function updateToolLogStatus(toolId, isError) {
  const item = document.getElementById(`tlog-${toolId}`);
  if (!item) return;
  const dot = item.querySelector(".tool-log-status");
  dot.className = `tool-log-status ${isError ? "dot-error" : "dot-done"}`;
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

function appendMsg(container, text, cls) {
  const div = document.createElement("div");
  div.className = cls;
  div.textContent = text;
  container.appendChild(div);
}

function esc(str) {
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
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
async function viewFile(path) {
  if (!currentChallengeId) return;
  let url = `/api/challenges/${currentChallengeId}/files/${path}`;
  const runSelect = $("#files-run-select");
  if (runSelect && runSelect.value) {
    url += `?run_id=${encodeURIComponent(runSelect.value)}`;
  }
  const res = await api(url);
  if (!res) return;
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

  // Set download link
  const dlBtn = $("#file-viewer-download");
  dlBtn.href = `/api/challenges/${currentChallengeId}/download/${path}`;
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
  // Sidebar tabs: 1-4
  if (e.key === "1") switchTab("tab-info");
  if (e.key === "2") switchTab("tab-tools");
  if (e.key === "3") switchTab("tab-files");
  if (e.key === "4") switchTab("tab-manager");

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
async function sendSteer() {
  const input = $("#steer-input");
  const msg = input.value.trim();
  if (!msg || !currentChallengeId) return;
  input.value = "";

  const body = { message: msg };
  // In parallel mode, include run_id if user selected a specific run
  const runSelect = $("#steer-run-select");
  if (runSelect && runSelect.value) {
    body.run_id = runSelect.value;
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
        .map((row) => kvRow(row.label, row.value))
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

function kvRow(key, value) {
  return `<span class="usage-kv"><span class="usage-k">${esc(String(key))}</span> ${esc(String(value))}</span>`;
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

// === VPN Modal ===
$("#btn-vpn").addEventListener("click", async () => {
  const res = await api("/api/vpn");
  if (!res) return;
  const data = await res.json();

  if (!data.installed) {
    $("#vpn-not-installed").classList.remove("hidden");
    $("#vpn-panel").classList.add("hidden");
  } else {
    $("#vpn-not-installed").classList.add("hidden");
    $("#vpn-panel").classList.remove("hidden");
    updateVpnStatus(data);
  }
  $("#vpn-overlay").classList.remove("hidden");
});

function updateVpnStatus(data) {
  const badge = $("#vpn-status-badge");
  const toggleBtn = $("#btn-vpn-toggle");
  if (data.up) {
    badge.textContent = "up";
    badge.className = "badge badge-solved";
    toggleBtn.textContent = "Stop";
  } else {
    badge.textContent = "down";
    badge.className = "badge badge-pending";
    toggleBtn.textContent = "Start";
  }

  const peerInfo = $("#vpn-peer-info");
  if (data.peer) {
    peerInfo.classList.remove("hidden");
    $("#vpn-peer-key").textContent = data.peer.public_key || "—";
    $("#vpn-peer-endpoint").textContent = data.peer.endpoint || "—";
    const rx = parseInt(data.peer.transfer_rx || 0);
    const tx = parseInt(data.peer.transfer_tx || 0);
    $("#vpn-peer-transfer").textContent = `${formatVpnBytes(rx)} rx / ${formatVpnBytes(tx)} tx`;
  } else {
    peerInfo.classList.add("hidden");
  }
}

function formatVpnBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

$("#vpn-close").addEventListener("click", () => {
  $("#vpn-overlay").classList.add("hidden");
});
$("#vpn-overlay").addEventListener("click", (e) => {
  if (e.target === $("#vpn-overlay")) $("#vpn-overlay").classList.add("hidden");
});

$("#btn-vpn-toggle").addEventListener("click", async () => {
  const badge = $("#vpn-status-badge");
  const action = badge.textContent === "up" ? "down" : "up";
  const res = await api("/api/vpn/toggle", {
    method: "POST",
    body: JSON.stringify({ action }),
  });
  if (res && res.ok) {
    const data = await res.json();
    const vpnRes = await api("/api/vpn");
    if (vpnRes) updateVpnStatus(await vpnRes.json());
    showToast(`VPN ${data.up ? "started" : "stopped"}`, "success");
  }
});

$("#btn-vpn-configure").addEventListener("click", async () => {
  const clientKey = $("#vpn-client-key").value.trim();
  const clientNetworks = $("#vpn-client-networks").value.trim();
  const dnsForward = $("#vpn-dns").checked;

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
  $("#vpn-client-config-text").textContent = data.client_config;
  $("#vpn-client-config").classList.remove("hidden");

  const vpnRes = await api("/api/vpn");
  if (vpnRes) updateVpnStatus(await vpnRes.json());
  showToast("VPN configured and started", "success");
});

$("#btn-vpn-copy-config").addEventListener("click", () => {
  const text = $("#vpn-client-config-text").textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = $("#btn-vpn-copy-config");
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy"; }, 1200);
  });
});

// === Manager Settings Modal ===
$("#btn-manager-settings").addEventListener("click", async () => {
  const res = await api("/api/settings");
  if (!res) return;
  const s = await res.json();
  $("#manager-interval").value = s.manager_interval || 10;
  $("#manager-min-time").value = s.manager_min_solve_time || 5;

  // Populate model dropdown from Claude provider's model list
  const claudeMeta = getAgentMeta("claude");
  const modelSel = $("#manager-model");
  modelSel.innerHTML = (claudeMeta.models || []).map((m) =>
    `<option value="${esc(m.value)}">${esc(m.label)}</option>`
  ).join("");
  modelSel.value = s.manager_model || "sonnet";

  // Render agent pool checkboxes
  const poolContainer = $("#manager-agent-pool");
  const currentPool = s.manager_agent_pool || [];
  poolContainer.innerHTML = agentCatalog.map((agent) => {
    const checked = currentPool.length === 0 || currentPool.includes(agent.name) ? "checked" : "";
    return `<label class="checkbox-label agent-checkbox-item">
      <input type="checkbox" value="${esc(agent.name)}" ${checked}>
      <span>${esc(agent.label)}</span>
    </label>`;
  }).join("");

  $("#manager-overlay").classList.remove("hidden");
});
$("#manager-close").addEventListener("click", () => {
  $("#manager-overlay").classList.add("hidden");
});
$("#manager-overlay").addEventListener("click", (e) => {
  if (e.target === $("#manager-overlay")) $("#manager-overlay").classList.add("hidden");
});
$("#btn-manager-save").addEventListener("click", async () => {
  const agentPool = Array.from($("#manager-agent-pool").querySelectorAll("input[type=checkbox]:checked"))
    .map((cb) => cb.value);
  const body = {
    manager_interval: parseInt($("#manager-interval").value) || 10,
    manager_min_solve_time: parseInt($("#manager-min-time").value) || 5,
    manager_model: $("#manager-model").value.trim() || "sonnet",
    manager_agent_pool: agentPool,
  };
  const res = await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
  if (res && res.ok) {
    showToast("Manager settings saved", "success");
    $("#manager-overlay").classList.add("hidden");
  }
});

// === Manager Sidebar Tab ===
async function loadManagerState() {
  if (!currentChallengeId) return;
  const res = await api(`/api/challenges/${currentChallengeId}/manager`);
  if (!res) return;
  const state = await res.json();
  renderManagerTab(state);
}

function renderManagerTab(state) {
  const steerCount = state.steer_count || 0;
  const shelveReason = state.shelve_reason || "";
  const history = state.review_history || [];

  $("#manager-steer-count").textContent = steerCount
    ? `Steered ${steerCount} time${steerCount !== 1 ? "s" : ""}`
    : "No manager interventions yet";
  const shelveEl = $("#manager-shelve-reason");
  if (shelveReason) {
    shelveEl.textContent = `Shelve reason: ${shelveReason}`;
    shelveEl.classList.remove("hidden");
  } else {
    shelveEl.textContent = "";
    shelveEl.classList.add("hidden");
  }

  const historyEl = $("#manager-history");
  if (!history.length) {
    historyEl.innerHTML = '<div class="text-muted">No reviews yet</div>';
    return;
  }
  historyEl.innerHTML = history.slice().reverse().map((entry) => {
    const verdictClass = entry.verdict === "STEER" ? "manager-verdict-steer"
      : entry.verdict === "SHELVE" ? "manager-verdict-shelve"
      : "manager-verdict-wait";
    const ts = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : "";
    return `
    <div class="manager-review-entry">
      <div class="manager-review-header">
        <span class="manager-verdict ${verdictClass}">${esc(entry.verdict)}</span>
        <span class="manager-review-time">${esc(ts)}</span>
      </div>
      <div class="manager-review-reasoning">${esc(entry.reasoning || "")}</div>
      ${entry.instructions ? `<div class="manager-review-instructions"><strong>Instructions:</strong> ${esc(entry.instructions)}</div>` : ""}
    </div>`;
  }).join("");
}

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
  const res = await fetch("/api/challenges");
  if (res.ok) {
    const csrfRes = await fetch("/api/csrf-token");
    if (csrfRes.ok) {
      const data = await csrfRes.json();
      csrfToken = data.csrf_token;
    }
    if (await loadAgentCatalog()) {
      loadDefaultAgent();
      checkAgentAuth();
      await handleDeepLink();
    }
  } else {
    showView("login");
  }
})();
