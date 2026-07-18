(() => {
  "use strict";

  const params = new URLSearchParams(location.search);
  const suppliedToken = params.get("token");
  if (suppliedToken) {
    sessionStorage.setItem("cros-token", suppliedToken);
    history.replaceState({}, "", location.pathname);
  }
  const token = sessionStorage.getItem("cros-token") || suppliedToken || "";

  function loadStoredArray(key) {
    try {
      const value = JSON.parse(localStorage.getItem(key) || "[]");
      return Array.isArray(value) ? value.filter(item => typeof item === "string") : [];
    } catch (_) {
      return [];
    }
  }

  function loadStoredPins() {
    try {
      const value = JSON.parse(localStorage.getItem("cros-pinboard") || "[]");
      return Array.isArray(value) ? value.filter(item => item && typeof item === "object").slice(0, 100) : [];
    } catch (_) {
      return [];
    }
  }

  const state = {
    tools: [],
    lessons: {},
    sources: [],
    filter: "all",
    query: "",
    commandIndex: 0,
    commandMatches: [],
    posture: [],
    lessonFilter: "all",
    lessonQuery: "",
    selectedLesson: "",
    completedLessons: new Set(loadStoredArray("cros-completed-lessons")),
    favoriteTools: new Set(loadStoredArray("cros-favorite-tools")),
    recentTools: loadStoredArray("cros-recent-tools").slice(0, 12),
    pins: loadStoredPins(),
    graph: { nodes: [], edges: [] },
    selectedNode: "",
    selectedEdge: "",
    imageResult: null,
    workspaceView: "research",
    workspaceHomeView: "research",
    identityToolId: "1",
    sessionId: "",
    sessionOffset: 0,
    sessionPoll: 0,
    sessionDone: true,
    sessionSocialResults: [],
    sessionSocialSignature: "",
    sessionEmailResults: [],
    sessionEmailSignature: "",
    sessionDisplaySignature: "",
    usernameProviders: {},
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  function escapeHtml(value) { const node = document.createElement("span"); node.textContent = String(value ?? ""); return node.innerHTML; }
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("X-Cros-Token", token);
    if (options.body) headers.set("Content-Type", "application/json");
    const response = await fetch(path, { ...options, headers });
    let payload = {};
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (!response.ok) throw new Error(payload.error || `Local request failed (${response.status})`);
    return payload;
  }

  const APPEARANCE_KEYS = ["cros-interface-preset", "cros-accent", "cros-custom-accent", "cros-background", "cros-star-color", "cros-particles", "cros-wings", "cros-compact", "cros-animations", "cros-glow", "cros-motion", "cros-particle-density", "cros-light-smoothing", "cros-star-brightness", "cros-shape", "cros-columns", "cros-screen-fit", "cros-rail-autoclose", "cros-operator-name", "cros-logo-style"];
  let appearanceSaveTimer = 0;
  function appearanceSnapshot() { return Object.fromEntries(APPEARANCE_KEYS.filter(key => localStorage.getItem(key) !== null).map(key => [key, localStorage.getItem(key)])); }
  function queueAppearanceSave() { clearTimeout(appearanceSaveTimer); appearanceSaveTimer = setTimeout(() => { api("/api/appearance", { method: "POST", body: JSON.stringify(appearanceSnapshot()) }).catch(() => {}); }, 180); }
  function saveAppearanceNow() {
    clearTimeout(appearanceSaveTimer);
    return api("/api/appearance", { method: "POST", body: JSON.stringify(appearanceSnapshot()), keepalive: true }).catch(() => {});
  }
  async function restoreAppearanceFromServer() { try { const saved = await api("/api/appearance"); Object.entries(saved || {}).forEach(([key, value]) => { if (APPEARANCE_KEYS.includes(key)) localStorage.setItem(key, String(value)); }); } catch (_) {} }
  async function restoreProviderKeys() {
    try {
      const saved = await api("/api/provider-keys");
      if (saved.osintdog) localStorage.setItem("cros-osintdog-key", saved.osintdog);
      if (saved.hibp) { localStorage.setItem("cros-hibp-key", saved.hibp); const input = $("#hibp-api-key"); if (input) input.value = saved.hibp; }
    } catch (_) {}
  }

  function toast(title, message, error = false) {
    const item = document.createElement("div");
    item.className = `toast${error ? " error" : ""}`;
    const strong = document.createElement("strong");
    const span = document.createElement("span");
    strong.textContent = title;
    span.textContent = message;
    item.append(strong, span);
    $("#toast-stack").append(item);
    setTimeout(() => item.remove(), 3800);
  }

  function applyOperatorName(value, save = true) {
    const name = String(value || "").trim().replace(/\s+/g, " ").slice(0, 40);
    if (!name) return false;
    if (save) { localStorage.setItem("cros-operator-name", name); saveAppearanceNow(); }
    $("#operator-name").value = name;
    $("#settings-operator-name").value = name;
    $("#brand-welcome").textContent = `WELCOME, ${name.toUpperCase()}`;
    $("#hero-welcome-copy").textContent = `${name}, this is your local Intelligence Center for public-source research, local analysis, and defensive Windows security. Nothing is uploaded unless a tool clearly tells you first.`;
    return true;
  }

  function restoreOperatorName() {
    const saved = localStorage.getItem("cros-operator-name") || "";
    if (saved) applyOperatorName(saved, false);
    else $("#welcome-layer").hidden = false;
  }

  async function installDesktopShortcut() {
    try {
      await api("/api/install-desktop", { method: "POST", body: "{}" });
      toast("Desktop shortcut added", "Cros is now available from your Windows desktop.");
    } catch (error) { toast("Could not add shortcut", error.message, true); }
  }

  function codeFor(tool) {
    const prefix = tool.category === "osint" ? "OS" : tool.category === "advanced" ? "AX" : "SH";
    return `${prefix}-${String(tool.id).padStart(2, "0")}`;
  }

  function accessLabel(access) {
    return ({ local: "LOCAL", network: "NETWORK", browser: "BROWSER", admin: "ADMIN", confirm: "CONFIRM" })[access] || access.toUpperCase();
  }

  function matches(tool, query = state.query, filter = state.filter) {
    const haystack = `${tool.name} ${tool.description} ${tool.section} ${tool.category} ${tool.access}`.toLowerCase();
    const queryOk = !query || query.toLowerCase().trim().split(/\s+/).every(word => haystack.includes(word));
    const filterOk = filter === "all"
      || tool.category === filter
      || tool.access === filter
      || (filter === "favorites" && state.favoriteTools.has(tool.key))
      || (filter === "recent" && state.recentTools.includes(tool.key));
    return queryOk && filterOk;
  }

  function renderTools() {
    const filtered = state.tools.filter(tool => matches(tool));
    if (state.filter === "recent") {
      filtered.sort((left, right) => state.recentTools.indexOf(left.key) - state.recentTools.indexOf(right.key));
    }
    $("#result-count").textContent = `${filtered.length} / ${state.tools.length} TOOLS`;
    const root = $("#tool-groups");
    root.replaceChildren();
    if (!filtered.length) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.innerHTML = "<strong>No matching tools</strong><span>Try a broader term or switch the category filter.</span>";
      root.append(empty);
      return;
    }

    const grouped = new Map();
    filtered.forEach(tool => {
      const key = `${tool.category}|${tool.section}`;
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key).push(tool);
    });

    const fragment = document.createDocumentFragment();
    grouped.forEach((tools, key) => {
      const [, sectionName] = key.split("|");
      const group = document.createElement("section");
      group.className = "tool-group";
      const head = document.createElement("div");
      head.className = "group-head";
      const heading = document.createElement("h3");
      const count = document.createElement("span");
      heading.textContent = sectionName;
      count.textContent = `${tools.length} WORKFLOW${tools.length === 1 ? "" : "S"}`;
      head.append(heading, count);
      const grid = document.createElement("div");
      grid.className = "tool-grid";
      tools.forEach(tool => grid.append(buildToolCard(tool)));
      group.append(head, grid);
      fragment.append(group);
    });
    root.append(fragment);
    bindPointerGlow();
  }

  let toolRenderFrame = 0;
  function scheduleToolRender() {
    cancelAnimationFrame(toolRenderFrame);
    toolRenderFrame = requestAnimationFrame(renderTools);
  }

  function workspacePayload() {
    return {
      pins: state.pins,
      favorite_tools: [...state.favoriteTools],
      recent_tools: state.recentTools,
      graph: state.graph,
    };
  }

  let workspaceSaveTimer = 0;
  function persistWorkspace() {
    localStorage.setItem("cros-favorite-tools", JSON.stringify([...state.favoriteTools]));
    localStorage.setItem("cros-recent-tools", JSON.stringify(state.recentTools));
    localStorage.setItem("cros-pinboard", JSON.stringify(state.pins));
    clearTimeout(workspaceSaveTimer);
    workspaceSaveTimer = setTimeout(() => {
      api("/api/workspace", { method: "POST", body: JSON.stringify(workspacePayload()) })
        .catch(error => toast("Workspace not saved", error.message, true));
    }, 120);
  }

  function saveWorkspaceNow() {
    clearTimeout(workspaceSaveTimer);
    localStorage.setItem("cros-favorite-tools", JSON.stringify([...state.favoriteTools]));
    localStorage.setItem("cros-recent-tools", JSON.stringify(state.recentTools));
    localStorage.setItem("cros-pinboard", JSON.stringify(state.pins));
    return api("/api/workspace", { method: "POST", body: JSON.stringify(workspacePayload()), keepalive: true }).catch(() => {});
  }

  async function loadWorkspace() {
    const localFavorites = [...state.favoriteTools];
    const localRecents = [...state.recentTools];
    const localPins = [...state.pins];
    const payload = await api("/api/workspace");
    const serverEmpty = !(payload.pins || []).length
      && !(payload.favorite_tools || []).length
      && !(payload.recent_tools || []).length
      && !(payload.graph?.nodes || []).length;
    const migrateLocal = serverEmpty && (localFavorites.length || localRecents.length || localPins.length);
    state.favoriteTools = new Set(migrateLocal ? localFavorites : (payload.favorite_tools || []));
    state.recentTools = (migrateLocal ? localRecents : (payload.recent_tools || [])).slice(0, 12);
    state.pins = (migrateLocal ? localPins : (payload.pins || [])).slice(0, 100);
    state.graph = {
      nodes: Array.isArray(payload.graph?.nodes) ? payload.graph.nodes : [],
      edges: Array.isArray(payload.graph?.edges) ? payload.graph.edges : [],
    };
    if (migrateLocal) persistWorkspace();
    renderPins();
    renderPinnedTools();
    renderGraph();
  }

  function saveToolPreferences() {
    persistWorkspace();
  }

  function toggleFavorite(tool) {
    const saved = state.favoriteTools.has(tool.key);
    if (saved) state.favoriteTools.delete(tool.key);
    else state.favoriteTools.add(tool.key);
    saveToolPreferences();
    renderTools();
    renderPinnedTools();
    toast(saved ? "Tool unpinned" : "Tool pinned", `${tool.name} ${saved ? "was removed from" : "is ready in"} your workspace.`);
  }

  function recordRecent(tool) {
    state.recentTools = [tool.key, ...state.recentTools.filter(key => key !== tool.key)].slice(0, 12);
    saveToolPreferences();
  }

  function buildToolCard(tool) {
    const article = document.createElement("article");
    article.className = "tool-card";
    article.dataset.key = tool.key;
    const top = document.createElement("div");
    top.className = "tool-card-top";
    const code = document.createElement("span");
    code.className = "tool-code";
    code.textContent = codeFor(tool);
    const access = document.createElement("span");
    access.className = `access-badge ${tool.access}`;
    access.textContent = accessLabel(tool.access);
    const save = document.createElement("button");
    const saved = state.favoriteTools.has(tool.key);
    save.className = `tool-save${saved ? " active" : ""}`;
    save.textContent = saved ? "PINNED" : "PIN";
    save.setAttribute("aria-pressed", String(saved));
    save.setAttribute("aria-label", `${saved ? "Remove" : "Add"} ${tool.name} ${saved ? "from" : "to"} pinned tools`);
    const meta = document.createElement("span");
    meta.className = "tool-card-meta";
    meta.append(access, save);
    top.append(code, meta);
    const title = document.createElement("h4");
    title.textContent = tool.name;
    const description = document.createElement("p");
    description.textContent = tool.description;
    const launch = document.createElement("button");
    launch.className = "tool-launch";
    launch.innerHTML = "LAUNCH TOOL <span>&rarr;</span>";
    const learn = document.createElement("button");
    learn.className = "tool-learn";
    learn.textContent = "LEARN";
    learn.setAttribute("aria-label", `Learn how to use ${tool.name}`);
    const actions = document.createElement("div");
    actions.className = "tool-card-actions";
    actions.append(launch, learn);
    article.append(top, title, description, actions);
    article.addEventListener("click", () => launchTool(tool));
    learn.addEventListener("click", event => { event.stopPropagation(); openLearning(tool.key, "tutorials"); });
    save.addEventListener("click", event => { event.stopPropagation(); toggleFavorite(tool); });
    return article;
  }

  async function launchTool(toolOrKey) {
    const tool = typeof toolOrKey === "string" ? state.tools.find(item => item.key === toolOrKey) : toolOrKey;
    if (!tool) return;
    if (tool.key === "osint:17") {
      recordRecent(tool); closeWorkspace(); setSettingsOpen(true); closeCommand();
      toast("Appearance opened", "Customize the Cros app directly in Settings.");
      return;
    }
    if (["osint:18", "advanced:20", "security:24"].includes(tool.key)) {
      recordRecent(tool); closeCommand(); openLearning(tool.key === "osint:18" ? "" : tool.key, "tutorials");
      return;
    }
    if (["osint:1", "osint:2"].includes(tool.key)) {
      recordRecent(tool);
      state.identityToolId = tool.id;
      openWorkspace("research");
      setTimeout(() => $("#name-search-query").focus(), 180);
      toast("Blackbird ready", tool.id === "2"
        ? "Enter a username to check focused variations against live public sources."
        : "Enter a username to run live public-source checks inside Cros.");
      closeCommand();
      return;
    }
    if (tool.key === "osint:15") {
      recordRecent(tool);
      openWorkspace("research");
      toast("Opened local image investigator", "Choose a photo for local analysis.");
      closeCommand();
      return;
    }
    if (tool.key === "security:10") {
      recordRecent(tool);
      closeCommand();
      startToolSession("security", "10", { title: "RAT & Malware File Scan" });
      return;
    }
    recordRecent(tool);
    closeCommand();
    startToolSession(tool.category, tool.id, { title: tool.name });
  }

  function setFilter(filter) {
    state.filter = filter;
    $$('[data-filter]').forEach(button => button.classList.toggle("active", button.dataset.filter === filter));
    renderTools();
  }

  async function loadCatalog() {
    const payload = await api("/api/catalog");
    state.tools = payload.tools || [];
    $("#tool-count-hero").textContent = payload.count || state.tools.length;
    const lessonEmptyCount = $("#lesson-empty-count");
    if (lessonEmptyCount) lessonEmptyCount.textContent = `${payload.count || state.tools.length} STEP-BY-STEP LESSONS`;
    renderTools();
    renderPinnedTools();
  }

  async function loadLearning() {
    const payload = await api("/api/learning");
    state.lessons = payload.lessons || {};
    state.sources = payload.sources || [];
    if (Array.isArray(payload.completed)) state.completedLessons = new Set(payload.completed);
    renderLessonList();
    renderSourceGrid();
    renderPathways();
    updateLearningProgress();
  }

  function savePins() {
    persistWorkspace();
    renderPins();
  }

  function pinKind(target) {
    if (!target) return "NOTE";
    if (/^https?:\/\//i.test(target)) return "LINK";
    if (/^mailto:/i.test(target)) return "EMAIL";
    return "LOCAL";
  }

  function renderPins() {
    const root = $("#pin-grid");
    root.replaceChildren();
    const pins = [...state.pins].sort((a, b) => Number(Boolean(b.priority)) - Number(Boolean(a.priority)) || Number(b.created || 0) - Number(a.created || 0));
    $("#pinboard-count").textContent = `${state.favoriteTools.size} TOOLS / ${pins.length} NOTES`;
    $("#pin-mini-label").textContent = `${state.favoriteTools.size} TOOLS`;
    if (!pins.length) {
      const empty = document.createElement("div");
      empty.className = "pin-empty";
      empty.innerHTML = "<strong>Nothing pinned yet</strong><span>Add a note, web link, file, or folder above.</span>";
      root.append(empty);
      return;
    }
    pins.forEach(pin => {
      const card = document.createElement("article");
      card.className = `pin-card${pin.priority ? " priority" : ""}`;
      card.dataset.pinId = pin.id;
      const top = document.createElement("div");
      top.className = "pin-card-top";
      const kind = document.createElement("span");
      kind.textContent = pinKind(pin.target);
      const priority = document.createElement("button");
      priority.type = "button";
      priority.dataset.pinAction = "priority";
      priority.title = pin.priority ? "Move out of the top group" : "Keep at the top";
      priority.textContent = pin.priority ? "★ TOP" : "☆ TOP";
      top.append(kind, priority);
      const title = document.createElement("h3");
      title.textContent = pin.title || pin.target || "Quick note";
      const target = document.createElement("p");
      target.className = "pin-target";
      target.textContent = pin.target || "NOTE ONLY";
      const note = document.createElement("p");
      note.className = "pin-note";
      note.textContent = pin.note || "No extra note";
      const actions = document.createElement("div");
      actions.className = "pin-actions";
      if (pin.target) {
        const open = document.createElement("button");
        open.type = "button"; open.dataset.pinAction = "open"; open.textContent = "OPEN";
        const copy = document.createElement("button");
        copy.type = "button"; copy.dataset.pinAction = "copy"; copy.textContent = "COPY";
        actions.append(open, copy);
      }
      const remove = document.createElement("button");
      remove.type = "button"; remove.dataset.pinAction = "remove"; remove.textContent = "REMOVE";
      actions.append(remove);
      card.append(top, title, target, note, actions);
      root.append(card);
    });
  }

  function renderPinnedTools() {
    const root = $("#pinned-tool-grid");
    if (!root) return;
    root.replaceChildren();
    const tools = [...state.favoriteTools].map(toolByKey).filter(Boolean);
    if (!tools.length) {
      const empty = document.createElement("div");
      empty.className = "pinned-tool-empty";
      empty.innerHTML = "<strong>No tools pinned yet</strong><span>Browse the index and select PIN on any tool.</span>";
      root.append(empty);
    }
    tools.forEach(tool => {
      const card = document.createElement("article");
      card.className = "pinned-tool-card";
      const code = document.createElement("span");
      code.textContent = codeFor(tool);
      const title = document.createElement("h3");
      title.textContent = tool.name;
      const copy = document.createElement("p");
      copy.textContent = tool.description;
      const actions = document.createElement("div");
      const launch = document.createElement("button");
      launch.type = "button"; launch.className = "primary-button"; launch.textContent = "LAUNCH";
      const learn = document.createElement("button");
      learn.type = "button"; learn.textContent = "LEARN";
      const remove = document.createElement("button");
      remove.type = "button"; remove.textContent = "UNPIN";
      launch.addEventListener("click", () => launchTool(tool));
      learn.addEventListener("click", () => openLearning(tool.key, "tutorials"));
      remove.addEventListener("click", () => toggleFavorite(tool));
      actions.append(launch, learn, remove);
      card.append(code, title, copy, actions);
      root.append(card);
    });
    renderPins();
  }

  function addPin(event) {
    event.preventDefault();
    const title = $("#pin-title").value.trim();
    const target = $("#pin-target").value.trim();
    const note = $("#pin-note").value.trim();
    if (!title && !target && !note) {
      toast("Pin is empty", "Add a label, link or file path, or a note.", true);
      return;
    }
    state.pins.push({ id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`, title, target, note, priority: false, created: Date.now() });
    $("#pin-form").reset();
    savePins();
    toast("Pinned", title || target || "Your note was added to the board.");
  }

  async function handlePinAction(event) {
    const button = event.target.closest("[data-pin-action]");
    const card = event.target.closest("[data-pin-id]");
    if (!button || !card) return;
    const pin = state.pins.find(item => item.id === card.dataset.pinId);
    if (!pin) return;
    if (button.dataset.pinAction === "priority") { pin.priority = !pin.priority; savePins(); }
    if (button.dataset.pinAction === "remove") { state.pins = state.pins.filter(item => item.id !== pin.id); savePins(); }
    if (button.dataset.pinAction === "copy") {
      try { await navigator.clipboard.writeText(pin.target); toast("Copied", "The pinned target is on your clipboard."); }
      catch (_) { toast("Copy blocked", "Select and copy the target manually.", true); }
    }
    if (button.dataset.pinAction === "open") {
      try { await api("/api/open-pinned", { method: "POST", body: JSON.stringify({ target: pin.target }) }); }
      catch (error) { toast("Could not open pin", error.message, true); }
    }
  }

  async function openResearchUrl(url) {
    try { await api("/api/open-url", { method: "POST", body: JSON.stringify({ url }) }); }
    catch (error) { toast("Could not open research page", error.message, true); }
  }

  function openLensWithSelectedImage() {
    const file = $("#image-file")?.files?.[0];
    if (!file) { toast("Choose an image first", "Select an image before opening Google Lens.", true); return; }
    const form = document.createElement("form");
    form.action = `https://lens.google.com/v3/upload?ep=ccm&s=&st=${Date.now()}`;
    form.method = "POST"; form.enctype = "multipart/form-data"; form.target = "_blank"; form.hidden = true;
    const input = document.createElement("input"); input.type = "file"; input.name = "encoded_image"; input.accept = "image/*";
    const transfer = new DataTransfer(); transfer.items.add(file); input.files = transfer.files;
    const dimensions = document.createElement("input"); dimensions.type = "hidden"; dimensions.name = "processed_image_dimensions"; dimensions.value = "1000,1000";
    form.append(input, dimensions); document.body.append(form); form.submit(); setTimeout(() => form.remove(), 1000);
    toast("Google Lens opened", "Your selected image was handed to Google Lens in a new tab.");
  }

  async function profileKey(passphrase, salt) { const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]); return crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations:150000, hash:"SHA-256" }, material, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]); }
  async function exportProfile() {
    const pass = $("#profile-passphrase").value; if (pass.length < 8) { toast("Passphrase too short", "Use at least 8 characters.", true); return; }
    const workspace = await api("/api/workspace"); const local = Object.fromEntries(Object.keys(localStorage).filter(k => k.startsWith("cros-")).map(k => [k, localStorage.getItem(k)]));
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12)), key = await profileKey(pass, salt); const data = new TextEncoder().encode(JSON.stringify({ version:1, workspace, local })); const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, data));
    const payload = { version:1, salt:Array.from(salt), iv:Array.from(iv), data:Array.from(encrypted) }; const blob = new Blob([JSON.stringify(payload)], { type:"application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "cros-encrypted-profile.json"; link.click(); URL.revokeObjectURL(link.href); toast("Profile exported", "Keep the backup and passphrase separate.");
  }
  async function importProfile(event) { const file = event.target.files[0], pass = $("#profile-passphrase").value; if (!file || pass.length < 8) { toast("Backup needs a passphrase", "Choose a backup and enter its passphrase.", true); return; } try { const payload = JSON.parse(await file.text()), key = await profileKey(pass, new Uint8Array(payload.salt)), plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv:new Uint8Array(payload.iv) }, key, new Uint8Array(payload.data)), value = JSON.parse(new TextDecoder().decode(plain)); await api("/api/workspace", { method:"POST", body:JSON.stringify(value.workspace || {}) }); Object.entries(value.local || {}).forEach(([k,v]) => localStorage.setItem(k, v)); toast("Profile imported", "Restart Cros to apply the restored profile."); } catch (_) { toast("Import failed", "The passphrase or backup file is invalid.", true); } event.target.value = ""; }

  function researchButton(item) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "research-link";
    button.innerHTML = `<span>${item.name}</span><b>OPEN ↗</b>`;
    button.addEventListener("click", () => item.name === "Google Lens" ? openLensWithSelectedImage() : openResearchUrl(item.url));
    return button;
  }

  function setWorkspaceView(view) {
    state.workspaceView = ["research", "map", "session"].includes(view) ? view : "research";
    $$('[data-workspace-tab]').forEach(button => {
      const active = button.dataset.workspaceTab === state.workspaceView;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
    });
    $$('[data-workspace-panel]').forEach(panel => { panel.hidden = panel.dataset.workspacePanel !== state.workspaceView; });
    if (state.workspaceView === "map") renderGraph();
  }

  function openWorkspace(view = state.workspaceHomeView) {
    const dock = $("#workspace-dock");
    dock.hidden = false;
    dock.setAttribute("aria-hidden", "false");
    document.body.classList.add("workspace-open");
    $("#workspace-restore").hidden = true;
    setWorkspaceView(view);
  }

  function closeWorkspace() {
    const dock = $("#workspace-dock");
    dock.hidden = true;
    dock.setAttribute("aria-hidden", "true");
    document.body.classList.remove("workspace-open");
    $("#workspace-settings").hidden = true;
    $("#workspace-customize").setAttribute("aria-expanded", "false");
    $("#workspace-restore").hidden = false;
  }

  function setWorkspaceWidth(value, persist = true) {
    const width = Math.max(300, Math.min(Math.min(900, innerWidth - 20), Number(value) || 570));
    document.documentElement.style.setProperty("--workspace-width", `${width}px`);
    $("#workspace-width-control").value = String(Math.round(width));
    $("#workspace-width-value").textContent = `${Math.round(width)}px`;
    if (persist) localStorage.setItem("cros-workspace-width", String(Math.round(width)));
  }

  function setWorkspaceTabSize(size, persist = true) {
    const value = ["compact", "normal", "large"].includes(size) ? size : "normal";
    $("#workspace-dock").dataset.tabSize = value;
    $$('[data-workspace-tab-size]').forEach(button => {
      const active = button.dataset.workspaceTabSize === value;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    if (persist) localStorage.setItem("cros-workspace-tab-size", value);
  }

  function setWorkspaceHomeView(view, persist = true) {
    state.workspaceHomeView = ["research", "map", "session"].includes(view) ? view : "research";
    $("#workspace-home-view").value = state.workspaceHomeView;
    if (persist) localStorage.setItem("cros-workspace-home-view", state.workspaceHomeView);
  }

  function toggleWorkspaceSettings() {
    const panel = $("#workspace-settings");
    panel.hidden = !panel.hidden;
    $("#workspace-customize").setAttribute("aria-expanded", String(!panel.hidden));
  }

  function setupWorkspaceDock() {
    const content = $("#workspace-dock-content");
    content.prepend($("#investigation-workbench"), $("#investigation-map"));
    setWorkspaceWidth(localStorage.getItem("cros-workspace-width") || 570, false);
    const savedHeight = Number(localStorage.getItem("cros-workspace-height"));
    if (savedHeight >= 360) $("#workspace-dock").style.height = `${Math.min(savedHeight, innerHeight - 16)}px`;
    setWorkspaceTabSize(localStorage.getItem("cros-workspace-tab-size") || "normal", false);
    setWorkspaceHomeView(localStorage.getItem("cros-workspace-home-view") || "research", false);
    setWorkspaceView(state.workspaceHomeView);
    try { const v = JSON.parse(localStorage.getItem("cros-map-view") || "null"); if (v && v.width) graphView = v; } catch (_) {}
    if (window.ResizeObserver) new ResizeObserver(() => {
      const dock = $("#workspace-dock");
      if (!dock.classList.contains("expanded") && dock.clientHeight >= 360) localStorage.setItem("cros-workspace-height", String(dock.clientHeight));
    }).observe($("#workspace-dock"));
    try { const p = JSON.parse(localStorage.getItem("cros-workspace-position") || "null"); if (p) setWorkspacePosition(Number(p.left), Number(p.top), false); } catch (_) {}
  }

  let workspaceResizing = false;
  let railResizing = false;
  let railAutoCloseTimer = 0;
  function toggleNavigation() { document.body.classList.toggle("rail-collapsed"); localStorage.setItem("cros-rail-collapsed", document.body.classList.contains("rail-collapsed") ? "1" : "0"); }
  function scheduleRailClose() { clearTimeout(railAutoCloseTimer); const delay = Number(localStorage.getItem("cros-rail-autoclose") ?? 3000); if (delay > 0 && innerWidth >= 1100) railAutoCloseTimer = setTimeout(() => { document.body.classList.add("rail-collapsed"); localStorage.setItem("cros-rail-collapsed", "1"); }, delay); }
  function handleRailResize(event) { if (!railResizing || innerWidth < 1100) return; const width = Math.max(240, Math.min(420, event.clientX - 12)); document.documentElement.style.setProperty("--rail-width", `${width}px`); localStorage.setItem("cros-rail-width", String(width)); }
  let workspaceDragging = false;
  let workspaceDragOffset = { x: 0, y: 0 };
  let workspaceFrame = 0;
  let workspacePending = null;
  function setWorkspacePosition(left, top, persist = true) {
    const dock = $("#workspace-dock"), width = dock.getBoundingClientRect().width || 570;
    dock.style.left = `${Math.max(8, Math.min(innerWidth - width - 8, left))}px`; dock.style.right = "auto";
    dock.style.top = `${Math.max(8, Math.min(innerHeight - 90, top))}px`; dock.style.bottom = "auto";
    if (persist) localStorage.setItem("cros-workspace-position", JSON.stringify({ left: parseInt(dock.style.left), top: parseInt(dock.style.top) }));
  }
  function handleWorkspaceDrag(event) {
    if (!workspaceDragging || innerWidth <= 880) return;
    workspacePending = { left: event.clientX - workspaceDragOffset.x, top: event.clientY - workspaceDragOffset.y };
    if (!workspaceFrame) workspaceFrame = requestAnimationFrame(() => { workspaceFrame = 0; if (workspacePending) { setWorkspacePosition(workspacePending.left, workspacePending.top); workspacePending = null; } });
  }
  function handleWorkspaceResize(event) {
    if (!workspaceResizing || innerWidth <= 880) return;
    setWorkspaceWidth(innerWidth - event.clientX);
  }
  function handleWorkspaceViewportChange() {
    const dock = $("#workspace-dock");
    if (!dock || dock.hidden) return;
    if (innerWidth <= 880) { dock.style.left = "4px"; dock.style.right = "4px"; dock.style.top = "4px"; dock.style.bottom = "4px"; dock.style.width = "auto"; dock.style.height = "auto"; return; }
    if (!dock.classList.contains("expanded")) {
      const rect = dock.getBoundingClientRect();
      const saved = JSON.parse(localStorage.getItem("cros-workspace-position") || "null");
      setWorkspacePosition(Number(saved?.left ?? rect.left), Number(saved?.top ?? rect.top), false);
      const height = Number(localStorage.getItem("cros-workspace-height"));
      if (height >= 360) dock.style.height = `${Math.min(height, innerHeight - 16)}px`;
    }
  }

  function resizeWorkspaceBy(delta) {
    if (innerWidth <= 880) return;
    const current = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--workspace-width")) || 570;
    setWorkspaceWidth(current + delta);
  }

  function toggleWorkspaceSize() {
    const dock = $("#workspace-dock");
    const expanded = !dock.classList.contains("expanded");
    if (expanded) {
      dock.classList.add("expanded");
    } else {
      dock.classList.remove("expanded");
      dock.style.right = "auto";
      dock.style.bottom = "auto";
      try { const p = JSON.parse(localStorage.getItem("cros-workspace-position") || "null"); if (p) setWorkspacePosition(Number(p.left), Number(p.top), false); } catch (_) {}
    }
    $("#workspace-size").textContent = expanded ? "▣" : "□";
    $("#workspace-size").setAttribute("aria-label", expanded ? "Restore workspace size" : "Maximize workspace");
  }

  function formatSessionTime(milliseconds) {
    return `${(Math.max(0, milliseconds) / 1000).toFixed(1)}s`;
  }

  function updateSessionProgress(payload = {}) {
    const progress = $("#session-progress");
    const done = Boolean(payload.done);
    const ready = Boolean(payload.ready);
    const failed = done && Number(payload.returncode || 0) !== 0;
    progress.classList.toggle("running", !done && !ready);
    progress.classList.toggle("complete", done && !failed && !ready);
    progress.classList.toggle("failed", failed);
    progress.classList.toggle("ready", ready);
    progress.setAttribute("aria-valuetext", ready ? "Ready for input" : !done ? "Running live" : failed ? "Finished with an error" : "Complete");
    $("#session-status").textContent = ready ? "READY" : payload.waiting_for_input ? "INPUT" : !done ? "LIVE" : failed ? "REVIEW" : "COMPLETE";
    $("#session-stage").textContent = payload.stage || (ready ? "Ready" : !done ? "Working" : "Complete");
    $("#session-time").textContent = formatSessionTime(payload.elapsed_ms || 0);
  }

  function graphPosition(index) {
    const angle = index * 2.399;
    const radius = index ? Math.min(205, 82 + index * 15) : 0;
    return {
      x: Math.round(500 + Math.cos(angle) * radius),
      y: Math.round(210 + Math.sin(angle) * Math.min(radius, 160)),
    };
  }

  function mappedSocialNode(account) {
    return state.graph.nodes.find(node => node.type === "account" && node.note?.includes(`Blackbird result: ${account.url}`));
  }

  function addSocialToMap(account) {
    if (!account?.url || !account?.platform || !account?.username) return;
    const username = String(account.username).replace(/^@/, "").slice(0, 64);
    const leadMarker = `Blackbird username lead: @${username}`;
    let lead = state.graph.nodes.find(node => node.note?.includes(leadMarker));
    if (!lead) {
      const position = graphPosition(state.graph.nodes.length);
      lead = {
        id: crypto.randomUUID ? crypto.randomUUID() : `node-${Date.now()}-${Math.random()}`,
        label: `@${username}`.slice(0, 80), type: "account", note: `${leadMarker}.`, ...position,
      };
      state.graph.nodes.push(lead);
    }

    let social = mappedSocialNode(account);
    if (!social) {
      const position = graphPosition(state.graph.nodes.length);
      social = {
        id: crypto.randomUUID ? crypto.randomUUID() : `node-${Date.now()}-${Math.random()}`,
        label: `${account.platform} · @${username}`.slice(0, 80), type: "account",
        note: `Blackbird result: ${String(account.url).slice(0, 240)}. Verify profile details before linking identities.`,
        ...position,
      };
      state.graph.nodes.push(social);
    }
    if (!state.graph.edges.some(edge => edge.source === lead.id && edge.target === social.id)) {
      state.graph.edges.push({
        id: crypto.randomUUID ? crypto.randomUUID() : `edge-${Date.now()}-${Math.random()}`,
        source: lead.id, target: social.id, label: "Blackbird result",
      });
    }
    persistWorkspace();
    renderGraph();
    renderSessionSocialResults();
    toast("Added to investigation map", `${account.platform} was connected to @${username}.`);
  }

  async function copyAccountLink(account, button) {
    if (!account?.url) return;
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(account.url);
      else { const field = document.createElement("textarea"); field.value = account.url; field.style.position = "fixed"; field.style.opacity = "0"; document.body.append(field); field.select(); document.execCommand("copy"); field.remove(); }
      const original = button.textContent; button.textContent = "COPIED"; button.disabled = true;
      setTimeout(() => { button.textContent = original; button.disabled = false; }, 1400);
      toast("Account link copied", "Paste the public profile URL wherever you need it.");
    } catch (_) { toast("Could not copy link", "Select the URL text and copy it manually.", true); }
  }

  async function openAccountResult(account) {
    if (!state.sessionId || !account?.url) return;
    try {
      await api("/api/session/result/open", { method: "POST", body: JSON.stringify({ session_id: state.sessionId, url: account.url }) });
    } catch (error) { toast("Could not open result", error.message, true); }
  }

  async function copyAllAccountResults() {
    const lines = state.sessionSocialResults.map(account => `${account.platform}\t${account.url}`).join("\n");
    if (!lines) return;
    try { await navigator.clipboard.writeText(lines); toast("Results copied", `${state.sessionSocialResults.length} public result${state.sessionSocialResults.length === 1 ? "" : "s"} copied.`); }
    catch (_) { toast("Could not copy results", "Copy individual result links instead.", true); }
  }

  function renderSessionSocialResults() {
    const section = $("#session-socials");
    const root = $("#session-social-list");
    section.hidden = !state.sessionSocialResults.length;
    root.replaceChildren();
    const filter = ($("#session-social-filter")?.value || "").trim().toLowerCase();
    const visible = state.sessionSocialResults.filter(account => !filter || `${account.platform} ${account.url}`.toLowerCase().includes(filter));
    $("#session-social-count").textContent = filter ? `${visible.length} / ${state.sessionSocialResults.length}` : `${state.sessionSocialResults.length} RESULT${state.sessionSocialResults.length === 1 ? "" : "S"}`;
    if (!visible.length && state.sessionSocialResults.length) {
      const empty = document.createElement("div"); empty.className = "session-result-empty"; empty.textContent = "No results match this filter."; root.append(empty); return;
    }
    visible.forEach(account => {
      const row = document.createElement("div"); row.className = "session-social-row";
      const copy = document.createElement("div");
      const name = document.createElement("strong"); name.textContent = account.platform;
      const url = document.createElement("span"); url.textContent = account.url;
      const meta = document.createElement("small"); meta.className = "session-result-confidence"; meta.textContent = "LIVE ENGINE HIT · VERIFY IDENTITY";
      copy.append(name, url, meta);
      const actions = document.createElement("div"); actions.className = "session-social-actions";
      const openButton = document.createElement("button"); openButton.type = "button"; openButton.textContent = "OPEN RESULT";
      openButton.addEventListener("click", () => openAccountResult(account));
      const copyButton = document.createElement("button"); copyButton.type = "button"; copyButton.className = "secondary"; copyButton.textContent = "COPY LINK";
      copyButton.addEventListener("click", () => copyAccountLink(account, copyButton));
      const button = document.createElement("button"); button.type = "button";
      const mapped = Boolean(mappedSocialNode(account));
      button.textContent = mapped ? "ADDED" : "ADD TO MAP";
      button.disabled = mapped;
      button.addEventListener("click", () => addSocialToMap(account));
      actions.append(openButton, copyButton, button); row.append(copy, actions); root.append(row);
    });
  }

  async function copyEmail(value, button) {
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value);
      else { const field = document.createElement("textarea"); field.value = value; field.style.position = "fixed"; field.style.opacity = "0"; document.body.append(field); field.select(); document.execCommand("copy"); field.remove(); }
      const original = button.textContent; button.textContent = "COPIED"; button.disabled = true;
      setTimeout(() => { button.textContent = original; button.disabled = false; }, 1400);
    } catch (_) { toast("Could not copy email", "Select the address and copy it manually.", true); }
  }

  function renderSessionEmailResults() {
    const section = $("#session-emails");
    const root = $("#session-email-list");
    section.hidden = !state.sessionEmailResults.length;
    root.replaceChildren();
    state.sessionEmailResults.forEach(value => {
      const row = document.createElement("div"); row.className = "session-social-row";
      const email = document.createElement("strong"); email.textContent = value;
      const button = document.createElement("button"); button.type = "button"; button.className = "secondary"; button.textContent = "COPY";
      button.addEventListener("click", () => copyEmail(value, button));
      row.append(email, button); root.append(row);
    });
  }

  function renderSessionAppResults(results = {}, payload = {}) {
    const section = $("#session-app-results");
    const root = $("#session-app-results-body");
    const socialUrls = new Set(state.sessionSocialResults.map(item => item.url));
    const links = (Array.isArray(results.links) ? results.links : []).filter(item => item?.url && !socialUrls.has(item.url));
    const facts = Array.isArray(results.facts) ? results.facts : [];
    const findings = Array.isArray(results.findings) ? results.findings : [];
    const failed = Boolean(payload.done && Number(payload.returncode || 0) !== 0);
    const completeEmpty = Boolean(payload.done && !failed && !links.length && !facts.length && !findings.length && !state.sessionSocialResults.length && !state.sessionEmailResults.length);
    if (state.sessionSocialResults.length || (!links.length && !facts.length && !findings.length && !failed && !completeEmpty)) {
      section.hidden = true;
      root.replaceChildren();
      return;
    }
    section.hidden = false;
    root.replaceChildren();
    const total = links.length + facts.length + findings.length;
    $("#session-app-results-title").textContent = `${$("#session-title").textContent || "Tool"} result`;
    $("#session-app-results-count").textContent = failed ? "NEEDS ATTENTION" : (total ? `${total} ITEM${total === 1 ? "" : "S"}` : "COMPLETE");

    if (failed || completeEmpty) {
      const status = document.createElement("div");
      status.className = `app-result-status ${failed ? "is-error" : "is-complete"}`;
      const mark = document.createElement("i"); mark.textContent = failed ? "!" : "✓";
      const copy = document.createElement("div");
      const heading = document.createElement("strong"); heading.textContent = failed ? "This tool could not finish" : "Task completed";
      const note = document.createElement("span"); note.textContent = failed ? (payload.stage || "Review the input and try again.") : "Cros finished the tool successfully. No additional result fields were returned.";
      copy.append(heading, note); status.append(mark, copy); root.append(status);
    }

    if (links.length) {
      const group = document.createElement("section"); group.className = "app-result-group";
      const title = document.createElement("h5"); title.textContent = links.length === 1 ? "RESEARCH DESTINATION" : "RESEARCH DESTINATIONS";
      const grid = document.createElement("div"); grid.className = "app-link-grid";
      links.forEach(item => {
        const card = document.createElement("article"); card.className = "app-link-card";
        const icon = document.createElement("i"); icon.textContent = "↗";
        const copy = document.createElement("div");
        const name = document.createElement("strong"); name.textContent = item.label || "Open web result";
        const host = document.createElement("span"); host.textContent = item.host || item.url;
        const url = document.createElement("small"); url.textContent = item.url;
        copy.append(name, host, url);
        const actions = document.createElement("div"); actions.className = "app-link-actions";
        const open = document.createElement("button"); open.type = "button"; open.textContent = "OPEN"; open.addEventListener("click", () => openAccountResult(item));
        const copyButton = document.createElement("button"); copyButton.type = "button"; copyButton.className = "secondary"; copyButton.textContent = "COPY"; copyButton.addEventListener("click", () => copyAccountLink(item, copyButton));
        actions.append(open, copyButton); card.append(icon, copy, actions); grid.append(card);
      });
      group.append(title, grid); root.append(group);
    }

    if (facts.length) {
      const group = document.createElement("section"); group.className = "app-result-group";
      const title = document.createElement("h5"); title.textContent = "RESULT DETAILS";
      const grid = document.createElement("dl"); grid.className = "app-fact-grid";
      facts.forEach(item => { const card = document.createElement("div"); const label = document.createElement("dt"); const value = document.createElement("dd"); label.textContent = item.label; value.textContent = item.value; card.append(label, value); grid.append(card); });
      group.append(title, grid); root.append(group);
    }

    if (findings.length) {
      const group = document.createElement("section"); group.className = "app-result-group";
      const title = document.createElement("h5"); title.textContent = "FINDINGS";
      const list = document.createElement("ul"); list.className = "app-findings";
      findings.forEach(value => { const item = document.createElement("li"); item.textContent = value; list.append(item); });
      group.append(title, list); root.append(group);
    }
  }

  async function pollToolSession() {
    if (!state.sessionId) return;
    const sessionId = state.sessionId;
    try {
      const payload = await api(`/api/session?id=${encodeURIComponent(sessionId)}&offset=${state.sessionOffset}`);
      if (sessionId !== state.sessionId) return;
      if (payload.output) {
        const output = $("#session-output");
        if (state.sessionOffset === 0) output.textContent = "";
        output.textContent += payload.output.replace(/\r(?!\n)/g, "\n");
        output.scrollTop = output.scrollHeight;
      }
      state.sessionOffset = Number(payload.next_offset || state.sessionOffset);
      state.sessionDone = Boolean(payload.done);
      if (Array.isArray(payload.social_results)) {
        const signature = JSON.stringify(payload.social_results);
        if (signature !== state.sessionSocialSignature) {
          state.sessionSocialSignature = signature;
          state.sessionSocialResults = payload.social_results;
          renderSessionSocialResults();
        }
      }
      if (Array.isArray(payload.email_results)) {
        const signature = JSON.stringify(payload.email_results);
        if (signature !== state.sessionEmailSignature) {
          state.sessionEmailSignature = signature;
          state.sessionEmailResults = payload.email_results;
          renderSessionEmailResults();
        }
      }
      if (payload.display_results && typeof payload.display_results === "object") {
        const signature = JSON.stringify([payload.display_results, payload.done, payload.returncode, payload.stage]);
        if (signature !== state.sessionDisplaySignature) {
          state.sessionDisplaySignature = signature;
          renderSessionAppResults(payload.display_results, payload);
        }
      }
      updateSessionProgress(payload);
      const inputForm = $("#session-input-form");
      inputForm.hidden = !payload.waiting_for_input || state.sessionDone;
      if (payload.waiting_for_input) {
        $("#session-input-label").textContent = payload.prompt || "TOOL NEEDS YOUR INPUT";
        $("#session-input").focus({ preventScroll: true });
      }
      if (!state.sessionDone) state.sessionPoll = setTimeout(pollToolSession, 350);
    } catch (error) {
      state.sessionDone = true;
      updateSessionProgress({ done: true, returncode: 1, stage: error.message });
      toast("Tool session stopped", error.message, true);
    }
  }

  async function stopActiveSession(showNotice = true) {
    clearTimeout(state.sessionPoll);
    if (!state.sessionId || state.sessionDone) return;
    try {
      await api("/api/session/stop", { method: "POST", body: JSON.stringify({ session_id: state.sessionId }) });
      if (showNotice) toast("Stopping tool", "The in-app session is closing safely.");
      setTimeout(pollToolSession, 120);
    } catch (error) {
      if (showNotice) toast("Could not stop tool", error.message, true);
    }
  }

  async function runNativeWifiAudit(panel) {
    updateSessionProgress({ done: false, stage: "Reading saved Wi-Fi security settings" });
    try {
      const result = await api("/api/wifi-audit", { method: "POST", body: "{}" });
      const profiles = Array.isArray(result.profiles) ? result.profiles : [];
      const reviewCount = profiles.filter(item => item.status === "review").length;
      panel.innerHTML = `<div class="native-tool-head"><span>WINDOWS SECURITY · VISUAL AUDIT</span><h4>Saved Wi-Fi protection</h4><p>Authentication and encryption only. Cros never requests or reveals saved passwords.</p></div><div class="wifi-audit"><div class="wifi-summary"><div><strong>${profiles.length} saved profile${profiles.length === 1 ? "" : "s"}</strong><span>${reviewCount ? `${reviewCount} open network${reviewCount === 1 ? "" : "s"} should be reviewed` : "No open saved networks detected"}</span></div><b>${reviewCount ? "REVIEW" : "PROTECTED"}</b></div>${profiles.length ? `<div class="wifi-table-wrap"><table class="wifi-table"><thead><tr><th>NETWORK</th><th>AUTHENTICATION</th><th>CIPHER</th><th>SECURITY KEY</th><th>ASSESSMENT</th></tr></thead><tbody>${profiles.map(item => `<tr><td>${escapeHtml(item.profile)}</td><td>${escapeHtml(item.authentication)}</td><td>${escapeHtml(item.cipher)}</td><td>${escapeHtml(item.security_key)}</td><td><span class="wifi-status ${escapeHtml(item.status)}">${escapeHtml(item.review)}</span></td></tr>`).join("")}</tbody></table></div>` : `<div class="lab-empty"><strong>No saved profiles found</strong><span>Windows did not return any saved Wi-Fi networks.</span></div>`}<p class="wifi-note">${escapeHtml(result.note || "Wi-Fi passwords are never requested or displayed.")}</p></div>`;
      updateSessionProgress({ done: true, returncode: 0, stage: reviewCount ? "Audit complete · review open networks" : "Audit complete" });
    } catch (error) {
      panel.innerHTML = `<div class="lab-empty"><strong>Wi-Fi audit unavailable</strong><span>${escapeHtml(error.message)}</span></div>`;
      updateSessionProgress({ done: true, returncode: 1, stage: "Wi-Fi audit unavailable" });
    }
  }

  function renderNativeLinkResults(root, { title = "Result", links = [], facts = [], note = "Prepared locally by Cros." } = {}) {
    root.hidden = false;
    root.replaceChildren();
    const section = document.createElement("section"); section.className = "session-app-results native-generated-card";
    const header = document.createElement("header");
    const headingCopy = document.createElement("div"); const kicker = document.createElement("span"); kicker.textContent = "APP RESULTS";
    const heading = document.createElement("h4"); heading.textContent = title; headingCopy.append(kicker, heading);
    const count = document.createElement("b"); const total = links.length + facts.length; count.textContent = `${total} ITEM${total === 1 ? "" : "S"}`;
    header.append(headingCopy, count);
    const body = document.createElement("div"); body.className = "session-app-results-body";
    if (links.length) {
      const group = document.createElement("section"); group.className = "app-result-group";
      const groupTitle = document.createElement("h5"); groupTitle.textContent = links.length === 1 ? "RESEARCH DESTINATION" : "CHOOSE A PROVIDER";
      const grid = document.createElement("div"); grid.className = "app-link-grid";
      links.forEach(item => {
        const card = document.createElement("article"); card.className = "app-link-card";
        const icon = document.createElement("i"); icon.textContent = "↗";
        const copy = document.createElement("div"); const name = document.createElement("strong"); name.textContent = item.label;
        const host = document.createElement("span"); host.textContent = item.host;
        const value = document.createElement("small"); value.textContent = item.description || item.url;
        copy.append(name, host, value);
        const actions = document.createElement("div"); actions.className = "app-link-actions";
        const open = document.createElement("button"); open.type = "button"; open.textContent = "OPEN"; open.addEventListener("click", () => openResearchUrl(item.url));
        const copyButton = document.createElement("button"); copyButton.type = "button"; copyButton.className = "secondary"; copyButton.textContent = "COPY"; copyButton.addEventListener("click", () => copyAccountLink(item, copyButton));
        actions.append(open, copyButton); card.append(icon, copy, actions); grid.append(card);
      });
      group.append(groupTitle, grid); body.append(group);
    }
    if (facts.length) {
      const group = document.createElement("section"); group.className = "app-result-group";
      const groupTitle = document.createElement("h5"); groupTitle.textContent = "RESULT DETAILS";
      const list = document.createElement("dl"); list.className = "app-fact-grid";
      facts.forEach(item => { const card = document.createElement("div"); const label = document.createElement("dt"); const value = document.createElement("dd"); label.textContent = item.label; value.textContent = item.value; card.append(label, value); list.append(card); });
      group.append(groupTitle, list); body.append(group);
    }
    const foot = document.createElement("small"); foot.textContent = note;
    section.append(header, body, foot); root.append(section);
    setTimeout(() => root.scrollIntoView({ behavior: "smooth", block: "start" }), 0);
  }

  function publicSearchLinks(query) {
    const encoded = encodeURIComponent(query);
    return [
      { label: "Search with Google", host: "google.com", url: `https://www.google.com/search?q=${encoded}`, description: "Broad public-web results" },
      { label: "Search with Bing", host: "bing.com", url: `https://www.bing.com/search?q=${encoded}`, description: "Independent web index" },
      { label: "Search with DuckDuckGo", host: "duckduckgo.com", url: `https://duckduckgo.com/?q=${encoded}`, description: "Privacy-focused search" },
    ];
  }

  async function runNativeDiagnostics(panel) {
    const root = panel.querySelector("#native-generated-results");
    try {
      const payload = await api("/api/diagnostics");
      const facts = (payload.checks || []).map(item => ({ label: item.label, value: item.value }));
      renderNativeLinkResults(root, { title: "Cros health check", facts, note: "All checks are read-only and stay on this computer." });
      const providers = document.createElement("div"); providers.className = "native-provider-status";
      (payload.providers || []).forEach(item => { const card = document.createElement("div"); card.className = item.available ? "is-ready" : "is-review"; const copy = document.createElement("div"); const name = document.createElement("strong"); name.textContent = item.name; const description = document.createElement("span"); description.textContent = item.description; const badge = document.createElement("b"); badge.textContent = item.available ? "READY" : "REVIEW"; copy.append(name, description); card.append(copy, badge); providers.append(card); });
      root.querySelector(".session-app-results-body").append(providers);
      updateSessionProgress({ done: true, returncode: 0, stage: "Diagnostics complete" });
    } catch (error) {
      renderNativeLinkResults(root, { title: "Diagnostics unavailable", facts: [{ label: "Problem", value: error.message }] });
      updateSessionProgress({ done: true, returncode: 1, stage: "Diagnostics unavailable" });
    }
  }

  function showNativeTool(category, id) {
    const panel = $("#native-tool-panel");
    panel.replaceChildren(); panel.hidden = true;
    if (category === "osint" && String(id) === "4") {
      panel.innerHTML = `<div class="native-tool-head"><span>BREACH INTELLIGENCE · METADATA ONLY</span><h4>Breach exposure check</h4><p>Check an email with Have I Been Pwned, or check a username against free public profile sources. Cros never displays passwords or stolen records.</p></div><form class="native-workflow-form" id="native-breach-form"><label class="native-field"><span>CHECK TYPE</span><select id="native-breach-mode"><option value="email">Email breach metadata · HIBP API</option><option value="username">Username · free public profiles</option></select></label><label class="native-field"><span id="native-breach-target-label">EMAIL ADDRESS</span><input id="native-breach-target" type="email" maxlength="320" placeholder="you@example.com" required></label><div class="native-inline-links"><a href="https://haveibeenpwned.com/API/Key" target="_blank" rel="noreferrer">GET HIBP API KEY</a><a href="https://haveibeenpwned.com/" target="_blank" rel="noreferrer">FREE MANUAL HIBP CHECK</a></div><button class="primary-button" type="submit">RUN CHECK <span>→</span></button></form><div class="native-generated-results" id="native-generated-results"></div>`;
      panel.hidden = false;
      panel.querySelector(".native-tool-head p").textContent = "Email uses XposedOrNot free metadata, Password uses HIBP's free k-anonymous check, and Username uses clearly labeled local demo data. No paid HIBP email lookup is used.";
      panel.querySelector('a[href*="/API/Key"]')?.remove();
      const mode = panel.querySelector("#native-breach-mode");
      const targetInput = panel.querySelector("#native-breach-target");
      const targetLabel = panel.querySelector("#native-breach-target-label");
      const tabs = document.createElement("div"); tabs.className = "breach-tabs"; [["email", "EMAIL"], ["password", "PASSWORD"], ["username", "USERNAME"]].forEach(([value, label]) => { const tab = document.createElement("button"); tab.type = "button"; tab.dataset.breachTab = value; tab.textContent = label; if (value === "email") tab.className = "active"; tab.addEventListener("click", () => { mode.value = value; mode.dispatchEvent(new Event("change")); tabs.querySelectorAll("button").forEach(item => item.classList.toggle("active", item === tab)); }); tabs.append(tab); }); mode.style.display = "none"; panel.querySelector("#native-breach-form").insertBefore(tabs, panel.querySelector("#native-breach-form").firstElementChild);
      const passwordOption = document.createElement("option"); passwordOption.value = "password"; passwordOption.textContent = "Password · HIBP k-anonymous check"; mode.append(passwordOption);
      const freeOption = mode.querySelector('option[value="email"]'); if (freeOption) freeOption.textContent = "Email breach metadata · XposedOrNot Free";
      const infoLinks = document.createElement("div"); infoLinks.className = "native-inline-links"; infoLinks.innerHTML = '<a href="https://xon-web-test.xposedornot.com/api_doc" target="_blank" rel="noreferrer">FREE EMAIL API INFO</a><a href="https://haveibeenpwned.com/API/V3#PwnedPasswordsV2" target="_blank" rel="noreferrer">FREE PASSWORD API INFO</a>'; panel.querySelector("#native-breach-form").append(infoLinks);
      mode.addEventListener("change", () => { const username = mode.value === "username"; const password = mode.value === "password"; targetInput.type = username ? "text" : password ? "password" : "email"; targetInput.placeholder = username ? "public handle" : password ? "Enter a password locally" : "you@example.com"; targetLabel.textContent = username ? "PUBLIC USERNAME" : password ? "PASSWORD · NEVER UPLOADED" : "EMAIL ADDRESS"; });
      panel.querySelector("#native-breach-form").addEventListener("submit", async event => {
        event.preventDefault();
        const target = targetInput.value.trim();
        const root = panel.querySelector("#native-generated-results"); root.replaceChildren();
        const status = document.createElement("div"); status.className = "blackbird-live-note"; status.textContent = mode.value === "username" ? "Checking free public username sources…" : mode.value === "email-hibp" ? "Checking Have I Been Pwned metadata…" : "Checking free XposedOrNot breach metadata…"; root.append(status);
        try {
          if (mode.value === "username") {
            const response = await api("/api/breach-check", { method: "POST", body: JSON.stringify({ target, mode: "username", demo: true }) });
            root.replaceChildren(); renderBreachDashboard(root, response, target); addDashboardChecklists(root, response.results || []); updateSessionProgress({ done: true, returncode: 0, stage: "Username demo check complete" });
          } else if (mode.value === "password") {
            const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(target)); const hex = [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, "0")).join("").toUpperCase(); const response = await api("/api/hibp-password-check", { method: "POST", body: JSON.stringify({ prefix: hex.slice(0, 5), suffix: hex.slice(5) }) }); root.replaceChildren(); const result = document.createElement("div"); result.className = `password-result ${response.found ? "is-exposed" : "is-clear"}`; result.innerHTML = `<strong>${response.found ? "PASSWORD FOUND IN HIBP DATA" : "PASSWORD NOT FOUND IN HIBP DATA"}</strong><span>${response.found ? `${Number(response.count).toLocaleString()} observed matches` : "No match returned by the free k-anonymous check"}. The password itself was never sent.</span>`; root.append(result); appendExposureChecklist(root, response.found ? ["Password"] : [], false); targetInput.value = ""; updateSessionProgress({ done: true, returncode: 0, stage: "Password privacy check complete" });
          } else await runBreachCheck(target, root, true, "xposedornot");
        }
        catch (error) { root.replaceChildren(); const warning = document.createElement("p"); warning.textContent = error.message; root.append(warning); updateSessionProgress({ done: true, returncode: 1, stage: "Breach check unavailable" }); }
      });
      setTimeout(() => panel.querySelector("#native-breach-target")?.focus(), 0);
      return true;
    }
    if (category === "osint" && String(id) === "4") {
      panel.innerHTML = `<div class="native-tool-head"><span>OFFICIAL SERVICE · PRIVACY-FIRST</span><h4>Breach notifications</h4><p>Use Have I Been Pwned's official notification page. Your email is entered on their website and is never collected by Cros.</p></div><div class="native-privacy-card"><i>✓</i><div><strong>No email entered in Cros</strong><span>The official service handles verification and notifications directly.</span></div></div><div class="native-generated-results" id="native-generated-results"></div>`;
      panel.hidden = false;
      renderNativeLinkResults(panel.querySelector("#native-generated-results"), { title: "Official breach notification service", links: [{ label: "Open Have I Been Pwned", host: "haveibeenpwned.com", url: "https://haveibeenpwned.com/NotifyMe", description: "Official email notification enrollment" }], note: "Cros does not collect, transmit, or store your email address." });
      setTimeout(() => updateSessionProgress({ done: true, returncode: 0, stage: "Official notification service ready" }), 0);
      return true;
    }
    if (category === "osint" && String(id) === "6") {
      panel.innerHTML = `<div class="native-tool-head"><span>WEB ARCHIVE · NATIVE WORKFLOW</span><h4>Website history</h4><p>Validate a public domain or URL, then open its capture timeline in the Internet Archive.</p></div><form class="native-workflow-form" id="native-history-form"><label class="native-field"><span>DOMAIN OR PUBLIC URL</span><input id="native-history-input" placeholder="example.com or https://example.com/page" required></label><button class="primary-button" type="submit">BUILD HISTORY VIEW <span>→</span></button></form><div class="native-generated-results" id="native-generated-results" hidden></div>`;
      panel.hidden = false;
      panel.querySelector("#native-history-form").addEventListener("submit", event => {
        event.preventDefault();
        try {
          const raw = panel.querySelector("#native-history-input").value.trim();
          const parsed = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : `https://${raw}`);
          if (!parsed.hostname || !["http:", "https:"].includes(parsed.protocol)) throw new Error();
          const target = /^[a-z]+:\/\//i.test(raw) ? parsed.href : `${parsed.hostname}${parsed.pathname === "/" ? "" : parsed.pathname}${parsed.search}`;
          const url = `https://web.archive.org/web/*/${target}`;
          renderNativeLinkResults(panel.querySelector("#native-generated-results"), { title: "Website history ready", links: [{ label: "Open capture timeline", host: "web.archive.org", url, description: `Archived versions of ${parsed.hostname}` }], facts: [{ label: "Target", value: target }, { label: "Source", value: "Internet Archive Wayback Machine" }], note: "The target is only sent to the Internet Archive if you choose Open." });
          updateSessionProgress({ done: true, returncode: 0, stage: "History research prepared" });
        } catch (_) { toast("Enter a valid public URL", "Use a domain such as example.com or a complete http/https URL.", true); }
      });
      return true;
    }
    if (category === "osint" && String(id) === "7") {
      panel.innerHTML = `<div class="native-tool-head"><span>QUERY STUDIO · NATIVE WORKFLOW</span><h4>Public search builder</h4><p>Create a focused query and choose which public search provider to use.</p></div><form class="native-workflow-form" id="native-search-builder"><label class="native-field"><span>DOMAIN, USERNAME, OR PHRASE</span><input id="native-search-target" placeholder="example.com, username, or exact phrase" required></label><label class="native-field"><span>SEARCH MODE</span><select id="native-search-mode"><option value="mentions">Exact mentions</option><option value="site">Search one site</option><option value="files">Public documents</option><option value="custom">Use as written</option></select></label><button class="primary-button" type="submit">BUILD SEARCH <span>→</span></button></form><div class="native-generated-results" id="native-generated-results" hidden></div>`;
      panel.hidden = false;
      panel.querySelector("#native-search-builder").addEventListener("submit", event => {
        event.preventDefault(); const target = panel.querySelector("#native-search-target").value.trim().slice(0, 300); const mode = panel.querySelector("#native-search-mode").value;
        if (!target) return;
        const query = ({ mentions: `"${target.replaceAll('"', "")}"`, site: `site:${target.replace(/^https?:\/\//, "").split("/")[0]}`, files: `site:${target.replace(/^https?:\/\//, "").split("/")[0]} (filetype:pdf OR filetype:docx OR filetype:xlsx)`, custom: target })[mode];
        renderNativeLinkResults(panel.querySelector("#native-generated-results"), { title: "Focused search ready", links: publicSearchLinks(query), facts: [{ label: "Query", value: query }, { label: "Mode", value: panel.querySelector("#native-search-mode").selectedOptions[0].textContent }], note: "Nothing is searched until you choose a provider." });
        updateSessionProgress({ done: true, returncode: 0, stage: "Search query prepared" });
      });
      return true;
    }
    if (category === "osint" && String(id) === "8") {
      panel.innerHTML = `<div class="native-tool-head"><span>PASTE RESEARCH · MULTI-SOURCE</span><h4>Find public paste references</h4><p>Build one transparent query across selected public paste and snippet sources.</p></div><form class="native-workflow-form" id="native-paste-form"><label class="native-field"><span>USERNAME, EMAIL, DOMAIN, OR PHRASE</span><input id="native-paste-term" placeholder="Public research term" required></label><fieldset class="native-source-picker"><legend>PUBLIC SOURCES</legend><label><input type="checkbox" value="pastebin.com" checked><span>Pastebin</span></label><label><input type="checkbox" value="rentry.co" checked><span>Rentry</span></label><label><input type="checkbox" value="gist.github.com" checked><span>GitHub Gist</span></label><label><input type="checkbox" value="hastebin.com"><span>Hastebin</span></label></fieldset><button class="primary-button" type="submit">PREPARE RESEARCH <span>→</span></button></form><div class="native-generated-results" id="native-generated-results" hidden></div>`;
      panel.hidden = false;
      panel.querySelector("#native-paste-form").addEventListener("submit", event => {
        event.preventDefault(); const term = panel.querySelector("#native-paste-term").value.trim().replaceAll('"', "").slice(0, 240); const sources = [...panel.querySelectorAll(".native-source-picker input:checked")].map(input => input.value);
        if (!term) return; if (!sources.length) { toast("Choose a public source", "Select at least one paste or snippet source.", true); return; }
        const query = `(${sources.map(source => `site:${source}`).join(" OR ")}) "${term}"`;
        renderNativeLinkResults(panel.querySelector("#native-generated-results"), { title: "Paste research plan", links: publicSearchLinks(query), facts: [{ label: "Research term", value: term }, { label: "Sources", value: sources.join(", ") }, { label: "Query", value: query }], note: "Search providers may return no results. A match is a lead and should be verified at the original public source." });
        updateSessionProgress({ done: true, returncode: 0, stage: "Paste research prepared" });
      });
      return true;
    }
    if (category === "advanced" && String(id) === "16") {
      panel.innerHTML = `<div class="native-tool-head"><span>MAP RESEARCH · NATIVE WORKFLOW</span><h4>Coordinate helper</h4><p>Validate latitude and longitude, then choose a map provider.</p></div><form class="native-workflow-form native-coordinate-form" id="native-coordinate-form"><label class="native-field"><span>LATITUDE</span><input id="native-latitude" inputmode="decimal" placeholder="34.0522" required></label><label class="native-field"><span>LONGITUDE</span><input id="native-longitude" inputmode="decimal" placeholder="-118.2437" required></label><button class="primary-button" type="submit">VALIDATE COORDINATES <span>→</span></button></form><div class="native-generated-results" id="native-generated-results" hidden></div>`;
      panel.hidden = false;
      panel.querySelector("#native-coordinate-form").addEventListener("submit", event => {
        event.preventDefault(); const lat = Number(panel.querySelector("#native-latitude").value); const lon = Number(panel.querySelector("#native-longitude").value);
        if (!Number.isFinite(lat) || !Number.isFinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180) { toast("Coordinates are invalid", "Latitude must be -90 to 90 and longitude -180 to 180.", true); return; }
        const value = `${lat},${lon}`;
        renderNativeLinkResults(panel.querySelector("#native-generated-results"), { title: "Coordinates validated", links: [{ label: "Open Google Maps", host: "google.com", url: `https://www.google.com/maps?q=${value}`, description: "Satellite and street map" }, { label: "Open OpenStreetMap", host: "openstreetmap.org", url: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`, description: "Community-maintained map" }], facts: [{ label: "Latitude", value: String(lat) }, { label: "Longitude", value: String(lon) }], note: "Opening a provider sends only these coordinates to that provider." });
        updateSessionProgress({ done: true, returncode: 0, stage: "Coordinates validated" });
      });
      return true;
    }
    if (category === "advanced" && String(id) === "18") {
      panel.innerHTML = `<div class="native-tool-head"><span>ENGINE PACK · READ-ONLY STATUS</span><h4>Account engine health</h4><p>Cros includes its username engines. Review readiness here—no terminal installation workflow.</p></div><div class="native-generated-results" id="native-generated-results"></div>`;
      panel.hidden = false;
      api("/api/username-providers").then(payload => {
        const facts = (payload.providers || []).map(item => ({ label: item.name, value: item.available ? `Ready · ${item.description}` : `Needs repair · ${item.description}` }));
        renderNativeLinkResults(panel.querySelector("#native-generated-results"), { title: "Included engine pack", facts, note: "If an included engine needs repair, reinstall the Cros package instead of running terminal commands." });
        updateSessionProgress({ done: true, returncode: 0, stage: "Engine status ready" });
      }).catch(error => { renderNativeLinkResults(panel.querySelector("#native-generated-results"), { title: "Engine status unavailable", facts: [{ label: "Problem", value: error.message }] }); updateSessionProgress({ done: true, returncode: 1, stage: "Engine status unavailable" }); });
      return true;
    }
    if (category === "advanced" && String(id) === "19") {
      panel.innerHTML = `<div class="native-tool-head"><span>LOCAL APP · VISUAL HEALTH CHECK</span><h4>Cros diagnostics</h4><p>Checking the app runtime, local binding, data folder, and included username engines.</p></div><div class="native-generated-results" id="native-generated-results"></div>`;
      panel.hidden = false; setTimeout(() => runNativeDiagnostics(panel), 0); return true;
    }
    if (category === "security" && String(id) === "11") {
      panel.innerHTML = `<div class="native-tool-head"><span>HASH REPUTATION · LOCAL-FIRST</span><h4>Check a SHA-256 reputation</h4><p>Enter a SHA-256 or choose a file to hash locally in the app. Only the hash is sent if you open a provider.</p></div><form class="native-workflow-form" id="native-hash-reputation-form"><label class="native-field"><span>SHA-256 (OPTIONAL WHEN A FILE IS CHOSEN)</span><input id="native-reputation-hash" placeholder="64 hexadecimal characters" maxlength="64"></label><label class="native-file-choice"><span>OR HASH A FILE LOCALLY</span><input id="native-reputation-file" type="file"><b id="native-reputation-file-label">Choose file</b></label><button class="primary-button" type="submit">PREPARE REPUTATION CHECK <span>→</span></button></form><div class="native-generated-results" id="native-generated-results" hidden></div>`;
      panel.hidden = false;
      panel.querySelector("#native-reputation-file").addEventListener("change", event => { panel.querySelector("#native-reputation-file-label").textContent = event.target.files[0]?.name || "Choose file"; });
      panel.querySelector("#native-hash-reputation-form").addEventListener("submit", async event => {
        event.preventDefault(); let digest = panel.querySelector("#native-reputation-hash").value.trim().toLowerCase(); const file = panel.querySelector("#native-reputation-file").files[0];
        if (file) { if (file.size > 200 * 1024 * 1024) { toast("File is too large", "Choose a file under 200 MB for local browser hashing.", true); return; } updateSessionProgress({ done: false, stage: "Hashing file locally" }); const hash = await crypto.subtle.digest("SHA-256", await file.arrayBuffer()); digest = [...new Uint8Array(hash)].map(value => value.toString(16).padStart(2, "0")).join(""); }
        if (!/^[a-f0-9]{64}$/.test(digest)) { toast("Enter a valid SHA-256", "Use 64 hexadecimal characters or choose a file.", true); return; }
        renderNativeLinkResults(panel.querySelector("#native-generated-results"), { title: "Hash reputation providers", links: [{ label: "Check VirusTotal", host: "virustotal.com", url: `https://www.virustotal.com/gui/file/${digest}`, description: "Multi-engine reputation page" }, { label: "Check MalwareBazaar", host: "bazaar.abuse.ch", url: `https://bazaar.abuse.ch/browse.php?search=sha256%3A${digest}`, description: "Public malware sample index" }], facts: [{ label: "SHA-256", value: digest }, { label: "File handling", value: file ? "Hashed locally · file not uploaded" : "Hash entered manually" }], note: "Cros never uploads the file. Opening a provider sends only the SHA-256 in the URL." });
        updateSessionProgress({ done: true, returncode: 0, stage: "Reputation research prepared" });
      });
      return true;
    }
    if (category === "advanced" && String(id) === "12") {
      panel.innerHTML = `<div class="native-tool-head"><span>LOCAL TOOL · NO TERMINAL</span><h4>Base64 encoder / decoder</h4><p>Base64 is encoding, not encryption. Choose an action, enter text, and run it locally.</p></div><div class="choice-bubbles"><button type="button" class="active" data-native-mode="encode">ENCODE</button><button type="button" data-native-mode="decode">DECODE</button></div><label class="native-field"><span>INPUT</span><textarea id="native-base64-input" placeholder="Paste text or Base64 data"></textarea></label><button type="button" class="primary-button" id="native-base64-run">RUN LOCALLY <span>→</span></button><label class="native-field"><span>RESULT</span><textarea id="native-base64-output" readonly></textarea></label>`;
      panel.hidden = false; let mode = "encode";
      panel.querySelectorAll("[data-native-mode]").forEach(button => button.addEventListener("click", () => { mode = button.dataset.nativeMode; panel.querySelectorAll("[data-native-mode]").forEach(item => item.classList.toggle("active", item === button)); }));
      $("#native-base64-run").addEventListener("click", () => { try { const input = $("#native-base64-input").value; $("#native-base64-output").value = mode === "encode" ? btoa(unescape(encodeURIComponent(input))) : decodeURIComponent(escape(atob(input.replace(/\s+/g, "")))); updateSessionProgress({ done: true, returncode: 0, stage: "Encoding complete" }); } catch (_) { $("#native-base64-output").value = "Invalid Base64 input."; updateSessionProgress({ done: true, returncode: 1, stage: "Invalid Base64 input" }); } });
      return true;
    }
    if (category === "advanced" && String(id) === "4") {
      panel.innerHTML = `<div class="native-tool-head"><span>LOCAL TOOL · NO TERMINAL</span><h4>URL parser</h4><p>Break a URL into readable parts without opening it.</p></div><label class="native-field"><span>URL</span><input id="native-url-input" placeholder="https://example.com/path?query=value"></label><button type="button" class="primary-button" id="native-url-run">PARSE LOCALLY <span>→</span></button><pre class="native-output" id="native-url-output">Enter a URL to inspect its parts.</pre>`;
      panel.hidden = false; $("#native-url-run").addEventListener("click", () => { try { const url = new URL($("#native-url-input").value); $("#native-url-output").textContent = JSON.stringify({ scheme: url.protocol.replace(":", ""), host: url.hostname, port: url.port || "default", path: url.pathname, query: Object.fromEntries(url.searchParams.entries()), fragment: url.hash.slice(1) }, null, 2); updateSessionProgress({ done: true, returncode: 0, stage: "URL analysis complete" }); } catch (_) { $("#native-url-output").textContent = "Enter a valid URL."; updateSessionProgress({ done: true, returncode: 1, stage: "Enter a valid URL" }); } });
      return true;
    }
    if (category === "security" && String(id) === "33") {
      panel.innerHTML = `<div class="native-tool-head"><span>WINDOWS SECURITY · VISUAL AUDIT</span><h4>Saved Wi-Fi protection</h4><p>Reading authentication and encryption settings without accessing passwords.</p></div><div class="scan-progress-card"><div class="scan-orbit"><i></i></div><strong>Checking saved networks</strong><span>Windows is returning profile security details…</span><div class="scan-progress-track"><i></i></div></div>`;
      panel.hidden = false;
      setTimeout(() => runNativeWifiAudit(panel), 0);
      return true;
    }
    if (category === "security" && String(id) === "10") {
      panel.innerHTML = `<div class="native-tool-head"><span>SECURITY TOOL · NO TERMINAL</span><h4>RAT &amp; malware file scan</h4><p>Drop a file or JAR. Cros hashes it, inspects archive contents, and runs Microsoft Defender locally.</p></div><div class="native-file-scan file-scan-host"><form id="native-file-scan-form"><label class="file-drop" id="native-file-drop"><input id="native-file-scan-file" type="file"><strong>Drop a file here</strong><span id="native-file-scan-label">25 MB maximum · local only</span></label><button class="primary-button" type="submit">SCAN LOCALLY <span>→</span></button></form><div class="file-scan-results" id="native-file-scan-results"><div class="lab-empty"><strong>No file scanned</strong><span>Never execute an unknown sample.</span></div></div></div>`;
      panel.hidden = false;
      const host = panel.querySelector(".file-scan-host");
      const form = host.querySelector("#native-file-scan-form");
      const input = host.querySelector("#native-file-scan-file");
      const drop = host.querySelector("#native-file-drop");
      form.addEventListener("submit", scanDroppedFile);
      input.addEventListener("change", event => { const selected = event.target.files[0]; drop.classList.toggle("has-file", Boolean(selected)); if (selected) { drop.querySelector("strong").textContent = "FILE DROPPED"; host.querySelector("#native-file-scan-label").textContent = `${selected.name} · ${(selected.size / 1048576).toFixed(2)} MB`; } });
      drop.addEventListener("dragover", event => { event.preventDefault(); drop.classList.add("dragging"); });
      drop.addEventListener("dragleave", () => drop.classList.remove("dragging"));
      drop.addEventListener("drop", event => { event.preventDefault(); drop.classList.remove("dragging"); if (event.dataTransfer.files.length) { const transfer = new DataTransfer(); transfer.items.add(event.dataTransfer.files[0]); input.files = transfer.files; input.dispatchEvent(new Event("change")); } });
      return true;
    }
    return false;
  }

  async function startToolSession(category, id, options = {}) {
    await stopActiveSession(false);
    clearTimeout(state.sessionPoll);
    openWorkspace("session");
    $("#session-log").hidden = true;
    $("#session-log").open = false;
    $("#session-input-form").hidden = true;
    $("#session-advanced-toggle").textContent = "ENGINE DETAILS";
    $("#session-title").textContent = options.title || "Tool session";
    $("#session-output").textContent = "Starting inside Cros…";
    state.sessionId = "";
    state.sessionOffset = 0;
    state.sessionDone = false;
    state.sessionSocialResults = [];
    state.sessionSocialSignature = "";
    state.sessionEmailResults = [];
    state.sessionEmailSignature = "";
    state.sessionDisplaySignature = "";
    renderSessionSocialResults();
    renderSessionEmailResults();
    $("#session-app-results").hidden = true;
    $("#session-app-results-body").replaceChildren();
    updateSessionProgress({ done: false, stage: "Starting local tool", elapsed_ms: 0 });
    if (showNativeTool(category, id)) { updateSessionProgress({ ready: true, done: false, stage: "Ready for your input", elapsed_ms: 0 }); return; }
    try {
      const providerSession = category === "username-provider";
      const payload = await api(providerSession ? "/api/username-session/start" : "/api/session/start", {
        method: "POST",
        body: JSON.stringify(providerSession
          ? { provider: options.provider || id, username: options.username || "" }
          : { category, id, username: options.username || "" }),
      });
      state.sessionId = payload.id;
      if (category === "osint" && String(id) === "4") {
        await openResearchUrl("https://haveibeenpwned.com/NotifyMe");
      }
      pollToolSession();
    } catch (error) {
      state.sessionDone = true;
      $("#session-output").textContent = error.message;
      updateSessionProgress({ done: true, returncode: 1, stage: "Could not start" });
      renderSessionAppResults({}, { done: true, returncode: 1, stage: error.message });
      toast("Launch blocked", error.message, true);
    }
  }

  async function sendSessionInput(event) {
    event.preventDefault();
    const input = $("#session-input");
    if (!state.sessionId || state.sessionDone || !input.value) return;
    try {
      await api("/api/session/input", { method: "POST", body: JSON.stringify({ session_id: state.sessionId, input: input.value }) });
      input.value = "";
      $("#session-input-form").hidden = true;
      updateSessionProgress({ done: false, stage: "Continuing with your input" });
    } catch (error) {
      toast("Input was not sent", error.message, true);
    }
  }

  function renderBreachMetadata(root, payload, target) {
    const block = document.createElement("section"); block.className = "provider-result breach-result";
    const heading = document.createElement("h4"); heading.textContent = "BREACH CHECK · HIBP METADATA"; block.append(heading);
    const note = document.createElement("p"); note.textContent = payload.cached ? "Showing a locally cached result from the last 24 hours." : "Only breach metadata is shown. Passwords and stolen records are never returned."; block.append(note);
    if (payload.supported === false) { const unsupported = document.createElement("p"); unsupported.textContent = payload.message || "This input type is not supported by HIBP account checks."; block.append(unsupported); root.append(block); return; }
    const results = Array.isArray(payload.results || payload.breaches) ? (payload.results || payload.breaches) : [];
    if (!results.length) { const empty = document.createElement("strong"); empty.textContent = `No breaches found for ${target} in the connected database.`; block.append(empty); root.append(block); return; }
    results.forEach(item => {
      const row = document.createElement("article"); row.className = "breach-row";
      const title = document.createElement("strong"); title.textContent = item.service || item.Name || "Unnamed breach";
      const facts = document.createElement("span"); facts.textContent = `${item.breach_date || item.BreachDate || "Date unavailable"} · ${(item.data_types || item.DataClasses || []).join(", ") || "Categories unavailable"}`;
      row.append(title, facts);
      const link = document.createElement("a"); link.href = `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(item.service || item.Name || "")}`; link.target = "_blank"; link.rel = "noreferrer"; link.textContent = "VIEW DETAILS →"; row.append(link);
      block.append(row);
    });
    root.append(block);
  }

  function breachRisk(item) {
    const fields = (item.data_types || item.DataClasses || []).map(value => String(value).toLowerCase());
    let score = 0;
    if (fields.some(value => value.includes("password"))) score += 4;
    if (fields.some(value => value.includes("social") || value.includes("security") || value.includes("financial"))) score += 3;
    if (fields.some(value => value.includes("phone") || value.includes("address") || value.includes("location") || value.includes("ip"))) score += 2;
    if (Number(item.pwn_count || item.PwnCount || 0) > 1000000) score += 2;
    return score >= 7 ? ["CRITICAL", "critical"] : score >= 5 ? ["HIGH", "high"] : score >= 3 ? ["MEDIUM", "medium"] : ["LOW", "low"];
  }

  async function loadBreachDetails(card, item) {
    const name = item.service || item.Name || "";
    const button = card.querySelector(".breach-detail-button");
    if (button) { button.disabled = true; button.textContent = "LOADING METADATA…"; }
    try {
      const details = await api("/api/hibp-breach-details", { method: "POST", body: JSON.stringify({ name }) });
      const existing = card.querySelector(".breach-expanded"); if (existing) existing.remove();
      const expanded = document.createElement("div"); expanded.className = "breach-expanded";
      const description = document.createElement("p"); description.textContent = details.Description ? details.Description.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() : "No description supplied by the provider."; expanded.append(description);
      const detailStats = document.createElement("div"); detailStats.className = "breach-flags"; ["BreachDate", "AddedDate", "ModifiedDate", "PwnCount"].forEach(key => { const flag = document.createElement("span"); flag.textContent = `${key}: ${key === "PwnCount" ? Number(details[key] || 0).toLocaleString() : details[key] || "Unavailable"}`; detailStats.append(flag); }); expanded.append(detailStats);
      const fields = ["Email addresses", "Passwords", "Usernames", "IP addresses", "Names", "Phone numbers", "Physical addresses", "Geographic locations", "Dates of birth", "Social media profiles", "Security questions and answers", "Financial information", "Credit cards", "Government issued IDs", "Photos", "Other data"].map(value => [value, (details.DataClasses || []).some(item => String(item).toLowerCase() === value.toLowerCase())]);
      const fieldGrid = document.createElement("div"); fieldGrid.className = "breach-field-grid";
      const present = new Set((details.DataClasses || []).map(value => String(value).toLowerCase()));
      (details.DataClasses || []).forEach(value => { if (!fields.some(item => item[0].toLowerCase() === String(value).toLowerCase())) fields.push([String(value), true]); });
      fields.forEach(([label, found]) => { const chip = document.createElement("span"); chip.className = found ? "is-exposed" : "is-clear"; chip.textContent = `${found ? "✓" : "—"} ${label}`; fieldGrid.append(chip); });
      expanded.append(fieldGrid);
      const flags = document.createElement("div"); flags.className = "breach-flags"; ["IsVerified", "IsSensitive", "IsRetired", "IsSpamList", "IsMalware", "IsSubscriptionFree"].forEach(key => { const flag = document.createElement("span"); flag.textContent = `${key.replace(/^Is/, "")} · ${details[key] ? "YES" : "NO"}`; flags.append(flag); }); expanded.append(flags);
      card.append(expanded);
      if (button) { button.disabled = false; button.textContent = "HIDE FULL METADATA"; button.onclick = () => { expanded.remove(); button.textContent = "LOAD FULL METADATA"; button.onclick = () => loadBreachDetails(card, item); }; }
    } catch (error) { if (button) { button.disabled = false; button.textContent = "RETRY FULL METADATA"; } toast("Breach details unavailable", error.message, true); }
  }

  function renderBreachDashboard(root, payload, target) {
    const dashboard = document.createElement("section"); dashboard.className = "breach-dashboard";
    if (payload.demo) dashboard.dataset.demo = "true";
    const heading = document.createElement("div"); heading.className = "breach-dashboard-head"; const title = document.createElement("h4"); title.textContent = "BREACH AWARENESS DASHBOARD"; const note = document.createElement("p"); note.textContent = `${payload.cached ? "Cached for 24 hours · " : "Live provider result · "}Metadata only for ${target}. No credentials or stolen records are displayed.`; heading.append(title, note); dashboard.append(heading);
    if (payload.supported === false) { const unsupported = document.createElement("p"); unsupported.textContent = payload.message || "This input type is not supported."; dashboard.append(unsupported); root.append(dashboard); return; }
    const results = Array.isArray(payload.results || payload.breaches) ? (payload.results || payload.breaches) : [];
    const passwordRecords = results.filter(item => (item.data_types || item.DataClasses || []).some(value => String(value).toLowerCase().includes("password"))).reduce((sum, item) => sum + Number(item.pwn_count || item.PwnCount || 0), 0);
    const totalRecords = results.reduce((sum, item) => sum + Number(item.pwn_count || item.PwnCount || 0), 0);
    const riskScore = Math.min(100, results.reduce((sum, item) => sum + (breachRisk(item)[0] === "CRITICAL" ? 30 : breachRisk(item)[0] === "HIGH" ? 22 : breachRisk(item)[0] === "MEDIUM" ? 12 : 5), 0));
    const stats = document.createElement("div"); stats.className = "breach-summary-stats"; [["TOTAL BREACHES", results.length], ["AFFECTED RECORDS", totalRecords.toLocaleString()], ["PASSWORD-EXPOSED RECORDS", passwordRecords.toLocaleString()], ["RISK SCORE", `${riskScore}/100`]].forEach(([label, value]) => { const card = document.createElement("div"); card.className = "breach-stat"; const valueEl = document.createElement("strong"); valueEl.textContent = value; const labelEl = document.createElement("span"); labelEl.textContent = label; card.append(valueEl, labelEl); stats.append(card); }); dashboard.append(stats);
    if (!results.length) { appendExposureChecklist(dashboard, [], false); const empty = document.createElement("strong"); empty.textContent = `No breaches found for ${target} in the connected free database.`; dashboard.append(empty); root.append(dashboard); return; }
    const cards = document.createElement("div"); cards.className = "breach-card-grid";
    results.forEach(item => { const card = document.createElement("article"); card.className = "breach-card"; const [risk, riskClass] = breachRisk(item); const head = document.createElement("div"); head.className = "breach-card-head"; const name = document.createElement("h5"); name.textContent = item.service || item.Name || "Unnamed breach"; const badge = document.createElement("b"); badge.className = `risk-badge ${riskClass}`; badge.textContent = risk; head.append(name, badge); card.append(head); const meta = document.createElement("div"); meta.className = "breach-card-meta"; [["DATE", item.breach_date || item.BreachDate || "Unavailable"], ["AFFECTED", Number(item.pwn_count || item.PwnCount || 0).toLocaleString()], ["DOMAIN", item.domain || item.Domain || "Unavailable"]].forEach(([label, value]) => { const row = document.createElement("span"); row.innerHTML = `<small>${label}</small><strong></strong>`; row.querySelector("strong").textContent = value; meta.append(row); }); card.append(meta); const fields = document.createElement("div"); fields.className = "breach-field-preview"; (item.data_types || item.DataClasses || ["Metadata unavailable"]).forEach(value => { const chip = document.createElement("span"); chip.textContent = `✓ ${value}`; fields.append(chip); }); card.append(fields); const button = document.createElement("button"); button.className = "breach-detail-button"; button.type = "button"; button.textContent = "LOAD FULL METADATA"; button.addEventListener("click", () => loadBreachDetails(card, item)); card.append(button); cards.append(card); }); dashboard.append(cards); root.append(dashboard);
  }

  function appendDemoFields(parent, record) {
    if (!record?.email && !record?.password && !record?.username) return;
    const grid = document.createElement("div"); grid.className = "breach-demo-fields";
    [["EMAIL · DEMO", record.email], ["PASSWORD · DEMO", record.password], ["USERNAME · DEMO", record.username], ["IP · DEMO", record.ip], ["LOCATION · DEMO", record.location]].forEach(([label, value]) => {
      if (!value) return;
      const item = document.createElement("div"); const key = document.createElement("small"); key.textContent = label; const valueEl = document.createElement("strong"); valueEl.textContent = value; item.append(key, valueEl); grid.append(item);
    });
    parent.append(grid);
  }

  function addDashboardChecklists(root, results) {
    const cards = [...root.querySelectorAll(".breach-card")];
    cards.forEach((card, index) => {
      appendDemoFields(card, results[index]);
      if (!card.querySelector(".exposure-checklist")) appendExposureChecklist(card, results[index]?.data_types || results[index]?.DataClasses || [], false);
    });
  }

  async function runBreachCheck(target, root, progress = true, provider = "xposedornot") {
    if (progress) updateSessionProgress({ done: false, stage: provider === "hibp" ? "Checking HIBP breach metadata" : "Checking free XposedOrNot breach metadata" });
    const response = await api("/api/breach-check", { method: "POST", body: JSON.stringify({ target, provider: "xposedornot" }) });
    renderBreachDashboard(root, response, target);
    addDashboardChecklists(root, Array.isArray(response.results || response.breaches) ? (response.results || response.breaches) : []);
    if (progress) updateSessionProgress({ done: true, returncode: 0, stage: "Breach metadata check complete" });
    return response;
  }

  async function searchNames(event) {
    event.preventDefault();
    const query = $("#name-search-query").value.trim();
    if (!query) return;
    const provider = $("#name-provider-select").value || "blackbird";
    $("#name-search-loading").textContent = `STARTING ${provider.toUpperCase()}…`;
    $("#name-search-loading").hidden = false;
    try {
      const root = $("#name-results");
      const isEmailTarget = query.includes("@") && query.includes(".");
      root.replaceChildren();
      if (isEmailTarget) {
        const status = document.createElement("div"); status.className = "blackbird-live-note"; status.innerHTML = "<strong>BREACH CHECK</strong><span>Checking verified breach metadata alongside the public search.</span>"; root.append(status);
        try { await runBreachCheck(query, root, false); } catch (error) { const warning = document.createElement("p"); warning.textContent = `Breach check unavailable: ${error.message}`; root.append(warning); }
        return;
      }
      if (provider === "quick") {
        const response = await api("/api/free-public-search", { method: "POST", body: JSON.stringify({ username: query }) });
        renderPublicProviderResults(root, "CROS QUICK CHECK", response.results,
          "Fast public GitHub and GitLab results. A matching username is a lead, not proof of identity.");
        return;
      }
      const status = document.createElement("div");
      status.className = "blackbird-live-note";
      status.innerHTML = `<strong>${escapeHtml(provider.toUpperCase())} LIVE SESSION</strong><span>Verified public results will appear as profile cards in Tool Session.</span>`;
      root.append(status);
      if (provider === "blackbird") {
        const toolId = state.identityToolId === "2" ? "2" : "1";
        const label = toolId === "2" ? "Blackbird variations" : "Blackbird";
        await startToolSession("osint", toolId, { username: query, title: `${label} · ${query}`, hideOutput: true });
      } else {
        const info = state.usernameProviders[provider];
        if (!info?.available) throw new Error(`${info?.name || provider} is unavailable in this Cros engine pack. Reopen Cros or run the updater to repair it.`);
        await startToolSession("username-provider", provider, { provider, username: query,
          title: `${info.name} · ${query}`, hideOutput: true });
      }
    } catch (error) {
      toast("Username search unavailable", error.message, true);
    } finally {
      $("#name-search-loading").hidden = true;
    }
  }

  function appendExposureChecklist(parent, dataTypes = [], unavailable = false) {
    const known = ["Email", "Password", "Username", "IP address", "Location", "Phone", "Name", "Date of birth", "Address", "Financial", "Social profiles"];
    const normalized = dataTypes.map(value => String(value).toLowerCase());
    const checklist = document.createElement("div"); checklist.className = "exposure-checklist";
    known.forEach(label => { const exposed = normalized.some(value => value.includes(label.toLowerCase().replace(" ", " ")) || (label === "IP address" && value.includes("ip address")) || (label === "Password" && value.includes("password"))); const item = document.createElement("span"); item.className = exposed ? "is-exposed" : "is-clear"; item.textContent = unavailable ? `— ${label} · source not provided` : `${exposed ? "✓" : "—"} ${label}`; checklist.append(item); });
    parent.append(checklist);
    return checklist;
  }

  function renderPublicProviderResults(root, title, results, note = "") {
    const block = document.createElement("section"); block.className = "provider-result provider-visible";
    const heading = document.createElement("h4"); heading.textContent = title; block.append(heading);
    if (note) { const copy = document.createElement("p"); copy.textContent = note; block.append(copy); }
    const publicResults = Array.isArray(results) ? results : [];
    if (!publicResults.length) appendExposureChecklist(block, [], true);
    publicResults.forEach(item => {
      const row = document.createElement("div"); row.className = "public-provider-row";
      const info = document.createElement("div"); const name = document.createElement("strong"); name.textContent = item.source || "Public source"; const detail = document.createElement("span"); detail.textContent = item.found ? `@${item.username || "match"}` : "No public profile found"; info.append(name, detail); appendExposureChecklist(info, [], true); row.append(info);
      if (item.found && item.profile) { const link = document.createElement("a"); link.href = item.profile; link.target = "_blank"; link.rel = "noreferrer"; link.textContent = "OPEN PROFILE ↗"; row.append(link); }
      block.append(row);
    });
    root.append(block); root.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  async function searchNamesWithProviders(event) {
    event.preventDefault();
    const query = $("#name-search-query").value.trim();
    if (!query) return;
    const provider = localStorage.getItem("cros-name-provider") || "blackbird";
    const apiKey = localStorage.getItem("cros-osintdog-key") || "";
    const root = $("#name-results");
    $("#name-search-loading").hidden = false;
    try {
      root.replaceChildren();
      if ((provider === "osintdog" || provider === "both") && !apiKey) throw new Error("Add your OSINT Dog key in Settings first.");
      if (provider === "blackbird" || provider === "both") {
        const status = document.createElement("div"); status.className = "blackbird-live-note";
        status.innerHTML = "<strong>BLACKBIRD LIVE SESSION</strong><span>Results stream in the in-app workspace. Only accounts returned by the installed engine are shown.</span>";
        root.append(status);
        const toolId = state.identityToolId === "2" ? "2" : "1";
        const label = toolId === "2" ? "Blackbird variations" : "Blackbird";
        startToolSession("osint", toolId, { username: query, title: `${label} · ${query}` });
      }
      if (provider === "osintdog" || provider === "both") {
        const response = await api("/api/osintdog-search", { method: "POST", body: JSON.stringify({ username: query, api_key: apiKey }) });
        const block = document.createElement("section"); block.className = "provider-result";
        const heading = document.createElement("h4"); heading.textContent = "OSINT DOG API RESULT";
        const pre = document.createElement("pre"); pre.textContent = JSON.stringify(response.result || response, null, 2);
        block.append(heading, pre); root.append(block);
      }
      if (provider === "free") {
        const response = await api("/api/free-public-search", { method: "POST", body: JSON.stringify({ username: query }) });
        renderPublicProviderResults(root, "FREE PUBLIC API RESULTS", response.results, "Public GitHub and GitLab checks. Verify that a match belongs to the same person.");
        toast("Results ready", "Free public profiles were checked.");
      }
    } catch (error) {
      const tlsFailure = /CERTIFICATE_VERIFY_FAILED|SSLV3_ALERT_HANDSHAKE_FAILURE|certificate chain|local issuer/i.test(error.message || "");
      if ((provider === "osintdog" || provider === "both") && tlsFailure) {
        try {
          const fallback = await api("/api/free-public-search", { method: "POST", body: JSON.stringify({ username: query }) });
          root.replaceChildren();
          renderPublicProviderResults(root, "FREE FALLBACK RESULTS", fallback.results, "OSINT Dog could not establish a trusted HTTPS connection on this PC. Showing free public GitHub and GitLab checks instead.");
          toast("OSINT Dog unavailable", "Used free public checks instead.");
        } catch (fallbackError) { toast("Free fallback unavailable", fallbackError.message, true); }
      } else { toast("Name search unavailable", error.message, true); }
    }
    finally { $("#name-search-loading").hidden = true; }
  }

  function updateNameProviderCard(provider) {
    const values = {
      blackbird: { kicker: "01 / BLACKBIRD USERNAME SEARCH", description: "Run the installed Blackbird engine inside Cros. Results come from live public-site checks—not guessed profile links.", stats: ["600+", "public site checks", "LIVE", "verified responses"] },
      quick: { kicker: "01 / CROS QUICK CHECK", description: "Check public GitHub and GitLab profiles immediately without an API key or extra installation.", stats: ["2", "public services", "READY", "no install"] },
      sherlock: { kicker: "01 / SHERLOCK USERNAME SEARCH", description: "Run the included Sherlock engine locally for focused public-account checks across hundreds of networks.", stats: ["400+", "public networks", "BUNDLED", "ready in Cros"] },
      maigret: { kicker: "01 / MAIGRET USERNAME SEARCH", description: "Run the included Maigret engine locally for a broader, deeper public username search.", stats: ["500", "default checks", "BUNDLED", "ready in Cros"] },
    }[provider] || null;
    if (!values) return;
    $("#name-provider-kicker").textContent = values.kicker;
    $("#name-provider-description").textContent = values.description;
    const stats = $("#name-provider-stats");
    stats.replaceChildren();
    values.stats.forEach((value, index) => { const node = document.createElement(index % 2 ? "span" : "b"); node.textContent = value; stats.append(node); if (index === 1) { const divider = document.createElement("i"); stats.append(divider); } });
  }

  async function loadUsernameProviders() {
    const payload = await api("/api/username-providers");
    state.usernameProviders = Object.fromEntries((payload.providers || []).map(item => [item.id, item]));
    const select = $("#name-provider-select");
    $$('option', select).forEach(option => {
      const info = state.usernameProviders[option.value];
      if (!info) return;
      option.textContent = `${info.name} · ${info.available ? "ready" : "not installed"}`;
    });
    const saved = localStorage.getItem("cros-name-provider") || "blackbird";
    setNameProvider(state.usernameProviders[saved] ? saved : "blackbird", false);
    $$(".engine-option", $("#name-provider-picker")).forEach(button => {
      const info = state.usernameProviders[button.dataset.provider];
      const available = Boolean(info?.available);
      button.classList.toggle("is-unavailable", !available);
      button.querySelector("em").textContent = available ? "INCLUDED" : "REPAIR";
      button.title = available ? `${info.name} is included and ready` : `${info?.name || button.dataset.provider} needs repair`;
    });
  }

  function setNameProvider(provider, persist = true) {
    const selected = state.usernameProviders[provider] ? provider : "blackbird";
    $("#name-provider-select").value = selected;
    $$(".engine-option", $("#name-provider-picker")).forEach(button => {
      const active = button.dataset.provider === selected;
      button.setAttribute("aria-checked", String(active));
      button.tabIndex = active ? 0 : -1;
    });
    if (persist) localStorage.setItem("cros-name-provider", selected);
    updateNameProviderCard(selected);
  }

  function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || "").split(",")[1] || "");
      reader.onerror = () => reject(new Error("Windows could not read that image"));
      reader.readAsDataURL(file);
    });
  }

  function fact(label, value) {
    const item = document.createElement("div");
    const key = document.createElement("span"); key.textContent = label;
    const data = document.createElement("strong"); data.textContent = String(value);
    item.append(key, data); return item;
  }

  function renderImageResult() {
    const result = state.imageResult;
    if (!result) return;
    const mode = $("#image-scan-mode").value;
    const root = $("#image-results"); root.replaceChildren();
    const preview = document.createElement("div"); preview.className = "image-preview";
    const image = document.createElement("img"); image.src = result.thumbnail; image.alt = `Local preview of ${result.file_name}`;
    preview.append(image);
    if (mode !== "location") (result.face_boxes || []).forEach(box => {
      const marker = document.createElement("span"); marker.className = "face-box";
      marker.style.left = `${box.x * 100}%`; marker.style.top = `${box.y * 100}%`;
      marker.style.width = `${box.width * 100}%`; marker.style.height = `${box.height * 100}%`;
      preview.append(marker);
    });
    const summary = document.createElement("div"); summary.className = "image-summary";
    const facts = document.createElement("div"); facts.className = "image-facts";
    facts.append(fact("FORMAT", result.format), fact("DIMENSIONS", `${result.width} × ${result.height}`), fact("SIZE", `${(result.size_bytes / 1048576).toFixed(2)} MB`));
    if (mode !== "location") facts.append(fact("FACE REGIONS", result.face_engine === "unavailable" ? "Detector unavailable" : result.face_count));
    if (mode !== "face") facts.append(fact("GPS", result.gps ? `${result.gps.latitude}, ${result.gps.longitude}` : "Not embedded"), fact("SHA-256", result.sha256));
    summary.append(facts);
    if (mode !== "face") {
      const location = document.createElement("p"); location.className = "analysis-note"; location.textContent = result.location_note; summary.append(location);
      if (result.metadata?.length) {
        const metadata = document.createElement("div"); metadata.className = "metadata-list";
        result.metadata.forEach(item => metadata.append(fact(item.label.toUpperCase(), item.value)));
        summary.append(metadata);
      }
    }
    if (mode !== "location") { const faceNote = document.createElement("p"); faceNote.className = "analysis-note"; faceNote.textContent = result.face_note; summary.append(faceNote); }
    const ocr = document.createElement("div"); ocr.className = "ocr-result";
    const ocrTitle = document.createElement("h4"); ocrTitle.textContent = "VISIBLE TEXT (OCR)";
    const ocrBody = document.createElement("p"); ocrBody.textContent = result.ocr_text || "No local OCR engine was available or no readable text was found.";
    ocr.append(ocrTitle, ocrBody); summary.append(ocr);
    const reverse = document.createElement("div"); reverse.className = "reverse-searches";
    const reverseTitle = document.createElement("h4"); reverseTitle.textContent = "OPTIONAL REVERSE-IMAGE SEARCH";
    const reverseNote = document.createElement("p"); reverseNote.textContent = "These providers are third parties. Opening one does not upload this file automatically; choose the image there only if you accept that provider’s privacy terms.";
    const reverseLinks = document.createElement("div"); reverseLinks.className = "research-link-grid";
    [
      { name: "Google Lens", url: "https://lens.google.com/upload" },
      { name: "Bing Visual Search", url: "https://www.bing.com/visualsearch" },
      { name: "Yandex Images", url: "https://yandex.com/images/" },
    ].forEach(item => reverseLinks.append(researchButton(item)));
    reverse.append(reverseTitle, reverseNote, reverseLinks);
    root.append(preview, summary, reverse);
  }

  async function scanImage(event) {
    event.preventDefault();
    const file = $("#image-file").files[0];
    if (!file) return;
    if (file.size > 10_000_000) { toast("Image is too large", "Choose a file smaller than 10 MB.", true); return; }
    $("#image-scan-loading").hidden = false;
    try {
      const data = await readFileAsBase64(file);
      state.imageResult = await api("/api/image-analyze", { method: "POST", body: JSON.stringify({ name: file.name, data }) });
      renderImageResult();
    } catch (error) {
      toast("Image scan failed", error.message, true);
    } finally {
      $("#image-scan-loading").hidden = true;
    }
  }

  const SVG_NS = "http://www.w3.org/2000/svg";
  const GRAPH_BOUNDS = { width: 1000, height: 560 };
  let graphView = { x: 0, y: 0, width: GRAPH_BOUNDS.width, height: GRAPH_BOUNDS.height };
  function svgElement(name, attributes = {}) {
    const element = document.createElementNS(SVG_NS, name);
    Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
    return element;
  }

  function graphPoint(event) {
    const svg = $("#neural-map");
    const point = svg.createSVGPoint();
    point.x = event.clientX;
    point.y = event.clientY;
    return point.matrixTransform(svg.getScreenCTM().inverse());
  }

  function graphNodeBounds() {
    const margin = 48;
    return {
      minX: graphView.x + margin,
      maxX: graphView.x + graphView.width - margin,
      minY: graphView.y + margin,
      maxY: graphView.y + graphView.height - margin,
    };
  }

  function clampGraphPoint(point) {
    const bounds = graphNodeBounds();
    return {
      x: Math.max(bounds.minX, Math.min(bounds.maxX, Math.round(point.x))),
      y: Math.max(bounds.minY, Math.min(bounds.maxY, Math.round(point.y))),
    };
  }

  function updateNodeSelectors() {
    ["#edge-source", "#edge-target"].forEach(selector => {
      const select = $(selector);
      const current = select.value;
      select.replaceChildren(new Option("Choose node", ""));
      state.graph.nodes.forEach(node => select.add(new Option(node.label, node.id)));
      if (state.graph.nodes.some(node => node.id === current)) select.value = current;
    });
  }

  function selectGraphNode(id) {
    state.selectedNode = id;
    state.selectedEdge = "";
    const node = state.graph.nodes.find(item => item.id === id);
    const panel = $("#map-selection");
    panel.hidden = !node;
    if (node) {
      $("#selection-kicker").textContent = "SELECTED NODE";
      $("#selected-node-label").textContent = node.label;
      $("#selected-node-meta").textContent = node.type.toUpperCase();
      $("#selected-node-note").textContent = node.note || "No context added.";
    }
    $("#node-actions").hidden = !node;
    $("#edge-actions").hidden = true;
    $("#node-edit-form").hidden = true;
    $$(".neural-node", $("#neural-map")).forEach(item => item.classList.toggle("selected", item.dataset.nodeId === id));
    $$(".neural-edge", $("#neural-map")).forEach(item => item.classList.remove("selected"));
  }

  function selectGraphEdge(id) {
    const edge = state.graph.edges.find(item => item.id === id);
    const source = state.graph.nodes.find(item => item.id === edge?.source);
    const target = state.graph.nodes.find(item => item.id === edge?.target);
    if (!edge || !source || !target) return;
    state.selectedNode = "";
    state.selectedEdge = id;
    const panel = $("#map-selection");
    panel.hidden = false;
    $("#selection-kicker").textContent = "SELECTED RELATIONSHIP";
    $("#selected-node-label").textContent = edge.label || "Unlabeled connection";
    $("#selected-node-meta").textContent = `${source.label}  →  ${target.label}`;
    $("#selected-node-note").textContent = "Relationships stay local and can be removed without affecting either entity.";
    $("#node-actions").hidden = true;
    $("#edge-actions").hidden = false;
    $("#node-edit-form").hidden = true;
    $$(".neural-node", $("#neural-map")).forEach(item => item.classList.remove("selected"));
    $$(".neural-edge", $("#neural-map")).forEach(item => item.classList.toggle("selected", item.dataset.edgeId === id));
  }

  const REGION_ALIASES = new Map([["cali", "California"], ["calif", "California"], ["ca", "California"], ["california", "California"], ["ny", "New York"], ["tx", "Texas"], ["fl", "Florida"], ["usa", "United States"], ["us", "United States"], ["uk", "United Kingdom"], ["england", "United Kingdom"], ["au", "Australia"], ["mx", "Mexico"]]);
  function normalizeRegion(value) { const clean = value.trim().replace(/\s+/g, " "); if (!clean) return ""; return REGION_ALIASES.get(clean.toLowerCase()) || clean; }
  function setupRegionAssistant() {
    const input = $("#location-region"); if (!input) return;
    input.setAttribute("list", "location-region-options");
    const datalist = document.createElement("datalist"); datalist.id = "location-region-options";
    ["California", "United States", "Canada", "United Kingdom", "Australia", "Mexico", "New York", "Texas", "Florida", "Los Angeles, California", "San Francisco, California", "Toronto, Canada", "London, United Kingdom"].forEach(value => { const option = document.createElement("option"); option.value = value; datalist.append(option); });
    document.body.append(datalist);
    const hint = document.createElement("small"); hint.className = "field-hint"; hint.textContent = "Suggestions appear as you type. Shortcuts like Cali and CA are expanded."; input.parentElement.append(hint);
    input.addEventListener("blur", () => { input.value = normalizeRegion(input.value); });
  }
  function buildLocationHypotheses(event) { event.preventDefault(); const region = normalizeRegion($("#location-region").value); $("#location-region").value = region; const clues = $("#location-clues").value.trim(); if (!clues) return; const root = $("#location-results"); root.replaceChildren(); const title = document.createElement("strong"); title.textContent = "RESEARCH LEADS"; const note = document.createElement("p"); note.textContent = "Use these clues as hypotheses. Verify with maps, official venue pages, street-level context, and multiple independent sources."; const list = document.createElement("ul"); const items = [region ? `Start with public places in ${region} matching the visible clues.` : "Identify the broad region from language, road markings, architecture, and terrain.", "Search distinctive sign text in quotes and compare official pages or map listings.", "Cross-check candidate landmarks against building shape, road layout, weather, and image date."]; items.forEach(text => { const li = document.createElement("li"); li.textContent = text; list.append(li); }); root.append(title, note, list); }

  function editSelectedNode() {
    const node = state.graph.nodes.find(item => item.id === state.selectedNode);
    if (!node) return;
    $("#edit-node-label").value = node.label;
    $("#edit-node-note").value = node.note || "";
    $("#node-edit-form").hidden = false;
    $("#edit-node-label").focus();
  }

  function saveEditedNode(event) {
    event.preventDefault();
    const node = state.graph.nodes.find(item => item.id === state.selectedNode);
    const label = $("#edit-node-label").value.trim();
    if (!node || !label) return;
    node.label = label.slice(0, 80); node.note = $("#edit-node-note").value.trim().slice(0, 300);
    $("#node-edit-form").hidden = true; persistWorkspace(); renderGraph(); selectGraphNode(node.id);
  }

  function renderGraph() {
    const svg = $("#neural-map");
    if (!svg) return;
    svg.setAttribute("viewBox", `${graphView.x} ${graphView.y} ${graphView.width} ${graphView.height}`);
    svg.replaceChildren();
    const defs = svgElement("defs");
    const filter = svgElement("filter", { id: "node-glow", x: "-80%", y: "-80%", width: "260%", height: "260%" });
    filter.append(svgElement("feGaussianBlur", { stdDeviation: "5", result: "blur" }));
    const merge = svgElement("feMerge");
    merge.append(svgElement("feMergeNode", { in: "blur" }), svgElement("feMergeNode", { in: "SourceGraphic" }));
    filter.append(merge); defs.append(filter); svg.append(defs);
    const nodeMap = new Map(state.graph.nodes.map(node => [node.id, node]));
    state.graph.edges.forEach(edge => {
      const source = nodeMap.get(edge.source);
      const target = nodeMap.get(edge.target);
      if (!source || !target) return;
      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const curve = Math.min(90, Math.hypot(dx, dy) * .18);
      const middleX = (source.x + target.x) / 2 - (dy ? Math.sign(dy) : 1) * curve;
      const middleY = (source.y + target.y) / 2 + (dx ? Math.sign(dx) : 1) * curve;
      const path = svgElement("path", { d: `M ${source.x} ${source.y} Q ${middleX} ${middleY} ${target.x} ${target.y}`, class: `neural-edge${state.selectedEdge === edge.id ? " selected" : ""}`, tabindex: "0", role: "button", "aria-label": `${source.label} to ${target.label}${edge.label ? `: ${edge.label}` : ""}` });
      path.dataset.edgeId = edge.id;
      path.addEventListener("click", event => { event.stopPropagation(); selectGraphEdge(edge.id); });
      path.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectGraphEdge(edge.id); } });
      svg.append(path);
      if (edge.label) {
        const label = svgElement("text", { x: middleX, y: middleY - 8, class: "neural-edge-label", "text-anchor": "middle" });
        label.textContent = edge.label;
        svg.append(label);
      }
    });
    state.graph.nodes.forEach(node => {
      const point = clampGraphPoint({ x: Number(node.x) || 500, y: Number(node.y) || 280 });
      node.x = point.x;
      node.y = point.y;
      const group = svgElement("g", { class: `neural-node type-${node.type}${state.selectedNode === node.id ? " selected" : ""}`, transform: `translate(${node.x} ${node.y})`, tabindex: "0", role: "button", "aria-label": `${node.label}, ${node.type}` });
      group.dataset.nodeId = node.id;
      group.append(svgElement("circle", { r: "24" }), svgElement("circle", { r: "15", class: "node-core" }));
      const label = svgElement("text", { y: "39", "text-anchor": "middle" });
      label.textContent = node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label;
      const kind = svgElement("text", { y: "5", class: "node-kind", "text-anchor": "middle" });
      kind.textContent = node.type.slice(0, 3).toUpperCase();
      group.append(kind, label);
      group.addEventListener("click", () => selectGraphNode(node.id));
      group.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectGraphNode(node.id); }
      });
      group.addEventListener("pointerdown", event => {
        event.preventDefault();
        event.stopPropagation();
        draggingNode = node.id;
        selectGraphNode(node.id);
      });
      svg.append(group);
    });
    $("#map-empty").hidden = Boolean(state.graph.nodes.length);
    $("#map-count").textContent = `${state.graph.nodes.length} ${state.graph.nodes.length === 1 ? "NODE" : "NODES"}`;
    $("#map-zoom-readout").textContent = `${Math.round((GRAPH_BOUNDS.width / graphView.width) * 100)}%`;
    updateNodeSelectors();
    if (state.selectedNode && !nodeMap.has(state.selectedNode)) selectGraphNode("");
  }

  let draggingNode = "";
  let panningGraph = false;
  let panStart = null;
  function handleGraphPointerMove(event) {
    if (!draggingNode) return;
    const node = state.graph.nodes.find(item => item.id === draggingNode);
    if (!node) return;
    const point = graphPoint(event);
    const clamped = clampGraphPoint(point);
    node.x = clamped.x;
    node.y = clamped.y;
    renderGraph();
  }

  function finishGraphDrag() {
    if (!draggingNode) return;
    draggingNode = "";
    persistWorkspace();
  }

  function handleGraphPanStart(event) {
    if (event.target !== event.currentTarget) return;
    event.preventDefault();
    panningGraph = true;
    panStart = { x: event.clientX, y: event.clientY, viewX: graphView.x, viewY: graphView.y };
    event.currentTarget.setPointerCapture?.(event.pointerId);
  }

  function handleGraphPanMove(event) {
    if (!panningGraph || !panStart) return;
    const svg = $("#neural-map");
    const rect = svg.getBoundingClientRect();
    graphView.x = panStart.viewX - (event.clientX - panStart.x) * graphView.width / rect.width;
    graphView.y = panStart.viewY - (event.clientY - panStart.y) * graphView.height / rect.height;
    renderGraph();
  }

  function finishGraphPan() {
    if (!panningGraph) return;
    panningGraph = false;
    panStart = null;
    localStorage.setItem("cros-map-view", JSON.stringify(graphView));
  }

  function zoomGraph(event) {
    event.preventDefault();
    const factor = event.deltaY > 0 ? 1.12 : 0.89;
    const point = graphPoint(event);
    const width = Math.max(420, Math.min(1400, graphView.width * factor));
    const height = Math.max(280, Math.min(1100, graphView.height * factor));
    graphView = { x: point.x - (point.x - graphView.x) * (width / graphView.width), y: point.y - (point.y - graphView.y) * (height / graphView.height), width, height };
    localStorage.setItem("cros-map-view", JSON.stringify(graphView));
    renderGraph();
  }

  function setGraphZoom(factor) {
    const center = { x: graphView.x + graphView.width / 2, y: graphView.y + graphView.height / 2 };
    const width = Math.max(420, Math.min(1800, graphView.width * factor));
    const height = Math.max(280, Math.min(1100, graphView.height * factor));
    graphView = { x: center.x - width / 2, y: center.y - height / 2, width, height };
    localStorage.setItem("cros-map-view", JSON.stringify(graphView));
    renderGraph();
  }

  function fitGraph() {
    if (!state.graph.nodes.length) { resetGraphView(); return; }
    const xs = state.graph.nodes.map(node => Number(node.x) || 500);
    const ys = state.graph.nodes.map(node => Number(node.y) || 280);
    const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
    const width = Math.max(420, Math.min(1800, maxX - minX + 260));
    const height = Math.max(280, Math.min(1100, maxY - minY + 220));
    graphView = { x: (minX + maxX) / 2 - width / 2, y: (minY + maxY) / 2 - height / 2, width, height };
    localStorage.setItem("cros-map-view", JSON.stringify(graphView));
    renderGraph();
  }

  function resetGraphView() {
    graphView = { x: 0, y: 0, width: GRAPH_BOUNDS.width, height: GRAPH_BOUNDS.height };
    localStorage.setItem("cros-map-view", JSON.stringify(graphView));
    renderGraph();
  }

  function addGraphNode(event) {
    event.preventDefault();
    const label = $("#node-label").value.trim();
    if (!label) return;
    const position = graphPosition(state.graph.nodes.length);
    state.graph.nodes.push({
      id: crypto.randomUUID ? crypto.randomUUID() : `node-${Date.now()}-${Math.random()}`,
      label,
      type: $("#node-type").value,
      note: $("#node-note").value.trim(),
      ...position,
    });
    event.currentTarget.reset();
    persistWorkspace();
    renderGraph();
    selectGraphNode(state.graph.nodes.at(-1).id);
  }

  function addGraphEdge(event) {
    event.preventDefault();
    const source = $("#edge-source").value;
    const target = $("#edge-target").value;
    if (!source || !target || source === target) {
      toast("Connection needs two nodes", "Choose two different entities to connect.", true);
      return;
    }
    state.graph.edges.push({
      id: crypto.randomUUID ? crypto.randomUUID() : `edge-${Date.now()}-${Math.random()}`,
      source,
      target,
      label: $("#edge-label").value.trim(),
    });
    $("#edge-label").value = "";
    persistWorkspace();
    renderGraph();
    toast("Nodes connected", "The relationship was added to your local map.");
  }

  function deleteSelectedNode() {
    if (!state.selectedNode) return;
    const id = state.selectedNode;
    draggingNode = "";
    state.graph.nodes = state.graph.nodes.filter(node => node.id !== id);
    state.graph.edges = state.graph.edges.filter(edge => edge.source !== id && edge.target !== id);
    state.selectedNode = "";
    persistWorkspace();
    renderGraph();
    $("#map-selection").hidden = true;
    toast("Node removed", "The node and its connected relationships were removed.");
  }

  function deleteSelectedEdge() {
    if (!state.selectedEdge) return;
    state.graph.edges = state.graph.edges.filter(edge => edge.id !== state.selectedEdge);
    state.selectedEdge = "";
    persistWorkspace();
    renderGraph();
    $("#map-selection").hidden = true;
    toast("Relationship removed", "The entities remain on the map.");
  }

  function toolByKey(key) { return state.tools.find(tool => tool.key === key); }
  function lessonByKey(key) { return state.lessons[key]; }
  function sourceById(id) { return state.sources.find(source => source.id === id); }

  function saveLearningProgress() {
    const completed = [...state.completedLessons];
    localStorage.setItem("cros-completed-lessons", JSON.stringify(completed));
    api("/api/learning-progress", { method: "POST", body: JSON.stringify({ completed }) })
      .catch(error => toast("Progress not saved", error.message, true));
    updateLearningProgress();
    renderLessonList();
  }

  function updateLearningProgress() {
    const total = Object.keys(state.lessons).length || state.tools.length || 92;
    const complete = [...state.completedLessons].filter(key => state.lessons[key]).length;
    $("#learning-progress-count").textContent = `${complete} / ${total}`;
    $("#learning-progress-bar").style.width = `${total ? (complete / total) * 100 : 0}%`;
  }

  function setLearningView(view) {
    const selected = ["tutorials", "pathways", "sources"].includes(view) ? view : "tutorials";
    $$('[data-learning-view]').forEach(button => {
      const active = button.dataset.learningView === selected;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
    });
    ["tutorials", "pathways", "sources"].forEach(name => {
      $(`#${name}-view`).hidden = name !== selected;
    });
  }

  function openLearning(key = "", view = "tutorials") {
    setLearningView(view);
    if (key && state.lessons[key]) {
      state.selectedLesson = key;
      renderLessonList();
      renderLessonDetail(key);
    } else if (view === "tutorials" && !state.selectedLesson) {
      const first = state.tools.find(tool => state.lessons[tool.key]);
      if (first) {
        state.selectedLesson = first.key;
        renderLessonList();
        renderLessonDetail(first.key);
      }
    }
    $("#learning").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderLessonList() {
    const root = $("#lesson-list");
    if (!root) return;
    const query = state.lessonQuery.trim().toLowerCase();
    const tools = state.tools.filter(tool => {
      const lesson = lessonByKey(tool.key);
      if (!lesson) return false;
      const filterOk = state.lessonFilter === "all" || tool.category === state.lessonFilter;
      const text = `${tool.name} ${tool.section} ${tool.description} ${lesson.best_for}`.toLowerCase();
      return filterOk && (!query || query.split(/\s+/).every(word => text.includes(word)));
    });
    root.replaceChildren();
    tools.forEach(tool => {
      const button = document.createElement("button");
      button.className = `lesson-item${state.selectedLesson === tool.key ? " active" : ""}${state.completedLessons.has(tool.key) ? " complete" : ""}`;
      const code = document.createElement("span");
      code.textContent = codeFor(tool);
      const copy = document.createElement("span");
      const name = document.createElement("strong");
      const section = document.createElement("small");
      name.textContent = tool.name;
      section.textContent = tool.section;
      copy.append(name, section);
      const mark = document.createElement("i");
      mark.textContent = state.completedLessons.has(tool.key) ? "DONE" : accessLabel(tool.access);
      button.append(code, copy, mark);
      button.addEventListener("click", () => {
        state.selectedLesson = tool.key;
        renderLessonList();
        renderLessonDetail(tool.key);
        if (innerWidth < 900) $("#lesson-detail").scrollIntoView({ behavior: "smooth", block: "start" });
      });
      root.append(button);
    });
    if (!tools.length) {
      const empty = document.createElement("div");
      empty.className = "lesson-list-empty";
      empty.textContent = "No lessons match that search.";
      root.append(empty);
    }
  }

  function renderLessonDetail(key) {
    const lesson = lessonByKey(key);
    const tool = toolByKey(key);
    const root = $("#lesson-detail");
    if (!lesson || !tool || !root) return;
    root.replaceChildren();

    const head = document.createElement("header");
    head.className = "lesson-detail-head";
    const meta = document.createElement("div");
    meta.className = "lesson-detail-meta";
    const code = document.createElement("span");
    code.className = "tool-code";
    code.textContent = codeFor(tool);
    const access = document.createElement("span");
    access.className = `access-badge ${tool.access}`;
    access.textContent = accessLabel(tool.access);
    const section = document.createElement("span");
    section.textContent = tool.section.toUpperCase();
    meta.append(code, access, section);
    const title = document.createElement("h3");
    title.textContent = lesson.title;
    const purpose = document.createElement("p");
    purpose.textContent = lesson.purpose;
    head.append(meta, title, purpose);

    const actions = document.createElement("div");
    actions.className = "lesson-actions";
    const launch = document.createElement("button");
    launch.className = "primary-button lesson-launch";
    launch.innerHTML = "LAUNCH TOOL <span>&rarr;</span>";
    const complete = document.createElement("button");
    complete.className = `outline-button lesson-complete${state.completedLessons.has(key) ? " active" : ""}`;
    complete.textContent = state.completedLessons.has(key) ? "LESSON COMPLETE" : "MARK AS LEARNED";
    launch.addEventListener("click", () => launchTool(tool));
    complete.addEventListener("click", () => {
      if (state.completedLessons.has(key)) state.completedLessons.delete(key);
      else state.completedLessons.add(key);
      saveLearningProgress();
      renderLessonDetail(key);
    });
    actions.append(launch, complete);

    const overview = document.createElement("div");
    overview.className = "lesson-overview-grid";
    overview.append(buildLessonBlock("BEST USED FOR", lesson.best_for), buildLessonBlock("WHAT YOU NEED", lesson.input));

    const requirements = document.createElement("section");
    requirements.className = "lesson-block";
    const reqTitle = document.createElement("h4");
    reqTitle.textContent = "REQUIREMENTS";
    const reqList = document.createElement("ul");
    lesson.requirements.forEach(value => { const li = document.createElement("li"); li.textContent = value; reqList.append(li); });
    requirements.append(reqTitle, reqList);

    const steps = document.createElement("section");
    steps.className = "lesson-block lesson-steps";
    const stepsTitle = document.createElement("h4");
    stepsTitle.textContent = "SAFE STEP-BY-STEP";
    const stepsList = document.createElement("ol");
    lesson.steps.forEach(value => { const li = document.createElement("li"); const span = document.createElement("span"); span.textContent = value; li.append(span); stepsList.append(li); });
    steps.append(stepsTitle, stepsList);

    const interpretation = buildLessonBlock("HOW TO READ THE RESULT", lesson.interpretation, "lesson-block lesson-result");
    const safety = buildLessonBlock("SAFETY BOUNDARY", lesson.safety, "lesson-block lesson-safety");

    const sourceSection = document.createElement("section");
    sourceSection.className = "lesson-block lesson-references";
    const sourceTitle = document.createElement("h4");
    sourceTitle.textContent = "SUPPORTING SOURCES";
    const sourceLinks = document.createElement("div");
    sourceLinks.className = "lesson-source-links";
    (lesson.source_ids || []).map(sourceById).filter(Boolean).forEach(source => sourceLinks.append(buildSourceLink(source)));
    if (!sourceLinks.childElementCount) {
      const local = document.createElement("span");
      local.className = "local-reference";
      local.textContent = "Local Cros workflow — no external source required";
      sourceLinks.append(local);
    }
    sourceSection.append(sourceTitle, sourceLinks);

    const related = document.createElement("section");
    related.className = "lesson-block lesson-related";
    const relatedTitle = document.createElement("h4");
    relatedTitle.textContent = "RELATED LESSONS";
    const relatedLinks = document.createElement("div");
    (lesson.related || []).map(toolByKey).filter(Boolean).forEach(item => {
      const button = document.createElement("button");
      const relatedCode = document.createElement("span");
      relatedCode.textContent = codeFor(item);
      const name = document.createElement("strong");
      name.textContent = item.name;
      button.append(relatedCode, name);
      button.addEventListener("click", () => openLearning(item.key, "tutorials"));
      relatedLinks.append(button);
    });
    related.append(relatedTitle, relatedLinks);

    root.append(head, actions, overview, requirements, steps, interpretation, safety, sourceSection, related);
  }

  function buildLessonBlock(titleText, bodyText, className = "lesson-block") {
    const block = document.createElement("section");
    block.className = className;
    const title = document.createElement("h4");
    title.textContent = titleText;
    const body = document.createElement("p");
    body.textContent = bodyText;
    block.append(title, body);
    return block;
  }

  function buildSourceLink(source) {
    const link = document.createElement("a");
    link.href = source.url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    const kind = document.createElement("span");
    kind.textContent = source.kind;
    const name = document.createElement("strong");
    name.textContent = source.name;
    const arrow = document.createElement("i");
    arrow.textContent = "OPEN";
    link.append(kind, name, arrow);
    return link;
  }

  function renderSourceGrid() {
    const root = $("#source-grid");
    if (!root) return;
    const query = ($("#source-search")?.value || "").trim().toLowerCase();
    const sources = state.sources.filter(source => !query || `${source.name} ${source.kind} ${source.topic} ${source.description}`.toLowerCase().includes(query));
    root.replaceChildren();
    sources.forEach((source, index) => {
      const card = document.createElement("article");
      card.className = "source-card";
      const number = document.createElement("span");
      number.className = "source-number";
      number.textContent = String(index + 1).padStart(2, "0");
      const kind = document.createElement("span");
      kind.className = "source-kind";
      kind.textContent = `${source.kind} / ${source.topic.toUpperCase()}`;
      const name = document.createElement("h4");
      name.textContent = source.name;
      const description = document.createElement("p");
      description.textContent = source.description;
      const link = document.createElement("a");
      link.href = source.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.innerHTML = "OPEN SOURCE <span>&rarr;</span>";
      card.append(number, kind, name, description, link);
      root.append(card);
    });
  }

  const PATHWAYS = [
    { code: "PATH / 01", title: "Public username check", description: "Start with one handle, expand carefully, and verify identity clues across sources.", tools: ["osint:1", "osint:2", "osint:7", "advanced:17"] },
    { code: "PATH / 02", title: "Suspicious file triage", description: "Inspect locally first, ask Defender, then use hash-only reputation research when appropriate.", tools: ["security:9", "advanced:8", "security:10", "security:11"] },
    { code: "PATH / 03", title: "Windows protection check", description: "Read the overall posture, confirm Defender and firewall, then review exposed services.", tools: ["security:25", "security:7", "security:17", "security:37"] },
    { code: "PATH / 04", title: "Domain investigation", description: "Build a public infrastructure picture from registration, DNS, certificates, and web behavior.", tools: ["osint:12", "osint:13", "osint:14", "advanced:2"] },
    { code: "PATH / 05", title: "Photo location research", description: "Preserve the original, read metadata, compare visual matches, and validate map features.", tools: ["osint:15", "advanced:16", "advanced:17"] },
    { code: "PATH / 06", title: "Possible remote access malware", description: "Correlate processes, connections, persistence, and Defender evidence before deciding anything.", tools: ["security:1", "security:2", "security:3", "security:4", "security:22"] },
  ];

  function renderPathways() {
    const root = $("#pathway-grid");
    if (!root) return;
    root.replaceChildren();
    PATHWAYS.forEach(path => {
      const card = document.createElement("article");
      card.className = "pathway-card";
      const code = document.createElement("span");
      code.textContent = path.code;
      const title = document.createElement("h4");
      title.textContent = path.title;
      const description = document.createElement("p");
      description.textContent = path.description;
      const steps = document.createElement("ol");
      path.tools.map(toolByKey).filter(Boolean).forEach((tool, index) => {
        const li = document.createElement("li");
        const button = document.createElement("button");
        const number = document.createElement("i");
        number.textContent = String(index + 1).padStart(2, "0");
        const copy = document.createElement("span");
        const name = document.createElement("strong");
        name.textContent = tool.name;
        const detail = document.createElement("small");
        detail.textContent = tool.description;
        copy.append(name, detail);
        button.append(number, copy);
        button.addEventListener("click", () => openLearning(tool.key, "tutorials"));
        li.append(button);
        steps.append(li);
      });
      const start = document.createElement("button");
      start.className = "pathway-start";
      start.innerHTML = "START THIS PATH <span>&rarr;</span>";
      start.addEventListener("click", () => openLearning(path.tools[0], "tutorials"));
      card.append(code, title, description, steps, start);
      root.append(card);
    });
  }

  function updateStatus(payload) {
    const summary = payload.summary || {};
    const pass = Number(summary.pass || 0);
    const review = Number(summary.review || 0);
    const unknown = Number(summary.unknown || 0);
    const total = Math.max(1, pass + review + unknown);
    const score = Math.max(0, Math.min(100, Math.round(((pass + unknown * 0.35) / total) * 100)));
    $("#posture-score").textContent = score;
    $("#posture-bar").style.width = `${score}%`;
    $("#posture-copy").textContent = review ? `${review} setting${review === 1 ? "" : "s"} marked for review. Open posture for context.` : "No protection settings are currently marked for review.";
    $("#process-count").textContent = summary.processes ?? "--";
    $("#connection-count").textContent = summary.connections ?? "--";
    $("#connection-detail").textContent = `${summary.established || 0} ESTABLISHED / ${summary.listening || 0} LISTENING`;
    $("#startup-count").textContent = summary.startup ?? "--";
    $("#pass-count").textContent = pass;
    $("#review-count").textContent = review;
    $("#unknown-count").textContent = unknown;
    $("#machine-name").textContent = payload.machine || "LOCAL MACHINE";
    $("#machine-platform").textContent = payload.platform || "Windows workstation";
    $("#checked-time").textContent = payload.checked_at || "CHECKED";
    state.posture = payload.posture || [];
    renderPosture();
  }

  async function refreshStatus(showToast = false) {
    const button = $("#refresh-status");
    button.disabled = true;
    button.firstChild.textContent = "CHECKING STATUS ";
    try {
      const payload = await api("/api/status");
      updateStatus(payload);
      if (showToast) toast("Status refreshed", "Local Windows protection signals are current.");
    } catch (error) {
      $("#posture-copy").textContent = "Protection status could not be read in this session.";
      toast("Status unavailable", error.message, true);
    } finally {
      button.disabled = false;
      button.firstChild.textContent = "REFRESH STATUS ";
    }
  }

  function renderPosture() {
    const root = $("#posture-list");
    root.replaceChildren();
    if (!state.posture.length) {
      root.textContent = "No posture data loaded yet.";
      return;
    }
    state.posture.forEach(item => {
      const row = document.createElement("article");
      row.className = "posture-item";
      const name = document.createElement("strong");
      name.textContent = item.check;
      const result = document.createElement("span");
      result.className = `posture-result ${item.result.toLowerCase()}`;
      result.textContent = item.result;
      const detail = document.createElement("p");
      detail.textContent = item.detail;
      row.append(name, result, detail);
      root.append(row);
    });
  }

  function openCommand(initial = "") {
    const layer = $("#command-layer");
    layer.hidden = false;
    const input = $("#command-search");
    input.value = initial;
    state.commandIndex = 0;
    renderCommandResults();
    requestAnimationFrame(() => input.focus());
  }

  function closeCommand() { $("#command-layer").hidden = true; }

  function renderCommandResults() {
    const query = $("#command-search").value.trim().toLowerCase();
    const rank = tool => {
      if (!query) return 10;
      const name = tool.name.toLowerCase();
      if (name === query) return 0;
      if (name.startsWith(query)) return 1;
      if (name.split(/\s+/).some(word => word.startsWith(query))) return 2;
      if (name.includes(query)) return 3;
      if (tool.section.toLowerCase().includes(query)) return 4;
      return 5;
    };
    state.commandMatches = state.tools.filter(tool => matches(tool, query, "all"))
      .sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name)).slice(0, 10);
    if (state.commandIndex >= state.commandMatches.length) state.commandIndex = 0;
    const root = $("#command-results");
    root.replaceChildren();
    state.commandMatches.forEach((tool, index) => {
      const button = document.createElement("button");
      button.className = `command-result${index === state.commandIndex ? " selected" : ""}`;
      const code = document.createElement("span");
      code.className = "command-result-code";
      code.textContent = codeFor(tool);
      const copy = document.createElement("span");
      const name = document.createElement("strong");
      const section = document.createElement("small");
      name.textContent = tool.name;
      section.textContent = tool.section;
      copy.append(name, section);
      const category = document.createElement("span");
      category.textContent = tool.category;
      button.append(code, copy, category);
      button.addEventListener("click", () => launchTool(tool));
      root.append(button);
    });
    if (!state.commandMatches.length) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "No matching workflow.";
      root.append(empty);
    }
  }

  function bindPointerGlow() {
    $$(".tool-card, .status-card").forEach(card => {
      if (card.dataset.glowBound) return;
      card.dataset.glowBound = "1";
      card.addEventListener("pointermove", event => {
        const rect = card.getBoundingClientRect();
        card.style.setProperty("--mx", `${event.clientX - rect.left}px`);
        card.style.setProperty("--my", `${event.clientY - rect.top}px`);
      });
    });
  }

  const ACCENTS = {
    violet: ["#8566ff", "133, 102, 255", "#b5a5ff"],
    cyan: ["#37cce4", "55, 204, 228", "#9beaf4"],
    red: ["#ef536d", "239, 83, 109", "#ff9aac"],
    green: ["#4dcc8b", "77, 204, 139", "#a0ecc4"],
    amber: ["#e5a84f", "229, 168, 79", "#f1d19d"],
    ice: ["#cad8ff", "202, 216, 255", "#edf2ff"],
  };

  function setAccent(name) {
    const values = ACCENTS[name] || ACCENTS.violet;
    document.documentElement.style.setProperty("--accent", values[0]);
    document.documentElement.style.setProperty("--accent-rgb", values[1]);
    document.documentElement.style.setProperty("--accent-soft", values[2]);
    document.documentElement.style.setProperty("--cros-preset-color", values[0]);
    $$('[data-accent]').forEach(button => button.classList.toggle("active", button.dataset.accent === name));
    $("#custom-accent").value = values[0];
    localStorage.setItem("cros-accent", name);
  }

  function hexToRgb(hex) {
    const value = hex.replace("#", "");
    if (!/^[0-9a-f]{6}$/i.test(value)) return null;
    return [0, 2, 4].map(offset => parseInt(value.slice(offset, offset + 2), 16));
  }

  function setCustomAccent(hex) {
    const rgb = hexToRgb(hex);
    if (!rgb) return;
    const soft = rgb.map(channel => Math.round(channel + (255 - channel) * .42));
    document.documentElement.style.setProperty("--accent", hex);
    document.documentElement.style.setProperty("--accent-rgb", rgb.join(", "));
    document.documentElement.style.setProperty("--accent-soft", `rgb(${soft.join(", ")})`);
    document.documentElement.style.setProperty("--cros-preset-color", hex);
    $$('[data-accent]').forEach(button => button.classList.remove("active"));
    localStorage.setItem("cros-accent", "custom");
    localStorage.setItem("cros-custom-accent", hex);
  }
  function setCustomBackground(hex, save = true) { document.documentElement.style.setProperty("--custom-bg", hex); if (save) localStorage.setItem("cros-background", hex); }
  function setStarColor(hex, save = true) { const rgb = hexToRgb(hex); if (!rgb) return; document.documentElement.style.setProperty("--star-rgb", rgb.join(", ")); $("#custom-stars").value = hex; if (save) localStorage.setItem("cros-star-color", hex); }
  function setSettingsOpen(open) {
    const drawer = $("#settings-drawer");
    drawer.hidden = !open;
    drawer.classList.toggle("open", open);
    drawer.setAttribute("aria-hidden", String(!open));
    document.body.classList.toggle("settings-open", open);
  }

  function jumpSettings(section) {
    const targets = {
      "settings-logo": $(".logo-settings"),
      "settings-themes": $(".interface-presets"),
      "settings-colors": $(".color-settings"),
      "settings-layout": $(".screen-fit-section"),
      "settings-motion": $("#particle-toggle")?.closest(".drawer-section"),
      "settings-data": $("#reset-appearance")?.closest(".drawer-section"),
    };
    const target = targets[section];
    if (!target) return;
    $$('[data-settings-jump]').forEach(button => button.classList.toggle("active", button.dataset.settingsJump === section));
    target.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function scanDroppedFile(event) {
    event.preventDefault();
    const scanPanel = event.currentTarget.closest(".file-scan-host") || document.querySelector("#tools .security-file-scan");
    const inNativeTool = Boolean(scanPanel.closest("#native-tool-panel"));
    const file = scanPanel.querySelector("input[type=\"file\"]").files[0];
    if (!file) { toast("Choose a file first", "Drop a file or use the file picker.", true); return; }
    if (file.size > 25_000_000) { toast("File is too large", "Choose a file smaller than 25 MB.", true); return; }
    const results = scanPanel.querySelector(".file-scan-results");
    if (inNativeTool) updateSessionProgress({ done: false, stage: "Scanning locally" });
    results.innerHTML = `<div class="scan-progress-card"><div class="scan-orbit"><i></i></div><strong id="scan-progress-title">Preparing local scan</strong><span id="scan-progress-detail">Creating a temporary isolated copy…</span><div class="scan-progress-track"><i></i></div></div>`;
    const scanStages = [["Hashing file", "Calculating SHA-256 locally…"], ["Inspecting structure", file.name.toLowerCase().endsWith(".jar") ? "Opening JAR contents without executing them…" : "Checking file type and static indicators…"], ["Running Defender", "Microsoft Defender is scanning the temporary copy…"]];
    let scanStage = 0;
    const scanTimer = setInterval(() => { const stage = scanStages[Math.min(scanStage++, scanStages.length - 1)]; const title = scanPanel.querySelector("#scan-progress-title"); const detail = scanPanel.querySelector("#scan-progress-detail"); if (title) title.textContent = stage[0]; if (detail) detail.textContent = stage[1]; }, 700);
    try {
      const result = await api("/api/file-scan", { method: "POST", body: JSON.stringify({ name: file.name, data: await readFileAsBase64(file) }) });
      const detections = Array.isArray(result.detections) ? result.detections : [];
      const indicators = Array.isArray(result.indicators) ? result.indicators : [];
      const flagged = detections.length || indicators.length;
      const assessment = result.assessment || (detections.length ? "Defender detection" : "inconclusive");
      const outcomeClass = detections.length || assessment === "likely RAT-like behavior" || assessment === "likely keylogger behavior" ? "danger" : flagged ? "review" : "safe";
      const jar = result.jar_summary;
      const jarRow = jar ? `<div class="jar-summary"><b>JAR STRUCTURE</b><span>${jar.integrity} · ${jar.entries} entries · ${jar.classes} classes · ${jar.native_libraries} native libraries · ${jar.nested_archives} nested archives · manifest ${jar.manifest ? "present" : "absent"}</span></div>` : "";
      results.innerHTML = `<div class="file-scan-card ${outcomeClass}"><div class="file-scan-status ${outcomeClass}">${detections.length ? "CONFIRMED DEFENDER DETECTION" : assessment === "likely RAT-like behavior" ? "LIKELY RAT-LIKE BEHAVIOR" : assessment === "likely keylogger behavior" ? "LIKELY KEYLOGGER BEHAVIOR" : flagged ? "SUSPICIOUS INDICATORS" : "NO RAT INDICATORS FOUND"}</div><dl><dt>FILE</dt><dd>${escapeHtml(result.file_name)}</dd><dt>SHA-256</dt><dd class="hash-value">${escapeHtml(result.sha256)}</dd><dt>ASSESSMENT</dt><dd>${escapeHtml(assessment)}</dd><dt>DEFENDER</dt><dd>${escapeHtml(result.defender)}</dd><dt>REVIEW</dt><dd>${escapeHtml(result.review)}</dd></dl>${jarRow}${indicators.length ? `<div class="file-indicators"><b>LOCAL INDICATORS</b><ul>${indicators.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>` : ""}${detections.length ? `<pre>${escapeHtml(JSON.stringify(detections, null, 2))}</pre>` : "<small>Heuristics identify behavior patterns; only Defender or another confirmed signature establishes a confirmed detection.</small>"}<button type="button" class="scan-again-button">SCAN AGAIN</button></div>`;
      if (inNativeTool) updateSessionProgress({ done: true, returncode: 0, stage: flagged ? "Scan complete · review findings" : "Scan complete" });
      results.querySelector(".scan-again-button").addEventListener("click", () => { const input = scanPanel.querySelector("input[type=\"file\"]"); const drop = scanPanel.querySelector(".file-drop"); input.value = ""; drop.classList.remove("has-file"); drop.querySelector("strong").textContent = "Drop a file here"; const label = drop.querySelector("span"); if (label) label.textContent = "25 MB maximum · local only"; results.innerHTML = "<div class=\"lab-empty\"><strong>Ready for another scan</strong><span>Drop a file or choose one to begin.</span></div>"; });
    } catch (error) {
      results.innerHTML = `<div class="lab-empty"><strong>Scan failed</strong><span>${escapeHtml(error.message)}</span></div>`;
      if (inNativeTool) updateSessionProgress({ done: true, returncode: 1, stage: "Scan failed" });
      toast("File scan failed", error.message, true);
    } finally { clearInterval(scanTimer); }
  }

  function toggleSetting(id, bodyClass, storageKey, invert = false) {
    const button = $(id);
    const active = !button.classList.contains("active");
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
    document.body.classList.toggle(bodyClass, invert ? !active : active);
    localStorage.setItem(storageKey, String(active));
    if (bodyClass === "no-wings" && active) {
      $$(".wing").forEach(wing => { wing.style.animation = "none"; void wing.offsetWidth; wing.style.animation = ""; });
    }
  }

  function setGlow(value, save = true) {
    const level = Math.max(0, Math.min(100, Number(value) || 0));
    document.documentElement.style.setProperty("--glow-level", String(level / 100));
    $("#glow-range").value = String(level);
    $("#glow-output").textContent = `${level}%`;
    if (save) localStorage.setItem("cros-glow", String(level));
  }

  function setMotion(value, save = true) {
    const speed = Math.max(35, Math.min(180, Number(value) || 100));
    const factor = speed / 100;
    document.documentElement.style.setProperty("--orbit-fast", `${(18 / factor).toFixed(2)}s`);
    document.documentElement.style.setProperty("--orbit-slow", `${(28 / factor).toFixed(2)}s`);
    document.documentElement.style.setProperty("--wing-speed", `${(4.6 / factor).toFixed(2)}s`);
    $("#motion-range").value = String(speed);
    $("#motion-output").textContent = `${speed}%`;
    if (save) localStorage.setItem("cros-motion", String(speed));
  }

  function setParticleDensity(value, save = true) {
    const density = Math.max(20, Math.min(180, Number(value) || 100));
    $("#particle-density").value = String(density);
    $("#particle-density-output").textContent = `${density}%`;
    if (save) localStorage.setItem("cros-particle-density", String(density));
    dispatchEvent(new Event("resize"));
  }

  function setLightSmoothing(value, save = true) {
    const smoothing = Math.max(20, Math.min(100, Number(value) || 75));
    document.documentElement.style.setProperty("--light-smoothing", String(smoothing / 100));
    $("#light-smoothing").value = String(smoothing);
    $("#light-smoothing-output").textContent = `${smoothing}%`;
    if (save) localStorage.setItem("cros-light-smoothing", String(smoothing));
  }

  function setStarBrightness(value, save = true) {
    const brightness = Math.max(30, Math.min(240, Number(value) || 120));
    document.documentElement.style.setProperty("--star-brightness", String(brightness / 100));
    $("#star-brightness").value = String(brightness);
    $("#star-brightness-output").textContent = `${brightness}%`;
    if (save) localStorage.setItem("cros-star-brightness", String(brightness));
  }

  function setShape(shape, save = true) {
    const radii = { soft: "17px", sharp: "6px", round: "26px" };
    const selected = radii[shape] ? shape : "soft";
    document.documentElement.style.setProperty("--card-radius", radii[selected]);
    $$('[data-shape]').forEach(button => button.classList.toggle("active", button.dataset.shape === selected));
    if (save) localStorage.setItem("cros-shape", selected);
  }

  function setColumns(value, save = true) {
    const selected = ["auto", "3", "4", "5"].includes(String(value)) ? String(value) : "auto";
    document.body.classList.toggle("fixed-columns", selected !== "auto");
    document.documentElement.style.setProperty("--tool-columns", selected === "auto" ? "4" : selected);
    $$('[data-columns]').forEach(button => button.classList.toggle("active", button.dataset.columns === selected));
    if (save) localStorage.setItem("cros-columns", selected);
  }

  function setScreenFit(value, save = true) {
    const selected = ["laptop", "medium", "large"].includes(value) ? value : "medium";
    document.documentElement.dataset.screenFit = selected;
    $$("[data-screen-fit]").forEach(button => {
      const active = button.dataset.screenFit === selected;
      button.classList.toggle("active", active);
      button.setAttribute("aria-checked", String(active));
    });
    const recommended = { laptop: 680, medium: 620, large: 760 }[selected];
    const width = Math.max(360, Math.min(recommended, innerWidth - 16));
    document.documentElement.style.setProperty("--workspace-width", `${width}px`);
    if ($("#workspace-width-control")) {
      $("#workspace-width-control").value = String(width);
      $("#workspace-width-value").textContent = `${width}px`;
    }
    handleWorkspaceViewportChange();
    if (save) localStorage.setItem("cros-screen-fit", selected);
  }

  function setInterfacePreset(value, save = true) {
    const available = new Set(["flux", "cros", "arctic", "matrix", "amber", "mono", "ocean", "rose", "cyber", "midnight", "minimal", "slate", "paper", "graphite", "linen", "vs-dark", "vs-light", "vs-contrast"]);
    const selected = available.has(value) ? value : "flux";
    document.documentElement.dataset.interfacePreset = selected;
    $$('[data-interface-preset]').forEach(button => {
      const active = button.dataset.interfacePreset === selected;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    if (save) localStorage.setItem("cros-interface-preset", selected);
  }

  function showLogoSelection(value) {
    const selected = ["original", "signal", "scope", "shield", "mono", "custom"].includes(value) ? value : "original";
    $$('[data-logo-style]').forEach(button => {
      const active = button.dataset.logoStyle === selected;
      button.classList.toggle("active", active);
      button.setAttribute("aria-checked", String(active));
    });
    return selected;
  }

  function refreshAppIcon(url) {
    $$('link[rel="icon"], link[rel="apple-touch-icon"]').forEach(link => { link.href = url; });
  }

  async function changeLogoStyle(preset, image = "") {
    const buttons = $$('[data-logo-style]');
    buttons.forEach(button => { button.disabled = true; });
    $("#logo-note").textContent = "Updating the Cros app and Windows shortcut…";
    try {
      const result = await api("/api/logo", { method: "POST", body: JSON.stringify({ preset, image }) });
      localStorage.setItem("cros-logo-style", result.preset);
      showLogoSelection(result.preset);
      refreshAppIcon(result.icon);
      $("#logo-note").textContent = "Logo saved. The app, desktop shortcut, and taskbar identity now use this mark.";
      toast("Cros logo updated", `${result.preset.toUpperCase()} is now your app logo.`);
    } catch (error) {
      $("#logo-note").textContent = "The logo was not changed. Choose a PNG, JPG, or WebP up to 6 MB.";
      toast("Logo could not be changed", error.message, true);
    } finally {
      buttons.forEach(button => { button.disabled = false; });
      $("#custom-logo-file").value = "";
    }
  }

  function useCustomLogo(file) {
    if (!file) return;
    if (file.size > 6_000_000) { toast("Logo is too large", "Choose an image up to 6 MB.", true); return; }
    const reader = new FileReader();
    reader.addEventListener("load", () => changeLogoStyle("custom", String(reader.result || "")));
    reader.addEventListener("error", () => toast("Logo could not be read", "Choose another image file.", true));
    reader.readAsDataURL(file);
  }

  function restoreSettings() {
    setInterfacePreset(localStorage.getItem("cros-interface-preset") || "flux", false);
    showLogoSelection(localStorage.getItem("cros-logo-style") || "original");
    const accent = localStorage.getItem("cros-accent") || "violet";
    if (accent === "custom") {
      const custom = localStorage.getItem("cros-custom-accent") || "#8566ff";
      $("#custom-accent").value = custom;
      setCustomAccent(custom);
    } else setAccent(accent);
    const particles = localStorage.getItem("cros-particles") !== "false";
    const wings = localStorage.getItem("cros-wings") !== "false";
    const compact = localStorage.getItem("cros-compact") === "true";
    const animations = localStorage.getItem("cros-animations") !== "false";
    $("#particle-toggle").classList.toggle("active", particles);
    $("#particle-toggle").setAttribute("aria-pressed", String(particles));
    document.body.classList.toggle("no-particles", !particles);
    $("#wing-toggle").classList.toggle("active", wings);
    $("#wing-toggle").setAttribute("aria-pressed", String(wings));
    document.body.classList.toggle("no-wings", !wings);
    $("#compact-toggle").classList.toggle("active", compact);
    $("#compact-toggle").setAttribute("aria-pressed", String(compact));
    document.body.classList.toggle("compact", compact);
    $("#animation-toggle").classList.toggle("active", animations);
    $("#animation-toggle").setAttribute("aria-pressed", String(animations));
    document.body.classList.toggle("no-animations", !animations);
    setGlow(localStorage.getItem("cros-glow") || 70, false);
    setMotion(localStorage.getItem("cros-motion") || 100, false);
    setParticleDensity(localStorage.getItem("cros-particle-density") || 100, false);
    setLightSmoothing(localStorage.getItem("cros-light-smoothing") || 75, false);
    setStarBrightness(localStorage.getItem("cros-star-brightness") || 120, false);
    setShape(localStorage.getItem("cros-shape") || "soft", false);
    setColumns(localStorage.getItem("cros-columns") || "auto", false);
    const storedFit = localStorage.getItem("cros-screen-fit");
    setScreenFit(storedFit || ((innerWidth <= 1500 || innerHeight <= 850) ? "laptop" : "medium"), false);
  }

  function toggleWingDeck(force) {
    const stage = $("#signal-stage");
    const open = typeof force === "boolean" ? force : !stage.classList.contains("wings-open");
    stage.classList.toggle("wings-open", open);
    $("#wing-core").setAttribute("aria-expanded", String(open));
    $("#wing-deck").setAttribute("aria-hidden", String(!open));
  }

  function initParticles() {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const canvas = $("#particle-field");
    const context = canvas.getContext("2d");
    let width = 0, height = 0, ratio = 1;
    const particles = [];
    const pointer = { x: -1000, y: -1000 };

    function resize() {
      ratio = Math.min(devicePixelRatio || 1, 2);
      width = innerWidth; height = innerHeight;
      canvas.width = width * ratio; canvas.height = height * ratio;
      canvas.style.width = `${width}px`; canvas.style.height = `${height}px`;
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      const wanted = Math.min(110, Math.floor((width * height) / 15500));
      while (particles.length < wanted) particles.push({ x: Math.random() * width, y: Math.random() * height, r: Math.random() * 1.4 + .3, vx: (Math.random() - .5) * .12, vy: (Math.random() - .5) * .12, a: Math.random() * .5 + .15 });
      particles.length = wanted;
    }

    addEventListener("resize", resize, { passive: true });
    addEventListener("pointermove", event => { pointer.x = event.clientX; pointer.y = event.clientY; }, { passive: true });
    resize();

    let previousTime = performance.now();
    function frame(now) {
      const delta = Math.min(2, Math.max(.25, (now - previousTime) / 16.67));
      previousTime = now;
      if (document.hidden || document.body.classList.contains("no-particles")) {
        requestAnimationFrame(frame);
        return;
      }
      context.clearRect(0, 0, width, height);
        const styles = getComputedStyle(document.documentElement);
        const accent = styles.getPropertyValue("--accent-rgb").trim() || "133,102,255";
        const starColor = styles.getPropertyValue("--star-rgb").trim() || accent;
      particles.forEach((particle, index) => {
        particle.x += particle.vx * delta; particle.y += particle.vy * delta;
        if (particle.x < -10) particle.x = width + 10; if (particle.x > width + 10) particle.x = -10;
        if (particle.y < -10) particle.y = height + 10; if (particle.y > height + 10) particle.y = -10;
        const distance = Math.hypot(pointer.x - particle.x, pointer.y - particle.y);
        const boost = distance < 150 ? (150 - distance) / 150 : 0;
        context.beginPath(); context.arc(particle.x, particle.y, particle.r + boost * 1.2, 0, Math.PI * 2);
        const rootStyle = getComputedStyle(document.documentElement);
        const smoothness = Number(rootStyle.getPropertyValue("--light-smoothing")) || .75;
        const brightness = Number(rootStyle.getPropertyValue("--star-brightness")) || 1.2;
        const shimmer = .82 + Math.sin(now * .0012 + index) * .18 * smoothness;
        context.fillStyle = `rgba(${starColor},${Math.min(1, ((particle.a * shimmer) + boost * .35) * brightness)})`; context.fill();
        if (index % 7 === 0 && boost > .25) {
          context.beginPath(); context.moveTo(particle.x, particle.y); context.lineTo(pointer.x, pointer.y);
          context.strokeStyle = `rgba(${starColor},${boost * .08})`; context.stroke();
        }
      });
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  function bindEvents() {
    $("#hero-search-form").addEventListener("submit", event => {
      event.preventDefault();
      const query = $("#hero-search").value.trim();
      if (!query) { openCommand(); return; }
      $("#tool-search").value = query;
      state.query = query;
      renderTools();
      $("#tools").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    $("#tool-search").addEventListener("input", event => { state.query = event.target.value; scheduleToolRender(); });
    $("#pin-jump").addEventListener("click", () => $("#pinboard").scrollIntoView({ behavior: "smooth", block: "start" }));
    $("#pin-form").addEventListener("submit", addPin);
    $("#pin-grid").addEventListener("click", handlePinAction);
    $("#browse-tools").addEventListener("click", () => { setFilter("all"); $("#tools").scrollIntoView({ behavior: "smooth", block: "start" }); });
    $("#node-form").addEventListener("submit", addGraphNode);
    $("#edge-form").addEventListener("submit", addGraphEdge);
    $("#delete-node").addEventListener("click", deleteSelectedNode);
    $("#delete-edge").addEventListener("click", deleteSelectedEdge);
    $("#edit-node").addEventListener("click", editSelectedNode);
    $("#node-edit-form").addEventListener("submit", saveEditedNode);
    $("#cancel-node-edit").addEventListener("click", () => { $("#node-edit-form").hidden = true; });
    $("#neural-map").addEventListener("wheel", zoomGraph, { passive: false });
    $("#neural-map").addEventListener("pointerdown", handleGraphPanStart);
    $("#map-zoom-out").addEventListener("click", () => setGraphZoom(1.18));
    $("#map-zoom-in").addEventListener("click", () => setGraphZoom(0.85));
    $("#map-fit").addEventListener("click", fitGraph);
    $("#map-reset").addEventListener("click", resetGraphView);
    $("#name-search-form").addEventListener("submit", searchNames);
    $("#save-hibp-key")?.addEventListener("click", async () => {
      const value = $("#hibp-api-key").value.trim();
      if (!/^[0-9a-fA-F]{32}$/.test(value)) { toast("HIBP key not saved", "Use the 32-character key from your HIBP account.", true); return; }
      try { await api("/api/provider-keys", { method: "POST", body: JSON.stringify({ hibp: value }) }); localStorage.setItem("cros-hibp-key", value); toast("HIBP key saved", "Stored locally for future breach checks."); }
      catch (error) { toast("HIBP key not saved", error.message, true); }
    });
    $$("[data-playbook-tool]").forEach(button => button.addEventListener("click", () => launchTool(button.dataset.playbookTool)));
    $("#name-provider-picker").addEventListener("click", event => {
      const button = event.target.closest(".engine-option");
      if (button) setNameProvider(button.dataset.provider);
    });
    $("#name-provider-picker").addEventListener("keydown", event => {
      if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) return;
      const buttons = $$(".engine-option", event.currentTarget);
      const current = buttons.findIndex(button => button.getAttribute("aria-checked") === "true");
      const step = ["ArrowRight", "ArrowDown"].includes(event.key) ? 1 : -1;
      const next = buttons[(current + step + buttons.length) % buttons.length];
      event.preventDefault(); setNameProvider(next.dataset.provider); next.focus();
    });
    $$('[data-engine-project]').forEach(button => button.addEventListener("click", () => {
      const info = state.usernameProviders[button.dataset.engineProject];
      if (info?.project) openResearchUrl(info.project);
    }));
    $("#session-advanced-toggle").addEventListener("click", () => {
      const log = $("#session-log");
      log.hidden = !log.hidden;
      if (!log.hidden) log.open = true;
      $("#session-advanced-toggle").textContent = log.hidden ? "ENGINE DETAILS" : "HIDE DETAILS";
    });
    $("#image-scan-form").addEventListener("submit", scanImage);
    $("#image-file").addEventListener("change", event => { $("#image-file-label").textContent = event.target.files[0]?.name || "Choose image"; });
    $("#image-scan-mode").addEventListener("change", renderImageResult);
    $("#location-form").addEventListener("submit", buildLocationHypotheses);
    const fileScanPanel = document.querySelector("#tools .security-file-scan");
    fileScanPanel.querySelector("#file-scan-form").addEventListener("submit", scanDroppedFile);
    fileScanPanel.querySelector("#file-scan-file").addEventListener("change", event => { fileScanPanel.querySelector("#file-drop").classList.toggle("has-file", Boolean(event.target.files[0])); const label = fileScanPanel.querySelector("#file-scan-label"); if (label && event.target.files[0]) label.textContent = `${event.target.files[0].name} · ${(event.target.files[0].size / 1048576).toFixed(2)} MB`; });
    fileScanPanel.querySelector("#file-drop").addEventListener("dragover", event => { event.preventDefault(); event.currentTarget.classList.add("dragging"); });
    fileScanPanel.querySelector("#file-drop").addEventListener("dragleave", event => event.currentTarget.classList.remove("dragging"));
    fileScanPanel.querySelector("#file-drop").addEventListener("drop", event => { event.preventDefault(); event.currentTarget.classList.remove("dragging"); const files = event.dataTransfer.files; if (files.length) { const input = fileScanPanel.querySelector("#file-scan-file"); const transfer = new DataTransfer(); transfer.items.add(files[0]); input.files = transfer.files; input.dispatchEvent(new Event("change")); } });
    setupRegionAssistant();
    $("#session-input-form").addEventListener("submit", sendSessionInput);
    $("#session-stop").addEventListener("click", () => stopActiveSession(true));
    $("#session-view-map").addEventListener("click", () => openWorkspace("map"));
    $("#session-social-filter").addEventListener("input", renderSessionSocialResults);
    $("#session-copy-all").addEventListener("click", copyAllAccountResults);
    $$('[data-workspace-tab]').forEach(button => button.addEventListener("click", () => setWorkspaceView(button.dataset.workspaceTab)));
    $("#workspace-close").addEventListener("click", closeWorkspace);
    $("#workspace-restore").addEventListener("click", () => openWorkspace());
    $("#workspace-customize").addEventListener("click", toggleWorkspaceSettings);
    $("#workspace-size").addEventListener("click", toggleWorkspaceSize);
    $("#workspace-width-control").addEventListener("input", event => setWorkspaceWidth(event.target.value));
    $$('[data-workspace-tab-size]').forEach(button => button.addEventListener("click", () => setWorkspaceTabSize(button.dataset.workspaceTabSize)));
    $("#workspace-home-view").addEventListener("change", event => setWorkspaceHomeView(event.target.value));
    $("#workspace-resize-handle").addEventListener("pointerdown", event => { event.preventDefault(); event.currentTarget.setPointerCapture?.(event.pointerId); workspaceResizing = true; workspaceDragging = false; });
    $("#workspace-drag-handle").addEventListener("pointerdown", event => { if (event.target.closest("button")) return; const r = $("#workspace-dock").getBoundingClientRect(); workspaceDragOffset = { x: event.clientX-r.left, y: event.clientY-r.top }; workspaceDragging = true; workspaceResizing = false; event.currentTarget.setPointerCapture?.(event.pointerId); event.preventDefault(); });
    $("#workspace-resize-handle").addEventListener("keydown", event => {
      if (event.key === "ArrowLeft") { event.preventDefault(); resizeWorkspaceBy(24); }
      if (event.key === "ArrowRight") { event.preventDefault(); resizeWorkspaceBy(-24); }
    });
    addEventListener("pointermove", handleGraphPointerMove);
    addEventListener("pointermove", handleGraphPanMove);
    addEventListener("pointermove", handleWorkspaceResize);
    addEventListener("pointermove", handleWorkspaceDrag);
    addEventListener("pointerup", finishGraphDrag);
    addEventListener("pointerup", finishGraphPan);
    addEventListener("pointerup", () => { workspaceResizing = false; workspaceDragging = false; });
    addEventListener("pointercancel", finishGraphDrag);
    addEventListener("pointercancel", finishGraphPan);
    addEventListener("pointercancel", () => { workspaceResizing = false; });
    addEventListener("resize", handleWorkspaceViewportChange);
    $$('[data-filter]').forEach(button => button.addEventListener("click", () => setFilter(button.dataset.filter)));
    $("#lesson-search").addEventListener("input", event => { state.lessonQuery = event.target.value; renderLessonList(); });
    $$('[data-lesson-filter]').forEach(button => button.addEventListener("click", () => {
      state.lessonFilter = button.dataset.lessonFilter;
      $$('[data-lesson-filter]').forEach(item => item.classList.toggle("active", item === button));
      renderLessonList();
    }));
    $$('[data-learning-view]').forEach(button => button.addEventListener("click", () => setLearningView(button.dataset.learningView)));
    $("#source-search").addEventListener("input", renderSourceGrid);
    $$('[data-learning-footer]').forEach(button => button.addEventListener("click", () => openLearning("", button.dataset.learningFooter)));
    $$('[data-quick]').forEach(button => button.addEventListener("click", () => launchTool(button.dataset.quick)));
    $("#refresh-status").addEventListener("click", () => refreshStatus(true));
    $("#posture-details").addEventListener("click", () => { $("#detail-layer").hidden = false; });
    $$('[data-close-detail]').forEach(button => button.addEventListener("click", () => { $("#detail-layer").hidden = true; }));
    $("#command-button").addEventListener("click", () => openCommand());
    $(".brand")?.addEventListener("click", event => { event.preventDefault(); toggleNavigation(); });
    const railWidth = Number(localStorage.getItem("cros-rail-width"));
    if (railWidth >= 240) document.documentElement.style.setProperty("--rail-width", `${Math.min(420, railWidth)}px`);
    if (localStorage.getItem("cros-rail-collapsed") === "1") document.body.classList.add("rail-collapsed");
    $("#rail-autoclose").value = localStorage.getItem("cros-rail-autoclose") ?? "3000";
    $("#rail-autoclose").addEventListener("change", event => localStorage.setItem("cros-rail-autoclose", event.target.value));
    $("#rail-resize-handle").addEventListener("pointerdown", event => { railResizing = true; event.currentTarget.setPointerCapture?.(event.pointerId); event.preventDefault(); });
    addEventListener("pointermove", handleRailResize);
    addEventListener("pointerup", () => { railResizing = false; });
    $$('[data-view]').forEach(button => button.addEventListener("click", scheduleRailClose));
    $$('[data-close-command]').forEach(button => button.addEventListener("click", closeCommand));
    $("#command-search").addEventListener("input", () => { state.commandIndex = 0; renderCommandResults(); });
    $("#command-search").addEventListener("keydown", event => {
      if (event.key === "ArrowDown") { event.preventDefault(); state.commandIndex = Math.min(state.commandMatches.length - 1, state.commandIndex + 1); renderCommandResults(); }
      if (event.key === "ArrowUp") { event.preventDefault(); state.commandIndex = Math.max(0, state.commandIndex - 1); renderCommandResults(); }
      if (event.key === "Enter" && state.commandMatches[state.commandIndex]) { event.preventDefault(); launchTool(state.commandMatches[state.commandIndex]); }
    });
    addEventListener("keydown", event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); openCommand(); }
      if (event.key.toLowerCase() === "c" && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName)) { event.preventDefault(); openWorkspace(); $("[data-workspace-tab].active")?.focus(); }
      if (event.key === "Escape") { closeCommand(); $("#detail-layer").hidden = true; setSettingsOpen(false); closeWorkspace(); }
    });
    $("#settings-button").addEventListener("click", () => setSettingsOpen(!$("#settings-drawer").classList.contains("open")));
    $("#search-settings").addEventListener("click", () => setSettingsOpen(true));
    $("#settings-close").addEventListener("click", () => setSettingsOpen(false));
    $$('[data-settings-jump]').forEach(button => button.addEventListener("click", () => jumpSettings(button.dataset.settingsJump)));
    $("#save-operator-name").addEventListener("click", () => {
      if (applyOperatorName($("#operator-name").value)) $("#welcome-layer").hidden = true;
      else toast("Name required", "Enter a name for your local welcome label.", true);
    });
    $("#operator-name").addEventListener("keydown", event => { if (event.key === "Enter") $("#save-operator-name").click(); });
    $("#settings-operator-name").addEventListener("change", event => applyOperatorName(event.target.value));
    $("#desktop-install-button").addEventListener("click", installDesktopShortcut);
    $("#desktop-install-settings").addEventListener("click", installDesktopShortcut);
    $$('[data-accent]').forEach(button => button.addEventListener("click", () => setAccent(button.dataset.accent)));
    $("#custom-accent").addEventListener("input", event => setCustomAccent(event.target.value));
    $("#custom-background").value = localStorage.getItem("cros-background") || "#090b14";
    setCustomBackground($("#custom-background").value, false);
    $("#custom-background").addEventListener("input", event => setCustomBackground(event.target.value));
    $("#custom-stars").value = localStorage.getItem("cros-star-color") || "#9ca9ff";
    setStarColor($("#custom-stars").value, false);
    $("#custom-stars").addEventListener("input", event => setStarColor(event.target.value));
    $("#particle-toggle").addEventListener("click", () => toggleSetting("#particle-toggle", "no-particles", "cros-particles", true));
    $("#wing-toggle").addEventListener("click", () => toggleSetting("#wing-toggle", "no-wings", "cros-wings", true));
    $("#compact-toggle").addEventListener("click", () => { toggleSetting("#compact-toggle", "compact", "cros-compact"); renderTools(); });
    $("#animation-toggle").addEventListener("click", () => toggleSetting("#animation-toggle", "no-animations", "cros-animations", true));
    $("#glow-range").addEventListener("input", event => setGlow(event.target.value));
    $("#motion-range").addEventListener("input", event => setMotion(event.target.value));
    $("#particle-density").addEventListener("input", event => setParticleDensity(event.target.value));
    $("#light-smoothing").addEventListener("input", event => setLightSmoothing(event.target.value));
    $("#star-brightness").addEventListener("input", event => setStarBrightness(event.target.value));
    $$('[data-shape]').forEach(button => button.addEventListener("click", () => setShape(button.dataset.shape)));
    $$('[data-columns]').forEach(button => button.addEventListener("click", () => setColumns(button.dataset.columns)));
    $$('[data-screen-fit]').forEach(button => button.addEventListener("click", () => setScreenFit(button.dataset.screenFit)));
    $$('[data-interface-preset]').forEach(button => button.addEventListener("click", () => setInterfacePreset(button.dataset.interfacePreset)));
    $$('[data-logo-style]').forEach(button => button.addEventListener("click", () => changeLogoStyle(button.dataset.logoStyle)));
    $("#custom-logo-file").addEventListener("change", event => useCustomLogo(event.target.files?.[0]));
    $("#reset-appearance").addEventListener("click", () => {
      ["cros-interface-preset", "cros-accent", "cros-custom-accent", "cros-background", "cros-star-color", "cros-particles", "cros-wings", "cros-compact", "cros-animations", "cros-glow", "cros-motion", "cros-particle-density", "cros-light-smoothing", "cros-star-brightness", "cros-shape", "cros-columns", "cros-screen-fit", "cros-logo-style"].forEach(key => localStorage.removeItem(key));
      document.body.classList.remove("no-particles", "no-wings", "no-animations", "compact", "fixed-columns");
      restoreSettings();
      changeLogoStyle("original");
      renderTools();
      toast("Appearance reset", "The original CROS interface settings are restored.");
    });
    $$(`#settings-drawer input, #settings-drawer select, #settings-drawer .toggle, #settings-drawer [data-accent], #settings-drawer [data-shape], #settings-drawer [data-columns], #settings-drawer [data-screen-fit], #settings-drawer [data-interface-preset]`).forEach(control => {
      ["input", "change", "click"].forEach(type => control.addEventListener(type, () => setTimeout(queueAppearanceSave, 0)));
    });
    let clearArmed = false, clearTimer = 0;
    $("#clear-local-data").addEventListener("click", async () => {
      if (!clearArmed) { clearArmed = true; $("#clear-local-data").textContent = "CLICK AGAIN TO CLEAR"; clearTimer = setTimeout(() => { clearArmed = false; $("#clear-local-data").textContent = "CLEAR LOCAL CROS DATA"; }, 5000); return; }
      clearArmed = false; clearTimeout(clearTimer); $("#clear-local-data").textContent = "CLEARING…";
      try {
        await api("/api/clear-local-data", { method: "POST", body: "{}" });
        Object.keys(localStorage).filter(key => key.startsWith("cros-")).forEach(key => localStorage.removeItem(key));
        $("#clear-local-data").textContent = "CLEAR LOCAL CROS DATA"; toast("Local data cleared", "Cros saved state and preferences were removed.");
      } catch (error) { toast("Could not clear local data", error.message, true); }
    });
    $("#profile-export").addEventListener("click", exportProfile); $("#profile-import-file").addEventListener("change", importProfile);
    $("#wing-core").addEventListener("click", () => toggleWingDeck());
    $("#wing-tools").addEventListener("click", () => {
      toggleWingDeck(false);
      setFilter("all");
      $("#tools").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    $$('[data-view]').forEach(button => button.addEventListener("click", () => {
      const view = button.dataset.view;
      $$('[data-view]').forEach(item => item.classList.toggle("active", item === button));
      if (view === "home") scrollTo({ top: 0, behavior: "smooth" });
      if (view === "pinboard") $("#pinboard").scrollIntoView({ behavior: "smooth", block: "start" });
      if (view === "investigate") openWorkspace("research");
      if (view === "map") openWorkspace("map");
      if (view === "tools") {
        setFilter("all");
        $("#tools").scrollIntoView({ behavior: "smooth", block: "start" });
      }
      if (view === "security") {
        setFilter("security");
        $("#tools").scrollIntoView({ behavior: "smooth", block: "start" });
      }
      if (view === "guide") {
        openLearning("", "tutorials");
      }
      if (view === "sources") {
        openLearning("", "sources");
      }
    }));
    $$('[data-scroll]').forEach(button => button.addEventListener("click", () => scrollTo({ top: 0, behavior: "smooth" })));
    $("#guide-button").addEventListener("click", () => openLearning("", "tutorials"));
    $$('[data-open]').forEach(button => button.addEventListener("click", () => openTarget(button.dataset.open)));
    $("#exit-button").addEventListener("click", async () => {
      await Promise.allSettled([saveAppearanceNow(), saveWorkspaceNow()]);
      try { await api("/api/shutdown", { method: "POST", body: "{}" }); } catch (_) {}
      window.close();
      setTimeout(() => { if (!document.hidden) location.replace("about:blank"); }, 350);
    });

    addEventListener("pagehide", () => {
      saveAppearanceNow();
      saveWorkspaceNow();
    });
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") {
        saveAppearanceNow();
        saveWorkspaceNow();
      }
    });
  }

  async function openTarget(target) {
    try { await api("/api/open", { method: "POST", body: JSON.stringify({ target }) }); }
    catch (error) { toast("Could not open item", error.message, true); }
  }

  async function init() {
    // Always reopen on the Home view; Settings is never a persisted startup screen.
    setSettingsOpen(false);
    window.scrollTo(0, 0);
    setupWorkspaceDock();
    await restoreAppearanceFromServer();
    restoreSettings();
    restoreOperatorName();
    renderPins();
    renderPinnedTools();
    renderGraph();
    bindEvents();
    bindPointerGlow();
    initParticles();
    try {
      await loadWorkspace();
      await Promise.all([loadCatalog(), loadLearning(), loadUsernameProviders()]);
      renderLessonList();
      renderSourceGrid();
      renderPathways();
      updateLearningProgress();
    }
    catch (error) { toast("Tool index unavailable", error.message, true); }
    refreshStatus(false);
    setInterval(() => api("/api/ping", { method: "POST", body: "{}" }).catch(() => {}), 15000);
  }

  init();
})();
