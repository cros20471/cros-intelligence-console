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
    imageResult: null,
    workspaceView: "research",
    workspaceHomeView: "research",
    identityToolId: "1",
    sessionId: "",
    sessionOffset: 0,
    sessionPoll: 0,
    sessionDone: true,
  };

  const $ = (selector, root = document) => root.querySelector(selector);
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
    if (tool.key === "advanced:20" || tool.key === "security:24") {
      recordRecent(tool);
      openLearning(tool.key === "security:24" ? "security:1" : "osint:1", "tutorials");
      closeCommand();
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

  function researchButton(item) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "research-link";
    button.innerHTML = `<span>${item.name}</span><b>OPEN ↗</b>`;
    button.addEventListener("click", () => openResearchUrl(item.url));
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
    $("#workspace-restore").hidden = true;
    setWorkspaceView(view);
  }

  function closeWorkspace() {
    const dock = $("#workspace-dock");
    dock.hidden = true;
    dock.setAttribute("aria-hidden", "true");
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
    setWorkspaceTabSize(localStorage.getItem("cros-workspace-tab-size") || "normal", false);
    setWorkspaceHomeView(localStorage.getItem("cros-workspace-home-view") || "research", false);
    setWorkspaceView(state.workspaceHomeView);
  }

  let workspaceResizing = false;
  function handleWorkspaceResize(event) {
    if (!workspaceResizing || innerWidth <= 880) return;
    setWorkspaceWidth(innerWidth - event.clientX);
  }

  function resizeWorkspaceBy(delta) {
    if (innerWidth <= 880) return;
    const current = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--workspace-width")) || 570;
    setWorkspaceWidth(current + delta);
  }

  function toggleWorkspaceSize() {
    const dock = $("#workspace-dock");
    const expanded = dock.classList.toggle("expanded");
    $("#workspace-size").textContent = expanded ? "▣" : "□";
    $("#workspace-size").setAttribute("aria-label", expanded ? "Restore workspace size" : "Maximize workspace");
  }

  function formatSessionTime(milliseconds) {
    return `${(Math.max(0, milliseconds) / 1000).toFixed(1)}s`;
  }

  function updateSessionProgress(payload = {}) {
    const progress = $("#session-progress");
    const done = Boolean(payload.done);
    const failed = done && Number(payload.returncode || 0) !== 0;
    progress.classList.toggle("running", !done);
    progress.classList.toggle("complete", done && !failed);
    progress.classList.toggle("failed", failed);
    progress.setAttribute("aria-valuetext", !done ? "Running live" : failed ? "Finished with an error" : "Complete");
    $("#session-status").textContent = !done ? "LIVE" : failed ? "REVIEW" : "COMPLETE";
    $("#session-stage").textContent = payload.stage || (!done ? "Working" : "Complete");
    $("#session-time").textContent = formatSessionTime(payload.elapsed_ms || 0);
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
      updateSessionProgress(payload);
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

  async function startToolSession(category, id, options = {}) {
    await stopActiveSession(false);
    clearTimeout(state.sessionPoll);
    openWorkspace("session");
    $("#session-title").textContent = options.title || "Tool session";
    $("#session-output").textContent = "Starting inside Cros…";
    state.sessionId = "";
    state.sessionOffset = 0;
    state.sessionDone = false;
    updateSessionProgress({ done: false, stage: "Starting local tool", elapsed_ms: 0 });
    try {
      const payload = await api("/api/session/start", {
        method: "POST",
        body: JSON.stringify({ category, id, username: options.username || "" }),
      });
      state.sessionId = payload.id;
      pollToolSession();
    } catch (error) {
      state.sessionDone = true;
      $("#session-output").textContent = error.message;
      updateSessionProgress({ done: true, returncode: 1, stage: "Could not start" });
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
      input.focus();
    } catch (error) {
      toast("Input was not sent", error.message, true);
    }
  }

  async function searchNames(event) {
    event.preventDefault();
    const query = $("#name-search-query").value.trim();
    if (!query) return;
    $("#name-search-loading").hidden = false;
    try {
      const root = $("#name-results");
      root.replaceChildren();
      const status = document.createElement("div");
      status.className = "blackbird-live-note";
      status.innerHTML = "<strong>BLACKBIRD LIVE SESSION</strong><span>Results are streaming in Tool Session. Only accounts returned by the installed engine are shown.</span>";
      root.append(status);
      const toolId = state.identityToolId === "2" ? "2" : "1";
      const label = toolId === "2" ? "Blackbird variations" : "Blackbird";
      await startToolSession("osint", toolId, { username: query, title: `${label} · ${query}` });
    } catch (error) {
      toast("Blackbird search unavailable", error.message, true);
    } finally {
      $("#name-search-loading").hidden = true;
    }
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
    const node = state.graph.nodes.find(item => item.id === id);
    const panel = $("#map-selection");
    panel.hidden = !node;
    if (node) {
      $("#selected-node-label").textContent = node.label;
      $("#selected-node-meta").textContent = node.type.toUpperCase();
      $("#selected-node-note").textContent = node.note || "No context added.";
    }
    $$(".neural-node", $("#neural-map")).forEach(item => item.classList.toggle("selected", item.dataset.nodeId === id));
  }

  function renderGraph() {
    const svg = $("#neural-map");
    if (!svg) return;
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
      const path = svgElement("path", { d: `M ${source.x} ${source.y} Q ${middleX} ${middleY} ${target.x} ${target.y}`, class: "neural-edge" });
      svg.append(path);
      if (edge.label) {
        const label = svgElement("text", { x: middleX, y: middleY - 8, class: "neural-edge-label", "text-anchor": "middle" });
        label.textContent = edge.label;
        svg.append(label);
      }
    });
    state.graph.nodes.forEach(node => {
      node.y = Math.max(32, Math.min(388, Number(node.y) || 210));
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
        draggingNode = node.id;
        selectGraphNode(node.id);
      });
      svg.append(group);
    });
    $("#map-empty").hidden = Boolean(state.graph.nodes.length);
    $("#map-count").textContent = `${state.graph.nodes.length} ${state.graph.nodes.length === 1 ? "NODE" : "NODES"}`;
    updateNodeSelectors();
    if (state.selectedNode && !nodeMap.has(state.selectedNode)) selectGraphNode("");
  }

  let draggingNode = "";
  function handleGraphPointerMove(event) {
    if (!draggingNode) return;
    const node = state.graph.nodes.find(item => item.id === draggingNode);
    if (!node) return;
    const point = graphPoint(event);
    node.x = Math.max(48, Math.min(952, Math.round(point.x)));
    node.y = Math.max(32, Math.min(388, Math.round(point.y)));
    renderGraph();
  }

  function finishGraphDrag() {
    if (!draggingNode) return;
    draggingNode = "";
    persistWorkspace();
  }

  function addGraphNode(event) {
    event.preventDefault();
    const label = $("#node-label").value.trim();
    if (!label) return;
    const index = state.graph.nodes.length;
    const angle = index * 2.399;
    const radius = index ? Math.min(205, 82 + index * 15) : 0;
    state.graph.nodes.push({
      id: crypto.randomUUID ? crypto.randomUUID() : `node-${Date.now()}-${Math.random()}`,
      label,
      type: $("#node-type").value,
      note: $("#node-note").value.trim(),
      x: Math.round(500 + Math.cos(angle) * radius),
      y: Math.round(210 + Math.sin(angle) * Math.min(radius, 160)),
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
    state.graph.nodes = state.graph.nodes.filter(node => node.id !== id);
    state.graph.edges = state.graph.edges.filter(edge => edge.source !== id && edge.target !== id);
    state.selectedNode = "";
    persistWorkspace();
    renderGraph();
    selectGraphNode("");
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
    $$('[data-accent]').forEach(button => button.classList.remove("active"));
    localStorage.setItem("cros-accent", "custom");
    localStorage.setItem("cros-custom-accent", hex);
  }

  function toggleSetting(id, bodyClass, storageKey, invert = false) {
    const button = $(id);
    const active = !button.classList.contains("active");
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
    document.body.classList.toggle(bodyClass, invert ? !active : active);
    localStorage.setItem(storageKey, String(active));
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

  function restoreSettings() {
    const accent = localStorage.getItem("cros-accent") || "violet";
    if (accent === "custom") {
      const custom = localStorage.getItem("cros-custom-accent") || "#8566ff";
      $("#custom-accent").value = custom;
      setCustomAccent(custom);
    } else setAccent(accent);
    const particles = localStorage.getItem("cros-particles") !== "false";
    const wings = localStorage.getItem("cros-wings") !== "false";
    const compact = localStorage.getItem("cros-compact") === "true";
    $("#particle-toggle").classList.toggle("active", particles);
    $("#particle-toggle").setAttribute("aria-pressed", String(particles));
    document.body.classList.toggle("no-particles", !particles);
    $("#wing-toggle").classList.toggle("active", wings);
    $("#wing-toggle").setAttribute("aria-pressed", String(wings));
    document.body.classList.toggle("no-wings", !wings);
    $("#compact-toggle").classList.toggle("active", compact);
    $("#compact-toggle").setAttribute("aria-pressed", String(compact));
    document.body.classList.toggle("compact", compact);
    setGlow(localStorage.getItem("cros-glow") || 70, false);
    setMotion(localStorage.getItem("cros-motion") || 100, false);
    setShape(localStorage.getItem("cros-shape") || "soft", false);
    setColumns(localStorage.getItem("cros-columns") || "auto", false);
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

    function frame() {
      if (document.hidden || document.body.classList.contains("no-particles")) {
        requestAnimationFrame(frame);
        return;
      }
      context.clearRect(0, 0, width, height);
      const accent = getComputedStyle(document.documentElement).getPropertyValue("--accent-rgb").trim() || "133,102,255";
      particles.forEach((particle, index) => {
        particle.x += particle.vx; particle.y += particle.vy;
        if (particle.x < -10) particle.x = width + 10; if (particle.x > width + 10) particle.x = -10;
        if (particle.y < -10) particle.y = height + 10; if (particle.y > height + 10) particle.y = -10;
        const distance = Math.hypot(pointer.x - particle.x, pointer.y - particle.y);
        const boost = distance < 150 ? (150 - distance) / 150 : 0;
        context.beginPath(); context.arc(particle.x, particle.y, particle.r + boost * 1.2, 0, Math.PI * 2);
        context.fillStyle = `rgba(${accent},${particle.a + boost * .35})`; context.fill();
        if (index % 7 === 0 && boost > .25) {
          context.beginPath(); context.moveTo(particle.x, particle.y); context.lineTo(pointer.x, pointer.y);
          context.strokeStyle = `rgba(${accent},${boost * .08})`; context.stroke();
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
    $("#name-search-form").addEventListener("submit", searchNames);
    $("#image-scan-form").addEventListener("submit", scanImage);
    $("#image-file").addEventListener("change", event => { $("#image-file-label").textContent = event.target.files[0]?.name || "Choose image"; });
    $("#image-scan-mode").addEventListener("change", renderImageResult);
    $("#session-input-form").addEventListener("submit", sendSessionInput);
    $("#session-stop").addEventListener("click", () => stopActiveSession(true));
    $$('[data-workspace-tab]').forEach(button => button.addEventListener("click", () => setWorkspaceView(button.dataset.workspaceTab)));
    $("#workspace-close").addEventListener("click", closeWorkspace);
    $("#workspace-restore").addEventListener("click", () => openWorkspace());
    $("#workspace-customize").addEventListener("click", toggleWorkspaceSettings);
    $("#workspace-size").addEventListener("click", toggleWorkspaceSize);
    $("#workspace-width-control").addEventListener("input", event => setWorkspaceWidth(event.target.value));
    $$('[data-workspace-tab-size]').forEach(button => button.addEventListener("click", () => setWorkspaceTabSize(button.dataset.workspaceTabSize)));
    $("#workspace-home-view").addEventListener("change", event => setWorkspaceHomeView(event.target.value));
    $("#workspace-resize-handle").addEventListener("pointerdown", event => { event.preventDefault(); workspaceResizing = true; });
    $("#workspace-resize-handle").addEventListener("keydown", event => {
      if (event.key === "ArrowLeft") { event.preventDefault(); resizeWorkspaceBy(24); }
      if (event.key === "ArrowRight") { event.preventDefault(); resizeWorkspaceBy(-24); }
    });
    addEventListener("pointermove", handleGraphPointerMove);
    addEventListener("pointermove", handleWorkspaceResize);
    addEventListener("pointerup", finishGraphDrag);
    addEventListener("pointerup", () => { workspaceResizing = false; });
    addEventListener("pointercancel", finishGraphDrag);
    addEventListener("pointercancel", () => { workspaceResizing = false; });
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
    $$('[data-close-command]').forEach(button => button.addEventListener("click", closeCommand));
    $("#command-search").addEventListener("input", () => { state.commandIndex = 0; renderCommandResults(); });
    $("#command-search").addEventListener("keydown", event => {
      if (event.key === "ArrowDown") { event.preventDefault(); state.commandIndex = Math.min(state.commandMatches.length - 1, state.commandIndex + 1); renderCommandResults(); }
      if (event.key === "ArrowUp") { event.preventDefault(); state.commandIndex = Math.max(0, state.commandIndex - 1); renderCommandResults(); }
      if (event.key === "Enter" && state.commandMatches[state.commandIndex]) { event.preventDefault(); launchTool(state.commandMatches[state.commandIndex]); }
    });
    addEventListener("keydown", event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); openCommand(); }
      if (event.key === "Escape") { closeCommand(); $("#detail-layer").hidden = true; $("#settings-drawer").classList.remove("open"); closeWorkspace(); }
    });
    $("#settings-button").addEventListener("click", () => $("#settings-drawer").classList.add("open"));
    $("#search-settings").addEventListener("click", () => $("#settings-drawer").classList.add("open"));
    $("#settings-close").addEventListener("click", () => $("#settings-drawer").classList.remove("open"));
    $$('[data-accent]').forEach(button => button.addEventListener("click", () => setAccent(button.dataset.accent)));
    $("#custom-accent").addEventListener("input", event => setCustomAccent(event.target.value));
    $("#particle-toggle").addEventListener("click", () => toggleSetting("#particle-toggle", "no-particles", "cros-particles", true));
    $("#wing-toggle").addEventListener("click", () => toggleSetting("#wing-toggle", "no-wings", "cros-wings", true));
    $("#compact-toggle").addEventListener("click", () => { toggleSetting("#compact-toggle", "compact", "cros-compact"); renderTools(); });
    $("#glow-range").addEventListener("input", event => setGlow(event.target.value));
    $("#motion-range").addEventListener("input", event => setMotion(event.target.value));
    $$('[data-shape]').forEach(button => button.addEventListener("click", () => setShape(button.dataset.shape)));
    $$('[data-columns]').forEach(button => button.addEventListener("click", () => setColumns(button.dataset.columns)));
    $("#reset-appearance").addEventListener("click", () => {
      ["cros-accent", "cros-custom-accent", "cros-particles", "cros-wings", "cros-compact", "cros-glow", "cros-motion", "cros-shape", "cros-columns"].forEach(key => localStorage.removeItem(key));
      document.body.classList.remove("no-particles", "no-wings", "compact", "fixed-columns");
      restoreSettings();
      renderTools();
      toast("Appearance reset", "The original CROS interface settings are restored.");
    });
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
    $("#terminal-button").addEventListener("click", () => startToolSession("terminal", "main", { title: "Complete Cros menu" }));
    $("#guide-button").addEventListener("click", () => openLearning("", "tutorials"));
    $$('[data-open]').forEach(button => button.addEventListener("click", () => openTarget(button.dataset.open)));
    $("#exit-button").addEventListener("click", async () => { try { await api("/api/shutdown", { method: "POST", body: "{}" }); } catch (_) {} window.close(); });
  }

  async function openTarget(target) {
    try { await api("/api/open", { method: "POST", body: JSON.stringify({ target }) }); }
    catch (error) { toast("Could not open item", error.message, true); }
  }

  async function init() {
    setupWorkspaceDock();
    restoreSettings();
    renderPins();
    renderPinnedTools();
    renderGraph();
    bindEvents();
    bindPointerGlow();
    initParticles();
    try {
      await loadWorkspace();
      await Promise.all([loadCatalog(), loadLearning()]);
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
