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

  function saveToolPreferences() {
    localStorage.setItem("cros-favorite-tools", JSON.stringify([...state.favoriteTools]));
    localStorage.setItem("cros-recent-tools", JSON.stringify(state.recentTools));
  }

  function toggleFavorite(tool) {
    const saved = state.favoriteTools.has(tool.key);
    if (saved) state.favoriteTools.delete(tool.key);
    else state.favoriteTools.add(tool.key);
    saveToolPreferences();
    renderTools();
    toast(saved ? "Removed from saved" : "Tool saved", `${tool.name} ${saved ? "was removed from" : "was added to"} your saved tools.`);
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
    save.textContent = saved ? "SAVED" : "SAVE";
    save.setAttribute("aria-pressed", String(saved));
    save.setAttribute("aria-label", `${saved ? "Remove" : "Add"} ${tool.name} ${saved ? "from" : "to"} saved tools`);
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
    if (tool.key === "advanced:20" || tool.key === "security:24") {
      recordRecent(tool);
      openLearning(tool.key === "security:24" ? "security:1" : "osint:1", "tutorials");
      closeCommand();
      return;
    }
    try {
      await api("/api/launch", { method: "POST", body: JSON.stringify({ category: tool.category, id: tool.id }) });
      recordRecent(tool);
      toast("Tool launched", `${tool.name} opened in a dedicated result window.`);
      closeCommand();
    } catch (error) {
      toast("Launch blocked", error.message, true);
    }
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
    localStorage.setItem("cros-pinboard", JSON.stringify(state.pins));
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
    $("#pinboard-count").textContent = `${pins.length} ${pins.length === 1 ? "ITEM" : "ITEMS"}`;
    $("#pin-mini-label").textContent = `${pins.length} ${pins.length === 1 ? "PIN" : "PINS"}`;
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
      if (event.key === "Escape") { closeCommand(); $("#detail-layer").hidden = true; $("#settings-drawer").classList.remove("open"); }
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
    $("#terminal-button").addEventListener("click", async () => {
      try { await api("/api/launch", { method: "POST", body: JSON.stringify({ category: "terminal", id: "main" }) }); toast("Terminal mode launched", "The original wings and complete menu are open."); }
      catch (error) { toast("Launch blocked", error.message, true); }
    });
    $("#guide-button").addEventListener("click", () => openLearning("", "tutorials"));
    $$('[data-open]').forEach(button => button.addEventListener("click", () => openTarget(button.dataset.open)));
    $("#exit-button").addEventListener("click", async () => { try { await api("/api/shutdown", { method: "POST", body: "{}" }); } catch (_) {} window.close(); });
  }

  async function openTarget(target) {
    try { await api("/api/open", { method: "POST", body: JSON.stringify({ target }) }); }
    catch (error) { toast("Could not open item", error.message, true); }
  }

  async function init() {
    restoreSettings();
    renderPins();
    bindEvents();
    bindPointerGlow();
    initParticles();
    try {
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
