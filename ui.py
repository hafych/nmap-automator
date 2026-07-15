UI_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nmap Automator Console</title>
  <style>
    :root {
      --bg: #eef2ee;
      --ink: #1e2520;
      --muted: #66736a;
      --panel: #fbfcf8;
      --line: #ccd6cc;
      --accent: #087f5b;
      --accent-2: #9a5b00;
      --danger: #a11d1d;
      --ok: #146c43;
      --shadow: 0 12px 32px rgba(30, 37, 32, .12);
      --radius: 6px;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: "IBM Plex Sans", "Aptos", "Segoe UI", sans-serif;
      background:
        linear-gradient(135deg, rgba(8, 127, 91, .13), transparent 28rem),
        linear-gradient(315deg, rgba(154, 91, 0, .16), transparent 24rem),
        repeating-linear-gradient(0deg, rgba(30,37,32,.045), rgba(30,37,32,.045) 1px, transparent 1px, transparent 28px),
        var(--bg);
    }

    button, input, select, textarea {
      font: inherit;
    }

    button {
      min-height: 44px;
      border: 1px solid var(--ink);
      border-radius: var(--radius);
      background: var(--ink);
      color: #fff;
      padding: 0 14px;
      cursor: pointer;
    }

    button.secondary {
      background: var(--panel);
      color: var(--ink);
      border-color: var(--line);
    }

    button.danger {
      background: var(--danger);
      border-color: var(--danger);
    }

    button:disabled {
      opacity: .55;
      cursor: wait;
    }

    .shell {
      width: min(1280px, calc(100% - 32px));
      margin: 0 auto;
      padding: 24px 0 32px;
    }

    .topbar {
      display: grid;
      gap: 16px;
      grid-template-columns: 1fr auto;
      align-items: end;
      margin-bottom: 18px;
    }

    h1 {
      margin: 0;
      font-size: clamp(28px, 5vw, 54px);
      line-height: .95;
      letter-spacing: 0;
      max-width: 760px;
    }

    .status-strip {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      justify-content: flex-end;
    }

    .pill {
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(251, 252, 248, .78);
      padding: 7px 10px;
      color: var(--muted);
      white-space: nowrap;
    }

    .pill strong {
      color: var(--ink);
      font-weight: 700;
    }

    .grid {
      display: grid;
      gap: 16px;
      grid-template-columns: 420px 1fr;
      align-items: start;
    }

    .panel {
      background: rgba(251, 252, 248, .9);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }

    .panel header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      border-bottom: 1px solid var(--line);
      padding: 14px 16px;
    }

    .panel h2 {
      margin: 0;
      font-size: 17px;
      letter-spacing: 0;
    }

    .panel-body {
      padding: 16px;
    }

    label {
      display: grid;
      gap: 6px;
      margin-bottom: 12px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }

    input, select, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: #fff;
      color: var(--ink);
      padding: 10px 11px;
    }

    input, select { min-height: 44px; }

    :focus-visible {
      outline: 3px solid #0b6bcb;
      outline-offset: 2px;
    }

    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }

    textarea {
      min-height: 320px;
      resize: vertical;
      font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      font-size: 13px;
      line-height: 1.45;
    }

    .row {
      display: grid;
      gap: 10px;
      grid-template-columns: 1fr 1fr;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
    }

    .hint {
      margin: 10px 0 0;
      color: var(--muted);
      font-size: 13px;
    }

    .workspace {
      display: grid;
      gap: 16px;
    }

    .tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .tabs button {
      background: #fff;
      color: var(--ink);
      border-color: var(--line);
      min-height: 44px;
    }

    .tabs button.active {
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
    }

    .task-list {
      display: grid;
      gap: 8px;
    }

    .task {
      display: grid;
      gap: 10px;
      grid-template-columns: 1fr auto;
      align-items: center;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: #fff;
    }

    .task code {
      display: block;
      overflow-wrap: anywhere;
      font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      font-size: 13px;
    }

    .mini {
      color: var(--muted);
      font-size: 12px;
      margin-top: 3px;
    }

    .empty {
      color: var(--muted);
      border: 1px dashed var(--line);
      border-radius: var(--radius);
      padding: 16px;
      background: rgba(255,255,255,.55);
    }

    .result-head {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
    }

    .metric-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-bottom: 14px;
    }

    .metric {
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 12px;
      background: #fff;
    }

    .metric b {
      display: block;
      font-size: 22px;
      margin-bottom: 2px;
    }

    .metric span {
      color: var(--muted);
      font-size: 12px;
    }

    .toast {
      min-height: 20px;
      margin-top: 12px;
      color: var(--accent-2);
      font-weight: 700;
    }

    @media (max-width: 920px) {
      .topbar, .grid {
        grid-template-columns: 1fr;
      }
      .status-strip {
        justify-content: flex-start;
      }
      .metric-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <div class="topbar">
      <div>
        <h1>Nmap Operator Console</h1>
        <p class="hint">Authorized network scanning, task control, and AI-readable output.</p>
      </div>
      <div class="status-strip" id="statusStrip" aria-live="polite">
        <span class="pill">API <strong id="apiStatus">checking</strong></span>
        <span class="pill">Nmap <strong id="nmapStatus">unknown</strong></span>
        <span class="pill">Tasks <strong id="taskCount">0</strong></span>
      </div>
    </div>

    <section class="grid">
      <aside class="panel">
        <header>
          <h2>Scan Control</h2>
          <button class="secondary" id="refreshBtn" type="button">Refresh</button>
        </header>
        <div class="panel-body">
          <label>API token
            <input id="apiToken" type="password" autocomplete="off" placeholder="X-API-KEY">
          </label>
          <label>Target
            <input id="target" value="127.0.0.1" spellcheck="false">
          </label>
          <div class="row">
            <label>Scan type
              <select id="scanType">
                <option>Ping</option>
                <option selected>TCP</option>
                <option>SYN</option>
                <option>UDP</option>
                <option>OS</option>
                <option>Aggressive</option>
              </select>
            </label>
            <label>Interval minutes
              <input id="interval" type="number" value="30" min="1" step="1">
            </label>
          </div>
          <div class="actions">
            <button id="scanBtn" type="button">Run Scan</button>
            <button class="secondary" id="scheduleBtn" type="button">Schedule</button>
          </div>
          <p class="hint">The token stays in browser session storage. Results are returned by the existing API.</p>
          <div class="toast" id="toast" role="status" aria-live="polite" aria-atomic="true"></div>
        </div>
      </aside>

      <div class="workspace">
        <section class="panel">
          <header>
            <h2>Active Tasks</h2>
            <span class="pill"><strong id="runningCount">0</strong> running</span>
          </header>
          <div class="panel-body">
            <div class="task-list" id="tasks"></div>
          </div>
        </section>

        <section class="panel">
          <header>
            <h2>Tool Inventory</h2>
            <span class="pill"><strong id="toolAvailable">0</strong> ready</span>
          </header>
          <div class="panel-body">
            <p class="hint">Checks official Kali metapackages, local packages, and commands; formats the result for GPT/Claude.</p>
            <div class="actions">
              <button id="toolsBtn" type="button">Refresh Tools</button>
              <button class="secondary" id="copyToolsBtn" type="button">Copy AI Context</button>
            </div>
            <div class="metric-grid">
              <div class="metric"><b id="toolChecked">0</b><span>checked</span></div>
              <div class="metric"><b id="toolMissing">0</b><span>missing</span></div>
              <div class="metric"><b id="toolProfiles">0</b><span>profiles</span></div>
            </div>
            <label class="sr-only" for="toolsBox">Tool inventory output</label>
            <textarea id="toolsBox" readonly placeholder="Refresh to build a Kali tool inventory and AI handoff."></textarea>
          </div>
        </section>

        <section class="panel">
          <header>
            <h2>Result Workspace</h2>
            <div class="tabs" role="tablist" aria-label="Result view">
              <button class="active" data-view="summary" type="button" role="tab" aria-selected="true" aria-controls="resultBox">Summary</button>
              <button data-view="json" type="button" role="tab" aria-selected="false" aria-controls="resultBox">JSON</button>
              <button data-view="jsonl" type="button" role="tab" aria-selected="false" aria-controls="resultBox">JSONL</button>
              <button data-view="plan" type="button" role="tab" aria-selected="false" aria-controls="resultBox">Recon Plan</button>
            </div>
          </header>
          <div class="panel-body">
            <div class="metric-grid">
              <div class="metric"><b id="hostMetric">0</b><span>hosts</span></div>
              <div class="metric"><b id="upMetric">0</b><span>up</span></div>
              <div class="metric"><b id="openMetric">0</b><span>open ports</span></div>
            </div>
            <div class="result-head">
              <span class="hint" id="resultLabel">No scan result yet.</span>
              <div class="actions">
                <button class="secondary" id="planBtn" type="button">Build Plan</button>
                <button class="secondary" id="copyBtn" type="button">Copy View</button>
              </div>
            </div>
            <label class="sr-only" for="resultBox">Selected scan result view</label>
            <textarea id="resultBox" role="tabpanel" readonly></textarea>
          </div>
        </section>
      </div>
    </section>
  </main>

  <script>
    const state = {
      lastResult: null,
      lastPlan: null,
      toolsContext: "",
      view: "summary",
      apiHeader: "X-API-KEY",
    };
    const $ = (id) => document.getElementById(id);

    const tokenInput = $("apiToken");
    tokenInput.value = sessionStorage.getItem("nmap_api_token") || "";
    tokenInput.addEventListener("input", () => sessionStorage.setItem("nmap_api_token", tokenInput.value));

    function headers() {
      const token = tokenInput.value.trim();
      return token
        ? { "Content-Type": "application/json", [state.apiHeader]: token }
        : { "Content-Type": "application/json" };
    }

    function setBusy(isBusy) {
      $("scanBtn").disabled = isBusy;
      $("scheduleBtn").disabled = isBusy;
      $("refreshBtn").disabled = isBusy;
      $("toolsBtn").disabled = isBusy;
      $("planBtn").disabled = isBusy;
    }

    function say(message, isError = false) {
      const toast = $("toast");
      toast.textContent = message;
      toast.style.color = isError ? "var(--danger)" : "var(--accent-2)";
    }

    async function api(path, options = {}) {
      const response = await fetch(path, { ...options, headers: { ...headers(), ...(options.headers || {}) } });
      const text = await response.text();
      let body;
      try { body = text ? JSON.parse(text) : null; } catch { body = text; }
      if (!response.ok) {
        const detail = body && body.error ? body.error : response.statusText;
        throw new Error(`${response.status}: ${detail}`);
      }
      return body;
    }

    function observations(result) {
      if (!result || !Array.isArray(result.hosts)) return [];
      const rows = [];
      for (const host of result.hosts) {
        rows.push({ type: "host", host: host.host, hostname: host.hostname, state: host.state });
        for (const [protocol, ports] of Object.entries(host.protocols || {})) {
          for (const port of ports) {
            rows.push({
              type: "service",
              host: host.host,
              protocol,
              port: port.port,
              state: port.state,
              service: { name: port.name, product: port.product, version: port.version },
              llm_hint: `${host.host} has ${protocol}/${port.port} ${port.state} (${port.name || "unknown"})`
            });
          }
        }
      }
      return rows;
    }

    function metrics(result) {
      const hosts = Array.isArray(result?.hosts) ? result.hosts : [];
      const openPorts = observations(result).filter((row) => row.type === "service" && row.state === "open").length;
      $("hostMetric").textContent = hosts.length;
      $("upMetric").textContent = hosts.filter((host) => host.state === "up").length;
      $("openMetric").textContent = openPorts;
    }

    function summary(result) {
      if (!result) return "";
      const lines = [`Scan time: ${result.scan_time || "unknown"}`, ""];
      for (const host of result.hosts || []) {
        lines.push(`${host.host} (${host.state})`);
        if (host.hostname && host.hostname !== "N/A") lines.push(`  hostname: ${host.hostname}`);
        const rows = observations({ hosts: [host] }).filter((row) => row.type === "service" && row.state === "open");
        if (!rows.length) {
          lines.push("  open ports: none observed");
        } else {
          for (const row of rows) {
            const product = [row.service.product, row.service.version].filter(Boolean).join(" ");
            lines.push(`  ${row.protocol}/${row.port} ${row.service.name || "unknown"}${product ? " - " + product : ""}`);
          }
        }
        lines.push("");
      }
      return lines.join("\n").trim();
    }

    function planText(plan) {
      if (!plan) return "Build a recon plan after a scan.";
      const rows = plan.recommendations || [];
      if (!rows.length) return "No safe service-specific recon steps were identified.";
      const lines = [
        `Recon recommendations: ${(plan.summary || {}).recommendations || rows.length}`,
        `Ready: ${(plan.summary || {}).ready || 0}`,
        `Missing tools: ${(plan.summary || {}).missing || 0}`,
        "",
      ];
      for (const row of rows) {
        lines.push(`${row.host} ${row.protocol}/${row.port} ${row.service} -> ${row.tool} [${row.status}]`);
        lines.push(`  ${row.command}`);
        lines.push(`  ${row.purpose}`);
        lines.push("");
      }
      return lines.join("\n").trim();
    }

    function renderResult() {
      const result = state.lastResult;
      metrics(result);
      let content = "";
      if (state.view === "json") content = result ? JSON.stringify(result, null, 2) : "";
      if (state.view === "jsonl") content = observations(result).map((row) => JSON.stringify(row)).join("\n");
      if (state.view === "plan") content = planText(state.lastPlan);
      if (state.view === "summary") content = summary(result);
      $("resultBox").value = content;
      if (state.view === "plan") {
        $("resultLabel").textContent = state.lastPlan ? "PLAN view" : "Build a recon plan first.";
      } else if (result) {
        $("resultLabel").textContent = `${state.view.toUpperCase()} view`;
      } else {
        $("resultLabel").textContent = "No scan result yet.";
      }
    }

    async function refresh({ announce = true } = {}) {
      try {
        const docs = await api("/api/docs");
        state.apiHeader = docs?.security?.api_auth_header || "X-API-KEY";
        tokenInput.placeholder = state.apiHeader;
        const health = await api("/health", { headers: {} });
        $("apiStatus").textContent = health.status || "online";
        $("nmapStatus").textContent = health.nmap_available ? "ready" : "missing";
        const tasks = await api("/tasks");
        $("taskCount").textContent = tasks.length;
        $("runningCount").textContent = tasks.filter((task) => task.running).length;
        renderTasks(tasks);
        if (announce) say("Dashboard refreshed.");
      } catch (error) {
        $("apiStatus").textContent = "auth needed";
        say(error.message, true);
      }
    }

    function renderTasks(tasks) {
      const root = $("tasks");
      root.innerHTML = "";
      if (!tasks.length) {
        root.innerHTML = '<div class="empty">No scheduled scans.</div>';
        return;
      }
      for (const task of tasks) {
        const row = document.createElement("div");
        row.className = "task";
        row.innerHTML = `<div><code></code><div class="mini">${task.running ? "running" : "stopped"}${task.cancelled ? " / cancelled" : ""}</div></div><button class="danger" type="button">Cancel</button>`;
        row.querySelector("code").textContent = task.id;
        const cancelButton = row.querySelector("button");
        cancelButton.setAttribute("aria-label", `Cancel scheduled task ${task.id}`);
        cancelButton.addEventListener("click", async () => {
          if (!window.confirm(`Cancel scheduled task ${task.id}?`)) return;
          try {
            await api(`/tasks/${encodeURIComponent(task.id)}`, { method: "DELETE" });
            say("Task cancelled.");
            await refresh({ announce: false });
          } catch (error) {
            say(error.message, true);
          }
        });
        root.appendChild(row);
      }
    }

    function renderTools(inventory, context) {
      const summary = inventory.summary || {};
      const profiles = inventory.profiles || [];
      const missing = summary.missing_packages || [];
      state.toolsContext = context || "";
      $("toolChecked").textContent = summary.packages_checked || 0;
      $("toolAvailable").textContent = summary.available || 0;
      $("toolMissing").textContent = summary.missing || 0;
      $("toolProfiles").textContent = profiles.length;
      const visibleMissing = missing.slice(0, 16);
      const lines = [
        `Schema: ${inventory.schema || "unknown"}`,
        `Source: ${inventory.source || "local system"}`,
        `Profiles: ${profiles.map((profile) => profile.profile || profile.name).join(", ") || "none"}`,
        `Packages checked: ${summary.packages_checked || 0}`,
        `Ready: ${summary.available || 0}`,
        `Missing: ${summary.missing || 0}`,
      ];
      if (visibleMissing.length) {
        lines.push("", "Missing packages:", ...visibleMissing.map((name) => `- ${name}`));
      }
      $("toolsBox").value = lines.join("\n");
    }

    async function refreshTools() {
      setBusy(true);
      try {
        const inventory = await api("/tools?expand=0");
        const context = await api("/tools/ai-context?format=jsonl&expand=0");
        renderTools(inventory, context);
        say(`Tool inventory refreshed: ${(inventory.summary || {}).available || 0} ready.`);
      } catch (error) {
        say(error.message, true);
      } finally {
        setBusy(false);
      }
    }

    async function runScan() {
      setBusy(true);
      say("Scanning...");
      try {
        state.lastPlan = null;
        state.lastResult = await api("/scan", {
          method: "POST",
          body: JSON.stringify({ target: $("target").value, scan_type: $("scanType").value })
        });
        renderResult();
        say("Scan complete.");
        await refresh({ announce: false });
      } catch (error) {
        say(error.message, true);
      } finally {
        setBusy(false);
      }
    }

    async function buildPlan() {
      if (!state.lastResult) {
        say("Run a scan first.", true);
        return;
      }
      setBusy(true);
      try {
        state.lastPlan = await api("/recon/plan", {
          method: "POST",
          body: JSON.stringify({ scan: state.lastResult })
        });
        state.view = "plan";
        document.querySelectorAll(".tabs button").forEach((item) => {
          const selected = item.dataset.view === "plan";
          item.classList.toggle("active", selected);
          item.setAttribute("aria-selected", String(selected));
        });
        renderResult();
        say(`Recon plan built: ${(state.lastPlan.summary || {}).recommendations || 0} steps.`);
      } catch (error) {
        say(error.message, true);
      } finally {
        setBusy(false);
      }
    }

    async function scheduleScan() {
      setBusy(true);
      try {
        const body = { target: $("target").value, scan_type: $("scanType").value, interval: Number($("interval").value) };
        await api("/schedule", { method: "POST", body: JSON.stringify(body) });
        say("Scan scheduled.");
        await refresh({ announce: false });
      } catch (error) {
        say(error.message, true);
      } finally {
        setBusy(false);
      }
    }

    $("scanBtn").addEventListener("click", runScan);
    $("scheduleBtn").addEventListener("click", scheduleScan);
    $("refreshBtn").addEventListener("click", () => refresh());
    $("toolsBtn").addEventListener("click", refreshTools);
    $("planBtn").addEventListener("click", buildPlan);
    async function copyText(content, successMessage) {
      try {
        await navigator.clipboard.writeText(content);
        say(successMessage);
      } catch {
        say("Copy failed. Select the text and copy it manually.", true);
      }
    }

    $("copyToolsBtn").addEventListener("click", () =>
      copyText(state.toolsContext || $("toolsBox").value, "Copied tool AI context."));
    $("copyBtn").addEventListener("click", () =>
      copyText($("resultBox").value, "Copied current view."));

    document.querySelectorAll(".tabs button").forEach((button) => {
      button.addEventListener("click", () => {
        document.querySelectorAll(".tabs button").forEach((item) => {
          const selected = item === button;
          item.classList.toggle("active", selected);
          item.setAttribute("aria-selected", String(selected));
        });
        state.view = button.dataset.view;
        renderResult();
      });
    });

    refresh();
  </script>
</body>
</html>
"""
