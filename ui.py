UI_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Recon Operator</title>
  <style nonce="__CSP_NONCE__">
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
        <h1>Recon Operator</h1>
        <p class="hint">Multi-tool recon control plane: Nmap engine, Kali inventory, review-only planner, encrypted results.</p>
      </div>
      <div class="status-strip" id="statusStrip" aria-live="polite">
        <span class="pill">API <strong id="apiStatus">checking</strong></span>
        <span class="pill">Nmap <strong id="nmapStatus">unknown</strong></span>
        <span class="pill">Tasks <strong id="taskCount">0</strong></span>
        <span class="pill">Jobs <strong id="jobCount">0</strong></span>
        <span class="pill">Refresh <strong id="lastRefresh">never</strong></span>
        <span class="pill">Last scan <strong id="lastScanMeta">none</strong></span>
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
          <p class="hint" id="keyMeta" aria-live="polite">Key: not identified</p>
          <label>Target
            <input id="target" value="127.0.0.1" spellcheck="false">
          </label>
          <div class="row">
            <label>Scan profile
              <select id="scanType">
                <option>Ping</option>
                <option selected>TCP</option>
                <option>SYN</option>
                <option>UDP</option>
                <option>Version</option>
                <option>Safe</option>
                <option>Vuln</option>
                <option>Full</option>
                <option>Hybrid</option>
                <option>HybridNaabu</option>
                <option>HybridRustScan</option>
                <option>OS</option>
                <option>Aggressive</option>
              </select>
            </label>
            <label>Interval minutes
              <input id="interval" type="number" value="30" min="1" step="1">
            </label>
          </div>
          <div class="row">
            <label>Ports (optional)
              <input id="ports" placeholder="22,80,443 or 1-1000" spellcheck="false">
            </label>
            <label>Extra NSE (optional)
              <input id="scripts" placeholder="banner,http-title" spellcheck="false">
            </label>
          </div>
          <label>Discovery frontend (optional)
            <select id="discovery">
              <option value="" selected>none (Nmap only)</option>
              <option value="auto">auto (Naabu → RustScan)</option>
              <option value="naabu">naabu</option>
              <option value="rustscan">rustscan</option>
            </select>
          </label>
          <div class="actions">
            <button id="scanBtn" type="button">Run Scan</button>
            <button class="secondary" id="scheduleBtn" type="button">Schedule</button>
          </div>
          <label>Import Nmap XML
            <textarea id="xmlImport" rows="3" placeholder="Paste Nmap XML to import into encrypted history."></textarea>
          </label>
          <div class="actions">
            <button class="secondary" id="importBtn" type="button">Import XML</button>
            <button class="secondary" id="diffBtn" type="button">Diff last two</button>
          </div>
          <p class="hint">Token stays in session storage. Jobs + multi-tool inventory + recon plans — not Nmap-only.</p>
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
            <h2>Scan History</h2>
            <span class="pill"><strong id="historyCount">0</strong> stored</span>
          </header>
          <div class="panel-body">
            <div class="actions">
              <button class="secondary" id="historyBtn" type="button">Refresh History</button>
            </div>
            <div class="task-list" id="history"></div>
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
              <button data-view="diff" type="button" role="tab" aria-selected="false" aria-controls="resultBox">Diff</button>
            </div>
          </header>
          <div class="panel-body">
            <div class="metric-grid">
              <div class="metric"><b id="hostMetric">0</b><span>hosts</span></div>
              <div class="metric"><b id="upMetric">0</b><span>up</span></div>
              <div class="metric"><b id="openMetric">0</b><span>open ports</span></div>
              <div class="metric"><b id="serviceMetric">0</b><span>services</span></div>
            </div>
            <div id="serviceBars" class="hint" style="margin-bottom:10px"></div>
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

  <script nonce="__CSP_NONCE__">
    const state = {
      lastResult: null,
      previousResult: null,
      lastPlan: null,
      lastDiff: null,
      toolsContext: "",
      view: "summary",
      apiHeader: "X-API-KEY",
      activeJobId: null,
      historyIds: [],
      lastRefreshAt: null,
      lastScanStartedAt: null,
      lastScanFinishedAt: null,
      lastScanDurationMs: null,
    };

    function formatClock(value) {
      if (!value) return "never";
      try {
        return new Date(value).toLocaleTimeString();
      } catch {
        return String(value);
      }
    }

    function formatDuration(ms) {
      if (ms == null || Number.isNaN(ms)) return "";
      const seconds = Math.max(0, Math.round(ms / 1000));
      if (seconds < 60) return `${seconds}s`;
      const minutes = Math.floor(seconds / 60);
      const rem = seconds % 60;
      return `${minutes}m ${rem}s`;
    }

    function updateTimingPills() {
      $("lastRefresh").textContent = formatClock(state.lastRefreshAt);
      if (state.lastScanFinishedAt) {
        const duration = formatDuration(state.lastScanDurationMs);
        $("lastScanMeta").textContent = duration
          ? `${formatClock(state.lastScanFinishedAt)} (${duration})`
          : formatClock(state.lastScanFinishedAt);
      } else if (state.lastScanStartedAt) {
        $("lastScanMeta").textContent = `started ${formatClock(state.lastScanStartedAt)}`;
      } else {
        $("lastScanMeta").textContent = "none";
      }
    }
    const $ = (id) => document.getElementById(id);

    const tokenInput = $("apiToken");
    tokenInput.value = sessionStorage.getItem("recon_api_token")
      || sessionStorage.getItem("nmap_api_token")
      || "";
    tokenInput.addEventListener("input", () => {
      sessionStorage.setItem("recon_api_token", tokenInput.value);
      sessionStorage.setItem("nmap_api_token", tokenInput.value);
    });

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
      $("historyBtn").disabled = isBusy;
      $("importBtn").disabled = isBusy;
      $("diffBtn").disabled = isBusy;
    }

    function scanPayload() {
      const body = {
        target: $("target").value,
        scan_type: $("scanType").value,
        interval: Number($("interval").value),
      };
      const ports = $("ports").value.trim();
      const scripts = $("scripts").value.trim();
      const discovery = $("discovery").value.trim();
      if (ports) body.ports = ports;
      if (scripts) body.scripts = scripts;
      if (discovery) body.discovery = discovery;
      return body;
    }

    function say(message, isError = false) {
      const toast = $("toast");
      toast.textContent = message;
      toast.style.color = isError ? "var(--danger)" : "var(--accent-2)";
    }

    function sleep(ms) {
      return new Promise((resolve) => setTimeout(resolve, ms));
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

    async function waitForJob(jobId) {
      const terminal = new Set(["completed", "failed", "cancelled", "timeout"]);
      while (true) {
        const job = await api(`/jobs/${encodeURIComponent(jobId)}`);
        state.activeJobId = jobId;
        if (terminal.has(job.status)) return job;
        say(`Scan ${job.status}...`);
        await sleep(1000);
      }
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
      const services = result?.stats?.services || {};
      $("hostMetric").textContent = hosts.length;
      $("upMetric").textContent = hosts.filter((host) => host.state === "up").length;
      $("openMetric").textContent = openPorts;
      $("serviceMetric").textContent = Object.keys(services).length;
      const bars = Object.entries(services).slice(0, 8).map(([name, count]) => {
        const width = Math.max(8, Math.min(100, Number(count) * 12));
        return `${name} (${count}) ${"█".repeat(Math.ceil(width / 12))}`;
      });
      $("serviceBars").textContent = bars.length ? `Top services: ${bars.join(" · ")}` : "";
    }

    function summary(result) {
      if (!result) return "";
      const lines = [
        `Product: ${result.product || "Recon Operator"}`,
        `Scan time: ${result.scan_time || "unknown"}`,
        `Profile: ${result.scan_type || "unknown"}`,
        result.ports ? `Ports: ${result.ports}` : "",
        result.scripts ? `Scripts: ${result.scripts}` : "",
        "",
      ].filter((line) => line !== undefined);
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

    function diffText(diff) {
      if (!diff) return "Run Diff last two (or compare after two scans).";
      const s = diff.summary || {};
      const lines = [
        `Changed: ${s.changed ? "yes" : "no"}`,
        `Hosts added: ${s.hosts_added || 0}`,
        `Hosts removed: ${s.hosts_removed || 0}`,
        `Ports opened: ${s.ports_opened || 0}`,
        `Ports closed: ${s.ports_closed || 0}`,
        "",
      ];
      for (const row of diff.ports_opened || []) {
        lines.push(`+ ${row.host} ${row.protocol}/${row.port} ${row.service}`);
      }
      for (const row of diff.ports_closed || []) {
        lines.push(`- ${row.host} ${row.protocol}/${row.port} ${row.service}`);
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
      if (state.view === "diff") content = diffText(state.lastDiff);
      if (state.view === "summary") content = summary(result);
      $("resultBox").value = content;
      if (state.view === "plan") {
        $("resultLabel").textContent = state.lastPlan ? "PLAN view" : "Build a recon plan first.";
      } else if (state.view === "diff") {
        $("resultLabel").textContent = state.lastDiff ? "DIFF view" : "No diff yet.";
      } else if (result) {
        $("resultLabel").textContent = `${state.view.toUpperCase()} view`;
      } else {
        $("resultLabel").textContent = "No scan result yet.";
      }
    }

    async function refreshKeyMeta() {
      const meta = $("keyMeta");
      if (!meta) return;
      if (!tokenInput.value.trim()) {
        meta.textContent = "Key: not identified";
        return;
      }
      try {
        const me = await api("/auth/whoami");
        const label = me.label || me.key_id || "key";
        const scopes = Array.isArray(me.scopes) ? me.scopes.join(", ") : "";
        meta.textContent = scopes
          ? `Key: ${label} (${scopes})`
          : `Key: ${label}`;
      } catch (_error) {
        meta.textContent = "Key: invalid or insufficient";
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
        $("jobCount").textContent = health.jobs_count || 0;
        await refreshKeyMeta();
        const tasks = await api("/tasks");
        $("taskCount").textContent = tasks.length;
        $("runningCount").textContent = tasks.filter((task) => task.running).length;
        renderTasks(tasks);
        await refreshHistory({ announce: false });
        state.lastRefreshAt = Date.now();
        updateTimingPills();
        if (announce) say("Dashboard refreshed.");
      } catch (error) {
        $("apiStatus").textContent = "auth needed";
        const meta = $("keyMeta");
        if (meta) meta.textContent = "Key: not identified";
        say(error.message, true);
      }
    }

    function renderHistory(items) {
      const root = $("history");
      root.innerHTML = "";
      $("historyCount").textContent = items.length;
      if (!items.length) {
        root.innerHTML = '<div class="empty">No encrypted results yet.</div>';
        return;
      }
      for (const item of items) {
        const row = document.createElement("div");
        row.className = "task";
        row.innerHTML = `<div><code></code><div class="mini"></div></div><button class="secondary" type="button">Open</button>`;
        row.querySelector("code").textContent = item.filename || item.id;
        row.querySelector(".mini").textContent = item.modified_at || "";
        const openButton = row.querySelector("button");
        openButton.setAttribute("aria-label", `Open result ${item.id}`);
        openButton.addEventListener("click", async () => {
          try {
            const payload = await api(`/results/${encodeURIComponent(item.id)}`);
            rememberResult(payload.result);
            state.view = "summary";
            document.querySelectorAll(".tabs button").forEach((tab) => {
              const selected = tab.dataset.view === "summary";
              tab.classList.toggle("active", selected);
              tab.setAttribute("aria-selected", String(selected));
            });
            renderResult();
            say(`Loaded result ${item.id}`);
          } catch (error) {
            say(error.message, true);
          }
        });
        root.appendChild(row);
      }
    }

    async function refreshHistory({ announce = true } = {}) {
      try {
        const payload = await api("/results?limit=20");
        const items = payload.results || [];
        state.historyIds = items.map((item) => item.id || item.filename);
        renderHistory(items);
        if (announce) say(`History refreshed: ${items.length} results.`);
      } catch (error) {
        if (announce) say(error.message, true);
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

    function rememberResult(result) {
      if (state.lastResult) state.previousResult = state.lastResult;
      state.lastResult = result;
      state.lastPlan = null;
    }

    async function runScan() {
      setBusy(true);
      say("Queueing scan...");
      state.lastScanStartedAt = Date.now();
      state.lastScanFinishedAt = null;
      state.lastScanDurationMs = null;
      updateTimingPills();
      try {
        const job = await api("/scan", {
          method: "POST",
          body: JSON.stringify(scanPayload())
        });
        const finished = await waitForJob(job.job_id);
        state.lastScanFinishedAt = Date.now();
        state.lastScanDurationMs = state.lastScanFinishedAt - state.lastScanStartedAt;
        updateTimingPills();
        if (finished.status !== "completed") {
          throw new Error(finished.error || `Scan ${finished.status}`);
        }
        rememberResult(finished.result);
        renderResult();
        const duration = formatDuration(state.lastScanDurationMs);
        const saved = finished.result_file ? ` Saved ${finished.result_file}.` : "";
        say(`Scan complete in ${duration || "0s"}.${saved}`);
        await refresh({ announce: false });
      } catch (error) {
        state.lastScanFinishedAt = Date.now();
        if (state.lastScanStartedAt) {
          state.lastScanDurationMs = state.lastScanFinishedAt - state.lastScanStartedAt;
        }
        updateTimingPills();
        say(error.message, true);
      } finally {
        setBusy(false);
        state.activeJobId = null;
      }
    }

    async function importXml() {
      const xml = $("xmlImport").value.trim();
      if (!xml) {
        say("Paste Nmap XML first.", true);
        return;
      }
      setBusy(true);
      try {
        const payload = await api("/results/import", {
          method: "POST",
          body: JSON.stringify({ xml, target: $("target").value || "xml-import" }),
        });
        rememberResult(payload.result);
        state.view = "summary";
        document.querySelectorAll(".tabs button").forEach((tab) => {
          const selected = tab.dataset.view === "summary";
          tab.classList.toggle("active", selected);
          tab.setAttribute("aria-selected", String(selected));
        });
        renderResult();
        say(`Imported ${payload.filename || "XML"}`);
        await refreshHistory({ announce: false });
      } catch (error) {
        say(error.message, true);
      } finally {
        setBusy(false);
      }
    }

    async function diffLastTwo() {
      setBusy(true);
      try {
        let baseline = state.previousResult;
        let current = state.lastResult;
        if ((!baseline || !current) && state.historyIds.length >= 2) {
          const [newer, older] = state.historyIds;
          const currentPayload = await api(`/results/${encodeURIComponent(newer)}`);
          const baselinePayload = await api(`/results/${encodeURIComponent(older)}`);
          current = currentPayload.result;
          baseline = baselinePayload.result;
        }
        if (!baseline || !current) {
          throw new Error("Need two results to diff (run two scans or open history).");
        }
        state.lastDiff = await api("/results/diff", {
          method: "POST",
          body: JSON.stringify({ baseline, current }),
        });
        state.view = "diff";
        document.querySelectorAll(".tabs button").forEach((tab) => {
          const selected = tab.dataset.view === "diff";
          tab.classList.toggle("active", selected);
          tab.setAttribute("aria-selected", String(selected));
        });
        renderResult();
        const s = state.lastDiff.summary || {};
        say(s.changed ? `Diff: ${s.ports_opened || 0} opened, ${s.ports_closed || 0} closed.` : "Diff: no changes.");
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
        await api("/schedule", { method: "POST", body: JSON.stringify(scanPayload()) });
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
    $("importBtn").addEventListener("click", importXml);
    $("diffBtn").addEventListener("click", diffLastTwo);
    $("refreshBtn").addEventListener("click", () => refresh());
    $("historyBtn").addEventListener("click", () => refreshHistory());
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

    updateTimingPills();
    refresh();
  </script>
</body>
</html>
"""
