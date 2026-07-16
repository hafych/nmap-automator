const state = {
      lastResult: null,
      previousResult: null,
      lastPlan: null,
      lastBrief: null,
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
      if ($("briefBtn")) $("briefBtn").disabled = isBusy;
      $("historyBtn").disabled = isBusy;
      $("importBtn").disabled = isBusy;
      $("diffBtn").disabled = isBusy;
    }

    function scanPayload() {
      const body = {
        target: $("target").value,
        interval: Number($("interval").value),
      };
      const preset = ($("preset") && $("preset").value.trim()) || "";
      if (preset) {
        body.preset = preset;
      } else {
        body.scan_type = $("scanType").value;
      }
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
      if (state.view === "brief") content = state.lastBrief || "Load an AI pack (low-token brief) after a scan.";
      if (state.view === "diff") content = diffText(state.lastDiff);
      if (state.view === "summary") content = summary(result);
      $("resultBox").value = content;
      if (state.view === "plan") {
        $("resultLabel").textContent = state.lastPlan ? "PLAN view" : "Build a recon plan first.";
      } else if (state.view === "brief") {
        $("resultLabel").textContent = state.lastBrief ? "AI BRIEF (budget=s pack)" : "No AI pack yet.";
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
      state.lastBrief = null;
    }

    async function loadAiBrief({ retest = false } = {}) {
      if (!state.lastResult) {
        say("Run a scan first.", true);
        return;
      }
      setBusy(true);
      try {
        const payload = { scan: state.lastResult, budget: "s" };
        let path = "/ai/pack?budget=s";
        if (retest && state.previousResult) {
          payload.baseline = state.previousResult;
          path = "/ai/pack?mode=retest&budget=s";
        }
        const response = await fetch(path, {
          method: "POST",
          headers: headers(),
          body: JSON.stringify(payload),
        });
        const text = await response.text();
        if (!response.ok) {
          let detail = response.statusText;
          try {
            const errBody = JSON.parse(text);
            if (errBody && errBody.error) detail = errBody.error;
          } catch (_e) {
            /* ignore */
          }
          throw new Error(`${response.status}: ${detail}`);
        }
        state.lastBrief = text;
        state.view = "brief";
        document.querySelectorAll(".tabs button").forEach((item) => {
          const selected = item.dataset.view === "brief";
          item.classList.toggle("active", selected);
          item.setAttribute("aria-selected", String(selected));
        });
        renderResult();
        const lines = text.split("\n").filter(Boolean).length;
        say(
          retest
            ? `AI retest pack loaded (${lines} lines).`
            : `AI pack loaded (${lines} lines, budget=s).`
        );
      } catch (error) {
        say(error.message, true);
      } finally {
        setBusy(false);
      }
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
    if ($("briefBtn")) {
      $("briefBtn").addEventListener("click", () => loadAiBrief({ retest: false }));
    }
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
