"""Operator dashboard HTML shell.

CSS/JS live under ``static/`` and are served as cacheable assets.
"""

UI_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Recon Operator</title>
  <link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/static/dashboard.css" nonce="__CSP_NONCE__">

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
          <label>Engagement preset
            <select id="preset">
              <option value="">custom (use profile below)</option>
              <option value="discovery">discovery — host liveness</option>
              <option value="map">map — service map</option>
              <option value="safe">safe — safe NSE depth</option>
              <option value="depth">depth — full TCP/scripts</option>
              <option value="vuln">vuln — vuln NSE (authorized)</option>
              <option value="hybrid">hybrid — discovery + version</option>
            </select>
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
              <button data-view="brief" type="button" role="tab" aria-selected="false" aria-controls="resultBox">AI Brief</button>
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
                <button class="secondary" id="briefBtn" type="button">AI Pack</button>
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

  <script src="/static/dashboard.js" nonce="__CSP_NONCE__" defer></script>

</body>
</html>
"""
