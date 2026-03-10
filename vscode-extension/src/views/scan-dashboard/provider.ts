/**
 * Scan Dashboard WebviewView provider.
 *
 * Renders a real-time dashboard showing the 4-phase scan lifecycle
 * with animated scanner cards, progress bars, and results.
 */

import * as vscode from "vscode";
import type { ScanState } from "../../backend/types.js";
import { getOutputChannel } from "../../utils/output-channel.js";
import { resolveFilePath } from "../../utils/diagnostics.js";

/**
 * Summary of a completed scan, stored in the history list.
 */
interface ScanHistoryEntry {
  timestamp: string;
  targetFolder: string;
  issuesFound: number;
  elapsedSeconds: number;
  reportPath: string;
  scannersUsed: string[];
  mode: "parallel" | "serial";
  status: "success" | "error" | "timeout";
}

/**
 * WebviewViewProvider for the AgentSec scan dashboard.
 *
 * Registered as the "agentsec.dashboard" view in package.json.
 */
export class ScanDashboardProvider implements vscode.WebviewViewProvider {
  private view: vscode.WebviewView | undefined;
  private extensionUri: vscode.Uri;
  private currentState: ScanState | null = null;

  /** Completed scan history (most recent first, session-scoped). */
  private scanHistory: ScanHistoryEntry[] = [];

  /** Called when the user clicks a scanner card or phase header. */
  onShowOutput?: (name: string) => void;

  /** Called when the user clicks "View Full Report". */
  onOpenReport?: () => void;

  constructor(extensionUri: vscode.Uri) {
    this.extensionUri = extensionUri;
  }

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ): void {
    this.view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this.extensionUri],
    };

    // Keep the webview DOM alive when the panel is collapsed/hidden
    // so scan results and history are not lost on toggle.
    webviewView.options = { webviewOptions: { retainContextWhenHidden: true } };

    webviewView.webview.html = this.getHtml(webviewView.webview);

    // Handle messages from the webview
    webviewView.webview.onDidReceiveMessage((message) => {
      const out = getOutputChannel();
      out.info(`[dashboard] Received webview message: ${JSON.stringify(message)}`);
      switch (message.command) {
        case "cancelScan":
          out.info("[dashboard] Executing agentsec.cancelScan");
          vscode.commands.executeCommand("agentsec.cancelScan");
          break;
        case "startScan":
          out.info("[dashboard] Executing agentsec.scanWorkspace");
          vscode.commands.executeCommand("agentsec.scanWorkspace");
          break;
        case "log":
          // Forward webview console logs to the output channel
          out.info(`[dashboard webview] ${message.text}`);
          break;
        case "openFile":
          if (message.filePath) {
            const workspaceRoot = this.currentState?.targetFolder || "";
            resolveFilePath(message.filePath, workspaceRoot).then(
              (resolved) => {
                const uri = vscode.Uri.file(resolved);
                const line = Math.max(0, (message.lineNumber || 1) - 1);
                vscode.window.showTextDocument(uri, {
                  selection: new vscode.Range(line, 0, line, 0),
                });
              }
            );
          }
          break;
        case "showOutput":
          if (message.name && this.onShowOutput) {
            out.info(`[dashboard] Showing output for: ${message.name}`);
            this.onShowOutput(message.name);
          }
          break;
        case "openReport":
          out.info("[dashboard] Open report requested");
          this.onOpenReport?.();
          break;
        case "openHistoryReport":
          if (message.reportPath) {
            out.info(`[dashboard] Opening history report: ${message.reportPath}`);
            vscode.window.showTextDocument(
              vscode.Uri.file(message.reportPath),
              { preview: false }
            );
          }
          break;
        case "ready":
          // Webview script finished loading — send current state + history
          out.info("[dashboard] Webview ready — restoring state");
          if (this.currentState) {
            this.postState(this.currentState);
          }
          break;
      }
    });
  }

  /**
   * Update the dashboard with new scan state.
   */
  updateState(state: ScanState): void {
    // When a scan just completed, add it to history
    if (
      state.phase === "complete" &&
      this.currentState?.phase !== "complete"
    ) {
      this.scanHistory.unshift({
        timestamp: new Date().toISOString(),
        targetFolder: state.targetFolder,
        issuesFound: state.issuesFound,
        elapsedSeconds: state.elapsedSeconds,
        reportPath: state.reportPath,
        scannersUsed: state.scanners.map((s) => s.name),
        mode: state.mode,
        status: "success",
      });
    } else if (
      state.phase === "error" &&
      this.currentState?.phase !== "error" &&
      state.targetFolder
    ) {
      this.scanHistory.unshift({
        timestamp: new Date().toISOString(),
        targetFolder: state.targetFolder,
        issuesFound: state.issuesFound,
        elapsedSeconds: state.elapsedSeconds,
        reportPath: state.reportPath,
        scannersUsed: state.scanners.map((s) => s.name),
        mode: state.mode,
        status: "error",
      });
    }

    this.currentState = state;
    this.postState(state);
  }

  private postState(state: ScanState): void {
    // Always post — the ready handshake and retainContextWhenHidden
    // ensure the webview is alive when this is called.
    if (this.view) {
      this.view.webview.postMessage({
        type: "stateUpdate",
        state,
        history: this.scanHistory,
      });
    }
    // Log only on phase transitions or completion to avoid spamming
    if (state.phase === "complete" || state.phase === "error") {
      const out = getOutputChannel();
      out.info(
        `[dashboard.postState] phase=${state.phase}, issues=${state.issuesFound}, ` +
        `scanners=${state.scanners.length}, resultContent=${state.resultContent?.length ?? 0} chars, ` +
        `reportPath="${state.reportPath || "(none)"}"`
      );
    }
  }

  private getHtml(webview: vscode.Webview): string {
    const nonce = getNonce();

    return /*html*/ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
    content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <title>AgentSec Dashboard</title>
  <style>
    :root {
      --section-radius: 4px;
      --card-radius: 3px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-sideBar-background, var(--vscode-editor-background));
      padding: 12px;
    }
    h2 {
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--vscode-sideBarSectionHeader-foreground, var(--vscode-foreground));
    }
    .header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--vscode-sideBarSectionHeader-border, var(--vscode-panel-border));
    }
    .header-icon { font-size: 18px; }
    .header h2 { margin-bottom: 0; }
    .meta {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      margin-bottom: 12px;
    }
    .meta span { margin-right: 12px; }

    /* Phases */
    .phase {
      border: 1px solid var(--vscode-panel-border, #333);
      border-radius: var(--section-radius);
      margin-bottom: 8px;
      overflow: hidden;
    }
    .phase-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 10px;
      background: var(--vscode-sideBarSectionHeader-background, rgba(255,255,255,0.04));
      font-size: 12px;
      font-weight: 600;
    }
    .phase-header.clickable {
      cursor: pointer;
    }
    .phase-header.clickable:hover {
      opacity: 0.85;
    }
    .phase-body { padding: 8px 10px; }
    .phase-body.empty { display: none; }
    .phase-status {
      font-size: 11px;
      font-weight: 400;
      color: var(--vscode-descriptionForeground);
    }

    /* Scanner cards */
    .scanner-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .scanner-card {
      flex: 1 1 calc(33% - 4px);
      min-width: 90px;
      border: 1px solid var(--vscode-panel-border, #333);
      border-radius: var(--card-radius);
      padding: 6px 8px;
      font-size: 11px;
      transition: border-color 0.3s, opacity 0.2s;
      cursor: pointer;
    }
    .scanner-card:hover {
      opacity: 0.85;
    }
    .scanner-card.running {
      border-color: var(--vscode-progressBar-background, #0078d4);
    }
    .scanner-card.completed {
      border-color: var(--vscode-charts-green, #4caf50);
    }
    .scanner-card.failed {
      border-color: var(--vscode-errorForeground, #f44);
    }
    .scanner-name {
      font-weight: 600;
      margin-bottom: 2px;
    }
    .scanner-status {
      color: var(--vscode-descriptionForeground);
    }

    /* Progress bar */
    .progress-bar {
      height: 4px;
      background: var(--vscode-progressBar-background, #0078d4);
      border-radius: 2px;
      margin-top: 8px;
      transition: width 0.5s ease;
    }
    .progress-track {
      height: 4px;
      background: var(--vscode-input-border, #333);
      border-radius: 2px;
      overflow: hidden;
    }

    /* Footer */
    .footer {
      margin-top: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
    }
    button {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      padding: 4px 12px;
      border-radius: 2px;
      cursor: pointer;
      font-size: 11px;
      font-family: var(--vscode-font-family);
    }
    button:hover {
      background: var(--vscode-button-hoverBackground);
    }
    button.secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }

    /* Idle state */
    .idle-state {
      text-align: center;
      padding: 24px 12px;
      color: var(--vscode-descriptionForeground);
    }
    .idle-state p { margin-bottom: 12px; }

    /* Results */
    .finding {
      padding: 6px 8px;
      border-left: 3px solid var(--vscode-panel-border);
      margin-bottom: 6px;
      font-size: 11px;
      cursor: pointer;
    }
    .finding:hover {
      background: var(--vscode-list-hoverBackground);
    }
    .finding.critical, .finding.high {
      border-left-color: var(--vscode-errorForeground, #f44);
    }
    .finding.medium {
      border-left-color: var(--vscode-editorWarning-foreground, #fa0);
    }
    .finding.low, .finding.info {
      border-left-color: var(--vscode-editorInfo-foreground, #3794ff);
    }
    .finding-title { font-weight: 600; }
    .finding-location {
      color: var(--vscode-descriptionForeground);
      font-size: 10px;
    }

    /* History section */
    .history-section {
      margin-top: 16px;
      padding-top: 12px;
      border-top: 1px solid var(--vscode-sideBarSectionHeader-border, var(--vscode-panel-border));
    }
    .history-section h2 {
      font-size: 11px;
      margin-bottom: 8px;
    }
    .history-row {
      border: 1px solid var(--vscode-panel-border, #333);
      border-radius: var(--card-radius);
      padding: 8px 10px;
      margin-bottom: 6px;
      font-size: 11px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .history-row:hover {
      background: var(--vscode-list-hoverBackground);
    }
    .history-row .history-info {
      flex: 1;
      min-width: 0;
    }
    .history-row .history-main {
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .history-row .history-details {
      color: var(--vscode-descriptionForeground);
      font-size: 10px;
      margin-top: 2px;
    }
    .history-row .history-actions {
      flex-shrink: 0;
      margin-left: 8px;
    }
    .history-row.error {
      border-left: 3px solid var(--vscode-errorForeground, #f44);
    }
    .history-row.success {
      border-left: 3px solid var(--vscode-charts-green, #4caf50);
    }

    /* Completion footer (replaces cancel button on complete) */
    .completion-footer {
      margin-top: 12px;
      padding-top: 8px;
      border-top: 1px solid var(--vscode-panel-border, #333);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
    }
    .completion-footer .completion-stats {
      font-weight: 600;
      color: var(--vscode-foreground);
    }
    .completion-footer .completion-buttons {
      display: flex;
      gap: 6px;
    }
  </style>
</head>
<body>
  <div class="header">
    <span class="header-icon">&#128737;</span>
    <h2>AgentSec Scanner</h2>
  </div>

  <div id="dashboard">
    <div class="idle-state" id="idle-view">
      <p>No scan running</p>
      <button id="start-btn">Start Scan</button>
    </div>

    <div id="scan-view" style="display:none;">
      <div class="meta" id="scan-meta"></div>

      <div class="phase" id="phase-discovery">
        <div class="phase-header">
          <span>Phase 1: Discovery</span>
          <span class="phase-status" id="phase-discovery-status">pending</span>
        </div>
        <div class="phase-body empty" id="phase-discovery-body"></div>
      </div>

      <div class="phase" id="phase-parallel">
        <div class="phase-header">
          <span>Phase 2: Parallel Scan</span>
          <span class="phase-status" id="phase-parallel-status">pending</span>
        </div>
        <div class="phase-body" id="phase-parallel-body">
          <div class="scanner-grid" id="scanner-grid"></div>
          <div class="progress-track" style="margin-top: 8px;">
            <div class="progress-bar" id="scan-progress" style="width: 0%;"></div>
          </div>
        </div>
      </div>

      <div class="phase" id="phase-llm">
        <div class="phase-header">
          <span>Phase 3: LLM Analysis</span>
          <span class="phase-status" id="phase-llm-status">pending</span>
        </div>
        <div class="phase-body empty" id="phase-llm-body"></div>
      </div>

      <div class="phase" id="phase-synthesis">
        <div class="phase-header">
          <span>Phase 4: Synthesis</span>
          <span class="phase-status" id="phase-synthesis-status">pending</span>
        </div>
        <div class="phase-body empty" id="phase-synthesis-body"></div>
      </div>

      <div class="footer" id="scan-footer">
        <span id="elapsed"></span>
        <button class="secondary" id="cancel-btn">Cancel</button>
      </div>

      <div class="completion-footer" id="completion-footer" style="display:none;">
        <div>
          <span class="completion-stats" id="completion-stats"></span>
        </div>
        <div class="completion-buttons">
          <button id="open-report-btn" style="display:none;">&#128196; View Report</button>
          <button id="new-scan-btn">New Scan</button>
        </div>
      </div>
    </div>

    <div id="history-section" class="history-section" style="display:none;">
      <h2>Scan History</h2>
      <div id="history-list"></div>
    </div>

    <div id="error-view" style="display:none;">
      <p style="color: var(--vscode-errorForeground);" id="error-message"></p>
      <div class="footer">
        <span></span>
        <button id="retry-btn">Retry</button>
      </div>
    </div>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();

    // Helper: send a log message to the extension output channel
    function log(text) {
      console.log('[dashboard]', text);
      vscode.postMessage({ command: 'log', text: text });
    }

    log('Webview script loaded and executing');

    function startScan() {
      log('startScan() called — posting startScan command to extension');
      vscode.postMessage({ command: 'startScan' });
    }

    function cancelScan() {
      log('cancelScan() called — posting cancelScan command to extension');
      vscode.postMessage({ command: 'cancelScan' });
    }

    function openFile(filePath, lineNumber) {
      log('openFile() called: ' + filePath + ':' + lineNumber);
      vscode.postMessage({ command: 'openFile', filePath, lineNumber });
    }

    // Wire up button click handlers via addEventListener
    // (inline onclick= attributes are blocked by CSP nonce policy)
    document.getElementById('start-btn').addEventListener('click', function() {
      log('Start Scan button clicked (idle view)');
      startScan();
    });
    document.getElementById('cancel-btn').addEventListener('click', function() {
      log('Cancel button clicked');
      cancelScan();
    });
    document.getElementById('new-scan-btn').addEventListener('click', function() {
      log('New Scan button clicked');
      startScan();
    });
    document.getElementById('open-report-btn').addEventListener('click', function() {
      log('View Full Report button clicked');
      vscode.postMessage({ command: 'openReport' });
    });
    document.getElementById('retry-btn').addEventListener('click', function() {
      log('Retry button clicked (error view)');
      startScan();
    });

    log('All button event listeners attached');

    // Notify the extension that the webview script is ready
    // to receive state updates. This handshake ensures state
    // is restored after the webview is recreated.
    vscode.postMessage({ command: 'ready' });
    log('Sent ready handshake to extension');

    const phaseOrder = ['idle', 'discovery', 'parallel_scan', 'llm_analysis', 'synthesis', 'complete', 'error'];

    function updateDashboard(state, history) {
      const idleView = document.getElementById('idle-view');
      const scanView = document.getElementById('scan-view');
      const errorView = document.getElementById('error-view');
      const historySection = document.getElementById('history-section');
      const scanFooter = document.getElementById('scan-footer');
      const completionFooter = document.getElementById('completion-footer');

      // Hide all views
      idleView.style.display = 'none';
      scanView.style.display = 'none';
      errorView.style.display = 'none';

      // Always render history if available
      renderHistory(history);

      if (state.phase === 'idle') {
        idleView.style.display = '';
        return;
      }

      if (state.phase === 'error') {
        errorView.style.display = '';
        document.getElementById('error-message').textContent =
          state.errorMessage || 'Scan failed';
        return;
      }

      // Show scan-view for both active phases AND completion
      scanView.style.display = '';

      // Meta line
      document.getElementById('scan-meta').innerHTML =
        '<span>Target: ' + escapeHtml(state.targetFolder) + '</span>' +
        '<span>Mode: ' + state.mode + '</span>';

      // Phase statuses and clickable headers
      const phases = [
        { id: 'discovery', active: 'discovery', channel: 'Discovery' },
        { id: 'parallel', active: 'parallel_scan', channel: null },
        { id: 'llm', active: 'llm_analysis', channel: 'LLM Analysis' },
        { id: 'synthesis', active: 'synthesis', channel: 'Synthesis' },
      ];

      const currentIdx = phaseOrder.indexOf(state.phase);
      for (const p of phases) {
        const pIdx = phaseOrder.indexOf(p.active);
        const statusEl = document.getElementById('phase-' + p.id + '-status');
        const headerEl = document.getElementById('phase-' + p.id).querySelector('.phase-header');
        if (currentIdx > pIdx || state.phase === 'complete') {
          statusEl.textContent = 'done';
        } else if (currentIdx === pIdx) {
          statusEl.textContent = 'running...';
        } else {
          statusEl.textContent = 'pending';
        }
        // Make phase headers clickable once they have started (not pending)
        if (p.channel && (currentIdx >= pIdx || state.phase === 'complete')) {
          headerEl.classList.add('clickable');
          headerEl.onclick = function() {
            vscode.postMessage({ command: 'showOutput', name: p.channel });
          };
          headerEl.title = 'Click to view output';
        } else if (p.channel) {
          headerEl.classList.remove('clickable');
          headerEl.onclick = null;
          headerEl.title = '';
        }
      }

      // Scanner cards
      const grid = document.getElementById('scanner-grid');
      grid.innerHTML = '';
      for (const scanner of state.scanners || []) {
        const card = document.createElement('div');
        card.className = 'scanner-card ' + scanner.state;
        const icon = scanner.state === 'completed' ? '&#10003;'
          : scanner.state === 'running' ? '&#8987;'
          : scanner.state === 'failed' ? '&#10007;'
          : '&#9711;';
        card.innerHTML =
          '<div class="scanner-name">' + icon + ' ' + escapeHtml(scanner.name) + '</div>' +
          '<div class="scanner-status">' + escapeHtml(scanner.state) +
          (scanner.findingsCount > 0 ? ' | ' + scanner.findingsCount + ' findings' : '') +
          '</div>';
        card.addEventListener('click', function() {
          vscode.postMessage({ command: 'showOutput', name: scanner.name });
        });
        card.title = 'Click to view output';
        grid.appendChild(card);
      }

      // Progress bar
      var pct = state.phase === 'complete' ? 100 : (state.percentComplete >= 0 ? state.percentComplete : 0);
      document.getElementById('scan-progress').style.width = pct + '%';

      // Switch between scan footer (cancel) and completion footer
      if (state.phase === 'complete') {
        scanFooter.style.display = 'none';
        completionFooter.style.display = '';

        // Completion stats
        document.getElementById('completion-stats').textContent =
          '\\u2705 Completed in ' + Math.round(state.elapsedSeconds) + 's  |  ' +
          state.issuesFound + ' findings';

        // Show report button
        var reportBtn = document.getElementById('open-report-btn');
        reportBtn.style.display = state.reportPath ? '' : 'none';
      } else {
        scanFooter.style.display = '';
        completionFooter.style.display = 'none';

        // Elapsed
        document.getElementById('elapsed').textContent =
          'Elapsed: ' + Math.round(state.elapsedSeconds) + 's | Findings: ' + state.issuesFound;
      }
    }

    function renderHistory(history) {
      var section = document.getElementById('history-section');
      var list = document.getElementById('history-list');

      if (!history || history.length === 0) {
        section.style.display = 'none';
        return;
      }

      section.style.display = '';
      list.innerHTML = '';

      for (var i = 0; i < history.length; i++) {
        var entry = history[i];
        var row = document.createElement('div');
        row.className = 'history-row ' + entry.status;

        // Format date/time
        var dt = new Date(entry.timestamp);
        var dateStr = (dt.getMonth() + 1).toString().padStart(2, '0') + '/' +
          dt.getDate().toString().padStart(2, '0') + ' ' +
          dt.getHours().toString().padStart(2, '0') + ':' +
          dt.getMinutes().toString().padStart(2, '0');

        // Shorten folder path for display
        var folder = entry.targetFolder || '';
        var folderParts = folder.replace(/\\\\/g, '/').split('/');
        var shortFolder = folderParts.length > 2
          ? '.../' + folderParts.slice(-2).join('/')
          : folder;

        // Duration
        var durMin = Math.floor(entry.elapsedSeconds / 60);
        var durSec = Math.round(entry.elapsedSeconds % 60);
        var durStr = durMin > 0 ? durMin + 'm ' + durSec + 's' : durSec + 's';

        // Status icon
        var statusIcon = entry.status === 'success' ? '\\u2705' : '\\u274C';

        var infoDiv = document.createElement('div');
        infoDiv.className = 'history-info';
        infoDiv.innerHTML =
          '<div class="history-main">' + statusIcon + ' ' + escapeHtml(shortFolder) + '</div>' +
          '<div class="history-details">' +
            escapeHtml(dateStr) + '  \\u2022  ' +
            entry.issuesFound + ' findings  \\u2022  ' +
            escapeHtml(durStr) + '  \\u2022  ' +
            escapeHtml(entry.mode) +
          '</div>';
        row.appendChild(infoDiv);

        // "Open" button (only if report exists)
        if (entry.reportPath) {
          var btn = document.createElement('button');
          btn.className = 'secondary';
          btn.textContent = 'Open';
          btn.title = 'Open the scan report';
          (function(rp) {
            btn.addEventListener('click', function(e) {
              e.stopPropagation();
              vscode.postMessage({ command: 'openHistoryReport', reportPath: rp });
            });
          })(entry.reportPath);
          var actionsDiv = document.createElement('div');
          actionsDiv.className = 'history-actions';
          actionsDiv.appendChild(btn);
          row.appendChild(actionsDiv);
        }

        list.appendChild(row);
      }
    }

    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str || '';
      return div.innerHTML;
    }

    window.addEventListener('message', (event) => {
      const message = event.data;
      if (message.type === 'stateUpdate') {
        updateDashboard(message.state, message.history || []);
      }
    });
  </script>
</body>
</html>`;
  }
}

function getNonce(): string {
  let text = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 32; i++) {
    text += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return text;
}
