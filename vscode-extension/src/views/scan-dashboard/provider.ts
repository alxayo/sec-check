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
 * WebviewViewProvider for the AgentSec scan dashboard.
 *
 * Registered as the "agentsec.dashboard" view in package.json.
 */
export class ScanDashboardProvider implements vscode.WebviewViewProvider {
  private view: vscode.WebviewView | undefined;
  private extensionUri: vscode.Uri;
  private currentState: ScanState | null = null;

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
      }
    });

    // If we already have state, send it to the new webview
    if (this.currentState) {
      this.postState(this.currentState);
    }
  }

  /**
   * Update the dashboard with new scan state.
   */
  updateState(state: ScanState): void {
    this.currentState = state;
    this.postState(state);
  }

  private postState(state: ScanState): void {
    const visible = !!this.view?.visible;
    if (visible) {
      this.view!.webview.postMessage({ type: "stateUpdate", state });
    }
    // Log only on phase transitions or completion to avoid spamming
    if (state.phase === "complete" || state.phase === "error") {
      const out = getOutputChannel();
      out.info(
        `[dashboard.postState] phase=${state.phase}, issues=${state.issuesFound}, ` +
        `scanners=${state.scanners.length}, resultContent=${state.resultContent?.length ?? 0} chars, ` +
        `reportPath="${state.reportPath || "(none)"}", webviewVisible=${visible}`
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

      <div class="footer">
        <span id="elapsed"></span>
        <button class="secondary" id="cancel-btn">Cancel</button>
      </div>
    </div>

    <div id="results-view" style="display:none;">
      <div class="meta" id="results-meta"></div>
      <div id="results-list"></div>
      <div class="footer">
        <button id="open-report-btn" style="display:none;">&#128196; View Full Report</button>
        <button id="new-scan-btn">New Scan</button>
      </div>
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
      log('New Scan button clicked (results view)');
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

    const phaseOrder = ['idle', 'discovery', 'parallel_scan', 'llm_analysis', 'synthesis', 'complete', 'error'];

    function updateDashboard(state) {
      const idleView = document.getElementById('idle-view');
      const scanView = document.getElementById('scan-view');
      const resultsView = document.getElementById('results-view');
      const errorView = document.getElementById('error-view');

      // Hide all views
      idleView.style.display = 'none';
      scanView.style.display = 'none';
      resultsView.style.display = 'none';
      errorView.style.display = 'none';

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

      if (state.phase === 'complete') {
        resultsView.style.display = '';
        document.getElementById('results-meta').textContent =
          'Completed in ' + Math.round(state.elapsedSeconds) + 's  |  ' +
          state.issuesFound + ' findings';

        // Show "View Full Report" button when a report file exists
        var reportBtn = document.getElementById('open-report-btn');
        if (state.reportPath) {
          reportBtn.style.display = '';
        } else {
          reportBtn.style.display = 'none';
        }
        return;
      }

      // Active scan phases
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
        if (currentIdx > pIdx) {
          statusEl.textContent = 'done';
        } else if (currentIdx === pIdx) {
          statusEl.textContent = 'running...';
        } else {
          statusEl.textContent = 'pending';
        }
        // Make phase headers clickable once they have started (not pending)
        if (p.channel && currentIdx >= pIdx) {
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
      const pct = state.percentComplete >= 0 ? state.percentComplete : 0;
      document.getElementById('scan-progress').style.width = pct + '%';

      // Elapsed
      document.getElementById('elapsed').textContent =
        'Elapsed: ' + Math.round(state.elapsedSeconds) + 's | Findings: ' + state.issuesFound;
    }

    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str || '';
      return div.innerHTML;
    }

    window.addEventListener('message', (event) => {
      const message = event.data;
      if (message.type === 'stateUpdate') {
        updateDashboard(message.state);
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
