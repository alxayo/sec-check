/**
 * Scan orchestrator for the AgentSec VS Code extension.
 *
 * Manages the lifecycle of a security scan: starts the Python
 * bridge, routes progress events to UI components, tracks
 * scanner states via the SubagentRegistry, and handles
 * cancellation and results.
 */

import * as vscode from "vscode";
import { AgentSecBridge } from "../backend/bridge.js";
import type { Finding, ProgressMessage, ResultMessage, ScannerInfo, ScannerOutputMessage, ScanState } from "../backend/types.js";
import { createInitialScanState } from "../backend/types.js";
import { getExtensionConfig, toScanConfig } from "../utils/config.js";
import { parseFindings, pushFindings, resolveAllPaths } from "../utils/diagnostics.js";
import { SubagentRegistry } from "./subagent-registry.js";

/**
 * Manages the full scan lifecycle and exposes state for UI consumption.
 *
 * Usage:
 *   const orchestrator = new ScanOrchestrator(bridge, outputChannel);
 *   orchestrator.onStateChange = (state) => updateUI(state);
 *   await orchestrator.startScan("/path/to/project");
 */
export class ScanOrchestrator {
  private bridge: AgentSecBridge;
  private outputChannel: vscode.LogOutputChannel;
  private scannerRegistry = new SubagentRegistry();
  private _state: ScanState | null = null;
  private _findings: Finding[] = [];
  private _isScanning = false;
  private scannerChannels = new Map<string, vscode.OutputChannel>();

  /** Known scanners from the latest tool discovery. */
  private _knownScanners: ScannerInfo[] = [];

  /** Called whenever the scan state changes. */
  onStateChange?: (state: ScanState) => void;

  /** Called when the scan completes (success, error, or timeout). */
  onScanComplete?: (state: ScanState, findings: Finding[]) => void;

  /** Called when the user clicks a scanner card or phase header. */
  onShowOutput?: (name: string) => void;

  constructor(bridge: AgentSecBridge, outputChannel: vscode.LogOutputChannel) {
    this.bridge = bridge;
    this.outputChannel = outputChannel;

    // Wire up bridge events
    this.bridge.on("progress", (msg) => {
      this.outputChannel.debug(`[orchestrator] Progress event: ${msg.event} — ${msg.message ?? ""}`);
      this.handleProgress(msg);
    });
    this.bridge.on("result", (msg) => {
      this.outputChannel.info(`[orchestrator] Result event: status=${msg.status}, error=${msg.error ?? "(none)"}`);
      this.handleResult(msg);
    });
    this.bridge.on("scannerOutput", (msg) => {
      this.handleScannerOutput(msg);
    });
  }

  /**
   * Get the current scan state.
   */
  get state(): ScanState | null {
    return this._state;
  }

  /**
   * Get parsed findings from the latest scan.
   */
  get findings(): Finding[] {
    return this._findings;
  }

  /**
   * Whether a scan is currently running.
   */
  get isScanning(): boolean {
    return this._isScanning;
  }

  /**
   * Update the known scanner list (called after tool discovery).
   */
  updateKnownScanners(scanners: ScannerInfo[]): void {
    this._knownScanners = scanners;
  }

  /**
   * Start a security scan.
   */
  async startScan(folder: string): Promise<void> {
    this.outputChannel.info(`[orchestrator.startScan] Called with folder="${folder}"`);
    if (this._isScanning) {
      this.outputChannel.warn("[orchestrator.startScan] A scan is already running — ignoring");
      vscode.window.showWarningMessage("A scan is already running.");
      return;
    }

    const config = getExtensionConfig();
    this.outputChannel.info(
      `[orchestrator.startScan] Config: mode=${config.scanMode}, ` +
      `model=${config.model}, maxConcurrent=${config.maxConcurrent}, timeout=${config.scanTimeout}`
    );

    // If the user opted into scanner selection, show a QuickPick
    // with all installed scanners so they can choose which to run.
    let selectedScanners: string[] | undefined;
    if (config.promptScannerSelection) {
      const installed = this._knownScanners.filter((s) => s.toolAvailable);
      if (installed.length > 0) {
        const picks = installed.map((s) => ({
          label: s.name,
          description: s.description,
          detail: `Tool: ${s.toolName}`,
          picked: true,
        }));

        const chosen = await vscode.window.showQuickPick(picks, {
          canPickMany: true,
          placeHolder: "Select scanners to run (all selected by default)",
          title: "AgentSec: Scanner Selection",
        });

        // User cancelled the QuickPick — abort the scan
        if (!chosen) {
          this.outputChannel.info("[orchestrator.startScan] Scanner selection cancelled by user");
          return;
        }

        selectedScanners = chosen.map((c) => c.label);
        this.outputChannel.info(
          `[orchestrator.startScan] User selected ${selectedScanners.length} scanners: ${selectedScanners.join(", ")}`
        );
      }
    }

    this._state = createInitialScanState(folder, config.scanMode);
    this._findings = [];
    this._isScanning = true;
    this.scannerRegistry.clear();

    // Dispose previous per-scanner channels for a fresh scan
    for (const ch of this.scannerChannels.values()) {
      ch.dispose();
    }
    this.scannerChannels.clear();

    this.emitStateChange();

    const scanConfig = toScanConfig(config);
    if (selectedScanners) {
      scanConfig.scanners = selectedScanners;
    }

    this.outputChannel.info(`[orchestrator.startScan] Sending scan command to bridge...`);
    this.bridge.sendScan(folder, config.scanMode, scanConfig);
  }

  /**
   * Cancel the running scan.
   */
  cancelScan(): void {
    if (!this._isScanning) {
      return;
    }
    this.outputChannel.info("Cancelling scan");
    this.bridge.sendCancel();
  }

  /**
   * Show the output channel for a specific scanner or phase.
   */
  showScannerOutput(name: string): void {
    const channel = this.scannerChannels.get(name);
    if (channel) {
      channel.show(true);
    } else {
      this.outputChannel.info(`[orchestrator] No output channel for "${name}"`);
    }
  }

  /**
   * Dispose the orchestrator.
   */
  dispose(): void {
    this.scannerRegistry.dispose();
    for (const ch of this.scannerChannels.values()) {
      ch.dispose();
    }
    this.scannerChannels.clear();
    this.onStateChange = undefined;
    this.onScanComplete = undefined;
    this.onShowOutput = undefined;
  }

  // ── Event handlers ────────────────────────────────────────

  private handleScannerOutput(msg: ScannerOutputMessage): void {
    const name = msg.scanner || "unknown";
    let channel = this.scannerChannels.get(name);
    if (!channel) {
      channel = vscode.window.createOutputChannel(`AgentSec: ${name}`);
      this.scannerChannels.set(name, channel);
    }
    channel.append(msg.text);
  }

  private handleProgress(msg: ProgressMessage): void {
    if (!this._state) {
      this.outputChannel.warn(
        `[handleProgress] event=${msg.event} arrived but _state is null — ignoring`
      );
      return;
    }

    this.outputChannel.debug(
      `[handleProgress] event=${msg.event}, files=${msg.filesScanned}/${msg.totalFiles}, ` +
      `issues=${msg.issuesFound}, pct=${msg.percentComplete}, msg="${msg.message ?? ""}"`
    );

    // Update common fields
    this._state.elapsedSeconds = msg.elapsedSeconds;
    this._state.filesScanned = msg.filesScanned;
    this._state.totalFiles = msg.totalFiles;
    this._state.issuesFound = msg.issuesFound;
    this._state.percentComplete = msg.percentComplete;

    // Update phase based on event type
    switch (msg.event) {
      case "scan_started":
        this._state.phase = "discovery";
        break;

      case "parallel_plan_ready":
        this._state.phase = "parallel_scan";
        break;

      case "sub_agent_started": {
        this._state.phase = "parallel_scan";
        const scannerName = msg.currentFile || "unknown";
        let entry = this.scannerRegistry.get(scannerName);
        if (!entry) {
          entry = this.scannerRegistry.register(scannerName, scannerName);
        }
        this.scannerRegistry.markRunning(scannerName);
        this.updateScannersState();
        break;
      }

      case "sub_agent_finished": {
        const name = msg.currentFile || "unknown";
        this.scannerRegistry.markCompleted(name, msg.issuesFound);
        this.updateScannersState();
        break;
      }

      case "llm_analysis_started":
        this._state.phase = "llm_analysis";
        break;

      case "llm_analysis_finished":
        break;

      case "synthesis_started":
        this._state.phase = "synthesis";
        break;

      case "synthesis_finished":
        break;

      case "scan_finished":
        this._state.phase = "complete";
        break;

      case "warning":
        this.outputChannel.warn(msg.message);
        break;

      case "error":
        this.outputChannel.error(msg.message);
        break;
    }

    this.emitStateChange();
  }

  private async handleResult(msg: ResultMessage): Promise<void> {
    this._isScanning = false;

    if (!this._state) {
      this.outputChannel.warn("[handleResult] No _state — ignoring result message");
      return;
    }

    // Detailed logging for troubleshooting the results pipeline
    this.outputChannel.info(
      `[handleResult] status=${msg.status}, content length=${msg.content?.length ?? 0}, ` +
      `error=${msg.error || "(none)"}`
    );
    if (msg.content) {
      this.outputChannel.debug(
        `[handleResult] content preview (first 500 chars):\n${msg.content.slice(0, 500)}`
      );
    }

    this._state.resultContent = msg.content;
    this._state.errorMessage = msg.error;
    this._state.reportPath = msg.reportPath || "";

    if (msg.reportPath) {
      this.outputChannel.info(`[handleResult] Report saved to: ${msg.reportPath}`);
    }

    if (msg.status === "success" && msg.content) {
      this._state.phase = "complete";
      this.outputChannel.info(
        `[handleResult] Calling parseFindings on content (${msg.content.length} chars)...`
      );
      this._findings = parseFindings(msg.content);

      this.outputChannel.info(
        `[handleResult] parseFindings returned ${this._findings.length} findings`
      );
      if (this._findings.length > 0) {
        for (let i = 0; i < Math.min(5, this._findings.length); i++) {
          const f = this._findings[i];
          this.outputChannel.debug(
            `[handleResult] finding[${i}]: severity=${f.severity}, ` +
            `file=${f.filePath}:${f.lineNumber}, title="${f.title.slice(0, 80)}", source=${f.source || "(none)"}`
          );
        }
        if (this._findings.length > 5) {
          this.outputChannel.debug(
            `[handleResult] ... and ${this._findings.length - 5} more findings`
          );
        }
      }
      if (this._findings.length === 0) {
        this.outputChannel.warn(
          `[handleResult] 0 findings parsed from ${msg.content.length} chars of content — ` +
          `the report format may not contain file:line patterns. ` +
          `Showing raw report in AgentSec output channel.`
        );
        // Show the raw report in the main output channel so the user
        // can at least see the results even if parsing found nothing.
        this.outputChannel.info("─── Scan Report ───");
        this.outputChannel.info(msg.content);
        this.outputChannel.info("─── End of Report ───");
      }

      // Push findings to VS Code Problems panel
      const workspaceRoot = this._state.targetFolder;
      this.outputChannel.info(
        `[handleResult] Pushing ${this._findings.length} findings to diagnostics (workspaceRoot="${workspaceRoot}")`
      );
      await pushFindings(this._findings, workspaceRoot);

      // Update issuesFound from parsed findings so dashboard shows the real count
      this._state.issuesFound = this._findings.length;

      this.outputChannel.info(
        `[handleResult] Scan complete: ${this._findings.length} findings pushed to diagnostics, ` +
        `state.issuesFound updated to ${this._state.issuesFound}`
      );
    } else if (msg.status === "timeout") {
      this._state.phase = "error";
      this._state.errorMessage = msg.error || "Scan timed out";
      this.outputChannel.warn(
        `[handleResult] Scan timed out: ${msg.error || "(no error details)"}`
      );
      // Still parse partial results if available
      if (msg.content) {
        this._findings = parseFindings(msg.content);
        this.outputChannel.info(
          `[handleResult] Parsed ${this._findings.length} findings from partial (timeout) content`
        );
      }
    } else {
      this._state.phase = "error";
      this._state.errorMessage = msg.error || "Scan failed";
      this.outputChannel.error(
        `[handleResult] Scan failed: status=${msg.status}, error=${msg.error || "(none)"}`
      );
    }

    this.outputChannel.info(
      `[handleResult] Emitting state change (phase=${this._state.phase}) ` +
      `and onScanComplete (${this._findings.length} findings)`
    );
    this.emitStateChange();
    this.onScanComplete?.(this._state, this._findings);
  }

  private updateScannersState(): void {
    if (!this._state) {
      return;
    }
    this._state.scanners = this.scannerRegistry.getAll().map((entry) => ({
      name: entry.label,
      state: entry.state as "queued" | "running" | "completed" | "failed" | "timeout",
      findingsCount: entry.findingsCount,
      elapsedSeconds: (Date.now() - entry.startedAt) / 1000,
      message: "",
    }));
  }

  private emitStateChange(): void {
    if (this._state) {
      this.outputChannel.debug(
        `[emitStateChange] phase=${this._state.phase}, issues=${this._state.issuesFound}, ` +
        `scanners=${this._state.scanners.length}, hasOnStateChange=${!!this.onStateChange}, ` +
        `hasOnScanComplete=${!!this.onScanComplete}`
      );
      this.onStateChange?.({ ...this._state });
    } else {
      this.outputChannel.debug("[emitStateChange] _state is null — nothing to emit");
    }
  }
}
