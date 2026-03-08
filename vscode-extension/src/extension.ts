/**
 * AgentSec VS Code Extension — entry point.
 *
 * Registers commands, tree views, the chat participant, the
 * scan dashboard webview, and the status bar item.
 */

import * as vscode from "vscode";
import { AgentSecBridge, discoverTools } from "./backend/bridge.js";
import { ScanOrchestrator } from "./orchestrator/scan-orchestrator.js";
import { scanWorkspace, scanFolder, scanFile } from "./commands/scan.js";
import { ToolStatusProvider } from "./views/tool-status/provider.js";
import { ResultsTreeProvider } from "./views/results-tree/provider.js";
import { ScanDashboardProvider } from "./views/scan-dashboard/provider.js";
import { registerChatParticipant } from "./chat/participant.js";
import { getOutputChannel, disposeOutputChannel } from "./utils/output-channel.js";
import { disposeDiagnostics } from "./utils/diagnostics.js";

let bridge: AgentSecBridge | undefined;
let orchestrator: ScanOrchestrator | undefined;
let statusBarItem: vscode.StatusBarItem | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const outputChannel = getOutputChannel();
  outputChannel.info("AgentSec extension activating");
  outputChannel.info(`[activate] extensionPath = ${context.extensionPath}`);
  outputChannel.info(`[activate] extensionUri  = ${context.extensionUri.fsPath}`);
  outputChannel.info(`[activate] workspace folders = ${vscode.workspace.workspaceFolders?.map(f => f.uri.fsPath).join(", ") ?? "(none)"}`);

  const extensionPath = context.extensionPath;

  // ── Status bar ────────────────────────────────────────────
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    50
  );
  statusBarItem.command = "agentsec.showDashboard";
  statusBarItem.text = "$(shield) AgentSec";
  statusBarItem.tooltip = "AgentSec Security Scanner";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // ── Tree views ────────────────────────────────────────────
  const toolStatusProvider = new ToolStatusProvider();
  toolStatusProvider.populateFromRegistry();
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("agentsec.toolStatus", toolStatusProvider)
  );

  const resultsProvider = new ResultsTreeProvider();
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("agentsec.results", resultsProvider)
  );

  // ── Dashboard webview ─────────────────────────────────────
  const dashboardProvider = new ScanDashboardProvider(context.extensionUri);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("agentsec.dashboard", dashboardProvider)
  );

  // ── Helper: ensure bridge + orchestrator are started ──────
  async function ensureOrchestrator(): Promise<ScanOrchestrator> {
    outputChannel.info("[ensureOrchestrator] Called");
    if (orchestrator && bridge?.isRunning) {
      outputChannel.info("[ensureOrchestrator] Reusing existing bridge + orchestrator");
      return orchestrator;
    }

    // Clean up previous instance
    if (bridge) {
      outputChannel.info("[ensureOrchestrator] Disposing previous bridge");
      bridge.dispose();
    }

    outputChannel.info("[ensureOrchestrator] Creating new AgentSecBridge + ScanOrchestrator");
    bridge = new AgentSecBridge(outputChannel, extensionPath);
    orchestrator = new ScanOrchestrator(bridge, outputChannel);

    // Wire up state changes to UI components
    orchestrator.onStateChange = (state) => {
      dashboardProvider.updateState(state);

      const statusText: Record<string, string> = {
        idle: "$(shield~spin) AgentSec: Scanning...",
        discovery: "$(shield~spin) AgentSec: Scanning...",
        llm_analysis: "$(shield~spin) AgentSec: Analyzing...",
        synthesis: "$(shield~spin) AgentSec: Synthesizing...",
        complete: `$(shield) AgentSec: ${state.issuesFound} findings`,
        error: "$(shield) AgentSec: Error",
      };

      if (state.phase === "parallel_scan") {
        const done = state.scanners.filter((s) => s.state === "completed").length;
        statusBarItem!.text = `$(shield~spin) AgentSec: ${done}/${state.scanners.length} tools`;
      } else {
        statusBarItem!.text = statusText[state.phase] ?? "$(shield) AgentSec";
      }
    };

    orchestrator.onScanComplete = (state, findings) => {
      outputChannel.info(
        `[onScanComplete] phase=${state.phase}, findings=${findings.length}, ` +
        `resultContent length=${state.resultContent?.length ?? 0}`
      );
      const workspaceRoot = state.targetFolder;
      resultsProvider.update(findings, workspaceRoot);

      if (state.phase === "complete") {
        if (findings.length > 0) {
          vscode.window.showInformationMessage(
            `AgentSec scan complete: ${findings.length} findings`
          );
        } else if (state.resultContent) {
          // Findings parser couldn't extract structured findings, but
          // a report was produced.  Show it in the output channel so
          // the user isn't left with a blank results pane.
          vscode.window.showInformationMessage(
            "AgentSec scan complete. Report written to the AgentSec output channel.",
            "Show Output"
          ).then((choice) => {
            if (choice === "Show Output") {
              outputChannel.show(true);
            }
          });
        } else {
          vscode.window.showInformationMessage(
            "AgentSec scan complete: no findings."
          );
        }
      } else if (state.phase === "error") {
        vscode.window.showErrorMessage(
          `AgentSec scan failed: ${state.errorMessage}`
        );
      }
    };

    // Wire dashboard → orchestrator for "show output" clicks
    dashboardProvider.onShowOutput = (name) => {
      orchestrator?.showScannerOutput(name);
    };

    // Wire dashboard → open full report in editor
    dashboardProvider.onOpenReport = () => {
      const reportPath = orchestrator?.state?.reportPath;
      outputChannel.info(`[onOpenReport] reportPath=${reportPath || "(none)"}`);
      if (reportPath) {
        vscode.window.showTextDocument(vscode.Uri.file(reportPath), {
          preview: false,
        });
      } else if (orchestrator?.state?.resultContent) {
        // Fallback: open an untitled document with the report content
        outputChannel.info("[onOpenReport] No reportPath — opening untitled document");
        vscode.workspace.openTextDocument({
          content: orchestrator.state.resultContent,
          language: "markdown",
        }).then((doc) => vscode.window.showTextDocument(doc, { preview: false }));
      }
    };

    outputChannel.info("[ensureOrchestrator] Starting bridge (await bridge.start())...");
    try {
      await bridge.start();
      outputChannel.info("[ensureOrchestrator] Bridge started successfully");

      // Auto-discover scanners so the QuickPick has data on the
      // first scan without requiring a manual "Refresh Tools".
      try {
        const scanners = await discoverTools(outputChannel, undefined, extensionPath);
        toolStatusProvider.update(scanners);
        orchestrator.updateKnownScanners(scanners);
        outputChannel.info(`[ensureOrchestrator] Auto-discovered ${scanners.length} scanners`);
      } catch (discErr) {
        outputChannel.warn(`[ensureOrchestrator] Auto-discovery failed: ${discErr}`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      outputChannel.error(`[ensureOrchestrator] Bridge failed to start: ${msg}`);
      // Reset so next attempt creates a fresh bridge
      bridge?.dispose();
      bridge = undefined;
      orchestrator = undefined;
      throw err;
    }
    return orchestrator;
  }

  // ── Commands ──────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("agentsec.scanWorkspace", async () => {
      outputChannel.info("[command] agentsec.scanWorkspace triggered");
      try {
        const orch = await ensureOrchestrator();
        await scanWorkspace(orch);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        outputChannel.error(`[command] scanWorkspace failed: ${msg}`);
        vscode.window.showErrorMessage(`AgentSec: ${msg}`);
      }
    }),

    vscode.commands.registerCommand("agentsec.scanFolder", async (uri?: vscode.Uri) => {
      outputChannel.info(`[command] agentsec.scanFolder triggered, uri=${uri?.fsPath ?? "(none)"}`);
      try {
        const orch = await ensureOrchestrator();
        await scanFolder(orch, uri);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        outputChannel.error(`[command] scanFolder failed: ${msg}`);
        vscode.window.showErrorMessage(`AgentSec: ${msg}`);
      }
    }),

    vscode.commands.registerCommand("agentsec.scanFile", async (uri?: vscode.Uri) => {
      outputChannel.info(`[command] agentsec.scanFile triggered, uri=${uri?.fsPath ?? "(none)"}`);
      try {
        const orch = await ensureOrchestrator();
        await scanFile(orch, uri);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        outputChannel.error(`[command] scanFile failed: ${msg}`);
        vscode.window.showErrorMessage(`AgentSec: ${msg}`);
      }
    }),

    vscode.commands.registerCommand("agentsec.showDashboard", () => {
      // The dashboard is a webview view in the sidebar; focus it
      vscode.commands.executeCommand("agentsec.dashboard.focus");
    }),

    vscode.commands.registerCommand("agentsec.cancelScan", () => {
      if (orchestrator?.isScanning) {
        orchestrator.cancelScan();
      } else {
        vscode.window.showInformationMessage("No scan is currently running.");
      }
    }),

    vscode.commands.registerCommand("agentsec.refreshTools", async () => {
      outputChannel.info("[command] agentsec.refreshTools triggered");
      try {
        const scanners = await discoverTools(outputChannel, undefined, extensionPath);
        outputChannel.info(`[command] refreshTools succeeded: ${scanners.length} scanners found`);
        toolStatusProvider.update(scanners);
        // Keep the orchestrator's scanner list in sync so the
        // QuickPick (when enabled) shows accurate availability.
        if (orchestrator) {
          orchestrator.updateKnownScanners(scanners);
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        outputChannel.error(`[command] refreshTools failed: ${message}`);
        vscode.window.showErrorMessage(`Tool discovery failed: ${message}`);
      }
    }),

    vscode.commands.registerCommand("agentsec.configure", () => {
      vscode.commands.executeCommand("workbench.action.openSettings", "@ext:agentsec.agentsec");
    })
  );

  // ── Chat participant ──────────────────────────────────────
  registerChatParticipant(context, ensureOrchestrator);

  outputChannel.info("AgentSec extension activated");
}

export function deactivate(): void {
  bridge?.dispose();
  orchestrator?.dispose();
  disposeDiagnostics();
  disposeOutputChannel();
}
