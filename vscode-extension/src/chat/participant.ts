/**
 * Chat Participant for AgentSec.
 *
 * Registers an `@agentsec` chat participant in GitHub Copilot Chat
 * with slash commands for scanning, results, and tool status.
 */

import * as vscode from "vscode";
import type { ScanOrchestrator } from "../orchestrator/scan-orchestrator.js";
import { discoverTools } from "../backend/bridge.js";
import { getOutputChannel } from "../utils/output-channel.js";

type OrchestratorFactory = () => Promise<ScanOrchestrator>;

/**
 * Register the @agentsec chat participant and its slash commands.
 */
export function registerChatParticipant(
  context: vscode.ExtensionContext,
  getOrchestrator: OrchestratorFactory
): void {
  const participant = vscode.chat.createChatParticipant(
    "agentsec.chat",
    async (
      request: vscode.ChatRequest,
      _chatContext: vscode.ChatContext,
      stream: vscode.ChatResponseStream,
      token: vscode.CancellationToken
    ) => {
      const command = request.command;

      switch (command) {
        case "scan":
          await handleScan(stream, token, getOrchestrator, false);
          break;

        case "quick-scan":
          await handleScan(stream, token, getOrchestrator, true);
          break;

        case "supply-chain":
          await handleSupplyChain(stream, token, getOrchestrator);
          break;

        case "results":
          await handleResults(stream, getOrchestrator);
          break;

        case "tools":
          await handleTools(stream);
          break;

        default:
          // No command — treat as a general query
          stream.markdown(
            "I can help you scan your code for security vulnerabilities. Try one of these commands:\n\n" +
            "- `/scan` — Full parallel security scan\n" +
            "- `/quick-scan` — Quick scan (skip LLM analysis)\n" +
            "- `/supply-chain` — Scan dependencies for supply chain attacks\n" +
            "- `/results` — Show latest scan results\n" +
            "- `/tools` — Show available scanner tools\n"
          );
          break;
      }
    }
  );

  participant.iconPath = new vscode.ThemeIcon("shield");

  context.subscriptions.push(participant);
}

async function handleScan(
  stream: vscode.ChatResponseStream,
  token: vscode.CancellationToken,
  getOrchestrator: OrchestratorFactory,
  quickMode: boolean
): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    stream.markdown("No workspace folder is open. Please open a folder first.");
    return;
  }

  const folder = workspaceFolders[0].uri.fsPath;
  const mode = quickMode ? "quick" : "full";
  stream.progress(`Starting ${mode} security scan of ${folder}...`);

  try {
    const orchestrator = await getOrchestrator();

    // Listen for state changes and report via chat progress
    const originalOnChange = orchestrator.onStateChange;
    orchestrator.onStateChange = (state) => {
      originalOnChange?.(state);

      switch (state.phase) {
        case "discovery":
          stream.progress("Discovering files and selecting scanners...");
          break;
        case "parallel_scan": {
          const done = state.scanners.filter((s) => s.state === "completed").length;
          stream.progress(
            `Running scanners: ${done}/${state.scanners.length} complete`
          );
          break;
        }
        case "llm_analysis":
          stream.progress("Running LLM semantic analysis...");
          break;
        case "synthesis":
          stream.progress("Synthesizing results...");
          break;
      }
    };

    // Wait for scan completion
    const scanResult = await new Promise<{ content: string; error: string; findingsCount: number }>(
      (resolve) => {
        const originalOnComplete = orchestrator.onScanComplete;
        orchestrator.onScanComplete = (state, findings) => {
          originalOnComplete?.(state, findings);
          resolve({
            content: state.resultContent,
            error: state.errorMessage,
            findingsCount: findings.length,
          });
        };

        orchestrator.startScan(folder);
      }
    );

    if (token.isCancellationRequested) {
      stream.markdown("Scan was cancelled.");
      return;
    }

    if (scanResult.error) {
      stream.markdown(`**Scan failed:** ${scanResult.error}`);
      return;
    }

    // Show results summary
    stream.markdown(`## Scan Complete\n\n`);
    stream.markdown(`**${scanResult.findingsCount} findings** detected.\n\n`);

    if (scanResult.content) {
      // Truncate if very long for chat display
      const maxLen = 8000;
      const content =
        scanResult.content.length > maxLen
          ? scanResult.content.slice(0, maxLen) + "\n\n*... truncated. Use `/results` for full report.*"
          : scanResult.content;
      stream.markdown(content);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    stream.markdown(`**Error starting scan:** ${message}`);
  }
}

async function handleSupplyChain(
  stream: vscode.ChatResponseStream,
  token: vscode.CancellationToken,
  getOrchestrator: OrchestratorFactory
): Promise<void> {
  stream.markdown(
    "Supply chain scanning focuses on dependency analysis using `guarddog`, `trivy`, and `dependency-check`.\n\n"
  );
  await handleScan(stream, token, getOrchestrator, false);
}

async function handleResults(
  stream: vscode.ChatResponseStream,
  getOrchestrator: OrchestratorFactory
): Promise<void> {
  try {
    const orchestrator = await getOrchestrator();
    const findings = orchestrator.findings;

    if (findings.length === 0) {
      stream.markdown(
        "No scan results available. Run `/scan` to start a security scan."
      );
      return;
    }

    stream.markdown(`## Latest Scan Results\n\n`);
    stream.markdown(`**${findings.length} findings:**\n\n`);

    const severityCounts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    for (const f of findings) {
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    }

    stream.markdown(
      `| Severity | Count |\n|----------|-------|\n` +
      Object.entries(severityCounts)
        .filter(([, count]) => count > 0)
        .map(([sev, count]) => `| ${sev} | ${count} |`)
        .join("\n") +
      "\n\n"
    );

    for (const f of findings.slice(0, 20)) {
      stream.markdown(
        `- **[${f.severity}]** ${f.title} — \`${f.filePath}:${f.lineNumber}\`\n`
      );
    }

    if (findings.length > 20) {
      stream.markdown(
        `\n*... and ${findings.length - 20} more. Check the Problems panel for all findings.*\n`
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    stream.markdown(`**Error:** ${message}`);
  }
}

async function handleTools(stream: vscode.ChatResponseStream): Promise<void> {
  try {
    const outputChannel = getOutputChannel();
    const scanners = await discoverTools(outputChannel);

    stream.markdown("## Security Scanner Tools\n\n");

    const installed = scanners.filter((s) => s.toolAvailable);
    const missing = scanners.filter((s) => !s.toolAvailable);

    if (installed.length > 0) {
      stream.markdown("**Installed:**\n");
      for (const s of installed) {
        stream.markdown(`- ${s.toolName} — ${s.description}\n`);
      }
      stream.markdown("\n");
    }

    if (missing.length > 0) {
      stream.markdown("**Not installed:**\n");
      for (const s of missing) {
        stream.markdown(`- ${s.toolName} — ${s.description}\n`);
      }
    }

    if (scanners.length === 0) {
      stream.markdown(
        "Could not detect any scanners. Make sure `agentsec-core` is installed.\n"
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    stream.markdown(`**Error discovering tools:** ${message}`);
  }
}
