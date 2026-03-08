/**
 * Python bridge for the AgentSec VS Code extension.
 *
 * Spawns a Python child process running agentsec.vscode_bridge and
 * communicates over JSON Lines via stdin/stdout. Provides an
 * EventEmitter-based API for the extension to subscribe to progress
 * events, results, and tool status updates.
 */

import { ChildProcess, execFileSync, spawn } from "child_process";
import { EventEmitter } from "events";
import { existsSync } from "fs";
import { join } from "path";
import * as readline from "readline";
import * as vscode from "vscode";
import type {
  BridgeCommand,
  BridgeMessage,
  LogMessage,
  ProgressMessage,
  ResultMessage,
  ScanConfig,
  ScannerInfo,
  ScannerOutputMessage,
  ToolStatusMessage,
} from "./types.js";

/**
 * Events emitted by the AgentSecBridge.
 *
 * Subscribe using bridge.on("progress", handler) etc.
 */
export interface BridgeEvents {
  ready: [];
  progress: [ProgressMessage];
  result: [ResultMessage];
  toolStatus: [ToolStatusMessage];
  log: [LogMessage];
  error: [Error];
  exit: [number | null];
}

/**
 * Bridge to the Python agentsec-core agent.
 *
 * Lifecycle:
 *   1. const bridge = new AgentSecBridge(outputChannel)
 *   2. await bridge.start()           // spawns Python process
 *   3. bridge.on("progress", ...)     // subscribe to events
 *   4. bridge.sendScan(folder, ...)   // trigger a scan
 *   5. bridge.dispose()               // kill process, clean up
 */
export class AgentSecBridge extends EventEmitter<BridgeEvents> {
  private process: ChildProcess | null = null;
  private lineReader: readline.Interface | null = null;
  private outputChannel: vscode.LogOutputChannel;
  private readyPromise: Promise<void> | null = null;
  private extensionPath: string | undefined;

  constructor(outputChannel: vscode.LogOutputChannel, extensionPath?: string) {
    super();
    this.outputChannel = outputChannel;
    this.extensionPath = extensionPath;
  }

  /**
   * Start the Python bridge process.
   *
   * Spawns `python -m agentsec.vscode_bridge` and waits for
   * the "ready" message before resolving.
   */
  async start(): Promise<void> {
    if (this.process) {
      this.outputChannel.warn("[bridge.start] Bridge already running, skipping start");
      return;
    }

    this.outputChannel.info("[bridge.start] Resolving Python path...");

    const configuredPython = vscode.workspace
      .getConfiguration("agentsec")
      .get<string>("pythonPath", "python3");
    this.outputChannel.info(`[bridge.start] Configured pythonPath setting = "${configuredPython}"`);

    const pythonPath = resolvePython(configuredPython, this.outputChannel, this.extensionPath);
    this.outputChannel.info(`[bridge.start] Resolved Python executable = "${pythonPath}"`);

    // Verify the Python process can import agentsec before spawning the bridge
    this.outputChannel.info("[bridge.start] Verifying agentsec module is importable...");
    try {
      const importResult = execFileSync(
        pythonPath,
        ["-c", "import agentsec; print('agentsec location:', agentsec.__file__)"],
        { timeout: 10000, encoding: "utf-8" }
      );
      this.outputChannel.info(`[bridge.start] agentsec module found — ${importResult.trim()}`);
    } catch (importErr) {
      const stderr = (importErr as { stderr?: string }).stderr || "";
      const stdout = (importErr as { stdout?: string }).stdout || "";
      this.outputChannel.error(
        `[bridge.start] agentsec import FAILED.\n` +
        `  Python: "${pythonPath}"\n` +
        `  stdout: ${stdout.trim()}\n` +
        `  stderr: ${stderr.trim()}\n` +
        `  FIX: Activate the venv that has agentsec-core installed, or set ` +
        `"agentsec.pythonPath" in VS Code settings to the correct Python.`
      );
      throw new Error(
        `Python at "${pythonPath}" cannot import agentsec. ` +
        `Make sure agentsec-core is installed: pip install -e ./core\n` +
        `stderr: ${stderr.trim()}`
      );
    }

    this.outputChannel.info(`[bridge.start] Spawning: ${pythonPath} -m agentsec.vscode_bridge`);

    try {
      this.process = spawn(pythonPath, ["-m", "agentsec.vscode_bridge"], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env },
      });
      this.outputChannel.info(`[bridge.start] Process spawned, PID = ${this.process.pid}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.outputChannel.error(`[bridge.start] spawn() threw: ${message}`);
      throw new Error(
        `Failed to start Python ("${pythonPath}"): ${message}. ` +
        `Install Python 3.12+ and set "agentsec.pythonPath" in settings.`
      );
    }

    // Read stderr for Python logging (not part of the protocol)
    // Show stderr at WARN level so it's visible by default — this is
    // where Python tracebacks and import errors appear.
    if (this.process.stderr) {
      const errReader = readline.createInterface({ input: this.process.stderr });
      errReader.on("line", (line) => {
        this.outputChannel.warn(`[python stderr] ${line}`);
      });
    } else {
      this.outputChannel.warn("[bridge.start] No stderr pipe available");
    }

    // Read stdout as JSON Lines
    if (this.process.stdout) {
      this.lineReader = readline.createInterface({ input: this.process.stdout });
      this.lineReader.on("line", (line) => {
        this.outputChannel.debug(`[python stdout] ${line}`);
        this.handleLine(line);
      });
    } else {
      this.outputChannel.warn("[bridge.start] No stdout pipe available");
    }

    // Handle process exit
    this.process.on("exit", (code, signal) => {
      // SIGTERM is expected when we call dispose() — log at info, not error
      if (signal === "SIGTERM") {
        this.outputChannel.info(
          `[bridge] Process terminated (signal=SIGTERM) — this is normal cleanup after dispose()`
        );
      } else {
        this.outputChannel.error(
          `[bridge] Process exited unexpectedly — code=${code}, signal=${signal}. ` +
          `Check [python stderr] lines above for the traceback.`
        );
      }
      this.process = null;
      this.lineReader = null;
      this.emit("exit", code);
    });

    this.process.on("error", (err) => {
      this.outputChannel.error(`[bridge] Process error event: ${err.message}`);
      this.emit("error", err);
    });

    // Wait for the "ready" message
    this.outputChannel.info("[bridge.start] Waiting for 'ready' message from Python bridge...");
    this.readyPromise = new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.outputChannel.error("[bridge.start] Timed out after 30s waiting for 'ready' message");
        reject(new Error("Bridge did not send ready message within 30 seconds"));
      }, 30000);

      this.once("ready", () => {
        clearTimeout(timeout);
        this.outputChannel.info("[bridge.start] Received 'ready' — bridge is operational");
        resolve();
      });

      this.once("error", (err) => {
        clearTimeout(timeout);
        this.outputChannel.error(`[bridge.start] Error before ready: ${err.message}`);
        reject(err);
      });

      this.once("exit", (code) => {
        clearTimeout(timeout);
        this.outputChannel.error(
          `[bridge.start] Python process exited (code=${code}) before sending 'ready'. ` +
          `Check the [python stderr] lines in this log for the root cause.`
        );
        reject(new Error(`Bridge exited with code ${code} before ready`));
      });
    });

    return this.readyPromise;
  }

  /**
   * Send a scan command to the Python bridge.
   */
  sendScan(
    folder: string,
    mode: "parallel" | "serial" = "parallel",
    config: ScanConfig = {}
  ): void {
    this.send({ type: "scan", folder, mode, config });
  }

  /**
   * Send a cancel command to abort the running scan.
   */
  sendCancel(): void {
    this.send({ type: "cancel" });
  }

  /**
   * Request tool discovery from the bridge.
   */
  sendDiscover(folder?: string): void {
    this.send({ type: "discover", folder });
  }

  /**
   * Check if the bridge process is running.
   */
  get isRunning(): boolean {
    return this.process !== null && this.process.exitCode === null;
  }

  /**
   * Kill the bridge process and clean up resources.
   */
  dispose(): void {
    if (this.process) {
      this.process.kill();
      this.process = null;
    }
    if (this.lineReader) {
      this.lineReader.close();
      this.lineReader = null;
    }
    this.removeAllListeners();
  }

  // ── Private methods ──────────────────────────────────────

  private send(command: BridgeCommand): void {
    if (!this.process?.stdin?.writable) {
      this.outputChannel.error(`[bridge.send] Cannot send '${command.type}' — bridge not running or stdin closed`);
      return;
    }
    const line = JSON.stringify(command);
    this.outputChannel.info(`[bridge.send] Sending command: ${command.type}`);
    this.outputChannel.debug(`[bridge.send] Payload: ${line}`);
    this.process.stdin.write(line + "\n");
  }

  private handleLine(line: string): void {
    if (!line.trim()) {
      return;
    }

    let msg: BridgeMessage;
    try {
      msg = JSON.parse(line) as BridgeMessage;
    } catch {
      this.outputChannel.warn(`Non-JSON output from bridge: ${line}`);
      return;
    }

    switch (msg.type) {
      case "ready":
        this.outputChannel.info("Bridge is ready");
        this.emit("ready");
        break;

      case "progress":
        this.emit("progress", msg as ProgressMessage);
        break;

      case "result":
        this.emit("result", msg as ResultMessage);
        break;

      case "tool_status":
        this.emit("toolStatus", msg as ToolStatusMessage);
        break;

      case "log": {
        const logMsg = msg as LogMessage;
        switch (logMsg.level) {
          case "error":
            this.outputChannel.error(logMsg.message);
            break;
          case "warn":
            this.outputChannel.warn(logMsg.message);
            break;
          default:
            this.outputChannel.info(logMsg.message);
        }
        this.emit("log", logMsg);
        break;
      }

      case "scanner_output": {
        const soMsg = msg as ScannerOutputMessage;
        this.emit("scannerOutput", soMsg);
        break;
      }

      default:
        this.outputChannel.warn(`Unknown message type: ${(msg as { type: string }).type}`);
    }
  }
}

// ── Python resolution helper ────────────────────────────────

/**
 * Resolve the Python executable path.
 *
 * Search order:
 *   1. If user set an explicit absolute path, use it directly.
 *   2. Look for a virtualenv in each workspace folder.
 *   3. Look for a virtualenv relative to the extension source directory
 *      (covers the case where the scanned project differs from the AgentSec repo).
 *   4. Fall back to system "python3" then "python".
 */
function resolvePython(
  configured: string,
  log?: vscode.LogOutputChannel,
  extensionPath?: string
): string {
  log?.info(`[resolvePython] Starting Python resolution (configured="${configured}")`);

  // If user set an absolute / custom path, honour it
  if (configured !== "python" && configured !== "python3") {
    log?.info(`[resolvePython] Using user-configured path: "${configured}"`);
    return configured;
  }

  // Build the list of root directories to search for venvs
  const searchRoots: string[] = [];

  // Add workspace folders
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (workspaceFolders) {
    for (const folder of workspaceFolders) {
      searchRoots.push(folder.uri.fsPath);
    }
  }

  // Add the extension's parent directory (the AgentSec repo root)
  // e.g. extensionPath = /mnt/c/code/AgentSec/vscode-extension
  //      parent        = /mnt/c/code/AgentSec  (where venv/ lives)
  if (extensionPath) {
    const extensionParent = join(extensionPath, "..");
    searchRoots.push(extensionParent);
    // Also check the extension directory itself
    searchRoots.push(extensionPath);
  }

  log?.info(`[resolvePython] Search roots for venvs: [${searchRoots.join(", ")}]`);

  // Search each root for a virtualenv
  for (const root of searchRoots) {
    const venvCandidates = [
      join(root, "venv", "bin", "python3"),
      join(root, "venv", "bin", "python"),
      join(root, ".venv", "bin", "python3"),
      join(root, ".venv", "bin", "python"),
      // Windows
      join(root, "venv", "Scripts", "python.exe"),
      join(root, ".venv", "Scripts", "python.exe"),
    ];
    for (const candidate of venvCandidates) {
      const exists = existsSync(candidate);
      log?.info(`[resolvePython]   Checking: ${candidate}  exists=${exists}`);
      if (exists) {
        try {
          const versionOut = execFileSync(candidate, ["--version"], {
            encoding: "utf-8",
            timeout: 5000,
          }).trim();
          log?.info(`[resolvePython]   ✓ FOUND working venv Python: ${candidate} (${versionOut})`);
          return candidate;
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          log?.warn(`[resolvePython]   ✗ ${candidate} exists but failed to run: ${msg}`);
        }
      }
    }
  }

  // Fall back to system Python
  log?.info("[resolvePython] No venv found in any search root, trying system Python...");
  const systemCandidates = ["python3", "python"];
  for (const candidate of systemCandidates) {
    try {
      const versionOut = execFileSync(candidate, ["--version"], {
        encoding: "utf-8",
        timeout: 5000,
      }).trim();
      log?.info(`[resolvePython] Using system Python: ${candidate} (${versionOut})`);
      return candidate;
    } catch {
      log?.info(`[resolvePython]   System '${candidate}' not found or failed`);
    }
  }

  log?.warn(`[resolvePython] No Python found anywhere! Falling back to "${configured}"`);
  return configured;
}

// ── Convenience: one-shot tool discovery ──

/**
 * Run tool discovery and return scanner info without keeping
 * the bridge process alive afterward.
 */
export async function discoverTools(
  outputChannel: vscode.LogOutputChannel,
  folder?: string,
  extensionPath?: string
): Promise<ScannerInfo[]> {
  outputChannel.info("[discoverTools] Starting one-shot tool discovery");
  const bridge = new AgentSecBridge(outputChannel, extensionPath);

  try {
    outputChannel.info("[discoverTools] Starting bridge...");
    await bridge.start();
    outputChannel.info("[discoverTools] Bridge started, sending discover command");

    return await new Promise<ScannerInfo[]>((resolve, reject) => {
      const timeout = setTimeout(() => {
        outputChannel.error("[discoverTools] Timed out after 15s waiting for tool_status response");
        reject(new Error("Tool discovery timed out"));
      }, 15000);

      bridge.on("toolStatus", (msg) => {
        clearTimeout(timeout);
        outputChannel.info(`[discoverTools] Received tool_status with ${msg.scanners.length} scanners`);
        for (const s of msg.scanners) {
          const icon = s.toolAvailable ? "✓" : "✗";
          outputChannel.info(
            `[discoverTools]   ${icon} ${s.name}: available=${s.toolAvailable}, ` +
            `tool=${s.toolName ?? "?"}, path=${s.toolPath ?? "(not found on PATH)"}` +
            `${!s.toolAvailable ? " — install this tool or add it to PATH" : ""}`
          );
        }
        resolve(msg.scanners);
      });

      bridge.sendDiscover(folder);
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    outputChannel.error(`[discoverTools] Failed: ${message}`);
    throw err;
  } finally {
    outputChannel.info("[discoverTools] Disposing one-shot bridge");
    bridge.dispose();
  }
}
