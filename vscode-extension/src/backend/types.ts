/**
 * Shared TypeScript types for the AgentSec VS Code extension.
 *
 * These types mirror the Python dataclasses and enums from the
 * agentsec-core package, ensuring type-safe communication over
 * the JSON Lines bridge protocol.
 */

// ── Progress event types (mirrors progress.py ProgressEventType) ──

export type ProgressEventType =
  | "scan_started"
  | "scan_finished"
  | "files_discovered"
  | "file_started"
  | "file_finished"
  | "heartbeat"
  | "parallel_plan_ready"
  | "sub_agent_started"
  | "sub_agent_finished"
  | "synthesis_started"
  | "synthesis_finished"
  | "llm_analysis_started"
  | "llm_analysis_finished"
  | "tool_stuck"
  | "tool_error_detected"
  | "tool_retry_loop"
  | "warning"
  | "error";

// ── Messages from Python -> TypeScript ──

export interface ProgressMessage {
  type: "progress";
  event: ProgressEventType;
  message: string;
  currentFile: string | null;
  filesScanned: number;
  totalFiles: number;
  issuesFound: number;
  elapsedSeconds: number;
  percentComplete: number;
}

export interface ResultMessage {
  type: "result";
  status: "success" | "error" | "timeout";
  content: string;
  error: string;
  reportPath?: string;
}

export interface ScannerInfo {
  name: string;
  description: string;
  toolName: string;
  toolAvailable: boolean;
  toolPath: string | null;
  source: "user" | "project";
}

export interface ToolStatusMessage {
  type: "tool_status";
  scanners: ScannerInfo[];
}

export interface LogMessage {
  type: "log";
  level: "info" | "warn" | "error";
  message: string;
}

export interface ReadyMessage {
  type: "ready";
}

export interface ScannerOutputMessage {
  type: "scanner_output";
  scanner: string;
  text: string;
}

export type BridgeMessage =
  | ProgressMessage
  | ResultMessage
  | ToolStatusMessage
  | LogMessage
  | ReadyMessage
  | ScannerOutputMessage;

// ── Messages from TypeScript -> Python ──

export interface ScanCommand {
  type: "scan";
  folder: string;
  mode: "parallel" | "serial";
  config: ScanConfig;
}

export interface ScanConfig {
  model?: string;
  maxConcurrent?: number;
  enableLlmAnalysis?: boolean;
  timeout?: number;
  systemMessage?: string;
  scanners?: string[];
}

export interface CancelCommand {
  type: "cancel";
}

export interface DiscoverCommand {
  type: "discover";
  folder?: string;
}

export type BridgeCommand = ScanCommand | CancelCommand | DiscoverCommand;

// ── Scan state for UI tracking ──

export type ScanPhase =
  | "idle"
  | "discovery"
  | "parallel_scan"
  | "llm_analysis"
  | "synthesis"
  | "complete"
  | "error";

export type ScannerState =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "timeout";

export interface ScannerStatus {
  name: string;
  state: ScannerState;
  findingsCount: number;
  elapsedSeconds: number;
  message: string;
}

export interface ScanState {
  phase: ScanPhase;
  targetFolder: string;
  mode: "parallel" | "serial";
  elapsedSeconds: number;
  totalFiles: number;
  filesScanned: number;
  issuesFound: number;
  percentComplete: number;
  scanners: ScannerStatus[];
  resultContent: string;
  errorMessage: string;
  reportPath: string;
}

export function createInitialScanState(
  folder: string,
  mode: "parallel" | "serial"
): ScanState {
  return {
    phase: "idle",
    targetFolder: folder,
    mode,
    elapsedSeconds: 0,
    totalFiles: 0,
    filesScanned: 0,
    issuesFound: 0,
    percentComplete: -1,
    scanners: [],
    resultContent: "",
    errorMessage: "",
    reportPath: "",
  };
}

// ── Finding parsed from scan results ──

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  severity: FindingSeverity;
  title: string;
  filePath: string;
  lineNumber: number;
  source: string;
  codeSnippet: string;
  description: string;
}
