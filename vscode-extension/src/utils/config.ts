/**
 * Extension configuration helper.
 *
 * Reads agentsec.* settings from the VS Code workspace
 * configuration and returns typed values.
 */

import * as vscode from "vscode";
import type { ScanConfig } from "../backend/types.js";

export interface ExtensionConfig {
  pythonPath: string;
  model: string;
  maxConcurrent: number;
  enableLlmAnalysis: boolean;
  scanTimeout: number;
  scanMode: "parallel" | "serial";
  promptScannerSelection: boolean;
}

/**
 * Read the current extension configuration.
 */
export function getExtensionConfig(): ExtensionConfig {
  const cfg = vscode.workspace.getConfiguration("agentsec");
  return {
    pythonPath: cfg.get<string>("pythonPath", "python3"),
    model: cfg.get<string>("model", "gpt-5"),
    maxConcurrent: cfg.get<number>("maxConcurrent", 3),
    enableLlmAnalysis: cfg.get<boolean>("enableLlmAnalysis", true),
    scanTimeout: cfg.get<number>("scanTimeout", 1800),
    scanMode: cfg.get<"parallel" | "serial">("scanMode", "parallel"),
    promptScannerSelection: cfg.get<boolean>("promptScannerSelection", false),
  };
}

/**
 * Convert extension config to a ScanConfig for the bridge.
 */
export function toScanConfig(cfg: ExtensionConfig): ScanConfig {
  return {
    model: cfg.model,
    maxConcurrent: cfg.maxConcurrent,
    enableLlmAnalysis: cfg.enableLlmAnalysis,
    timeout: cfg.scanTimeout,
  };
}
