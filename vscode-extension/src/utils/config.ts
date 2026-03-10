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
  modelScanners: string;
  modelAnalysis: string;
  modelSynthesis: string;
  maxConcurrent: number;
  enableLlmAnalysis: boolean;
  scanTimeout: number;
  scanMode: "parallel" | "serial";
  promptScannerSelection: boolean;
  systemMessage: string;
  systemMessageFile: string;
  initialPrompt: string;
  initialPromptFile: string;
  configFile: string;
  skipScanners: string[];
  verbose: boolean;
}

/**
 * Read the current extension configuration.
 */
export function getExtensionConfig(): ExtensionConfig {
  const cfg = vscode.workspace.getConfiguration("agentsec");
  return {
    pythonPath: cfg.get<string>("pythonPath", "python3"),
    model: cfg.get<string>("model", "gpt-5"),
    modelScanners: cfg.get<string>("modelScanners", ""),
    modelAnalysis: cfg.get<string>("modelAnalysis", ""),
    modelSynthesis: cfg.get<string>("modelSynthesis", ""),
    maxConcurrent: cfg.get<number>("maxConcurrent", 3),
    enableLlmAnalysis: cfg.get<boolean>("enableLlmAnalysis", true),
    scanTimeout: cfg.get<number>("scanTimeout", 1800),
    scanMode: cfg.get<"parallel" | "serial">("scanMode", "parallel"),
    promptScannerSelection: cfg.get<boolean>("promptScannerSelection", false),
    systemMessage: cfg.get<string>("systemMessage", ""),
    systemMessageFile: cfg.get<string>("systemMessageFile", ""),
    initialPrompt: cfg.get<string>("initialPrompt", ""),
    initialPromptFile: cfg.get<string>("initialPromptFile", ""),
    configFile: cfg.get<string>("configFile", ""),
    skipScanners: cfg.get<string[]>("skipScanners", []),
    verbose: cfg.get<boolean>("verbose", false),
  };
}

/**
 * Convert extension config to a ScanConfig for the bridge.
 */
export function toScanConfig(cfg: ExtensionConfig): ScanConfig {
  const scanCfg: ScanConfig = {
    model: cfg.model,
    maxConcurrent: cfg.maxConcurrent,
    enableLlmAnalysis: cfg.enableLlmAnalysis,
    timeout: cfg.scanTimeout,
  };

  // Per-phase model overrides (only send if user set them)
  if (cfg.modelScanners) {
    scanCfg.modelScanners = cfg.modelScanners;
  }
  if (cfg.modelAnalysis) {
    scanCfg.modelAnalysis = cfg.modelAnalysis;
  }
  if (cfg.modelSynthesis) {
    scanCfg.modelSynthesis = cfg.modelSynthesis;
  }

  // System message / prompt overrides
  if (cfg.systemMessage) {
    scanCfg.systemMessage = cfg.systemMessage;
  }
  if (cfg.initialPrompt) {
    scanCfg.initialPrompt = cfg.initialPrompt;
  }

  return scanCfg;
}
