/**
 * Scan commands for the AgentSec extension.
 */

import * as vscode from "vscode";
import { ScanOrchestrator } from "../orchestrator/scan-orchestrator.js";

/**
 * Scan the current workspace root folder.
 */
export async function scanWorkspace(orchestrator: ScanOrchestrator): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    vscode.window.showErrorMessage("No workspace folder open.");
    return;
  }

  const folder = folders.length === 1
    ? folders[0]
    : await vscode.window.showWorkspaceFolderPick({ placeHolder: "Select workspace folder to scan" });

  if (folder) {
    await orchestrator.startScan(folder.uri.fsPath);
  }
}

/**
 * Scan a specific folder (from explorer context menu or picker).
 */
export async function scanFolder(orchestrator: ScanOrchestrator, uri?: vscode.Uri): Promise<void> {
  if (!uri) {
    const uris = await vscode.window.showOpenDialog({
      canSelectFiles: false,
      canSelectFolders: true,
      canSelectMany: false,
      title: "Select folder to scan",
    });
    uri = uris?.[0];
  }
  if (uri) {
    await orchestrator.startScan(uri.fsPath);
  }
}

/**
 * Scan the parent directory of a file (from context menu or active editor).
 */
export async function scanFile(orchestrator: ScanOrchestrator, uri?: vscode.Uri): Promise<void> {
  if (!uri) {
    uri = vscode.window.activeTextEditor?.document.uri;
    if (!uri) {
      vscode.window.showErrorMessage("No file selected.");
      return;
    }
  }
  await orchestrator.startScan(vscode.Uri.joinPath(uri, "..").fsPath);
}
