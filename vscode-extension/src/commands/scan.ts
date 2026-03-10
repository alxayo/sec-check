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
 * Scan a specific file (from explorer context menu or active editor).
 *
 * When called from the explorer context menu, VS Code may pass multiple
 * selected URIs as the second argument.  We collect all file paths and
 * pass them to the orchestrator so the agent scans exactly those files
 * rather than the entire parent directory.
 */
export async function scanFile(
  orchestrator: ScanOrchestrator,
  uri?: vscode.Uri,
  allUris?: vscode.Uri[],
): Promise<void> {
  // Collect file URIs: multi-select, single click, or active editor.
  const uris: vscode.Uri[] = allUris?.length
    ? allUris
    : uri
      ? [uri]
      : vscode.window.activeTextEditor
        ? [vscode.window.activeTextEditor.document.uri]
        : [];

  if (!uris.length) {
    vscode.window.showErrorMessage("No file selected.");
    return;
  }

  const filePaths = uris.map((u) => u.fsPath);
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(uris[0]);
  const rootFolder = workspaceFolder?.uri.fsPath
    ?? vscode.Uri.joinPath(uris[0], "..").fsPath;

  await orchestrator.startScan(rootFolder, filePaths);
}

/**
 * Scan from the Source Control pane context menu.
 *
 * The SCM pane passes a SourceControlResourceState (an object with
 * a `resourceUri` property) rather than a plain vscode.Uri.
 * When multiple resources are selected, VS Code passes the full
 * array as the second argument.
 */
export async function scanScmResource(
  orchestrator: ScanOrchestrator,
  resource?: { resourceUri: vscode.Uri },
  allSelected?: { resourceUri: vscode.Uri }[],
): Promise<void> {
  // Collect URIs from all selected resources (or fall back to the single one).
  const resources = allSelected?.length ? allSelected : resource ? [resource] : [];

  if (!resources.length) {
    vscode.window.showErrorMessage("No file selected in Source Control.");
    return;
  }

  const filePaths = resources.map((r) => r.resourceUri.fsPath);
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(resources[0].resourceUri);
  const rootFolder = workspaceFolder?.uri.fsPath
    ?? vscode.Uri.joinPath(resources[0].resourceUri, "..").fsPath;

  await orchestrator.startScan(rootFolder, filePaths);
}
