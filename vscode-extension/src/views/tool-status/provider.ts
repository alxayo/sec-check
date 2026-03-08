/**
 * Tool status TreeView provider.
 *
 * Shows a tree of security scanner tools with their availability
 * status (installed or missing) in the AgentSec sidebar.
 */

import * as vscode from "vscode";
import type { ScannerInfo } from "../../backend/types.js";
import { SCANNER_REGISTRY } from "../../backend/scanner-registry.js";

/**
 * TreeDataProvider that displays scanner tool availability.
 *
 * Each tree item shows the scanner name, description, and
 * whether the underlying CLI tool is installed.
 */
export class ToolStatusProvider implements vscode.TreeDataProvider<ToolStatusItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<ToolStatusItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private scanners: ScannerInfo[] = [];

  /**
   * Update the scanner list and refresh the tree.
   */
  update(scanners: ScannerInfo[]): void {
    this.scanners = scanners;
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Populate with static registry data (before bridge runs).
   */
  populateFromRegistry(): void {
    this.scanners = Object.entries(SCANNER_REGISTRY).map(([name, def]) => ({
      name,
      description: def.description,
      toolName: def.tool,
      toolAvailable: false,
      toolPath: null,
      source: "user" as const,
    }));
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: ToolStatusItem): vscode.TreeItem {
    return element;
  }

  getChildren(): ToolStatusItem[] {
    return this.scanners.map((scanner) => new ToolStatusItem(scanner));
  }

  dispose(): void {
    this._onDidChangeTreeData.dispose();
  }
}

class ToolStatusItem extends vscode.TreeItem {
  constructor(scanner: ScannerInfo) {
    super(scanner.toolName, vscode.TreeItemCollapsibleState.None);

    this.description = scanner.description;
    this.tooltip = scanner.toolAvailable
      ? `${scanner.toolName} is installed at ${scanner.toolPath}`
      : `${scanner.toolName} is not installed`;

    this.iconPath = scanner.toolAvailable
      ? new vscode.ThemeIcon("check", new vscode.ThemeColor("charts.green"))
      : new vscode.ThemeIcon("circle-slash", new vscode.ThemeColor("charts.red"));

    this.contextValue = scanner.toolAvailable ? "installed" : "missing";
  }
}
