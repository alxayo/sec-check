/**
 * Results TreeView provider.
 *
 * Displays scan findings in the AgentSec sidebar, grouped by
 * severity. Clicking a finding navigates to the source location.
 */

import * as vscode from "vscode";
import type { Finding, FindingSeverity } from "../../backend/types.js";
import { getOutputChannel } from "../../utils/output-channel.js";

type ResultsTreeItem = SeverityGroup | FindingItem;

/**
 * TreeDataProvider that displays scan findings grouped by severity.
 */
export class ResultsTreeProvider implements vscode.TreeDataProvider<ResultsTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<ResultsTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: Finding[] = [];
  private workspaceRoot = "";

  /**
   * Update findings and refresh the tree.
   */
  update(findings: Finding[], workspaceRoot: string): void {
    const out = getOutputChannel();
    out.info(
      `[ResultsTreeProvider.update] Received ${findings.length} findings, ` +
      `workspaceRoot="${workspaceRoot}"`
    );
    if (findings.length > 0) {
      out.info(
        `[ResultsTreeProvider.update] First finding: severity=${findings[0].severity}, ` +
        `title="${findings[0].title}", file=${findings[0].filePath}:${findings[0].lineNumber}`
      );
    } else {
      out.warn("[ResultsTreeProvider.update] No findings to display in results tree");
    }
    this.findings = findings;
    this.workspaceRoot = workspaceRoot;
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Clear all findings.
   */
  clear(): void {
    this.findings = [];
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: ResultsTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: ResultsTreeItem): ResultsTreeItem[] {
    if (!element) {
      // Root level: show severity groups
      return this.getSeverityGroups();
    }

    if (element instanceof SeverityGroup) {
      // Show findings for this severity
      return this.findings
        .filter((f) => f.severity === element.severity)
        .map((f) => new FindingItem(f, this.workspaceRoot));
    }

    return [];
  }

  private getSeverityGroups(): SeverityGroup[] {
    const severities: FindingSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    const groups: SeverityGroup[] = [];

    for (const severity of severities) {
      const count = this.findings.filter((f) => f.severity === severity).length;
      if (count > 0) {
        groups.push(new SeverityGroup(severity, count));
      }
    }

    return groups;
  }

  dispose(): void {
    this._onDidChangeTreeData.dispose();
  }
}

class SeverityGroup extends vscode.TreeItem {
  constructor(
    public readonly severity: FindingSeverity,
    count: number
  ) {
    super(`${severity} (${count})`, vscode.TreeItemCollapsibleState.Expanded);

    const iconMap: Record<FindingSeverity, [string, string]> = {
      CRITICAL: ["error", "errorForeground"],
      HIGH: ["error", "errorForeground"],
      MEDIUM: ["warning", "warningForeground"],
      LOW: ["info", "infoForeground"],
      INFO: ["info", "infoForeground"],
    };

    const [icon, color] = iconMap[severity];
    this.iconPath = new vscode.ThemeIcon(icon, new vscode.ThemeColor(color));
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(finding: Finding, workspaceRoot: string) {
    const shortPath = finding.filePath.replace(/\\/g, "/");
    const label = finding.title || `Issue at ${shortPath}:${finding.lineNumber}`;

    super(label, vscode.TreeItemCollapsibleState.None);

    this.description = `${shortPath}:${finding.lineNumber}`;
    this.tooltip = [
      `[${finding.severity}] ${finding.title}`,
      `File: ${finding.filePath}:${finding.lineNumber}`,
      finding.source ? `Source: ${finding.source}` : "",
      finding.codeSnippet ? `\n${finding.codeSnippet}` : "",
    ]
      .filter(Boolean)
      .join("\n");

    // Click to navigate to the finding
    const absPath = finding.filePath.startsWith("/") || finding.filePath.includes(":")
      ? finding.filePath
      : `${workspaceRoot}/${finding.filePath}`;

    this.command = {
      command: "vscode.open",
      title: "Go to Finding",
      arguments: [
        vscode.Uri.file(absPath),
        {
          selection: new vscode.Range(
            Math.max(0, finding.lineNumber - 1),
            0,
            Math.max(0, finding.lineNumber - 1),
            200
          ),
        },
      ],
    };

    const iconMap: Record<FindingSeverity, string> = {
      CRITICAL: "error",
      HIGH: "error",
      MEDIUM: "warning",
      LOW: "info",
      INFO: "info",
    };
    this.iconPath = new vscode.ThemeIcon(iconMap[finding.severity]);
  }
}
