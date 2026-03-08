/**
 * Diagnostics integration for AgentSec.
 *
 * Parses scan result Markdown to extract findings and pushes
 * them to the VS Code Diagnostics API so they appear in the
 * Problems panel with inline squiggles.
 */

import * as vscode from "vscode";
import type { Finding, FindingSeverity } from "../backend/types.js";

import { getOutputChannel } from "./output-channel.js";

let _collection: vscode.DiagnosticCollection | undefined;

/**
 * Get or create the AgentSec diagnostics collection.
 */
export function getDiagnosticCollection(): vscode.DiagnosticCollection {
  if (!_collection) {
    _collection = vscode.languages.createDiagnosticCollection("AgentSec");
  }
  return _collection;
}

/**
 * Map an AgentSec severity to a VS Code DiagnosticSeverity.
 */
function mapSeverity(severity: FindingSeverity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return vscode.DiagnosticSeverity.Error;
    case "MEDIUM":
      return vscode.DiagnosticSeverity.Warning;
    case "LOW":
      return vscode.DiagnosticSeverity.Information;
    case "INFO":
      return vscode.DiagnosticSeverity.Hint;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

/**
 * Push findings to the VS Code Problems panel.
 *
 * Groups findings by file and creates diagnostics for each one.
 * Clears previous AgentSec diagnostics first.
 */
export function pushFindings(
  findings: Finding[],
  workspaceRoot: string
): void {
  const collection = getDiagnosticCollection();
  collection.clear();

  // Group findings by file
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const finding of findings) {
    if (!finding.filePath) {
      continue;
    }

    const absPath = finding.filePath.startsWith("/") || finding.filePath.includes(":")
      ? finding.filePath
      : `${workspaceRoot}/${finding.filePath}`;

    const uri = vscode.Uri.file(absPath);
    const key = uri.toString();

    if (!byFile.has(key)) {
      byFile.set(key, []);
    }

    // Line numbers in findings are 1-based; VS Code uses 0-based
    const line = Math.max(0, (finding.lineNumber || 1) - 1);
    const range = new vscode.Range(line, 0, line, 200);

    const diagnostic = new vscode.Diagnostic(
      range,
      `[${finding.severity}] ${finding.title}`,
      mapSeverity(finding.severity)
    );
    diagnostic.source = "AgentSec";
    if (finding.source) {
      diagnostic.code = finding.source;
    }

    byFile.get(key)!.push(diagnostic);
  }

  // Apply diagnostics per file
  for (const [uriStr, diagnostics] of byFile) {
    collection.set(vscode.Uri.parse(uriStr), diagnostics);
  }
}

/**
 * Parse a Markdown scan report into structured findings.
 *
 * Extracts findings by looking for patterns like:
 *   - **severity** lines (CRITICAL, HIGH, MEDIUM, LOW)
 *   - File path:line number references
 *   - Code snippets in backticks
 *
 * This is a best-effort parser since the report format
 * can vary depending on the LLM synthesis.
 */
export function parseFindings(reportMarkdown: string): Finding[] {
  const out = getOutputChannel();
  const findings: Finding[] = [];
  const lines = reportMarkdown.split("\n");

  out.debug(`[parseFindings] Parsing ${lines.length} lines (${reportMarkdown.length} chars)`);

  let currentSeverity: FindingSeverity = "MEDIUM";

  // Track a set of (filePath, lineNumber) to avoid duplicates
  const seen = new Set<string>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Detect severity headers — e.g. "## CRITICAL", "### HIGH Findings", "**CRITICAL**"
    const severityMatch = line.match(
      /(?:^#+\s*|^\*\*|\[)\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b/i
    );
    if (severityMatch) {
      currentSeverity = severityMatch[1].toUpperCase() as FindingSeverity;
      continue;
    }

    // Also detect inline severity tags like "[CRITICAL]" or "**HIGH**" before a title
    const inlineSeverityMatch = line.match(
      /\*\*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*/i
    );
    if (inlineSeverityMatch) {
      currentSeverity = inlineSeverityMatch[1].toUpperCase() as FindingSeverity;
    }

    // Look for file:line patterns — multiple formats the LLM might produce:
    //   src/app.py:42          **src/app.py:42**
    //   `src/app.py:42`        — `src/app.py:42`
    //   **File**: src/app.py:42
    //   **File**: `src/app.py:42`
    const fileLineMatch = line.match(
      /(?:\*\*)?(?:File\s*:\s*)?(?:`)?([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,10}):(\d+)(?:`)?(?:\*\*)?/
    );
    if (fileLineMatch) {
      const filePath = fileLineMatch[1];
      const lineNumber = parseInt(fileLineMatch[2], 10);

      // Deduplicate same file:line within a severity
      const key = `${currentSeverity}:${filePath}:${lineNumber}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);

      // Try to extract the finding title from the same or previous line
      let title = line.replace(fileLineMatch[0], "").trim();
      title = title.replace(/^[-*•·:|`\]]+\s*/, "").trim();
      // Remove trailing markdown formatting
      title = title.replace(/\*\*$/g, "").trim();
      if (!title && i > 0) {
        title = lines[i - 1].replace(/^[-*•#]+\s*/, "").trim();
      }
      if (!title) {
        title = `Finding at ${filePath}:${lineNumber}`;
      }

      // Try to extract code snippet from next line if it's indented or fenced
      let codeSnippet = "";
      if (i + 1 < lines.length) {
        const nextLine = lines[i + 1];
        if (nextLine.startsWith("    ") || nextLine.startsWith("\t") || nextLine.startsWith("> ")) {
          codeSnippet = nextLine.trim().replace(/^>\s*/, "");
        }
      }

      // Try to extract the source scanner from the line
      let source = "";
      const sourceMatch = line.match(
        /\b(bandit|eslint|trivy|graudit|guarddog|shellcheck|checkov|dependency-check|template-analyzer|LLM)\b/i
      );
      if (sourceMatch) {
        source = sourceMatch[1].toLowerCase();
      }

      findings.push({
        severity: currentSeverity,
        title,
        filePath,
        lineNumber,
        source,
        codeSnippet,
        description: title,
      });
    }
  }

  out.info(
    `[parseFindings] Extracted ${findings.length} findings ` +
    `(CRITICAL=${findings.filter(f => f.severity === "CRITICAL").length}, ` +
    `HIGH=${findings.filter(f => f.severity === "HIGH").length}, ` +
    `MEDIUM=${findings.filter(f => f.severity === "MEDIUM").length}, ` +
    `LOW=${findings.filter(f => f.severity === "LOW").length})`
  );

  return findings;
}

/**
 * Clear all AgentSec diagnostics.
 */
export function clearDiagnostics(): void {
  _collection?.clear();
}

/**
 * Dispose the diagnostics collection. Call on extension deactivation.
 */
export function disposeDiagnostics(): void {
  _collection?.dispose();
  _collection = undefined;
}
