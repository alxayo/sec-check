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

/**
 * Cache of resolved file paths to avoid repeated filesystem lookups.
 * Maps a (workspaceRoot, relativePath) key to an absolute path.
 */
const _resolvedPathCache = new Map<string, string>();

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
 * Resolve a file path extracted from the report to an actual file on disk.
 *
 * Tries the direct join first.  If that file does not exist, falls back
 * to a workspace-wide glob search for a matching filename suffix.
 * Results are cached so repeated calls for the same path are fast.
 *
 * @param relativePath - The path as parsed from the report (may be partial).
 * @param workspaceRoot - The scanned folder (used as the base for joining).
 * @returns The absolute path to the resolved file, or the best-effort
 *          direct-join path if nothing was found.
 */
export async function resolveFilePath(
  relativePath: string,
  workspaceRoot: string
): Promise<string> {
  const out = getOutputChannel();

  // If the path is already absolute, use it directly
  if (relativePath.startsWith("/") || relativePath.includes(":")) {
    return relativePath;
  }

  const cacheKey = `${workspaceRoot}||${relativePath}`;
  const cached = _resolvedPathCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  // Try the direct join first
  const directPath = `${workspaceRoot}/${relativePath}`;
  try {
    await vscode.workspace.fs.stat(vscode.Uri.file(directPath));
    _resolvedPathCache.set(cacheKey, directPath);
    return directPath;
  } catch {
    // File not found at direct path — try fuzzy resolution
  }

  // Extract just the filename for a glob search
  const fileName = relativePath.split("/").pop() || relativePath;

  // Search across all workspace folders if available, otherwise use the
  // scanned folder itself. We use a RelativePattern so the search is
  // scoped to the workspace folder that contains workspaceRoot.
  try {
    const matches = await vscode.workspace.findFiles(
      `**/${fileName}`,
      "**/node_modules/**",
      20
    );

    if (matches.length === 0) {
      out.debug(`[resolveFilePath] No matches for **/${fileName}`);
      _resolvedPathCache.set(cacheKey, directPath);
      return directPath;
    }

    // If there is only one match, use it
    if (matches.length === 1) {
      const resolved = matches[0].fsPath;
      out.debug(`[resolveFilePath] Single match: ${resolved}`);
      _resolvedPathCache.set(cacheKey, resolved);
      return resolved;
    }

    // Multiple matches — pick the one whose path suffix best matches
    // the relative path from the report.  Normalize to forward slashes.
    const normalizedRelative = relativePath.replace(/\\/g, "/");
    let bestMatch = matches[0].fsPath;
    let bestScore = 0;

    for (const uri of matches) {
      const candidate = uri.fsPath.replace(/\\/g, "/");
      if (candidate.endsWith(normalizedRelative)) {
        // Exact suffix match — best possible outcome
        bestMatch = uri.fsPath;
        bestScore = normalizedRelative.length;
        break;
      }
      // Score by how many trailing path segments match
      const segments = normalizedRelative.split("/");
      let score = 0;
      for (let s = segments.length - 1; s >= 0; s--) {
        const suffix = segments.slice(s).join("/");
        if (candidate.endsWith(suffix)) {
          score = suffix.length;
        }
      }
      if (score > bestScore) {
        bestScore = score;
        bestMatch = uri.fsPath;
      }
    }

    out.debug(
      `[resolveFilePath] Best match for "${relativePath}" → "${bestMatch}" (score=${bestScore}, ${matches.length} candidates)`
    );
    _resolvedPathCache.set(cacheKey, bestMatch);
    return bestMatch;
  } catch (err) {
    out.debug(`[resolveFilePath] findFiles error: ${err}`);
    _resolvedPathCache.set(cacheKey, directPath);
    return directPath;
  }
}

/**
 * Resolve file paths for an array of findings in parallel.
 *
 * Populates each finding's `resolvedFilePath` field with the
 * actual absolute path on disk.
 */
export async function resolveAllPaths(
  findings: Finding[],
  workspaceRoot: string
): Promise<void> {
  const out = getOutputChannel();
  out.info(
    `[resolveAllPaths] Resolving paths for ${findings.length} findings...`
  );

  const promises = findings.map(async (finding) => {
    if (!finding.filePath) {
      finding.resolvedFilePath = "";
      return;
    }
    finding.resolvedFilePath = await resolveFilePath(
      finding.filePath,
      workspaceRoot
    );
  });

  await Promise.all(promises);

  const resolved = findings.filter(
    (f) => f.resolvedFilePath && f.resolvedFilePath !== `${workspaceRoot}/${f.filePath}`
  ).length;
  out.info(
    `[resolveAllPaths] Done. ${resolved} paths were fuzzy-resolved to different locations.`
  );
}

/**
 * Push findings to the VS Code Problems panel.
 *
 * Resolves file paths (with fuzzy fallback), groups findings by
 * file, and creates diagnostics with rich messages including
 * description, remediation guidance, and scanner source.
 * Clears previous AgentSec diagnostics first.
 */
export async function pushFindings(
  findings: Finding[],
  workspaceRoot: string
): Promise<void> {
  const out = getOutputChannel();
  out.info(
    `[pushFindings] Received ${findings.length} findings, workspaceRoot="${workspaceRoot}"`
  );

  // Resolve all file paths (fuzzy search if direct path not found)
  await resolveAllPaths(findings, workspaceRoot);

  const collection = getDiagnosticCollection();
  collection.clear();

  // Group findings by file
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const finding of findings) {
    if (!finding.filePath) {
      continue;
    }

    const absPath = finding.resolvedFilePath || (
      finding.filePath.startsWith("/") || finding.filePath.includes(":")
        ? finding.filePath
        : `${workspaceRoot}/${finding.filePath}`
    );

    const uri = vscode.Uri.file(absPath);
    const key = uri.toString();

    if (!byFile.has(key)) {
      byFile.set(key, []);
    }

    // Line numbers in findings are 1-based; VS Code uses 0-based
    const line = Math.max(0, (finding.lineNumber || 1) - 1);
    const range = new vscode.Range(line, 0, line, 200);

    // Build a rich diagnostic message with full context
    const messageParts = [`[${finding.severity}] ${finding.title}`];

    if (finding.details && finding.details !== finding.title) {
      messageParts.push("", finding.details);
    }

    if (finding.codeSnippet) {
      messageParts.push("", `Code: ${finding.codeSnippet}`);
    }

    if (finding.remediation) {
      messageParts.push("", `Remediation: ${finding.remediation}`);
    }

    if (finding.confidence) {
      messageParts.push("", `Confidence: ${finding.confidence}`);
    }

    const diagnostic = new vscode.Diagnostic(
      range,
      messageParts.join("\n"),
      mapSeverity(finding.severity)
    );
    diagnostic.source = finding.source
      ? `AgentSec(${finding.source})`
      : "AgentSec";
    if (finding.source) {
      diagnostic.code = finding.source;
    }

    byFile.get(key)!.push(diagnostic);
  }

  // Apply diagnostics per file
  let totalDiagnostics = 0;
  for (const [uriStr, diagnostics] of byFile) {
    collection.set(vscode.Uri.parse(uriStr), diagnostics);
    totalDiagnostics += diagnostics.length;
  }

  out.info(
    `[pushFindings] Pushed ${totalDiagnostics} diagnostics across ${byFile.size} files to Problems panel`
  );
}

/**
 * Parse a Markdown scan report into structured findings.
 *
 * Extracts findings by looking for patterns like:
 *   - **severity** lines (CRITICAL, HIGH, MEDIUM, LOW)
 *   - File path:line number references
 *   - Code snippets in backticks
 *   - Surrounding context paragraphs for details and remediation
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
      out.debug(`[parseFindings] L${i + 1}: severity header → ${currentSeverity}`);
      continue;
    }

    // Also detect inline severity tags like "[CRITICAL]" or "**HIGH**" before a title
    const inlineSeverityMatch = line.match(
      /\*\*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*/i
    );
    if (inlineSeverityMatch) {
      currentSeverity = inlineSeverityMatch[1].toUpperCase() as FindingSeverity;
      out.debug(`[parseFindings] L${i + 1}: inline severity → ${currentSeverity}`);
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
        out.debug(`[parseFindings] L${i + 1}: duplicate key ${key} — skipping`);
        continue;
      }
      seen.add(key);
      out.debug(`[parseFindings] L${i + 1}: matched ${filePath}:${lineNumber} (${currentSeverity})`);

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

      // ── Collect surrounding context: details, remediation, confidence ──
      // Scan forward from the current line to gather context paragraphs
      // until we hit another file:line match, severity header, or blank section.
      const contextLines: string[] = [];
      const remediationLines: string[] = [];
      let confidence = "";

      const maxLookahead = Math.min(i + 20, lines.length);
      for (let j = i + 1; j < maxLookahead; j++) {
        const ctxLine = lines[j];

        // Stop at the next file:line pattern or severity header
        if (
          ctxLine.match(/(?:`)?[a-zA-Z0-9_./-]+\.[a-zA-Z]{1,10}:\d+(?:`)?/) &&
          j > i + 1
        ) {
          break;
        }
        if (ctxLine.match(/(?:^#+\s*|^\*\*|\[)\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b/i)) {
          break;
        }

        // Stop after 2 consecutive blank lines (end of section)
        if (!ctxLine.trim() && j + 1 < lines.length && !lines[j + 1].trim()) {
          break;
        }

        const trimmed = ctxLine.trim();
        if (!trimmed) {
          continue;
        }

        // Detect remediation lines (contain fix/remediate/mitigate keywords)
        if (
          trimmed.match(
            /\b(fix|remediat|mitigat|instead\s+use|replace\s+with|use\s+parameterized|should\s+use|recommend|solution|patch|upgrade|sanitiz|escap|encod|validat)\b/i
          )
        ) {
          const cleaned = trimmed.replace(/^[-*•·]+\s*/, "");
          remediationLines.push(cleaned);
          continue;
        }

        // Detect confidence notes (confirmed by multiple scanners)
        if (
          trimmed.match(
            /\b(confirmed\s+by|high-confidence|cross-validated|multiple\s+(tools|scanners)|validated\s+by)\b/i
          )
        ) {
          confidence = trimmed.replace(/^[-*•·]+\s*/, "");
          continue;
        }

        // Otherwise it's a context/description line
        // Skip lines that are just markdown formatting or code fences
        if (trimmed !== "```" && !trimmed.match(/^---+$/)) {
          const cleaned = trimmed.replace(/^[-*•·]+\s*/, "");
          if (cleaned && cleaned !== title) {
            contextLines.push(cleaned);
          }
        }
      }

      // Also check the previous few lines for context that precedes
      // the file:line reference (e.g. the finding description header)
      for (let j = Math.max(0, i - 3); j < i; j++) {
        const prevLine = lines[j].trim();
        if (!prevLine || prevLine === title) {
          continue;
        }
        // Skip severity headers and formatting
        if (prevLine.match(/(?:^#+\s*|^\*\*|\[)\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b/i)) {
          continue;
        }
        if (prevLine.match(/^---+$/) || prevLine === "```") {
          continue;
        }
        const cleaned = prevLine.replace(/^[-*•·#]+\s*/, "").replace(/\*\*/g, "").trim();
        if (cleaned && !contextLines.includes(cleaned)) {
          contextLines.unshift(cleaned);
        }
      }

      // Also check the source line and surrounding lines for scanner attribution
      if (!source) {
        for (let j = Math.max(0, i - 2); j <= Math.min(i + 3, lines.length - 1); j++) {
          const nearbyMatch = lines[j].match(
            /\b(bandit|eslint|trivy|graudit|guarddog|shellcheck|checkov|dependency-check|template-analyzer|LLM)\b/i
          );
          if (nearbyMatch) {
            source = nearbyMatch[1].toLowerCase();
            break;
          }
        }
      }

      const details = contextLines.slice(0, 5).join("\n");
      const remediation = remediationLines.slice(0, 5).join("\n");

      findings.push({
        severity: currentSeverity,
        title,
        filePath,
        lineNumber,
        source,
        codeSnippet,
        description: details || title,
        details,
        remediation,
        confidence,
        resolvedFilePath: "",
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
