/**
 * Scanner registry — mirrors SCANNER_REGISTRY from
 * core/agentsec/skill_discovery.py.
 *
 * This is used for UI display (icons, labels) when the Python
 * bridge is not yet running, and for static type information.
 */

export interface ScannerDefinition {
  tool: string;
  extensions: string[] | null;
  description: string;
  icon: string;
}

/**
 * Static registry of known security scanners.
 *
 * Matches the entries in SCANNER_REGISTRY from skill_discovery.py.
 * The `icon` field uses VS Code codicons for tree view display.
 */
export const SCANNER_REGISTRY: Record<string, ScannerDefinition> = {
  "bandit-security-scan": {
    tool: "bandit",
    extensions: [".py"],
    description: "Python AST security analysis",
    icon: "snake",
  },
  "eslint-security-scan": {
    tool: "eslint",
    extensions: [".js", ".jsx", ".ts", ".tsx"],
    description: "JavaScript / TypeScript security analysis",
    icon: "file-code",
  },
  "shellcheck-security-scan": {
    tool: "shellcheck",
    extensions: [".sh", ".bash"],
    description: "Shell script security analysis",
    icon: "terminal",
  },
  "graudit-security-scan": {
    tool: "graudit",
    extensions: null,
    description: "Pattern-based source code auditing (multi-language)",
    icon: "search",
  },
  "guarddog-security-scan": {
    tool: "guarddog",
    extensions: [],
    description: "Supply-chain / malicious package detection",
    icon: "package",
  },
  "trivy-security-scan": {
    tool: "trivy",
    extensions: null,
    description: "Container, filesystem, and IaC scanning",
    icon: "server",
  },
  "checkov-security-scan": {
    tool: "checkov",
    extensions: [".tf", ".yaml", ".yml"],
    description: "Infrastructure-as-Code security scanning",
    icon: "cloud",
  },
  "dependency-check-security-scan": {
    tool: "dependency-check",
    extensions: [],
    description: "Dependency CVE scanning",
    icon: "library",
  },
};
