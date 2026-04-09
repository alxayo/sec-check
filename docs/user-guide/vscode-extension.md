---
title: VS Code Extension
layout: default
parent: User Guide
nav_order: 3
description: "Guide to using the AgentSec VS Code extension with dashboard, tree views, and chat participant."
---

# VS Code Extension
{: .no_toc }

Native VS Code integration with a scan dashboard, tool status tree view, and Copilot Chat participant.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## Overview

The AgentSec VS Code extension provides a native IDE experience for security scanning:

- **Activity Bar panel** with scan dashboard, tool status, and results views
- **Context menu integration** — right-click folders or files to scan
- **Chat Participant** — use `@agentsec` commands in Copilot Chat
- **SCM integration** — scan changed files from the Source Control panel

---

## Commands

Open the Command Palette (`Ctrl+Shift+P`) and search for "AgentSec":

| Command | Description |
|:--------|:------------|
| **AgentSec: Scan Workspace for Security Issues** | Run a full security scan on the workspace |
| **AgentSec: Scan Folder for Security Issues** | Scan a specific folder |
| **AgentSec: Scan File for Security Issues** | Scan a single file |
| **AgentSec: Show Scan Dashboard** | Open the scan dashboard webview |
| **AgentSec: Cancel Running Scan** | Abort the current scan |
| **AgentSec: Refresh Tool Status** | Re-detect installed security tools |

---

## Chat Participant

The extension registers a `@agentsec` chat participant in Copilot Chat:

| Command | Description |
|:--------|:------------|
| `@agentsec /scan` | Run a full parallel security scan |
| `@agentsec /quick-scan` | Quick scan — skip LLM deep analysis |
| `@agentsec /supply-chain` | Scan dependencies for supply chain attacks |
| `@agentsec /results` | Show latest scan results |
| `@agentsec /tools` | Show available and missing security tools |

---

## Activity Bar

The extension adds an **AgentSec** panel to the Activity Bar (shield icon) with three views:

### Scan Dashboard

A webview that shows:
- Current scan progress and status
- Findings summary with severity breakdown
- Scan history

### Security Scanners

A tree view listing all supported security tools and their installation status:
- ✅ Installed and available
- ❌ Not found — with install instructions

Use the refresh button to re-detect tools.

### Scan Results

A tree view showing findings from the latest scan, organized by severity and file.

---

## Context Menu

Right-click in the Explorer:
- **On a folder** → _AgentSec: Scan Folder for Security Issues_
- **On a file** → _AgentSec: Scan File for Security Issues_

Right-click in Source Control (changed files):
- _AgentSec: Scan for Security Issues_ — scans only the changed files

---

## Extension Settings

Configure the extension in VS Code Settings (`Ctrl+,`) under **AgentSec**:

| Setting | Default | Description |
|:--------|:--------|:------------|
| `agentsec.pythonPath` | `python3` | Path to Python interpreter with agentsec-core installed |
| `agentsec.model` | `gpt-5` | Global LLM model for all scan phases |
| `agentsec.modelScanners` | _(empty)_ | Model override for Phase 2 (scanner sub-agents) |
| `agentsec.modelAnalysis` | _(empty)_ | Model override for Phase 3 (LLM deep analysis) |
| `agentsec.modelSynthesis` | _(empty)_ | Model override for Phase 4 (report synthesis) |
| `agentsec.maxConcurrent` | `3` | Max parallel scanner sessions (1–10) |
| `agentsec.enableLlmAnalysis` | `true` | Enable LLM deep analysis phase |
| `agentsec.scanTimeout` | `1800` | Safety timeout in seconds |
| `agentsec.scanMode` | `parallel` | `parallel` or `serial` execution mode |
| `agentsec.promptScannerSelection` | `false` | Show scanner picker before each scan |
| `agentsec.systemMessage` | _(empty)_ | Custom system message override |
| `agentsec.systemMessageFile` | _(empty)_ | Path to system message file |
| `agentsec.initialPrompt` | _(empty)_ | Custom initial prompt template |
| `agentsec.initialPromptFile` | _(empty)_ | Path to initial prompt file |
| `agentsec.configFile` | _(empty)_ | Path to YAML config file |
| `agentsec.skipScanners` | `[]` | Scanner names to always exclude |
| `agentsec.verbose` | `false` | Enable debug logging |

{: .tip }
> Leave model-specific settings empty to use the global `agentsec.model` value. Set them to use different models for different scan phases — e.g., a fast model for scanners and a powerful model for analysis.
