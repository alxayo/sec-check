---
title: CLI Tool
layout: default
parent: User Guide
nav_order: 1
description: "Complete guide to using the AgentSec CLI for automated security scanning."
---

# CLI Tool (AgentSec)
{: .no_toc }

The standalone command-line interface for automated security scanning.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## Basic Usage

```bash
# Scan a folder
agentsec scan ./my-project

# Scan current directory
agentsec scan .

# Show version
agentsec --version

# Show help
agentsec --help
```

The agent will:
1. Connect to GitHub Copilot CLI
2. Discover all files in the target folder
3. Run applicable security scanners (Bandit, Graudit, ShellCheck, etc.)
4. Perform LLM-based semantic code analysis
5. Generate a structured Markdown security report

---

## Scan Modes

### Sequential Mode (Default)

Runs all scanners in a single LLM session, one after another:

```bash
agentsec scan ./my-project
```

Best for: smaller projects, lower API usage, simpler debugging.

### Parallel Mode

Runs multiple scanners concurrently as independent sub-agents:

```bash
agentsec scan ./my-project --parallel
```

Best for: larger projects, faster results, comprehensive coverage.

**How parallel mode works** — a 3-phase workflow:

| Phase | What Happens |
|:------|:-------------|
| **1. Discovery** | Walks the target folder, classifies files by type, determines which scanners are relevant and available, builds a scan plan |
| **2. Parallel Scan** | Spawns one sub-agent session per scanner. Sessions run concurrently via `asyncio.gather` with a semaphore to cap parallelism |
| **3. Synthesis** | Feeds all sub-agent findings into a synthesis session that deduplicates, normalizes severity, and compiles a single Markdown report |

Control concurrency:

```bash
# Allow up to 5 scanners at once (default: 3)
agentsec scan ./my-project --parallel --max-concurrent 5
```

---

## CLI Options Reference

| Option | Short | Description | Default |
|:-------|:------|:------------|:--------|
| `--config FILE` | `-c` | Path to YAML config file | Auto-search |
| `--system-message TEXT` | `-s` | Override system message | Built-in |
| `--system-message-file FILE` | `-sf` | Load system message from file | — |
| `--prompt TEXT` | `-p` | Override initial prompt template | Built-in |
| `--prompt-file FILE` | `-pf` | Load initial prompt from file | — |
| `--parallel` | — | Run scanners concurrently as sub-agents | Off |
| `--max-concurrent N` | — | Max parallel scanners (requires `--parallel`) | 3 |
| `--verbose` | `-v` | Enable debug logging | Off |
| `--timeout SECONDS` | — | Safety ceiling timeout | 1800 |
| `--model MODEL` | `-m` | Override LLM model | gpt-5 |

---

## Progress Tracking

AgentSec shows real-time progress during scans:

```
⠋ Starting security scan of ./my_project

📁 Found 15 files to scan

⠹ [████████░░░░░░░░] 50% Scanning (8/15): app.py
⚠ Finished app.py: 2 issues found

✅ Scan complete: 15 files scanned, 5 issues found (23s)
```

In verbose mode (`-v`), you also see:
- SDK event types and timestamps
- Tool invocation details
- Stall detection status
- Session lifecycle events

---

## Output

The agent generates a structured Markdown security report containing:

- **Executive summary** with overall risk level
- **Severity counts** — CRITICAL / HIGH / MEDIUM / LOW
- **Per-file findings** with:
  - Line numbers
  - Vulnerable code snippets
  - Severity classification
  - Remediation recommendations
- **Prioritized remediation checklist**

### Example Report Structure

```markdown
# Security Scan Results

## Executive Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High | 1 |
| 🟡 Medium | 3 |
| 🟢 Low | 1 |

## Findings

### [CRITICAL] SQL Injection — app.py:42
...code snippet and remediation...

### [HIGH] Hardcoded API Key — config.py:8
...code snippet and remediation...
```

---

## Reliability Features

AgentSec includes multiple mechanisms to ensure scans complete reliably:

| Feature | Description |
|:--------|:------------|
| **Activity-based stall detection** | Monitors SDK events continuously; sends nudge after 120s of inactivity; aborts after 3 unresponsive nudges |
| **Transient error retry** | Rate limits (429), 5xx, and transient errors are automatically retried with exponential backoff |
| **Configurable timeout** | Default 1800s safety ceiling; partial results returned on timeout |
| **Safety guardrails** | System message prevents execution of scanned code, blocks dangerous commands, defends against prompt injection |
| **Dynamic skill discovery** | Available scanner skills are detected at runtime and injected into the system message |
| **Per-sub-agent isolation** | In parallel mode, each sub-agent runs in its own session; failures in one scanner don't affect others |

---

## Examples

### Scan a Python project

```bash
agentsec scan ./my-flask-app
```

### Scan with a custom config

```bash
agentsec scan ./project --config ./security-config.yaml
```

### Scan with a specific model

```bash
agentsec scan ./project --model claude-sonnet-4.5
```

### Quick parallel scan with verbose logging

```bash
agentsec scan ./project --parallel --max-concurrent 5 --verbose
```

### Override the system message

```bash
agentsec scan ./project -s "Focus only on Python SQL injection and XSS vulnerabilities."
```

### Use a custom prompt from a file

```bash
agentsec scan ./project --prompt-file ./my-scan-prompt.txt
```
