---
title: Configuration
layout: default
nav_order: 4
description: "Complete configuration reference for Sec-Check — YAML config, CLI options, VS Code settings, and model selection."
---

# Configuration Reference
{: .no_toc }

Sec-Check can be configured via YAML files, CLI arguments, and VS Code settings. CLI arguments always override file settings.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## Configuration Precedence

Settings are resolved in this order (highest priority first):

1. **CLI arguments** — `--model`, `--system-message`, etc.
2. **YAML config file** — `agentsec.yaml`
3. **Built-in defaults** — sensible defaults for all settings

---

## YAML Configuration File

Create an `agentsec.yaml` file in your project root (or any of the auto-search paths):

```yaml
# System message — controls the AI agent's behavior
system_message: |
  You are a security expert specializing in Python web applications.
  Focus on SQL injection, XSS, and authentication vulnerabilities.
  Generate a Markdown report with severity levels and remediation advice.

# Initial prompt template — {folder_path} is replaced with the target
initial_prompt: |
  Scan {folder_path} for security vulnerabilities.
  Focus on HIGH and CRITICAL severity only.
  Use bandit-security-scan and graudit-security-scan skills.

# Model selection
model: gpt-5

# Per-phase model overrides (optional)
model_scanners: gpt-4.1-mini     # Phase 2: scanner sub-agents
model_analysis: claude-sonnet-4.5   # Phase 3: LLM deep analysis
model_synthesis: gpt-4.1-mini    # Phase 4: report synthesis

# Parallel scanning
max_concurrent: 3
```

### Auto-Search Paths

The CLI automatically searches for config files in this order:

1. Current directory: `agentsec.yaml`, `agentsec.yml`, `.agentsec.yaml`, `.agentsec.yml`
2. Home directory: `~/agentsec.yaml`
3. Config directory: `~/.config/agentsec/agentsec.yaml`

Or specify explicitly:

```bash
agentsec scan ./src --config ./my-config.yaml
```

### External Prompt Files

For long prompts, store them in separate files:

```yaml
# Reference files instead of inline text
system_message_file: ./prompts/system-message.txt
initial_prompt_file: ./prompts/scan-prompt.txt
```

{: .note }
> If both inline text and a file reference are provided, the inline text takes priority.

---

## System Message

The system message controls the AI agent's identity, behavior, and safety guardrails. The built-in default:

- Identifies the agent as "AgentSec, the Malicious Code Scanner"
- Lists all available Copilot CLI tools (`bash`, `skill`, `view`)
- Provides a structured 4-step scanning workflow
- Includes comprehensive safety guardrails against executing scanned code
- Defends against prompt injection from analyzed code

### Customizing the System Message

Override via CLI:

```bash
agentsec scan ./src -s "Focus only on Python code. Ignore JavaScript."
```

Or via a file:

```bash
agentsec scan ./src --system-message-file ./my-system-prompt.txt
```

Or via YAML:

```yaml
system_message: |
  You are a security expert specializing in cloud infrastructure.
  Focus on IAM misconfigurations and exposed secrets.
```

{: .warning }
> Overriding the system message replaces the built-in safety guardrails. Make sure your custom message includes appropriate safety instructions.

---

## Initial Prompt Template

The initial prompt is sent to the agent at the start of each scan. Use `{folder_path}` as a placeholder for the target path.

### Built-in Default

The default prompt instructs the agent to:
1. Use `bash` with `find` to discover files
2. Use the `skill` tool to run security scanners
3. Use `view` for manual inspection
4. Compile a structured Markdown report

### Custom Examples

**Quick scan — HIGH severity only:**

```yaml
initial_prompt: |
  Quick security check of {folder_path}.
  Only report HIGH and CRITICAL severity issues.
  Use bandit-security-scan skill, then generate a brief summary.
```

**Multi-language scanning:**

```yaml
initial_prompt: |
  Scan {folder_path} for security issues across all file types.
  For Python files: use bandit-security-scan
  For JS/TS files: use eslint-security-scan
  For shell scripts: use shellcheck-security-scan
  For all files: use graudit-security-scan with secrets database
  Compile all findings into one report.
```

---

## Model Selection

### Global Model

Set the default model for all scan phases:

```bash
agentsec scan ./src --model claude-sonnet-4.5
```

Or in YAML:

```yaml
model: gpt-5
```

### Per-Phase Model Overrides

Use different models for each scan phase to optimize cost vs. quality:

```yaml
# Fast/cheap model for tool-running phases
model: gpt-4.1-mini

# Powerful model for the analysis phase that needs deep reasoning
model_analysis: gpt-5
```

| Phase | YAML Key | CLI Flag | Description |
|:------|:---------|:---------|:------------|
| Global default | `model` | `--model` | Used by all phases unless overridden |
| Phase 2: Scanners | `model_scanners` | — | Scanner sub-agent sessions |
| Phase 3: Analysis | `model_analysis` | — | LLM deep analysis / semantic review |
| Phase 4: Synthesis | `model_synthesis` | — | Report deduplication and compilation |

### Available Models

| Model | Notes |
|:------|:------|
| `gpt-5` | Default — strong general performance |
| `gpt-4.1` | Fast and cost-effective |
| `gpt-4.1-mini` | Fastest and cheapest |
| `claude-sonnet-4.5` | Strong reasoning and code analysis |
| `claude-opus-4.5` | Premium reasoning |

---

## Timeout & Reliability

| Setting | CLI Flag | YAML Key | Default | Description |
|:--------|:---------|:---------|:--------|:------------|
| Scan timeout | `--timeout` | — | 1800s | Safety ceiling; partial results returned |
| Max concurrent | `--max-concurrent` | `max_concurrent` | 3 | Max parallel scanners |
| Stall detection | — | — | 120s | Nudge sent after inactivity |
| Stall abort | — | — | 3 nudges | Session aborted after unresponsive nudges |

---

## Full Example Configuration

```yaml
# agentsec.yaml — Full example configuration

# ── System Message ─────────────────────────────────
# Customize the AI agent's behavior and focus areas.
system_message: |
  You are a security expert specializing in Python web applications.
  Use the skill tool to invoke bandit-security-scan and graudit-security-scan.
  Focus especially on:
  - SQL injection vulnerabilities
  - Cross-site scripting (XSS)
  - Authentication and authorization issues
  - Sensitive data exposure
  Generate a Markdown report with severity levels and remediation advice.

# ── Initial Prompt ─────────────────────────────────
# Template used when starting a scan. {folder_path} is replaced automatically.
initial_prompt: |
  Scan {folder_path} for security issues across all file types.
  For Python files: use bandit-security-scan
  For JS/TS files: use eslint-security-scan
  For shell scripts: use shellcheck-security-scan
  For all files: use graudit-security-scan with secrets database
  Compile all findings into one report.

# ── Model Selection ────────────────────────────────
model: gpt-5
model_scanners: gpt-4.1-mini
model_analysis: claude-sonnet-4.5
model_synthesis: gpt-4.1-mini

# ── Parallel Scanning ──────────────────────────────
max_concurrent: 5
```
