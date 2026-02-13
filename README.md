# AgentSec

AI-powered security scanner for your code, built with the GitHub Copilot SDK.

## Overview

AgentSec is a monorepo containing three packages:
- **core/** — Shared agent and skills library (Python)
- **cli/** — Command-line interface (Python)
- **desktop/** — GUI application with FastAPI backend and Next.js frontend

## Quick Start

### Prerequisites

- Python 3.12+ (3.11 minimum)
- GitHub Copilot subscription
- GitHub Copilot CLI installed and authenticated

### 1. Activate Environment

```bash
# Simple activation (recommended)
source activate.sh

# Or manual activation
source venv/bin/activate
```

### 2. Authenticate Copilot CLI

```bash
# Check authentication status
copilot --version

# If needed, authenticate
copilot auth login
```

### 3. Run Your First Scan

```bash
# Scan the test folder
agentsec scan ./test-scan

# Scan current directory
agentsec scan .

# Scan any project
agentsec scan /path/to/your/project

# Use a custom configuration file
agentsec scan ./src --config ./agentsec.yaml

# Override the system message
agentsec scan ./src --system-message-file ./custom-prompt.txt
```

## Setup Details

The virtual environment and packages are **already installed**! If you need to reinstall:

```bash
# Create fresh virtual environment
python3 -m venv venv
source venv/bin/activate

# Install packages in editable mode
pip install -e ./core
pip install -e ./cli
```

For detailed setup instructions, troubleshooting, and development workflow, see [SETUP.md](SETUP.md).

## What Gets Scanned

AgentSec uses **Copilot CLI built-in tools** (`bash`, `skill`, `view`) to invoke real security scanners and analyze your code. The agent follows a structured workflow:

1. **File Discovery** — Uses `bash` with `find` to discover all files in the target folder
2. **Security Scanning** — Invokes Copilot CLI agentic skills and/or runs scanner CLIs directly:
   - **bandit** for Python AST security analysis
   - **graudit** for multi-language pattern-based auditing
   - **guarddog** for supply chain / malicious package detection
   - **shellcheck** for shell script analysis
   - **trivy** for container & filesystem scanning
   - **eslint** for JavaScript/TypeScript security
   - And more (checkov, dependency-check, template-analyzer)
3. **Manual Inspection** — Uses `view` to read suspicious files for deeper LLM analysis
4. **Report Generation** — Compiles all findings into a structured Markdown report with severity levels, line numbers, code snippets, and remediation advice

### Reliability Features

- **Stall detection**: Monitors tool activity every 5 seconds; sends nudge messages if the LLM's tool calls stall for 30+ seconds
- **Configurable timeout**: Default 300s scan timeout; partial results returned on timeout instead of discarding all work
- **Safety guardrails**: System message prevents execution of scanned code, blocks dangerous commands, and defends against prompt injection

## Progress Tracking

AgentSec provides real-time progress feedback during scans:

```
⠋ Starting security scan of ./my_project

  📁 Found 15 files to scan

  ⠹ [██████████░░░░░░░░░░] 50% Scanning (8/15): app.py
  ⚠️  Finished app.py: 2 issues found

✅ Scan complete: 15 files scanned, 5 issues found (23s)
```

Features:
- Visual progress bar with percentage
- Current file being scanned
- Files scanned count / total files
- Elapsed time tracking
- Issues found counter
- Periodic heartbeat to show work is ongoing

## Configuration

AgentSec can be configured via:

1. **YAML config file** (`agentsec.yaml`) — Set default system message and initial prompt
2. **CLI arguments** — Override config file settings per-run
3. **External prompt files** — Store long prompts in separate files

See [agentsec.example.yaml](agentsec.example.yaml) for a full example with comments.

**CLI Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--config FILE` | `-c` | Path to YAML config file |
| `--system-message TEXT` | `-s` | Override system message |
| `--system-message-file FILE` | `-sf` | Load system message from file |
| `--prompt TEXT` | `-p` | Override initial prompt template |
| `--prompt-file FILE` | `-pf` | Load initial prompt from file |

## Documentation

- **[SETUP.md](SETUP.md)** — Complete setup and testing guide
- **[.github/copilot-instructions.md](.github/copilot-instructions.md)** — Project architecture and development guide
- **[spec/plan-agentSec.md](spec/plan-agentSec.md)** — Implementation roadmap and design
- **[agentsec.example.yaml](agentsec.example.yaml)** — Example configuration file

## Architecture

AgentSec uses the GitHub Copilot SDK to create an AI agent that leverages **Copilot CLI built-in tools** for security scanning:

1. **`bash`** — Runs file discovery commands (`find`, `ls`) and invokes security scanner CLIs directly (bandit, graudit, etc.)
2. **`skill`** — Invokes pre-configured Copilot CLI agentic skills for structured scanning (bandit-security-scan, graudit-security-scan, etc.)
3. **`view`** — Reads file contents for manual LLM code inspection

The agent also has fallback `@tool` skills (`list_files`, `analyze_file`, `generate_report`) defined in `core/agentsec/skills.py` for basic pattern-matching analysis.

A **directive system message** guides the LLM through a structured scanning workflow with safety guardrails. **Stall detection** monitors tool activity and sends nudge messages if the LLM becomes inactive.

The agent is implemented in [core/agentsec/agent.py](core/agentsec/agent.py) and shared by both the CLI and Desktop app.

## External Security Tools (Skill Discovery)

AgentSec dynamically discovers Copilot CLI agentic skills at runtime instead of maintaining a hardcoded tool list. It scans the same directories the Copilot CLI uses:

| Location | Scope | Path |
|----------|-------|------|
| **User-level** | All projects | `~/.copilot/skills/` |
| **Project-level** | Current project only | `<project>/.copilot/skills/` |

Each skill directory contains a `SKILL.md` file with YAML frontmatter describing the skill's name and purpose. AgentSec maps each skill to its underlying CLI tool and verifies availability on the system.

**Currently discovered skills include:**

| Tool | Description | Status |
|------|-------------|--------|
| bandit | Python AST security analysis | ✅ |
| checkov | IaC misconfiguration scanning | ✅ |
| dependency-check | CVE detection in dependencies | ✅ |
| eslint | JavaScript/TypeScript security | ✅ |
| graudit | Multi-language pattern matching | ✅ |
| guarddog | Malicious package detection | ✅ |
| shellcheck | Shell script security analysis | ✅ |
| trivy | Container & filesystem scanning | ✅ |
| template-analyzer | ARM/Bicep template scanning | ⬜ |

> **Note**: The list above reflects the current system. Your available tools may differ. The CLI displays the actual discovery results at scan time.

## Development

Since packages are installed in editable mode, changes to the code are immediately available:

```bash
# Edit skills
vim core/agentsec/skills.py

# Changes are live - no reinstall needed
agentsec scan ./test-scan
```

Run tests:

```bash
cd core
pytest tests/
```

## License

Coming soon.
