# AgentSec CLI

**AI-powered security scanner for your code, from the command line.**

AgentSec CLI scans your project folders for security vulnerabilities using an AI agent built on the GitHub Copilot SDK. It analyzes your code and reports potential issues — all from a single terminal command.

---

## Prerequisites

Before using AgentSec CLI, make sure you have:

1. **Python 3.10 or newer** — Check with `python --version`
2. **Copilot CLI installed** — Install from [GitHub Copilot CLI docs](https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli)
3. **Copilot CLI authenticated** — Run `copilot auth login` and follow the prompts

---

## Installation

### For Users (from PyPI)

```bash
pip install agentsec
```

### For Developers (editable install from source)

```bash
# Clone the repo and install in editable mode
git clone <repo-url>
cd AgentSec
pip install -e ./core      # Install shared agent library first
pip install -e ./cli        # Install CLI package
```

---

## Usage

### Scan a project folder

```bash
agentsec scan ./my_project
```

This scans all files in `./my_project` and prints a security report to your terminal with real-time progress indicators.

### Parallel Scanning Mode

Run multiple scanners concurrently for faster results:

```bash
# Run relevant scanners in parallel (default: 3 concurrent)
agentsec scan ./my_project --parallel

# Allow up to 5 concurrent scanner sessions
agentsec scan ./my_project --parallel --max-concurrent 5
```

In parallel mode, AgentSec follows a 3-phase workflow:

1. **Discovery** — Classifies files and determines which scanners are relevant
2. **Parallel Scan** — Spawns one sub-agent session per scanner, all running concurrently
3. **Synthesis** — Deduplicates and compiles all findings into a single report

Parallel progress output:
```
🔀 Parallel mode: up to 3 concurrent scanners

📋 Scan plan: running bandit, graudit, trivy (skipped: eslint, shellcheck)

🔍 Sub-agent started: bandit
🔍 Sub-agent started: graudit
🔍 Sub-agent started: trivy
⚠️  Sub-agent finished: bandit — 3 findings (12s)
✅ Sub-agent finished: graudit — 0 findings (8s)
⚠️  Sub-agent finished: trivy — 1 findings (15s)

📝 Synthesising findings from 3 scanners...
📊 Synthesis complete

✅ Scan complete: 4 issues found (18s)
```

### Progress Display

When scanning, you'll see real-time progress:

```
⠋ Starting security scan of ./my_project

  📁 Found 15 files to scan

  ⠹ [██████████░░░░░░░░░░] 50% Scanning (8/15): app.py
  ⚠️  Finished app.py: 2 issues found

✅ Scan complete: 15 files scanned, 5 issues found (23s)
```

### Skill & Tool Discovery

Before each scan, the CLI dynamically discovers available Copilot CLI agentic skills and checks whether their underlying tools are installed on your system. This replaces any hardcoded tool list and adapts automatically to your environment.

```
📋 Available scanning skills:
  Built-in skills (registered @tool functions):
    • list_files       — Discover files in target directory
    • analyze_file     — Analyze a file for security vulnerabilities
    • generate_report  — Generate a formatted vulnerability report
  Copilot CLI agentic skills (8/9 tools available):
    📂 ~/.copilot/skills/ (9 skills)
    ✅ bandit               — Security audit of Python source code...
    ✅ checkov              — Scan IaC for security misconfigurations...
    ✅ eslint               — Security analysis of JavaScript/TypeScript code...
    ⬜ template-analyzer    — Scan ARM/Bicep templates... (not installed)
```

Skills are discovered from two locations:
- **User-level**: `~/.copilot/skills/` — available for all projects
- **Project-level**: `<project>/.copilot/skills/` — only for the current project

Each skill directory must contain a `SKILL.md` file with YAML frontmatter (name, description). The CLI maps each skill to its underlying CLI tool and verifies availability using the system PATH.

Features:
- Visual progress bar with percentage
- Current file being scanned
- Files scanned count / total files
- Elapsed time tracking
- Issues found counter
- Spinner animation to show work is ongoing

### Scan the current directory

```bash
agentsec scan .
```

### Use a custom configuration file

```bash
agentsec scan ./src --config ./agentsec.yaml
```

### Override the system message (AI instructions)

```bash
# Directly in the command
agentsec scan ./src --system-message "You are a security expert focusing on SQL injection..."

# Or from a file
agentsec scan ./src --system-message-file ./prompts/my-system.txt
```

### Override the initial prompt

```bash
# Directly in the command
agentsec scan ./src --prompt "Quick scan of {folder_path}. Only HIGH severity issues."

# Or from a file
agentsec scan ./src --prompt-file ./prompts/my-prompt.txt
```

### Show the version number

```bash
agentsec --version
```

### Show help

```bash
agentsec --help
```

---

## Configuration

AgentSec can be configured in three ways (in order of priority):

1. **CLI arguments** (highest priority) — override everything
2. **Configuration file** — YAML file with default settings
3. **Built-in defaults** (lowest priority) — used if nothing else is specified

### Configuration File

Create an `agentsec.yaml` file in your project root:

```yaml
# System message tells the AI who it is and how to behave
system_message: |
  You are AgentSec, a security scanning agent.
  Focus on finding HIGH severity vulnerabilities.

# Or load from an external file:
# system_message_file: ./prompts/system.txt

# Initial prompt template (use {folder_path} as placeholder)
initial_prompt: |
  Scan {folder_path} for security issues.
  Generate a detailed report.

# Or load from an external file:
# initial_prompt_file: ./prompts/scan.txt
```

AgentSec automatically searches for config files in:
- Current directory: `agentsec.yaml`, `agentsec.yml`, `.agentsec.yaml`, `.agentsec.yml`
- Home directory
- `~/.config/agentsec/`

See [`agentsec.example.yaml`](../agentsec.example.yaml) for a full example with comments.

### CLI Override Options

| Option | Short | Description |
|--------|-------|-------------|
| `--config FILE` | `-c` | Path to YAML config file |
| `--system-message TEXT` | `-s` | Override system message |
| `--system-message-file FILE` | `-sf` | Load system message from file |
| `--prompt TEXT` | `-p` | Override initial prompt template |
| `--prompt-file FILE` | `-pf` | Load initial prompt from file |
| `--parallel` | | Run scanners concurrently as sub-agents |
| `--max-concurrent N` | | Max parallel scanners (default 3, needs `--parallel`) |
| `--verbose` | `-v` | Enable debug logging for troubleshooting |

**Note:** `--system-message` and `--system-message-file` are mutually exclusive. Same for `--prompt` and `--prompt-file`.

### Environment Variables

AgentSec also loads values from a `.env` file at the workspace root. See [`.env.example`](../.env.example) for available options.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | **Success** — scan completed without errors |
| `1`  | **Error** — something went wrong (bad path, import failure, agent error) |
| `2`  | **Timeout** — the scan took too long to complete |

You can use these exit codes in scripts and CI pipelines:

```bash
agentsec scan ./src
if [ $? -ne 0 ]; then
    echo "Security scan failed!"
fi
```

---

## Troubleshooting

### "Copilot CLI not found"

The Copilot CLI is not installed or not on your PATH.

**Fix:**
1. Install Copilot CLI: [installation guide](https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli)
2. Authenticate: `copilot auth login`
3. Verify it works: `copilot --version`

### "Folder not found"

The folder path you provided does not exist.

**Fix:**
- Double-check the path for typos
- Use an absolute path if relative paths are confusing: `agentsec scan C:\code\myapp`
- Make sure the folder exists: `ls ./my_project` (or `dir` on Windows)

### "Timeout"

The scan took too long. This usually happens with very large projects.

**Fix:**
- Try scanning a smaller subfolder first: `agentsec scan ./src/api`
- Close other programs to free up resources
- Check your network connection (the agent calls the Copilot API)

### "Agent not initialized" or "Could not import SecurityScannerAgent"

The agent could not start, usually due to authentication issues.

**Fix:**
1. Make sure Copilot CLI is authenticated: `copilot auth login`
2. Verify the core package is installed: `pip install -e ./core`
3. Check that your Copilot subscription is active

---

## Examples

```bash
# Scan a Python project
agentsec scan ./my-flask-app

# Scan a Node.js project
agentsec scan ./express-server

# Scan the current directory
agentsec scan .

# Parallel scan for faster results
agentsec scan ./my-flask-app --parallel

# Parallel with higher concurrency
agentsec scan ./large-project --parallel --max-concurrent 5

# Parallel with verbose output for debugging
agentsec scan ./my-flask-app --parallel -v

# Use in a CI script
agentsec scan ./src || exit 1

# Parallel scan in CI
agentsec scan ./src --parallel || exit 1
```

---

## Project Links

- [Main AgentSec README](../README.md) — overview of the full project
- [Core package](../core/) — shared agent and skills library
- [Implementation plan](../spec/implementation-plan.md) — project roadmap

---

## License

See the [main project README](../README.md) for license information.
