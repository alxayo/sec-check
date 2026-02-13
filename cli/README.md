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

This scans all files in `./my_project` and prints a security report to your terminal.

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

# Use in a CI script
agentsec scan ./src || exit 1
```

---

## Project Links

- [Main AgentSec README](../README.md) — overview of the full project
- [Core package](../core/) — shared agent and skills library
- [Implementation plan](../spec/implementation-plan.md) — project roadmap

---

## License

See the [main project README](../README.md) for license information.
