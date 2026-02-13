# AgentSec Setup and Testing Guide

## Current Status ✅

Your project has been successfully set up! Here's what's installed:

- **Python**: 3.12.3 ✅
- **Virtual Environment**: Created and configured ✅
- **Core Package** (`agentsec-core`): Installed in editable mode ✅
- **CLI Package** (`agentsec-cli`): Installed in editable mode ✅
- **Copilot CLI**: Installed ✅
- **Test Files**: Created in `test-scan/` directory ✅

## Prerequisites Checklist

Before running your first scan, verify these requirements:

### 1. GitHub Copilot Authentication

The agent requires GitHub Copilot CLI to be authenticated. Check your authentication status:

```bash
# Check if authenticated
copilot --version

# If not authenticated, login:
copilot auth login
```

Note: The login command will open your browser to authenticate with GitHub.

### 2. GitHub Copilot Subscription

You must have an active GitHub Copilot subscription (Individual, Business, or Enterprise).

---

## How to Test AgentSec

### Step 1: Activate the Virtual Environment

Every time you open a new terminal, activate the virtual environment first:

```bash
cd /mnt/c/code/AgentSec
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt.

### Step 2: Verify Installation

```bash
# Check the version
agentsec --version
# Output: agentsec 0.1.0

# View available commands
agentsec --help
```

### Step 3: Run Your First Scan

Scan the test folder we created:

```bash
# From the AgentSec root directory
agentsec scan ./test-scan
```

**Expected behavior:**
1. The CLI will connect to Copilot CLI
2. The agent will discover files in `test-scan/` using bash commands
3. The agent will invoke security scanners (bandit, graudit, etc.) via the `skill` tool and/or bash
4. The agent will inspect suspicious files using the `view` tool
5. You'll see a structured security report with findings including:
   - Severity levels (CRITICAL / HIGH / MEDIUM / LOW)
   - Per-file findings with line numbers and code snippets
   - Remediation recommendations

**Reliability features active during scan:**
- Stall detection monitors tool activity every 5 seconds
- If the LLM stalls for 30+ seconds, a nudge message redirects it
- Default 300-second timeout with partial results on timeout

### Step 4: Scan Your Own Code

To scan a different folder:

```bash
# Scan current directory
agentsec scan .

# Scan a specific project
agentsec scan /path/to/your/project

# Scan the core package itself (for demonstration)
agentsec scan ./core/agentsec
```

---

## Project Structure

```
AgentSec/
├── core/                      # Shared agent library
│   ├── agentsec/
│   │   ├── agent.py          # SecurityScannerAgent class (stall detection, nudge system)
│   │   ├── config.py         # AgentSecConfig + directive system message
│   │   ├── progress.py       # ProgressTracker for real-time scan feedback
│   │   ├── skill_discovery.py # Dynamic Copilot CLI skill discovery
│   │   └── skills.py         # Security scanning skills (@tool functions)
│   ├── tests/
│   │   ├── test_progress.py  # Progress tracking unit tests
│   │   └── test_skills.py    # Skill function unit tests
│   └── pyproject.toml
│
├── cli/                       # Command-line interface
│   ├── agentsec_cli/
│   │   └── main.py           # CLI entry point (config options, progress display)
│   └── pyproject.toml
│
├── spec/                      # Design documents
│   ├── plan-agentSec.md      # Architecture & specification
│   └── implementation-plan.md # Detailed task-by-task implementation plan
│
├── test-scan/                 # Test files with vulnerabilities
│   ├── vulnerable_app.py     # Intentionally vulnerable code
│   └── utils.py              # Safe utility functions
│
├── agentsec.example.yaml      # Example configuration file
├── venv/                      # Virtual environment (Linux/WSL)
└── SETUP.md                   # This file
```

---

## Development Workflow

### Running Tests

```bash
# Activate venv
source venv/bin/activate

# Run unit tests
cd core
pytest tests/

# Test the agent directly (Python)
python -c "
import asyncio
from agentsec.agent import SecurityScannerAgent

async def test():
    agent = SecurityScannerAgent()
    try:
        await agent.initialize()
        result = await agent.scan('./test-scan')
        print(result)
    finally:
        await agent.cleanup()

asyncio.run(test())
"
```

### Making Changes

The packages are installed in **editable mode** (`-e` flag), which means:

- Changes to `core/agentsec/*.py` are immediately available
- Changes to `cli/agentsec_cli/*.py` are immediately available
- No need to reinstall after editing code

### Adding New Skills

1. Open [`core/agentsec/skills.py`](core/agentsec/skills.py)
2. Create a new async function
3. Decorate it with `@tool(description="...")`
4. The agent will automatically have access to it

Example:

```python
@tool(description="Check for SQL injection vulnerabilities")
async def check_sql_injection(file_path: str) -> dict:
    """Check a file for SQL injection patterns."""
    # Your implementation here
    return {
        "file": file_path,
        "issues": [],
        "severity": "info"
    }
```

---

## Troubleshooting

### Issue: `agentsec: command not found`

**Solution:**
```bash
# Make sure venv is activated
source venv/bin/activate

# Reinstall CLI package
pip install -e ./cli
```

### Issue: `Copilot CLI not found`

**Solution:**
The Copilot CLI should already be installed at:
```
/home/alyoche/.vscode-server-insiders/data/User/globalStorage/github.copilot-chat/copilotCli/copilot
```

If you get this error when running `agentsec scan`, make sure this path is in your PATH:
```bash
export PATH="$PATH:/home/alyoche/.vscode-server-insiders/data/User/globalStorage/github.copilot-chat/copilotCli"
```

### Issue: `Error: Could not import SecurityScannerAgent`

**Solution:**
```bash
# Reinstall core package
pip install -e ./core
```

### Issue: `FileNotFoundError` or `Authentication failed`

**Solution:**
```bash
# Re-authenticate with Copilot
copilot auth login
```

---

## Next Steps

1. **Test the CLI**: Run `agentsec scan ./test-scan` to see the agent in action
2. **Explore the Code**: Read through [`agent.py`](core/agentsec/agent.py) and [`skills.py`](core/agentsec/skills.py)
3. **Add New Skills**: Extend the agent with more security checks
4. **Check Errors**: Use `get_errors` command in your editor to see any lint/type issues
5. **Read Documentation**: Check `.github/copilot-instructions.md` for project guidelines

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `agentsec --version` | Show version |
| `agentsec --help` | Show help menu |
| `agentsec scan <folder>` | Scan a folder for security issues |
| `pip install -e ./core` | Reinstall core package |
| `pip install -e ./cli` | Reinstall CLI package |
| `pytest core/tests/` | Run unit tests |
| `copilot auth login` | Authenticate Copilot CLI |

---

## Important Notes

### Authentication Required

Before running your first scan, you **must** authenticate Copilot CLI:

```bash
copilot auth login
```

This will open your browser to authenticate with GitHub.

### Async/Await Required

All agent and skill code must use `async def` and `await`:

✅ **Correct:**
```python
async def my_skill():
    result = await session.send_and_wait(...)
    return result
```

❌ **Wrong:**
```python
def my_skill():  # Missing async
    result = session.send_and_wait(...)  # Missing await
    return result
```

### Resource Cleanup Required

Always use try-finally to cleanup the agent:

```python
agent = SecurityScannerAgent()
try:
    await agent.initialize()
    result = await agent.scan("./folder")
finally:
    await agent.cleanup()  # Always cleanup!
```

---

## Getting Help

- **Project Guidelines**: [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
- **Python SDK Guide**: [`.vscode/python-copilot-sdk.instructions.md`](.vscode/python-copilot-sdk.instructions.md)
- **Architecture**: [`spec/plan-agentSec.md`](spec/plan-agentSec.md)
- **GitHub Copilot CLI Docs**: https://docs.github.com/en/copilot/using-github-copilot/using-github-copilot-in-the-command-line

---

**Ready to test!** Run `agentsec scan ./test-scan` to see AgentSec in action.
