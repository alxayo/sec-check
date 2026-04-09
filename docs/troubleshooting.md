---
title: Troubleshooting
layout: default
nav_order: 7
description: "Solutions for common issues with Sec-Check installation, authentication, and scanning."
---

# Troubleshooting
{: .no_toc }

Solutions for common issues and frequently asked questions.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## Installation Issues

### `agentsec: command not found`

The CLI is not on your PATH. Make sure your virtual environment is activated:

```bash
# Activate virtual environment
source venv/bin/activate      # macOS/Linux
.\venv\Scripts\activate       # Windows

# Reinstall CLI package
pip install -e ./cli
```

### `ModuleNotFoundError: No module named 'agentsec'`

The core package isn't installed:

```bash
pip install -e ./core
```

### `ModuleNotFoundError: No module named 'copilot'`

The GitHub Copilot SDK is missing. Install it:

```bash
pip install github-copilot-sdk
```

---

## Authentication Issues

### `Authentication failed` or `Copilot CLI not found`

**Step 1:** Verify Copilot CLI is installed:

```bash
copilot --version
```

If not found, see [GitHub Copilot CLI installation docs](https://docs.github.com/en/copilot/using-github-copilot/using-github-copilot-in-the-command-line).

**Step 2:** Authenticate:

```bash
copilot auth login
```

This opens your browser for GitHub authentication.

**Step 3:** Verify your subscription:

You must have an active GitHub Copilot subscription (Individual, Business, or Enterprise).

### Copilot CLI Path Issues

If `copilot` isn't found but is installed via VS Code, add it to your PATH:

```bash
# Find the Copilot CLI location
find ~ -name "copilot" -type f 2>/dev/null | grep copilotCli

# Add to PATH (adjust the path for your system)
export PATH="$PATH:$HOME/.vscode/data/User/globalStorage/github.copilot-chat/copilotCli"
```

Add this to your shell profile (`.bashrc`, `.zshrc`) for persistence.

---

## Scanning Issues

### Scan hangs or stalls

AgentSec includes automatic stall detection. If the agent stalls:

1. **Wait** — the stall detector sends nudge messages after 120s of inactivity
2. **After 3 nudges** — the session is automatically aborted with partial results
3. **Use `--timeout`** — set a shorter timeout: `agentsec scan ./src --timeout 300`

For debugging, use verbose mode:

```bash
agentsec scan ./src --verbose
```

### No scanners detected

The agent works with whatever tools are installed. To see what's available:

```bash
agentsec scan ./test-scan --verbose
```

Look for lines like:
```
Discovered skills: bandit-security-scan, graudit-security-scan, shellcheck-security-scan
```

Install missing scanners — see the [Scanners Reference]({% link scanners.md %}).

### Rate limit errors (429)

AgentSec automatically retries rate-limited requests with exponential backoff. If you're hitting limits frequently:

- Reduce `--max-concurrent` (default: 3) to lower parallel load
- Use a faster/cheaper model: `--model gpt-4.1-mini`
- Wait and retry — rate limits are usually temporary

### Scan timeout

The default timeout is 1800 seconds (30 minutes). Adjust if needed:

```bash
agentsec scan ./large-project --timeout 3600  # 1 hour
```

When a timeout occurs, the agent returns **partial results** — whatever it found before the timeout.

---

## VS Code Extension Issues

### Extension not activating

1. Check that the extension is installed: Extensions panel → search "AgentSec"
2. Verify `agentsec.pythonPath` in settings points to a Python with `agentsec-core` installed
3. Open the Output panel → select "AgentSec" to see error messages

### "Python not found" errors

Set the correct Python path in VS Code settings:

```json
{
  "agentsec.pythonPath": "/path/to/venv/bin/python"
}
```

### Chat participant not appearing

The `@agentsec` chat participant requires:
- VS Code 1.95+
- GitHub Copilot Chat extension installed
- AgentSec extension installed and activated

Try reloading VS Code: `Ctrl+Shift+P` → **Developer: Reload Window**

---

## Copilot Toolkit Issues

### Skills not detected

Skills require the repo to be open in VS Code. Check:

1. The `.github/skills/` directory exists and contains skill files
2. You have the GitHub Copilot extension installed
3. Try reloading VS Code

### Prompts not showing

Custom prompts (`/sechek.*`) require:
- The `.github/prompts/` directory with prompt files
- GitHub Copilot Chat extension
- The repo must be the active workspace

---

## FAQ

### Does Sec-Check execute the code it scans?

**No.** The agent is explicitly instructed via safety guardrails to never execute, run, or invoke any code being analyzed. It uses static analysis tools and LLM-based pattern recognition only.

### Does my code leave my machine?

The code is sent to the LLM API (via GitHub Copilot) for analysis. The same privacy policies that apply to GitHub Copilot apply here. No code is stored or shared with third parties beyond what Copilot normally does.

### Can I use this in CI/CD?

Yes — the CLI tool can run in any CI/CD pipeline. Example GitHub Actions:

```yaml
- name: Security Scan
  run: |
    pip install agentsec-cli
    agentsec scan ./src --parallel --timeout 600
```

You'll need to authenticate Copilot CLI in your CI environment.

### What models are supported?

Any model available through GitHub Copilot:
- `gpt-5` (default)
- `gpt-4.1`, `gpt-4.1-mini`
- `claude-sonnet-4.5`, `claude-opus-4.5`
- And others as they become available

### Can I add my own scanners?

Yes, in two ways:

1. **As a Copilot skill** — create a markdown file in `.github/skills/` following the existing skill format. Use `/create-security-skill` to generate one from tool docs.

2. **As a custom tool** — write a Python function with the `@tool` decorator in `core/agentsec/skills.py`.

### Is this a replacement for professional security audits?

**No.** Sec-Check is a first-pass filter that catches common red flags. It may miss obfuscated or novel attacks. For production or high-security environments, always combine with:
- Manual code review
- Professional penetration testing
- Sandboxed execution environments
