---
title: Installation
layout: default
nav_order: 2
description: "How to install and set up Sec-Check — VS Code toolkit, CLI tool, and VS Code extension."
---

# Installation Guide
{: .no_toc }

Detailed instructions for every way to install and use Sec-Check.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## Prerequisites

| Requirement | Minimum | Recommended | Required For |
|:------------|:--------|:------------|:-------------|
| Python | 3.11 | 3.12+ | CLI tool |
| GitHub Copilot subscription | Any tier | — | All components |
| VS Code | 1.95+ | Latest | Extension & Toolkit |
| GitHub Copilot extension | Latest | Latest | Toolkit |
| GitHub Copilot CLI | Latest | Latest | CLI tool |
| Node.js | 18+ | 20+ | Building extension from source |
| Git | 2.0+ | Latest | Cloning the repo |

---

## VS Code Copilot Toolkit

The Copilot Toolkit (agent, skills, and prompts) requires **no installation** — it works automatically when the repo is open in VS Code with GitHub Copilot.

### Step 1: Clone the Repository

```bash
git clone https://github.com/alxayo/sec-check.git
cd sec-check
```

### Step 2: Open in VS Code

```bash
code .
```

### Step 3: Verify

Open GitHub Copilot Chat (`Ctrl+Shift+I`) and type:

```
/sechek.security-scan-quick
```

If you see the agent start analyzing your workspace, everything is working.

{: .note }
> The skills and prompts are located in `.github/skills/` and `.github/prompts/`. VS Code + Copilot detects them automatically when the workspace is open.

---

## CLI Tool (AgentSec)

### From PyPI (Recommended)

```bash
pip install agentsec-cli
```

This installs both `agentsec-core` (the agent library) and `agentsec-cli` (the command-line interface).

### From Source

```bash
git clone https://github.com/alxayo/sec-check.git
cd sec-check

# Create and activate a virtual environment
python -m venv venv

# Windows
.\venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# Install packages in editable mode
pip install -e ./core
pip install -e ./cli
```

### Verify Installation

```bash
agentsec --version
# Output: agentsec 0.1.1

agentsec --help
```

### Authenticate Copilot CLI

The CLI tool requires GitHub Copilot CLI to be installed and authenticated:

```bash
# Check if Copilot CLI is available
copilot --version

# Authenticate (opens browser)
copilot auth login
```

{: .important }
> You must have an active GitHub Copilot subscription (Individual, Business, or Enterprise) and be authenticated before running scans.

---

## VS Code Extension

### From VSIX (Pre-built)

Download the latest `.vsix` from [GitHub Releases](https://github.com/alxayo/sec-check/releases), then install in VS Code:

1. Open VS Code
2. `Ctrl+Shift+P` → **Extensions: Install from VSIX...**
3. Select the downloaded `.vsix` file

### Build from Source

```bash
cd vscode-extension
npm install
npm run build
npx vsce package
```

This generates a `.vsix` file you can install as above.

### Extension Prerequisites

The extension requires the CLI tool to be installed. Configure the Python path in VS Code settings:

```json
{
  "agentsec.pythonPath": "python3"
}
```

If you installed to a virtual environment, point to its Python:

```json
{
  "agentsec.pythonPath": "/path/to/sec-check/venv/bin/python"
}
```

---

## Installing Security Scanners

Sec-Check orchestrates external security tools. **None are strictly required** — the agent works with whatever is available — but installing them produces far better results.

### Quick Install (All Scanners)

```bash
# Python tools
pip install bandit guarddog

# System tools (Ubuntu/Debian)
sudo apt install shellcheck

# Graudit (git clone)
git clone https://github.com/wireghoul/graudit.git ~/graudit
export PATH="$PATH:$HOME/graudit"

# Trivy
# See https://aquasecurity.github.io/trivy/latest/getting-started/installation/

# Checkov
pip install checkov

# ESLint (for JS/TS projects)
npm install -g eslint
```

### Per-Scanner Installation

See the [Scanners Reference]({% link scanners.md %}) for detailed installation instructions for each tool.

{: .tip }
> Run `agentsec scan --verbose ./test-scan` to see which scanners are detected and which are missing. The agent will tell you exactly what it found.

---

## Building Release Packages

To build distributable wheel files:

```bash
python scripts/build_release.py 0.2.0
```

This will:
1. Update version numbers in `pyproject.toml` and `__init__.py` files
2. Build `.whl` packages for `core` and `cli`
3. Place artifacts in the `dist/` folder

Install the generated package:

```bash
pip install dist/agentsec_cli-0.2.0-py3-none-any.whl
```

---

## Upgrading

### PyPI

```bash
pip install --upgrade agentsec-cli
```

### From Source

```bash
cd sec-check
git pull
pip install -e ./core
pip install -e ./cli
```

---

## Uninstalling

```bash
pip uninstall agentsec-cli agentsec-core
```

For the VS Code extension, go to the Extensions panel and click **Uninstall** on AgentSec.
