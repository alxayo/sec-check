# AgentSec — Detailed Implementation Plan

> **Generated from**: `spec/plan-agentSec.md`, `.github/copilot-instructions.md`,
> `.vscode/python-copilot-sdk.instructions.md`, `.vscode/copilot-sdk.instructions.md`
>
> **Date**: February 13, 2026
>
> Each task below is scoped to be a single, self-contained commit. Tasks are
> grouped by phase. Inside each phase you will find a **dependency graph** that
> tells you which tasks can run in parallel and which must run sequentially.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| `[P]` | Can execute in **parallel** with other `[P]` tasks in the same group |
| `[S]` | Must execute **sequentially** — depends on the task(s) listed in *Depends on* |
| `COMMIT` | Suggested git commit message |

---

## Phase 1 — Core Agent Foundation

### [ ] Task 1.1 — Initialize monorepo root & workspace config `[P]`

**Depends on**: nothing
**COMMIT**: `chore: initialize monorepo root with gitignore, env template, and editorconfig`

**What to do**:

1. Create workspace-root files:
   - `.gitignore` — ignore `venv/`, `__pycache__/`, `.env`, `node_modules/`, `dist/`, `build/`, `*.egg-info/`, `.pytest_cache/`, `*.pyc`, `/tmp/agentsec-port.txt`
   - `.env.example` — template for credentials (see content below)
   - `.editorconfig` — standardize indentation (4 spaces for Python, 2 for TS/JSON)
   - `README.md` — placeholder root README with project name and "Setup instructions coming soon"

2. File content for `.env.example`:
   ```env
   # === GitHub Copilot Authentication ===
   # Option A: Use CLI login (recommended for development)
   #   Run: copilot auth login
   # Option B: Set token directly
   COPILOT_GITHUB_TOKEN=

   # === Azure OpenAI (alternative to GitHub Copilot) ===
   AZURE_OPENAI_API_KEY=
   AZURE_OPENAI_ENDPOINT=
   AZURE_OPENAI_DEPLOYMENT_NAME=

   # === Development ===
   DEBUG=false
   LOG_LEVEL=INFO
   ```

3. File content for `.gitignore`:
   ```gitignore
   # Python
   venv/
   __pycache__/
   *.pyc
   *.pyo
   *.egg-info/
   dist/
   build/
   .pytest_cache/

   # Environment
   .env

   # Node / Frontend
   node_modules/
   .next/
   out/

   # Electron
   release/

   # OS
   .DS_Store
   Thumbs.db

   # Runtime
   /tmp/agentsec-port.txt
   ```

**Verification**: `git status` shows only untracked files, no errors.

---

### [ ] Task 1.2 — Create `core/` Python package scaffolding `[P]`

**Depends on**: nothing (can run in parallel with 1.1)
**COMMIT**: `feat(core): scaffold agentsec-core package with pyproject.toml`

**What to do**:

1. Create directory tree:
   ```
   core/
   ├── agentsec/
   │   ├── __init__.py
   │   ├── agent.py      (empty placeholder with module docstring)
   │   └── skills.py     (empty placeholder with module docstring)
   ├── tests/
   │   ├── __init__.py
   │   └── test_skills.py (empty placeholder)
   ├── pyproject.toml
   └── README.md
   ```

2. `core/pyproject.toml` content:
   ```toml
   [build-system]
   requires = ["setuptools>=68.0", "wheel"]
   build-backend = "setuptools.backends._legacy:_Backend"

   [project]
   name = "agentsec-core"
   version = "0.1.0"
   description = "AgentSec core agent and skills library"
   requires-python = ">=3.10"
   dependencies = [
       "agent-framework-core==1.0.0b260107",
       "agent-framework-azure-ai==1.0.0b260107",
       "python-dotenv>=1.0.0",
   ]

   [project.optional-dependencies]
   dev = [
       "pytest>=7.0",
       "pytest-asyncio>=0.21",
   ]
   ```

3. `core/agentsec/__init__.py`:
   ```python
   """
   AgentSec Core — shared agent and skills library.

   This package provides the SecurityScannerAgent and all @tool-decorated
   skill functions used by both the CLI and the Desktop app.
   """

   __version__ = "0.1.0"
   ```

4. Placeholder `core/agentsec/agent.py`:
   ```python
   """
   SecurityScannerAgent — the main agent class for AgentSec.

   This module will contain the SecurityScannerAgent class which
   uses the GitHub Copilot SDK to analyze code for security issues.
   """
   ```

5. Placeholder `core/agentsec/skills.py`:
   ```python
   """
   Skills (tools) for the SecurityScannerAgent.

   Each skill is an async function decorated with @tool.
   Skills are the building blocks the agent calls to scan code.
   """
   ```

6. `core/README.md` — one-paragraph description explaining the core package.

**Verification**: `pip install -e ./core` succeeds (dependencies may fail until venv set up — that's OK at this stage).

---

### [ ] Task 1.3 — Create virtual environment & install core dependencies `[S]`

**Depends on**: 1.2
**COMMIT**: `chore: create workspace venv and install core dependencies`

**What to do**:

1. From workspace root (`c:\code\AgentSec`):
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   pip install --upgrade pip setuptools wheel
   pip install -e ./core
   ```

2. Verify installation:
   ```powershell
   python -c "import agentsec; print(agentsec.__version__)"
   # Should print: 0.1.0
   ```

3. Verify SDK imports (will confirm the pinned versions work):
   ```powershell
   python -c "from agent_framework import tool; print('agent_framework OK')"
   ```

4. If `copilot` CLI is not yet installed, install it:
   ```powershell
   copilot --version
   copilot auth login
   ```

**Verification**: All import statements succeed. `pip list | Select-String agent-framework` shows the pinned versions.

---

### [ ] Task 1.4 — Implement `list_files` skill `[S]`

**Depends on**: 1.3
**COMMIT**: `feat(core): implement list_files skill with @tool decorator`

**What to do**:

Replace the placeholder in `core/agentsec/skills.py` with the first skill function.

**Full code for `list_files`**:
```python
"""
Skills (tools) for the SecurityScannerAgent.

Each skill is an async function decorated with @tool.
Skills are the building blocks the agent calls to scan code.
"""

import os
import logging
from typing import List

from agent_framework import tool

# Set up logging so we can track what the skills are doing
logger = logging.getLogger(__name__)


@tool(description="List all files in a directory recursively")
async def list_files(folder_path: str) -> dict:
    """
    Scan a directory and return all file paths found.

    This function walks through a folder and collects the paths of all files.
    It skips hidden directories (like .git) and common non-code folders
    (like node_modules and __pycache__) so the agent focuses on real code.

    Args:
        folder_path: The path to the folder to scan.
                     Example: "/home/user/project" or "C:\\code\\myapp"

    Returns:
        A dictionary with:
        - "files": List of file paths found
        - "total": Total number of files
        - "folder": The folder that was scanned

    Raises:
        FileNotFoundError: If the folder does not exist

    Example:
        >>> result = await list_files("./src")
        >>> print(f"Found {result['total']} files")
    """
    # Folders we want to skip because they are not source code
    folders_to_skip = {
        ".git",
        "__pycache__",
        "node_modules",
        ".next",
        "venv",
        ".venv",
        "dist",
        "build",
    }

    try:
        # Collect all file paths
        files_found: List[str] = []

        # os.walk goes through every folder and subfolder
        for current_folder, subdirectories, filenames in os.walk(folder_path):
            # Remove folders we want to skip from the list
            # Modifying subdirectories in-place prevents os.walk from entering them
            subdirectories[:] = [
                directory
                for directory in subdirectories
                if directory not in folders_to_skip
            ]

            # Add each file's full path to our list
            for filename in filenames:
                full_path = os.path.join(current_folder, filename)
                files_found.append(full_path)

        logger.info(f"Listed {len(files_found)} files in {folder_path}")

        return {
            "files": files_found,
            "total": len(files_found),
            "folder": folder_path,
        }

    except FileNotFoundError:
        error_message = f"Folder not found: {folder_path}"
        logger.error(error_message)
        return {
            "files": [],
            "total": 0,
            "folder": folder_path,
            "error": error_message,
        }
    except PermissionError:
        error_message = f"Permission denied: {folder_path}"
        logger.error(error_message)
        return {
            "files": [],
            "total": 0,
            "folder": folder_path,
            "error": error_message,
        }
```

**Verification**:
```python
import asyncio
from agentsec.skills import list_files

result = asyncio.run(list_files("."))
print(result["total"], "files found")
```

---

### [ ] Task 1.5 — Implement `analyze_file` skill `[P with 1.6]`

**Depends on**: 1.4
**COMMIT**: `feat(core): implement analyze_file skill for mock security checks`

**What to do**:

Add the `analyze_file` function to `core/agentsec/skills.py` (append after `list_files`).

**Full code**:
```python
@tool(description="Analyze a single file for security vulnerabilities")
async def analyze_file(file_path: str) -> dict:
    """
    Analyze a single file for security vulnerabilities.

    This function reads a file and checks for common security issues such as
    unsafe eval/exec calls, hardcoded passwords, and dangerous imports.
    It returns a structured dictionary with all findings.

    For the MVP, these are simple string-matching checks. In the future,
    this will be replaced by real scanners (bandit, semgrep, etc.).

    Args:
        file_path: Full path to the file to analyze.
                   Example: "/home/user/project/app.py"

    Returns:
        A dictionary with:
        - "file": The path to the file that was analyzed
        - "issues": List of issue dictionaries, each containing:
            - "type": Short identifier (e.g., "unsafe-eval")
            - "message": Human-readable description
            - "severity": "HIGH", "MEDIUM", or "LOW"
            - "line": Approximate line number (1-based)
        - "severity": Overall severity ("info", "warning", or "error")
        - "lines_scanned": Total lines in the file

    Example:
        >>> result = await analyze_file("app.py")
        >>> for issue in result["issues"]:
        ...     print(f"[{issue['severity']}] {issue['message']} (line {issue['line']})")
    """
    try:
        # Step 1: Read the file content
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            content = file.read()

        # Split into lines so we can report approximate line numbers
        lines = content.splitlines()

        # Step 2: Run each security check
        issues: list = []

        # Check for unsafe eval()
        for line_number, line in enumerate(lines, start=1):
            if "eval(" in line:
                issues.append({
                    "type": "unsafe-eval",
                    "message": "Found unsafe eval() call — eval executes arbitrary code",
                    "severity": "HIGH",
                    "line": line_number,
                })

        # Check for unsafe exec()
        for line_number, line in enumerate(lines, start=1):
            if "exec(" in line:
                issues.append({
                    "type": "unsafe-exec",
                    "message": "Found unsafe exec() call — exec executes arbitrary code",
                    "severity": "HIGH",
                    "line": line_number,
                })

        # Check for hardcoded passwords
        password_patterns = ["password=", "passwd=", "secret=", "api_key="]
        for line_number, line in enumerate(lines, start=1):
            lower_line = line.lower()
            for pattern in password_patterns:
                if pattern in lower_line:
                    # Skip lines that are just comments or docstrings
                    stripped = line.strip()
                    if not stripped.startswith("#") and not stripped.startswith('"""'):
                        issues.append({
                            "type": "hardcoded-secret",
                            "message": f"Possible hardcoded secret ({pattern.rstrip('=')})",
                            "severity": "MEDIUM",
                            "line": line_number,
                        })
                    break  # one issue per line is enough

        # Check for dangerous imports
        dangerous_imports = ["import subprocess", "import os", "import pickle"]
        for line_number, line in enumerate(lines, start=1):
            for dangerous_import in dangerous_imports:
                if dangerous_import in line:
                    issues.append({
                        "type": "dangerous-import",
                        "message": f"Found potentially dangerous import: {dangerous_import}",
                        "severity": "LOW",
                        "line": line_number,
                    })

        # Step 3: Determine overall severity
        overall_severity = "info"
        for issue in issues:
            if issue["severity"] == "HIGH":
                overall_severity = "error"
                break
            elif issue["severity"] == "MEDIUM":
                overall_severity = "warning"

        logger.info(f"Analyzed {file_path}: {len(issues)} issues found")

        return {
            "file": file_path,
            "issues": issues,
            "severity": overall_severity,
            "lines_scanned": len(lines),
        }

    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return {
            "file": file_path,
            "issues": [{"type": "error", "message": f"File not found: {file_path}", "severity": "HIGH", "line": 0}],
            "severity": "error",
            "lines_scanned": 0,
        }
    except Exception as error:
        logger.error(f"Error analyzing {file_path}: {error}")
        return {
            "file": file_path,
            "issues": [{"type": "error", "message": str(error), "severity": "HIGH", "line": 0}],
            "severity": "error",
            "lines_scanned": 0,
        }
```

**Verification**:
```python
import asyncio
from agentsec.skills import analyze_file

# Create a test file with a known issue
with open("_test_vuln.py", "w") as f:
    f.write("password='secret123'\nresult = eval(user_input)\n")

result = asyncio.run(analyze_file("_test_vuln.py"))
assert len(result["issues"]) >= 2, f"Expected >=2 issues, got {len(result['issues'])}"
print("analyze_file OK:", result)
import os; os.remove("_test_vuln.py")
```

---

### [ ] Task 1.6 — Implement `generate_report` skill `[P with 1.5]`

**Depends on**: 1.4
**COMMIT**: `feat(core): implement generate_report skill for formatting results`

**What to do**:

Add `generate_report` function to `core/agentsec/skills.py` (append after the other skills).

**Full code**:
```python
@tool(description="Generate a formatted security report from scan findings")
async def generate_report(findings: list) -> dict:
    """
    Generate a formatted security report from a list of scan findings.

    This function takes the raw findings from analyze_file calls and produces
    a human-readable summary report with statistics and recommendations.

    Args:
        findings: A list of dictionaries, where each dictionary is the output
                  of the analyze_file() skill. Each must contain:
                  - "file": path to the file
                  - "issues": list of issue dicts
                  - "severity": overall severity string

    Returns:
        A dictionary with:
        - "summary": Human-readable text summary of all findings
        - "total_files": Number of files analyzed
        - "total_issues": Total number of issues across all files
        - "high_count": Number of HIGH severity issues
        - "medium_count": Number of MEDIUM severity issues
        - "low_count": Number of LOW severity issues
        - "files_with_issues": List of file paths that have issues

    Example:
        >>> findings = [await analyze_file("app.py"), await analyze_file("utils.py")]
        >>> report = await generate_report(findings)
        >>> print(report["summary"])
    """
    # Step 1: Count issues by severity
    high_count = 0
    medium_count = 0
    low_count = 0
    total_issues = 0
    files_with_issues: List[str] = []

    for finding in findings:
        file_issues = finding.get("issues", [])
        total_issues += len(file_issues)

        # Track which files have issues
        if len(file_issues) > 0:
            files_with_issues.append(finding.get("file", "unknown"))

        # Count by severity
        for issue in file_issues:
            severity = issue.get("severity", "LOW")
            if severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            else:
                low_count += 1

    # Step 2: Build a human-readable summary
    summary_lines = [
        "=" * 60,
        "  AgentSec Security Scan Report",
        "=" * 60,
        "",
        f"  Files scanned:  {len(findings)}",
        f"  Total issues:   {total_issues}",
        f"  HIGH severity:  {high_count}",
        f"  MEDIUM severity: {medium_count}",
        f"  LOW severity:   {low_count}",
        "",
    ]

    # Add per-file details
    if files_with_issues:
        summary_lines.append("  Files with issues:")
        for finding in findings:
            file_issues = finding.get("issues", [])
            if file_issues:
                file_path = finding.get("file", "unknown")
                summary_lines.append(f"    - {file_path} ({len(file_issues)} issues)")
                for issue in file_issues:
                    line_num = issue.get("line", "?")
                    message = issue.get("message", "Unknown issue")
                    severity = issue.get("severity", "?")
                    summary_lines.append(f"        [{severity}] Line {line_num}: {message}")
        summary_lines.append("")
    else:
        summary_lines.append("  No security issues found. Great job!")
        summary_lines.append("")

    summary_lines.append("=" * 60)

    summary_text = "\n".join(summary_lines)

    logger.info(f"Generated report: {total_issues} issues across {len(findings)} files")

    return {
        "summary": summary_text,
        "total_files": len(findings),
        "total_issues": total_issues,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "files_with_issues": files_with_issues,
    }
```

**Verification**:
```python
import asyncio
from agentsec.skills import generate_report

mock_findings = [
    {"file": "app.py", "issues": [{"type": "unsafe-eval", "message": "eval found", "severity": "HIGH", "line": 5}], "severity": "error"},
    {"file": "utils.py", "issues": [], "severity": "info"},
]
report = asyncio.run(generate_report(mock_findings))
print(report["summary"])
assert report["total_issues"] == 1
assert report["high_count"] == 1
```

---

### [x] Task 1.7 — Implement `SecurityScannerAgent` class `[S]`

**Depends on**: 1.5, 1.6
**COMMIT**: `feat(core): implement SecurityScannerAgent with session lifecycle`
**STATUS**: ✅ COMPLETED

**What was done**:
- Implemented `SecurityScannerAgent` class with `initialize()`, `scan()`, and `cleanup()` methods
- Agent accepts optional `AgentSecConfig` parameter for customization
- Uses system_message and initial_prompt from configuration
- Agent uses **Copilot CLI built-in tools** (`bash`, `skill`, `view`) as its primary scanning mechanism
- `scan()` accepts optional `timeout` parameter (defaults to `DEFAULT_SCAN_TIMEOUT_SECONDS = 300.0`)
- **Stall detection**: Polls every 5 seconds; if no tool activity for 30 seconds (`STALL_DETECTION_SECONDS`), sends a nudge message to redirect the LLM
- **Nudge system**: Two types of nudges — redirect (if no security scanners invoked) and progress (if stuck after scanning); max 2 nudges per scan (`MAX_NUDGES`)
- **Tool activity tracking**: Monitors `TOOL_EXECUTION_START` and `TOOL_EXECUTION_COMPLETE` events; tracks whether the `skill` tool or known scanner commands (bandit, graudit, etc.) have been invoked via `SCANNING_TOOL_NAMES`
- **Partial results on timeout**: If the scan times out but an assistant message was captured, returns `status: "timeout"` with the partial result instead of just an error
- **Progress tracker integration**: Tracks file reads via the `view` tool and updates the global `ProgressTracker`

**Key constants** (defined at module level in `agent.py`):
| Constant | Value | Purpose |
|----------|-------|---------|
| `DEFAULT_SCAN_TIMEOUT_SECONDS` | `300.0` | Maximum wall-clock time for a scan |
| `STALL_DETECTION_SECONDS` | `30.0` | Inactivity threshold before sending a nudge |
| `SCANNING_TOOL_NAMES` | `{"skill"}` | Tool names that count as security scanning activity |
| `MAX_NUDGES` | `2` | Maximum nudge messages per scan |

---

### [x] Task 1.7b — Implement Configuration System `[S]`

**Depends on**: 1.7
**COMMIT**: `feat(core): add AgentSecConfig for customizable system message and prompts`
**STATUS**: ✅ COMPLETED

**What was done**:

1. Created `core/agentsec/config.py` with `AgentSecConfig` dataclass:
   - `system_message`: The AI's system prompt (who it is, what it does)
   - `initial_prompt`: The prompt template for scans (use `{folder_path}` placeholder)
   - `system_message_source` / `initial_prompt_source`: Track where each value originated (built-in, config file, CLI flag)
   - `load()`: Load configuration from YAML file or defaults
   - `with_overrides()`: Apply CLI overrides to existing config
   - `format_prompt()`: Replace `{folder_path}` placeholder

2. **Default system message** (`DEFAULT_SYSTEM_MESSAGE`) is a highly directive prompt that:
   - Identifies the agent as "AgentSec, an AI-powered security scanning agent" and "Malicious Code Scanner"
   - Lists all three available Copilot CLI tools (`bash`, `skill`, `view`) with usage instructions
   - Provides a structured scanning workflow (discover files → run scanners → manual inspection → generate report)
   - Includes comprehensive safety guardrails preventing execution of scanned code
   - Defends against prompt injection from analyzed code comments
   - Lists all available security scanner skills (bandit, graudit, guarddog, shellcheck, trivy, checkov, eslint, dependency-check)

3. **Default initial prompt** (`DEFAULT_INITIAL_PROMPT`) provides step-by-step instructions for the scan:
   - Use bash to discover files
   - Use skill tool to run security scanners
   - Use view for manual inspection
   - Compile findings into a structured Markdown report

4. Configuration sources (in priority order):
   - CLI arguments (highest priority)
   - YAML config file (`agentsec.yaml`)
   - Built-in defaults (lowest priority)

5. Config file search paths:
   - Current directory: `agentsec.yaml`, `agentsec.yml`, `.agentsec.yaml`, `.agentsec.yml`
   - User home directory
   - `~/.config/agentsec/`

6. External file support:
   - `system_message_file`: Path to file containing system message
   - `initial_prompt_file`: Path to file containing initial prompt

7. Source tracking constants:
   - `SOURCE_BUILTIN`, `SOURCE_CONFIG_FILE`, `SOURCE_CONFIG_FILE_REF`, `SOURCE_CLI_FLAG`, `SOURCE_CLI_FILE_FLAG`

8. Updated dependencies:
   - Added `pyyaml>=6.0` to `core/pyproject.toml`

9. Created example config file:
   - `agentsec.example.yaml` with documentation and examples

**Verification**:
```python
from agentsec.config import AgentSecConfig

# Load from defaults
config = AgentSecConfig()
print(config.system_message[:50])  # Should print default message

# Load from file
config = AgentSecConfig.load("./agentsec.yaml")

# Apply overrides
config = config.with_overrides(system_message="Custom AI...")

# Format prompt
prompt = config.format_prompt("./my-project")
print(prompt)  # Should include "./my-project"
```

---

### [x] Task 1.7c — Implement Progress Tracking System `[S]`

**Depends on**: 1.5, 1.6
**COMMIT**: `feat(core): add ProgressTracker for real-time scan feedback`
**STATUS**: ✅ COMPLETED

**What was done**:

1. Created `core/agentsec/progress.py` with:
   - `ProgressEventType` enum — Types of progress events (SCAN_STARTED, FILE_STARTED, FILE_FINISHED, etc.)
   - `ProgressEvent` dataclass — Event data (current file, files scanned, total files, issues found, elapsed time, percent complete)
   - `ProgressTracker` class — Thread-safe tracker with heartbeat support
   - `get_global_tracker()` / `set_global_tracker()` — Global tracker for skills to access

2. Updated `core/agentsec/skills.py` to report progress:
   - `list_files()` calls `tracker.set_total_files(count)` when files are discovered
   - `analyze_file()` calls `tracker.start_file()` and `tracker.finish_file()` for each file

3. Updated `cli/agentsec_cli/main.py` with progress display:
   - Visual progress bar: `[████████░░░░░░░░░░░░] 50%`
   - Spinner animation to show activity
   - Current file being scanned
   - Files scanned count / total files
   - Elapsed time tracking
   - Issues found counter
   - Periodic heartbeat events (every 3 seconds)

4. Added `core/tests/test_progress.py` with unit tests for progress tracking

**Progress Display Example**:
```
⠋ Starting security scan of ./my_project

  📁 Found 15 files to scan

  ⠹ [██████████░░░░░░░░░░] 50% Scanning (8/15): app.py
  ⚠️  Finished app.py: 2 issues found

✅ Scan complete: 15 files scanned, 5 issues found (23s)
```

**Programmatic Usage**:
```python
from agentsec.progress import (
    ProgressTracker,
    ProgressEvent,
    ProgressEventType,
    set_global_tracker,
)

# Create callback for progress events
def on_progress(event: ProgressEvent):
    if event.type == ProgressEventType.FILE_STARTED:
        print(f"Scanning: {event.current_file}")
    elif event.type == ProgressEventType.SCAN_FINISHED:
        print(f"Done: {event.issues_found} issues in {event.elapsed_seconds:.1f}s")

# Create and register tracker
tracker = ProgressTracker(callback=on_progress, heartbeat_interval=3.0)
set_global_tracker(tracker)

# Run scan (skills automatically report progress)
tracker.start_scan("./project")
result = await agent.scan("./project")
tracker.finish_scan()

# Clean up
set_global_tracker(None)
```

**Verification**:
```python
from agentsec.progress import ProgressTracker, ProgressEventType

events = []
tracker = ProgressTracker(callback=lambda e: events.append(e), heartbeat_interval=0)
tracker.start_scan("/test")
tracker.set_total_files(2)
tracker.start_file("file1.py")
tracker.finish_file("file1.py", issues_found=1)
tracker.finish_scan()

assert any(e.type == ProgressEventType.SCAN_STARTED for e in events)
assert any(e.type == ProgressEventType.FILE_FINISHED for e in events)
print("Progress tracking OK")
```

---

### [ ] Task 1.8 — Create verification test script `[S]`

**Depends on**: 1.7
**COMMIT**: `test(core): add integration test script for agent verification`

**What to do**:

1. Create `core/tests/test_skills.py` with unit tests for each skill:
   ```python
   """
   Unit tests for AgentSec skills.

   These tests verify that each skill function works correctly
   without needing a connection to Copilot.
   """

   import asyncio
   import os
   import tempfile
   import pytest

   from agentsec.skills import list_files, analyze_file, generate_report


   @pytest.mark.asyncio
   async def test_list_files_returns_files():
       """list_files should return files in a directory."""
       # Create a temporary directory with some files
       with tempfile.TemporaryDirectory() as temp_dir:
           # Create test files
           for name in ["file1.py", "file2.txt", "file3.js"]:
               file_path = os.path.join(temp_dir, name)
               with open(file_path, "w") as f:
                   f.write("# test content")

           result = await list_files(temp_dir)

           assert result["total"] == 3
           assert len(result["files"]) == 3
           assert result["folder"] == temp_dir

   @pytest.mark.asyncio
   async def test_list_files_nonexistent_folder():
       """list_files should handle missing folders gracefully."""
       result = await list_files("/nonexistent/folder/path")
       assert result["total"] == 0
       assert "error" in result

   @pytest.mark.asyncio
   async def test_analyze_file_finds_eval():
       """analyze_file should detect eval() calls."""
       with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
           f.write("result = eval(user_input)\n")
           temp_path = f.name

       try:
           result = await analyze_file(temp_path)
           assert result["severity"] == "error"
           assert any(i["type"] == "unsafe-eval" for i in result["issues"])
       finally:
           os.unlink(temp_path)

   @pytest.mark.asyncio
   async def test_analyze_file_finds_hardcoded_secret():
       """analyze_file should detect hardcoded passwords."""
       with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
           f.write('db_password="hunter2"\n')
           temp_path = f.name

       try:
           result = await analyze_file(temp_path)
           assert any(i["type"] == "hardcoded-secret" for i in result["issues"])
       finally:
           os.unlink(temp_path)

   @pytest.mark.asyncio
   async def test_analyze_file_clean_file():
       """analyze_file should return no issues for clean code."""
       with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
           f.write("def hello():\n    print('Hello World')\n")
           temp_path = f.name

       try:
           result = await analyze_file(temp_path)
           assert result["severity"] == "info"
           assert len(result["issues"]) == 0
       finally:
           os.unlink(temp_path)

   @pytest.mark.asyncio
   async def test_generate_report_with_issues():
       """generate_report should produce correct summary statistics."""
       mock_findings = [
           {
               "file": "app.py",
               "issues": [
                   {"type": "unsafe-eval", "message": "eval found", "severity": "HIGH", "line": 5},
                   {"type": "hardcoded-secret", "message": "password found", "severity": "MEDIUM", "line": 10},
               ],
               "severity": "error",
           },
           {
               "file": "utils.py",
               "issues": [],
               "severity": "info",
           },
       ]

       report = await generate_report(mock_findings)

       assert report["total_files"] == 2
       assert report["total_issues"] == 2
       assert report["high_count"] == 1
       assert report["medium_count"] == 1
       assert report["low_count"] == 0
       assert "app.py" in report["files_with_issues"]

   @pytest.mark.asyncio
   async def test_generate_report_no_issues():
       """generate_report should handle clean codebases."""
       mock_findings = [
           {"file": "clean.py", "issues": [], "severity": "info"},
       ]

       report = await generate_report(mock_findings)

       assert report["total_issues"] == 0
       assert "No security issues found" in report["summary"]
   ```

2. Run tests:
   ```powershell
   cd core
   pip install -e ".[dev]"
   pytest tests/ -v
   ```

**Verification**: All tests pass.

---

## Phase 1 Dependency Graph

```
Task 1.1 ─────────────────────────┐
  (root files)         [PARALLEL] │
                                  ├──► Task 1.3 ──► Task 1.4 ──┬──► Task 1.5 ─┐
Task 1.2 ─────────────────────────┘     (venv)      (list_files)│  (analyze)   │
  (core scaffolding)   [PARALLEL]                               │              ├──► Task 1.7 ──► Task 1.7b ──► Task 1.7c ──► Task 1.8
                                                                └──► Task 1.6 ─┘   (agent)       (config)       (progress)    (tests)
                                                                    (report)
```

---

## Phase 2 — CLI Interface

### [ ] Task 2.1 — Scaffold `cli/` package `[S]`

**Depends on**: 1.7
**COMMIT**: `feat(cli): scaffold agentsec-cli package with pyproject.toml`

**What to do**:

1. Create directory tree:
   ```
   cli/
   ├── agentsec_cli/
   │   ├── __init__.py
   │   └── main.py        (placeholder)
   ├── pyproject.toml
   └── README.md
   ```

2. `cli/pyproject.toml`:
   ```toml
   [build-system]
   requires = ["setuptools>=68.0", "wheel"]
   build-backend = "setuptools.backends._legacy:_Backend"

   [project]
   name = "agentsec-cli"
   version = "0.1.0"
   description = "AgentSec command-line security scanner"
   requires-python = ">=3.10"
   dependencies = [
       "agentsec-core>=0.1.0",
   ]

   [project.scripts]
   agentsec = "agentsec_cli.main:main"

   [project.optional-dependencies]
   dev = [
       "pytest>=7.0",
       "pytest-asyncio>=0.21",
   ]
   ```

3. `cli/agentsec_cli/__init__.py`:
   ```python
   """AgentSec CLI — command-line security scanner."""
   __version__ = "0.1.0"
   ```

4. Install: `pip install -e ./cli`

**Verification**: `pip show agentsec-cli` returns package info.

---

### [x] Task 2.2 — Implement CLI main entry point `[S]`

**Depends on**: 2.1, 1.7b, 1.7c
**COMMIT**: `feat(cli): implement scan command with argparse, config support, and progress output`
**STATUS**: ✅ COMPLETED

**What was done**:

Implemented `cli/agentsec_cli/main.py` with full configuration and progress support:

1. **Configuration options for scan command**:
   - `--config`, `-c`: Path to YAML config file
   - `--system-message`, `-s`: Override system message text
   - `--system-message-file`, `-sf`: Load system message from file
   - `--prompt`, `-p`: Override initial prompt template
   - `--prompt-file`, `-pf`: Load initial prompt from file

2. **Configuration loading flow**:
   - Load from config file (or auto-search for `agentsec.yaml`)
   - Apply CLI overrides (CLI takes priority over config file)
   - Pass config to `SecurityScannerAgent`

3. **Mutual exclusivity**:
   - `--system-message` and `--system-message-file` are mutually exclusive
   - `--prompt` and `--prompt-file` are mutually exclusive

4. **Progress display features**:
   - Visual progress bar: `[████████░░░░░░░░░░░░] 50%`
   - Animated spinner to show activity
   - Current file being scanned
   - Files scanned count / total files
   - Elapsed time tracking
   - Issues found counter
   - Heartbeat events every 3 seconds to show ongoing activity

**Usage examples**:
```bash
# Basic scan
agentsec scan ./src

# With config file
agentsec scan ./src --config ./agentsec.yaml

# Override system message
agentsec scan ./src --system-message "You are a security expert..."

# Load system message from file
agentsec scan ./src --system-message-file ./prompts/system.txt

# Override initial prompt
agentsec scan ./src --prompt "Quick scan of {folder_path}"

# Load prompt from file
agentsec scan ./src --prompt-file ./prompts/scan.txt
```

**Verification**:
```powershell
pip install -e ./cli
agentsec --version              # Should print: agentsec 0.1.0
agentsec --help                 # Should show help text
agentsec scan --help            # Should show scan help with config options
agentsec scan ./core --config ./agentsec.example.yaml  # Should use config
```

---

### [x] Task 2.3 — Create CLI README `[P]`

**Depends on**: 2.2
**COMMIT**: `docs(cli): add README with installation, usage, and configuration instructions`
**STATUS**: ✅ COMPLETED

**What was done**:

Updated `cli/README.md` with:
- Package description
- Installation instructions
- Usage examples including configuration options
- Configuration section explaining YAML file and CLI overrides
- Table of CLI options
- Troubleshooting section

---

### [x] Task 2.2b — Dynamic skill discovery from Copilot CLI `[S]`

**Depends on**: 2.2
**COMMIT**: `feat(core): add dynamic Copilot CLI skill discovery with tool availability checking`
**STATUS**: ✅ COMPLETED

**What was done**:

Replaced the hardcoded external tool list in the CLI with dynamic discovery that mirrors how the Copilot CLI finds agentic skills.

1. Created `core/agentsec/skill_discovery.py` with:
   - `discover_all_skills(project_root)`: Scans `~/.copilot/skills/` (user-level) and `<project>/.copilot/skills/` (project-level) for skill directories containing `SKILL.md`
   - `get_skill_summary(skills)`: Returns counts of total, available, unavailable, user-level, and project-level skills
   - `_parse_skill_frontmatter(path)`: Parses YAML frontmatter from `SKILL.md` without requiring PyYAML
   - `_derive_tool_name(dir_name)`: Falls back to stripping `-security-scan` suffix when skill is not in the known map
   - `SKILL_TO_TOOL_MAP`: Maps 9 known skill directory names to their underlying CLI tool binary names
   - Tool availability checked via `shutil.which()` at runtime

2. Updated `cli/agentsec_cli/main.py`:
   - `print_available_skills(folder_path)` now calls `discover_all_skills()` instead of printing a hardcoded list
   - Shows source directories with skill counts
   - Displays each tool with ✅ (installed) or ⬜ (not installed) status

3. Updated `core/agentsec/__init__.py`:
   - Exported `discover_all_skills` and `get_skill_summary`

**Skills discovered** (from `~/.copilot/skills/`):
- bandit ✅, checkov ✅, dependency-check ✅, eslint ✅, graudit ✅, guarddog ✅, shellcheck ✅, trivy ✅, template-analyzer ⬜

**CLI output example**:
```
📋 Available scanning skills:
  Built-in skills (registered @tool functions):
    • list_files       — Discover files in target directory
    • analyze_file     — Analyze a file for security vulnerabilities
    • generate_report  — Generate a formatted vulnerability report
  Copilot CLI agentic skills (8/9 tools available):
    📂 ~/.copilot/skills/ (9 skills)
    ✅ bandit               — Security audit of Python source code for vulnerabilities using Bandit AST analysis.
    ✅ checkov              — Scan IaC for security misconfigurations using Checkov.
    ...
    ⬜ template-analyzer    — Scan ARM/Bicep templates for security issues. (not installed)
```

---

### [ ] Task 2.4 — Verify CLI end-to-end `[S]`

**Depends on**: 2.2
**COMMIT**: `test(cli): verify CLI scan command end-to-end`

**What to do**:

1. Create a test folder with known vulnerabilities:
   ```powershell
   mkdir test-folder
   echo "result = eval(input())" > test-folder/vulnerable.py
   echo "def hello(): print('hi')" > test-folder/clean.py
   ```

2. Run the CLI scan (requires Copilot auth):
   ```powershell
   agentsec scan ./test-folder
   ```

3. Verify:
   - Output shows files scanned
   - Output mentions the eval() vulnerability
   - Clean exit (exit code 0)

4. Clean up:
   ```powershell
   Remove-Item -Recurse test-folder
   ```

**Verification**: CLI completes scan and reports findings.

---

## Phase 2 Dependency Graph

```
Task 1.7b (config) ──► Task 2.1 ──► Task 2.2 ──┬──► Task 2.2b (skill discovery) [SEQUENTIAL] ✅
                        (scaffold)   (main.py)   ├──► Task 2.3 (README) [PARALLEL]
                                                 └──► Task 2.4 (e2e verify) [SEQUENTIAL]
```

---

## Phase 3 — GUI Backend (FastAPI Server)

### [ ] Task 3.1 — Scaffold `desktop/backend/` package `[P with 3.2]`

**Depends on**: 1.7
**COMMIT**: `feat(backend): scaffold FastAPI backend package`

**What to do**:

1. Create directory tree:
   ```
   desktop/
   ├── backend/
   │   ├── __init__.py
   │   ├── server.py        (placeholder)
   │   ├── pyproject.toml
   │   └── requirements.txt
   └── README.md            (placeholder)
   ```

2. `desktop/backend/pyproject.toml`:
   ```toml
   [build-system]
   requires = ["setuptools>=68.0", "wheel"]
   build-backend = "setuptools.backends._legacy:_Backend"

   [project]
   name = "agentsec-backend"
   version = "0.1.0"
   description = "AgentSec desktop backend — FastAPI server"
   requires-python = ">=3.10"
   dependencies = [
       "agentsec-core>=0.1.0",
       "fastapi>=0.104.0",
       "uvicorn>=0.24.0",
       "python-dotenv>=1.0.0",
   ]
   ```

3. `desktop/backend/requirements.txt` (for non-editable installs):
   ```
   agentsec-core>=0.1.0
   fastapi>=0.104.0
   uvicorn>=0.24.0
   python-dotenv>=1.0.0
   ```

4. Install: `pip install -e ./desktop/backend`

**Verification**: `pip show agentsec-backend` returns package info.

---

### [ ] Task 3.2 — Implement FastAPI server with `/api/health` `[P with 3.1]`

**Depends on**: 1.7
**COMMIT**: `feat(backend): implement FastAPI server with health check endpoint`

**What to do**:

Implement initial server in `desktop/backend/server.py` with just the health endpoint and CORS.

**Full code**:
```python
"""
AgentSec Backend Server — FastAPI application.

This module provides the HTTP API for the AgentSec desktop application.
The Next.js frontend communicates with this server to run security scans.

Usage (development):
    python desktop/backend/server.py

The server will:
1. Find an available port automatically
2. Write the port number to a temp file (for Electron to read)
3. Start serving at http://127.0.0.1:<port>
"""

import logging
import os
import socket
import tempfile

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create the FastAPI application
app = FastAPI(
    title="AgentSec Backend",
    description="Backend API for the AgentSec security scanner desktop app",
    version="0.1.0",
)

# Configure CORS (Cross-Origin Resource Sharing)
# This is required so the Next.js frontend (running on a different port)
# can make requests to this backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",    # Next.js dev server
        "http://localhost:3001",    # Alternative dev port
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],            # Allow GET, POST, etc.
    allow_headers=["*"],            # Allow all headers
)


@app.get("/api/health")
async def health_check() -> dict:
    """
    Health check endpoint.

    The frontend and Electron app call this endpoint to verify
    that the backend server is running and ready to handle requests.

    Returns:
        Dictionary with:
        - "status": Always "ok" if the server is running
        - "service": Name of this service
        - "version": Current version
    """
    return {
        "status": "ok",
        "service": "agentsec-backend",
        "version": "0.1.0",
    }


def find_available_port() -> int:
    """
    Find a TCP port that is available on localhost.

    We use this instead of hardcoding a port (like 8000) because
    the user might already have something running on that port.

    Returns:
        An integer port number that is currently available.
    """
    # Create a socket and bind it to port 0
    # The OS will assign a random available port
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_socket.bind(("127.0.0.1", 0))
    port = test_socket.getsockname()[1]
    test_socket.close()
    return port


def write_port_file(port: int) -> str:
    """
    Write the server port to a temp file so Electron can read it.

    The Electron main process needs to know which port the FastAPI
    server is running on so it can proxy requests from the frontend.

    Args:
        port: The port number the server is listening on.

    Returns:
        The path to the temp file that was written.
    """
    # Use the OS temp directory for the port file
    port_file_path = os.path.join(tempfile.gettempdir(), "agentsec-port.txt")

    with open(port_file_path, "w") as port_file:
        port_file.write(str(port))

    logger.info(f"Port file written to: {port_file_path}")
    return port_file_path


if __name__ == "__main__":
    import uvicorn

    # Find an available port
    server_port = find_available_port()

    # Write the port to a file for Electron
    write_port_file(server_port)

    logger.info(f"Starting AgentSec backend on http://127.0.0.1:{server_port}")

    # Start the server
    uvicorn.run(
        app,
        host="127.0.0.1",      # Only listen on localhost (security)
        port=server_port,
        log_level="info",
    )
```

**Verification**:
```powershell
# Start server
python desktop/backend/server.py
# In another terminal:
curl http://127.0.0.1:<port>/api/health
# Should return: {"status":"ok","service":"agentsec-backend","version":"0.1.0"}
```

---

### [ ] Task 3.3 — Add `/api/scan` endpoint with SSE streaming `[S]`

**Depends on**: 3.1, 3.2
**COMMIT**: `feat(backend): add /api/scan endpoint with SSE streaming`

**What to do**:

Add the scan endpoint to `desktop/backend/server.py`. This endpoint should:
1. Accept a POST with `{"folder": "/path/to/scan"}`
2. Create a `SecurityScannerAgent` instance
3. Run the scan
4. Return results (initially as a regular JSON response)
5. Add a separate SSE endpoint `/api/scan/stream` for real-time updates

**Code to add to `server.py`** (after the health endpoint):

```python
from fastapi import Request
from fastapi.responses import StreamingResponse
import asyncio
import json

from agentsec.agent import SecurityScannerAgent


@app.post("/api/scan")
async def scan_folder(request: Request) -> dict:
    """
    Scan a folder for security vulnerabilities.

    This endpoint receives a folder path from the frontend,
    creates a SecurityScannerAgent, runs the scan, and returns results.

    Request body:
        {"folder": "/path/to/folder"}

    Returns:
        Dictionary with scan results or error information.
    """
    try:
        # Parse the request body
        body = await request.json()
        folder_path = body.get("folder")

        # Validate input
        if not folder_path:
            return {"status": "error", "error": "Missing 'folder' in request body"}

        # Create and initialize the agent
        agent = SecurityScannerAgent()

        try:
            await agent.initialize()

            # Run the scan
            result = await agent.scan(folder_path)
            return result

        finally:
            # Always clean up the agent
            await agent.cleanup()

    except Exception as error:
        logger.error(f"Scan endpoint error: {error}")
        return {
            "status": "error",
            "error": f"Scan failed: {str(error)}",
        }


@app.post("/api/scan/stream")
async def scan_folder_stream(request: Request):
    """
    Scan a folder and stream progress updates via Server-Sent Events (SSE).

    This endpoint is used by the frontend to show real-time progress
    during a scan. Each SSE event contains a JSON object with:
    - "event": The type of event (started, progress, complete, error)
    - "data": Event-specific data

    Request body:
        {"folder": "/path/to/folder"}
    """
    body = await request.json()
    folder_path = body.get("folder")

    if not folder_path:
        async def error_stream():
            yield f"data: {json.dumps({'event': 'error', 'message': 'Missing folder path'})}\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")

    async def scan_event_stream():
        """Generator that yields SSE events during the scan."""
        agent = SecurityScannerAgent()

        try:
            # Event 1: Scan started
            yield f"data: {json.dumps({'event': 'started', 'folder': folder_path})}\n\n"

            # Initialize the agent
            yield f"data: {json.dumps({'event': 'progress', 'message': 'Initializing scanner...'})}\n\n"
            await agent.initialize()

            # Run the scan
            yield f"data: {json.dumps({'event': 'progress', 'message': f'Scanning {folder_path}...'})}\n\n"
            result = await agent.scan(folder_path)

            # Event: Scan complete
            yield f"data: {json.dumps({'event': 'complete', 'result': result})}\n\n"

        except Exception as error:
            # Event: Error
            yield f"data: {json.dumps({'event': 'error', 'message': str(error)})}\n\n"

        finally:
            await agent.cleanup()
            # Final event to signal end of stream
            yield f"data: {json.dumps({'event': 'done'})}\n\n"

    return StreamingResponse(
        scan_event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )
```

**Verification**:
```powershell
# Start server
python desktop/backend/server.py

# Test JSON endpoint
curl -X POST http://127.0.0.1:<port>/api/scan -H "Content-Type: application/json" -d '{"folder": "./core"}'

# Test SSE endpoint
curl -N -X POST http://127.0.0.1:<port>/api/scan/stream -H "Content-Type: application/json" -d '{"folder": "./core"}'
```

---

### [ ] Task 3.4 — Add graceful shutdown handler `[S]`

**Depends on**: 3.3
**COMMIT**: `feat(backend): add graceful shutdown with signal handlers`

**What to do**:

Add signal handlers to `server.py` so that when Electron kills the process (or the user presses Ctrl+C), the server shuts down cleanly.

**Code to add at the bottom of `server.py`** (replace the `if __name__` block):

```python
import signal
import sys


def create_shutdown_handler(server_port: int):
    """
    Create a signal handler that cleans up when the process is terminated.

    This is important for the Electron integration: when the user closes
    the desktop app, Electron sends a termination signal. We need to
    clean up the port file and stop the server gracefully.

    Args:
        server_port: The port number, used to identify the port file.
    """
    def handle_shutdown(signal_number, frame):
        """Handle SIGTERM and SIGINT signals."""
        logger.info(f"Received shutdown signal ({signal_number}), cleaning up...")

        # Remove the port file so Electron knows the server has stopped
        port_file_path = os.path.join(tempfile.gettempdir(), "agentsec-port.txt")
        if os.path.exists(port_file_path):
            os.remove(port_file_path)
            logger.info(f"Removed port file: {port_file_path}")

        logger.info("AgentSec backend shut down cleanly")
        sys.exit(0)

    return handle_shutdown


if __name__ == "__main__":
    import uvicorn

    # Find an available port
    server_port = find_available_port()

    # Write the port file
    write_port_file(server_port)

    # Register shutdown handlers
    shutdown_handler = create_shutdown_handler(server_port)
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    logger.info(f"Starting AgentSec backend on http://127.0.0.1:{server_port}")

    # Start the server
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=server_port,
        log_level="info",
    )
```

**Verification**: Start server, then press Ctrl+C. Confirm:
- Server logs "Received shutdown signal"
- Port file is deleted
- Process exits cleanly (exit code 0)

---

## Phase 3 Dependency Graph

```
Task 1.7 (agent) ──┬──► Task 3.1 (scaffold)    [PARALLEL] ──┐
                   │                                          ├──► Task 3.3 ──► Task 3.4
                   └──► Task 3.2 (health endpoint) [PARALLEL] ┘   (scan API)   (shutdown)
```

---

## Phase 4 — GUI Frontend (Next.js/React)

### [ ] Task 4.1 — Initialize Next.js project `[P with 4.2]`

**Depends on**: nothing (can start in parallel with Phase 3)
**COMMIT**: `feat(frontend): initialize Next.js project with TypeScript and TailwindCSS`

**What to do**:

1. From workspace root:
   ```powershell
   cd desktop/frontend
   npx create-next-app@latest . --typescript --tailwind --eslint --app --src-dir --no-import-alias
   ```

2. Configure API base URL in `desktop/frontend/.env.local`:
   ```env
   NEXT_PUBLIC_API_URL=http://localhost:8000
   ```

3. Create a `desktop/frontend/lib/api.ts` utility for API calls:
   ```typescript
   /**
    * API utility for communicating with the AgentSec backend.
    *
    * This module provides helper functions for making HTTP requests
    * to the FastAPI backend server.
    */

   /** Base URL for the backend API, configurable via environment variable */
   const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

   /**
    * Check if the backend server is running and healthy.
    *
    * @returns true if server responds with status "ok", false otherwise
    */
   export async function checkHealth(): Promise<boolean> {
     try {
       const response = await fetch(`${API_BASE_URL}/api/health`);
       const data = await response.json();
       return data.status === "ok";
     } catch {
       return false;
     }
   }

   /**
    * Get the base URL for the API.
    * Used by components that need to build custom URLs (e.g., for SSE).
    */
   export function getApiBaseUrl(): string {
     return API_BASE_URL;
   }
   ```

4. Clean up default Next.js boilerplate in `src/app/page.tsx`  — replace with a simple "AgentSec" heading placeholder.

**Verification**: `npm run dev` starts without errors, browser shows placeholder page at `localhost:3000`.

---

### [ ] Task 4.2 — Build `FolderSelector` component `[P with 4.1]`

**Depends on**: nothing (design/component work, no backend dependency)
**COMMIT**: `feat(frontend): implement FolderSelector component`

**What to do**:

Create `desktop/frontend/src/components/FolderSelector.tsx`:

```typescript
/**
 * FolderSelector component — lets the user choose a folder to scan.
 *
 * In the web browser, this is a text input where the user types a folder path.
 * In the Electron desktop app, this will be enhanced with a native folder picker.
 *
 * Props:
 *   onFolderSelected: Callback called when the user submits a folder path
 *   disabled: Whether the input is disabled (e.g., during a scan)
 */

"use client";

import { useState, FormEvent } from "react";

interface FolderSelectorProps {
  /** Called when the user selects a folder path */
  onFolderSelected: (folderPath: string) => void;
  /** Disable the input and button (e.g., while scanning) */
  disabled?: boolean;
}

export default function FolderSelector({
  onFolderSelected,
  disabled = false,
}: FolderSelectorProps) {
  // Track the current text in the input field
  const [folderPath, setFolderPath] = useState<string>("");

  /**
   * Handle form submission.
   * Prevents the default page reload and calls the parent callback.
   */
  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();

    // Only submit if the user entered something
    const trimmedPath = folderPath.trim();
    if (trimmedPath.length > 0) {
      onFolderSelected(trimmedPath);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex gap-3 items-end">
      {/* Folder path input */}
      <div className="flex-1">
        <label
          htmlFor="folder-path"
          className="block text-sm font-medium text-gray-700 mb-1"
        >
          Folder to scan
        </label>
        <input
          id="folder-path"
          type="text"
          value={folderPath}
          onChange={(e) => setFolderPath(e.target.value)}
          placeholder="Enter folder path (e.g., ./src or C:\code\myapp)"
          disabled={disabled}
          className="w-full px-4 py-2 border border-gray-300 rounded-lg
                     focus:ring-2 focus:ring-blue-500 focus:border-blue-500
                     disabled:bg-gray-100 disabled:text-gray-500"
        />
      </div>

      {/* Scan button */}
      <button
        type="submit"
        disabled={disabled || folderPath.trim().length === 0}
        className="px-6 py-2 bg-blue-600 text-white rounded-lg font-medium
                   hover:bg-blue-700 focus:ring-2 focus:ring-blue-500
                   disabled:bg-gray-400 disabled:cursor-not-allowed
                   transition-colors"
      >
        {disabled ? "Scanning..." : "Scan"}
      </button>
    </form>
  );
}
```

**Verification**: Component renders in browser with input and button.

---

### [ ] Task 4.3 — Build `ScanProgress` component `[S]`

**Depends on**: 4.1
**COMMIT**: `feat(frontend): implement ScanProgress SSE streaming component`

**What to do**:

Create `desktop/frontend/src/components/ScanProgress.tsx`:

```typescript
/**
 * ScanProgress component — shows real-time scan progress via SSE.
 *
 * This component connects to the /api/scan/stream endpoint using
 * Server-Sent Events and displays each progress message as it arrives.
 * This gives the user real-time feedback during the scan.
 *
 * Props:
 *   messages: Array of progress message strings to display
 *   isScanning: Whether a scan is currently in progress
 */

"use client";

interface ScanProgressProps {
  /** List of progress messages received from the backend */
  messages: string[];
  /** Whether a scan is currently running */
  isScanning: boolean;
}

export default function ScanProgress({
  messages,
  isScanning,
}: ScanProgressProps) {
  // Don't render anything if there are no messages
  if (messages.length === 0 && !isScanning) {
    return null;
  }

  return (
    <div className="mt-6">
      <h2 className="text-lg font-semibold text-gray-800 mb-2">
        {isScanning ? "Scan in progress..." : "Scan progress"}
      </h2>

      {/* Progress messages list */}
      <div className="bg-gray-50 rounded-lg p-4 max-h-48 overflow-y-auto">
        {messages.map((message, index) => (
          <div
            key={index}
            className="flex items-start gap-2 py-1 text-sm text-gray-600"
          >
            {/* Show a spinner for the last message if still scanning */}
            <span className="text-gray-400 mt-0.5">
              {isScanning && index === messages.length - 1 ? "⏳" : "✓"}
            </span>
            <span>{message}</span>
          </div>
        ))}
      </div>

      {/* Loading indicator */}
      {isScanning && (
        <div className="mt-2 flex items-center gap-2 text-sm text-blue-600">
          <div className="w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
          <span>Analyzing files...</span>
        </div>
      )}
    </div>
  );
}
```

**Verification**: Component renders placeholder UI when passed mock messages.

---

### [ ] Task 4.4 — Build `ResultsPanel` component `[P with 4.3]`

**Depends on**: 4.1
**COMMIT**: `feat(frontend): implement ResultsPanel component for displaying findings`

**What to do**:

Create `desktop/frontend/src/components/ResultsPanel.tsx`:

```typescript
/**
 * ResultsPanel component — displays security scan findings.
 *
 * This component takes the scan result from the backend and displays
 * it in a structured, readable format. It shows:
 * - Overall scan status
 * - The full text result from the agent
 *
 * Props:
 *   result: The scan result object from the backend, or null if no scan done yet
 */

"use client";

interface ScanResult {
  status: "success" | "timeout" | "error";
  result?: string;
  error?: string;
}

interface ResultsPanelProps {
  /** The scan result, or null if no result yet */
  result: ScanResult | null;
}

export default function ResultsPanel({ result }: ResultsPanelProps) {
  // Don't render if no result yet
  if (!result) {
    return null;
  }

  // Choose styling based on status
  const statusStyles: Record<string, string> = {
    success: "bg-green-50 border-green-200 text-green-800",
    timeout: "bg-yellow-50 border-yellow-200 text-yellow-800",
    error: "bg-red-50 border-red-200 text-red-800",
  };

  const statusLabels: Record<string, string> = {
    success: "Scan Complete",
    timeout: "Scan Timed Out",
    error: "Scan Failed",
  };

  const statusStyle = statusStyles[result.status] || statusStyles.error;
  const statusLabel = statusLabels[result.status] || "Unknown Status";

  return (
    <div className="mt-6">
      {/* Status banner */}
      <div className={`p-4 rounded-lg border ${statusStyle} mb-4`}>
        <h2 className="text-lg font-semibold">{statusLabel}</h2>
      </div>

      {/* Result content */}
      {result.result && (
        <div className="bg-gray-900 text-gray-100 rounded-lg p-6 overflow-x-auto">
          <pre className="whitespace-pre-wrap font-mono text-sm">
            {result.result}
          </pre>
        </div>
      )}

      {/* Error message */}
      {result.error && (
        <div className="bg-red-50 rounded-lg p-4 text-red-700 text-sm">
          <strong>Error:</strong> {result.error}
        </div>
      )}
    </div>
  );
}
```

**Verification**: Component displays mocked success, error, and timeout results.

---

### [ ] Task 4.5 — Wire up main page with all components `[S]`

**Depends on**: 4.2, 4.3, 4.4
**COMMIT**: `feat(frontend): connect all components in main page with SSE integration`

**What to do**:

Replace `desktop/frontend/src/app/page.tsx` with the full scanning page:

```typescript
/**
 * AgentSec main page — the home screen of the security scanner.
 *
 * This page connects three components together:
 * 1. FolderSelector — user picks a folder to scan
 * 2. ScanProgress — shows real-time scan progress via SSE
 * 3. ResultsPanel — displays the final scan results
 *
 * The page manages the overall scan state and coordinates
 * communication between the components and the backend API.
 */

"use client";

import { useState, useCallback } from "react";
import FolderSelector from "@/components/FolderSelector";
import ScanProgress from "@/components/ScanProgress";
import ResultsPanel from "@/components/ResultsPanel";
import { getApiBaseUrl } from "@/lib/api";

/** Shape of the scan result from the backend */
interface ScanResult {
  status: "success" | "timeout" | "error";
  result?: string;
  error?: string;
}

export default function HomePage() {
  // State for tracking scan progress
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [progressMessages, setProgressMessages] = useState<string[]>([]);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  /**
   * Handle the scan workflow.
   *
   * This function:
   * 1. Connects to the SSE streaming endpoint
   * 2. Reads events as they arrive
   * 3. Updates progress messages in real-time
   * 4. Sets the final result when complete
   */
  const handleScan = useCallback(async (folderPath: string) => {
    // Reset state for new scan
    setIsScanning(true);
    setProgressMessages([]);
    setScanResult(null);

    const apiUrl = getApiBaseUrl();

    try {
      // Connect to the SSE streaming endpoint
      const response = await fetch(`${apiUrl}/api/scan/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ folder: folderPath }),
      });

      // Check for HTTP errors
      if (!response.ok) {
        throw new Error(`Server responded with status ${response.status}`);
      }

      // Read the SSE stream
      const reader = response.body?.getReader();
      if (!reader) {
        throw new Error("No response body to read");
      }

      const decoder = new TextDecoder();

      // Read chunks from the stream
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        // Decode the chunk into text
        const chunk = decoder.decode(value, { stream: true });

        // Each SSE event starts with "data: " and ends with "\n\n"
        const lines = chunk.split("\n");
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const eventData = JSON.parse(line.slice(6));

              // Handle different event types
              if (eventData.event === "started") {
                setProgressMessages((prev) => [
                  ...prev,
                  `Started scanning: ${eventData.folder}`,
                ]);
              } else if (eventData.event === "progress") {
                setProgressMessages((prev) => [
                  ...prev,
                  eventData.message,
                ]);
              } else if (eventData.event === "complete") {
                setScanResult(eventData.result);
              } else if (eventData.event === "error") {
                setScanResult({
                  status: "error",
                  error: eventData.message,
                });
              }
            } catch {
              // Skip non-JSON lines
            }
          }
        }
      }
    } catch (error) {
      // Handle connection or network errors
      const errorMessage = error instanceof Error
        ? error.message
        : "Unknown error occurred";

      setScanResult({
        status: "error",
        error: `Failed to connect to backend: ${errorMessage}`,
      });
    } finally {
      setIsScanning(false);
    }
  }, []);

  return (
    <main className="min-h-screen bg-white">
      {/* Header */}
      <div className="bg-gray-900 text-white py-6 px-8">
        <h1 className="text-2xl font-bold">AgentSec</h1>
        <p className="text-gray-400 text-sm mt-1">
          AI-powered security scanner for your code
        </p>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-8 py-8">
        {/* Folder selection */}
        <FolderSelector
          onFolderSelected={handleScan}
          disabled={isScanning}
        />

        {/* Scan progress */}
        <ScanProgress
          messages={progressMessages}
          isScanning={isScanning}
        />

        {/* Results */}
        <ResultsPanel result={scanResult} />
      </div>
    </main>
  );
}
```

**Verification**: Run `npm run dev`, open `localhost:3000`. Verify:
- Folder input and scan button render
- Entering folder path and clicking Scan attempts connection to backend
- If backend is running, SSE events are displayed

---

### [ ] Task 4.6 — Frontend end-to-end verification `[S]`

**Depends on**: 4.5, 3.3
**COMMIT**: `test(frontend): verify end-to-end frontend-to-backend flow`

**What to do**:

1. Start backend: `python desktop/backend/server.py`
2. Note the port from the log output
3. Update `desktop/frontend/.env.local` to match the port
4. Start frontend: `cd desktop/frontend && npm run dev`
5. Open browser to `localhost:3000`
6. Enter `./core` as the folder path and click Scan
7. Verify:
   - Progress messages appear in real-time
   - Final results are displayed
   - No console errors in browser dev tools

**Verification**: Full scan completes from UI to backend to agent and back.

---

## Phase 4 Dependency Graph

```
                    ┌──► Task 4.2 (FolderSelector) [PARALLEL] ──┐
Task 4.1 (init) ──►├──► Task 4.3 (ScanProgress)   [SEQUENTIAL] ├──► Task 4.5 ──► Task 4.6
  [PARALLEL w/     └──► Task 4.4 (ResultsPanel)   [PARALLEL]   ┘   (wire up)    (e2e)
   Phase 3]                                                              │
                                                                         │
Task 3.3 (scan API) ────────────────────────────────────────────────────┘
```

---

## Phase 5 — Desktop Packaging (Electron)

### [ ] Task 5.1 — Initialize Electron project structure `[S]`

**Depends on**: 4.5
**COMMIT**: `feat(desktop): initialize Electron project with package.json and dependencies`

**What to do**:

1. Create/update `desktop/package.json`:
   ```json
   {
     "name": "agentsec-desktop",
     "version": "0.1.0",
     "description": "AgentSec Desktop — AI-powered security scanner",
     "main": "main.js",
     "scripts": {
       "start": "electron .",
       "dev": "concurrently \"cd frontend && npm run dev\" \"electron .\"",
       "build:frontend": "cd frontend && npm run build && npm run export",
       "build:win": "npm run build:frontend && electron-builder --win",
       "build:mac": "npm run build:frontend && electron-builder --mac"
     },
     "devDependencies": {
       "electron": "^28.0.0",
       "electron-builder": "^24.0.0",
       "concurrently": "^8.2.0"
     }
   }
   ```

2. Install dependencies:
   ```powershell
   cd desktop
   npm install
   ```

**Verification**: `npx electron --version` prints a version number.

---

### [ ] Task 5.2 — Implement Electron main process `[S]`

**Depends on**: 5.1
**COMMIT**: `feat(desktop): implement Electron main process with FastAPI subprocess management`

**What to do**:

Create `desktop/main.js`:

```javascript
/**
 * AgentSec Desktop — Electron main process.
 *
 * This file is the entry point for the Electron desktop application.
 * It manages:
 * 1. Starting the FastAPI backend as a child process
 * 2. Waiting for the backend to be ready
 * 3. Creating the browser window pointing to the frontend
 * 4. Shutting down the backend when the app closes
 */

const { app, BrowserWindow } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");
const http = require("http");

/** Reference to the FastAPI child process */
let backendProcess = null;

/** Reference to the main browser window */
let mainWindow = null;

/** Path to the port file written by the backend */
const PORT_FILE_PATH = path.join(os.tmpdir(), "agentsec-port.txt");

/**
 * Start the FastAPI backend server as a child process.
 *
 * The backend will find an available port and write it to a temp file.
 * We wait for that file to appear, then read the port number.
 *
 * @returns {Promise<number>} The port number the backend is listening on
 */
function startBackend() {
  return new Promise((resolve, reject) => {
    // Remove old port file if it exists
    if (fs.existsSync(PORT_FILE_PATH)) {
      fs.unlinkSync(PORT_FILE_PATH);
    }

    // Path to the backend server script
    const serverScript = path.join(__dirname, "backend", "server.py");

    // Determine Python executable (prefer venv)
    const venvPython = path.join(__dirname, "..", "venv", "Scripts", "python.exe");
    const pythonCmd = fs.existsSync(venvPython) ? venvPython : "python";

    // Start the backend process
    backendProcess = spawn(pythonCmd, [serverScript], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env },
    });

    // Log backend output
    backendProcess.stdout.on("data", (data) => {
      console.log(`[Backend] ${data.toString().trim()}`);
    });

    backendProcess.stderr.on("data", (data) => {
      console.error(`[Backend] ${data.toString().trim()}`);
    });

    backendProcess.on("error", (error) => {
      console.error(`Failed to start backend: ${error.message}`);
      reject(error);
    });

    // Poll for the port file (backend writes it when ready)
    const maxWaitMs = 15000; // 15 seconds maximum
    const pollIntervalMs = 200;
    let elapsed = 0;

    const pollInterval = setInterval(() => {
      elapsed += pollIntervalMs;

      if (fs.existsSync(PORT_FILE_PATH)) {
        clearInterval(pollInterval);
        const port = parseInt(fs.readFileSync(PORT_FILE_PATH, "utf-8").trim());
        console.log(`Backend started on port ${port}`);
        resolve(port);
      }

      if (elapsed >= maxWaitMs) {
        clearInterval(pollInterval);
        reject(new Error("Backend did not start within 15 seconds"));
      }
    }, pollIntervalMs);
  });
}

/**
 * Wait for the backend to respond to health checks.
 *
 * @param {number} port - The port to check
 * @param {number} maxRetries - Maximum number of retries
 * @returns {Promise<void>}
 */
function waitForBackendReady(port, maxRetries = 30) {
  return new Promise((resolve, reject) => {
    let retries = 0;

    const checkHealth = () => {
      const request = http.get(`http://127.0.0.1:${port}/api/health`, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else {
          retry();
        }
      });

      request.on("error", () => retry());
      request.setTimeout(1000, () => {
        request.destroy();
        retry();
      });
    };

    const retry = () => {
      retries++;
      if (retries >= maxRetries) {
        reject(new Error("Backend health check failed after max retries"));
      } else {
        setTimeout(checkHealth, 500);
      }
    };

    checkHealth();
  });
}

/**
 * Create the main application window.
 *
 * @param {number} backendPort - The port the backend is running on
 */
function createWindow(backendPort) {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: "AgentSec",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // In development, load from Next.js dev server
  // In production, load from the exported static files
  const isDev = !app.isPackaged;

  if (isDev) {
    mainWindow.loadURL("http://localhost:3000");
    mainWindow.webContents.openDevTools();
  } else {
    // Load the static export
    mainWindow.loadFile(path.join(__dirname, "frontend", "out", "index.html"));
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

/**
 * Stop the backend process gracefully.
 */
function stopBackend() {
  if (backendProcess) {
    console.log("Stopping backend server...");

    // On Windows, we need to kill the process tree
    if (process.platform === "win32") {
      spawn("taskkill", ["/pid", backendProcess.pid.toString(), "/f", "/t"]);
    } else {
      backendProcess.kill("SIGTERM");
    }

    backendProcess = null;
  }

  // Clean up port file
  if (fs.existsSync(PORT_FILE_PATH)) {
    fs.unlinkSync(PORT_FILE_PATH);
  }
}

// === Application lifecycle ===

app.whenReady().then(async () => {
  try {
    console.log("Starting AgentSec Desktop...");

    // Step 1: Start the backend
    const port = await startBackend();

    // Step 2: Wait for backend to be ready
    console.log("Waiting for backend to be ready...");
    await waitForBackendReady(port);
    console.log("Backend is ready!");

    // Step 3: Create the window
    createWindow(port);
  } catch (error) {
    console.error(`Failed to start: ${error.message}`);
    app.quit();
  }
});

app.on("window-all-closed", () => {
  stopBackend();
  app.quit();
});

app.on("before-quit", () => {
  stopBackend();
});
```

**Verification**: `cd desktop && npm start` launches the app (requires backend and frontend running).

---

### [ ] Task 5.3 — Create Electron preload script `[P with 5.2]`

**Depends on**: 5.1
**COMMIT**: `feat(desktop): add preload script for secure IPC bridge`

**What to do**:

Create `desktop/preload.js`:

```javascript
/**
 * Preload script for AgentSec Desktop.
 *
 * This script runs in a sandboxed environment before the web page loads.
 * It provides a secure bridge between the Electron main process and
 * the web content (Next.js frontend).
 *
 * The contextBridge.exposeInMainWorld() function makes specific APIs
 * available to the frontend without giving it full Node.js access.
 */

const { contextBridge, ipcRenderer } = require("electron");

// Expose a limited API to the frontend
contextBridge.exposeInMainWorld("electronAPI", {
  /**
   * Get the platform the app is running on.
   * @returns {"win32" | "darwin" | "linux"}
   */
  getPlatform: () => process.platform,

  /**
   * Check if running inside Electron (vs. a regular browser).
   * @returns {true}
   */
  isElectron: true,

  /**
   * Open a native folder picker dialog.
   * This sends a message to the main process which opens the dialog.
   *
   * @returns {Promise<string | null>} The selected folder path, or null if cancelled
   */
  selectFolder: () => ipcRenderer.invoke("select-folder"),
});
```

**Verification**: File created, no syntax errors.

---

### [ ] Task 5.4 — Configure electron-builder for installers `[S]`

**Depends on**: 5.2, 5.3
**COMMIT**: `feat(desktop): configure electron-builder for Windows and macOS installers`

**What to do**:

Create `desktop/electron-builder.json`:

```json
{
  "appId": "com.agentsec.desktop",
  "productName": "AgentSec",
  "directories": {
    "output": "release"
  },
  "files": [
    "main.js",
    "preload.js",
    "frontend/out/**/*",
    "backend/**/*",
    "!backend/__pycache__",
    "!backend/*.pyc"
  ],
  "extraResources": [
    {
      "from": "../venv",
      "to": "venv",
      "filter": ["**/*"]
    }
  ],
  "win": {
    "target": "nsis",
    "icon": "assets/icon.ico"
  },
  "nsis": {
    "oneClick": false,
    "perMachine": false,
    "allowToChangeInstallationDirectory": true,
    "createDesktopShortcut": true,
    "createStartMenuShortcut": true
  },
  "mac": {
    "target": "dmg",
    "icon": "assets/icon.icns",
    "category": "public.app-category.developer-tools"
  },
  "dmg": {
    "contents": [
      { "x": 130, "y": 220 },
      { "x": 410, "y": 220, "type": "link", "path": "/Applications" }
    ]
  }
}
```

Create `desktop/assets/` directory for app icons (placeholder).

**Verification**: `cd desktop && npx electron-builder --win --dry-run` runs without errors (may warn about missing icons which is expected).

---

### [ ] Task 5.5 — Add native folder picker IPC handler `[S]`

**Depends on**: 5.2, 5.3
**COMMIT**: `feat(desktop): add native folder picker dialog via IPC`

**What to do**:

Add IPC handler to `desktop/main.js` (before the `app.whenReady()` block):

```javascript
const { dialog, ipcMain } = require("electron");

// Handle folder picker requests from the renderer (frontend)
ipcMain.handle("select-folder", async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openDirectory"],
    title: "Select folder to scan",
  });

  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }

  return result.filePaths[0];
});
```

Update `FolderSelector.tsx` to detect Electron and use native picker:

Add to the component:
```typescript
// Check if running in Electron
const isElectron = typeof window !== "undefined" && (window as any).electronAPI?.isElectron;

const handleBrowse = async () => {
  if (isElectron) {
    const selectedPath = await (window as any).electronAPI.selectFolder();
    if (selectedPath) {
      setFolderPath(selectedPath);
    }
  }
};
```

Add a "Browse" button next to the text input that only appears in Electron.

**Verification**: Running in Electron shows a Browse button; clicking it opens native folder dialog.

---

### [ ] Task 5.6 — Desktop end-to-end verification `[S]`

**Depends on**: 5.4, 5.5
**COMMIT**: `test(desktop): verify end-to-end desktop app functionality`

**What to do**:

1. Build the frontend for production:
   ```powershell
   cd desktop/frontend
   npm run build
   # If using Next.js static export:
   # Ensure next.config.js has `output: 'export'`
   ```

2. Start the desktop app in dev mode:
   ```powershell
   cd desktop
   npm run dev
   ```

3. Verify:
   - Electron window opens
   - Backend starts automatically (check terminal logs)
   - Enter folder path or use Browse button
   - Click Scan
   - Progress messages appear
   - Results display correctly
   - Closing the window stops the backend process

**Verification**: Full desktop workflow works end-to-end.

---

## Phase 5 Dependency Graph

```
Task 4.5 ──► Task 5.1 ──┬──► Task 5.2 (main.js)   [PARALLEL] ──┬──► Task 5.5 ──► Task 5.6
              (init)     │                                        │   (folder IPC)  (e2e)
                         └──► Task 5.3 (preload.js) [PARALLEL] ──┤
                                                                  │
                              Task 5.4 (builder config) ─────────┘
```

---

## Phase 6 — Documentation & Development Tooling

### [ ] Task 6.1 — Write root README with architecture diagram `[P]`

**Depends on**: Phase 5 completion
**COMMIT**: `docs: add comprehensive root README with architecture overview`

**What to do**:

Replace `README.md` at workspace root with:
- Project description and features
- ASCII architecture diagram showing monorepo structure
- Quick start instructions for both CLI and Desktop
- Links to per-package READMEs
- Prerequisites (Python 3.12, Node.js 18+, Copilot CLI)
- Development setup steps

**Architecture diagram to include**:
```
┌─────────────── AgentSec Monorepo ───────────────┐
│                                                   │
│  ┌──────────┐   ┌──────────────────────────────┐ │
│  │          │   │     desktop/                  │ │
│  │  cli/    │   │  ┌──────────┐  ┌───────────┐ │ │
│  │          │   │  │ backend/ │  │ frontend/  │ │ │
│  │ main.py ─┼───┤  │ FastAPI  │←─│  Next.js   │ │ │
│  │          │   │  └────┬─────┘  └───────────┘ │ │
│  └────┬─────┘   │       │        ┌───────────┐ │ │
│       │         │       │        │ Electron   │ │ │
│       │         │       │        │ (wrapper)  │ │ │
│       │         │       │        └───────────┘ │ │
│       │         └───────┼──────────────────────┘ │
│       │                 │                         │
│       ▼                 ▼                         │
│  ┌────────────────────────────────┐               │
│  │         core/                  │               │
│  │  SecurityScannerAgent          │               │
│  │  + @tool skills                │               │
│  │  (list_files, analyze_file,    │               │
│  │   generate_report)             │               │
│  └───────────────┬────────────────┘               │
│                  │                                │
│                  ▼                                │
│     GitHub Copilot SDK (LLM inference)           │
└──────────────────────────────────────────────────┘
```

**Verification**: README renders correctly on GitHub / VS Code preview.

---

### [ ] Task 6.2 — Write per-package README files `[P with 6.1]`

**Depends on**: Phase 5 completion
**COMMIT**: `docs: add README files for core, cli, and desktop packages`

**What to do**:

1. `core/README.md` — Agent architecture, skill development guide, how to test
2. `cli/README.md` — Installation, usage examples, configuration
3. `desktop/README.md` — Build instructions, development workflow, troubleshooting

Each should include:
- Purpose of the package
- How to set up for development
- How to run tests
- How to extend/modify

**Verification**: All READMEs render correctly.

---

### [ ] Task 6.3 — Create VS Code launch.json `[P with 6.1]`

**Depends on**: Phase 3 completion
**COMMIT**: `chore: add VS Code debug configurations`

**What to do**:

Create `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug: Agent Test",
      "type": "debugpy",
      "request": "launch",
      "module": "pytest",
      "args": ["core/tests/", "-v"],
      "console": "integratedTerminal",
      "justMyCode": true
    },
    {
      "name": "Debug: CLI Scan",
      "type": "debugpy",
      "request": "launch",
      "module": "agentsec_cli.main",
      "args": ["scan", "./core"],
      "console": "integratedTerminal",
      "justMyCode": true
    },
    {
      "name": "Debug: FastAPI Backend",
      "type": "debugpy",
      "request": "launch",
      "program": "${workspaceFolder}/desktop/backend/server.py",
      "console": "integratedTerminal",
      "justMyCode": true
    },
    {
      "name": "Debug: Electron App",
      "type": "node",
      "request": "launch",
      "cwd": "${workspaceFolder}/desktop",
      "runtimeExecutable": "${workspaceFolder}/desktop/node_modules/.bin/electron",
      "args": ["."],
      "console": "integratedTerminal"
    }
  ]
}
```

**Verification**: Each configuration appears in VS Code Run & Debug panel. Pressing F5 for "Debug: Agent Test" runs pytest.

---

### [ ] Task 6.4 — Create VS Code tasks.json `[P with 6.3]`

**Depends on**: Phase 3 completion
**COMMIT**: `chore: add VS Code task configurations for common operations`

**What to do**:

Create `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Install all dependencies",
      "type": "shell",
      "command": "pip install -e ./core -e ./cli -e ./desktop/backend",
      "group": "build",
      "problemMatcher": []
    },
    {
      "label": "Run core tests",
      "type": "shell",
      "command": "pytest core/tests/ -v",
      "group": "test",
      "problemMatcher": []
    },
    {
      "label": "Start FastAPI backend",
      "type": "shell",
      "command": "python desktop/backend/server.py",
      "isBackground": true,
      "problemMatcher": []
    },
    {
      "label": "Start frontend dev server",
      "type": "shell",
      "command": "npm run dev",
      "options": { "cwd": "${workspaceFolder}/desktop/frontend" },
      "isBackground": true,
      "problemMatcher": []
    },
    {
      "label": "CLI: Scan current directory",
      "type": "shell",
      "command": "agentsec scan .",
      "problemMatcher": []
    }
  ]
}
```

**Verification**: Tasks appear in VS Code command palette under "Tasks: Run Task".

---

### [ ] Task 6.5 — Create VS Code extensions.json `[P with 6.3]`

**Depends on**: nothing
**COMMIT**: `chore: add recommended VS Code extensions`

**What to do**:

Create `.vscode/extensions.json`:

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.debugpy",
    "charliermarsh.ruff",
    "ms-azuretools.vscode-azure-github-copilot",
    "dbaeumer.vscode-eslint",
    "bradlc.vscode-tailwindcss"
  ]
}
```

**Verification**: File loads in VS Code with extension recommendations.

---

## Phase 6 Dependency Graph

```
Phase 5 done ──┬──► Task 6.1 (root README)     [PARALLEL]
               ├──► Task 6.2 (package READMEs)  [PARALLEL]
               ├──► Task 6.3 (launch.json)      [PARALLEL]
               ├──► Task 6.4 (tasks.json)       [PARALLEL]
               └──► Task 6.5 (extensions.json)  [PARALLEL]
```

All Phase 6 tasks can run in parallel since they are all independent documentation/config files.

---

## Master Dependency Graph (All Phases)

```
PHASE 1 — Core Agent Foundation
═══════════════════════════════════════════════════════════════

  1.1 (root files) ───────────┐
          [PARALLEL]          │
                              ├──► 1.3 (venv) ──► 1.4 (list_files) ──┬──► 1.5 (analyze) ─┐
  1.2 (core scaffold) ───────┘                                        │      [PARALLEL]    │
          [PARALLEL]                                                  └──► 1.6 (report) ──┤
                                                                            [PARALLEL]    │
                                                                                          ▼
                                                              1.7 (agent) ──► 1.7b (config) ──► 1.8 (tests)

PHASE 2 — CLI Interface                                PHASE 3 — GUI Backend
═══════════════════════                                ═══════════════════════

  1.7b ──► 2.1 (scaffold) ──► 2.2 (main.py)           1.7b ──┬──► 3.1 (scaffold) [P] ──┐
               ──┬──► 2.3 (README) [P]                        └──► 3.2 (health)   [P] ──┤
               └──► 2.4 (e2e)      [S]                                                   ▼
                                                                      3.3 (scan API) ──► 3.4 (shutdown)

PHASE 4 — GUI Frontend
═══════════════════════

                       ┌──► 4.2 (FolderSelector) [P] ──┐
  4.1 (Next.js init) ──├──► 4.3 (ScanProgress)   [S] ──┤
       [P w/ Phase 3]  └──► 4.4 (ResultsPanel)   [P] ──┤
                                                         ▼
                              3.3 ─────────────────► 4.5 (wire up) ──► 4.6 (e2e)

PHASE 5 — Desktop (Electron)
═════════════════════════════

  4.5 ──► 5.1 (Electron init) ──┬──► 5.2 (main.js)     [P] ──┬──► 5.5 (folder IPC) ──► 5.6 (e2e)
                                 └──► 5.3 (preload.js)  [P] ──┤
                                      5.4 (builder cfg)  [S] ──┘

PHASE 6 — Docs & Tooling
═════════════════════════

  Phase 5 ──┬──► 6.1 (root README)      [P]
            ├──► 6.2 (package READMEs)   [P]
            ├──► 6.3 (launch.json)       [P]
            ├──► 6.4 (tasks.json)        [P]
            └──► 6.5 (extensions.json)   [P]
```

---

## Critical Path (Longest Sequential Chain)

The **critical path** — the longest chain of sequential dependencies that determines the minimum project duration — is:

```
1.2 → 1.3 → 1.4 → 1.5 → 1.7 → 1.7b → 1.8 → 3.1/3.2 → 3.3 → 4.5 → 4.6 → 5.1 → 5.2 → 5.5 → 5.6 → 6.1
```

**Total tasks on critical path**: ~16 commits

**Parallelizable tasks** (can be done alongside the critical path):
- 1.1, 1.6, 2.1–2.4, 4.1–4.4, 5.3, 5.4, 6.2–6.5

---

## Summary Table

| Phase | Task | Description | Depends on | Parallel? | Status |
|-------|------|-------------|-----------|-----------|--------|
| 1 | 1.1 | Root files (.gitignore, .env.example) | — | P with 1.2 | ✅ |
| 1 | 1.2 | Core package scaffolding | — | P with 1.1 | ✅ |
| 1 | 1.3 | Virtual environment setup | 1.2 | Sequential | ✅ |
| 1 | 1.4 | `list_files` skill | 1.3 | Sequential | ✅ |
| 1 | 1.5 | `analyze_file` skill | 1.4 | P with 1.6 | ✅ |
| 1 | 1.6 | `generate_report` skill | 1.4 | P with 1.5 | ✅ |
| 1 | 1.7 | `SecurityScannerAgent` class + stall detection + nudge system | 1.5, 1.6 | Sequential | ✅ |
| 1 | 1.7b | `AgentSecConfig` + directive system message + safety guardrails | 1.7 | Sequential | ✅ |
| 1 | 1.8 | Unit tests for skills | 1.7b | Sequential | |
| 2 | 2.1 | CLI package scaffolding | 1.7b | Sequential | ✅ |
| 2 | 2.2 | CLI main.py with config support | 2.1 | Sequential | ✅ |
| 2 | 2.2b | Dynamic skill discovery | 2.2 | Sequential | ✅ |
| 2 | 2.3 | CLI README | 2.2 | P with 2.4 | ✅ |
| 2 | 2.4 | CLI end-to-end verification | 2.2 | Sequential | |
| 3 | 3.1 | Backend package scaffolding | 1.7b | P with 3.2 | |
| 3 | 3.2 | FastAPI server + health endpoint | 1.7b | P with 3.1 | |
| 3 | 3.3 | `/api/scan` + SSE streaming | 3.1, 3.2 | Sequential | |
| 3 | 3.4 | Graceful shutdown handler | 3.3 | Sequential | |
| 4 | 4.1 | Next.js project initialization | — | P with Phase 3 | |
| 4 | 4.2 | `FolderSelector` component | — | P with 4.1 | |
| 4 | 4.3 | `ScanProgress` component | 4.1 | Sequential | |
| 4 | 4.4 | `ResultsPanel` component | 4.1 | P with 4.3 | |
| 4 | 4.5 | Wire up main page | 4.2–4.4 | Sequential | |
| 4 | 4.6 | Frontend E2E verification | 4.5, 3.3 | Sequential | |
| 5 | 5.1 | Electron project init | 4.5 | Sequential | |
| 5 | 5.2 | Electron main.js | 5.1 | P with 5.3 | |
| 5 | 5.3 | Preload script | 5.1 | P with 5.2 | |
| 5 | 5.4 | electron-builder config | 5.2 | Sequential | |
| 5 | 5.5 | Native folder picker IPC | 5.2, 5.3 | Sequential | |
| 5 | 5.6 | Desktop E2E verification | 5.4, 5.5 | Sequential | |
| 6 | 6.1 | Root README | Phase 5 | P | |
| 6 | 6.2 | Package READMEs | Phase 5 | P | |
| 6 | 6.3 | VS Code launch.json | Phase 3 | P | |
| 6 | 6.4 | VS Code tasks.json | Phase 3 | P | |
| 6 | 6.5 | VS Code extensions.json | — | P | |

---

## How to Use This Plan

1. **Pick the next unblocked task** — any task whose dependencies are all done
2. **Read the full task description** — it has the exact files, code, and verification steps
3. **Implement it** — write the code following the patterns in the task
4. **Verify** — run the verification command listed in the task
5. **Commit** — use the suggested commit message
6. **Move to the next task**

When multiple tasks are marked `[P]` (parallel), you can work on them in any order or simultaneously if you have multiple contributors.

---

## Appendix A — Coding Conventions Quick Reference

| Rule | Details |
|------|---------|
| **Python async** | All functions MUST use `async def` |
| **Type hints** | Required on all function signatures |
| **Docstrings** | Every function gets Args/Returns/Example |
| **Variable names** | Descriptive: `folder_path` not `fp` |
| **Error handling** | Explicit try/except per error type |
| **Resource cleanup** | Always use `try/finally` for SDK clients |
| **Skills** | `@tool(description="...")` decorator |
| **Session IDs** | Include context: `f"scan-{folder}-{timestamp}"` |
| **Long ops** | Use event-driven, not `send_and_wait` |
| **Imports** | Standard lib → third-party → local (blank line between groups) |
| **Comments** | Explain *why*, not *what* |
| **Function size** | 5-15 lines; break larger functions up |

## Appendix B — Pinned Dependency Versions

```
agent-framework-core==1.0.0b260107
agent-framework-azure-ai==1.0.0b260107
fastapi>=0.104.0
uvicorn>=0.24.0
python-dotenv>=1.0.0
pyyaml>=6.0
Python 3.12 (recommended), 3.11 (supported), 3.10+ (minimum)
Next.js 14+
Electron latest stable
```

## Appendix C — SDK Reference Patterns

| Pattern | Source |
|---------|--------|
| HTTP hosting | `python/samples/01-get-started/06_host_your_agent.py` |
| AG-UI FastAPI integration | `python/packages/ag-ui/agent_framework_ag_ui_examples/server/main.py` |
| Tool definition | `python/samples/02-agents/tools/` |
| Workflow orchestration | `python/samples/03-workflows/parallelism/` |
| Event-driven streaming | `.vscode/copilot-sdk.instructions.md` — Recipe 1 |
| Session management | `.vscode/copilot-sdk.instructions.md` — Session Operations |
