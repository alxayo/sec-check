"""
Skills (tools) for the SecurityScannerAgent.

.. deprecated::
    These skills are LEGACY code from the early MVP prototype.
    The agent now uses Copilot CLI built-in tools (bash, skill, view)
    instead of these @tool-decorated functions. None of these skills
    are registered with any SDK session — they are dead code.

    The agent's actual scanning is driven by the system message in
    config.py which instructs the LLM to use the Copilot CLI's
    built-in ``skill`` tool to invoke agentic skills (bandit, graudit,
    etc.) and ``bash`` to run scanners directly.

    These functions are kept for reference and potential future use
    if custom SDK tools are needed. To use them, register them via
    the SDK's ``define_tool`` + ``tools`` parameter in SessionConfig.

Each skill is an async function decorated with @tool.
Skills are the building blocks the agent calls to scan code.
"""

import os
import logging
from typing import List

try:
    from agent_framework import tool
except ImportError:
    # Fallback: if agent_framework is not installed (e.g., during testing),
    # provide a no-op decorator so the skill functions still work as regular
    # async functions without the @tool registration.
    def tool(description: str = ""):
        """No-op fallback for @tool when agent_framework is not installed."""
        def decorator(func):
            return func
        return decorator

# Import progress tracking to report scanning progress
from agentsec.progress import get_global_tracker

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
        # Check that the folder exists before scanning
        if not os.path.isdir(folder_path):
            error_message = f"Folder not found: {folder_path}"
            logger.error(error_message)
            return {
                "files": [],
                "total": 0,
                "folder": folder_path,
                "error": error_message,
            }

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

        # Report the total files discovered to the progress tracker
        tracker = get_global_tracker()
        if tracker:
            tracker.set_total_files(len(files_found))

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
    # Report that we're starting to scan this file
    tracker = get_global_tracker()
    if tracker:
        tracker.start_file(file_path)

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

        # Report that we finished scanning this file
        if tracker:
            tracker.finish_file(file_path, issues_found=len(issues))

        return {
            "file": file_path,
            "issues": issues,
            "severity": overall_severity,
            "lines_scanned": len(lines),
        }

    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        # Report error but still mark file as processed
        if tracker:
            tracker.finish_file(file_path, issues_found=1)
        return {
            "file": file_path,
            "issues": [{"type": "error", "message": f"File not found: {file_path}", "severity": "HIGH", "line": 0}],
            "severity": "error",
            "lines_scanned": 0,
        }
    except Exception as error:
        logger.error(f"Error analyzing {file_path}: {error}")
        # Report error but still mark file as processed
        if tracker:
            tracker.finish_file(file_path, issues_found=1)
        return {
            "file": file_path,
            "issues": [{"type": "error", "message": str(error), "severity": "HIGH", "line": 0}],
            "severity": "error",
            "lines_scanned": 0,
        }


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
