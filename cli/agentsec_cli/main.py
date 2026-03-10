"""
AgentSec CLI — command-line interface for security scanning.

This module provides the entry point for the `agentsec` command.
It uses argparse to parse commands and calls the SecurityScannerAgent
from the core package.

Usage:
    agentsec scan ./my_project
    agentsec scan ./my_project --config ./agentsec.yaml
    agentsec scan ./my_project --system-message-file ./custom-prompt.txt
    agentsec --version
    agentsec --help
"""

import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

# NOTE: We do NOT import SecurityScannerAgent at the top level.
# The agent module requires the Copilot SDK, which may not be installed.
# Instead, we import it lazily inside run_scan() so that --version and
# --help still work even when the SDK is missing.

# Default logging is configured in main() based on --verbose flag.
# We just create the logger here.
logger = logging.getLogger(__name__)


def configure_logging(verbose: bool = False) -> None:
    """
    Configure logging for the CLI.

    In normal mode, only INFO messages are shown with a simple format.
    In verbose mode, DEBUG messages are shown with timestamps and module names,
    which is essential for troubleshooting SDK and event issues.

    Args:
        verbose: If True, enable DEBUG logging with detailed format
    """
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)-5s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        # Also enable debug for the copilot SDK and agent_framework
        logging.getLogger("copilot").setLevel(logging.DEBUG)
        logging.getLogger("agent_framework").setLevel(logging.DEBUG)
        logging.getLogger("agentsec").setLevel(logging.DEBUG)
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
        )


def create_progress_display():
    """
    Create a progress display callback for the CLI.

    This function returns a callback that prints progress updates
    to the terminal in a visually appealing way. It uses ANSI escape
    codes when available to show a dynamic progress bar.

    Returns:
        A callback function that accepts ProgressEvent objects
    """
    # Track state for the progress display
    last_update_time = [0.0]  # Use list to allow mutation in closure
    spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    spinner_index = [0]

    def display_progress(event):
        """
        Display a progress event in the terminal.

        This callback is called by the ProgressTracker whenever
        something happens during the scan. It formats the event
        and prints it to the terminal.

        Args:
            event: A ProgressEvent object from the tracker
        """
        from agentsec.progress import ProgressEventType

        # Get a spinner character for visual feedback
        spinner = spinner_chars[spinner_index[0] % len(spinner_chars)]
        spinner_index[0] += 1

        # Format elapsed time
        elapsed = event.elapsed_seconds
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

        # Handle different event types
        if event.type == ProgressEventType.SCAN_STARTED:
            print(f"\n{spinner} {event.message}")
            print()

        elif event.type == ProgressEventType.FILES_DISCOVERED:
            print(f"  📁 {event.message}")
            print()

        elif event.type == ProgressEventType.FILE_STARTED:
            # Print the current file being scanned
            # Use carriage return to overwrite the line for a cleaner look
            if event.total_files > 0:
                percent = (event.files_scanned / event.total_files) * 100
                progress_bar = create_progress_bar(percent)
                line = f"  {spinner} {progress_bar} {event.message}"
            else:
                line = f"  {spinner} {event.message}"

            # Print with carriage return to allow overwriting
            print(f"\r{line}", end="", flush=True)

        elif event.type == ProgressEventType.FILE_FINISHED:
            # Clear the line and print the finished file status
            # Only print if there were issues found
            if event.issues_found > event.files_scanned - 1:
                # New issues found in this file
                clear_line = "\r" + " " * 80 + "\r"
                if "issues found" in event.message and "no issues" not in event.message:
                    print(f"{clear_line}  ⚠️  {event.message}")

        elif event.type == ProgressEventType.HEARTBEAT:
            # Print heartbeat to show the scan is still running
            # (omit progress bar as it's often misleading during parallel scans)
            if event.total_files > 0:
                line = f"  {spinner} {event.files_scanned}/{event.total_files} files ({time_str})"
            else:
                line = f"  {spinner} {event.files_scanned} files scanned ({time_str})"

            print(f"\r{line}", end="", flush=True)

        elif event.type == ProgressEventType.SCAN_FINISHED:
            # Clear any partial line and print final summary
            print(f"\r" + " " * 80)  # Clear line
            print(f"✅ {event.message}")
            print()

        elif event.type == ProgressEventType.WARNING:
            print(f"\n  ⚠️  Warning: {event.message}")

        elif event.type == ProgressEventType.ERROR:
            print(f"\n  ❌ Error: {event.message}")

        # ── Parallel orchestration events ────────────────────────
        elif event.type == ProgressEventType.PARALLEL_PLAN_READY:
            print(f"  📋 {event.message}")
            print()

        elif event.type == ProgressEventType.SUB_AGENT_STARTED:
            print(f"  🔍 {event.message}")

        elif event.type == ProgressEventType.SUB_AGENT_FINISHED:
            # Choose icon based on outcome
            if "clean" in event.message or "0 findings" in event.message:
                icon = "✅"
            elif "error" in event.message or "timeout" in event.message:
                icon = "❌"
            else:
                icon = "⚠️"
            print(f"  {icon} {event.message}")

        elif event.type == ProgressEventType.SYNTHESIS_STARTED:
            print(f"\n  📝 {event.message}")

        elif event.type == ProgressEventType.SYNTHESIS_FINISHED:
            print(f"  📊 {event.message}")
            print()

        elif event.type == ProgressEventType.LLM_ANALYSIS_STARTED:
            print(f"\n  🧠 {event.message}")

        elif event.type == ProgressEventType.LLM_ANALYSIS_FINISHED:
            # Choose icon based on outcome
            if "clean" in event.message:
                icon = "✅"
            elif "error" in event.message or "timeout" in event.message:
                icon = "❌"
            else:
                icon = "🧠"
            print(f"  {icon} {event.message}")

    return display_progress


def create_progress_bar(percent: float, width: int = 20) -> str:
    """
    Create a text-based progress bar.

    This function generates a visual progress bar using Unicode
    block characters. The bar fills from left to right based on
    the completion percentage.

    Args:
        percent: Completion percentage (0-100)
        width: Width of the progress bar in characters (default 20)

    Returns:
        A string like "[████████░░░░░░░░░░░░] 40%"

    Example:
        >>> print(create_progress_bar(50))
        [██████████░░░░░░░░░░] 50%
    """
    # Calculate how many filled blocks we need
    filled = int(width * percent / 100)
    empty = width - filled

    # Use block characters for the bar
    filled_char = "█"
    empty_char = "░"

    # Build the progress bar string
    bar = filled_char * filled + empty_char * empty

    return f"[{bar}] {percent:3.0f}%"


def create_stuck_tool_handler():
    """
    Create an interactive handler for stuck tool situations.

    Returns an async callback that is invoked when a tool in a sub-agent
    (or the main agent session) appears stuck. The callback prints
    information about the stuck tool and prompts the user to decide
    whether to continue waiting or terminate the sub-agent.

    The callback uses asyncio.run_in_executor to read user input without
    blocking the event loop, so other sub-agents can continue running
    while the user makes a decision.

    Returns:
        An async callback function compatible with OnToolStuckCallback.
        Receives a StuckToolInfo, returns a StuckToolAction.
    """
    # Import StuckToolAction here to avoid import at module level
    from agentsec.tool_health import StuckToolAction, StuckToolInfo

    async def handle_stuck_tool(info: StuckToolInfo) -> StuckToolAction:
        """
        Interactive CLI prompt for stuck tool decisions.

        Shows the user what tool is stuck, how long it has been running,
        and in which sub-agent. Then asks the user to choose between
        waiting longer or terminating the sub-agent.

        Args:
            info: A StuckToolInfo with details about the stuck tool.

        Returns:
            StuckToolAction.WAIT or StuckToolAction.TERMINATE based
            on user's choice. Defaults to WAIT on invalid input.
        """
        minutes = int(info.elapsed_seconds // 60)
        seconds = int(info.elapsed_seconds % 60)

        # Print a clear, informative prompt
        print()
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║  ⚠️  Tool appears stuck                                 ║")
        print("  ╠══════════════════════════════════════════════════════════╣")
        print(f"  ║  Sub-agent: {info.agent_label:<44}║")
        print(f"  ║  Tool:      {info.tool_name:<44}║")

        if info.detail:
            # Truncate long detail for display
            detail_display = info.detail
            if len(detail_display) > 44:
                detail_display = detail_display[:41] + "..."
            print(f"  ║  Detail:    {detail_display:<44}║")

        print(f"  ║  Running:   {minutes}m {seconds}s{'':<38}║")

        if info.has_prior_errors:
            print("  ║  ⚠ This tool has had errors before      "
                  "               ║")

        print("  ╠══════════════════════════════════════════════════════════╣")
        print("  ║  [W] Wait longer   |   [T] Terminate this sub-agent    ║")
        print("  ╚══════════════════════════════════════════════════════════╝")

        # Read user input without blocking the event loop.
        # We use run_in_executor so other async tasks (like other
        # sub-agents) keep running while we wait for the user.
        def _read_input() -> str:
            """Blocking input read, run in executor."""
            try:
                return input("  Choice [W/t]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                # Non-interactive or user pressed Ctrl+C
                return "w"

        loop = asyncio.get_event_loop()
        choice = await loop.run_in_executor(None, _read_input)

        if choice in ("t", "terminate"):
            print("  → Terminating sub-agent...")
            print()
            return StuckToolAction.TERMINATE
        else:
            print("  → Continuing to wait...")
            print()
            return StuckToolAction.WAIT

    return handle_stuck_tool


def print_available_skills(folder_path: Optional[str] = None) -> None:
    """
    Print the available scanning skills and external tools.

    This function dynamically discovers Copilot CLI agentic skills by
    scanning the two directories where the Copilot CLI looks for them:
      1. User-level:    ~/.copilot/skills/
      2. Project-level: <project>/.copilot/skills/

    Each skill directory contains a SKILL.md file with YAML frontmatter
    (name, description). The function maps each skill to its underlying
    CLI tool and checks whether that tool is installed on the system.

    Args:
        folder_path: Path to the project root. Used to find project-level
                     skills in <folder_path>/.copilot/skills/.
                     If None, only user-level skills are checked.
    """
    # Import the dynamic skill discovery module from core
    from agentsec.skill_discovery import discover_all_skills, get_skill_summary

    print("\n📋 Available scanning tools:")
    print("  Copilot CLI built-in tools:")
    print("    • bash             — Run file discovery and scanner commands")
    print("    • skill            — Invoke agentic security scanning skills")
    print("    • view             — Read files for manual code inspection")

    # Dynamically discover Copilot CLI agentic skills
    # The Copilot CLI looks in ~/.copilot/skills/ (user) and
    # <project>/.copilot/skills/ (project) for skill definitions
    skills = discover_all_skills(project_root=folder_path)
    summary = get_skill_summary(skills)

    if summary["total"] == 0:
        print("  Copilot CLI agentic skills:")
        print("    (none found — add skills to ~/.copilot/skills/)")
        print()
        return

    print(
        f"  Copilot CLI agentic skills "
        f"({summary['available']}/{summary['total']} tools available):"
    )

    # Show where skills were discovered from
    if summary["user_count"] > 0:
        print(f"    📂 ~/.copilot/skills/ ({summary['user_count']} skills)")
    if summary["project_count"] > 0:
        print(f"    📂 .copilot/skills/   ({summary['project_count']} skills)")

    # Print each discovered skill with availability status
    for skill in skills:
        tool_name = skill["tool_name"]
        description = skill["description"]

        if skill["tool_available"]:
            print(f"    ✅ {tool_name:<20} — {description}")
        else:
            print(f"    ⬜ {tool_name:<20} — {description} (not installed)")

    print()


def save_report(
    report_content: str,
    folder_path: Path,
    log_dir: Optional[str] = None,
) -> Optional[str]:
    """
    Save the scan report to a Markdown file.

    When a log_dir is provided the report is saved inside the same
    timestamped run directory that contains the per-session logs,
    keeping all artefacts for a single scan together.  If no log_dir
    is given, the report is saved in the current working directory
    (backward-compatible fallback).

    The filename is always "agentsec-report.md" when saving into the
    run log directory (the directory itself is already timestamped).
    When saving to cwd, a timestamped filename is used instead so
    multiple runs don't overwrite each other.

    Args:
        report_content: The full text of the scan report from the agent
        folder_path: The folder that was scanned (included in the header)
        log_dir: Optional path to the run log directory.  When provided
                 the report is written there as "agentsec-report.md".

    Returns:
        The absolute path to the saved report file, or None if saving failed
    """
    import datetime

    if log_dir:
        # Save inside the run log directory alongside session logs
        report_filename = "agentsec-report.md"
        report_path = Path(log_dir) / report_filename
    else:
        # Fallback: save in cwd with a timestamped name
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        report_filename = f"agentsec-report-{timestamp}.md"
        report_path = Path.cwd() / report_filename

    try:
        with open(report_path, "w", encoding="utf-8") as report_file:
            # Write a header with metadata
            report_file.write("# AgentSec Security Report\n\n")
            report_file.write(f"**Scanned folder:** `{folder_path}`\n")
            report_file.write(
                f"**Date:** "
                f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )
            report_file.write("---\n\n")
            # Write the actual report content from the agent
            report_file.write(report_content)
            report_file.write("\n")

        return str(report_path)

    except Exception as error:
        logger.warning(f"Could not save report to file: {error}")
        return None


def _parse_result_counts(result_text: str) -> dict:
    """
    Try to parse file and issue counts from the agent's response.

    The agent's response typically includes phrases like "5 security issues"
    and file names in bold like **vulnerable_app.py**. This function uses
    simple regex patterns to extract those numbers so the progress tracker's
    final summary line shows accurate counts.

    Args:
        result_text: The text content of the agent's scan result

    Returns:
        A dictionary with optional keys "files" and "issues".
        Empty dict if no counts could be parsed.
    """
    import re

    counts = {}

    # Try to find issue count: "5 security issues", "3 issues", "5 findings"
    issue_match = re.search(
        r'\*?\*?(\d+)\*?\*?\s+(?:security\s+)?(?:issues?|findings?|vulnerabilit)',
        result_text,
        re.IGNORECASE,
    )
    if issue_match:
        counts["issues"] = int(issue_match.group(1))

    # Try to find scanned file names by looking for bold file names
    # like **vulnerable_app.py** and **utils.py** in the response
    file_mentions = re.findall(
        r'\*\*(\w+\.(?:py|js|ts|jsx|tsx|java|go|rb|rs|c|cpp|h))\*\*',
        result_text,
    )
    if file_mentions:
        # Count unique file names mentioned in bold
        counts["files"] = len(set(file_mentions))

    return counts


def _truncate_text(text: str, max_length: int = 120) -> str:
    """
    Truncate text to a maximum length for display.

    Replaces newlines with visible markers so multi-line text is
    readable on a single display line. Adds an ellipsis if truncated.

    Args:
        text: The text to truncate.
        max_length: Maximum character length for the preview.

    Returns:
        A single-line, possibly truncated, preview of the text.
    """
    # Replace newlines with a visible marker so the preview is one line
    preview = text.strip().replace("\n", " ↵ ")

    # Collapse multiple whitespace runs into a single space
    preview = " ".join(preview.split())

    if len(preview) > max_length:
        return preview[:max_length] + "..."
    return preview


def print_config_summary(config, folder_path) -> None:
    """
    Print a summary showing which system message and prompt are being
    used, where they came from, and a short preview of each.

    This gives the user full visibility into the effective configuration
    before the scan starts so they can verify the right prompts are
    being used.

    Args:
        config: An AgentSecConfig instance (with source tracking fields).
        folder_path: The resolved folder path (used to format the prompt preview).

    Example output:
        ┌─────────────────────────────────────────────────┐
        │ Configuration                                   │
        ├─────────────────────────────────────────────────┤
        │ System message                                  │
        │   Source : built-in default                     │
        │   Preview: You are AgentSec, an AI-powered ...  │
        │ Initial prompt                                  │
        │   Source : config file: ./agentsec.yaml         │
        │   Preview: Scan the folder {folder_path} fo...  │
        └─────────────────────────────────────────────────┘
    """
    # Format the prompt preview with the actual folder path so the user
    # can see exactly what will be sent to the LLM
    try:
        formatted_prompt = config.format_prompt(str(folder_path))
    except (KeyError, IndexError):
        formatted_prompt = config.initial_prompt

    # Build readable previews of each value
    sm_preview = _truncate_text(config.system_message)
    ip_preview = _truncate_text(formatted_prompt)

    print()
    print("┌─ Configuration ─────────────────────────────────────────────┐")
    print(f"│  System message")
    print(f"│    Source : {config.system_message_source}")
    print(f"│    Preview: {sm_preview}")
    print(f"│  Initial prompt")
    print(f"│    Source : {config.initial_prompt_source}")
    print(f"│    Preview: {ip_preview}")
    print("└─────────────────────────────────────────────────────────────┘")
    print()


async def run_scan(
    folder: str,
    config_path: Optional[str] = None,
    system_message: Optional[str] = None,
    system_message_file: Optional[str] = None,
    prompt: Optional[str] = None,
    prompt_file: Optional[str] = None,
    parallel: bool = False,
    max_concurrent: int = 3,
    timeout: Optional[int] = None,
    model: Optional[str] = None,
    model_scanners: Optional[str] = None,
    model_analysis: Optional[str] = None,
    model_synthesis: Optional[str] = None,
    no_llm_analysis: bool = False,
    scanners: Optional[list] = None,
    files: Optional[list] = None,
) -> int:
    """
    Execute a security scan on the given folder.

    This function:
    1. Validates that the folder exists
    2. Loads configuration (from file and/or CLI overrides)
    3. Creates and initializes the SecurityScannerAgent
    4. Runs the scan
    5. Prints results to stdout
    6. Cleans up the agent resources

    Args:
        folder: Path to the folder to scan (absolute or relative)
        config_path: Path to a config file (agentsec.yaml)
        system_message: Override system message text
        system_message_file: Path to file containing system message
        prompt: Override initial prompt text
        prompt_file: Path to file containing initial prompt
        parallel: If True, use parallel sub-agent scanning mode
        max_concurrent: Maximum concurrent sub-agents (only for parallel mode)
        timeout: Overall scan timeout in seconds (None uses agent default)

    Returns:
        Exit code: 0 for success, 1 for error, 2 for timeout
    """
    # Step 1: Validate the folder path
    folder_path = Path(folder).resolve()

    if not folder_path.exists():
        print(f"Error: Folder not found: {folder_path}", file=sys.stderr)
        return 1

    if not folder_path.is_dir():
        print(f"Error: Not a directory: {folder_path}", file=sys.stderr)
        return 1

    # Step 2: Import the agent and config (lazy import to avoid crashing
    # when the Copilot SDK is not installed)
    try:
        from agentsec.agent import SecurityScannerAgent
        from agentsec.config import AgentSecConfig
        from agentsec.progress import ProgressTracker, set_global_tracker
    except ImportError as import_error:
        print(
            f"Error: Could not import SecurityScannerAgent: {import_error}\n"
            "Make sure the Copilot SDK is installed:\n"
            "  pip install copilot-sdk",
            file=sys.stderr,
        )
        return 1

    # Step 3: Load configuration
    try:
        # First, load from config file (or defaults)
        config = AgentSecConfig.load(config_path)
        
        # Then, apply CLI overrides (CLI takes priority over config file)
        config = config.with_overrides(
            system_message=system_message,
            system_message_file=system_message_file,
            initial_prompt=prompt,
            initial_prompt_file=prompt_file,
            model=model,
            model_scanners=model_scanners,
            model_analysis=model_analysis,
            model_synthesis=model_synthesis,
            enable_llm_analysis=False if no_llm_analysis else None,
            scanners=scanners,
        )
    except FileNotFoundError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 1

    # Step 4: Display configuration provenance
    # This tells the user exactly where the system message and prompt
    # came from — built-in defaults, a config file, or CLI flags.
    print_config_summary(config, folder_path)

    # Step 5: Create the agent with the loaded configuration
    agent = SecurityScannerAgent(config=config)

    # Step 6: Set up progress tracking for real-time feedback
    progress_callback = create_progress_display()
    progress_tracker = ProgressTracker(
        callback=progress_callback,
        heartbeat_interval=3.0,  # Show heartbeat every 3 seconds
    )
    set_global_tracker(progress_tracker)

    # Step 7: Set up the stuck-tool handler for interactive decision-making
    # When a tool in a sub-agent (or the main session) appears stuck,
    # this callback prompts the user to wait or terminate.
    stuck_tool_handler = create_stuck_tool_handler()

    # Step 7b: Create a timestamped log directory for this run.
    # Each session (main-scan, sub-agents, synthesis) gets its own
    # log file inside this directory.
    from agentsec.session_logger import create_run_log_dir
    log_base_dir = os.path.join(os.getcwd(), "agentsec-logs")
    run_log_dir = create_run_log_dir(log_base_dir)
    print(f"📝 Session logs: {run_log_dir}")

    try:
        # Step 8: Initialize (connect to Copilot)
        print("Starting AgentSec security scanner...")
        await agent.initialize()

        # Step 8b: Show available scanning skills and external tools
        # Pass the folder path so project-level skills can also be found
        print_available_skills(folder_path=str(folder_path))

        # Step 9: Run the scan with progress tracking
        progress_tracker.start_scan(str(folder_path))

        if parallel:
            # Parallel mode: use sub-agent orchestration
            print(f"🔀 Parallel mode: up to {max_concurrent} concurrent scanners")
            result = await agent.scan_parallel(
                str(folder_path),
                timeout=float(timeout) if timeout else None,
                max_concurrent=max_concurrent,
                on_tool_stuck=stuck_tool_handler,
                log_dir=run_log_dir,
                files=files,
            )
        else:
            # Serial mode: single LLM session (original behaviour)
            result = await agent.scan(
                str(folder_path),
                timeout=float(timeout) if timeout else None,
                on_tool_stuck=stuck_tool_handler,
                log_dir=run_log_dir,
                files=files,
            )

        # Step 9b: Update progress tracker with issue count from
        # the agent's response (but keep the file count from the tracker
        # since it accurately reflects what was actually scanned)
        if result["status"] == "success" and result.get("result"):
            actual_counts = _parse_result_counts(result["result"])
            if actual_counts:
                # Update both file and issue counts from the agent's
                # response.  _parse_result_counts returns None for any
                # key it could not extract, and update_counts skips
                # None values, so this is safe for partial matches.
                progress_tracker.update_counts(
                    files_scanned=actual_counts.get("files"),
                    issues_found=actual_counts.get("issues"),
                )

        progress_tracker.finish_scan()

        # Step 10: Display results based on status
        if result["status"] == "success":
            print(result["result"])

            # Save the report inside the run log directory
            report_path = save_report(
                result["result"], folder_path, log_dir=run_log_dir,
            )
            if report_path:
                print(f"📄 Report saved to: {report_path}")

            return 0

        elif result["status"] == "timeout":
            # Check if we got partial results despite the timeout
            if result.get("result"):
                print("⚠️  Scan timed out, but partial results are available:\n")
                print(result["result"])

                # Save partial results too — they may still be useful
                report_path = save_report(
                    result["result"], folder_path, log_dir=run_log_dir,
                )
                if report_path:
                    print(f"📄 Partial report saved to: {report_path}")
            else:
                print(f"Timeout: {result['error']}", file=sys.stderr)
            return 2

        else:
            print(f"Error: {result['error']}", file=sys.stderr)
            return 1

    except FileNotFoundError:
        progress_tracker.finish_scan()
        print(
            "Error: Copilot CLI not found.\n"
            "Install it: https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli\n"
            "Then run: copilot auth login",
            file=sys.stderr,
        )
        return 1

    except Exception as error:
        progress_tracker.finish_scan()
        print(f"Unexpected error: {error}", file=sys.stderr)
        return 1

    finally:
        # Step 11: Always clean up resources
        set_global_tracker(None)  # Clear the global tracker
        await agent.cleanup()
        
        # Give a small delay to allow any background threads to finish
        await asyncio.sleep(0.5)


def main() -> None:
    """
    Main entry point for the agentsec CLI command.

    This function:
    1. Sets up the argument parser with commands
    2. Parses the user's input
    3. Routes to the appropriate command handler
    4. Sets the process exit code

    Commands:
        scan <folder>   Scan a folder for security issues
        --version       Show the version number
        --help          Show help message
    
    Configuration options (for scan command):
        --config                Path to config file (agentsec.yaml)
        --system-message        Override system message text
        --system-message-file   Path to file containing system message
        --prompt                Override initial prompt text
        --prompt-file           Path to file containing initial prompt
    """
    # Create the top-level parser
    parser = argparse.ArgumentParser(
        prog="agentsec",
        description="AgentSec — AI-powered security scanner for code",
        epilog=(
            "Examples:\n"
            "  agentsec scan ./my_project     Scan a project folder\n"
            "  agentsec scan .                Scan current directory\n"
            "  agentsec scan ./src --config ./agentsec.yaml\n"
            "  agentsec scan ./src --system-message-file ./custom-system.txt\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Add --version to the top-level parser
    parser.add_argument(
        "--version",
        action="version",
        version="agentsec 0.1.0",
    )

    # Create subcommands
    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available commands",
    )

    # Add the 'scan' subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a folder for security vulnerabilities",
        description="Scan all files in a folder for security issues",
    )
    scan_parser.add_argument(
        "folder",
        help="Path to the folder to scan (e.g., ./src or C:\\code\\myapp)",
    )
    
    # Verbose / debug logging option
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help=(
            "Enable verbose/debug logging. Shows all SDK events, "
            "tool calls, and internal state for troubleshooting."
        ),
    )

    # Parallel scanning mode
    scan_parser.add_argument(
        "--parallel",
        action="store_true",
        default=False,
        help=(
            "Run security scanners in parallel using sub-agent sessions. "
            "Each available scanner gets its own session that runs "
            "concurrently.  Results are synthesised into one report."
        ),
    )
    scan_parser.add_argument(
        "--max-concurrent",
        type=int,
        default=3,
        metavar="N",
        help=(
            "Maximum number of scanner sub-agents running at the same "
            "time (only used with --parallel).  Default is 3."
        ),
    )

    # Scanner selection (whitelist / blacklist)
    scanner_group = scan_parser.add_mutually_exclusive_group()
    scanner_group.add_argument(
        "--scanners",
        dest="scanners",
        metavar="LIST",
        help=(
            "Comma-separated list of scanner names to use "
            "(e.g. bandit-security-scan,trivy-security-scan). "
            "Only these scanners will run.  Use --list-scanners to "
            "see all available names."
        ),
    )
    scanner_group.add_argument(
        "--skip-scanners",
        dest="skip_scanners",
        metavar="LIST",
        help=(
            "Comma-separated list of scanner names to EXCLUDE "
            "(e.g. graudit-security-scan). All other relevant "
            "scanners will still run."
        ),
    )
    scan_parser.add_argument(
        "--list-scanners",
        action="store_true",
        default=False,
        help="Print all known scanner names and exit.",
    )
    scan_parser.add_argument(
        "--no-llm-analysis",
        action="store_true",
        default=False,
        help=(
            "Disable the LLM deep analysis phase that runs after "
            "deterministic scanners in parallel mode.  Use this for "
            "faster scans when semantic threat review is not needed."
        ),
    )
    scan_parser.add_argument(
        "--files",
        dest="files",
        metavar="LIST",
        help=(
            "Comma-separated list of specific file paths to scan "
            "instead of the entire folder.  The folder argument is "
            "still required as the project root for context.  "
            "Example: --files src/app.py,src/utils.py"
        ),
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        metavar="SECONDS",
        help=(
            "Safety ceiling timeout in seconds.  The scan uses "
            "activity-based detection and normally finishes well "
            "before this limit.  Default is 1800 (30 minutes).  "
            "Only increase if scanning extremely large codebases."
        ),
    )
    
    # Configuration file option
    scan_parser.add_argument(
        "--config", "-c",
        dest="config_path",
        metavar="FILE",
        help=(
            "Path to a YAML config file (agentsec.yaml). "
            "Config file can set default system_message and initial_prompt."
        ),
    )
    
    # System message options (text or file)
    system_group = scan_parser.add_mutually_exclusive_group()
    system_group.add_argument(
        "--system-message", "-s",
        dest="system_message",
        metavar="TEXT",
        help=(
            "Override the system message (AI instructions). "
            "Takes priority over config file."
        ),
    )
    system_group.add_argument(
        "--system-message-file", "-sf",
        dest="system_message_file",
        metavar="FILE",
        help=(
            "Path to a file containing the system message. "
            "Takes priority over config file."
        ),
    )
    
    # Initial prompt options (text or file)
    prompt_group = scan_parser.add_mutually_exclusive_group()
    prompt_group.add_argument(
        "--prompt", "-p",
        dest="prompt",
        metavar="TEXT",
        help=(
            "Override the initial prompt template. "
            "Use {folder_path} as placeholder. Takes priority over config file."
        ),
    )
    prompt_group.add_argument(
        "--prompt-file", "-pf",
        dest="prompt_file",
        metavar="FILE",
        help=(
            "Path to a file containing the initial prompt template. "
            "Use {folder_path} as placeholder. Takes priority over config file."
        ),
    )

    # Model selection (F2)
    scan_parser.add_argument(
        "--model", "-m",
        dest="model",
        metavar="MODEL",
        default=None,
        help=(
            "Override the LLM model name (e.g. gpt-5, claude-sonnet-4.5). "
            "Takes priority over config file. Default is gpt-5."
        ),
    )

    # Per-phase model overrides
    scan_parser.add_argument(
        "--model-scanners",
        dest="model_scanners",
        metavar="MODEL",
        default=None,
        help=(
            "Override the LLM model for Phase 2 (parallel scanner "
            "sub-agents). When not set, uses --model."
        ),
    )
    scan_parser.add_argument(
        "--model-analysis",
        dest="model_analysis",
        metavar="MODEL",
        default=None,
        help=(
            "Override the LLM model for Phase 3 (LLM deep analysis). "
            "When not set, uses --model."
        ),
    )
    scan_parser.add_argument(
        "--model-synthesis",
        dest="model_synthesis",
        metavar="MODEL",
        default=None,
        help=(
            "Override the LLM model for Phase 4 (report synthesis). "
            "When not set, uses --model."
        ),
    )

    # Parse arguments
    args = parser.parse_args()

    # Route to the correct command
    if args.command == "scan":
        # Handle --list-scanners: print known scanners and exit
        if getattr(args, "list_scanners", False):
            try:
                from agentsec.skill_discovery import SCANNER_REGISTRY
                print("Known scanner names:")
                for name in sorted(SCANNER_REGISTRY.keys()):
                    info = SCANNER_REGISTRY[name]
                    print(f"  {name}  ({info.get('tool', 'N/A')})")
            except ImportError:
                print("Error: agentsec-core not installed", file=sys.stderr)
            sys.exit(0)

        # Parse --scanners / --skip-scanners into a list
        scanners_list = None
        if getattr(args, "scanners", None):
            scanners_list = [
                s.strip() for s in args.scanners.split(",") if s.strip()
            ]
        elif getattr(args, "skip_scanners", None):
            # For --skip-scanners we need the full registry to compute
            # the inverse set.  Import it here (lazy).
            try:
                from agentsec.skill_discovery import SCANNER_REGISTRY
                skip_set = {
                    s.strip() for s in args.skip_scanners.split(",")
                    if s.strip()
                }
                scanners_list = [
                    name for name in SCANNER_REGISTRY.keys()
                    if name not in skip_set
                ]
            except ImportError:
                pass  # Will fail later with a clearer message

        # Parse --files into a list of file paths
        files_list = None
        if getattr(args, "files", None):
            files_list = [
                f.strip() for f in args.files.split(",") if f.strip()
            ]

        # Configure logging based on --verbose flag
        configure_logging(verbose=args.verbose)

        exit_code = asyncio.run(
            run_scan(
                folder=args.folder,
                config_path=args.config_path,
                system_message=args.system_message,
                system_message_file=args.system_message_file,
                prompt=args.prompt,
                prompt_file=args.prompt_file,
                parallel=args.parallel,
                max_concurrent=args.max_concurrent,
                timeout=args.timeout,
                model=args.model,
                model_scanners=args.model_scanners,
                model_analysis=args.model_analysis,
                model_synthesis=args.model_synthesis,
                no_llm_analysis=args.no_llm_analysis,
                scanners=scanners_list,
                files=files_list,
            )
        )

        # Use sys.exit instead of os._exit so that finally blocks,
        # atexit handlers, and file flushes run properly (F17).
        # The agent.cleanup() in run_scan's finally block already
        # calls client.stop() which terminates the SDK subprocess.
        # The heartbeat thread is a daemon thread, so it will be
        # cleaned up automatically when the process exits.
        sys.exit(exit_code)
    else:
        # No command given — show help
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
