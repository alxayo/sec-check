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
            if event.total_files > 0:
                percent = (event.files_scanned / event.total_files) * 100
                progress_bar = create_progress_bar(percent)
                line = f"  {spinner} {progress_bar} {event.files_scanned}/{event.total_files} files ({time_str})"
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


def print_available_skills() -> None:
    """
    Print the available scanning skills and external tools.

    This shows the user which built-in skills the agent has registered
    and which external security tools are available on the system.
    External tools (like bandit, graudit) provide deeper analysis
    when the agent invokes them via the bash tool.
    """
    import shutil

    print("\n📋 Available scanning skills:")
    print("  Built-in skills:")
    print("    • list_files       — Discover files in target directory")
    print("    • analyze_file     — Analyze a file for security vulnerabilities")
    print("    • generate_report  — Generate a formatted vulnerability report")
    print("  External security tools (auto-detected):")

    # List of external tools the agent may use, with descriptions
    external_tools = [
        ("bandit", "Python AST security scanner (eval, exec, secrets)"),
        ("graudit", "Pattern-based multi-language scanner (secrets, exec, SQL, XSS)"),
        ("semgrep", "Semantic code analysis for security patterns"),
        ("trivy", "Container and filesystem vulnerability scanner"),
        ("shellcheck", "Shell script security analyzer"),
    ]

    for tool_name, description in external_tools:
        if shutil.which(tool_name):
            print(f"    ✅ {tool_name:<14} — {description}")
        else:
            print(f"    ⬜ {tool_name:<14} — {description} (not installed)")

    print()


def save_report(report_content: str, folder_path: Path) -> Optional[str]:
    """
    Save the scan report to a Markdown file in the current directory.

    The report is saved with a timestamped filename like:
    agentsec-report-20260213-143025.md

    Args:
        report_content: The full text of the scan report from the agent
        folder_path: The folder that was scanned (included in the header)

    Returns:
        The absolute path to the saved report file, or None if saving failed
    """
    import datetime

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


async def run_scan(
    folder: str,
    config_path: Optional[str] = None,
    system_message: Optional[str] = None,
    system_message_file: Optional[str] = None,
    prompt: Optional[str] = None,
    prompt_file: Optional[str] = None,
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
        )
    except FileNotFoundError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 1

    # Step 4: Create the agent with the loaded configuration
    agent = SecurityScannerAgent(config=config)

    # Step 5: Set up progress tracking for real-time feedback
    progress_callback = create_progress_display()
    progress_tracker = ProgressTracker(
        callback=progress_callback,
        heartbeat_interval=3.0,  # Show heartbeat every 3 seconds
    )
    set_global_tracker(progress_tracker)

    try:
        # Step 6: Initialize (connect to Copilot)
        print("Starting AgentSec security scanner...")
        await agent.initialize()

        # Step 6b: Show available scanning skills and external tools
        print_available_skills()

        # Step 7: Run the scan with progress tracking
        progress_tracker.start_scan(str(folder_path))
        result = await agent.scan(str(folder_path))

        # Step 7b: Update progress tracker with actual counts from
        # the agent's response, so the final summary line shows
        # accurate numbers instead of approximate tool-based counts
        if result["status"] == "success" and result.get("result"):
            actual_counts = _parse_result_counts(result["result"])
            if actual_counts:
                progress_tracker.update_counts(
                    files_scanned=actual_counts.get("files"),
                    issues_found=actual_counts.get("issues"),
                )

        progress_tracker.finish_scan()

        # Step 8: Display results based on status
        if result["status"] == "success":
            print(result["result"])

            # Save the report to a file and show its location
            report_path = save_report(result["result"], folder_path)
            if report_path:
                print(f"📄 Report saved to: {report_path}")

            return 0

        elif result["status"] == "timeout":
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
        # Step 9: Always clean up resources
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

    # Parse arguments
    args = parser.parse_args()

    # Route to the correct command
    if args.command == "scan":
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
            )
        )

        # Force exit the process to avoid hanging on background threads
        # from the Copilot SDK subprocess or heartbeat timer
        os._exit(exit_code)
    else:
        # No command given — show help
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
