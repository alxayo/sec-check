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
import sys
from pathlib import Path
from typing import Optional

# NOTE: We do NOT import SecurityScannerAgent at the top level.
# The agent module requires the Copilot SDK, which may not be installed.
# Instead, we import it lazily inside run_scan() so that --version and
# --help still work even when the SDK is missing.

# Configure logging for the CLI
# We use INFO level so users see important messages but not debug noise
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",  # Simple format for CLI output
)
logger = logging.getLogger(__name__)


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

    try:
        # Step 5: Initialize (connect to Copilot)
        print("Starting AgentSec security scanner...")
        print()
        await agent.initialize()

        # Step 6: Run the scan
        print(f"Scanning: {folder_path}")
        print("This may take a moment...")
        print()

        result = await agent.scan(str(folder_path))

        # Step 7: Display results based on status
        if result["status"] == "success":
            print(result["result"])
            return 0

        elif result["status"] == "timeout":
            print(f"Timeout: {result['error']}", file=sys.stderr)
            return 2

        else:
            print(f"Error: {result['error']}", file=sys.stderr)
            return 1

    except FileNotFoundError:
        print(
            "Error: Copilot CLI not found.\n"
            "Install it: https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli\n"
            "Then run: copilot auth login",
            file=sys.stderr,
        )
        return 1

    except Exception as error:
        print(f"Unexpected error: {error}", file=sys.stderr)
        return 1

    finally:
        # Step 8: Always clean up resources
        await agent.cleanup()


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
        sys.exit(exit_code)
    else:
        # No command given — show help
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
