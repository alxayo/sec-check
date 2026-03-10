"""
VS Code extension bridge for AgentSec.

This module provides a JSON Lines stdin/stdout interface that the
VS Code extension uses to communicate with the Python agent. It
reads commands from stdin, runs the SecurityScannerAgent, and
streams progress events and results back to stdout as JSON Lines.

Protocol:
    TypeScript -> Python (stdin):
        {"type": "scan", "folder": "...", "mode": "parallel", "config": {...}}
        {"type": "cancel"}
        {"type": "discover"}

    Python -> TypeScript (stdout):
        {"type": "progress", "event": "...", ...}
        {"type": "result", "status": "...", "content": "...", "error": "..."}
        {"type": "tool_status", "scanners": [...]}
        {"type": "log", "level": "...", "message": "..."}
        {"type": "ready"}

Usage:
    python -m agentsec.vscode_bridge
"""

import asyncio
import json
import logging
import sys
import threading
from typing import Optional

import datetime
import os
from pathlib import Path

from agentsec.agent import SecurityScannerAgent
from agentsec.config import AgentSecConfig
from agentsec.progress import (
    ProgressEvent,
    ProgressTracker,
    set_global_tracker,
)
from agentsec.session_logger import create_run_log_dir
from agentsec.skill_discovery import discover_all_skills


# Redirect logging to stderr so it does not interfere with the
# JSON Lines protocol on stdout.
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Lock for thread-safe writes to stdout.  The progress callback
# fires from the heartbeat thread while the main asyncio loop
# may also write results.
_stdout_lock = threading.Lock()

# Threading event used to signal scan cancellation.
_cancel_event = threading.Event()


def _write_message(msg: dict) -> None:
    """Write a single JSON line to stdout (thread-safe)."""
    with _stdout_lock:
        line = json.dumps(msg, ensure_ascii=False)
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def _progress_callback(event: ProgressEvent) -> None:
    """
    Convert a ProgressEvent into a JSON message and write to stdout.

    This callback is called by the ProgressTracker for every progress
    update, including heartbeat events from the background thread.
    """
    msg = {
        "type": "progress",
        "event": event.type.value,
        "message": event.message,
        "currentFile": event.current_file,
        "filesScanned": event.files_scanned,
        "totalFiles": event.total_files,
        "issuesFound": event.issues_found,
        "elapsedSeconds": round(event.elapsed_seconds, 1),
        "percentComplete": round(event.percent_complete, 1),
    }
    _write_message(msg)


def _log(level: str, message: str) -> None:
    """Send a log message to the extension."""
    _write_message({"type": "log", "level": level, "message": message})


def _scanner_output(scanner: str, text: str) -> None:
    """
    Send per-scanner output text to the extension.

    Each message maps to a dedicated VS Code Output Channel so the
    user can view real-time output from individual scanners/phases.

    Args:
        scanner: Channel name (e.g. "Discovery", "bandit-security-scan").
        text:    The text to append to the channel.
    """
    _write_message({
        "type": "scanner_output",
        "scanner": scanner,
        "text": text,
    })


async def _handle_discover(project_root: Optional[str] = None) -> None:
    """Handle a 'discover' command — report available scanner tools."""
    try:
        skills = discover_all_skills(project_root=project_root)
        scanners = []
        for skill in skills:
            scanners.append({
                "name": skill["name"],
                "description": skill["description"],
                "toolName": skill["tool_name"],
                "toolAvailable": skill["tool_available"],
                "toolPath": skill["tool_path"],
                "source": skill["source"],
            })
        _write_message({"type": "tool_status", "scanners": scanners})
    except Exception as err:
        _log("error", f"Tool discovery failed: {err}")
        _write_message({"type": "tool_status", "scanners": []})


async def _handle_scan(command: dict) -> None:
    """Handle a 'scan' command — run a security scan."""
    folder = command.get("folder", ".")
    mode = command.get("mode", "parallel")
    config_overrides = command.get("config", {})

    _cancel_event.clear()

    # Build configuration from overrides
    config = AgentSecConfig()
    if config_overrides.get("model"):
        config.model = config_overrides["model"]
    if config_overrides.get("systemMessage"):
        config.system_message = config_overrides["systemMessage"]

    # Per-phase model overrides
    if config_overrides.get("modelScanners"):
        config.model_scanners = config_overrides["modelScanners"]
    if config_overrides.get("modelAnalysis"):
        config.model_analysis = config_overrides["modelAnalysis"]
    if config_overrides.get("modelSynthesis"):
        config.model_synthesis = config_overrides["modelSynthesis"]

    max_concurrent = config_overrides.get("maxConcurrent", 3)
    enable_llm = config_overrides.get("enableLlmAnalysis", True)
    timeout = config_overrides.get("timeout", 1800)

    # Scanner whitelist: if the extension sends a list of scanner names,
    # only those scanners will be used during the parallel scan.
    raw_scanners = config_overrides.get("scanners")
    scanners_list = None
    if isinstance(raw_scanners, list) and raw_scanners:
        scanners_list = [str(s).strip() for s in raw_scanners if str(s).strip()]

    # File list: if the extension sends specific file paths, only
    # those files will be scanned instead of the whole folder.
    raw_files = config_overrides.get("files")
    files_list = None
    if isinstance(raw_files, list) and raw_files:
        files_list = [str(f).strip() for f in raw_files if str(f).strip()]

    # Set up progress tracking for real-time updates
    tracker = ProgressTracker(
        callback=_progress_callback,
        heartbeat_interval=3.0,
    )
    set_global_tracker(tracker)

    agent = SecurityScannerAgent(config=config)

    try:
        _log("info", f"Initializing agent for scan of {folder}")
        await agent.initialize()

        tracker.start_scan(folder)

        if mode == "parallel":
            _log("info", f"Starting parallel scan (max_concurrent={max_concurrent})")
            result = await agent.scan_parallel(
                folder_path=folder,
                timeout=timeout,
                max_concurrent=max_concurrent,
                on_output=_scanner_output,
                scanners=scanners_list,
                files=files_list,
            )
        else:
            _log("info", "Starting serial scan")
            result = await agent.scan(
                folder_path=folder,
                timeout=timeout,
                files=files_list,
            )

        tracker.finish_scan()

        # Save the report to a Markdown file so the extension can
        # open it directly in the editor.
        report_path = _save_report(
            result.get("result", ""), folder,
        )

        _write_message({
            "type": "result",
            "status": result.get("status", "error"),
            "content": result.get("result", ""),
            "error": result.get("error", ""),
            "reportPath": report_path or "",
        })

    except Exception as err:
        logger.error(f"Scan failed: {err}", exc_info=True)
        tracker.finish_scan()
        _write_message({
            "type": "result",
            "status": "error",
            "content": "",
            "error": str(err),
            "reportPath": "",
        })
    finally:
        set_global_tracker(None)
        await agent.cleanup()


def _save_report(content: str, folder: str) -> Optional[str]:
    """
    Save the scan report to an agentsec-logs directory.

    Creates a timestamped subdirectory under the workspace's
    agentsec-logs/ folder and writes agentsec-report.md there.

    Args:
        content: The full Markdown report text.
        folder:  The folder that was scanned (used in the header).

    Returns:
        Absolute path to the saved file, or None on failure.
    """
    if not content:
        return None

    try:
        # Use workspace root (cwd) for the log base directory
        log_base_dir = os.path.join(os.getcwd(), "agentsec-logs")
        run_dir = create_run_log_dir(log_base_dir)
        report_path = Path(run_dir) / "agentsec-report.md"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# AgentSec Security Report\n\n")
            f.write(f"**Scanned folder:** `{folder}`\n")
            f.write(
                f"**Date:** "
                f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )
            f.write("---\n\n")
            f.write(content)
            f.write("\n")

        _log("info", f"Report saved to {report_path}")
        return str(report_path)

    except Exception as err:
        _log("error", f"Failed to save report: {err}")
        return None


async def _main_loop() -> None:
    """
    Main loop: read JSON lines from stdin and dispatch commands.

    The bridge runs until stdin is closed (extension process exits).

    NOTE: asyncio.run() already owns the event loop, so we must NOT
    call loop.run_forever() here.  Instead we await an asyncio.Event
    that the stdin reader thread sets when stdin closes.
    """
    _write_message({"type": "ready"})
    _log("info", "AgentSec VS Code bridge started")

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    # Read stdin in a thread to avoid blocking the asyncio loop
    def _read_stdin():
        """Read lines from stdin and schedule handlers on the event loop."""
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    command = json.loads(line)
                except json.JSONDecodeError as err:
                    _log("error", f"Invalid JSON from extension: {err}")
                    continue

                cmd_type = command.get("type", "")
                logger.info("Received command: %s", cmd_type)

                if cmd_type == "scan":
                    asyncio.run_coroutine_threadsafe(
                        _handle_scan(command), loop
                    )
                elif cmd_type == "discover":
                    asyncio.run_coroutine_threadsafe(
                        _handle_discover(command.get("folder")), loop
                    )
                elif cmd_type == "cancel":
                    _cancel_event.set()
                    _log("info", "Cancellation requested")
                else:
                    _log("error", f"Unknown command type: {cmd_type}")
        except Exception:
            # stdin closed — extension terminated
            logger.info("stdin closed, shutting down")
        finally:
            # Signal the main coroutine to finish
            loop.call_soon_threadsafe(stop_event.set)

    reader_thread = threading.Thread(target=_read_stdin, daemon=True)
    reader_thread.start()

    # Keep the coroutine alive until stdin reader signals stop
    await stop_event.wait()
    logger.info("Bridge main loop exiting")


def main() -> None:
    """Entry point for the VS Code bridge."""
    try:
        asyncio.run(_main_loop())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
