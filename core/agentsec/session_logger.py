"""
Per-session file logging for AgentSec.

This module provides the SessionLogger class which writes a detailed
log file for each agent or sub-agent session. The log captures the
full input/output of the session: system messages, prompts, tool
calls (with arguments and output), assistant messages, nudges,
errors, and lifecycle events.

Log files are organised by run:

    <log_dir>/
      └── <YYYY-MM-DD_HHMMSS>/
          ├── main-scan.log
          ├── bandit-security-scan.log
          ├── graudit-security-scan.log
          └── synthesis.log

Usage:
    # Create a run directory for this scan
    run_dir = create_run_log_dir("/path/to/agentsec-logs")

    # Create a logger for a specific session
    slog = SessionLogger(run_dir=run_dir, session_label="bandit-security-scan")

    # Log events as they happen
    slog.log_system_message(system_message_text)
    slog.log_prompt_sent(prompt_text)
    slog.log_tool_start(tool_name="bash", detail="bandit -r ./src", args={...})
    slog.log_tool_complete(tool_name="bash", detail="bandit", output="...")
    slog.log_assistant_message(content)
    slog.log_session_idle()

    # The log file is flushed after every write so it is always up to date.
"""

import datetime
import json
import logging
import os
import threading
from pathlib import Path
from typing import Optional

# Set up logging for this module itself (meta-logging)
logger = logging.getLogger(__name__)


def create_run_log_dir(base_log_dir: str) -> str:
    """
    Create a timestamped directory for this scan run's log files.

    The directory is created inside base_log_dir with a name like
    "2026-02-13_161936" (date_time format).

    Args:
        base_log_dir: The parent directory for all AgentSec logs.
                      Typically "<cwd>/agentsec-logs".

    Returns:
        The absolute path to the newly created run directory.

    Example:
        >>> run_dir = create_run_log_dir("/home/user/project/agentsec-logs")
        >>> # run_dir == "/home/user/project/agentsec-logs/2026-02-13_161936"
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    run_dir = os.path.join(base_log_dir, timestamp)
    os.makedirs(run_dir, exist_ok=True)

    logger.debug(f"Created run log directory: {run_dir}")
    return run_dir


class SessionLogger:
    """
    Writes a detailed log file for a single agent or sub-agent session.

    Each SessionLogger creates one log file named after the session
    label (e.g., "bandit-security-scan.log") inside the run directory.
    All writes are immediately flushed so the log is always up to date,
    even if the process crashes.

    The logger is thread-safe — it can be called from both the
    synchronous SDK event handler and the async poll loop.

    Log Format:
        Each entry has a timestamp, a tag (e.g., [SYSTEM], [PROMPT],
        [TOOL_START], [TOOL_COMPLETE], [ASSISTANT], [NUDGE], [ERROR]),
        and the relevant content. Tool arguments and output are logged
        in full so the log captures the complete interaction.

    Example:
        >>> slog = SessionLogger(run_dir="/tmp/logs/2026-02-13_161936",
        ...                      session_label="bandit-security-scan")
        >>> slog.log_system_message("You are a focused scanner...")
        >>> slog.log_prompt_sent("Scan ./src with bandit...")
        >>> slog.log_tool_start("bash", "bandit -r ./src", {"command": "bandit -r ./src"})
        >>> slog.log_tool_complete("bash", "bandit", output="No issues found.")
        >>> slog.log_assistant_message("### bandit Results\\n...")
        >>> slog.log_session_idle()
        >>> slog.close()
    """

    def __init__(
        self,
        run_dir: str,
        session_label: str,
    ) -> None:
        """
        Create a new session logger.

        Opens (or creates) the log file and writes a header with
        the session label and start timestamp.

        Args:
            run_dir: Path to the timestamped run directory.
            session_label: Name for this session (used as the
                           filename).  Examples: "main-scan",
                           "bandit-security-scan", "synthesis".
        """
        self._lock = threading.Lock()
        self._session_label = session_label

        # Sanitise the label for use as a filename
        safe_label = session_label.replace("/", "_").replace("\\", "_")
        log_filename = f"{safe_label}.log"
        self._log_path = os.path.join(run_dir, log_filename)

        # Open the file in append mode so we never lose data.
        # We keep the file handle open for the lifetime of the logger
        # and flush after every write.
        try:
            self._file = open(
                self._log_path, "a", encoding="utf-8",
            )
        except OSError as error:
            logger.warning(
                f"Could not create session log file "
                f"'{self._log_path}': {error}"
            )
            self._file = None
            return

        # Write a header
        self._write_raw(
            f"{'=' * 70}\n"
            f"  AgentSec Session Log\n"
            f"  Session : {session_label}\n"
            f"  Started : {self._timestamp()}\n"
            f"  Log file: {self._log_path}\n"
            f"{'=' * 70}\n\n"
        )

    # ── Public logging methods ───────────────────────────────────────

    def log_system_message(self, system_message: str) -> None:
        """
        Log the system message sent to this session.

        Args:
            system_message: The full system message text.
        """
        self._write_entry("SYSTEM", system_message)

    def log_prompt_sent(self, prompt: str) -> None:
        """
        Log a prompt (user message) sent to the session.

        This includes both the initial scan prompt and any nudge
        messages sent later.

        Args:
            prompt: The prompt text that was sent.
        """
        self._write_entry("PROMPT", prompt)

    def log_nudge_sent(self, nudge_message: str) -> None:
        """
        Log a nudge message sent to prod the session.

        Args:
            nudge_message: The nudge text.
        """
        self._write_entry("NUDGE", nudge_message)

    def log_tool_start(
        self,
        tool_name: str,
        detail: str = "",
        args: Optional[dict] = None,
        tool_call_id: Optional[str] = None,
    ) -> None:
        """
        Log the start of a tool execution.

        Args:
            tool_name: Name of the tool (e.g., "bash", "skill", "view").
            detail: Short description (e.g., command, skill name, file).
            args: Full tool arguments dictionary (logged as JSON).
            tool_call_id: SDK tool_call_id for correlation.
        """
        parts = [f"tool={tool_name}"]
        if detail:
            parts.append(f"detail={detail}")
        if tool_call_id:
            parts.append(f"id={tool_call_id}")

        header = "  ".join(parts)

        # Format arguments as indented JSON for readability
        if args:
            try:
                args_text = json.dumps(args, indent=2, default=str)
            except (TypeError, ValueError):
                args_text = str(args)
            body = f"{header}\n--- arguments ---\n{args_text}\n--- end arguments ---"
        else:
            body = header

        self._write_entry("TOOL_START", body)

    def log_tool_complete(
        self,
        tool_name: str,
        detail: str = "",
        output: str = "",
        tool_call_id: Optional[str] = None,
        elapsed_seconds: Optional[float] = None,
    ) -> None:
        """
        Log the completion of a tool execution.

        The full tool output is logged so the user can see exactly
        what each tool produced.

        Args:
            tool_name: Name of the tool.
            detail: Short description.
            output: The tool's full output text.
            tool_call_id: SDK tool_call_id for correlation.
            elapsed_seconds: How long the tool ran (if known).
        """
        parts = [f"tool={tool_name}"]
        if detail:
            parts.append(f"detail={detail}")
        if tool_call_id:
            parts.append(f"id={tool_call_id}")
        if elapsed_seconds is not None:
            parts.append(f"elapsed={elapsed_seconds:.1f}s")

        header = "  ".join(parts)

        if output:
            body = f"{header}\n--- output ---\n{output}\n--- end output ---"
        else:
            body = f"{header}\n(no output)"

        self._write_entry("TOOL_COMPLETE", body)

    def log_tool_error(
        self,
        tool_name: str,
        error_type: str,
        error_snippet: str,
    ) -> None:
        """
        Log an error detected in a tool's output.

        Args:
            tool_name: Name of the tool that had the error.
            error_type: Error category (e.g., "download_failure").
            error_snippet: Relevant output excerpt.
        """
        self._write_entry(
            "TOOL_ERROR",
            f"tool={tool_name}  error_type={error_type}\n{error_snippet}",
        )

    def log_assistant_message(self, content: str) -> None:
        """
        Log an assistant (LLM) message received from the session.

        Args:
            content: The full text of the assistant's response.
        """
        self._write_entry("ASSISTANT", content)

    def log_session_idle(self) -> None:
        """Log that the session has gone idle (processing complete)."""
        self._write_entry("SESSION_IDLE", "Session processing complete")

    def log_session_error(self, error_msg: str) -> None:
        """
        Log a session-level error.

        Args:
            error_msg: The error description.
        """
        self._write_entry("SESSION_ERROR", error_msg)

    def log_session_abort(self, reason: str = "") -> None:
        """
        Log that the session was aborted.

        Args:
            reason: Why the session was aborted.
        """
        self._write_entry(
            "SESSION_ABORT",
            reason or "Session aborted",
        )

    def log_event(self, event_type: str, data: str = "") -> None:
        """
        Log a generic SDK event.

        Use this for events that don't have a dedicated method
        (e.g., reasoning, compaction, sub-agent events).

        Args:
            event_type: The event type string.
            data: Optional event data (truncated if very long).
        """
        if data and len(data) > 2000:
            data = data[:2000] + "\n... [truncated]"
        self._write_entry("EVENT", f"type={event_type}\n{data}" if data else f"type={event_type}")

    def log_info(self, message: str) -> None:
        """
        Log an informational message.

        Use for lifecycle milestones like "scan started", "synthesis
        started", etc.

        Args:
            message: The information to log.
        """
        self._write_entry("INFO", message)

    def log_warning(self, message: str) -> None:
        """
        Log a warning message.

        Args:
            message: The warning text.
        """
        self._write_entry("WARNING", message)

    def log_stuck_tool(
        self,
        tool_name: str,
        detail: str,
        elapsed_seconds: float,
        action_taken: str,
    ) -> None:
        """
        Log a stuck-tool detection and the action taken.

        Args:
            tool_name: The stuck tool's name.
            detail: What the tool was doing.
            elapsed_seconds: How long the tool had been running.
            action_taken: "wait" or "terminate".
        """
        self._write_entry(
            "STUCK_TOOL",
            f"tool={tool_name}  detail={detail}  "
            f"elapsed={elapsed_seconds:.0f}s  action={action_taken}",
        )

    def log_retry_loop(self, tool_name: str) -> None:
        """
        Log that a tool entered a retry loop.

        Args:
            tool_name: The tool that was looping.
        """
        self._write_entry(
            "RETRY_LOOP",
            f"Tool '{tool_name}' is in a retry loop — session will be aborted",
        )

    def close(self) -> None:
        """
        Write a footer and close the log file.

        Safe to call multiple times — subsequent calls are no-ops.
        """
        with self._lock:
            if self._file and not self._file.closed:
                self._file.write(
                    f"\n{'=' * 70}\n"
                    f"  Session ended: {self._timestamp()}\n"
                    f"{'=' * 70}\n"
                )
                self._file.flush()
                self._file.close()

    # ── Private helpers ──────────────────────────────────────────────

    @staticmethod
    def _timestamp() -> str:
        """Return the current timestamp as a string."""
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _write_entry(self, tag: str, content: str) -> None:
        """
        Write a single tagged entry to the log file.

        Each entry starts with a timestamp and tag, followed by the
        content.  A separator line is added between entries for
        readability.

        Args:
            tag: The entry tag (e.g., "TOOL_START", "ASSISTANT").
            content: The entry content (may be multi-line).
        """
        with self._lock:
            if not self._file or self._file.closed:
                return

            try:
                self._file.write(
                    f"[{self._timestamp()}] [{tag}]\n"
                    f"{content}\n"
                    f"{'-' * 70}\n"
                )
                self._file.flush()
            except OSError:
                # If writing fails (disk full, etc.), don't crash the scan
                pass

    def _write_raw(self, text: str) -> None:
        """Write raw text to the log file without formatting."""
        with self._lock:
            if not self._file or self._file.closed:
                return
            try:
                self._file.write(text)
                self._file.flush()
            except OSError:
                pass

    # ── Context manager support ──────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.log_session_error(f"Exception: {exc_val}")
        self.close()
        return False
