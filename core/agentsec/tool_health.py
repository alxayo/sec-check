"""
Tool health monitoring for AgentSec.

This module provides the ToolHealthMonitor class which tracks the health
of tools running inside Copilot SDK sessions. It detects:

1. **Stuck tools** — tools that have been running for an unusually long
   time, possibly due to internal errors, missing dependencies, or
   waiting for user input that will never come.

2. **Tool errors** — tools that complete but produce error output
   indicating they could not do their job (e.g., missing database,
   connection failure, tool not installed).

3. **Retry loops** — when a broken tool keeps failing and the LLM
   keeps retrying it, wasting time without making progress.

The monitor integrates with the orchestrator and agent event handlers
to provide real-time visibility into what tools are doing, and supports
an async callback for interactive user decisions about stuck tools.

Usage:
    # Create a monitor for a session
    monitor = ToolHealthMonitor(
        agent_label="bandit-security-scan",
        concern_threshold=120.0,
    )

    # In event handler — register tool start
    monitor.tool_started(
        tool_call_id="call-123",
        tool_name="bash",
        detail="dependency-check --scan /project",
    )

    # In event handler — register tool completion and check output
    errors = monitor.tool_completed(
        tool_call_id="call-123",
        output="ERROR: Unable to download NVD database...",
    )
    # errors → [ToolErrorInfo(error_type="download_failure", ...)]

    # In poll loop — check for stuck tools
    stuck_tools = monitor.get_stuck_tools()
    for tool_info in stuck_tools:
        action = await on_tool_stuck(tool_info)
        if action == StuckToolAction.TERMINATE:
            await session.abort()
"""

import json
import logging
import os
import re
import time
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Dict, List, Optional, Set

# Set up logging for this module
logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────

# Default seconds before a running tool is considered potentially stuck.
# 120 seconds is generous enough for most tools but catches truly stuck
# processes (e.g., dependency-check failing to download NVD database).
DEFAULT_CONCERN_THRESHOLD = 120.0

# Maximum number of errors from the SAME tool+command combination
# before flagging a retry loop.  Errors are tracked by the
# combination of tool_name AND the first word of the detail
# (e.g., "bash:bandit" vs "bash:jq") so that different commands
# run via the same tool don't look like a retry loop.
# 3 is the threshold — the LLM gets two chances to recover before
# we consider it stuck in a loop.
MAX_TOOL_RETRIES_BEFORE_LOOP = 3

# Maximum TOTAL errors across ALL commands in a single session
# before we consider the session fundamentally broken.  This catches
# the scenario where the LLM keeps trying different approaches
# (dependency-check direct, docker, maven, etc.) but ALL of them
# fail — no single command hits the per-command retry threshold,
# but the session has accumulated so many errors that it is clearly
# not making progress and should be terminated.
MAX_TOTAL_ERRORS_BEFORE_ABORT = 5

# Patterns in tool output that indicate the tool encountered an error.
# Each entry is a (substring, error_category) tuple.  The substring is
# matched case-insensitively against the tool's output text.
#
# Order matters — more specific patterns should come before generic
# ones so the first match is the most informative.
TOOL_ERROR_INDICATORS: List[tuple] = [
    # ── Critical errors ──────────────────────────────────────────
    ("fatal error", "fatal_error"),
    ("critical error", "critical_error"),
    ("traceback (most recent call last)", "python_traceback"),
    ("java.lang.nullpointerexception", "java_exception"),
    ("java.lang.runtimeexception", "java_exception"),
    ("java.io.ioexception", "java_io_exception"),

    # ── Download / network failures ──────────────────────────────
    # Common with dependency-check (NVD database), trivy, guarddog
    ("unable to download", "download_failure"),
    ("unable to connect", "connection_failure"),
    ("unable to fetch", "fetch_failure"),
    ("connection refused", "connection_error"),
    ("connection timed out", "connection_timeout"),
    ("network unreachable", "network_error"),
    ("ssl: certificate_verify_failed", "ssl_error"),

    # ── Missing resources ────────────────────────────────────────
    ("database not found", "database_missing"),
    ("nvd database", "nvd_database_issue"),
    ("command not found", "tool_not_installed"),
    ("no such file or directory", "file_not_found"),
    ("permission denied", "permission_error"),

    # ── Tool waiting for user input ──────────────────────────────
    # These patterns indicate the tool is blocked waiting for input
    # that will never come (since tools run non-interactively).
    ("press enter", "waiting_for_input"),
    ("press any key", "waiting_for_input"),
    ("do you want to continue", "waiting_for_confirmation"),
    ("proceed? (y/n)", "waiting_for_confirmation"),
    ("[y/n]", "waiting_for_confirmation"),

    # ── Resource exhaustion ──────────────────────────────────────
    ("out of memory", "resource_exhaustion"),
    ("disk full", "resource_exhaustion"),
    ("no space left", "resource_exhaustion"),

    # ── Generic patterns (ONLY match tool-level failures) ────────
    # NOTE: The old patterns "error:" and "exception:" were removed
    # because they caused false positives — scanner tools like
    # graudit grep source code that naturally contains strings like
    # "new Error(...)" and "reject(error)".  The patterns below
    # are more specific and only match actual tool/runtime errors.
    #
    # We intentionally do NOT match "exited with exit code 1"
    # because many security tools use exit code 1 to indicate
    # "findings detected" (shellcheck, checkov, eslint), and grep
    # uses exit code 1 for "no match found".  Exit codes >= 2 are
    # caught by the tool-specific patterns above (fatal_error,
    # tool_not_installed at code 127, etc.).
]


# ── Enums and data classes ───────────────────────────────────────────

class StuckToolAction(Enum):
    """
    Actions that can be taken when a tool appears stuck.

    These are returned by the on_tool_stuck callback to tell the
    agent what to do about a stuck tool.

    Values:
        WAIT:      Continue waiting for the tool to complete.
                   The concern threshold is increased so the user
                   is not immediately prompted again.
        TERMINATE: Abort the entire sub-agent session.  The session
                   is destroyed and any partial results are kept.
    """

    # Continue waiting — the user believes the tool will finish
    WAIT = "wait"

    # Terminate — abort the sub-agent session
    TERMINATE = "terminate"


@dataclass
class RunningTool:
    """
    Information about a tool that is currently executing.

    Created when a TOOL_EXECUTION_START event is received, and
    removed when the corresponding TOOL_EXECUTION_COMPLETE arrives.

    Attributes:
        tool_call_id: Unique identifier for this tool invocation
        tool_name: Name of the tool (e.g., "bash", "skill", "view")
        detail: Additional context (e.g., bash command, skill name)
        agent_label: Label of the session running this tool
        start_time: Wall-clock time when the tool started (from time.time())
    """

    tool_call_id: str
    tool_name: str
    detail: str
    agent_label: str
    start_time: float

    @property
    def elapsed_seconds(self) -> float:
        """How long this tool has been running, in seconds."""
        return time.time() - self.start_time


@dataclass
class StuckToolInfo:
    """
    Information about a tool that appears to be stuck.

    This is passed to the on_tool_stuck callback so the user or
    system can make an informed decision about whether to wait
    or terminate the sub-agent.

    Attributes:
        tool_call_id: Unique identifier for this tool invocation
        tool_name: Name of the tool (e.g., "bash", "skill")
        detail: What the tool is doing (command being run, skill name)
        agent_label: Which sub-agent session this tool belongs to
        elapsed_seconds: How long the tool has been running
        message: Human-readable summary of the situation
        has_prior_errors: Whether this tool has previously completed
                          with errors (makes it more likely to be stuck)
    """

    tool_call_id: str
    tool_name: str
    detail: str
    agent_label: str
    elapsed_seconds: float
    message: str
    has_prior_errors: bool = False


@dataclass
class ToolErrorInfo:
    """
    Information about an error detected in a tool's output.

    Created when a TOOL_EXECUTION_COMPLETE event contains output
    matching known error patterns.

    Attributes:
        tool_name: Name of the tool that produced the error
        detail: What the tool was doing (command, skill name)
        agent_label: Which session the tool was running in
        error_type: Category of error (e.g., "download_failure",
                    "tool_not_installed", "waiting_for_input")
        error_snippet: Relevant excerpt from the tool output showing
                       the error context
    """

    tool_name: str
    detail: str
    agent_label: str
    error_type: str
    error_snippet: str


# ── Type alias for the stuck-tool callback ───────────────────────────

# The callback receives a StuckToolInfo with details about the stuck
# tool and returns a StuckToolAction telling the agent what to do.
#
# The callback MUST be an async function because the CLI implementation
# uses run_in_executor to read user input without blocking the event loop.
OnToolStuckCallback = Callable[[StuckToolInfo], Awaitable[StuckToolAction]]


# ── Utility functions ────────────────────────────────────────────────

def extract_tool_arguments(event_data) -> dict:
    """
    Extract tool arguments from a Copilot SDK event data object.

    The SDK may provide tool arguments in different attributes depending
    on the version. This function tries multiple attribute names and
    handles both dict and JSON string formats safely.

    Args:
        event_data: The event.data from a TOOL_EXECUTION_START event

    Returns:
        A dictionary of tool arguments, or empty dict if not available

    Example:
        >>> args = extract_tool_arguments(event.data)
        >>> command = args.get("command", "")
    """
    for attr_name in ("arguments", "input", "params", "tool_input"):
        try:
            args = getattr(event_data, attr_name, None)
            if args is not None:
                if isinstance(args, dict):
                    return args
                if isinstance(args, str):
                    return json.loads(args)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue

    return {}


def extract_tool_output(event_data) -> str:
    """
    Extract tool output text from a TOOL_EXECUTION_COMPLETE event.

    The Copilot SDK may store tool output in different attributes
    depending on the version. This function tries multiple common
    attribute names and returns the first non-empty string found.

    Args:
        event_data: The event.data from a TOOL_EXECUTION_COMPLETE event

    Returns:
        The tool output as a string, or empty string if not available

    Example:
        >>> output = extract_tool_output(event.data)
        >>> if "error" in output.lower():
        ...     print("Tool had errors!")
    """
    # Try known attribute names in order of likelihood
    for attr_name in ("output", "result", "content", "text", "tool_output"):
        try:
            value = getattr(event_data, attr_name, None)
            if value is not None:
                if isinstance(value, str):
                    return value
                # Handle dict/list by converting to string
                return str(value)
        except (TypeError, ValueError):
            continue

    # Fall back to the string representation of the entire event data.
    # Only return if it contains meaningful content (not just a class name).
    try:
        data_str = str(event_data)
        if len(data_str) > 20:
            return data_str
    except Exception:
        pass

    return ""


def extract_tool_detail(tool_name: str, tool_args: dict) -> str:
    """
    Extract a human-readable detail string from tool arguments.

    Produces a short description of what the tool is doing based on
    the tool name and its arguments.  For example:
    - bash tool → the command being run
    - skill tool → the skill name
    - view tool → the file being viewed

    Args:
        tool_name: The name of the tool ("bash", "skill", "view", etc.)
        tool_args: The tool's arguments dictionary

    Returns:
        A short detail string, or empty string if not available

    Example:
        >>> detail = extract_tool_detail("bash", {"command": "bandit -r ./src"})
        >>> # detail == "bandit -r ./src"
    """
    if not tool_args:
        return ""

    if tool_name == "bash":
        command = tool_args.get("command", "")
        if command:
            # Return the command, truncated if very long
            if len(command) > 120:
                return command[:120] + "…"
            return command

    elif tool_name == "skill":
        # Extract the skill name being invoked
        skill_name = tool_args.get(
            "name",
            tool_args.get(
                "skill_name",
                tool_args.get("skillName", ""),
            ),
        )
        return skill_name

    elif tool_name == "view":
        file_path = tool_args.get(
            "path",
            tool_args.get(
                "file_path",
                tool_args.get("filePath", ""),
            ),
        )
        if file_path:
            return os.path.basename(file_path)

    return ""


# ── ToolHealthMonitor class ──────────────────────────────────────────

class ToolHealthMonitor:
    """
    Monitors the health of tools running in a Copilot SDK session.

    This class tracks which tools are currently executing, how long
    they have been running, and whether their output contains error
    patterns. It provides methods to detect stuck tools and retry
    loops, enabling faster detection and user-driven decisions.

    The monitor is thread-safe and can be accessed from both the
    synchronous SDK event handler and the async poll loop.

    How it works:
        1. When a tool starts (TOOL_EXECUTION_START event), call
           tool_started() to register it with the monitor.
        2. When a tool completes (TOOL_EXECUTION_COMPLETE event),
           call tool_completed() to unregister it and inspect the
           output for error patterns.
        3. Periodically (in the poll loop), call get_stuck_tools()
           to find tools that have been running longer than the
           concern_threshold.
        4. If a stuck tool is found, the caller can invoke an
           on_tool_stuck callback to ask the user for a decision.
        5. If the user chooses WAIT, call reset_alert() so the tool
           is re-checked at a longer threshold.
        6. If the user chooses TERMINATE, abort the session.
        7. Additionally, call has_any_retry_loop() to detect when
           the LLM keeps retrying a broken tool.

    Example:
        >>> monitor = ToolHealthMonitor(
        ...     agent_label="bandit-security-scan",
        ...     concern_threshold=120.0,
        ... )
        >>>
        >>> # In event handler: register tool start
        >>> monitor.tool_started("call-1", "bash", "bandit -r ./src")
        >>>
        >>> # In poll loop: check for stuck tools
        >>> stuck = monitor.get_stuck_tools()
        >>> if stuck:
        ...     print(f"Stuck: {stuck[0].message}")
        >>>
        >>> # In event handler: register completion and check for errors
        >>> errors = monitor.tool_completed("call-1", output="No issues")
    """

    def __init__(
        self,
        agent_label: str = "session",
        concern_threshold: float = DEFAULT_CONCERN_THRESHOLD,
    ) -> None:
        """
        Create a new tool health monitor.

        Args:
            agent_label: Label for the session being monitored.
                         Used in log messages and stuck-tool reports
                         so the user knows which sub-agent has the
                         stuck tool.
            concern_threshold: Seconds of tool execution before the
                               tool is considered potentially stuck.
                               Default is 120 seconds.
        """
        self._lock = threading.Lock()
        self._agent_label = agent_label
        self._concern_threshold = concern_threshold

        # Currently running tools: tool_call_id → RunningTool
        self._running: Dict[str, RunningTool] = {}

        # Errors detected in completed tool output
        self._tool_errors: List[ToolErrorInfo] = []

        # Count of tool executions by tool name (for retry-loop detection)
        self._tool_exec_counts: Dict[str, int] = {}

        # Tool IDs that have already been flagged as stuck.
        # Prevents spamming the user with repeated alerts for the
        # same still-running tool.
        self._alerted_tool_ids: Set[str] = set()

    # ── Public API ───────────────────────────────────────────────────

    def tool_started(
        self,
        tool_call_id: str,
        tool_name: str,
        detail: str = "",
    ) -> None:
        """
        Register that a tool has started executing.

        Call this from the TOOL_EXECUTION_START event handler to
        begin tracking the tool's execution time.

        Args:
            tool_call_id: Unique identifier for this tool invocation
                          (from the SDK event data)
            tool_name: Name of the tool (e.g., "bash", "skill", "view")
            detail: Additional context — the command being run, the
                    skill being invoked, or the file being viewed
        """
        with self._lock:
            self._running[tool_call_id] = RunningTool(
                tool_call_id=tool_call_id,
                tool_name=tool_name,
                detail=detail,
                agent_label=self._agent_label,
                start_time=time.time(),
            )

            # Count executions of this tool for retry-loop detection
            self._tool_exec_counts[tool_name] = (
                self._tool_exec_counts.get(tool_name, 0) + 1
            )

        logger.debug(
            f"[{self._agent_label}] Tool health: tracking "
            f"'{tool_name}' (id={tool_call_id}, detail='{detail}')"
        )

    def tool_completed(
        self,
        tool_call_id: str,
        output: str = "",
    ) -> List[ToolErrorInfo]:
        """
        Register that a tool has finished and check its output.

        Call this from the TOOL_EXECUTION_COMPLETE event handler.
        Removes the tool from the running set and inspects the
        output for known error patterns.

        Args:
            tool_call_id: The tool_call_id from the completion event
            output: The tool's output text (extract using
                    extract_tool_output(event.data))

        Returns:
            A list of ToolErrorInfo if errors were detected in the
            output. Empty list if the output looks clean or if the
            tool_call_id was not being tracked.
        """
        with self._lock:
            tool = self._running.pop(tool_call_id, None)
            self._alerted_tool_ids.discard(tool_call_id)

        if not tool:
            # We never saw this tool start — can't check it
            return []

        elapsed = time.time() - tool.start_time
        logger.debug(
            f"[{self._agent_label}] Tool health: "
            f"'{tool.tool_name}' completed after {elapsed:.1f}s"
        )

        if not output:
            return []

        # Check the output for error patterns
        errors = self._detect_errors_in_output(output, tool)
        if errors:
            with self._lock:
                self._tool_errors.extend(errors)

            for error in errors:
                logger.warning(
                    f"[{self._agent_label}] Tool error detected: "
                    f"{error.error_type} in '{tool.tool_name}' — "
                    f"{error.error_snippet[:100]}"
                )

        return errors

    def get_stuck_tools(self) -> List[StuckToolInfo]:
        """
        Check for tools that have been running longer than expected.

        Returns tools that have exceeded the concern_threshold and
        have not already been reported. Each tool is only reported
        once — call reset_alert() to enable re-checking.

        Returns:
            List of StuckToolInfo for tools that appear stuck.
            Empty list if all tools are running normally.

        Example:
            >>> stuck = monitor.get_stuck_tools()
            >>> for info in stuck:
            ...     print(f"⚠ {info.message}")
        """
        with self._lock:
            stuck_tools: List[StuckToolInfo] = []

            for tool_id, tool in self._running.items():
                elapsed = tool.elapsed_seconds

                # Only report if over threshold and not already alerted
                if (
                    elapsed >= self._concern_threshold
                    and tool_id not in self._alerted_tool_ids
                ):
                    # Check whether this tool has had previous errors.
                    # Prior errors make it more likely that the tool is
                    # stuck rather than just slow.
                    has_prior = any(
                        e.tool_name == tool.tool_name
                        for e in self._tool_errors
                    )

                    # Build a descriptive message for the user
                    desc = tool.detail or tool.tool_name
                    minutes = int(elapsed // 60)
                    seconds = int(elapsed % 60)

                    if has_prior:
                        message = (
                            f"Tool '{desc}' in sub-agent "
                            f"'{tool.agent_label}' has been running for "
                            f"{minutes}m {seconds}s and has had prior "
                            f"errors — it may be stuck or broken"
                        )
                    else:
                        message = (
                            f"Tool '{desc}' in sub-agent "
                            f"'{tool.agent_label}' has been running for "
                            f"{minutes}m {seconds}s — it may be stuck "
                            f"or waiting for input"
                        )

                    stuck_tools.append(
                        StuckToolInfo(
                            tool_call_id=tool_id,
                            tool_name=tool.tool_name,
                            detail=tool.detail,
                            agent_label=tool.agent_label,
                            elapsed_seconds=elapsed,
                            message=message,
                            has_prior_errors=has_prior,
                        )
                    )

                    # Mark as alerted so we don't spam the same alert
                    self._alerted_tool_ids.add(tool_id)

            return stuck_tools

    def reset_alert(self, tool_call_id: str) -> None:
        """
        Clear the alert flag for a tool so it can be re-checked.

        Call this when the user chooses "wait" — the tool will be
        flagged again on the next poll cycle after the concern
        threshold has elapsed again (which is increased by 50% each
        time so the user is not immediately re-prompted).

        Args:
            tool_call_id: The tool to re-enable checking for.
        """
        with self._lock:
            self._alerted_tool_ids.discard(tool_call_id)

            # Increase the concern threshold by 50% so the next alert
            # comes later. This gives the tool more breathing room
            # each time the user chooses to wait.
            self._concern_threshold = self._concern_threshold * 1.5

        logger.debug(
            f"[{self._agent_label}] Alert reset for tool {tool_call_id}, "
            f"new threshold: {self._concern_threshold:.0f}s"
        )

    def has_any_retry_loop(
        self,
        max_retries: int = MAX_TOOL_RETRIES_BEFORE_LOOP,
    ) -> Optional[str]:
        """
        Check if ANY tool is in a retry loop (failing repeatedly).

        A retry loop occurs when the LLM keeps re-running the SAME
        command that keeps completing with error output. This wastes
        time without making progress and should trigger auto-termination.

        Errors are tracked by the combination of tool_name AND the
        first word of the detail string.  For example, "bash" running
        "jq ..." and "bash" running "python3 ..." are counted
        separately, because the LLM trying a different approach after
        one fails is not a retry loop — it's problem-solving.

        Only when the same tool+command combination fails
        ``max_retries`` times is it considered a loop.

        Args:
            max_retries: Number of error completions before flagging
                         a tool as being in a retry loop. Default is 3.

        Returns:
            The tool name if a retry loop is detected, or None if
            all tools are healthy.

        Example:
            >>> looping_tool = monitor.has_any_retry_loop()
            >>> if looping_tool:
            ...     print(f"Tool '{looping_tool}' is in a retry loop!")
        """
        with self._lock:
            # Count errors per tool_name + first word of detail.
            # This distinguishes "bash running jq" from "bash running
            # python3" so different recovery attempts don't trigger
            # a false retry-loop detection.
            error_counts: Dict[str, int] = {}
            for error in self._tool_errors:
                # Build a key from tool_name + first word of detail
                first_word = error.detail.split()[0] if error.detail.strip() else ""
                key = f"{error.tool_name}:{first_word}" if first_word else error.tool_name
                error_counts[key] = error_counts.get(key, 0) + 1

            # Return the first tool key exceeding the retry threshold
            for key, count in error_counts.items():
                if count >= max_retries:
                    # Return the tool_name portion for display
                    return key.split(":")[0] if ":" in key else key

        return None

    def has_excessive_errors(
        self,
        max_total: int = MAX_TOTAL_ERRORS_BEFORE_ABORT,
    ) -> Optional[int]:
        """
        Check if the session has accumulated too many total errors.

        This is a higher-level check than has_any_retry_loop().  It
        catches the scenario where the LLM keeps trying DIFFERENT
        commands that all fail — no single command hits the per-command
        retry threshold, but the session is clearly broken.

        For example, the LLM might try:
          1. dependency-check --scan → database error
          2. dependency-check --updateonly → cannot create directory
          3. dependency-check --data ~/.dc → NullPointerException
          4. docker run owasp/dependency-check → docker not found
          5. mvn dependency-check-maven:check → database corruption

        Each is a different first-word so has_any_retry_loop() never
        triggers, but 5 errors across 5 different approaches means
        this tool fundamentally cannot work and the session should
        be terminated.

        Args:
            max_total: Maximum total errors before flagging the session
                       as broken. Default is MAX_TOTAL_ERRORS_BEFORE_ABORT (5).

        Returns:
            The total error count if it exceeds max_total, or None if
            the session is within acceptable limits.

        Example:
            >>> total = monitor.has_excessive_errors()
            >>> if total:
            ...     print(f"Session has {total} total errors — aborting")
        """
        with self._lock:
            total = len(self._tool_errors)
            if total >= max_total:
                return total
        return None

    def get_error_summary(self) -> List[ToolErrorInfo]:
        """
        Get all errors detected so far across all tool completions.

        Returns:
            A copy of the internal error list.
        """
        with self._lock:
            return list(self._tool_errors)

    def get_running_tools_info(self) -> List[dict]:
        """
        Get information about all currently running tools.

        Useful for status displays and debugging.

        Returns:
            List of dictionaries with tool info:
            - "tool_call_id": str
            - "tool_name": str
            - "detail": str
            - "agent_label": str
            - "elapsed_seconds": float

        Example:
            >>> for info in monitor.get_running_tools_info():
            ...     print(f"{info['tool_name']}: {info['elapsed_seconds']:.0f}s")
        """
        with self._lock:
            return [
                {
                    "tool_call_id": tool.tool_call_id,
                    "tool_name": tool.tool_name,
                    "detail": tool.detail,
                    "agent_label": tool.agent_label,
                    "elapsed_seconds": tool.elapsed_seconds,
                }
                for tool in self._running.values()
            ]

    # ── Private helpers ──────────────────────────────────────────────

    def _detect_errors_in_output(
        self,
        output: str,
        tool: RunningTool,
    ) -> List[ToolErrorInfo]:
        """
        Scan tool output for known error patterns.

        Matches the output against TOOL_ERROR_INDICATORS and returns
        a ToolErrorInfo for the first matching pattern found. Only
        the first match is returned to avoid noisy duplicate reports.

        If the output indicates the tool exited successfully (exit
        code 0), error detection is skipped entirely.  Scanner tools
        like graudit produce output containing source code that
        naturally includes words like "Error" or "exception" — those
        are scan *results*, not tool failures.

        Args:
            output: The tool's output text
            tool: The RunningTool instance (for context in the report)

        Returns:
            List with at most one ToolErrorInfo (the first match),
            or empty list if no errors were detected.
        """
        errors: List[ToolErrorInfo] = []

        # ── Exit-code check ──────────────────────────────────────
        # The Copilot CLI wraps tool output with a trailer like
        # "<exited with exit code 0>".  If the tool exited with
        # code 0, it succeeded — any "error"-like strings in the
        # output are just scanner results (source code lines that
        # happen to contain the word "error"), NOT tool failures.
        exit_code_match = re.search(
            r"<exited with exit code (\d+)>",
            output,
        )
        if exit_code_match:
            exit_code = int(exit_code_match.group(1))
            if exit_code == 0:
                # Tool succeeded — do not flag anything as an error
                return []

        lower_output = output.lower()

        for pattern, category in TOOL_ERROR_INDICATORS:
            if pattern in lower_output:
                # Extract a snippet around the matching pattern
                # so the user can see context about the error
                idx = lower_output.find(pattern)
                start = max(0, idx - 50)
                end = min(len(output), idx + len(pattern) + 100)
                snippet = output[start:end].strip()

                errors.append(
                    ToolErrorInfo(
                        tool_name=tool.tool_name,
                        detail=tool.detail,
                        agent_label=tool.agent_label,
                        error_type=category,
                        error_snippet=snippet,
                    )
                )

                # One error per completion is enough — the first
                # match is typically the most specific/useful
                break

        return errors
