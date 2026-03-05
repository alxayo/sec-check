"""
Shared session-runner for AgentSec.

This module provides the ``run_session_to_completion`` function which
sends a prompt to a Copilot SDK session and waits for it to finish
using **activity-based detection** instead of a hard timeout.

Both the single-session scan (``agent.py``) and the orchestrator's
sub-agent scans (``orchestrator.py``) use this function so the
wait-loop logic, health monitoring, nudge mechanism, and session
logging are implemented in exactly one place.

Activity-based waiting works as follows:
  - The SDK emits events whenever the session is doing work (tool
    calls, messages, reasoning, etc.).
  - As long as events keep arriving, the session is alive — we wait.
  - Only when ALL activity stops for ``inactivity_timeout`` seconds
    do we send a nudge message.
  - After ``max_idle_nudges`` consecutive unresponsive nudges we
    call ``session.abort()`` and return partial results.
  - A ``safety_timeout`` acts as an absolute ceiling (safety net).

Usage:
    result = await run_session_to_completion(
        session=session,
        prompt="Scan ./src for vulnerabilities",
        label="main-scan",
        nudge_message="Please continue or finish up.",
        safety_timeout=1800.0,
    )
    print(result["status"])   # "success", "timeout", or "error"
    print(result["content"])  # assistant's response text
"""

import asyncio
import logging
import time
from typing import Callable, Optional, Union

from copilot import MessageOptions
from copilot.session import SessionEventType

from agentsec.progress import get_global_tracker
from agentsec.session_logger import SessionLogger
from agentsec.tool_health import (
    ToolHealthMonitor,
    OnToolStuckCallback,
    StuckToolAction,
    extract_tool_arguments,
    extract_tool_detail,
    extract_tool_output,
    MAX_TOOL_RETRIES_BEFORE_LOOP,
    MAX_TOTAL_ERRORS_BEFORE_ABORT,
)

# Set up logging for this module
logger = logging.getLogger(__name__)

# ── Default wait constants ───────────────────────────────────────────

# Seconds of silence (no SDK events at all) before we send a nudge.
DEFAULT_INACTIVITY_TIMEOUT = 120.0

# Consecutive nudges with no response before we abort.
DEFAULT_MAX_IDLE_NUDGES = 3

# Absolute safety ceiling for any single session (seconds).
DEFAULT_SAFETY_TIMEOUT = 1800.0

# ── Transient error detection (B1) ───────────────────────────────────
# These patterns in session error messages indicate transient failures
# that may resolve on retry (e.g., rate limits, temporary server issues).
# Permanent errors (auth failure, model not found) should NOT be retried.
TRANSIENT_ERROR_PATTERNS = [
    "rate limit",
    "rate_limit",
    "429",
    "too many requests",
    "temporarily unavailable",
    "service unavailable",
    "503",
    "502",
    "gateway timeout",
    "504",
    "internal server error",
    "500",
    "overloaded",
    "capacity",
    "throttl",
    "retry",
    "try again",
]

# Maximum number of automatic retries for transient session errors.
MAX_TRANSIENT_RETRIES = 3

# Base delay in seconds for exponential backoff on transient errors.
# Actual delays: 5s, 15s, 45s (multiplied by 3 each time).
TRANSIENT_RETRY_BASE_DELAY = 5.0


def _is_transient_error(error_msg: str) -> bool:
    """
    Check whether a session error message indicates a transient failure.

    Transient errors (rate limits, temporary server issues) may resolve
    on retry.  Permanent errors (auth failure, model not found) should
    not be retried.

    Args:
        error_msg: The error message from the SESSION_ERROR event.

    Returns:
        True if the error appears transient and worth retrying.
    """
    lower_msg = error_msg.lower()
    return any(pattern in lower_msg for pattern in TRANSIENT_ERROR_PATTERNS)


# Type for a nudge message that can be either a static string or a
# callable that returns the appropriate nudge dynamically.
NudgeMessageType = Union[str, Callable[[], str], None]

# Callback signature for custom processing on tool start events.
# Receives (tool_name, detail, tool_args, tool_call_id).
OnToolStartHook = Callable[[str, str, dict, Optional[str]], None]

# Callback signature for custom processing on tool complete events.
# Receives (tool_name, detail, output, tool_call_id).
OnToolCompleteHook = Callable[[str, str, str, Optional[str]], None]


# ── Activity event matching ──────────────────────────────────────────

# SDK event types that indicate the session is actively doing work.
_ACTIVITY_EVENT_TYPES = {
    SessionEventType.TOOL_EXECUTION_START,
    SessionEventType.TOOL_EXECUTION_COMPLETE,
    SessionEventType.ASSISTANT_MESSAGE,
}

# Forward-compatible string-based event type matching for newer SDK
# versions that may add event types not yet in our installed enum.
_ACTIVITY_EVENT_STRINGS = {
    "tool.execution_start",
    "tool.execution_complete",
    "tool.execution_progress",
    "tool.execution_partial_result",
    "assistant.message",
    "assistant.message_delta",
    "assistant.reasoning",
    "assistant.reasoning_delta",
    "assistant.turn_start",
    "assistant.turn_end",
    "assistant.intent",
    "skill.invoked",
    "subagent.started",
    "subagent.completed",
    "subagent.failed",
    "subagent.selected",
    "session.compaction_start",
    "session.compaction_complete",
    "hook.start",
    "hook.end",
}


def _is_activity_event(event) -> bool:
    """Return True if this event indicates the session is alive."""
    if event.type in _ACTIVITY_EVENT_TYPES:
        return True
    event_value = getattr(event.type, "value", None)
    if event_value and event_value in _ACTIVITY_EVENT_STRINGS:
        return True
    return False


# ── Session abort / cleanup helpers ──────────────────────────────────

async def abort_session(session, label: str = "session") -> None:
    """
    Abort a running Copilot SDK session.

    Calls ``session.abort()`` to cancel any in-flight work, then
    waits briefly for the abort to take effect.

    Args:
        session: The session to abort (may be None).
        label:   Label for log messages.
    """
    if session is None:
        return
    try:
        await asyncio.wait_for(session.abort(), timeout=10.0)
        logger.debug(f"[{label}] Session aborted")
    except asyncio.TimeoutError:
        logger.warning(f"[{label}] Session abort timed out")
    except Exception as error:
        logger.debug(f"[{label}] Session abort error: {error}")


async def cleanup_session(session, label: str = "session") -> None:
    """
    Safely destroy a Copilot SDK session.

    Handles timeouts and exceptions so cleanup never crashes the
    calling code.

    Args:
        session: The session to destroy (may be None).
        label:   Label for log messages.
    """
    if session is None:
        return
    try:
        await asyncio.wait_for(session.destroy(), timeout=5.0)
        logger.debug(f"[{label}] Session destroyed")
    except asyncio.TimeoutError:
        logger.warning(f"[{label}] Session destroy timed out")
    except Exception as error:
        logger.debug(f"[{label}] Session cleanup error: {error}")


# ── Main entry point ─────────────────────────────────────────────────

async def run_session_to_completion(
    session,
    prompt: str,
    label: str = "session",
    nudge_message: NudgeMessageType = None,
    inactivity_timeout: float = DEFAULT_INACTIVITY_TIMEOUT,
    max_idle_nudges: int = DEFAULT_MAX_IDLE_NUDGES,
    safety_timeout: float = DEFAULT_SAFETY_TIMEOUT,
    on_tool_stuck: Optional[OnToolStuckCallback] = None,
    log_dir: Optional[str] = None,
    system_message: Optional[str] = None,
    on_tool_start: Optional[OnToolStartHook] = None,
    on_tool_complete: Optional[OnToolCompleteHook] = None,
) -> dict:
    """
    Send a prompt to a session and wait for it to finish.

    Uses **activity-based waiting** instead of a hard timeout.
    The SDK emits events whenever the session is doing work (tool
    calls, messages, reasoning, etc.).  As long as events keep
    arriving, the session is alive and we keep waiting.

    Only when the session goes completely silent for
    ``inactivity_timeout`` seconds do we send a nudge.  After
    ``max_idle_nudges`` consecutive nudges that get no response,
    we call ``session.abort()`` and return whatever partial results
    are available.

    A ``safety_timeout`` acts as an absolute ceiling that should
    almost never be hit in normal operation.

    Args:
        session:            A Copilot SDK session object.
        prompt:             The prompt text to send.
        label:              Label for log messages (e.g. "main-scan").
        nudge_message:      Message sent when the session goes silent.
                            Can be a static string or a callable that
                            returns the nudge text dynamically.
        inactivity_timeout: Seconds of no events before nudging.
        max_idle_nudges:    Max consecutive unresponsive nudges.
        safety_timeout:     Absolute max runtime (safety net).
        on_tool_stuck:      Async callback for stuck-tool decisions.
        log_dir:            Directory for session log files.
        system_message:     System message text (for logging only).
        on_tool_start:      Optional hook called on TOOL_EXECUTION_START.
                            Receives (tool_name, detail, args, tool_call_id).
        on_tool_complete:   Optional hook called on TOOL_EXECUTION_COMPLETE.
                            Receives (tool_name, detail, output, tool_call_id).

    Returns:
        A dict with keys:
        - "status":  "success", "timeout", or "error"
        - "content": Assistant's response text (may be None)
        - "error":   Error message (may be None)
    """
    # State tracked inside the event handler closure
    final_response: dict = {"content": None}
    session_complete = asyncio.Event()
    session_error: dict = {"error": None, "transient": False}

    # Activity tracking — any SDK event resets this timer and clears
    # the consecutive nudge counter, because the session is alive.
    last_activity_time: dict = {"value": time.time()}
    consecutive_idle_nudges: dict = {"value": 0}

    # ── Session file logger ──────────────────────────────────────
    slog: Optional[SessionLogger] = None
    if log_dir:
        slog = SessionLogger(run_dir=log_dir, session_label=label)
        if system_message:
            slog.log_system_message(system_message)

    # ── Tool health monitor ──────────────────────────────────────
    tool_monitor = ToolHealthMonitor(
        agent_label=label,
        concern_threshold=inactivity_timeout,
    )

    def handle_event(event):
        """Handle events from this session."""
        try:
            # ── Activity tracking ────────────────────────────
            if _is_activity_event(event):
                last_activity_time["value"] = time.time()
                consecutive_idle_nudges["value"] = 0

            # ── Specific event handling ──────────────────────
            if event.type == SessionEventType.TOOL_EXECUTION_START:
                tool_name = getattr(event.data, "tool_name", "unknown")
                tool_call_id = getattr(
                    event.data, "tool_call_id", None
                )

                # Extract tool arguments and detail
                tool_args = extract_tool_arguments(event.data)
                detail = extract_tool_detail(tool_name, tool_args)

                # Register with the health monitor
                if tool_call_id:
                    tool_monitor.tool_started(
                        tool_call_id, tool_name, detail,
                    )

                # Log to session file
                if slog:
                    slog.log_tool_start(
                        tool_name=tool_name,
                        detail=detail,
                        args=tool_args,
                        tool_call_id=tool_call_id,
                    )

                # Call the optional custom hook
                if on_tool_start:
                    try:
                        on_tool_start(
                            tool_name, detail, tool_args, tool_call_id,
                        )
                    except Exception:
                        pass

                logger.debug(
                    f"[{label}] Tool started: {tool_name}"
                    + (f" ({detail})" if detail else "")
                )

            elif event.type == SessionEventType.TOOL_EXECUTION_COMPLETE:
                tool_call_id = getattr(
                    event.data, "tool_call_id", None
                )

                # Extract output and let the monitor check for errors
                output = extract_tool_output(event.data)
                tool_name = getattr(
                    event.data, "tool_name", "unknown"
                )
                # B1: Populate detail from tool arguments so the
                # on_tool_complete hook and log messages show which
                # skill / command finished (not just the tool name).
                tool_args = extract_tool_arguments(event.data)
                detail = extract_tool_detail(tool_name, tool_args)

                if tool_call_id:
                    errors = tool_monitor.tool_completed(
                        tool_call_id, output,
                    )
                    if errors:
                        progress_tracker = get_global_tracker()
                        for err in errors:
                            logger.warning(
                                f"[{label}] Tool error: "
                                f"{err.error_type} — "
                                f"{err.error_snippet[:80]}"
                            )
                            if slog:
                                slog.log_tool_error(
                                    err.tool_name,
                                    err.error_type,
                                    err.error_snippet,
                                )
                            if progress_tracker:
                                progress_tracker.emit_warning(
                                    f"{label}: tool '{err.tool_name}' "
                                    f"error — {err.error_type}: "
                                    f"{err.error_snippet[:60]}"
                                )

                # Log tool completion to session file
                if slog:
                    slog.log_tool_complete(
                        tool_name=tool_name,
                        output=output,
                        tool_call_id=tool_call_id,
                    )

                # Call the optional custom hook
                if on_tool_complete:
                    try:
                        on_tool_complete(
                            tool_name, detail, output, tool_call_id,
                        )
                    except Exception:
                        pass

                logger.debug(f"[{label}] Tool completed")

            elif event.type == SessionEventType.ASSISTANT_MESSAGE:
                if event.data and hasattr(event.data, "content"):
                    content = event.data.content
                    if content:
                        final_response["content"] = content
                        if slog:
                            slog.log_assistant_message(content)

            elif event.type == SessionEventType.SESSION_IDLE:
                logger.debug(f"[{label}] Session idle")
                if slog:
                    slog.log_session_idle()
                session_complete.set()

            elif event.type == SessionEventType.SESSION_ERROR:
                error_msg = (
                    str(event.data) if event.data else "Unknown error"
                )
                # B1: Classify the error.  Transient errors (rate
                # limits, 5xx) are stored separately so the wait loop
                # can retry instead of immediately aborting.
                if _is_transient_error(error_msg):
                    logger.warning(
                        f"[{label}] Transient session error: "
                        f"{error_msg}"
                    )
                    if slog:
                        slog.log_session_error(
                            f"TRANSIENT: {error_msg}"
                        )
                    session_error["error"] = error_msg
                    session_error["transient"] = True
                    session_complete.set()
                else:
                    logger.error(
                        f"[{label}] Session error: {error_msg}"
                    )
                    if slog:
                        slog.log_session_error(error_msg)
                    session_error["error"] = error_msg
                    session_error["transient"] = False
                    session_complete.set()

        except Exception as handler_err:
            logger.debug(
                f"[{label}] Event handler error: {handler_err}"
            )

    # Register the handler and send the prompt.
    # Capture the unsubscribe function for proper cleanup (B5).
    unsubscribe = session.on(handle_event)

    if slog:
        slog.log_prompt_sent(prompt)

    # Send the prompt with explicit error handling (B2).
    # If send() itself fails (session destroyed, connection lost),
    # we return immediately with a clear error instead of entering
    # the wait loop and timing out after inactivity_timeout seconds.
    try:
        await session.send(MessageOptions(prompt=prompt))
    except Exception as send_error:
        logger.error(
            f"[{label}] Failed to send prompt: {send_error}"
        )
        unsubscribe()
        if slog:
            slog.log_session_error(f"send() failed: {send_error}")
            slog.close()
        return {
            "status": "error",
            "content": None,
            "error": f"Failed to send prompt to session: {send_error}",
        }

    # ── Wait loop with activity-based detection ──────────────────
    start_time = time.time()

    while True:
        elapsed = time.time() - start_time

        # Safety ceiling
        if elapsed >= safety_timeout:
            logger.warning(
                f"[{label}] Safety timeout reached after "
                f"{int(elapsed)}s — aborting session"
            )
            if slog:
                slog.log_session_abort(
                    f"Safety timeout after {int(elapsed)}s"
                )
                slog.close()
            unsubscribe()
            await abort_session(session, label)
            return {
                "status": "timeout",
                "content": final_response["content"],
                "error": (
                    f"Safety timeout after {int(elapsed)}s"
                    + (
                        " (partial results available)"
                        if final_response["content"]
                        else ""
                    )
                ),
            }

        # Poll: wait a short interval for the session to complete
        poll_interval = min(5.0, safety_timeout - elapsed)
        try:
            await asyncio.wait_for(
                session_complete.wait(),
                timeout=poll_interval,
            )
            break  # Session completed
        except asyncio.TimeoutError:
            pass

        # ── Tool health checks ────────────────────────────────
        stuck_tools = tool_monitor.get_stuck_tools()
        for stuck_info in stuck_tools:
            logger.warning(f"[{label}] {stuck_info.message}")

            progress_tracker = get_global_tracker()
            if progress_tracker:
                progress_tracker.emit_warning(stuck_info.message)

            if on_tool_stuck:
                try:
                    action = await on_tool_stuck(stuck_info)
                except Exception as cb_err:
                    logger.debug(
                        f"[{label}] Stuck tool callback "
                        f"error: {cb_err}"
                    )
                    action = StuckToolAction.WAIT

                if action == StuckToolAction.TERMINATE:
                    logger.warning(
                        f"[{label}] User chose to terminate "
                        f"due to stuck tool: {stuck_info.detail}"
                    )
                    if slog:
                        slog.log_stuck_tool(
                            stuck_info.tool_name,
                            stuck_info.detail,
                            stuck_info.elapsed_seconds,
                            "terminate",
                        )
                        slog.close()
                    unsubscribe()
                    await abort_session(session, label)
                    return {
                        "status": "timeout",
                        "content": final_response["content"],
                        "error": (
                            f"Terminated by user: tool "
                            f"'{stuck_info.detail or stuck_info.tool_name}' "
                            f"appeared stuck after "
                            f"{int(stuck_info.elapsed_seconds)}s"
                        ),
                    }
                else:
                    if slog:
                        slog.log_stuck_tool(
                            stuck_info.tool_name,
                            stuck_info.detail,
                            stuck_info.elapsed_seconds,
                            "wait",
                        )
                    tool_monitor.reset_alert(
                        stuck_info.tool_call_id
                    )

        # Check for retry loops
        looping_tool = tool_monitor.has_any_retry_loop()
        if looping_tool:
            logger.warning(
                f"[{label}] Tool '{looping_tool}' is in a retry "
                f"loop (failing repeatedly) — aborting session"
            )
            if slog:
                slog.log_retry_loop(looping_tool)
                slog.close()
            progress_tracker = get_global_tracker()
            if progress_tracker:
                progress_tracker.emit_warning(
                    f"{label}: tool '{looping_tool}' failed "
                    f"multiple times — terminating"
                )
            unsubscribe()
            await abort_session(session, label)
            return {
                "status": "error",
                "content": final_response["content"],
                "error": (
                    f"Tool '{looping_tool}' entered a retry loop "
                    f"(failed {MAX_TOOL_RETRIES_BEFORE_LOOP}+ times "
                    f"with errors). The tool may be misconfigured "
                    f"or missing required dependencies."
                ),
            }

        # Check for excessive total errors
        total_errors = tool_monitor.has_excessive_errors()
        if total_errors:
            logger.warning(
                f"[{label}] Session has {total_errors} total errors "
                f"across different commands — aborting session"
            )
            if slog:
                slog.log_warning(
                    f"Excessive errors ({total_errors} total) — aborting"
                )
                slog.close()
            progress_tracker = get_global_tracker()
            if progress_tracker:
                progress_tracker.emit_warning(
                    f"{label}: {total_errors} tool errors across "
                    f"multiple commands — terminating"
                )
            unsubscribe()
            await abort_session(session, label)
            return {
                "status": "error",
                "content": final_response["content"],
                "error": (
                    f"Session accumulated {total_errors} tool errors "
                    f"across multiple different commands. The scanner "
                    f"appears fundamentally unable to run in this "
                    f"environment."
                ),
            }

        # ── Inactivity detection ─────────────────────────────
        time_since_activity = (
            time.time() - last_activity_time["value"]
        )

        if time_since_activity >= inactivity_timeout:
            if consecutive_idle_nudges["value"] >= max_idle_nudges:
                logger.warning(
                    f"[{label}] Unresponsive after "
                    f"{max_idle_nudges} nudges with no activity "
                    f"— aborting session"
                )
                if slog:
                    slog.log_session_abort(
                        f"Unresponsive after {max_idle_nudges} nudges"
                    )
                    slog.close()
                unsubscribe()
                await abort_session(session, label)
                return {
                    "status": "timeout",
                    "content": final_response["content"],
                    "error": (
                        f"Session unresponsive after "
                        f"{max_idle_nudges} consecutive nudges"
                    ),
                }

            # Resolve the nudge text (may be a callable or static)
            actual_nudge = None
            if callable(nudge_message):
                try:
                    actual_nudge = nudge_message()
                except Exception:
                    actual_nudge = None
            elif nudge_message:
                actual_nudge = nudge_message

            if actual_nudge:
                consecutive_idle_nudges["value"] += 1
                logger.warning(
                    f"[{label}] No activity for "
                    f"{int(time_since_activity)}s — sending nudge "
                    f"({consecutive_idle_nudges['value']}"
                    f"/{max_idle_nudges})"
                )
                try:
                    await session.send(
                        MessageOptions(prompt=actual_nudge)
                    )
                    if slog:
                        slog.log_nudge_sent(actual_nudge)
                    last_activity_time["value"] = time.time()
                except Exception as nudge_err:
                    logger.debug(
                        f"[{label}] Nudge failed: {nudge_err}"
                    )
            else:
                logger.warning(
                    f"[{label}] No activity for "
                    f"{int(time_since_activity)}s (no nudge configured)"
                )

    # ── Build return value ───────────────────────────────────────
    # Unsubscribe event handler and close session logger
    unsubscribe()
    if slog:
        slog.close()

    # B1: If the error is transient (rate limit, 5xx), retry with
    # exponential backoff instead of immediately returning an error.
    if session_error["error"] and session_error.get("transient"):
        # This is a transient error — the caller may want to retry.
        # We return a special "transient_error" flag so callers can
        # distinguish retryable from permanent failures.
        return {
            "status": "error",
            "content": final_response["content"],
            "error": session_error["error"],
            "transient": True,
        }

    if session_error["error"]:
        return {
            "status": "error",
            "content": final_response["content"],
            "error": session_error["error"],
        }

    if final_response["content"]:
        return {
            "status": "success",
            "content": final_response["content"],
            "error": None,
        }

    return {
        "status": "error",
        "content": None,
        "error": "No response received from session",
    }


async def run_session_with_retries(
    session_or_factory,
    prompt: str,
    max_retries: int = MAX_TRANSIENT_RETRIES,
    base_delay: float = TRANSIENT_RETRY_BASE_DELAY,
    **kwargs,
) -> dict:
    """
    Run a session to completion with automatic retry for transient errors.

    Wraps ``run_session_to_completion`` and retries up to ``max_retries``
    times when the session returns a transient error (rate limit, 5xx).
    Uses exponential backoff between retries.

    A1 optimisation: accepts either a live session object OR an async
    callable that creates a fresh session.  When a factory is provided,
    each retry gets a new session so it doesn't try to reuse a session
    that may be in a broken state after a SESSION_ERROR.

    Non-transient errors and successful results are returned immediately
    without retrying.

    Args:
        session_or_factory:
            Either a Copilot SDK session object, or an async callable
            (no args) that returns a new session.  When a factory is
            provided the session is destroyed after each failed attempt
            and a fresh one is created for the retry.
        prompt:      The prompt text to send.
        max_retries: Maximum number of automatic retries (default 3).
        base_delay:  Base delay in seconds for exponential backoff
                     (default 5s -> delays of 5s, 15s, 45s).
        **kwargs:    All other arguments are passed through to
                     ``run_session_to_completion``.

    Returns:
        Same dict as ``run_session_to_completion``.
    """
    label = kwargs.get("label", "session")
    is_factory = callable(session_or_factory)

    session = None
    result = None

    try:
        for attempt in range(max_retries + 1):
            # Obtain a session — either from the factory or use the one
            # provided directly.
            if is_factory:
                try:
                    session = await session_or_factory()
                except Exception as factory_err:
                    logger.error(
                        f"[{label}] Session factory failed: {factory_err}"
                    )
                    return {
                        "status": "error",
                        "content": None,
                        "error": f"Failed to create session: {factory_err}",
                    }
            else:
                session = session_or_factory

            result = await run_session_to_completion(
                session=session,
                prompt=prompt,
                **kwargs,
            )

            # If the result is not a transient error, return immediately
            if not result.get("transient"):
                return result

            # Transient error — should we retry?
            if attempt >= max_retries:
                logger.warning(
                    f"[{label}] Transient error after {max_retries} "
                    f"retries — giving up: {result['error']}"
                )
                # Remove the transient flag before returning
                result.pop("transient", None)
                return result

            # A1: If using a factory, destroy the broken session before
            # creating a fresh one for the next attempt.
            if is_factory and session is not None:
                await cleanup_session(session, label)
                session = None

            # Calculate delay with exponential backoff
            delay = base_delay * (3 ** attempt)
            logger.info(
                f"[{label}] Transient error (attempt {attempt + 1}/"
                f"{max_retries}), retrying in {delay:.0f}s: "
                f"{result['error']}"
            )

            await asyncio.sleep(delay)

        # Should not reach here, but just in case
        return result

    finally:
        # A1: Always clean up factory-created sessions, including
        # on the success path.  Without this, sessions created by
        # the factory on the final (successful) attempt would leak.
        if is_factory and session is not None:
            await cleanup_session(session, label)
