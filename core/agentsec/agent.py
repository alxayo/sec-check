"""
SecurityScannerAgent — the main agent class for AgentSec.

This module contains the SecurityScannerAgent class which uses the
GitHub Copilot SDK to analyze code for security vulnerabilities.
Both the CLI and the Desktop app import this class.

Usage:
    # Using default configuration
    agent = SecurityScannerAgent()
    try:
        await agent.initialize()
        result = await agent.scan("./my_project")
        print(result)
    finally:
        await agent.cleanup()
    
    # Using custom configuration
    from agentsec.config import AgentSecConfig
    config = AgentSecConfig.load("./agentsec.yaml")
    agent = SecurityScannerAgent(config=config)
"""

import asyncio
import json
import logging
import os
import time
from typing import Optional

from copilot import CopilotClient, SessionConfig, MessageOptions
from copilot.session import SessionEventType
from dotenv import load_dotenv

from agentsec.config import AgentSecConfig
from agentsec.progress import get_global_tracker

# Load environment variables from .env file at the workspace root
load_dotenv()

# Set up logging
logger = logging.getLogger(__name__)

# ── Timeout & stall-detection constants ──────────────────────────────
# These control how long the agent waits before deciding the LLM is
# stuck or the scan is finished.

# Maximum total wall-clock time for a scan (seconds).
# 300 s is enough for ~5 000 files; callers can override via the
# ``timeout`` parameter on scan().
DEFAULT_SCAN_TIMEOUT_SECONDS = 300.0

# If no tool call starts or completes for this many seconds after
# the last tool activity, we consider the LLM "stalled" and send
# a nudge message asking it to wrap up.
# 45 s gives the LLM enough time to begin composing a report or
# transition between scanning phases without triggering a false
# nudge, while still catching genuine stalls quickly.
STALL_DETECTION_SECONDS = 45.0

# The "skill" tool is the primary security scanning mechanism.
# We track whether it has been invoked so we can nudge the LLM
# if it is not using the security scanning skills.
# "bash" running scanner commands (bandit, graudit, etc.) also counts.
SCANNING_TOOL_NAMES = {"skill"}


def _extract_tool_arguments(event_data) -> dict:
    """
    Try to extract tool arguments from Copilot SDK event data.

    The SDK may provide tool arguments in different formats depending
    on the version. This function tries multiple attribute names and
    handles both dict and JSON string formats safely.

    Args:
        event_data: The event data from a TOOL_EXECUTION_START event

    Returns:
        A dictionary of tool arguments, or empty dict if not available
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


class SecurityScannerAgent:
    """
    Main security scanning agent for AgentSec.

    This agent connects to the GitHub Copilot SDK, creates a session,
    and uses Copilot CLI built-in tools (bash, skill, view) to scan
    code for security vulnerabilities.

    The agent follows a simple lifecycle:
        1. __init__()    — create the agent object (no connections yet)
        2. initialize()  — connect to Copilot and create a session
        3. scan()        — run a security scan on a folder
        4. cleanup()     — disconnect and free resources

    Example:
        >>> # With default configuration
        >>> agent = SecurityScannerAgent()
        >>> try:
        ...     await agent.initialize()
        ...     result = await agent.scan("./src")
        ...     print(result["status"])
        ... finally:
        ...     await agent.cleanup()
        
        >>> # With custom configuration
        >>> from agentsec.config import AgentSecConfig
        >>> config = AgentSecConfig.load("./agentsec.yaml")
        >>> agent = SecurityScannerAgent(config=config)
    """

    def __init__(self, config: Optional[AgentSecConfig] = None) -> None:
        """
        Initialize the agent object with optional configuration.

        This does NOT connect to Copilot yet. Call initialize() to connect.
        
        Args:
            config: Optional AgentSecConfig instance. If not provided,
                    default configuration will be used.
        """
        self.client: Optional[CopilotClient] = None
        self.session = None

        # Map of tool_call_id → {name, detail, file_path} for tracking
        # which SDK tools are being executed during a scan
        self._tool_call_map: dict = {}

        # Use provided config or create default
        self.config = config if config is not None else AgentSecConfig()

    async def initialize(self) -> None:
        """
        Connect to Copilot and create a session.

        This method must be called before using scan(). It:
        1. Creates a CopilotClient (connection to Copilot CLI)
        2. Starts the client
        3. Creates a session with agent instructions

        Raises:
            FileNotFoundError: If Copilot CLI is not installed
            ConnectionError: If authentication fails
        """
        try:
            # Create the client that talks to Copilot CLI
            self.client = CopilotClient()
            await self.client.start()

            # Create a session (a conversation context)
            # The system_message tells the LLM what its role is
            # This uses the system_message from configuration
            self.session = await self.client.create_session(
                SessionConfig(
                    model="gpt-5",
                    system_message={"content": self.config.system_message},
                )
            )

            logger.info("SecurityScannerAgent initialized successfully")
            logger.debug(f"Using system message: {self.config.system_message[:100]}...")

        except FileNotFoundError:
            logger.error(
                "Copilot CLI not found. "
                "Install it: https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli"
            )
            raise
        except Exception as error:
            logger.error(f"Failed to initialize agent: {error}")
            raise

    async def scan(self, folder_path: str, timeout: Optional[float] = None) -> dict:
        """
        Run a security scan on a folder.

        This sends a prompt to the LLM asking it to scan the given folder.
        The LLM will use Copilot CLI built-in tools (bash, skill, view)
        automatically based on its instructions.

        Uses an event-driven approach so that tool executions (which emit
        progress events) happen in real time rather than being blocked.

        The method also detects when the LLM "stalls" (stops calling tools
        for too long) and sends a nudge message to get it back on track.

        Args:
            folder_path: Path to the folder to scan.
                         Example: "./src" or "C:\\code\\myapp"
            timeout:     Maximum seconds to wait for the scan to finish.
                         Defaults to DEFAULT_SCAN_TIMEOUT_SECONDS (300 s).

        Returns:
            A dictionary with:
            - "status": "success", "timeout", or "error"
            - "result": The scan output (if successful)
            - "error": Error description (if failed)

        Example:
            >>> result = await agent.scan("./src")
            >>> if result["status"] == "success":
            ...     print(result["result"])
        """
        # Make sure the agent was initialized first
        if not self.session:
            return {
                "status": "error",
                "error": "Agent not initialized. Call initialize() first.",
            }

        # Use default timeout if none provided
        if timeout is None:
            timeout = DEFAULT_SCAN_TIMEOUT_SECONDS

        try:
            # Build the scan prompt using the configured template
            # The format_prompt method replaces {folder_path} placeholders
            scan_prompt = self.config.format_prompt(folder_path)

            logger.info(f"Starting scan of {folder_path}")
            logger.debug(f"Using prompt: {scan_prompt[:200]}...")
            logger.debug(f"Scan timeout: {timeout}s, stall detection: {STALL_DETECTION_SECONDS}s")

            # We collect the assistant's final response and track completion
            final_response = {"content": None}
            scan_complete = asyncio.Event()
            scan_error = {"error": None}

            # Reset tool call tracking for this scan
            self._tool_call_map = {}

            # ── Stall & custom-tool tracking state ───────────────
            # last_tool_activity_time tracks when the last tool started
            # or completed (wall-clock). If this gets too far in the past,
            # we send a nudge to the LLM.
            last_tool_activity_time = {"value": time.time()}

            # Track whether the LLM has invoked security scanning skills.
            # If it only uses view/bash without running scanners, we nudge it.
            scanner_was_invoked = {"value": False}

            # Track how many nudges we've sent so we don't spam.
            nudge_count = {"value": 0}
            MAX_NUDGES = 2

            # Define event handler for session events
            # This receives ALL events emitted by the Copilot session
            def handle_event(event):
                """
                Handle events from the Copilot session.

                This callback is invoked for every event the session emits,
                including tool calls, assistant messages, and idle signals.
                We log every event at DEBUG level for troubleshooting.
                """
                # Log every event so we can debug what the SDK is doing
                event_type_str = "unknown"
                if hasattr(event, 'type'):
                    event_type_str = str(event.type)
                    # Also try .value for enum types
                    if hasattr(event.type, 'value'):
                        event_type_str = event.type.value

                logger.debug(f"[EVENT] type={event_type_str}")

                # Log event data if present
                if hasattr(event, 'data') and event.data is not None:
                    data_str = str(event.data)
                    # Truncate long data for readability
                    if len(data_str) > 300:
                        data_str = data_str[:300] + "..."
                    logger.debug(f"[EVENT] data={data_str}")

                # Check event type using the proper SDK enum
                try:
                    # Tool execution started — shows the LLM is calling a skill
                    if event.type == SessionEventType.TOOL_EXECUTION_START:
                        # Record tool activity timestamp for stall detection
                        last_tool_activity_time["value"] = time.time()

                        tool_name = getattr(event.data, 'tool_name', 'unknown')
                        tool_call_id = getattr(
                            event.data, 'tool_call_id', None
                        )

                        # Extract tool arguments FIRST so they are available
                        # for all subsequent checks (scanner detection, detail
                        # extraction, etc.)
                        tool_args = _extract_tool_arguments(event.data)

                        # Check if the LLM is using security scanners
                        if tool_name in SCANNING_TOOL_NAMES:
                            scanner_was_invoked["value"] = True

                        # Also count bash invocations of scanner tools
                        # (e.g., bandit, graudit, trivy run directly)
                        if tool_name == "bash" and tool_args:
                            cmd = tool_args.get("command", "")
                            scanner_cmds = {
                                "bandit", "graudit", "guarddog",
                                "shellcheck", "trivy", "checkov",
                                "eslint", "dependency-check",
                            }
                            first_word = cmd.strip().split()[0] if cmd.strip() else ""
                            if first_word in scanner_cmds:
                                scanner_was_invoked["value"] = True

                        # Extract detail about what specific file, command,
                        # or skill is being used for richer log messages
                        detail = ""
                        file_path = None

                        if tool_name == "view" and tool_args:
                            # The "view" tool reads a file — track as file scan
                            file_path = tool_args.get(
                                "path",
                                tool_args.get(
                                    "file_path",
                                    tool_args.get("filePath", ""),
                                ),
                            )
                            if file_path:
                                detail = os.path.basename(file_path)
                        elif tool_name == "bash" and tool_args:
                            # Extract the command being run (e.g., bandit)
                            command = tool_args.get("command", "")
                            if command:
                                cmd_parts = command.strip().split()
                                if cmd_parts:
                                    detail = cmd_parts[0]
                        elif tool_name == "skill" and tool_args:
                            # Extract the skill name being invoked
                            # The Copilot CLI "skill" tool wraps external
                            # agentic skills (e.g., bandit, graudit, trivy).
                            # We surface the actual skill name so the user
                            # can see which scanner is running.
                            skill_name = tool_args.get(
                                "name",
                                tool_args.get(
                                    "skill_name",
                                    tool_args.get("skillName", ""),
                                ),
                            )
                            if skill_name:
                                detail = skill_name

                        # Store mapping so we can resolve names on completion
                        if tool_call_id:
                            self._tool_call_map[tool_call_id] = {
                                "name": tool_name,
                                "detail": detail,
                                "file_path": file_path,
                            }

                        # Update progress tracker for file reads (view tool)
                        # Only track actual files, not directories
                        if tool_name == "view" and file_path:
                            # Check if it's a directory by looking for file extension
                            # or checking if the basename has a dot
                            is_likely_file = "." in os.path.basename(file_path)
                            if is_likely_file:
                                tracker = get_global_tracker()
                                if tracker:
                                    tracker.start_file(file_path)

                        # Log with detail for better visibility.
                        # For the "skill" tool we surface the external skill
                        # name prominently so operators can see which scanner
                        # the LLM chose to invoke.
                        if tool_name == "skill" and detail:
                            logger.info(
                                f"  -> Skill invoked: {detail}"
                            )
                        elif detail:
                            logger.info(
                                f"  -> Tool started: {tool_name} ({detail})"
                            )
                        else:
                            logger.info(f"  -> Tool started: {tool_name}")

                    # Tool execution completed
                    elif event.type == SessionEventType.TOOL_EXECUTION_COMPLETE:
                        # Record tool activity timestamp for stall detection
                        last_tool_activity_time["value"] = time.time()

                        tool_call_id = getattr(
                            event.data, 'tool_call_id', 'unknown'
                        )

                        # Look up the tool name from our tracking map.
                        # If the start event was not captured (e.g., the
                        # SDK emitted a completion for a tool we never
                        # saw start), we try to read the tool_name
                        # directly from the completion event data.
                        tool_info = self._tool_call_map.pop(
                            tool_call_id, None
                        )
                        if tool_info:
                            tool_name = tool_info.get("name", "unknown")
                            detail = tool_info.get("detail", "")
                            file_path = tool_info.get("file_path")
                        else:
                            # Fallback: try to read from the event itself
                            tool_name = getattr(
                                event.data, 'tool_name',
                                getattr(event.data, 'name', 'unknown')
                            )
                            detail = ""
                            file_path = None

                        # Update progress tracker when a file read completes
                        # Only track actual files, not directories
                        if tool_name == "view" and file_path:
                            # Check if it's a directory by looking for file extension
                            is_likely_file = "." in os.path.basename(file_path)
                            if is_likely_file:
                                tracker = get_global_tracker()
                                if tracker:
                                    tracker.finish_file(file_path, issues_found=0)

                        # Log with tool name instead of opaque ID.
                        # For the "skill" tool we show the skill name
                        # to match the "Skill invoked" start message.
                        if tool_name == "skill" and detail:
                            logger.info(
                                f"  <- Skill completed: {detail}"
                            )
                        elif detail:
                            logger.info(
                                f"  <- Tool completed: {tool_name} ({detail})"
                            )
                        else:
                            logger.info(f"  <- Tool completed: {tool_name}")

                    # Assistant message — the LLM's text response
                    elif event.type == SessionEventType.ASSISTANT_MESSAGE:
                        # Count assistant messages as activity.
                        # When the LLM is generating a report it streams
                        # text without calling tools.  That is productive
                        # work, not a stall, so we reset the timer here
                        # to avoid false nudges during report generation.
                        last_tool_activity_time["value"] = time.time()

                        if event.data and hasattr(event.data, 'content'):
                            content = event.data.content
                            logger.debug(f"[ASSISTANT] {content[:200] if content else '(empty)'}...")
                            # Keep overwriting — the last message is the final answer
                            final_response["content"] = content

                    # Session idle — all processing is done
                    elif event.type == SessionEventType.SESSION_IDLE:
                        logger.info("Session idle — scan processing complete")
                        scan_complete.set()

                    # Session error
                    elif event.type == SessionEventType.SESSION_ERROR:
                        error_msg = str(event.data) if event.data else "Unknown error"
                        logger.error(f"[SESSION ERROR] {error_msg}")
                        scan_error["error"] = error_msg
                        scan_complete.set()

                except Exception as handler_error:
                    # Catch ALL exceptions so a single bad event never
                    # crashes the entire event loop.  Log at debug level
                    # because most of these are harmless SDK quirks.
                    logger.debug(
                        f"[EVENT] Error handling event "
                        f"{event_type_str}: {handler_error}"
                    )

                # Also check for error events
                try:
                    if hasattr(event, 'type') and hasattr(event.type, 'value'):
                        type_val = event.type.value.lower()
                        if 'error' in type_val and not scan_error["error"]:
                            error_msg = str(event.data) if event.data else "Unknown error"
                            logger.error(f"[EVENT ERROR] {error_msg}")
                            scan_error["error"] = error_msg
                            scan_complete.set()
                except Exception:
                    pass

            # Register the event handler on the session
            logger.debug("Registering event handler on session...")
            self.session.on(handle_event)

            # Send the prompt using non-blocking send()
            # The LLM will process the prompt, call tools, and eventually go idle
            logger.debug("Sending scan prompt via session.send()...")
            await self.session.send(MessageOptions(prompt=scan_prompt))
            logger.debug("Prompt sent, waiting for session.idle event...")

            # ── Wait loop with stall detection ───────────────────
            # Instead of a single asyncio.wait_for(), we poll in a loop
            # so we can detect stalls and send nudge messages.
            scan_start_time = time.time()

            while True:
                # How much total time has elapsed?
                elapsed = time.time() - scan_start_time
                remaining = timeout - elapsed

                if remaining <= 0:
                    # Hard timeout reached
                    logger.error(
                        f"Scan timed out after {int(elapsed)} seconds. "
                        "The session never became idle."
                    )
                    # Return whatever partial result we have
                    if final_response["content"]:
                        return {
                            "status": "timeout",
                            "result": final_response["content"],
                            "error": (
                                f"Scan timed out after {int(elapsed)}s but "
                                "partial results are available."
                            ),
                        }
                    return {
                        "status": "timeout",
                        "error": (
                            f"Scan took too long (>{int(timeout)}s). "
                            "The LLM did not complete the analysis. "
                            "Try a smaller folder or check --verbose logs."
                        ),
                    }

                # Wait for scan_complete with a short poll interval
                # so we can check for stalls periodically
                poll_interval = min(5.0, remaining)
                try:
                    await asyncio.wait_for(
                        scan_complete.wait(), timeout=poll_interval
                    )
                    # scan_complete was set — break out of the loop
                    break
                except asyncio.TimeoutError:
                    # scan_complete not yet set — check for stall
                    pass

                # ── Stall detection ──────────────────────────────
                time_since_last_tool = (
                    time.time() - last_tool_activity_time["value"]
                )

                if (
                    time_since_last_tool >= STALL_DETECTION_SECONDS
                    and nudge_count["value"] < MAX_NUDGES
                ):
                    nudge_count["value"] += 1

                    # Decide what nudge to send based on whether
                    # security scanners have been invoked
                    if not scanner_was_invoked["value"]:
                        # The LLM has not run any security scanners yet.
                        nudge_message = (
                            "You should use the skill tool to run security "
                            "scanners. Invoke skills like bandit-security-scan "
                            "and graudit-security-scan to analyze the code in "
                            f"{folder_path}. You can also run scanners directly "
                            "via bash (e.g., bandit, graudit)."
                        )
                        logger.warning(
                            f"LLM has not invoked any security scanners after "
                            f"{int(time_since_last_tool)}s — sending nudge "
                            f"(#{nudge_count['value']})"
                        )
                    else:
                        # Scanners were run but the LLM seems stuck.
                        # The most common cause is the LLM composing a
                        # lengthy report as pure text without tool calls.
                        # We nudge it to write the report to a file via
                        # bash so that tool activity is generated and
                        # progress stays visible.
                        nudge_message = (
                            "If you have completed scanning, use bash to "
                            "write your findings into a Markdown report "
                            "file in the target folder (e.g. "
                            "cat > report.md << 'REPORT' ... REPORT). "
                            "Then provide a brief summary and stop. "
                            "If more scanning is needed, continue using "
                            "the skill tool or bash to run additional scanners."
                        )
                        logger.warning(
                            f"No tool activity for {int(time_since_last_tool)}s "
                            f"— sending progress nudge (#{nudge_count['value']})"
                        )

                    # Send the nudge as a follow-up message in the session
                    try:
                        await self.session.send(
                            MessageOptions(prompt=nudge_message)
                        )
                        # Reset the activity timer after sending a nudge
                        last_tool_activity_time["value"] = time.time()
                    except Exception as nudge_error:
                        logger.debug(f"Failed to send nudge: {nudge_error}")

            # Check if there was an error
            if scan_error["error"]:
                return {
                    "status": "error",
                    "error": scan_error["error"],
                }

            # Check if we got a response
            if final_response["content"]:
                logger.info(f"Scan completed for {folder_path}")
                return {
                    "status": "success",
                    "result": final_response["content"],
                }
            else:
                logger.warning(
                    "Session went idle but no assistant message was captured. "
                    "The LLM may not have produced a text response."
                )
                return {
                    "status": "error",
                    "error": "No response received from Copilot",
                }

        except Exception as error:
            logger.error(f"Scan failed with exception: {error}", exc_info=True)
            return {
                "status": "error",
                "error": str(error),
            }

    async def scan_parallel(
        self,
        folder_path: str,
        timeout: Optional[float] = None,
        max_concurrent: int = 3,
    ) -> dict:
        """
        Run a security scan using parallel sub-agent sessions.

        Instead of a single LLM session that calls scanners one-by-one,
        this method uses the ParallelScanOrchestrator to:

        1. **Discover** which scanners are relevant for the folder (Python,
           no LLM call).
        2. **Run** N sub-agent sessions in parallel, each executing one
           scanner via the ``skill`` or ``bash`` tool.
        3. **Synthesise** all sub-agent findings into a single consolidated
           Markdown report via a synthesis LLM session.

        The method requires only the CopilotClient to be started (via
        ``initialize()``) — the orchestrator creates its own sessions.

        Args:
            folder_path:    Path to the folder to scan.
            timeout:        Maximum wall-clock seconds for the entire scan
                            (discovery + parallel scan + synthesis).
                            Defaults to DEFAULT_SCAN_TIMEOUT_SECONDS (300 s).
            max_concurrent: Maximum sub-agent sessions running at the same
                            time.  Default is 3 to stay within typical API
                            rate limits.

        Returns:
            A dictionary with:
            - "status": "success", "timeout", or "error"
            - "result": Consolidated Markdown report (if successful)
            - "error":  Error description (if failed)

        Example:
            >>> result = await agent.scan_parallel("./src", max_concurrent=4)
            >>> if result["status"] == "success":
            ...     print(result["result"])
        """
        # The parallel scan only needs the client, not the main session.
        if not self.client:
            return {
                "status": "error",
                "error": "Agent not initialized. Call initialize() first.",
            }

        if timeout is None:
            timeout = DEFAULT_SCAN_TIMEOUT_SECONDS

        try:
            # Import here to avoid circular imports and keep the
            # orchestrator as an optional component.
            from agentsec.orchestrator import ParallelScanOrchestrator

            orchestrator = ParallelScanOrchestrator(
                client=self.client,
                config=self.config,
                max_concurrent=max_concurrent,
            )

            logger.info(
                f"Starting parallel scan of {folder_path} "
                f"(max_concurrent={max_concurrent}, timeout={timeout}s)"
            )

            result = await orchestrator.run(
                folder_path=folder_path,
                timeout=timeout,
            )

            return result

        except Exception as error:
            logger.error(
                f"Parallel scan failed: {error}", exc_info=True
            )
            return {
                "status": "error",
                "error": str(error),
            }

    async def cleanup(self) -> None:
        """
        Disconnect from Copilot and free all resources.

        This method MUST be called when you are done with the agent.
        Use it in a finally block to guarantee cleanup even if errors occur.

        Example:
            >>> try:
            ...     await agent.initialize()
            ...     await agent.scan("./src")
            ... finally:
            ...     await agent.cleanup()
        """
        try:
            # Destroy the session if it exists
            if self.session:
                try:
                    await asyncio.wait_for(self.session.destroy(), timeout=5.0)
                except asyncio.TimeoutError:
                    logger.warning("Session destroy timed out")
                except Exception as e:
                    logger.warning(f"Error destroying session: {e}")
                finally:
                    self.session = None

            # Stop the client if it exists
            if self.client:
                try:
                    await asyncio.wait_for(self.client.stop(), timeout=5.0)
                except asyncio.TimeoutError:
                    logger.warning("Client stop timed out")
                except Exception as e:
                    logger.warning(f"Error stopping client: {e}")
                finally:
                    self.client = None

            logger.info("SecurityScannerAgent cleaned up successfully")

        except Exception as error:
            # Log but don't re-raise — cleanup should not crash the app
            logger.error(f"Error during cleanup: {error}")
