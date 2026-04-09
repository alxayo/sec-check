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
import logging
import os
import time
from typing import Optional

from copilot import CopilotClient, PermissionRequestResult
from dotenv import load_dotenv

from agentsec.config import AgentSecConfig
from agentsec.progress import get_global_tracker
from agentsec.session_runner import run_session_with_retries, abort_session
from agentsec.skill_discovery import (
    get_skill_directories,
    discover_all_skills,
    KNOWN_SCANNER_COMMANDS,
    SCANNER_RELEVANCE,
    classify_files,
    classify_file_list,
    is_scanner_relevant,
)
from agentsec.tool_health import (
    OnToolStuckCallback,
)

# Load environment variables from .env file at the workspace root
load_dotenv()

# Set up logging
logger = logging.getLogger(__name__)


def _auto_approve_permissions(request, context):
    """Auto-approve all tool permission requests from the Copilot SDK."""
    return PermissionRequestResult(kind="approved")

# ── Activity-based wait constants ────────────────────────────────────
#
# Instead of a hard timeout that cuts off long-running scans, we use
# an ACTIVITY-BASED approach.  The Copilot SDK emits events whenever
# the session is doing work (tool calls, messages, reasoning, etc.).
# As long as events keep arriving, the session is alive — we wait.
# Only when the session goes completely silent do we nudge, and after
# repeated unresponsive nudges we abort.

# Safety ceiling — maximum total wall-clock time for a scan (seconds).
# This is a catastrophic safety net that should almost never be hit.
# The activity-based detection handles the normal case.  1800 s (30
# minutes) is intentionally generous.  Callers can override via the
# ``timeout`` parameter on scan().
DEFAULT_SCAN_TIMEOUT_SECONDS = 1800.0

# Seconds of no SDK events before we consider the session stalled
# and send a nudge message.  120 s is generous enough for long-running
# tool calls (e.g. a single graudit or dependency-check invocation)
# which produce TOOL_EXECUTION_START at the beginning and
# TOOL_EXECUTION_COMPLETE at the end, with no events in between.
INACTIVITY_TIMEOUT_SECONDS = 120.0

# After this many consecutive nudges that receive NO activity response,
# we call session.abort() and return partial results.
MAX_CONSECUTIVE_IDLE_NUDGES = 3


class SecurityScannerAgent:
    """
    Main security scanning agent for AgentSec.

    This agent connects to the GitHub Copilot SDK, creates a session,
    and uses Copilot CLI built-in tools (bash, skill, view) to scan
    code for security vulnerabilities.

    The agent follows a simple lifecycle:
        1. __init__()    — create the agent object (no connections yet)
        2. initialize()  — connect to the Copilot CLI
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

        # Use provided config or create default
        self.config = config if config is not None else AgentSecConfig()

    async def initialize(self) -> None:
        """
        Connect to the Copilot CLI and prepare for scanning.

        This method must be called before using scan(). It:
        1. Creates a CopilotClient (connection to Copilot CLI)
        2. Starts the client
        3. Verifies connectivity
        4. Cleans up stale sessions

        Sessions are created per-scan (in scan()) so each scan gets
        a clean LLM context without accumulated history from previous
        scans (B1 optimisation).

        Raises:
            FileNotFoundError: If Copilot CLI is not installed
            ConnectionError: If authentication fails
        """
        try:
            # Create the client that talks to Copilot CLI
            self.client = CopilotClient()
            await self.client.start()

            # Verify the CLI server is responsive before proceeding.
            try:
                await self.client.ping("health check")
                logger.debug("Copilot CLI server connectivity verified")
            except Exception as ping_error:
                logger.warning(
                    f"Copilot CLI ping failed (non-fatal): {ping_error}"
                )

            # A2: Clean up stale sessions from previous runs.
            try:
                existing_sessions = await self.client.list_sessions()
                for sess_info in existing_sessions:
                    sid = getattr(sess_info, "session_id", "")
                    if sid and sid.startswith("agentsec-"):
                        try:
                            await self.client.delete_session(sid)
                            logger.debug(
                                f"Cleaned up stale session: {sid}"
                            )
                        except Exception:
                            pass
            except Exception as cleanup_err:
                logger.debug(
                    f"Stale session cleanup skipped: {cleanup_err}"
                )

            logger.info("SecurityScannerAgent initialized successfully")

        except FileNotFoundError:
            logger.error(
                "Copilot CLI not found. "
                "Install it: https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli"
            )
            raise
        except Exception as error:
            logger.error(f"Failed to initialize agent: {error}")
            raise

    async def scan(self, folder_path: str, timeout: Optional[float] = None, on_tool_stuck: Optional[OnToolStuckCallback] = None, log_dir: Optional[str] = None, files: Optional[list] = None) -> dict:
        """
        Run a security scan on a folder.

        This sends a prompt to the LLM asking it to scan the given folder.
        The LLM will use Copilot CLI built-in tools (bash, skill, view)
        automatically based on its instructions.

        Uses the shared ``run_session_to_completion`` function which
        handles event-driven waiting, activity-based stall detection,
        nudge messages, tool health monitoring, and session logging.

        The method adds scan-specific behaviour via callback hooks:
        - Tracks whether security scanner skills have been invoked
        - Tracks file reads (view tool) for progress display
        - Sends different nudge messages depending on scan state

        Args:
            folder_path: Path to the folder to scan.
                         Example: "./src" or "C:\\code\\myapp"
            timeout:     Maximum seconds to wait for the scan to finish.
                         Defaults to DEFAULT_SCAN_TIMEOUT_SECONDS.
            on_tool_stuck: Optional async callback for stuck-tool decisions.
            log_dir:     Optional directory for session log files.
            files:       Optional list of specific file paths to scan.
                         When provided, only these files are analysed
                         instead of the full folder.

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
        if not self.client:
            return {
                "status": "error",
                "error": "Agent not initialized. Call initialize() first.",
            }

        # Use default timeout if none provided
        if timeout is None:
            timeout = DEFAULT_SCAN_TIMEOUT_SECONDS

        # A1: Sessions are created inside the factory callable
        # and destroyed by the retry wrapper.  No outer session var.
        try:
            # Collect and validate skill directories.
            # D1: Pass folder_path so project-level skills in
            # <folder>/.copilot/skills/ are discovered too.
            skill_dirs = get_skill_directories(folder_path)
            skill_dirs = [d for d in skill_dirs if os.path.isdir(d)]

            # F1: Dynamically build the available-skills section of
            # the system message at session-creation time so it only
            # lists scanners that are actually installed.  This
            # prevents the LLM from trying to invoke missing skills.
            dynamic_system_message = self._build_dynamic_system_message(
                folder_path
            )

            # D3: Meaningful session ID
            folder_basename = os.path.basename(
                os.path.abspath(folder_path)
            )

            # A1: Build a session factory so run_session_with_retries
            # can create a fresh session on each retry attempt.
            # This avoids reusing a broken session after a transient
            # SESSION_ERROR.
            async def _create_scan_session():
                sid = (
                    f"agentsec-main-{folder_basename}"
                    f"-{int(time.time())}"
                )
                sess = await self.client.create_session(
                    on_permission_request=_auto_approve_permissions,
                    session_id=sid,
                    model=self.config.model,
                    system_message={
                        "mode": "append",
                        "content": dynamic_system_message,
                    },
                    skill_directories=(
                        skill_dirs if skill_dirs else None
                    ),
                )
                logger.debug(f"Created scan session: {sid}")
                return sess

            # Build the scan prompt using the configured template
            if files:
                scan_prompt = self.config.format_prompt_for_files(
                    folder_path, files
                )
            else:
                scan_prompt = self.config.format_prompt(folder_path)

            # C1: Determine which scanners are irrelevant for the
            # target folder based on file types present.  In single-
            # session mode the LLM has access to ALL skills, so we
            # add guidance to the prompt telling it which scanners
            # to skip, reducing wasted LLM turns.
            skip_guidance = self._build_skip_guidance(
                folder_path, files=files
            )
            if skip_guidance:
                scan_prompt = scan_prompt + "\n\n" + skip_guidance

            logger.info(f"Starting scan of {folder_path}")
            logger.debug(f"Using prompt: {scan_prompt[:200]}...")
            logger.debug(
                f"Scan timeout (safety ceiling): {timeout}s, "
                f"inactivity threshold: {INACTIVITY_TIMEOUT_SECONDS}s"
            )

            # ── Scan-specific state for callback hooks ───────────
            # C1: Capture available skill names for dynamic nudge
            # messages (instead of hardcoding bandit/graudit).
            available_skills = discover_all_skills(
                project_root=folder_path
            )
            available_skill_names = [
                s["name"] for s in available_skills
                if s["tool_available"]
            ][:2]  # Pick first 2 for the nudge example

            # Track whether the LLM has invoked security scanning
            # skills so we can send targeted nudge messages.
            scanner_was_invoked = {"value": False}

            def _on_tool_start(
                tool_name: str,
                detail: str,
                tool_args: dict,
                tool_call_id: Optional[str],
            ) -> None:
                """
                Custom hook called on every TOOL_EXECUTION_START event.

                Tracks scanner skill invocations and updates the
                progress tracker for file reads (view tool).
                """
                # Check if the LLM is using security scanners
                if tool_name == "skill":
                    scanner_was_invoked["value"] = True

                # Also count bash invocations of scanner tools
                # H1: Use the shared KNOWN_SCANNER_COMMANDS set
                # derived from SKILL_TO_TOOL_MAP instead of a
                # hardcoded duplicate list.
                if tool_name == "bash" and tool_args:
                    cmd = tool_args.get("command", "")
                    first_word = (
                        cmd.strip().split()[0] if cmd.strip() else ""
                    )
                    if first_word in KNOWN_SCANNER_COMMANDS:
                        scanner_was_invoked["value"] = True

                # Update progress tracker for file reads (view tool)
                if tool_name == "view" and tool_args:
                    file_path = tool_args.get(
                        "path",
                        tool_args.get(
                            "file_path",
                            tool_args.get("filePath", ""),
                        ),
                    )
                    if file_path:
                        is_likely_file = "." in os.path.basename(
                            file_path
                        )
                        if is_likely_file:
                            tracker = get_global_tracker()
                            if tracker:
                                tracker.start_file(file_path)

                # Log with detail for visibility
                if tool_name == "skill" and detail:
                    logger.info(f"  -> Skill invoked: {detail}")
                elif detail:
                    logger.info(
                        f"  -> Tool started: {tool_name} ({detail})"
                    )
                else:
                    logger.info(f"  -> Tool started: {tool_name}")

            def _on_tool_complete(
                tool_name: str,
                detail: str,
                output: str,
                tool_call_id: Optional[str],
            ) -> None:
                """
                Custom hook called on every TOOL_EXECUTION_COMPLETE.

                Updates progress tracker when file reads finish and
                logs completion with descriptive messages.
                """
                # We cannot reliably get the file_path from the
                # completion event alone, so we skip the file progress
                # finish_file here.  The progress tracker still works
                # because the heartbeat and scan_finished events
                # provide the summary counts.

                # Log with tool name for visibility
                if tool_name == "skill" and detail:
                    logger.info(f"  <- Skill completed: {detail}")
                elif detail:
                    logger.info(
                        f"  <- Tool completed: {tool_name} ({detail})"
                    )
                else:
                    logger.info(f"  <- Tool completed: {tool_name}")

            def _build_nudge() -> str:
                """
                Build a context-aware nudge message.

                Returns a different message depending on whether
                security scanners have been invoked yet. This guides
                the LLM to take the appropriate next step.
                """
                if not scanner_was_invoked["value"]:
                    # C1: Use dynamically-discovered skill names
                    # instead of hardcoded "bandit-security-scan".
                    if available_skill_names:
                        examples = " and ".join(
                            available_skill_names
                        )
                        return (
                            "You should use the skill tool to run "
                            "security scanners. Invoke skills like "
                            f"{examples} to analyze the code in "
                            f"{folder_path}. You can also run "
                            "scanners directly via bash."
                        )
                    else:
                        return (
                            "You should run security scanners on "
                            f"{folder_path}. Use bash to invoke "
                            "any available scanner CLIs directly."
                        )
                else:
                    return (
                        "If you have completed scanning, use bash to "
                        "write your findings into a Markdown report "
                        "file in the target folder (e.g. "
                        "cat > report.md << 'REPORT' ... REPORT). "
                        "Then provide a brief summary and stop. "
                        "If more scanning is needed, continue using "
                        "the skill tool or bash to run additional "
                        "scanners."
                    )

            # ── Run the session using the shared runner ──────────
            # A1: Pass the session factory so each retry attempt gets
            # a fresh session instead of reusing a potentially broken
            # one after a transient SESSION_ERROR.
            session_result = await run_session_with_retries(
                session_or_factory=_create_scan_session,
                prompt=scan_prompt,
                label="main-scan",
                nudge_message=_build_nudge,
                inactivity_timeout=INACTIVITY_TIMEOUT_SECONDS,
                max_idle_nudges=MAX_CONSECUTIVE_IDLE_NUDGES,
                safety_timeout=timeout,
                on_tool_stuck=on_tool_stuck,
                log_dir=log_dir,
                system_message=self.config.system_message,
                on_tool_start=_on_tool_start,
                on_tool_complete=_on_tool_complete,
            )

            # ── Map the session result to the agent's return format ──
            if session_result["status"] == "success":
                if session_result["content"]:
                    logger.info(f"Scan completed for {folder_path}")
                    return {
                        "status": "success",
                        "result": session_result["content"],
                    }
                else:
                    logger.warning(
                        "Session completed but no assistant message "
                        "was captured."
                    )
                    return {
                        "status": "error",
                        "error": "No response received from Copilot",
                    }

            elif session_result["status"] == "timeout":
                if session_result["content"]:
                    return {
                        "status": "timeout",
                        "result": session_result["content"],
                        "error": session_result["error"],
                    }
                return {
                    "status": "timeout",
                    "error": session_result["error"],
                }

            else:
                return {
                    "status": "error",
                    "error": session_result.get("error", "Unknown error"),
                }

        except Exception as error:
            logger.error(
                f"Scan failed with exception: {error}", exc_info=True
            )
            return {
                "status": "error",
                "error": str(error),
            }

    def _build_dynamic_system_message(
        self,
        folder_path: str,
    ) -> str:
        """
        Build the system message with a dynamically-generated skill list.

        F1 optimisation: instead of the hardcoded skill list in the
        default system message, this method discovers which scanner
        skills are actually installed and builds the "Available Skills"
        section dynamically.  This prevents the LLM from trying to
        invoke skills that don't exist, and automatically picks up
        newly-installed skills.

        The base system message from config is used as-is, with a
        dynamic addendum listing only the available skills.

        Args:
            folder_path: The folder being scanned (for project-level
                         skill discovery).

        Returns:
            The complete system message string with dynamic skill info.
        """
        try:
            skills = discover_all_skills(project_root=folder_path)
            available = [s for s in skills if s["tool_available"]]

            if not available:
                # No skills found — use the base config as-is
                return self.config.system_message

            # Build a dynamic skill list section
            skill_lines = []
            for skill in available:
                skill_lines.append(
                    f"- **{skill['name']}** — {skill['description']}"
                )

            dynamic_section = (
                "\n\n## Dynamically Discovered Skills\n\n"
                "The following security scanning skills are installed "
                "and available on this system. Use the `skill` tool "
                "to invoke them:\n"
                + "\n".join(skill_lines)
            )

            return self.config.system_message + dynamic_section

        except Exception as err:
            logger.debug(
                f"Dynamic system message generation failed: {err}"
            )
            return self.config.system_message

    @staticmethod
    def _build_skip_guidance(
        folder_path: str,
        files: Optional[list] = None,
    ) -> str:
        """
        Build guidance text telling the LLM which scanners to skip.

        Classifies files in the target folder by extension and compares
        against the known scanner relevance mapping.  Returns a short
        instruction string listing scanners the LLM should NOT invoke
        because there are no relevant files.

        When ``files`` is provided, classification is based on that
        list instead of the full folder walk.

        Args:
            folder_path: The folder being scanned.
            files:       Optional explicit file list.

        Returns:
            A guidance string, or empty string if all scanners are relevant.
        """
        try:
            # Use the shared classify_files function
            if files:
                file_extensions, file_names, _ = classify_file_list(
                    files
                )
            else:
                file_extensions, file_names, _ = classify_files(
                    folder_path
                )

            # Find scanners that are NOT relevant for these files
            irrelevant_scanners = []
            for scanner_name, relevance in SCANNER_RELEVANCE.items():
                if not is_scanner_relevant(
                    relevance,
                    file_extensions,
                    file_names,
                ):
                    irrelevant_scanners.append(scanner_name)

            if not irrelevant_scanners:
                return ""

            scanner_list = ", ".join(irrelevant_scanners)
            return (
                f"NOTE: The following scanners are NOT relevant for "
                f"this folder (no matching file types found) — do NOT "
                f"invoke them: {scanner_list}"
            )

        except Exception as err:
            logger.debug(f"Skip guidance generation failed: {err}")
            return ""

    async def scan_parallel(
        self,
        folder_path: str,
        timeout: Optional[float] = None,
        max_concurrent: int = 3,
        on_tool_stuck: Optional[OnToolStuckCallback] = None,
        log_dir: Optional[str] = None,
        on_output=None,
        scanners: Optional[list] = None,
        files: Optional[list] = None,
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
            scanners:       Optional list of scanner names to include.
                            When set, only these scanners will be used.
                            None means "use all relevant and available".
            files:          Optional list of specific file paths to scan.
                            When provided, the scan plan is based only on
                            these files rather than the full folder walk.

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

            # Resolve scanner whitelist: explicit param > config > None (all)
            effective_scanners = scanners if scanners is not None else self.config.scanners

            orchestrator = ParallelScanOrchestrator(
                client=self.client,
                config=self.config,
                max_concurrent=max_concurrent,
                on_output=on_output,
                scanner_whitelist=effective_scanners,
            )

            logger.info(
                f"Starting parallel scan of {folder_path} "
                f"(max_concurrent={max_concurrent}, timeout={timeout}s)"
            )

            result = await orchestrator.run(
                folder_path=folder_path,
                timeout=timeout,
                on_tool_stuck=on_tool_stuck,
                log_dir=log_dir,
                files=files,
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

        Note: Per-scan sessions are created and destroyed within scan()
        itself (B1 optimisation).  This method only cleans up the
        CopilotClient.

        Example:
            >>> try:
            ...     await agent.initialize()
            ...     await agent.scan("./src")
            ... finally:
            ...     await agent.cleanup()
        """
        try:
            # Stop the client if it exists
            if self.client:
                try:
                    await asyncio.wait_for(self.client.stop(), timeout=5.0)
                except asyncio.TimeoutError:
                    # B3: If stop() hangs, use force_stop() to ensure
                    # the CLI subprocess is actually killed.
                    logger.warning(
                        "Client stop timed out, using force_stop()"
                    )
                    try:
                        await self.client.force_stop()
                    except Exception as fs_err:
                        logger.debug(
                            f"force_stop() error: {fs_err}"
                        )
                except Exception as e:
                    logger.warning(f"Error stopping client: {e}")
                finally:
                    self.client = None

            logger.info("SecurityScannerAgent cleaned up successfully")

        except Exception as error:
            # Log but don't re-raise — cleanup should not crash the app
            logger.error(f"Error during cleanup: {error}")
