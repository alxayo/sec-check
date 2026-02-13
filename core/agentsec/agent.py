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
from typing import Optional

from copilot import CopilotClient, SessionConfig, MessageOptions
from copilot.session import SessionEventType
from dotenv import load_dotenv

# Import skills so they are registered with the agent framework
from agentsec.skills import list_files, analyze_file, generate_report  # noqa: F401
from agentsec.config import AgentSecConfig
from agentsec.progress import get_global_tracker

# Load environment variables from .env file at the workspace root
load_dotenv()

# Set up logging
logger = logging.getLogger(__name__)


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
    and uses skills (tools) to scan code for security vulnerabilities.

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

    async def scan(self, folder_path: str) -> dict:
        """
        Run a security scan on a folder.

        This sends a prompt to the LLM asking it to scan the given folder.
        The LLM will call the skills (list_files, analyze_file, generate_report)
        automatically based on its instructions.

        Uses an event-driven approach so that tool executions (which emit
        progress events) happen in real time rather than being blocked.

        Args:
            folder_path: Path to the folder to scan.
                         Example: "./src" or "C:\\code\\myapp"

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

        try:
            # Build the scan prompt using the configured template
            # The format_prompt method replaces {folder_path} placeholders
            scan_prompt = self.config.format_prompt(folder_path)

            logger.info(f"Starting scan of {folder_path}")
            logger.debug(f"Using prompt: {scan_prompt[:200]}...")

            # We collect the assistant's final response and track completion
            final_response = {"content": None}
            scan_complete = asyncio.Event()
            scan_error = {"error": None}

            # Reset tool call tracking for this scan
            self._tool_call_map = {}

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
                        tool_name = getattr(event.data, 'tool_name', 'unknown')
                        tool_call_id = getattr(
                            event.data, 'tool_call_id', None
                        )

                        # Try to extract arguments for more detail about
                        # what specific file or command is being used
                        detail = ""
                        file_path = None
                        tool_args = _extract_tool_arguments(event.data)

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
                        if tool_name == "view" and file_path:
                            tracker = get_global_tracker()
                            if tracker:
                                tracker.start_file(file_path)

                        # Log with detail for better visibility
                        if detail:
                            logger.info(
                                f"  -> Tool started: {tool_name} ({detail})"
                            )
                        else:
                            logger.info(f"  -> Tool started: {tool_name}")

                    # Tool execution completed
                    elif event.type == SessionEventType.TOOL_EXECUTION_COMPLETE:
                        tool_call_id = getattr(
                            event.data, 'tool_call_id', 'unknown'
                        )

                        # Look up the tool name from our tracking map
                        tool_info = self._tool_call_map.get(
                            tool_call_id, {}
                        )
                        tool_name = tool_info.get("name", "unknown")
                        detail = tool_info.get("detail", "")
                        file_path = tool_info.get("file_path")

                        # Update progress tracker when a file read completes
                        if tool_name == "view" and file_path:
                            tracker = get_global_tracker()
                            if tracker:
                                tracker.finish_file(file_path, issues_found=0)

                        # Log with tool name instead of opaque ID
                        if detail:
                            logger.info(
                                f"  <- Tool completed: {tool_name} ({detail})"
                            )
                        else:
                            logger.info(f"  <- Tool completed: {tool_name}")

                    # Assistant message — the LLM's text response
                    elif event.type == SessionEventType.ASSISTANT_MESSAGE:
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

                except (AttributeError, ValueError) as enum_error:
                    logger.debug(f"[EVENT] Could not match enum: {enum_error}")

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

            # Wait for the scan to complete with a timeout
            try:
                await asyncio.wait_for(scan_complete.wait(), timeout=120.0)
            except asyncio.TimeoutError:
                logger.error(
                    "Scan timed out after 120 seconds. "
                    "The session never became idle. "
                    "This may indicate the LLM did not call any tools."
                )
                return {
                    "status": "timeout",
                    "error": "Scan took too long (>120 seconds). Try a smaller folder.",
                }

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
