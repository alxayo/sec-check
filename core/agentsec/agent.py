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
from typing import Optional

from copilot import CopilotClient, SessionConfig, MessageOptions
from dotenv import load_dotenv

# Import skills so they are registered with the agent framework
from agentsec.skills import list_files, analyze_file, generate_report  # noqa: F401
from agentsec.config import AgentSecConfig

# Load environment variables from .env file at the workspace root
load_dotenv()

# Set up logging
logger = logging.getLogger(__name__)


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
            logger.debug(f"Using prompt: {scan_prompt[:100]}...")

            # Send the prompt and wait for the response
            # We allow up to 2 minutes for the scan to complete
            response = await self.session.send_and_wait(
                MessageOptions(prompt=scan_prompt),
                timeout=120.0,
            )

            # Check if we got a response
            if response and response.data and response.data.content:
                logger.info(f"Scan completed for {folder_path}")
                return {
                    "status": "success",
                    "result": response.data.content,
                }
            else:
                return {
                    "status": "error",
                    "error": "No response received from Copilot",
                }

        except TimeoutError:
            logger.error("Scan timed out after 120 seconds")
            return {
                "status": "timeout",
                "error": "Scan took too long (>120 seconds). Try a smaller folder.",
            }
        except Exception as error:
            logger.error(f"Scan failed: {error}")
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
                await self.session.destroy()
                self.session = None

            # Stop the client if it exists
            if self.client:
                await self.client.stop()
                self.client = None

            logger.info("SecurityScannerAgent cleaned up successfully")

        except Exception as error:
            # Log but don't re-raise — cleanup should not crash the app
            logger.error(f"Error during cleanup: {error}")
