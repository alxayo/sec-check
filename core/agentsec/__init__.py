"""
AgentSec Core — shared agent and skills library.

This package provides the SecurityScannerAgent, configuration management,
and all @tool-decorated skill functions used by both the CLI and the Desktop app.
"""

__version__ = "0.1.0"

# Import configuration (always available, no external dependencies)
from agentsec.config import AgentSecConfig

try:
    from agentsec.agent import SecurityScannerAgent
    __all__ = ["SecurityScannerAgent", "AgentSecConfig"]
except ImportError:
    # If the Copilot SDK is not installed, the agent class won't be available.
    # Config and skills can still be used directly for testing and development.
    __all__ = ["AgentSecConfig"]
