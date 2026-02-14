"""
AgentSec Core — shared agent and skills library.

This package provides the SecurityScannerAgent, configuration management,
progress tracking, and all @tool-decorated skill functions used by both
the CLI and the Desktop app.
"""

__version__ = "0.1.0"

# Import configuration (always available, no external dependencies)
from agentsec.config import AgentSecConfig

# Import skill discovery (always available, no external dependencies)
from agentsec.skill_discovery import discover_all_skills, get_skill_summary

# Import progress tracking (always available, no external dependencies)
from agentsec.progress import (
    ProgressTracker,
    ProgressEvent,
    ProgressEventType,
    ProgressCallback,
    get_global_tracker,
    set_global_tracker,
)

try:
    from agentsec.agent import SecurityScannerAgent
    from agentsec.orchestrator import ParallelScanOrchestrator
    __all__ = [
        "SecurityScannerAgent",
        "ParallelScanOrchestrator",
        "AgentSecConfig",
        "discover_all_skills",
        "get_skill_summary",
        "ProgressTracker",
        "ProgressEvent",
        "ProgressEventType",
        "ProgressCallback",
        "get_global_tracker",
        "set_global_tracker",
    ]
except ImportError:
    # If the Copilot SDK is not installed, the agent class won't be available.
    # Config, progress tracking, skills, and discovery can still be used.
    __all__ = [
        "AgentSecConfig",
        "discover_all_skills",
        "get_skill_summary",
        "ProgressTracker",
        "ProgressEvent",
        "ProgressEventType",
        "ProgressCallback",
        "get_global_tracker",
        "set_global_tracker",
    ]
