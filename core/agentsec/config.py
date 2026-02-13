"""
Configuration module for AgentSec.

This module provides configuration management for the SecurityScannerAgent.
Configuration can come from:
1. A YAML configuration file (agentsec.yaml)
2. CLI arguments (which override file settings)

The configuration controls:
- system_message: The AI agent's instructions (who it is, what it does)
- initial_prompt: The default prompt template for scanning

Both settings can be:
- Direct text in the config file
- A path to an external file containing the text

Usage:
    # Load from default config file
    config = AgentSecConfig.load()
    
    # Load from specific file
    config = AgentSecConfig.load("./custom-config.yaml")
    
    # Create with specific values
    config = AgentSecConfig(
        system_message="You are a security scanner...",
        initial_prompt="Scan the folder: {folder_path}"
    )
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Try to import yaml, but provide helpful error if not installed
try:
    import yaml
except ImportError:
    yaml = None

# Set up logging for config-related messages
logger = logging.getLogger(__name__)


# Default system message that tells the AI what it should do
DEFAULT_SYSTEM_MESSAGE = """You are AgentSec, an AI-powered security scanning agent.

Your job is to analyze source code for security vulnerabilities using the
tools provided to you.

CRITICAL: You MUST use the tools to scan. Do NOT just respond with text.

When asked to scan a folder, you MUST follow these steps in order:
1. REQUIRED: Call the list_files tool to get all files in the target folder.
2. REQUIRED: Call the analyze_file tool on EACH file found (not just some files, ALL of them).
3. REQUIRED: Call the generate_report tool to create a summary of all findings.

Never skip any of these steps. Never respond without using all three tools.
Always be thorough and check every file. Provide clear, actionable
recommendations for any issues you find.
"""


# Default prompt template for scanning
# Use {folder_path} as a placeholder that gets replaced with the actual path
DEFAULT_INITIAL_PROMPT = """Please perform a security scan of the folder: {folder_path}

Steps:
1. List all files in {folder_path}
2. Analyze each file for security issues
3. Generate a summary report with all findings
"""


# List of config file names to search for (in order of priority)
DEFAULT_CONFIG_FILENAMES = [
    "agentsec.yaml",
    "agentsec.yml",
    ".agentsec.yaml",
    ".agentsec.yml",
]


@dataclass
class AgentSecConfig:
    """
    Configuration settings for AgentSec.
    
    This dataclass holds all configurable settings for the security scanner.
    It provides methods to load settings from files and merge with CLI overrides.
    
    Attributes:
        system_message: The AI's system prompt (who it is, what it does).
                        This is sent to the LLM at session start.
        initial_prompt: The default prompt template for scan requests.
                        Use {folder_path} as placeholder for the target folder.
    
    Example:
        >>> config = AgentSecConfig.load("./agentsec.yaml")
        >>> print(config.system_message)
        >>> 
        >>> # Or create with defaults
        >>> config = AgentSecConfig()
        >>> print(config.initial_prompt)
    """
    
    # The system message tells the AI who it is and how to behave
    system_message: str = field(default=DEFAULT_SYSTEM_MESSAGE)
    
    # The initial prompt template for scan requests
    initial_prompt: str = field(default=DEFAULT_INITIAL_PROMPT)
    
    @classmethod
    def load(
        cls,
        config_path: Optional[str] = None,
        search_paths: Optional[list] = None,
    ) -> "AgentSecConfig":
        """
        Load configuration from a YAML file.
        
        This method searches for a config file and loads settings from it.
        If no config file is found, returns default configuration.
        
        Args:
            config_path: Explicit path to a config file. If provided,
                         only this file will be checked.
            search_paths: List of directories to search for config files.
                          Defaults to current directory and user home.
        
        Returns:
            An AgentSecConfig instance with loaded settings.
        
        Raises:
            FileNotFoundError: If config_path is specified but doesn't exist.
            ValueError: If the config file has invalid format.
        
        Example:
            >>> # Auto-search for config
            >>> config = AgentSecConfig.load()
            >>> 
            >>> # Load specific file
            >>> config = AgentSecConfig.load("./my-config.yaml")
        """
        # Check if yaml is available
        if yaml is None:
            logger.warning(
                "PyYAML not installed. Install with: pip install pyyaml\n"
                "Using default configuration."
            )
            return cls()
        
        # Step 1: Find the config file
        config_file = cls._find_config_file(config_path, search_paths)
        
        if config_file is None:
            logger.debug("No config file found, using defaults")
            return cls()
        
        # Step 2: Load and parse the YAML file
        logger.info(f"Loading configuration from: {config_file}")
        
        try:
            with open(config_file, "r", encoding="utf-8") as file:
                raw_config = yaml.safe_load(file)
        except yaml.YAMLError as error:
            raise ValueError(f"Invalid YAML in config file: {error}")
        
        # Handle empty config file
        if raw_config is None:
            raw_config = {}
        
        # Step 3: Parse the config values
        config_dir = Path(config_file).parent
        
        system_message = cls._resolve_text_or_file(
            raw_config.get("system_message"),
            raw_config.get("system_message_file"),
            config_dir,
            DEFAULT_SYSTEM_MESSAGE,
            "system_message",
        )
        
        initial_prompt = cls._resolve_text_or_file(
            raw_config.get("initial_prompt"),
            raw_config.get("initial_prompt_file"),
            config_dir,
            DEFAULT_INITIAL_PROMPT,
            "initial_prompt",
        )
        
        return cls(
            system_message=system_message,
            initial_prompt=initial_prompt,
        )
    
    @classmethod
    def _find_config_file(
        cls,
        config_path: Optional[str],
        search_paths: Optional[list],
    ) -> Optional[Path]:
        """
        Find the configuration file.
        
        Args:
            config_path: Explicit path to check.
            search_paths: Directories to search.
        
        Returns:
            Path to the config file, or None if not found.
        """
        # If explicit path is given, use it
        if config_path is not None:
            path = Path(config_path)
            if not path.exists():
                raise FileNotFoundError(f"Config file not found: {config_path}")
            return path
        
        # Search in default locations
        if search_paths is None:
            search_paths = [
                Path.cwd(),                    # Current directory
                Path.home(),                   # User home directory
                Path.home() / ".config" / "agentsec",  # XDG config dir
            ]
        
        for search_dir in search_paths:
            search_dir = Path(search_dir)
            if not search_dir.exists():
                continue
                
            for filename in DEFAULT_CONFIG_FILENAMES:
                config_file = search_dir / filename
                if config_file.exists():
                    return config_file
        
        return None
    
    @classmethod
    def _resolve_text_or_file(
        cls,
        text_value: Optional[str],
        file_value: Optional[str],
        config_dir: Path,
        default: str,
        field_name: str,
    ) -> str:
        """
        Resolve a configuration value from text or file.
        
        If both text and file are provided, text takes priority.
        File paths are resolved relative to the config file directory.
        
        Args:
            text_value: Direct text value from config.
            file_value: Path to file containing the text.
            config_dir: Directory containing the config file.
            default: Default value if neither is provided.
            field_name: Name of the field (for error messages).
        
        Returns:
            The resolved text content.
        """
        # Direct text takes priority
        if text_value is not None:
            return text_value
        
        # Try to load from file
        if file_value is not None:
            file_path = Path(file_value)
            
            # Resolve relative paths against config directory
            if not file_path.is_absolute():
                file_path = config_dir / file_path
            
            if not file_path.exists():
                raise FileNotFoundError(
                    f"File not found for {field_name}: {file_path}"
                )
            
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    content = file.read()
                logger.debug(f"Loaded {field_name} from: {file_path}")
                return content
            except IOError as error:
                raise ValueError(
                    f"Could not read {field_name} file '{file_path}': {error}"
                )
        
        # Return default
        return default
    
    def with_overrides(
        self,
        system_message: Optional[str] = None,
        system_message_file: Optional[str] = None,
        initial_prompt: Optional[str] = None,
        initial_prompt_file: Optional[str] = None,
    ) -> "AgentSecConfig":
        """
        Create a new config with CLI overrides applied.
        
        This method creates a copy of this config with any provided
        overrides applied. Direct text values take priority over files.
        
        Args:
            system_message: Override system message text.
            system_message_file: Override system message from file.
            initial_prompt: Override initial prompt text.
            initial_prompt_file: Override initial prompt from file.
        
        Returns:
            A new AgentSecConfig with overrides applied.
        
        Example:
            >>> base_config = AgentSecConfig.load()
            >>> custom = base_config.with_overrides(
            ...     system_message="Custom AI instructions..."
            ... )
        """
        # Start with current values
        new_system_message = self.system_message
        new_initial_prompt = self.initial_prompt
        
        # Apply system_message override (text has priority over file)
        if system_message is not None:
            new_system_message = system_message
        elif system_message_file is not None:
            new_system_message = self._load_file_content(
                system_message_file, 
                "system_message_file"
            )
        
        # Apply initial_prompt override (text has priority over file)
        if initial_prompt is not None:
            new_initial_prompt = initial_prompt
        elif initial_prompt_file is not None:
            new_initial_prompt = self._load_file_content(
                initial_prompt_file,
                "initial_prompt_file"
            )
        
        return AgentSecConfig(
            system_message=new_system_message,
            initial_prompt=new_initial_prompt,
        )
    
    @staticmethod
    def _load_file_content(file_path: str, field_name: str) -> str:
        """
        Load text content from a file.
        
        Args:
            file_path: Path to the file to read.
            field_name: Name of the field (for error messages).
        
        Returns:
            The file content as a string.
        
        Raises:
            FileNotFoundError: If the file doesn't exist.
            ValueError: If the file can't be read.
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(
                f"File not found for {field_name}: {file_path}"
            )
        
        try:
            with open(path, "r", encoding="utf-8") as file:
                return file.read()
        except IOError as error:
            raise ValueError(
                f"Could not read {field_name} file '{file_path}': {error}"
            )
    
    def format_prompt(self, folder_path: str) -> str:
        """
        Format the initial prompt with the folder path.
        
        This replaces {folder_path} placeholders in the initial_prompt
        with the actual folder path.
        
        Args:
            folder_path: The path to the folder being scanned.
        
        Returns:
            The formatted prompt string.
        
        Example:
            >>> config = AgentSecConfig()
            >>> prompt = config.format_prompt("./my-project")
            >>> print(prompt)
        """
        return self.initial_prompt.format(folder_path=folder_path)
