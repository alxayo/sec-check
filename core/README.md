# AgentSec Core

The core package for AgentSec, providing the `SecurityScannerAgent` class, configuration management, and all `@tool`-decorated skill functions. Both the CLI and Desktop app import from this package to perform security scanning.

## Installation

```bash
pip install -e ./core
```

## Package Structure

- `agentsec/agent.py` — `SecurityScannerAgent` class (main entry point)
- `agentsec/config.py` — `AgentSecConfig` class for configuration management
- `agentsec/skills.py` — `@tool` skill functions (list_files, analyze_file, generate_report)
- `tests/` — Unit and integration tests

## Configuration

The `AgentSecConfig` class manages configuration for the agent:

```python
from agentsec.config import AgentSecConfig

# Load from YAML file
config = AgentSecConfig.load("./agentsec.yaml")

# Or create with custom values
config = AgentSecConfig(
    system_message="You are a security scanner...",
    initial_prompt="Scan {folder_path} for issues."
)

# Apply CLI overrides
config = config.with_overrides(
    system_message_file="./custom-system.txt"
)
```

### Configuration Options

| Setting | Description |
|---------|-------------|
| `system_message` | The AI's system prompt (who it is, what it does) |
| `system_message_file` | Path to file containing system message |
| `initial_prompt` | Prompt template for scans (use `{folder_path}` placeholder) |
| `initial_prompt_file` | Path to file containing initial prompt |

### Config File Search Paths

`AgentSecConfig.load()` searches for config files in:
1. Current directory (`agentsec.yaml`, `agentsec.yml`, `.agentsec.yaml`, `.agentsec.yml`)
2. User home directory
3. `~/.config/agentsec/`

## Agent Usage

```python
from agentsec.agent import SecurityScannerAgent
from agentsec.config import AgentSecConfig

# With default configuration
agent = SecurityScannerAgent()

# With custom configuration
config = AgentSecConfig.load("./agentsec.yaml")
agent = SecurityScannerAgent(config=config)

try:
    await agent.initialize()
    result = await agent.scan("./my-project")
    print(result["result"])
finally:
    await agent.cleanup()
```
