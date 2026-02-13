# AgentSec Core

The core package for AgentSec, providing the `SecurityScannerAgent` class, configuration management, and all `@tool`-decorated skill functions. Both the CLI and Desktop app import from this package to perform security scanning.

## Installation

```bash
pip install -e ./core
```

## Package Structure

- `agentsec/agent.py` — `SecurityScannerAgent` class (main entry point, stall detection, nudge system)
- `agentsec/config.py` — `AgentSecConfig` class with directive system message and safety guardrails
- `agentsec/progress.py` — `ProgressTracker` class for real-time scan feedback
- `agentsec/skill_discovery.py` — Dynamic discovery of Copilot CLI agentic skills and tool availability checking
- `agentsec/skills.py` — `@tool` skill functions (list_files, analyze_file, generate_report)
- `tests/` — Unit and integration tests

## How Scanning Works

The agent uses **Copilot CLI built-in tools** as its primary scanning mechanism:

| Tool | Purpose |
|------|---------|
| `bash` | File discovery (`find`, `ls`) and direct invocation of security scanner CLIs (bandit, graudit, etc.) |
| `skill` | Invokes pre-configured Copilot CLI agentic skills (bandit-security-scan, graudit-security-scan, etc.) |
| `view` | Reads file contents for manual LLM code inspection |

A **directive system message** in `config.py` guides the LLM through a structured scanning workflow with comprehensive safety guardrails.

### Stall Detection & Nudge System

The `scan()` method monitors tool activity and prevents the LLM from getting stuck:

| Constant | Default | Purpose |
|----------|---------|---------|
| `DEFAULT_SCAN_TIMEOUT_SECONDS` | 300s | Maximum wall-clock time for a scan |
| `STALL_DETECTION_SECONDS` | 30s | Inactivity threshold before sending a nudge |
| `SCANNING_TOOL_NAMES` | `{"skill"}` | Tool names that count as security scanning activity |
| `MAX_NUDGES` | 2 | Maximum nudge messages per scan |

If no tool activity occurs for 30 seconds, a nudge message is sent. Two types of nudges:
1. **Redirect nudge** — if the LLM hasn't invoked any security scanners yet
2. **Progress nudge** — if the LLM ran scanners but seems stuck

Partial results are captured and returned on timeout instead of discarding all work.

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

## Progress Tracking

The core package provides a `ProgressTracker` class for real-time scan feedback:

```python
from agentsec.progress import (
    ProgressTracker,
    ProgressEvent,
    ProgressEventType,
    set_global_tracker,
)

# Create a callback to handle progress events
def on_progress(event: ProgressEvent):
    if event.type == ProgressEventType.FILE_STARTED:
        print(f"Scanning: {event.current_file}")
    elif event.type == ProgressEventType.FILE_FINISHED:
        print(f"Done: {event.files_scanned}/{event.total_files} files")
    elif event.type == ProgressEventType.SCAN_FINISHED:
        print(f"Complete: {event.issues_found} issues in {event.elapsed_seconds:.1f}s")

# Create and register the tracker
tracker = ProgressTracker(callback=on_progress, heartbeat_interval=3.0)
set_global_tracker(tracker)

# Run the scan (skills will automatically report progress)
tracker.start_scan("./my-project")
result = await agent.scan("./my-project")
tracker.finish_scan()

# Clear the tracker when done
set_global_tracker(None)
```

### Progress Events

| Event Type | Description |
|------------|-------------|
| `SCAN_STARTED` | Scan has begun |
| `FILES_DISCOVERED` | Total files to scan has been determined |
| `FILE_STARTED` | Started analyzing a specific file |
| `FILE_FINISHED` | Finished analyzing a file (includes issue count) |
| `HEARTBEAT` | Periodic update showing scan is still active |
| `SCAN_FINISHED` | Scan complete with final summary |
| `WARNING` | Non-fatal issue during scan |
| `ERROR` | Serious problem during scan |

## Skill Discovery

The `skill_discovery` module dynamically discovers Copilot CLI agentic skills from the same directories the Copilot CLI uses:

- **User-level**: `~/.copilot/skills/`
- **Project-level**: `<project_root>/.copilot/skills/`

Each skill directory contains a `SKILL.md` file with YAML frontmatter. The module parses these, maps each skill to its underlying CLI tool, and checks whether the tool is installed.

### Basic Usage

```python
from agentsec.skill_discovery import discover_all_skills, get_skill_summary

# Discover all skills (user + project level)
skills = discover_all_skills("/path/to/project")

# Print each skill with availability
for skill in skills:
    mark = "✅" if skill["tool_available"] else "⬜"
    print(f"  {mark} {skill['tool_name']:<20} — {skill['description']}")

# Get summary statistics
summary = get_skill_summary(skills)
print(f"Available: {summary['available']}/{summary['total']}")
```

### Skill Dictionary Keys

Each skill returned by `discover_all_skills()` is a dictionary with:

| Key | Type | Description |
|-----|------|-------------|
| `name` | str | Skill name from SKILL.md frontmatter |
| `description` | str | Short description of the skill |
| `tool_name` | str | Underlying CLI tool binary name |
| `tool_available` | bool | Whether the tool is found on PATH |
| `tool_path` | str or None | Full path to the tool binary |
| `source` | str | `"user"` or `"project"` |
| `skill_dir` | str | Absolute path to the skill directory |

### Summary Dictionary Keys

`get_skill_summary()` returns:

| Key | Type | Description |
|-----|------|-------------|
| `total` | int | Total skills discovered |
| `available` | int | Skills with installed tools |
| `unavailable` | int | Skills with missing tools |
| `user_count` | int | User-level skills |
| `project_count` | int | Project-level skills |
