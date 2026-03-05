# AgentSec Core

The core package for AgentSec, providing the `SecurityScannerAgent` class, configuration management, and all `@tool`-decorated skill functions. Both the CLI and Desktop app import from this package to perform security scanning.

## Installation

```bash
pip install -e ./core
```

## Package Structure

- `agentsec/agent.py` — `SecurityScannerAgent` class (per-scan session factory, dynamic system messages, skip guidance)
- `agentsec/config.py` — `AgentSecConfig` class with system message template (scanner list generated dynamically at runtime), model selection, and safety guardrails
- `agentsec/orchestrator.py` — `ParallelScanOrchestrator` class for concurrent sub-agent scanning
- `agentsec/session_runner.py` — Shared `run_session_to_completion()` + `run_session_with_retries()` — activity-based waiting, nudges, tool health, transient-error retry with session factory
- `agentsec/session_logger.py` — Per-session file logging for debugging
- `agentsec/progress.py` — `ProgressTracker` class (uses `contextvars.ContextVar` for safe concurrent usage)
- `agentsec/skill_discovery.py` — `SCANNER_REGISTRY` (single source of truth), `classify_files()`, `is_scanner_relevant()`, `FOLDERS_TO_SKIP`, `get_skill_directories()`, dynamic skill discovery with 30s TTL cache
- `agentsec/tool_health.py` — `ToolHealthMonitor` class for stuck-tool detection, error patterns, and retry loops
- `agentsec/skills.py` — Legacy `@tool` skill functions (list_files, analyze_file, generate_report) — **not registered with any session**
- `tests/` — Unit and integration tests

## How Scanning Works

The agent uses **Copilot CLI built-in tools** as its primary scanning mechanism:

| Tool | Purpose |
|------|---------|
| `bash` | File discovery (`find`, `ls`) and direct invocation of security scanner CLIs (bandit, graudit, etc.) |
| `skill` | Invokes pre-configured Copilot CLI agentic skills (bandit-security-scan, graudit-security-scan, etc.) |
| `view` | Reads file contents for manual LLM code inspection |

A **directive system message** in `config.py` guides the LLM through a structured scanning workflow with comprehensive safety guardrails.

### Stall Detection & Activity-Based Waiting

The shared `run_session_to_completion()` in `session_runner.py` handles all wait logic for both `agent.py` and `orchestrator.py`.  `run_session_with_retries()` wraps it with automatic retry for transient errors (rate limits, 5xx) using exponential backoff and a session factory for fresh sessions on each attempt:

| Constant | Default | Purpose |
|----------|---------|---------|   
| `DEFAULT_INACTIVITY_TIMEOUT` | 120s | Seconds of no SDK events before sending a nudge |
| `DEFAULT_MAX_IDLE_NUDGES` | 3 | Consecutive unresponsive nudges before aborting |
| `DEFAULT_SAFETY_TIMEOUT` | 1800s | Absolute safety ceiling (rarely hit) |
| `MAX_TRANSIENT_RETRIES` | 3 | Automatic retries for transient errors |
| `TRANSIENT_RETRY_BASE_DELAY` | 5s | Base delay for exponential backoff (5s, 15s, 45s) |

The approach is **activity-based**: as long as SDK events keep arriving (tool calls, messages, reasoning), the session is alive and we keep waiting. Only when all activity stops does the nudge/abort mechanism activate.

Additional features:
- **Tool health monitoring**: Detects stuck tools, error output patterns, and retry loops via `ToolHealthMonitor`
- **Event handler cleanup**: All `session.on()` calls capture and invoke unsubscribe functions
- **Custom hooks**: `on_tool_start` and `on_tool_complete` callbacks for scan-specific behaviour (e.g., scanner invocation tracking, progress updates)
- **Callable nudge messages**: Nudge text can be a function for context-aware messages

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

| Setting | YAML Key | Description |
|---------|----------|-------------|
| `system_message` | `system_message` | The AI's system prompt (who it is, what it does) |
| `system_message_file` | `system_message_file` | Path to file containing system message |
| `initial_prompt` | `initial_prompt` | Prompt template for scans (use `{folder_path}` placeholder) |
| `initial_prompt_file` | `initial_prompt_file` | Path to file containing initial prompt |
| `model` | `model` | LLM model name (default: `gpt-5`) |

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

### Parallel Scanning

Use `scan_parallel()` to run multiple scanners concurrently:

```python
from agentsec.agent import SecurityScannerAgent

agent = SecurityScannerAgent()

try:
    await agent.initialize()

    # Run scanners in parallel (max 3 at once)
    result = await agent.scan_parallel(
        "./my-project",
        max_concurrent=3,
        timeout=300.0,
    )
    print(result["result"])
finally:
    await agent.cleanup()
```

The parallel scan uses `ParallelScanOrchestrator` under the hood:

```python
from agentsec.orchestrator import ParallelScanOrchestrator

orchestrator = ParallelScanOrchestrator(
    client=copilot_client,
    config=agent_config,
    max_concurrent=3,
)
result = await orchestrator.run("./my_project", timeout=300.0)
```

**3-phase workflow:**
1. **Discovery** — Walks the folder, classifies files, picks relevant scanners, builds a `ScanPlan`
2. **Parallel Scan** — Spawns one sub-agent session per scanner via `asyncio.gather` with a semaphore
3. **Synthesis** — Compiles all `SubAgentResult` objects into a single deduplicated report

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
| `PARALLEL_PLAN_READY` | Parallel scan plan created (scanners selected/skipped) |
| `SUB_AGENT_STARTED` | A sub-agent scanner session has started |
| `SUB_AGENT_FINISHED` | A sub-agent scanner session has finished |
| `SYNTHESIS_STARTED` | Synthesis phase begun (compiling sub-agent results) |
| `SYNTHESIS_FINISHED` | Synthesis phase complete |

## Skill Discovery

The `skill_discovery` module is the **single source of truth** for all scanner-related data. It provides:

- **`SCANNER_REGISTRY`** — consolidated dict mapping each skill name to its CLI tool, file-type relevance, and description. Adding a new scanner requires editing one entry here; all derived data updates automatically.
- **`SKILL_TO_TOOL_MAP`**, **`SCANNER_RELEVANCE`**, **`KNOWN_SCANNER_COMMANDS`** — derived views for backward compatibility
- **`classify_files()`** — walks a folder and classifies files by extension/name (shared by both agent and orchestrator)
- **`is_scanner_relevant()`** — checks whether a scanner is relevant for the discovered file types
- **`FOLDERS_TO_SKIP`** — common non-source directories to exclude from scanning
- **`discover_all_skills()`** — discovers Copilot CLI agentic skills from user and project directories (with 30s TTL cache)
- **`get_skill_directories()`** — returns skill directory paths for `SessionConfig`

The module discovers skills from the same directories the Copilot CLI uses:

- **User-level**: `~/.copilot/skills/`
- **Project-level**: `<project_root>/.copilot/skills/`

Each skill directory contains a `SKILL.md` file with YAML frontmatter. The module parses these, maps each skill to its underlying CLI tool, and checks whether the tool is installed.

### Basic Usage

```python
from agentsec.skill_discovery import discover_all_skills, get_skill_summary, get_skill_directories

# Discover all skills (user + project level)
skills = discover_all_skills("/path/to/project")

# Print each skill with availability
for skill in skills:
    mark = "✅" if skill["tool_available"] else "⬜"
    print(f"  {mark} {skill['tool_name']:<20} — {skill['description']}")

# Get summary statistics
summary = get_skill_summary(skills)
print(f"Available: {summary['available']}/{summary['total']}")

# Get directory paths for SDK SessionConfig
skill_dirs = get_skill_directories("/path/to/project")
# Pass to SessionConfig(skill_directories=skill_dirs)
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
