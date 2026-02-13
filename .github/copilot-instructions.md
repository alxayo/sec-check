# AgentSec - AI Agent Coding Guide

**This project uses GitHub Copilot SDK with Microsoft Agent Framework for security scanning. Read the Python-specific guide at `.vscode/python-copilot-sdk.instructions.md` before writing any agent code.**

## Project Architecture

**Monorepo Structure** (3 independent packages in single repo):
```
agentsec/
├── core/                  # Shared agent + skills (Python)
│   └── agentsec/
│       ├── agent.py      # SecurityScannerAgent class
│       ├── config.py     # AgentSecConfig for customization
│       └── skills.py     # @tool decorated skill functions
├── cli/                  # Command-line interface (Python)
│   └── agentsec_cli/
│       └── main.py       # argparse CLI entry point
└── desktop/              # GUI + Electron wrapper
    ├── backend/          # FastAPI server (Python)
    │   └── server.py     # HTTP endpoint hosting agent
    └── frontend/         # Next.js UI (TypeScript)
```

**Communication Flow**:
- **CLI**: `main.py` → imports `SecurityScannerAgent` from core → direct agent invocation
- **Desktop**: Electron spawns FastAPI subprocess → FastAPI endpoint exposes agent via HTTP → Next.js frontend calls via SSE

**Deployment**:
- CLI distributed via PyPI: `pip install agentsec`
- Desktop distributed as native installer (Windows NSIS, macOS DMG)

---

## Critical Development Workflows

### Setup (Required First)

```bash
# 1. Verify Python 3.12 (or 3.11 min)
python --version

# 2. Create workspace-level venv (single environment for all 3 packages)
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate # macOS/Linux

# 3. Install Copilot CLI (required for SDK runtime)
copilot --version  # Verify installed
copilot auth login # Authenticate with GitHub

# 4. Install all packages in editable mode
pip install -e ./core        # Agent + skills
pip install -e ./cli         # CLI wrapper
pip install -e ./desktop/backend  # FastAPI server
```

### Agent Development (core/)

```bash
# Define agent in core/agentsec/agent.py
# - SecurityScannerAgent class
# - Uses CopilotClient from SDK
# - Manages session lifecycle (start/initialize/cleanup)

# Define skills in core/agentsec/skills.py
# - Use @tool decorator from agent_framework
# - Async functions only
# - Return dict with status, results, errors

# Test agent invocation
python -c "
import asyncio
from agentsec.agent import SecurityScannerAgent
asyncio.run(SecurityScannerAgent().scan('./test-folder'))
"
```

### CLI Development (cli/)

```bash
# CLI imports agent from core package
# agentsec_cli/main.py uses argparse for command routing
# Key commands: agentsec scan <folder>, agentsec --version

# Test CLI locally
agentsec scan ./test-folder

# Test with custom configuration
agentsec scan ./test-folder --config ./agentsec.yaml
agentsec scan ./test-folder --system-message-file ./custom-prompt.txt

# Test in clean environment before publishing
pip install -e .  # Local install
which agentsec    # Verify command available
agentsec --help   # Verify entry point
```

### Desktop Backend Development (desktop/backend/)

```bash
# FastAPI server exposes agent at /api/scan
# Uses add_agent_framework_fastapi_endpoint() utility
# Implements SSE streaming for real-time progress

# Start server (finds available port automatically)
python desktop/backend/server.py

# Test endpoint
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"folder": "./test-folder"}'

# Health check
curl http://localhost:8000/api/health
```

### Desktop Frontend Development (desktop/frontend/)

```bash
# Next.js TypeScript React components
# Key components: FolderSelector, ScanProgress (SSE), ResultsPanel

# Start dev server
cd desktop/frontend && npm run dev

# Connect to backend (configure via env var)
NEXT_PUBLIC_API_URL=http://localhost:8000

# Test end-to-end: select folder → click scan → stream results
```

---

## Configuration System

AgentSec supports customizable system messages and prompts via configuration files and CLI options.

### Configuration Priority (highest to lowest)
1. **CLI arguments** — `--system-message`, `--prompt`, etc.
2. **Config file** — `agentsec.yaml` or file specified via `--config`
3. **Built-in defaults** — hardcoded in `config.py`

### Using Configuration

**Via YAML file** (`agentsec.yaml`):
```yaml
# Set the AI's system prompt
system_message: |
  You are a security expert focusing on Python web apps.
  Focus on SQL injection and XSS vulnerabilities.

# Or load from external file
# system_message_file: ./prompts/system.txt

# Set the initial scan prompt template
initial_prompt: |
  Scan {folder_path} for security issues.
  Focus on HIGH severity only.

# Or load from external file
# initial_prompt_file: ./prompts/scan.txt
```

**Via CLI**:
```bash
# Use config file
agentsec scan ./src --config ./agentsec.yaml

# Override system message directly
agentsec scan ./src --system-message "You are a security expert..."

# Load system message from file
agentsec scan ./src --system-message-file ./prompts/system.txt

# Override initial prompt
agentsec scan ./src --prompt "Quick scan of {folder_path}"

# Load prompt from file
agentsec scan ./src --prompt-file ./prompts/scan.txt
```

**Programmatically**:
```python
from agentsec.config import AgentSecConfig
from agentsec.agent import SecurityScannerAgent

# Load from YAML
config = AgentSecConfig.load("./agentsec.yaml")

# Or create custom config
config = AgentSecConfig(
    system_message="Custom AI instructions...",
    initial_prompt="Scan {folder_path} for issues."
)

# Apply CLI overrides
config = config.with_overrides(
    system_message_file="./custom-system.txt"
)

# Create agent with config
agent = SecurityScannerAgent(config=config)
```

### Config File Search Paths

`AgentSecConfig.load()` auto-searches for config files in:
1. Current directory: `agentsec.yaml`, `agentsec.yml`, `.agentsec.yaml`, `.agentsec.yml`
2. User home directory
3. `~/.config/agentsec/`

See [agentsec.example.yaml](../agentsec.example.yaml) for a full example with comments.

---

## Project-Specific Patterns & Conventions

### Python Patterns (MANDATORY for this project)

**1. Async/Await is REQUIRED** - Never use synchronous code
```python
# ✅ Correct: All async functions in agent/skills
async def scan(folder: str) -> dict:
    response = await session.send_and_wait(prompt)
    return {"status": "success", "result": response.data.content}

# ❌ Wrong: Synchronous code will break with SDK
def scan(folder):
    response = session.send_and_wait(prompt)  # ← Breaks!
```

**2. Resource Cleanup with Try-Finally** - SDK clients must be stopped
```python
# ✅ Correct: Always cleanup
try:
    await client.start()
    session = await client.create_session(...)
    # ... work ...
finally:
    await client.stop()

# ❌ Wrong: Client left running
await client.start()
# ... work ...
# Client never stops if error occurs
```

**3. Skills as @tool Decorated Functions** - Consistent interface for agent
```python
from agent_framework import tool

@tool(description="Brief description for LLM")
async def analyze_file(file_path: str) -> dict:
    """Full docstring."""
    try:
        result = {"issues": [], "severity": "info"}
        # Implementation
        return result
    except Exception as e:
        return {"issues": [str(e)], "severity": "error"}
```

**4. Session Management for Multi-Turn** - Reuse sessions for context
```python
# Create once with meaningful ID including context
session = await client.create_session(SessionConfig(
    session_id=f"user-{user_id}-{task_name}",
    model="gpt-5"
))

# Follow-up messages maintain context automatically
response1 = await session.send_and_wait(MessageOptions(prompt="Question 1"))
response2 = await session.send_and_wait(MessageOptions(prompt="Follow-up"))
```

**5. Event-Driven for Long Operations** - Only send_and_wait for quick (<10s) tasks
```python
# ✅ Quick operation: blocking wait OK
response = await session.send_and_wait(
    MessageOptions(prompt="Quick question"),
    timeout=10.0
)

# ✅ Long operation: event-driven pattern
done = asyncio.Event()
def handle_event(event):
    if event.type == SessionEventType.ASSISTANT_MESSAGE:
        print(f"Progress: {event.data.content}")
    elif event.type.value == "session.idle":
        done.set()

session.on(handle_event)
await session.send(MessageOptions(prompt="Long task"))
await done.wait()
```

### TypeScript/Next.js Patterns (Frontend only)

**1. SSE Client for Streaming Results** - Real-time updates from FastAPI
```typescript
// FolderSelector.tsx → ScanProgress.tsx → ResultsPanel.tsx
const streamScanResults = async (folder: string) => {
    const response = await fetch(`${API_URL}/api/scan`, {
        method: 'POST',
        body: JSON.stringify({ folder })
    });
    
    const reader = response.body?.getReader();
    while (true) {
        const { done, value } = await reader?.read() ?? {};
        if (done) break;
        updateProgress(new TextDecoder().decode(value));
    }
};
```

**2. Environment Variable for API URL** - Points to FastAPI backend
```typescript
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
```

### FastAPI Patterns (Backend only)

**1. CORS Configuration** - Allow Next.js frontend
```python
# desktop/backend/server.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Dev only
    allow_methods=["*"]
)
```

**2. Dynamic Port Finding** - Electron reads port from temp file
```python
sock = socket.socket()
sock.bind(("", 0))
port = sock.getsockname()[1]
with open("/tmp/agentsec-port.txt", "w") as f:
    f.write(str(port))
```

---

## Critical Dependencies & Versions

**PINNED** (do not change without testing):
- `agent-framework-core==1.0.0b260107`
- `agent-framework-azure-ai==1.0.0b260107`
- `pyyaml>=6.0` (for configuration files)

**Flexible**:
- Python: 3.12 (recommended), 3.11 (supported), 3.10+ (minimum)
- FastAPI: 0.104.0+
- Next.js: 14+
- Electron: latest stable

All Python code uses `.vscode/python-copilot-sdk.instructions.md` for detailed async, error handling, and session management patterns.

---

## Essential Files to Know

| File | Purpose |
|------|---------|
| `.vscode/copilot-sdk.instructions.md` | SDK fundamentals (sessions, models, auth) |
| `.vscode/python-copilot-sdk.instructions.md` | Python patterns + AgentSec best practices |
| `spec/plan-agentSec.md` | Architecture & implementation roadmap |
| `agentsec.example.yaml` | Example configuration file with documentation |
| `core/agentsec/agent.py` | SecurityScannerAgent entry point |
| `core/agentsec/config.py` | AgentSecConfig for customizable prompts |
| `core/agentsec/skills.py` | @tool skill definitions |
| `cli/agentsec_cli/main.py` | CLI command routing with config options |
| `desktop/backend/server.py` | FastAPI + agent exposure |
| `desktop/frontend/pages/index.tsx` | Next.js UI entry point |

---

## When Adding New Features

1. **New Skill**: Add `@tool` function in `core/agentsec/skills.py`, test via agent
2. **New CLI Command**: Add command in `cli/agentsec_cli/main.py`, test with `agentsec <cmd>`
3. **New API Endpoint**: Add route in `desktop/backend/server.py`, test with curl
4. **New Frontend Page**: Add component in `desktop/frontend/pages/`, test with `npm run dev`

Always:
- ✅ Use async/await (Python)
- ✅ Handle errors explicitly
- ✅ Add type hints
- ✅ Test each layer independently
- ✅ Verify cross-layer integration
- ✅ Run from workspace-level venv

---

## Key Questions This Project Answers

**Q: Where does the agent get defined?**  
A: `core/agentsec/agent.py` → `SecurityScannerAgent` class

**Q: How do I customize the agent's behavior?**  
A: Use `AgentSecConfig` from `core/agentsec/config.py` to set custom system message or prompt

**Q: How do I configure the agent via command line?**  
A: Use CLI options: `--config`, `--system-message`, `--system-message-file`, `--prompt`, `--prompt-file`

**Q: How do I add a new scanning capability?**  
A: Create async `@tool` function in `core/agentsec/skills.py`

**Q: How do users run the agent?**  
A: Two paths: `agentsec scan <folder>` (CLI) or Desktop GUI (Electron)

**Q: How does real-time progress work in the GUI?**  
A: FastAPI endpoint returns Server-Sent Events (SSE) stream

**Q: Can the CLI and GUI use the same agent code?**  
A: Yes! Both import `SecurityScannerAgent` from core package

**Q: What Python version is required?**  
A: 3.12 (recommended), 3.11 (supported), 3.10+ (minimum)

**Q: Why use a monorepo instead of separate repos?**  
A: Single agent implementation used by CLI + Desktop; easier to keep logic in sync

---

## Code Quality & Documentation Standards

### Documentation Requirements

Every piece of code must be well-documented and easy to understand for beginners:

**✅ DO - Document Everything**:
```python
# ✅ Document the purpose, inputs, and outputs
async def analyze_file(file_path: str) -> dict:
    """
    Analyze a single file for security vulnerabilities.
    
    This function examines the provided file and identifies
    potential security issues. It's designed to be simple to understand
    and extend for beginners.
    
    Args:
        file_path: Full path to the file to analyze
        
    Returns:
        A dictionary with these keys:
        - "issues": List of security issues found
        - "severity": Level of risk (info, warning, error)
        - "file": The file that was analyzed
        
    Example:
        result = await analyze_file("app.py")
        if result["issues"]:
            print(f"Found {len(result['issues'])} issues")
    """
    issues = []
    severity = "info"
    
    # Read the file content
    with open(file_path, "r") as f:
        content = f.read()
    
    # Check for common security problems
    # (Simple checks that beginners can understand)
    if "eval(" in content:
        issues.append("Found unsafe eval() call")
        severity = "error"
    
    return {
        "issues": issues,
        "severity": severity,
        "file": file_path
    }
```

**❌ DON'T - Skip documentation or use cryptic code**:
```python
# ❌ No documentation, unclear variable names
async def af(fp: str) -> dict:
    i = []
    s = "i"
    with open(fp) as f:
        c = f.read()
    return {"i": i, "s": s, "f": fp}
```

### Code Simplicity Standards

Write code that is easy to read and understand:

**✅ DO - Use simple, clear patterns**:
```python
# Break complex operations into simple steps
async def scan_folder(folder_path: str) -> dict:
    """Scan all Python files in a folder."""
    
    # Step 1: Get all Python files
    python_files = []
    for file_name in os.listdir(folder_path):
        if file_name.endswith(".py"):
            full_path = os.path.join(folder_path, file_name)
            python_files.append(full_path)
    
    # Step 2: Analyze each file
    results = []
    for file_path in python_files:
        result = await analyze_file(file_path)
        results.append(result)
    
    # Step 3: Return results
    return {
        "files_scanned": len(python_files),
        "results": results
    }
```

**❌ DON'T - Use overly complex syntax**:
```python
# ❌ Too complex for beginners to understand
async def scan_folder(fp: str) -> dict:
    results = [await analyze_file(os.path.join(fp, f)) 
               for f in os.listdir(fp) if f.endswith(".py")]
    return {"files_scanned": len(results), "results": results}
```

### Variable Naming Standards

Use meaningful, descriptive variable names:

**✅ DO - Clear, descriptive names**:
```python
# Good: Names clearly explain what the variable holds
user_id = "user-123"
is_security_issue_found = True
max_timeout_seconds = 30
file_analysis_results = {}
error_message = "File not found"
```

**❌ DON'T - Cryptic abbreviations**:
```python
# Bad: Unclear what these variables mean
uid = "user-123"
isf = True
mto = 30
far = {}
em = "File not found"
```

### Function Size & Complexity

Keep functions small and focused:

**✅ DO - Small, focused functions (5-15 lines)**:
```python
async def read_file_content(file_path: str) -> str:
    """Read and return the entire file content."""
    try:
        with open(file_path, "r") as file:
            content = file.read()
        return content
    except FileNotFoundError:
        return ""

async def find_security_issues(content: str) -> list:
    """Find all security issues in code content."""
    issues = []
    
    # Check for each type of issue
    if "eval(" in content:
        issues.append("Found unsafe eval() call")
    if "exec(" in content:
        issues.append("Found unsafe exec() call")
    
    return issues
```

**❌ DON'T - Long functions doing many things**:
```python
# Bad: Function is too long and does too much
async def process_everything(file_path: str) -> dict:
    with open(file_path) as f:
        content = f.read()
    issues = []
    if "eval(" in content:
        issues.append("Found unsafe eval() call")
    if "exec(" in content:
        issues.append("Found unsafe exec() call")
    # ... many more checks
    # ... formatting results
    # ... sending data somewhere
    return {"file": file_path, "issues": issues}
```

### Comments & Clarity

Add comments to explain the "why", not just the "what":

**✅ DO - Helpful comments for beginners**:
```python
# We use try-finally to guarantee cleanup, even if an error occurs.
# This is important because leaving resources open causes problems.
try:
    await client.start()
    # ... do work ...
finally:
    # Always run this, regardless of errors
    await client.stop()

# We check if the file ends with ".py" because we only want Python files.
# Other file types don't need security analysis.
if file_name.endswith(".py"):
    # This is a Python file, so we should analyze it
    files_to_scan.append(file_name)
```

**❌ DON'T - Comments that just repeat the code**:
```python
# Set x to 5
x = 5

# Add 1 to x
x = x + 1
```

## Quick Validation Checklist

Before submitting code:
- [ ] Code is well-documented with docstrings and comments
- [ ] Function names clearly describe what they do
- [ ] Variable names are descriptive, not cryptic
- [ ] Each function does ONE thing only
- [ ] Code uses simple patterns, not complex syntax
- [ ] Comments explain the "why", not just the "what"
- [ ] A beginner could understand the code without extensive help
- [ ] Python code uses `async def` everywhere
- [ ] Agent/skill functions have type hints
- [ ] Try-finally blocks clean up SDK resources
- [ ] Skills decorated with `@tool`
- [ ] Session IDs include meaningful context
- [ ] Long operations use event handlers, not `send_and_wait`
- [ ] FastAPI has CORS configured for frontend
- [ ] Frontend uses `NEXT_PUBLIC_API_URL` env var
- [ ] Code tested from workspace-level venv
- [ ] No hardcoded localhost ports (use dynamic finding)
