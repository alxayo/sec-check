# Python Copilot SDK Development Guide for AgentSec

**CRITICAL**: Read this file before writing any Python code for the AgentSec project using GitHub Copilot SDK. This file ensures consistent Python version requirements, best practices, and project-specific patterns.

**Status**: AgentSec Project Standard  
**Target Python Versions**: 3.12 (recommended), 3.11 (supported), 3.10+ (minimum)  
**SDK Version**: v0.1.23+  
**Framework**: Microsoft Agent Framework with GitHub Copilot SDK

---

## Python Version Requirements

### Recommended Versions (in order of preference)

| Version | Status | Notes |
|---------|--------|-------|
| **3.12** | ⭐ Recommended | Latest stable, best performance, latest async features |
| **3.11** | ✅ Supported | Excellent async improvements, widely available |
| **3.10** | ⚠️ Minimum | Older but functional; avoid if possible |
| < 3.10 | ❌ Unsupported | Do not use; incompatible with agent framework |

### Verification Command

Always verify your Python version matches requirements:

```bash
python --version  # Should show Python 3.12.x, 3.11.x, or 3.10.x
```

### Setting up Correct Python Version

#### Windows
```bash
# Check installed versions
py --list-paths

# Create virtual environment with specific Python
py -3.12 -m venv venv
.\venv\Scripts\activate
```

#### macOS/Linux
```bash
# Using pyenv (recommended)
pyenv install 3.12.0
pyenv local 3.12.0

# Or using system Python
python3.12 -m venv venv
source venv/bin/activate
```

---

## Virtual Environment Setup (CRITICAL)

### AgentSec-Specific Setup

For the AgentSec monorepo with three packages (core, cli, desktop), use a **single workspace-level virtual environment**:

```bash
# At workspace root: c:\code\AgentSec
python -m venv venv

# Activate (Windows)
.\venv\Scripts\activate

# Activate (macOS/Linux)
source venv/bin/activate

# Install in editable mode for development
pip install -e ./core              # Core agent package
pip install -e ./cli               # CLI package
pip install -e ./desktop/backend   # Desktop backend (if using Python)
```

### Why Single Environment?
- Shared dependencies across packages reduce conflicts
- Simplified debugging across monorepo
- Easier dependency management
- Mirrors production deployment pattern

### Verify Installation

```bash
python -c "from agent_framework import Agent; print('Agent Framework OK')"
python -c "from copilot import CopilotClient; print('Copilot SDK OK')"
```

---

## Core Dependencies & Pinned Versions

### Required Packages (from AgentSec Plan)

```
# core/pyproject.toml
dependencies = [
    "agent-framework-core==1.0.0b260107",
    "agent-framework-azure-ai==1.0.0b260107",
]

# desktop/backend/requirements.txt
fastapi>=0.104.0
uvicorn>=0.24.0
python-dotenv>=1.0.0
```

### Install All Dependencies

```bash
# From workspace root
pip install -r requirements.txt  # If root file exists
pip install -e ./core
pip install -e ./cli
pip install -e ./desktop/backend
```

### DO NOT modify pinned versions without testing
- `1.0.0b260107` versions are tested and stable for AgentSec
- Changing versions may break agent functionality
- Always test locally after version changes

---

## Authentication Setup (Required)

### Step 1: Install Copilot CLI

**BEFORE running any Python code**, install the Copilot CLI:

```bash
# Follow official guide:
# https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli

# Verify installation
copilot --version  # Should show version > 0.1.0
```

### Step 2: Authenticate with GitHub

```bash
# Login with GitHub
copilot auth login

# Verify authentication
copilot auth status
```

### Step 3: Configure Environment Variables

Create `.env` file at workspace root:

```bash
# For GitHub authentication (uses copilot CLI)
# Leave empty if using: copilot auth login
COPILOT_GITHUB_TOKEN=

# For Azure OpenAI (alternative)
AZURE_OPENAI_API_KEY=
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_DEPLOYMENT_NAME=

# For development logging
DEBUG=false
LOG_LEVEL=INFO
```

Load in Python:

```python
import os
from dotenv import load_dotenv

load_dotenv()  # Loads .env file

# Copilot SDK will automatically use authenticated CLI
client = CopilotClient()
await client.start()  # Will use CLI authentication
```

---

## Best Practices for Python + Copilot SDK

### 1. Always Use Async/Await Patterns

❌ **DON'T** (blocking code)
```python
# Never use synchronous calls
response = session.send_and_wait(prompt)  # ❌ Wrong
```

✅ **DO** (async-first)
```python
# Always async
async def scan_folder(folder_path: str):
    response = await session.send_and_wait(
        MessageOptions(prompt=f"Scan {folder_path}")
    )
    return response
```

### 2. Always Clean Up Resources with Try-Finally

❌ **DON'T** (resource leak)
```python
async def main():
    client = CopilotClient()
    await client.start()
    # ... code ...
    # ❌ If error occurs, client never stops
```

✅ **DO** (guaranteed cleanup)
```python
async def main():
    client = CopilotClient()
    try:
        await client.start()
        # ... code ...
    finally:
        await client.stop()  # Always runs
```

### 3. Use Type Hints Throughout

❌ **DON'T** (weak typing)
```python
async def analyze(data):
    return process(data)
```

✅ **DO** (strong typing)
```python
from typing import Optional
from copilot import SessionEvent

async def analyze(data: dict) -> Optional[str]:
    result: str = await process(data)
    return result

def handle_event(event: SessionEvent) -> None:
    if event.type == SessionEventType.ASSISTANT_MESSAGE:
        print(event.data.content)
```

### 4. Implement Proper Error Handling

✅ **DO** (comprehensive error handling)
```python
async def safe_scan(session, prompt: str) -> dict:
    try:
        response = await session.send_and_wait(
            MessageOptions(prompt=prompt),
            timeout=30.0
        )
        if response:
            return {"status": "success", "content": response.data.content}
    except TimeoutError:
        return {"status": "timeout", "error": "Request took too long"}
    except FileNotFoundError:
        return {"status": "error", "error": "Copilot CLI not installed"}
    except ConnectionError:
        return {"status": "error", "error": "Authentication failed"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
```

### 5. Use Meaningful Session IDs for Persistence

✅ **DO** (traceable sessions)
```python
# Good session ID structure
session_id = f"{user_id}-scan-{project_name}-{timestamp}"

session = await client.create_session(SessionConfig(
    session_id=session_id,
    model="gpt-5"
))
```

### 6. Handle Events for Long Operations

❌ **DON'T** (blocking wait for long operations)
```python
# For operations > 10 seconds, don't use send_and_wait
response = await session.send_and_wait(
    MessageOptions(prompt="Very long analysis...")
)
```

✅ **DO** (event-driven for long operations)
```python
# Use non-blocking send for long operations
done = asyncio.Event()

def handle_event(event: SessionEvent):
    if event.type == SessionEventType.ASSISTANT_MESSAGE:
        print(f"Progress: {event.data.content}")
    elif event.type.value == "session.idle":
        done.set()  # Signals completion

session.on(handle_event)
await session.send(MessageOptions(prompt="Long task..."))
await done.wait()  # Wait for completion via event
```

### 7. Set Appropriate Timeouts Based on Operation

```python
# Quick operations (< 5 seconds)
response = await session.send_and_wait(
    MessageOptions(prompt="What is 2+2?"),
    timeout=10.0
)

# Medium operations (5-30 seconds)
response = await session.send_and_wait(
    MessageOptions(prompt="Analyze this code..."),
    timeout=60.0
)

# Long operations (> 30 seconds)
# Use event-driven pattern instead:
await session.send(MessageOptions(prompt="Analyze large codebase..."))
await done.wait()  # Wait indefinitely for events
```

### 8. Use Sessions for Multi-Turn Conversations

✅ **DO** (maintain context)
```python
# Reuse session for follow-up questions
session = await client.create_session(SessionConfig(
    session_id="analysis-session",
    model="gpt-5"
))

# First message
response1 = await session.send_and_wait(
    MessageOptions(prompt="What are the security issues?")
)

# Follow-up uses context from first message
response2 = await session.send_and_wait(
    MessageOptions(prompt="How can I fix the critical ones?")
)

# Session context is automatically maintained
```

---

## AgentSec-Specific Best Practices

### 1. Skills Implementation Pattern

✅ **DO** (AgentSec skills structure - Well documented and simple)
```python
# core/agentsec/skills.py
from agent_framework import tool
from typing import List, Optional
import logging
import os

logger = logging.getLogger(__name__)

@tool(description="List all files in a directory recursively")
async def list_files(folder_path: str) -> List[str]:
    """
    Scan a directory and return all file paths found.
    
    This function walks through a folder and collects the paths of all files.
    It's simple and easy to understand for beginners learning Python.
    
    Args:
        folder_path: The path to the folder to scan
                    Example: "/home/user/project"
    
    Returns:
        A list of file paths found
        Example: ["/home/user/project/main.py", "/home/user/project/utils.py"]
    
    Raises:
        FileNotFoundError: If the folder doesn't exist
    
    Example:
        >>> files = await list_files("./src")
        >>> print(f"Found {len(files)} files")
    """
    try:
        files: List[str] = []
        
        # Walk through all folders and subfolders
        for root, directories, filenames in os.walk(folder_path):
            # For each file in the current folder
            for filename in filenames:
                # Create the full path to the file
                full_path = os.path.join(root, filename)
                # Add it to our list
                files.append(full_path)
        
        logger.info(f"Listed {len(files)} files in {folder_path}")
        return files
    except FileNotFoundError:
        logger.error(f"Folder not found: {folder_path}")
        raise
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        raise

@tool(description="Analyze a file for security issues")
async def analyze_file(file_path: str) -> dict:
    """
    Analyze a single file for security vulnerabilities.
    
    This function examines a file and identifies potential security issues.
    It includes simple checks that beginners can understand and extend.
    
    Args:
        file_path: Path to the file to analyze
    
    Returns:
        Dictionary with:
        - "issues": List of issues found (empty if none)
        - "severity": Overall risk level (info, warning, error)
        - "file": The file that was analyzed
    
    Example:
        >>> result = await analyze_file("app.py")
        >>> for issue in result["issues"]:
        ...     print(f"Found issue: {issue}")
    """
    try:
        result: dict = {
            "issues": [],
            "severity": "info",
            "file": file_path
        }
        
        # Step 1: Read the file content
        with open(file_path, "r") as file:
            content = file.read()
        
        # Step 2: Check for common security problems
        # Check for unsafe eval() - eval runs arbitrary code
        if "eval(" in content:
            result["issues"].append("Found unsafe eval() call")
            result["severity"] = "error"
        
        # Check for unsafe exec() - exec also runs arbitrary code
        if "exec(" in content:
            result["issues"].append("Found unsafe exec() call")
            result["severity"] = "error"
        
        # Check for hardcoded passwords
        if "password=" in content.lower():
            result["issues"].append("Possible hardcoded password")
            if result["severity"] != "error":
                result["severity"] = "warning"
        
        # Step 3: Return the results
        return result
    except Exception as e:
        logger.error(f"Error analyzing {file_path}: {e}")
        return {
            "issues": [str(e)],
            "severity": "error",
            "file": file_path
        }
```

### 2. Agent Configuration Pattern

✅ **DO** (AgentSec agent structure - Clear and well documented)
```python
# core/agentsec/agent.py
from agent_framework import Agent
from copilot import CopilotClient, SessionConfig, MessageOptions
from .skills import list_files, analyze_file
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class SecurityScannerAgent:
    """
    Main security scanning agent for AgentSec.
    
    This agent uses the GitHub Copilot SDK to analyze code for security issues.
    It's designed to be easy to understand and extend for beginners.
    
    Example:
        >>> agent = SecurityScannerAgent()
        >>> await agent.initialize()
        >>> try:
        ...     result = await agent.scan("./my_project")
        ... finally:
        ...     await agent.cleanup()
    """
    
    def __init__(self) -> None:
        """Initialize the agent (doesn't start connections yet)."""
        self.client: Optional[CopilotClient] = None
        self.session = None
        
    async def initialize(self) -> None:
        """
        Start the agent and connect to Copilot.
        
        This must be called before using the agent.
        It creates the Copilot client and starts a session.
        """
        try:
            # Create and start the Copilot client
            self.client = CopilotClient()
            await self.client.start()
            
            # Create a session (conversation context)
            # The system_message tells the agent what its job is
            self.session = await self.client.create_session(
                SessionConfig(
                    model="gpt-5",
                    system_message={
                        "content": """You are a security scanning agent for AgentSec.
                        Your job is to analyze code for vulnerabilities.
                        Use the provided tools to scan folders and files.
                        Always provide actionable recommendations."""
                    }
                )
            )
            
            logger.info("Agent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize agent: {e}")
            raise
            
    async def scan(self, folder_path: str) -> dict:
        """
        Perform a security scan of a folder.
        
        This is the main method that runs the security analysis.
        
        Args:
            folder_path: Path to the folder to scan
        
        Returns:
            Dictionary with scan results
        
        Example:
            >>> result = await agent.scan("./src")
            >>> print(result["status"])  # "success" or "error"
        """
        try:
            # Create a prompt that tells the agent what to do
            scan_prompt = f"""Perform a security scan of {folder_path}:
            1. List all files in the folder
            2. Analyze each file for security issues
            3. Generate a summary report with recommendations"""
            
            # Send the prompt and wait for the response
            response = await self.session.send_and_wait(
                MessageOptions(prompt=scan_prompt),
                timeout=120.0  # Allow up to 2 minutes for the scan
            )
            
            # Return the results
            return {
                "status": "success",
                "result": response.data.content if response else "No response"
            }
        except TimeoutError:
            logger.error("Scan took too long and timed out")
            return {
                "status": "timeout",
                "error": "Scan took too long (>120 seconds)"
            }
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
            
    async def cleanup(self) -> None:
        """
        Clean up resources.
        
        This must be called when done with the agent to properly
        close connections and free up resources.
        """
        try:
            # Destroy the session (if it exists)
            if self.session:
                await self.session.destroy()
                
            # Stop the client (if it exists)
            if self.client:
                await self.client.stop()
            
            logger.info("Agent cleaned up successfully")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
```

### 3. CLI Integration Pattern

✅ **DO** (AgentSec CLI structure - Simple and well documented)
```python
# cli/agentsec_cli/main.py
import argparse
import asyncio
from pathlib import Path
from agentsec.agent import SecurityScannerAgent
import logging

# Set up logging so we can see what's happening
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def scan_command(folder: str) -> None:
    """
    Handle the 'scan' command.
    
    This function:
    1. Validates the folder path
    2. Creates an agent
    3. Runs the scan
    4. Cleans up resources
    """
    # Convert the folder string to a Path object and make it absolute
    folder_path = Path(folder).resolve()
    
    # Check if the folder exists
    if not folder_path.exists():
        print(f"Error: Folder not found: {folder_path}")
        return
    
    # Create the agent
    agent = SecurityScannerAgent()
    
    try:
        # Start the agent
        print("Starting security scanner...")
        await agent.initialize()
        
        # Print what we're doing
        print(f"🔍 Scanning {folder_path}...")
        
        # Run the scan
        result = await agent.scan(str(folder_path))
        
        # Print the results based on status
        if result["status"] == "success":
            print(f"\n✅ Scan complete:\n{result['result']}")
        elif result["status"] == "timeout":
            print(f"⏱️  {result['error']}")
        else:
            print(f"❌ Scan failed: {result['error']}")
    
    finally:
        # Always clean up resources, even if an error occurred
        print("Cleaning up...")
        await agent.cleanup()

def main() -> None:
    """
    Main entry point for the CLI.
    
    This function:
    1. Sets up the command-line argument parser
    2. Parses user input
    3. Calls the appropriate command
    """
    # Create the main argument parser
    parser = argparse.ArgumentParser(
        description="AgentSec - Security Scanner for Code",
        epilog="Example: agentsec scan ./my_project"
    )
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Add the 'scan' command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a folder for security vulnerabilities"
    )
    # The 'scan' command requires a folder argument
    scan_parser.add_argument(
        "folder",
        help="Path to the folder to scan"
    )
    
    # Add the '--version' flag
    parser.add_argument(
        "--version",
        action="version",
        version="agentsec 0.1.0"
    )
    
    # Parse the command-line arguments
    args = parser.parse_args()
    
    # Execute the appropriate command
    if args.command == "scan":
        # Run the scan command asynchronously
        asyncio.run(scan_command(args.folder))
    else:
        # If no command was given, show help
        parser.print_help()

if __name__ == "__main__":
    main()
```

### 4. FastAPI Integration Pattern (for Desktop Backend)

### 4. FastAPI Integration Pattern (for Desktop Backend)

✅ **DO** (Desktop backend structure - Well organized and documented)
```python
# desktop/backend/server.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import socket

# Get a logger for this module
logger = logging.getLogger(__name__)

# Create the FastAPI app
app = FastAPI(
    title="AgentSec Backend",
    description="Backend API for the AgentSec security scanner",
    version="0.1.0"
)

# Configure CORS (Cross-Origin Resource Sharing)
# This allows the Next.js frontend to call this backend API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",   # Next.js development server
        "http://localhost:3001",   # Alternative dev port
    ],
    allow_credentials=True,
    allow_methods=["*"],           # Allow all HTTP methods (GET, POST, etc)
    allow_headers=["*"],           # Allow all headers
)

# Import the agent after FastAPI setup
from agentsec.agent import SecurityScannerAgent

async def create_agent():
    """
    Factory function to create a new agent instance.
    
    This function is called by the framework when needed.
    It initializes a fresh agent for each request.
    """
    agent = SecurityScannerAgent()
    await agent.initialize()
    return agent

@app.post("/api/scan")
async def scan_folder(request: dict) -> dict:
    """
    API endpoint for scanning a folder.
    
    This endpoint receives a folder path from the frontend,
    scans it, and returns the results.
    
    Args:
        request: Dictionary with key "folder" containing the path to scan
    
    Returns:
        Dictionary with the scan results
    """
    try:
        # Extract the folder path from the request
        folder_path = request.get("folder")
        
        if not folder_path:
            return {"status": "error", "error": "No folder specified"}
        
        # Create an agent
        agent = await create_agent()
        
        try:
            # Run the scan
            result = await agent.scan(folder_path)
            return result
        finally:
            # Always clean up the agent
            await agent.cleanup()
    
    except Exception as e:
        logger.error(f"Error in scan endpoint: {e}")
        return {
            "status": "error",
            "error": f"Failed to scan: {str(e)}"
        }

@app.get("/api/health")
async def health_check() -> dict:
    """
    Health check endpoint.
    
    This endpoint returns a simple response to verify the backend is running.
    The frontend can call this to check if the server is available.
    """
    return {
        "status": "ok",
        "service": "agentsec-backend",
        "version": "0.1.0"
    }

if __name__ == "__main__":
    import uvicorn
    
    # Find an available port (not 8000 which might be in use)
    sock = socket.socket()
    sock.bind(("", 0))  # Bind to any available port
    port = sock.getsockname()[1]
    sock.close()
    
    # Write the port to a temporary file
    # This allows the Electron app to know which port the server is running on
    with open("/tmp/agentsec-port.txt", "w") as f:
        f.write(str(port))
    
    logger.info(f"Starting AgentSec backend server on port {port}")
    
    # Start the server
    uvicorn.run(
        app,
        host="127.0.0.1",  # Only listen on localhost
        port=port,
        log_level="info"
    )
```

### 4. FastAPI Integration Pattern (for Desktop Backend)

✅ **DO** (Desktop backend structure - Well organized and documented)
```python
# desktop/backend/server.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import socket

# Get a logger for this module
logger = logging.getLogger(__name__)

# Create the FastAPI app
app = FastAPI(
    title="AgentSec Backend",
    description="Backend API for the AgentSec security scanner",
    version="0.1.0"
)

# Configure CORS (Cross-Origin Resource Sharing)
# This allows the Next.js frontend to call this backend API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",   # Next.js development server
        "http://localhost:3001",   # Alternative dev port
    ],
    allow_credentials=True,
    allow_methods=["*"],           # Allow all HTTP methods (GET, POST, etc)
    allow_headers=["*"],           # Allow all headers
)

# Import the agent after FastAPI setup
from agentsec.agent import SecurityScannerAgent

async def create_agent():
    """
    Factory function to create a new agent instance.
    
    This function is called by the framework when needed.
    It initializes a fresh agent for each request.
    """
    agent = SecurityScannerAgent()
    await agent.initialize()
    return agent

@app.post("/api/scan")
async def scan_folder(request: dict) -> dict:
    """
    API endpoint for scanning a folder.
    
    This endpoint receives a folder path from the frontend,
    scans it, and returns the results.
    
    Args:
        request: Dictionary with key "folder" containing the path to scan
    
    Returns:
        Dictionary with the scan results
    """
    try:
        # Extract the folder path from the request
        folder_path = request.get("folder")
        
        if not folder_path:
            return {"status": "error", "error": "No folder specified"}
        
        # Create an agent
        agent = await create_agent()
        
        try:
            # Run the scan
            result = await agent.scan(folder_path)
            return result
        finally:
            # Always clean up the agent
            await agent.cleanup()
    
    except Exception as e:
        logger.error(f"Error in scan endpoint: {e}")
        return {
            "status": "error",
            "error": f"Failed to scan: {str(e)}"
        }

@app.get("/api/health")
async def health_check() -> dict:
    """
    Health check endpoint.
    
    This endpoint returns a simple response to verify the backend is running.
    The frontend can call this to check if the server is available.
    """
    return {
        "status": "ok",
        "service": "agentsec-backend",
        "version": "0.1.0"
    }

if __name__ == "__main__":
    import uvicorn
    
    # Find an available port (not 8000 which might be in use)
    sock = socket.socket()
    sock.bind(("", 0))  # Bind to any available port
    port = sock.getsockname()[1]
    sock.close()
    
    # Write the port to a temporary file
    # This allows the Electron app to know which port the server is running on
    with open("/tmp/agentsec-port.txt", "w") as f:
        f.write(str(port))
    
    logger.info(f"Starting AgentSec backend server on port {port}")
    
    # Start the server
    uvicorn.run(
        app,
        host="127.0.0.1",  # Only listen on localhost
        port=port,
        log_level="info"
    )
```
```

---

## Development Workflow in VS Code

### Recommended Extensions

Install these extensions in VS Code:

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.debugpy",
    "charliermarsh.ruff",
    "ms-azuretools.vscode-azure-github-copilot"
  ]
}
```

### Launch Configuration (`.vscode/launch.json`)

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Agent Test",
      "type": "python",
      "request": "launch",
      "module": "agentsec.agent",
      "console": "integratedTerminal",
      "jinja": true,
      "env": {"PYTHONPATH": "${workspaceFolder}/core"}
    },
    {
      "name": "CLI Scan",
      "type": "python",
      "request": "launch",
      "module": "agentsec_cli.main",
      "args": ["scan", "./test-folder"],
      "console": "integratedTerminal",
      "env": {"PYTHONPATH": "${workspaceFolder}/cli"}
    },
    {
      "name": "FastAPI Backend",
      "type": "python",
      "request": "launch",
      "module": "uvicorn",
      "args": ["desktop.backend.server:app", "--reload", "--port", "8000"],
      "console": "integratedTerminal",
      "env": {"PYTHONPATH": "${workspaceFolder}/desktop/backend"}
    }
  ]
}
```

### Tasks Configuration (`.vscode/tasks.json`)

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Activate venv (Windows)",
      "type": "shell",
      "command": ".\\venv\\Scripts\\activate",
      "problemMatcher": [],
      "runOptions": {"runOn": "folderOpen"}
    },
    {
      "label": "Install dependencies",
      "type": "shell",
      "command": "pip",
      "args": ["install", "-e", "./core", "-e", "./cli"],
      "problemMatcher": []
    },
    {
      "label": "Run agent test",
      "type": "shell",
      "command": "python",
      "args": ["-m", "agentsec.agent"],
      "problemMatcher": []
    },
    {
      "label": "Scan test folder",
      "type": "shell",
      "command": "agentsec",
      "args": ["scan", "./test-folder"],
      "problemMatcher": []
    }
  ]
}
```

---

## Common Patterns & Recipes

### Pattern 1: Basic Agent Initialization & Cleanup

```python
async def with_agent():
    """Template for agent operations"""
    agent = SecurityScannerAgent()
    
    try:
        await agent.initialize()  # Start client & session
        # ... perform operations ...
    except Exception as e:
        logger.error(f"Operation failed: {e}")
    finally:
        await agent.cleanup()  # Always clean up
```

### Pattern 2: Streaming Real-Time Results

```python
async def stream_scan_results(session, folder: str):
    """Stream scan results as they arrive"""
    done = asyncio.Event()
    
    def handle_events(event: SessionEvent):
        if event.type == SessionEventType.TOOL_EXECUTION_START:
            print(f"→ Scanning: {event.data.tool_name}")
        elif event.type == SessionEventType.ASSISTANT_MESSAGE:
            print(f"Result: {event.data.content}")
        elif event.type.value == "session.idle":
            done.set()
    
    session.on(handle_events)
    await session.send(MessageOptions(prompt=f"Scan {folder}"))
    await done.wait()
```

### Pattern 3: Resuming Sessions Across Runs

```python
async def get_or_create_session(client, session_id: str):
    """Reuse session if it exists, otherwise create new"""
    sessions = await client.list_sessions()
    session_ids = [s.session_id for s in sessions]
    
    if session_id in session_ids:
        session = await client.resume_session(session_id)
    else:
        session = await client.create_session(SessionConfig(
            session_id=session_id,
            model="gpt-5"
        ))
    
    return session
```

---

## Debugging & Troubleshooting

### Enable Debug Logging

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("copilot").setLevel(logging.DEBUG)
logging.getLogger("agent_framework").setLevel(logging.DEBUG)
```

### Common Issues & Solutions

**Issue: "Copilot CLI not found"**
```bash
# Solution: Install Copilot CLI
copilot --version  # Verify installation
which copilot      # Check PATH on macOS/Linux
where copilot      # Check PATH on Windows
```

**Issue: "Authentication failed"**
```bash
# Solution: Re-authenticate
copilot auth logout
copilot auth login
copilot auth status  # Verify
```

**Issue: "Timeout during scan"**
```python
# Solution: Increase timeout or use event-driven approach
response = await session.send_and_wait(
    MessageOptions(prompt="..."),
    timeout=300.0  # Increase from default 30s
)
```

**Issue: "Virtual environment not activated"**
```bash
# Solution: Verify activation
python --version  # Should show Python 3.12+
pip --version     # Should show pip from ./venv/

# If not activated:
.\venv\Scripts\activate  # Windows
source venv/bin/activate # macOS/Linux
```

---

## Testing Best Practices

### Unit Test Pattern

```python
# core/tests/test_skills.py
import pytest
from agentsec.skills import list_files

@pytest.mark.asyncio
async def test_list_files():
    """Test file listing skill"""
    files = await list_files("./test-data")
    assert len(files) > 0
    assert all(isinstance(f, str) for f in files)
```

### Integration Test Pattern

```python
# core/tests/test_agent.py
import pytest
from agentsec.agent import SecurityScannerAgent

@pytest.mark.asyncio
async def test_agent_initialization():
    """Test agent starts and stops cleanly"""
    agent = SecurityScannerAgent()
    
    await agent.initialize()
    assert agent.client is not None
    assert agent.session is not None
    
    await agent.cleanup()
    assert agent.client is None
```

---

## Environment Variables Reference

### Required (Development)

```bash
# At minimum, authenticate with GitHub:
# - Either: copilot auth login (no env var needed)
# - Or: COPILOT_GITHUB_TOKEN=ghp_xxxxx
```

### Optional (for Azure OpenAI)

```bash
AZURE_OPENAI_API_KEY=your_key
AZURE_OPENAI_ENDPOINT=https://xxx.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_NAME=deployment_name
```

### Development

```bash
DEBUG=true           # Enable debug logging
LOG_LEVEL=DEBUG      # Set log level
PYTHONUNBUFFERED=1   # Real-time output
```

---

## Performance Optimization

### 1. Lazy Load Heavy Dependencies

```python
# Only import when needed
def get_agent():
    from agentsec.agent import SecurityScannerAgent
    return SecurityScannerAgent()
```

### 2. Use Connection Pooling

```python
# Reuse client for multiple sessions
client = CopilotClient()
await client.start()

session1 = await client.create_session(SessionConfig(model="gpt-5"))
session2 = await client.create_session(SessionConfig(model="gpt-5"))

# Use both sessions...

await client.stop()  # Cleanup once
```

### 3. Parallel Scans with Multiple Sessions

```python
# Scan multiple folders concurrently
async def parallel_scans(folders: List[str]):
    agent = SecurityScannerAgent()
    await agent.initialize()
    
    tasks = [
        agent.scan(folder)
        for folder in folders
    ]
    
    results = await asyncio.gather(*tasks)
    await agent.cleanup()
    
    return results
```

---

## Project-Specific Checklist

- ✅ Python 3.11+ installed and verified
- ✅ Virtual environment created at workspace root
- ✅ Copilot CLI installed and authenticated
- ✅ Agent Framework pinned to `1.0.0b260107`
- ✅ All files use type hints
- ✅ Async/await patterns used throughout
- ✅ Try-finally for resource cleanup
- ✅ Meaningful session IDs with context
- ✅ Error handling for timeouts and auth
- ✅ Events used for long operations (>10s)
- ✅ Skills follow `@tool` decorator pattern
- ✅ CLI integration complete
- ✅ FastAPI backend for desktop
- ✅ Debug configurations in VS Code

---

## Version Information

**Python Target Versions**: 3.12 (recommended), 3.11, 3.10+  
**SDK Version**: v0.1.23+ (GitHub Copilot SDK)  
**Framework**: Microsoft Agent Framework (1.0.0b260107)  
**FastAPI**: 0.104.0+  
**Uvicorn**: 0.24.0+  

---

## Code Simplicity & Documentation for Beginners

This section ensures all Python code in AgentSec is written so beginners can understand and learn from it. **Code clarity is more important than brevity.**

### Principle 1: Comprehensive Documentation

**Every function must have a docstring** explaining what it does, why it exists, and how to use it.

**✅ DO - Detailed docstrings with examples**:
```python
async def scan_python_file(file_path: str) -> dict:
    """
    Scan a Python file for security vulnerabilities.
    
    This function reads a Python file and checks for common security issues
    like unsafe eval() calls, hardcoded passwords, and SQL injection risks.
    It's designed to be simple to understand so beginners can extend it.
    
    Args:
        file_path: The absolute path to the Python file to scan.
                  Example: "/home/user/project/main.py"
    
    Returns:
        A dictionary containing:
        - "file": The path to the file that was scanned
        - "issues": List of security issues found (empty if none)
        - "severity": Overall severity level: "info", "warning", or "error"
        - "scan_time": How long the scan took in seconds
    
    Raises:
        FileNotFoundError: If the file does not exist
        PermissionError: If you don't have permission to read the file
    
    Example:
        >>> result = await scan_python_file("app.py")
        >>> print(f"Found {len(result['issues'])} issues")
        >>> print(f"Severity: {result['severity']}")
    """
```

**❌ DON'T - Minimal or missing docstrings**:
```python
async def scan_python_file(file_path: str) -> dict:
    """Scan a file."""
    pass
```

### Principle 2: Simple Code Over Clever Code

**Prefer explicit code that a beginner can understand.** Avoid complex syntax like nested list comprehensions, lambda functions, or advanced Python features.

**✅ DO - Clear, step-by-step code**:
```python
async def find_security_issues(file_content: str) -> list:
    """
    Find all security issues in code content.
    
    This function checks code for common security problems.
    Each check is in its own section so it's easy to understand and modify.
    """
    issues = []
    
    # Check 1: Unsafe eval() call
    # eval() executes arbitrary Python code, which is dangerous
    if "eval(" in file_content:
        issue = {
            "type": "unsafe-eval",
            "message": "Found unsafe eval() call",
            "severity": "HIGH"
        }
        issues.append(issue)
    
    # Check 2: Unsafe exec() call
    # exec() executes arbitrary Python code, similar to eval()
    if "exec(" in file_content:
        issue = {
            "type": "unsafe-exec",
            "message": "Found unsafe exec() call",
            "severity": "HIGH"
        }
        issues.append(issue)
    
    # Check 3: Hardcoded password
    # Passwords should never be in source code
    if "password=" in file_content.lower():
        issue = {
            "type": "hardcoded-password",
            "message": "Found possible hardcoded password",
            "severity": "MEDIUM"
        }
        issues.append(issue)
    
    return issues
```

**❌ DON'T - Complex, hard-to-understand code**:
```python
async def find_security_issues(file_content: str) -> list:
    """Find security issues."""
    checks = [
        ("eval(", "unsafe-eval", "Found unsafe eval()"),
        ("exec(", "unsafe-exec", "Found unsafe exec()"),
        ("password=", "hardcoded-password", "Found possible hardcoded password")
    ]
    return [{"type": c[1], "message": c[2], "severity": "HIGH"} 
            for c in checks if c[0] in file_content]
```

### Principle 3: Meaningful Variable Names

**Use long, descriptive variable names.** Never abbreviate unless absolutely necessary.

**✅ DO - Clear variable names**:
```python
# Good: Anyone can understand what these variables mean
maximum_timeout_seconds = 60
is_file_readable = True
security_issues_found = []
user_authentication_token = "ghp_xxxxx"
folder_to_scan_path = "/home/user/project"
number_of_files_analyzed = 0
error_message_for_user = "Invalid folder path"
```

**❌ DON'T - Abbreviated variable names**:
```python
# Bad: Unclear what these variables represent
max_to = 60
is_fr = True
sif = []
uat = "ghp_xxxxx"
fsp = "/home/user/project"
nfa = 0
emfu = "Invalid folder path"
```

### Principle 4: Small, Focused Functions

**Each function should do ONE thing only.** If a function is longer than about 15 lines, consider breaking it into smaller functions.

**✅ DO - Small, focused functions**:
```python
async def read_python_file(file_path: str) -> str:
    """Read the content of a Python file."""
    with open(file_path, "r") as file:
        content = file.read()
    return content

async def check_for_eval(content: str) -> bool:
    """Check if code contains unsafe eval() calls."""
    return "eval(" in content

async def check_for_hardcoded_secrets(content: str) -> bool:
    """Check if code contains hardcoded passwords or API keys."""
    dangerous_patterns = ["password=", "api_key=", "secret="]
    for pattern in dangerous_patterns:
        if pattern in content.lower():
            return True
    return False

async def scan_file(file_path: str) -> dict:
    """Scan a file for security issues."""
    # Step 1: Read the file
    content = await read_python_file(file_path)
    
    # Step 2: Check for issues
    issues = []
    if await check_for_eval(content):
        issues.append("Found unsafe eval() call")
    if await check_for_hardcoded_secrets(content):
        issues.append("Found hardcoded secret")
    
    # Step 3: Return results
    return {"file": file_path, "issues": issues}
```

**❌ DON'T - Long functions doing multiple things**:
```python
async def scan_file(file_path: str) -> dict:
    """Scan a file for security issues."""
    # Too much happening in one function
    with open(file_path, "r") as f:
        content = f.read()
    issues = []
    if "eval(" in content:
        issues.append("Found unsafe eval() call")
    if "password=" in content.lower():
        issues.append("Found hardcoded password")
    # ... more checks
    # ... more processing
    # ... more formatting
    return {"file": file_path, "issues": issues}
```

### Principle 5: Helpful Comments

**Add comments to explain WHY, not WHAT.** The code should be clear enough that the "what" is obvious.

**✅ DO - Comments that explain purpose**:
```python
async def analyze_file(file_path: str) -> dict:
    """Analyze a file for security issues."""
    
    # We read the file in text mode because we're looking at Python source code.
    # This allows us to easily search for string patterns.
    with open(file_path, "r") as file:
        content = file.read()
    
    issues = []
    
    # We check for 'eval(' because eval() executes arbitrary Python code.
    # This is dangerous if the code comes from an untrusted source.
    if "eval(" in content:
        issues.append({
            "issue": "unsafe-eval",
            "reason": "eval() can execute arbitrary code"
        })
    
    # We use a loop here so we can check multiple dangerous patterns.
    # Each pattern is checked independently, making it easy to add more checks.
    dangerous_patterns = ["exec(", "input(", "__import__"]
    for pattern in dangerous_patterns:
        if pattern in content:
            issues.append({"issue": pattern, "reason": "Potentially dangerous"})
    
    return {"file": file_path, "issues": issues}
```

**❌ DON'T - Comments that just repeat the code**:
```python
async def analyze_file(file_path: str) -> dict:
    """Analyze a file for security issues."""
    
    # Open the file
    with open(file_path, "r") as file:
        # Read the content
        content = file.read()
    
    # Create an empty list
    issues = []
    
    # Check if 'eval(' is in content
    if "eval(" in content:
        # Add to issues
        issues.append({"issue": "unsafe-eval"})
    
    # Return the dictionary
    return {"file": file_path, "issues": issues}
```

### Principle 6: Error Handling for Clarity

**Always handle errors explicitly.** This helps beginners understand what can go wrong and how to handle it.

**✅ DO - Clear error handling**:
```python
async def read_file(file_path: str) -> str:
    """
    Read a file, with proper error handling.
    
    This function shows how to handle different types of errors
    that can occur when reading a file.
    """
    try:
        # Try to open and read the file
        with open(file_path, "r") as file:
            content = file.read()
        
        return content
    
    except FileNotFoundError:
        # This error means the file doesn't exist
        error_message = f"File not found: {file_path}"
        logger.error(error_message)
        raise FileNotFoundError(error_message)
    
    except PermissionError:
        # This error means we don't have permission to read the file
        error_message = f"Permission denied: {file_path}"
        logger.error(error_message)
        raise PermissionError(error_message)
    
    except Exception as e:
        # This catches any other error we didn't expect
        logger.error(f"Unexpected error reading file: {e}")
        raise
```

**❌ DON'T - Silent failures or unclear error handling**:
```python
async def read_file(file_path: str) -> str:
    """Read a file."""
    try:
        with open(file_path, "r") as file:
            return file.read()
    except:
        # Silently fail - beginners won't understand what went wrong
        return ""
```

### Principle 7: Type Hints for Clarity

**Always use type hints.** They help beginners understand what type of data each function expects and returns.

**✅ DO - Complete type hints**:
```python
from typing import List, Dict, Optional

# Type hints show what types are expected
async def analyze_files(
    file_paths: List[str],
    max_severity: str = "error"
) -> Dict[str, any]:
    """
    Analyze multiple files.
    
    Args:
        file_paths: List of paths to analyze (like ["file1.py", "file2.py"])
        max_severity: Maximum severity to report (like "error", "warning")
    
    Returns:
        Dictionary with keys:
        - "total_files": Number of files analyzed
        - "issues": List of all issues found
        - "scan_time": Time taken in seconds
    """
    results: Dict[str, any] = {
        "total_files": len(file_paths),
        "issues": [],
        "scan_time": 0.0
    }
    
    # Analyze each file
    for file_path in file_paths:
        analysis_result: Dict = await analyze_file(file_path)
        results["issues"].extend(analysis_result["issues"])
    
    return results
```

**❌ DON'T - Missing or unclear type hints**:
```python
async def analyze_files(file_paths, max_severity="error"):
    """Analyze files."""
    results = {}
    for f in file_paths:
        r = await analyze_file(f)
        # Unclear what types are involved
    return results
```

1. **Always use Python 3.12** (or 3.11 minimum)
2. **Activate workspace venv** before any work
3. **Install Copilot CLI and authenticate** first
4. **Use async/await throughout** - no synced code
5. **Always cleanup resources** with try-finally
6. **Add type hints** to all functions
7. **Handle errors properly** with meaningful exceptions
8. **Use sessions wisely** - reuse for multi-turn, create new for isolation
9. **Event-driven for long ops** - send + wait only for quick responses
10. **Follow AgentSec patterns** - skills, agent, CLI structure

This ensures consistent, maintainable, and reliable Python code using the Copilot SDK for the AgentSec security scanning platform.
