# GitHub Copilot SDK Instructions

**CRITICAL**: Read this file when building applications that integrate GitHub Copilot's agentic capabilities programmatically using the Copilot SDK. This file provides comprehensive guidance for Python, TypeScript/Node.js, Go, and .NET implementations.

## Overviewb

The GitHub Copilot SDK allows you to embed Copilot's agentic workflows directly into your applications. It provides a programmable interface to the same engine that powers the Copilot CLI, enabling your applications to leverage AI-powered planning, tool invocation, file operations, and multi-turn conversations.

**Status**: Technical Preview  
**Languages**: Python, TypeScript/Node.js, Go, .NET  
**GitHub Repository**: https://github.com/github/copilot-sdk  
**Cookbook Repository**: https://github.com/github/awesome-copilot/tree/main/cookbook/copilot-sdk

---

## Prerequisites

### 1. GitHub Copilot Subscription
- **Required** unless using BYOK (Bring Your Own Key)
- Includes free tier with limited usage
- Usage counts towards premium request quota
- See: https://github.com/features/copilot#pricing

### 2. Copilot CLI Installation
- **Required**: The SDK communicates with Copilot CLI in server mode
- Installation guide: https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli
- Ensure `copilot` command is available in PATH

### 3. SDK Installation

#### Python
```bash
pip install github-copilot-sdk
```

#### TypeScript/Node.js
```bash
npm install @github/copilot-sdk
```

#### Go
```bash
go get github.com/github/copilot-sdk/go
```

#### .NET
```bash
dotnet add package GitHub.Copilot.SDK
```

---

## Architecture

The SDK uses a client-server architecture:

```
Your Application
      ↓
  SDK Client
      ↓ (JSON-RPC)
Copilot CLI (server mode)
```

**Key Points**:
- SDK manages CLI process lifecycle automatically
- Communication via JSON-RPC protocol
- Can connect to external CLI server if needed
- Supports multiple concurrent sessions

---

## Authentication Methods

The SDK supports multiple authentication methods (in order of precedence):

1. **GitHub signed-in user**: Uses OAuth credentials from `copilot` CLI login
2. **OAuth GitHub App**: Pass user tokens from your GitHub OAuth app
3. **Environment variables**: `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`
4. **BYOK**: Use your own API keys (no GitHub auth required)

### Setting Up Authentication

#### GitHub CLI Login (Recommended for Development)
```bash
copilot auth login
```

#### BYOK (Bring Your Own Key)
```bash
# Set environment variable for OpenAI
export OPENAI_API_KEY=your_key_here

# Or Azure AI Foundry
export AZURE_AI_FOUNDRY_API_KEY=your_key_here
```

---

## Core Concepts

### 1. CopilotClient
The main entry point for SDK interactions. Manages connection to Copilot CLI.

### 2. Session
Represents a conversation context with its own history and state. Each session:
- Maintains independent conversation history
- Can be persisted and resumed
- Supports custom system messages
- Can use different models

### 3. Messages
User prompts sent to Copilot within a session.

### 4. Events
Real-time updates from Copilot about processing status, tool execution, and responses.

### 5. Tools
Built-in capabilities Copilot can use (file operations, Git, web requests, GitHub API, etc.)

---

## Basic Usage Pattern (Python)

### Minimal Example

```python
import asyncio
from copilot import CopilotClient, SessionConfig, MessageOptions

async def main():
    # Create and start client
    client = CopilotClient()
    await client.start()
    
    # Create a session
    session = await client.create_session(SessionConfig(model="gpt-5"))
    
    # Send a prompt and wait for response
    response = await session.send_and_wait(
        MessageOptions(prompt="Explain async programming in Python")
    )
    
    if response:
        print(response.data.content)
    
    # Clean up
    await session.destroy()
    await client.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Session Management

### Creating Sessions

```python
from copilot import SessionConfig

# Basic session
session = await client.create_session(SessionConfig(
    model="gpt-5"
))

# Session with custom ID (for persistence)
session = await client.create_session(SessionConfig(
    session_id="user-123-chat",
    model="claude-sonnet-4.5"
))

# Session with system message
session = await client.create_session(SessionConfig(
    model="gpt-5",
    system_message={
        "content": """You are a Python expert helping with code reviews.
        Focus on best practices and performance optimizations."""
    }
))
```

### Available Models
- `gpt-5` - Latest GPT model
- `claude-sonnet-4.5` - Anthropic Claude
- Other models available via CLI

**Note**: Use `await client.get_models()` to fetch available models at runtime.

### Resuming Sessions

```python
# Resume a previous session by ID
session = await client.resume_session("user-123-chat")

# Previous context is automatically restored
response = await session.send_and_wait(
    MessageOptions(prompt="What were we discussing?")
)
```

### Session Lifecycle

```python
# List all sessions
sessions = await client.list_sessions()
for s in sessions:
    print(f"Session: {s.session_id}")

# Get session history
messages = await session.get_messages()
for msg in messages:
    print(f"[{msg.type}] {msg.data.content}")

# Destroy session (keeps data on disk for resuming)
await session.destroy()

# Permanently delete session and all data
await client.delete_session("user-123-chat")
```

---

## Message Handling

### Sending Messages

```python
# Blocking: Wait for complete response
response = await session.send_and_wait(
    MessageOptions(prompt="Write a Python function to sort a list"),
    timeout=30.0  # Optional timeout in seconds
)

# Non-blocking: Use event handlers
await session.send(
    MessageOptions(prompt="Generate a long analysis...")
)
```

### Event-Driven Processing

```python
from copilot import SessionEvent, SessionEventType

# Create event handler
def handle_event(event: SessionEvent):
    if event.type == SessionEventType.ASSISTANT_MESSAGE:
        print(f"Copilot: {event.data.content}")
    elif event.type == SessionEventType.TOOL_EXECUTION_START:
        print(f"→ Running tool: {event.data.tool_name}")
    elif event.type == SessionEventType.TOOL_EXECUTION_COMPLETE:
        print(f"✓ Completed: {event.data.tool_call_id}")
    elif event.type.value == "session.idle":
        done.set()

# Register handler
session.on(handle_event)

# Send message
await session.send(MessageOptions(prompt="Analyze this repository"))

# Wait for completion
await done.wait()
```

### Common Event Types
- `ASSISTANT_MESSAGE` - Copilot's text response
- `TOOL_EXECUTION_START` - Tool invocation begins
- `TOOL_EXECUTION_COMPLETE` - Tool invocation completes
- `session.idle` - Session finished processing

---

## Error Handling Patterns

### Basic Try-Except

```python
async def safe_copilot_interaction():
    client = CopilotClient()
    
    try:
        await client.start()
        session = await client.create_session(SessionConfig(model="gpt-5"))
        
        response = await session.send_and_wait(
            MessageOptions(prompt="Hello!")
        )
        
        if response:
            print(response.data.content)
        
        await session.destroy()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.stop()
```

### Specific Error Types

```python
try:
    await client.start()
except FileNotFoundError:
    print("Copilot CLI not found. Please install it first.")
except ConnectionError:
    print("Could not connect to Copilot CLI server.")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Timeout Handling

```python
try:
    response = await session.send_and_wait(
        MessageOptions(prompt="Complex question..."),
        timeout=30.0
    )
    print("Response received")
except TimeoutError:
    print("Request timed out")
```

### Aborting Requests

```python
# Start a long-running request
await session.send(MessageOptions(prompt="Write a very long story..."))

# Abort after some condition
await asyncio.sleep(5)
await session.abort()
print("Request aborted")
```

### Graceful Shutdown

```python
import signal
import sys

def signal_handler(sig, frame):
    print("\nShutting down...")
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(client.stop())
    except RuntimeError:
        asyncio.run(client.stop())
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
```

---

## Multiple Concurrent Sessions

```python
async def multi_session_example():
    client = CopilotClient()
    await client.start()
    
    # Create multiple independent sessions
    python_session = await client.create_session(
        SessionConfig(session_id="python-help", model="gpt-5")
    )
    typescript_session = await client.create_session(
        SessionConfig(session_id="typescript-help", model="gpt-5")
    )
    go_session = await client.create_session(
        SessionConfig(session_id="go-help", model="claude-sonnet-4.5")
    )
    
    # Each session maintains its own context
    await python_session.send(
        MessageOptions(prompt="Help with Python virtual environments")
    )
    await typescript_session.send(
        MessageOptions(prompt="Help with TypeScript generics")
    )
    await go_session.send(
        MessageOptions(prompt="Help with Go modules")
    )
    
    # Follow-up messages stay in their respective contexts
    await python_session.send(
        MessageOptions(prompt="How do I activate it?")
    )
    
    # Clean up all sessions
    await python_session.destroy()
    await typescript_session.destroy()
    await go_session.destroy()
    await client.stop()
```

### Use Cases for Multiple Sessions
- **Multi-user applications**: One session per user
- **Multi-task workflows**: Separate sessions for different tasks
- **A/B testing**: Compare responses from different models
- **Parallel processing**: Handle multiple requests concurrently

---

## Tool Configuration

### Default Behavior
By default, the SDK enables all first-party tools (`--allow-all` mode):
- File system operations (read, write, create, delete)
- Git operations (commit, branch, status, diff)
- Web requests (HTTP GET/POST)
- GitHub API access via MCP servers
- Code execution (Python, Node.js, etc.)

### Custom Tool Configuration
Refer to individual SDK documentation for tool enablement/disablement options.

---

## Practical Recipes

### Recipe 1: File Management with AI

```python
import asyncio
import os
from copilot import (
    CopilotClient, SessionConfig, MessageOptions,
    SessionEvent, SessionEventType
)

async def organize_files():
    client = CopilotClient()
    await client.start()
    
    session = await client.create_session(SessionConfig(model="gpt-5"))
    
    done = asyncio.Event()
    
    def handle_event(event: SessionEvent):
        if event.type == SessionEventType.ASSISTANT_MESSAGE:
            print(f"\nCopilot: {event.data.content}")
        elif event.type == SessionEventType.TOOL_EXECUTION_START:
            print(f"  → {event.data.tool_name}")
        elif event.type.value == "session.idle":
            done.set()
    
    session.on(handle_event)
    
    target_folder = os.path.expanduser("~/Downloads")
    
    await session.send(MessageOptions(prompt=f"""
    Analyze files in "{target_folder}" and organize them into subfolders
    by file type. Create folders like "images", "documents", "videos".
    Show me the plan first before moving any files.
    """))
    
    await done.wait()
    
    await session.destroy()
    await client.stop()

if __name__ == "__main__":
    asyncio.run(organize_files())
```

### Recipe 2: GitHub Integration

```python
import asyncio
import subprocess
import re
from copilot import (
    CopilotClient, SessionConfig, MessageOptions,
    SessionEvent, SessionEventType
)

async def analyze_github_prs():
    # Detect GitHub repository
    result = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        capture_output=True,
        text=True
    )
    remote_url = result.stdout.strip()
    
    # Parse owner/repo from URL
    match = re.search(r"github\.com[:/](.+/.+?)(?:\.git)?$", remote_url)
    if not match:
        print("Not a GitHub repository")
        return
    
    repo = match.group(1)
    owner, repo_name = repo.split("/")
    
    client = CopilotClient()
    await client.start()
    
    session = await client.create_session(SessionConfig(
        model="gpt-5",
        system_message={
            "content": f"""
            You are analyzing pull requests for {owner}/{repo_name}.
            Use GitHub MCP Server tools to fetch PR data.
            """
        }
    ))
    
    done = asyncio.Event()
    
    def handle_event(event: SessionEvent):
        if event.type == SessionEventType.ASSISTANT_MESSAGE:
            print(f"\n{event.data.content}")
        elif event.type.value == "session.idle":
            done.set()
    
    session.on(handle_event)
    
    await session.send(MessageOptions(prompt=f"""
    Fetch open pull requests for {owner}/{repo_name}.
    Calculate age of each PR in days.
    Summarize: average age, oldest PR, and how many are stale (>7 days).
    """))
    
    await done.wait()
    
    await session.destroy()
    await client.stop()

if __name__ == "__main__":
    asyncio.run(analyze_github_prs())
```

### Recipe 3: Interactive CLI Tool

```python
import asyncio
from copilot import CopilotClient, SessionConfig, MessageOptions

async def interactive_assistant():
    client = CopilotClient()
    await client.start()
    
    # Create persistent session
    session = await client.create_session(SessionConfig(
        session_id="interactive-assistant",
        model="gpt-5",
        system_message={
            "content": "You are a helpful coding assistant. Be concise."
        }
    ))
    
    print("Interactive Assistant (type 'exit' to quit)\n")
    
    while True:
        user_input = input("You: ").strip()
        
        if user_input.lower() in ["exit", "quit"]:
            break
        
        if not user_input:
            continue
        
        try:
            response = await session.send_and_wait(
                MessageOptions(prompt=user_input),
                timeout=60.0
            )
            
            if response:
                print(f"\nAssistant: {response.data.content}\n")
        
        except TimeoutError:
            print("\nRequest timed out. Try again.\n")
        except Exception as e:
            print(f"\nError: {e}\n")
    
    await session.destroy()
    await client.stop()
    print("Goodbye!")

if __name__ == "__main__":
    asyncio.run(interactive_assistant())
```

---

## Best Practices

### 1. Always Clean Up Resources
```python
# Use try-finally to ensure cleanup
try:
    await client.start()
    # ... work with sessions
finally:
    await client.stop()
```

### 2. Handle Connection Errors
The CLI might not be installed or authentication might fail:
```python
try:
    await client.start()
except FileNotFoundError:
    print("Install Copilot CLI first")
except ConnectionError:
    print("Authentication failed")
```

### 3. Set Appropriate Timeouts
```python
# For quick responses
response = await session.send_and_wait(prompt, timeout=10.0)

# For complex operations
response = await session.send_and_wait(prompt, timeout=120.0)
```

### 4. Use Meaningful Session IDs
```python
# Include context in session ID
session_id = f"user-{user_id}-{project_name}"
session = await client.create_session(SessionConfig(
    session_id=session_id,
    model="gpt-5"
))
```

### 5. Log Events for Debugging
```python
def handle_event(event: SessionEvent):
    logging.info(f"Event: {event.type} - {event.data}")
    # ... handle event
```

### 6. Use Event-Driven for Long Operations
For operations that might take time, use event handlers instead of blocking:
```python
# Good for long operations
await session.send(MessageOptions(prompt="..."))
# Process events as they come

# Good for quick operations
response = await session.send_and_wait(MessageOptions(prompt="..."))
```

### 7. Handle Session Persistence Wisely
```python
# Check if session exists before attempting to resume
sessions = await client.list_sessions()
session_ids = [s.session_id for s in sessions]

if "user-123-chat" in session_ids:
    session = await client.resume_session("user-123-chat")
else:
    session = await client.create_session(SessionConfig(
        session_id="user-123-chat",
        model="gpt-5"
    ))
```

### 8. Clean Up Old Sessions Periodically
```python
# Delete sessions older than N days
sessions = await client.list_sessions()
for session_info in sessions:
    if should_delete(session_info):
        await client.delete_session(session_info.session_id)
```

---

## Common Patterns

### Pattern: Request-Response
Simple synchronous interaction:
```python
response = await session.send_and_wait(
    MessageOptions(prompt="Quick question")
)
print(response.data.content)
```

### Pattern: Streaming Events
Monitor real-time progress:
```python
done = asyncio.Event()

def handler(event):
    if event.type == SessionEventType.ASSISTANT_MESSAGE:
        print(event.data.content, end="", flush=True)
    elif event.type.value == "session.idle":
        done.set()

session.on(handler)
await session.send(MessageOptions(prompt="Long task"))
await done.wait()
```

### Pattern: Multi-Turn Conversation
Maintain context across multiple exchanges:
```python
session = await client.create_session(SessionConfig(model="gpt-5"))

await session.send_and_wait(MessageOptions(prompt="I'm building a REST API"))
await session.send_and_wait(MessageOptions(prompt="What framework should I use?"))
await session.send_and_wait(MessageOptions(prompt="Show me an example endpoint"))
```

### Pattern: Resumable Workflow
Persist and resume work across application restarts:
```python
# First run
session = await client.create_session(SessionConfig(
    session_id="data-analysis-task",
    model="gpt-5"
))
await session.send_and_wait(MessageOptions(prompt="Analyze dataset.csv"))
await session.destroy()

# Later, after restart
session = await client.resume_session("data-analysis-task")
await session.send_and_wait(MessageOptions(prompt="What were the key findings?"))
```

---

## Troubleshooting

### Issue: "Copilot CLI not found"
**Solution**: Install Copilot CLI and ensure it's in PATH
```bash
# Verify installation
copilot --version
```

### Issue: Authentication Errors
**Solution**: Authenticate with GitHub
```bash
copilot auth login
# Or set environment variable
export COPILOT_GITHUB_TOKEN=your_token
```

### Issue: Timeout Errors
**Solution**: Increase timeout or use async event handlers
```python
# Increase timeout
response = await session.send_and_wait(prompt, timeout=300.0)

# Or use non-blocking send
await session.send(prompt)
```

### Issue: Session Not Found
**Solution**: Check if session exists before resuming
```python
sessions = await client.list_sessions()
session_ids = [s.session_id for s in sessions]
if my_session_id in session_ids:
    session = await client.resume_session(my_session_id)
```

### Issue: High Billing Costs
**Solution**: Monitor usage and optimize prompts
- Each prompt counts as a premium request
- Use concise, specific prompts
- Consider BYOK for cost control

---

## Language-Specific Notes

### Python
- Requires Python 3.8+
- Use `asyncio.run()` for async main functions
- Install: `pip install github-copilot-sdk`

### TypeScript/Node.js
- Similar API to Python
- Use async/await patterns
- Install: `npm install @github/copilot-sdk`

### Go
- Context-aware APIs
- Use goroutines for concurrent sessions
- Install: `go get github.com/github/copilot-sdk/go`

### .NET
- C# async/await support
- Task-based async patterns
- Install: `dotnet add package GitHub.Copilot.SDK`

---

## Additional Resources

### Official Documentation
- SDK Repository: https://github.com/github/copilot-sdk
- Getting Started: https://github.com/github/copilot-sdk/blob/main/docs/getting-started.md
- Authentication Guide: https://github.com/github/copilot-sdk/blob/main/docs/auth/index.md
- BYOK Setup: https://github.com/github/copilot-sdk/blob/main/docs/auth/byok.md

### Cookbook Recipes
- Python Recipes: https://github.com/github/awesome-copilot/tree/main/cookbook/copilot-sdk/python
- All Languages: https://github.com/github/awesome-copilot/tree/main/cookbook/copilot-sdk

### Copilot Instructions
For accelerated development with the SDK:
- https://github.com/github/awesome-copilot/blob/main/collections/copilot-sdk.md

### Support
- Issues: https://github.com/github/copilot-sdk/issues
- Discussions: https://github.com/github/copilot-sdk/discussions

---

## Security Considerations

### Tool Access
- Review tool permissions before deployment
- SDK operates in `--allow-all` mode by default
- Can perform file operations, Git commands, web requests
- Configure tool restrictions based on your security requirements

### API Keys (BYOK)
- Store keys securely (environment variables, key vaults)
- Never commit keys to source control
- Rotate keys regularly
- Use least-privilege access permissions

### Session Data
- Sessions persist conversation history on disk
- Clean up sensitive data when no longer needed
- Consider data retention policies
- Use `delete_session()` for permanent deletion

---

## Quick Reference

### Client Lifecycle
```python
client = CopilotClient()
await client.start()      # Connect to CLI
# ... work ...
await client.stop()       # Disconnect
```

### Session Operations
```python
# Create
session = await client.create_session(SessionConfig(model="gpt-5"))

# Resume
session = await client.resume_session("session-id")

# List
sessions = await client.list_sessions()

# Destroy (keeps data)
await session.destroy()

# Delete (removes data)
await client.delete_session("session-id")
```

### Messaging
```python
# Blocking
response = await session.send_and_wait(MessageOptions(prompt="..."))

# Non-blocking
await session.send(MessageOptions(prompt="..."))

# With timeout
response = await session.send_and_wait(MessageOptions(prompt="..."), timeout=30.0)

# Abort
await session.abort()
```

### Event Handling
```python
def handler(event: SessionEvent):
    if event.type == SessionEventType.ASSISTANT_MESSAGE:
        print(event.data.content)

session.on(handler)
```

---

## Version Information

**SDK Version**: v0.1.23 (as of February 2026)  
**Status**: Technical Preview  
**Python Protocol**: AsyncIO-based  
**CLI Required**: Yes (managed automatically by SDK)

---

## Writing Simple, Readable Code for Beginners

This section emphasizes that all code using the Copilot SDK should be written so that beginners can understand and learn from it.

### Documentation is Essential

Every function and class must have clear documentation:

**✅ DO - Comprehensive docstrings**:
```python
async def safe_copilot_interaction():
    """
    Demonstrate safe interaction with the Copilot API.
    
    This example shows the proper way to:
    1. Create a client connection
    2. Start the client
    3. Create a session
    4. Send a message
    5. Clean up resources
    
    The try-finally block ensures resources are cleaned up
    even if an error occurs, which is important for reliability.
    """
    client = CopilotClient()
    
    try:
        # Start the client (connect to Copilot CLI)
        await client.start()
        
        # Create a session (conversation context)
        session = await client.create_session(SessionConfig(model="gpt-5"))
        
        # Send a message and wait for response
        response = await session.send_and_wait(
            MessageOptions(prompt="Hello!")
        )
        
        # Print the response
        if response:
            print(response.data.content)
        
        # Destroy the session (clean up)
        await session.destroy()
    except Exception as e:
        # Handle any errors that occur
        print(f"Error: {e}")
    finally:
        # Always stop the client, even if an error occurred
        # This is crucial for proper resource cleanup
        await client.stop()
```

**❌ DON'T - Minimal or cryptic documentation**:
```python
async def sci():
    c = CopilotClient()
    try:
        await c.start()
        s = await c.create_session(SessionConfig(model="gpt-5"))
        r = await s.send_and_wait(MessageOptions(prompt="Hello!"))
        if r:
            print(r.data.content)
        await s.destroy()
    except Exception as e:
        pass
    finally:
        await c.stop()
```

### Use Simple Patterns

Avoid overly clever or complex code:

**✅ DO - Simple, step-by-step code**:
```python
# Break the operation into clear steps with comments
async def process_files(file_list):
    """Process a list of files one at a time."""
    
    results = []
    
    # Process each file
    for file_path in file_list:
        # Read the file
        try:
            with open(file_path, "r") as file:
                content = file.read()
        except FileNotFoundError:
            # Skip if file doesn't exist
            continue
        
        # Analyze the content
        analysis_result = await analyze(content)
        
        # Store the result
        results.append({
            "file": file_path,
            "result": analysis_result
        })
    
    return results
```

**❌ DON'T - Complex list comprehensions or clever tricks**:
```python
# Too complex for beginners to understand
async def process_files(file_list):
    return [{"file": f, "result": await analyze(open(f).read())} 
            for f in file_list if Path(f).exists()]
```

### Clear Variable Names

Use names that explain what the variable contains:

**✅ DO - Descriptive names**:
```python
# These names clearly show what each variable holds
session_timeout_seconds = 60
is_authentication_successful = True
copilot_response_content = response.data.content
list_of_files_to_process = ["file1.py", "file2.py"]
error_message_to_user = "Please check your authentication"
```

**❌ DON'T - Abbreviated or unclear names**:
```python
# These are hard to understand
sto = 60
ia = True
crc = response.data.content
lfp = ["file1.py", "file2.py"]
em = "Please check your authentication"
```

### Comments for Learning

Add comments to help beginners understand why, not just what:

**✅ DO - Comments that teach**:
```python
# Sessions maintain conversation history.
# If we want to ask follow-up questions, we need to use the same session.
session = await client.create_session(SessionConfig(model="gpt-5"))

# We use a timeout of 10 seconds here because this is a quick question.
# For longer operations, we would use event handlers instead.
response = await session.send_and_wait(
    MessageOptions(prompt="What is 2+2?"),
    timeout=10.0
)

# The response might be None if something went wrong,
# so we check before trying to access its content.
if response:
    print(response.data.content)
```

**❌ DON'T - Comments that just repeat code**:
```python
# Create a session
session = await client.create_session(SessionConfig(model="gpt-5"))

# Set timeout
timeout = 10.0

# Check if response exists
if response:
    pass
```

---

## When to Use This SDK

✅ **Use the SDK when**:
- Building custom AI-powered applications
- Integrating Copilot into existing workflows
- Creating interactive CLI tools
- Automating development tasks
- Building multi-user AI applications
- Requiring programmatic control over AI agents

❌ **Don't use the SDK when**:
- Simple one-off tasks (use Copilot Chat instead)
- No programming requirements (use Copilot CLI directly)
- Production stability is critical (SDK is in Technical Preview)

---

## Summary

The GitHub Copilot SDK provides a powerful way to integrate AI-powered agentic workflows into your applications. Key capabilities include:

- **Multi-language support**: Python, TypeScript, Go, .NET
- **Session management**: Create, persist, and resume conversations
- **Event-driven architecture**: Real-time updates on processing
- **Built-in tools**: File operations, Git, GitHub API, web requests
- **Flexible authentication**: GitHub OAuth, tokens, BYOK
- **Production-ready runtime**: Same engine as Copilot CLI

Use this instruction file as a comprehensive reference when building applications with the Copilot SDK. For language-specific details, refer to the individual SDK documentation in the official repository.
