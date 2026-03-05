# Subagent Orchestration & Lifecycle Management Guide

> **Date:** February 14, 2026  
> **Scope:** VS Code Agent API, GitHub Copilot SDK, Agent Session Management  
> **Purpose:** Practical framework for managing subagents, detecting idle/crashed processes, and enabling orchestrating agents to recover gracefully.

---

## Table of Contents

- [How VS Code Manages Subagents Internally](#how-vs-code-manages-subagents-internally)
- [Framework: Reliable Subagent Orchestration](#framework-reliable-subagent-orchestration)
  - [1. The Cancellation Token Pattern](#1-the-cancellation-token-pattern-first-line-of-defense)
  - [2. Timeout Wrapping](#2-timeout-wrapping-detect-idlehung-subagents)
  - [3. Health-Check Heartbeat Pattern](#3-health-check-heartbeat-pattern-detect-crashed-processes)
  - [4. Subagent Registry](#4-subagent-registry-central-state-management)
  - [5. The Orchestrator Pattern](#5-the-orchestrator-pattern-putting-it-all-together)
- [Best Practices Summary](#best-practices-summary)
- [VS Code Built-In Agent Session Management](#vs-codes-built-in-agent-session-management)
- [Key Takeaway](#key-takeaway)

---

## How VS Code Manages Subagents Internally

VS Code defines a **subagent** as:

> *"A child agent spawned within a session to handle a subtask in its own isolated context window. An agent researching a topic spawns a subagent to gather information, then receives only the summary back."*

VS Code's architecture provides several layers of management:

### Core Primitives Used by VS Code

| Primitive | Purpose |
|---|---|
| `CancellationToken` / `CancellationTokenSource` | Cooperative cancellation — every agent operation receives a token that can be checked (`isCancellationRequested`) or listened to (`onCancellationRequested`) |
| `Disposable` pattern | Every resource (event listener, terminal, tool registration) returns a `Disposable` that cleans up on `.dispose()` |
| Agent Status Indicator | Tracks **unread** and **in-progress** session counts; badges update in real time |
| Agent Sessions List | Unified view to manage all sessions with status, type, and file changes |
| `TerminalShellExecutionEndEvent` | Fires when a terminal command finishes, including its `exitCode` |
| `TaskProcessEndEvent` / `TaskProcessStartEvent` | Tracks when processes inside tasks start/exit, including the `exitCode` and `processId` |

---

## Framework: Reliable Subagent Orchestration

### 1. The Cancellation Token Pattern (First Line of Defense)

Every operation in VS Code's agent system receives a `CancellationToken`. This is the canonical mechanism for cooperative cancellation:

```typescript
// The orchestrator creates a token source for each subagent
const cts = new CancellationTokenSource();

// Pass cts.token to the subagent's operation
const result = await subagentOperation(input, cts.token);

// If the subagent becomes unresponsive, cancel it:
cts.cancel();

// Always clean up:
cts.dispose();
```

**Inside the subagent**, check for cancellation at every meaningful checkpoint:

```typescript
async function subagentOperation(input: any, token: CancellationToken) {
  for (const step of steps) {
    // Check before each expensive operation
    if (token.isCancellationRequested) {
      throw new CancellationError();
    }

    // Or register a listener for reactive cancellation
    token.onCancellationRequested(() => {
      cleanup();
    });

    await doWork(step);
  }
}
```

---

### 2. Timeout Wrapping (Detect Idle/Hung Subagents)

VS Code doesn't have a built-in "timeout" on subagent calls, but you can build one using `Promise.race`:

```typescript
interface SubagentResult<T> {
  status: 'completed' | 'timeout' | 'error' | 'cancelled';
  result?: T;
  error?: Error;
  durationMs: number;
}

async function runWithTimeout<T>(
  operation: (token: CancellationToken) => Promise<T>,
  timeoutMs: number,
  label: string
): Promise<SubagentResult<T>> {
  const cts = new CancellationTokenSource();
  const startTime = Date.now();

  let timer: ReturnType<typeof setTimeout>;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      cts.cancel(); // Signal the subagent to stop
      reject(new Error(`Subagent "${label}" timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });

  try {
    const result = await Promise.race([
      operation(cts.token),
      timeoutPromise
    ]);
    clearTimeout(timer!);
    return {
      status: 'completed',
      result,
      durationMs: Date.now() - startTime
    };
  } catch (err: any) {
    clearTimeout(timer!);
    if (err instanceof CancellationError) {
      return { status: 'cancelled', durationMs: Date.now() - startTime };
    }
    return {
      status: err.message?.includes('timed out') ? 'timeout' : 'error',
      error: err,
      durationMs: Date.now() - startTime
    };
  } finally {
    cts.dispose();
  }
}
```

---

### 3. Health-Check Heartbeat Pattern (Detect Crashed Processes)

For subagents that launch external processes (terminals, tasks), use VS Code's event system to detect crashes:

```typescript
import {
  Terminal, Disposable, window,
  TerminalExitReason, CancellationTokenSource
} from 'vscode';

class SubagentProcessMonitor {
  private lastHeartbeat = Date.now();
  private disposables: Disposable[] = [];
  private healthCheckInterval: ReturnType<typeof setInterval>;

  constructor(
    private terminal: Terminal,
    private onUnresponsive: () => void,
    private heartbeatTimeoutMs = 30000
  ) {
    // Monitor terminal shell execution completions
    this.disposables.push(
      window.onDidEndTerminalShellExecution((event) => {
        if (event.terminal === this.terminal) {
          this.lastHeartbeat = Date.now();
          if (event.exitCode !== 0) {
            // Process inside subagent crashed
            this.handleProcessCrash(event.exitCode);
          }
        }
      })
    );

    // Monitor terminal closure (subagent died completely)
    this.disposables.push(
      window.onDidCloseTerminal((closedTerminal) => {
        if (closedTerminal === this.terminal) {
          const exit = closedTerminal.exitStatus;
          if (exit?.reason === TerminalExitReason.Process) {
            this.handleProcessCrash(exit.code);
          }
        }
      })
    );

    // Periodic health check
    this.healthCheckInterval = setInterval(() => {
      if (Date.now() - this.lastHeartbeat > this.heartbeatTimeoutMs) {
        this.onUnresponsive();
      }
    }, 5000);
  }

  recordHeartbeat() {
    this.lastHeartbeat = Date.now();
  }

  private handleProcessCrash(exitCode: number) {
    console.error(`Subagent process crashed with exit code ${exitCode}`);
    this.dispose();
  }

  dispose() {
    clearInterval(this.healthCheckInterval);
    this.disposables.forEach(d => d.dispose());
  }
}
```

---

### 4. Subagent Registry (Central State Management)

Maintain a registry of all active subagents so the orchestrator can inspect, cancel, or retry any of them:

```typescript
import { CancellationTokenSource } from 'vscode';

enum SubagentState {
  Pending   = 'pending',
  Running   = 'running',
  Completed = 'completed',
  Failed    = 'failed',
  TimedOut  = 'timed-out',
  Cancelled = 'cancelled',
  Idle      = 'idle'          // Detected as unresponsive
}

interface SubagentEntry<T = any> {
  id: string;
  label: string;
  state: SubagentState;
  cancellationSource: CancellationTokenSource;
  startedAt: number;
  lastActivity: number;
  retryCount: number;
  maxRetries: number;
  result?: T;
  error?: Error;
}

class SubagentRegistry {
  private agents = new Map<string, SubagentEntry>();
  private idleThresholdMs = 60000;
  private watchdogInterval: ReturnType<typeof setInterval>;

  constructor() {
    // Watchdog: periodically scan for idle subagents
    this.watchdogInterval = setInterval(() => this.detectIdleAgents(), 10000);
  }

  register(
    id: string,
    label: string,
    cts: CancellationTokenSource,
    maxRetries = 2
  ): SubagentEntry {
    const entry: SubagentEntry = {
      id,
      label,
      state: SubagentState.Running,
      cancellationSource: cts,
      startedAt: Date.now(),
      lastActivity: Date.now(),
      retryCount: 0,
      maxRetries
    };
    this.agents.set(id, entry);
    return entry;
  }

  recordActivity(id: string) {
    const entry = this.agents.get(id);
    if (entry) {
      entry.lastActivity = Date.now();
    }
  }

  markCompleted(id: string, result: any) {
    const entry = this.agents.get(id);
    if (entry) {
      entry.state = SubagentState.Completed;
      entry.result = result;
    }
  }

  markFailed(id: string, error: Error) {
    const entry = this.agents.get(id);
    if (entry) {
      entry.state = SubagentState.Failed;
      entry.error = error;
    }
  }

  cancel(id: string) {
    const entry = this.agents.get(id);
    if (entry && entry.state === SubagentState.Running) {
      entry.cancellationSource.cancel();
      entry.state = SubagentState.Cancelled;
    }
  }

  cancelAll() {
    for (const [id] of this.agents) {
      this.cancel(id);
    }
  }

  canRetry(id: string): boolean {
    const entry = this.agents.get(id);
    return entry ? entry.retryCount < entry.maxRetries : false;
  }

  incrementRetry(id: string): SubagentEntry | undefined {
    const entry = this.agents.get(id);
    if (entry) {
      entry.retryCount++;
      entry.state = SubagentState.Running;
      entry.lastActivity = Date.now();
      entry.cancellationSource = new CancellationTokenSource();
    }
    return entry;
  }

  getStatus(): Map<string, SubagentState> {
    const status = new Map<string, SubagentState>();
    for (const [id, entry] of this.agents) {
      status.set(id, entry.state);
    }
    return status;
  }

  private detectIdleAgents() {
    const now = Date.now();
    for (const [id, entry] of this.agents) {
      if (
        entry.state === SubagentState.Running &&
        now - entry.lastActivity > this.idleThresholdMs
      ) {
        entry.state = SubagentState.Idle;
        // Let the orchestrator decide what to do
        this.onIdleDetected?.(id, entry);
      }
    }
  }

  onIdleDetected?: (id: string, entry: SubagentEntry) => void;

  dispose() {
    clearInterval(this.watchdogInterval);
    this.cancelAll();
    for (const entry of this.agents.values()) {
      entry.cancellationSource.dispose();
    }
  }
}
```

---

### 5. The Orchestrator Pattern (Putting It All Together)

```typescript
class AgentOrchestrator {
  private registry = new SubagentRegistry();

  constructor() {
    // React to idle subagents
    this.registry.onIdleDetected = (id, entry) => {
      console.warn(
        `Subagent "${entry.label}" is idle. Attempting recovery...`
      );

      if (this.registry.canRetry(id)) {
        this.registry.cancel(id);
        this.retrySubagent(id, entry);
      } else {
        this.registry.cancel(id);
        console.error(
          `Subagent "${entry.label}" exhausted retries. Skipping.`
        );
      }
    };
  }

  async runSubagent<T>(
    id: string,
    label: string,
    task: (token: CancellationToken) => Promise<T>,
    options: { timeoutMs?: number; maxRetries?: number } = {}
  ): Promise<SubagentResult<T>> {
    const { timeoutMs = 120000, maxRetries = 2 } = options;
    const cts = new CancellationTokenSource();

    this.registry.register(id, label, cts, maxRetries);

    const result = await runWithTimeout(
      async (token) => {
        // Wrap the task to record activity
        this.registry.recordActivity(id);
        const output = await task(token);
        this.registry.recordActivity(id);
        return output;
      },
      timeoutMs,
      label
    );

    // Update registry based on result
    switch (result.status) {
      case 'completed':
        this.registry.markCompleted(id, result.result);
        break;
      case 'timeout':
        if (this.registry.canRetry(id)) {
          return this.retrySubagentWithTask(id, task, timeoutMs);
        }
        this.registry.markFailed(id, result.error!);
        break;
      case 'error':
        this.registry.markFailed(id, result.error!);
        break;
    }

    return result;
  }

  private async retrySubagentWithTask<T>(
    id: string,
    task: (token: CancellationToken) => Promise<T>,
    timeoutMs: number
  ): Promise<SubagentResult<T>> {
    const updated = this.registry.incrementRetry(id);
    console.log(
      `Retrying subagent (attempt ${updated!.retryCount}/${updated!.maxRetries})`
    );
    return runWithTimeout(task, timeoutMs, updated!.label);
  }

  private retrySubagent(id: string, entry: SubagentEntry) {
    this.registry.incrementRetry(id);
    console.log(
      `Retry queued for "${entry.label}" ` +
      `(attempt ${entry.retryCount + 1}/${entry.maxRetries})`
    );
  }

  /** Get a summary of all subagent states for inspection */
  getStatusReport(): string {
    const lines: string[] = ['=== Subagent Status Report ==='];
    for (const [id, state] of this.registry.getStatus()) {
      lines.push(`  [${state.toUpperCase()}] ${id}`);
    }
    return lines.join('\n');
  }

  dispose() {
    this.registry.dispose();
  }
}
```

---

## Best Practices Summary

| Practice | How |
|---|---|
| **Always pass `CancellationToken`** | Every subagent call must accept and honor a token. This is VS Code's foundational cooperative cancellation pattern. |
| **Wrap with timeouts** | Use `Promise.race` against a timer. If the subagent doesn't respond within the budget, cancel the token and mark it as timed out. |
| **Use a registry** | Track every spawned subagent's state (`running`, `idle`, `failed`, `completed`). The orchestrator queries the registry to decide next steps. |
| **Implement a watchdog** | A periodic interval checks `lastActivity` timestamps. If a subagent hasn't reported activity beyond a threshold, mark it `idle` and trigger recovery. |
| **Monitor process exit codes** | For subagents that run terminal commands or tasks, listen to `onDidEndTerminalShellExecution`, `onDidCloseTerminal`, and `TaskProcessEndEvent` to catch process crashes immediately. |
| **Retry with exponential backoff** | On timeout or crash, retry up to N times with increasing delays before giving up. |
| **Limit concurrent subagents** | Use a semaphore or concurrency pool to avoid overwhelming resources. |
| **Log and surface status** | Use VS Code's `LogOutputChannel` or `ChatResponseStream.progress()` to give the user visibility into subagent health. |
| **Dispose everything** | Use the `Disposable` pattern. Cancel tokens, clear intervals, remove event listeners. Leaked subagents waste cycles. |
| **Fail fast, fail loudly** | When a tool inside a subagent throws, surface a descriptive error message so the LLM can adapt (skip the tool, try different parameters, or inform the user). |

---

## VS Code's Built-In Agent Session Management

VS Code already implements several of these patterns at the product level:

- **Agent Status Indicator**: Shows badges for in-progress and unread sessions via `chat.agentsControl.enabled`
- **Session archival**: Completed/inactive sessions can be archived without deletion
- **Hand-off**: Sessions can be transferred between agent types (local -> background -> cloud), carrying conversation history
- **Parallel sessions**: Multiple independent agent sessions can run simultaneously
- **Process monitoring**: Terminal shell integration (`TerminalShellExecution`) tracks command execution status and exit codes
- **Background agents** use Git worktrees for isolation, preventing conflicts with the active workspace

The proposed `chatSessionsProvider` API (currently in [`vscode.proposed.chatSessionsProvider.d.ts`](https://github.com/microsoft/vscode/blob/main/src/vscode-dts/vscode.proposed.chatSessionsProvider.d.ts)) will allow extension developers to integrate their own session providers into this unified management view.

---

## Key Takeaway

There is no single "subagent health framework" shipped as an importable library. Instead, VS Code provides **primitives** (`CancellationToken`, `Disposable`, event-driven process monitoring, agent session management UI) that you compose into your own orchestration layer.

The patterns in this guide — **timeout wrapping**, **heartbeat monitoring**, **a central registry with a watchdog**, and **retry logic** — form the reliable management framework for handling subagents that become unresponsive, idle, or crash during execution.

---

## References

- [VS Code API Reference](https://code.visualstudio.com/api/references/vscode-api)
- [Language Model API](https://code.visualstudio.com/api/extension-guides/ai/language-model)
- [Chat Participant API](https://code.visualstudio.com/api/extension-guides/ai/chat)
- [Language Model Tool API](https://code.visualstudio.com/api/extension-guides/ai/tools)
- [AI Extensibility Overview](https://code.visualstudio.com/api/extension-guides/ai/ai-extensibility-overview)
- [Using Agents in VS Code](https://code.visualstudio.com/docs/copilot/agents/overview)
- [GitHub Copilot Agents Concepts](https://docs.github.com/en/copilot/concepts/agents)
- [Proposed chatSessionsProvider API](https://github.com/microsoft/vscode/blob/main/src/vscode-dts/vscode.proposed.chatSessionsProvider.d.ts)
