/**
 * Subagent registry for tracking scanner states.
 *
 * Maintains a simple registry of scanner sub-agents and their
 * lifecycle states for UI display.
 */

export type SubagentState = "pending" | "running" | "completed" | "failed";

export interface SubagentEntry {
  id: string;
  label: string;
  state: SubagentState;
  startedAt: number;
  findingsCount: number;
}

/**
 * Tracks each scanner sub-agent's lifecycle state.
 */
export class SubagentRegistry {
  private agents = new Map<string, SubagentEntry>();

  register(id: string, label: string): SubagentEntry {
    const entry: SubagentEntry = {
      id,
      label,
      state: "pending",
      startedAt: Date.now(),
      findingsCount: 0,
    };
    this.agents.set(id, entry);
    return entry;
  }

  markRunning(id: string): void {
    const entry = this.agents.get(id);
    if (entry) {
      entry.state = "running";
    }
  }

  markCompleted(id: string, findingsCount = 0): void {
    const entry = this.agents.get(id);
    if (entry) {
      entry.state = "completed";
      entry.findingsCount = findingsCount;
    }
  }

  get(id: string): SubagentEntry | undefined {
    return this.agents.get(id);
  }

  getAll(): SubagentEntry[] {
    return Array.from(this.agents.values());
  }

  clear(): void {
    this.agents.clear();
  }

  dispose(): void {
    this.clear();
  }
}
