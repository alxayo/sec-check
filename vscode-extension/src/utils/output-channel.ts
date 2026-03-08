/**
 * Output channel for AgentSec extension logging.
 *
 * Provides a single LogOutputChannel shared across all extension
 * components for consistent debug/info/error output.
 */

import * as vscode from "vscode";

let _channel: vscode.LogOutputChannel | undefined;

/**
 * Get or create the shared AgentSec output channel.
 */
export function getOutputChannel(): vscode.LogOutputChannel {
  if (!_channel) {
    _channel = vscode.window.createOutputChannel("AgentSec", { log: true });
  }
  return _channel;
}

/**
 * Dispose the output channel. Call on extension deactivation.
 */
export function disposeOutputChannel(): void {
  _channel?.dispose();
  _channel = undefined;
}
