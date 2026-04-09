#!/usr/bin/env bash
set -euo pipefail

# Thin wrapper for macOS users.
# Delegates to the shared Unix installer.

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[agentsec-install] ERROR: install-macos.sh must be run on macOS" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$script_dir/install.sh" "$@"
