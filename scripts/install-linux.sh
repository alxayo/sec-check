#!/usr/bin/env bash
set -euo pipefail

# Thin wrapper for Linux users.
# Delegates to the shared Unix installer.

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[agentsec-install] ERROR: install-linux.sh must be run on Linux" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$script_dir/install.sh" "$@"
