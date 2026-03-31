#!/usr/bin/env bash
# retag.sh — Move a version tag to HEAD and force-push to re-trigger release workflows.
#
# Usage:
#   ./scripts/retag.sh           # auto-detects version from core/pyproject.toml
#   ./scripts/retag.sh v0.1.2    # use an explicit tag

set -euo pipefail

# ── Resolve the tag ──────────────────────────────────────────────────────────
if [[ $# -ge 1 ]]; then
    TAG="$1"
else
    # Read version from core/pyproject.toml using Python (stdlib only)
    VERSION=$(python3 - << 'PY'
import tomllib
from pathlib import Path
data = tomllib.loads(Path("core/pyproject.toml").read_text(encoding="utf-8"))
print(data["project"]["version"])
PY
    )
    TAG="v${VERSION}"
fi

# ── Safety check ─────────────────────────────────────────────────────────────
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
HEAD_COMMIT=$(git rev-parse HEAD)

echo "Branch  : $CURRENT_BRANCH"
echo "HEAD    : $HEAD_COMMIT"
echo "Tag     : $TAG"
echo ""

read -r -p "Move tag '$TAG' to HEAD and force-push? [y/N] " confirm
if [[ "$(echo "$confirm" | tr '[:upper:]' '[:lower:]')" != "y" ]]; then
    echo "Aborted."
    exit 0
fi

# ── Move tag and push ─────────────────────────────────────────────────────────
git tag -f "$TAG"
git push origin "$TAG" --force

echo ""
echo "✅  Tag '$TAG' moved to HEAD and pushed."
echo "    The release-wheels workflow will re-trigger automatically."
