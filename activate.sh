#!/bin/bash
# AgentSec Activation Script
# Source this file to set up your environment for AgentSec development

# Activate the virtual environment
source "$(dirname "$0")/venv/bin/activate"

# Add Copilot CLI to PATH if it's not already there
COPILOT_PATH="/home/alyoche/.vscode-server-insiders/data/User/globalStorage/github.copilot-chat/copilotCli"
if [[ ":$PATH:" != *":$COPILOT_PATH:"* ]]; then
    export PATH="$PATH:$COPILOT_PATH"
fi

echo "✅ AgentSec environment activated!"
echo "   Python: $(python --version)"
echo "   AgentSec: $(agentsec --version 2>/dev/null || echo 'Not found - run: pip install -e ./cli')"
echo ""
echo "Quick commands:"
echo "  agentsec scan ./test-scan    # Scan the test folder"
echo "  agentsec --help              # Show help"
echo "  deactivate                   # Exit the virtual environment"
