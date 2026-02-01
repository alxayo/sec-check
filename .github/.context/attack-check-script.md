# Security Scan Wrapper Script (safe-scan.sh)

This Bash wrapper script automates the security review process by routing scripts through language-specific static analysis tools (SAST) and a behavioral "red flag" grep scanner.

## Prerequisites

Ensure you have the required scanners installed:

- **Bash**: ShellCheck
- **Python**: Bandit
- **Node.js**: ESLint (with eslint-plugin-security)
- **PowerShell**: PSScriptAnalyzer

## The Wrapper Script

```bash
#!/bin/bash

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FILE=$1

if [[ -z "$FILE" ]]; then
    echo -e "${RED}Usage: $0 <script_to_scan>${NC}"
    exit 1
fi

echo -e "${YELLOW}Starting Security Scan for: $FILE${NC}"
echo "------------------------------------------"

# --- Step 1: Universal Red-Flag Grep Scan ---
echo -e "${YELLOW}[1/2] Searching for high-risk patterns...${NC}"
DANGER_ZONE=("base64" "eval" "socket" "curl" "wget" "rm -rf" "chmod" "/dev/tcp" "Invoke-Expression" "IEX" "EncodedCommand")

for pattern in "${DANGER_ZONE[@]}"; do
    if grep -qi "$pattern" "$FILE"; then
        echo -e "${RED}[!] WARNING: Found suspicious keyword: '$pattern'${NC}"
    fi
done

# --- Step 2: Language-Specific SAST ---
echo -e "\n${YELLOW}[2/2] Running deep static analysis...${NC}"

case "$FILE" in
    *.sh)
        echo "[+] Detected Bash script. Running ShellCheck..."
        shellcheck "$FILE" || echo -e "${RED}ShellCheck found issues.${NC}"
        ;;
    *.py)
        echo "[+] Detected Python script. Running Bandit..."
        bandit -r "$FILE"
        ;;
    *.js)
        echo "[+] Detected Node.js script. Running ESLint..."
        npx eslint "$FILE" --plugin security --rule 'security/detect-child-process: warn'
        ;;
    *.ps1)
        echo "[+] Detected PowerShell script. Running PSScriptAnalyzer..."
        pwsh -Command "Invoke-ScriptAnalyzer -Path $FILE"
        ;;
    *)
        echo -e "${RED}[!] Error: Unsupported file extension.${NC}"
        exit 1
        ;;
esac

echo "------------------------------------------"
echo -e "${GREEN}Scan Complete.${NC} Always review flagged lines manually before execution."
```

## How to Use It

1. **Save the script**: Save the code above as `safe-scan.sh`
2. **Make it executable**:
   ```bash
   chmod +x safe-scan.sh
   ```
3. **Run a scan**:
   ```bash
   ./safe-scan.sh suspicious_script.py
   ```

## Key Security Features

- **Heuristic Detection**: The "Red-Flag" section catches obfuscation (base64) and network attempts (curl/socket) even if the deep scanners miss them.
- **Context Awareness**: It automatically switches between ShellCheck for Bash and Bandit for Python based on the file extension.
- **Non-Destructive**: The wrapper never executes the target script; it only reads the source code.