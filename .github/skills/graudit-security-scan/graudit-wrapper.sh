#!/bin/bash
#
# graudit-wrapper.sh - Security scanning wrapper using graudit
# Part of the graudit-security-scan agent skill
#

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Configuration ---
CONTEXT_LINES=2
OUTPUT_FORMAT="color"  # color, plain, json

# --- Functions ---
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           GRAUDIT SECURITY SCANNER WRAPPER               ║"
    echo "║     Source Code Audit Tool - Pattern-Based Detection     ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo -e "${YELLOW}Usage:${NC} $0 [OPTIONS] <target_path>"
    echo ""
    echo "OPTIONS:"
    echo "  -d <database>   Specific database to use (python, js, php, etc.)"
    echo "  -a              Auto-detect language and use appropriate database"
    echo "  -s              Include secrets scan"
    echo "  -x              Include execution vulnerability scan"
    echo "  -f              Full scan (all relevant databases)"
    echo "  -c <num>        Context lines to show (default: 2)"
    echo "  -q              Quiet mode (suppress banner)"
    echo "  -h              Show this help"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 -a ./myproject           # Auto-detect and scan"
    echo "  $0 -d python ./script.py    # Scan Python file"
    echo "  $0 -f -s ./project          # Full scan with secrets"
    exit 1
}

check_graudit() {
    if ! command -v graudit &> /dev/null; then
        echo -e "${RED}[ERROR] graudit is not installed or not in PATH${NC}"
        echo ""
        echo "Install graudit:"
        echo "  git clone https://github.com/wireghoul/graudit ~/graudit"
        echo "  export PATH=\"\$HOME/graudit:\$PATH\""
        exit 1
    fi
}

detect_language() {
    local target=$1
    local detected=""
    
    if [[ -f "$target" ]]; then
        case "$target" in
            *.py)     detected="python" ;;
            *.js)     detected="js" ;;
            *.ts)     detected="typescript" ;;
            *.php)    detected="php" ;;
            *.java)   detected="java" ;;
            *.go)     detected="go" ;;
            *.rb)     detected="ruby" ;;
            *.pl)     detected="perl" ;;
            *.c|*.h)  detected="c" ;;
            *.cs)     detected="dotnet" ;;
            *.sh)     detected="default" ;;
            *.sql)    detected="sql" ;;
            *)        detected="default" ;;
        esac
    elif [[ -d "$target" ]]; then
        # Detect based on common files in directory
        if find "$target" -name "*.py" -type f | head -1 | grep -q .; then
            detected="python"
        elif find "$target" -name "*.js" -type f | head -1 | grep -q .; then
            detected="js"
        elif find "$target" -name "*.php" -type f | head -1 | grep -q .; then
            detected="php"
        elif find "$target" -name "*.java" -type f | head -1 | grep -q .; then
            detected="java"
        elif find "$target" -name "*.go" -type f | head -1 | grep -q .; then
            detected="go"
        else
            detected="default"
        fi
    fi
    
    echo "$detected"
}

run_scan() {
    local database=$1
    local target=$2
    local context=$3
    
    echo -e "${YELLOW}[SCAN] Running graudit with database: ${BLUE}$database${NC}"
    echo "────────────────────────────────────────────────────────────"
    
    local result
    result=$(graudit -c "$context" -d "$database" "$target" 2>&1)
    local exit_code=$?
    
    if [[ -n "$result" ]]; then
        echo -e "${RED}[!] Potential issues found:${NC}"
        echo "$result"
        echo ""
        return 1
    else
        echo -e "${GREEN}[✓] No issues found with $database database${NC}"
        echo ""
        return 0
    fi
}

count_findings() {
    local database=$1
    local target=$2
    
    graudit -z -d "$database" "$target" 2>/dev/null | wc -l | tr -d ' '
}

# --- Main Script ---

# Parse arguments
AUTO_DETECT=false
INCLUDE_SECRETS=false
INCLUDE_EXEC=false
FULL_SCAN=false
QUIET=false
DATABASE=""
TARGET=""

while getopts "d:asxfc:qh" opt; do
    case $opt in
        d) DATABASE="$OPTARG" ;;
        a) AUTO_DETECT=true ;;
        s) INCLUDE_SECRETS=true ;;
        x) INCLUDE_EXEC=true ;;
        f) FULL_SCAN=true ;;
        c) CONTEXT_LINES="$OPTARG" ;;
        q) QUIET=true ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND-1))

TARGET="$1"

if [[ -z "$TARGET" ]]; then
    echo -e "${RED}[ERROR] No target specified${NC}"
    usage
fi

if [[ ! -e "$TARGET" ]]; then
    echo -e "${RED}[ERROR] Target not found: $TARGET${NC}"
    exit 1
fi

# Check prerequisites
check_graudit

# Print banner unless quiet mode
if [[ "$QUIET" != true ]]; then
    print_banner
fi

echo -e "${CYAN}Target:${NC} $TARGET"
echo -e "${CYAN}Time:${NC}   $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

ISSUES_FOUND=0
DATABASES_SCANNED=0

# Auto-detect language if requested
if [[ "$AUTO_DETECT" == true && -z "$DATABASE" ]]; then
    DATABASE=$(detect_language "$TARGET")
    echo -e "${GREEN}[+] Auto-detected language database: $DATABASE${NC}"
    echo ""
fi

# Run scans based on options
if [[ "$FULL_SCAN" == true ]]; then
    # Full scan with multiple databases
    echo -e "${YELLOW}[*] Running full security scan...${NC}"
    echo ""
    
    # Language-specific scan
    lang_db=$(detect_language "$TARGET")
    run_scan "$lang_db" "$TARGET" "$CONTEXT_LINES" || ((ISSUES_FOUND++))
    ((DATABASES_SCANNED++))
    
    # Always include these in full scan
    run_scan "secrets" "$TARGET" "$CONTEXT_LINES" || ((ISSUES_FOUND++))
    ((DATABASES_SCANNED++))
    
    run_scan "exec" "$TARGET" "$CONTEXT_LINES" || ((ISSUES_FOUND++))
    ((DATABASES_SCANNED++))
    
    run_scan "xss" "$TARGET" "$CONTEXT_LINES" || ((ISSUES_FOUND++))
    ((DATABASES_SCANNED++))
    
    run_scan "sql" "$TARGET" "$CONTEXT_LINES" || ((ISSUES_FOUND++))
    ((DATABASES_SCANNED++))
    
elif [[ -n "$DATABASE" ]]; then
    # Specific database scan
    run_scan "$DATABASE" "$TARGET" "$CONTEXT_LINES" || ((ISSUES_FOUND++))
    ((DATABASES_SCANNED++))
else
    # Default scan
    run_scan "default" "$TARGET" "$CONTEXT_LINES" || ((ISSUES_FOUND++))
    ((DATABASES_SCANNED++))
fi

# Additional scans if requested
if [[ "$INCLUDE_SECRETS" == true && "$FULL_SCAN" != true ]]; then
    run_scan "secrets" "$TARGET" "$CONTEXT_LINES" || ((ISSUES_FOUND++))
    ((DATABASES_SCANNED++))
fi

if [[ "$INCLUDE_EXEC" == true && "$FULL_SCAN" != true ]]; then
    run_scan "exec" "$TARGET" "$CONTEXT_LINES" || ((ISSUES_FOUND++))
    ((DATABASES_SCANNED++))
fi

# Summary
echo "════════════════════════════════════════════════════════════"
echo -e "${CYAN}SCAN SUMMARY${NC}"
echo "────────────────────────────────────────────────────────────"
echo -e "Databases scanned: ${BLUE}$DATABASES_SCANNED${NC}"

if [[ $ISSUES_FOUND -gt 0 ]]; then
    echo -e "Status: ${RED}$ISSUES_FOUND database(s) found potential issues${NC}"
    echo ""
    echo -e "${YELLOW}⚠ IMPORTANT: Review all findings manually.${NC}"
    echo -e "${YELLOW}  Graudit uses pattern matching and may produce false positives.${NC}"
    exit 1
else
    echo -e "Status: ${GREEN}No issues detected${NC}"
    exit 0
fi
