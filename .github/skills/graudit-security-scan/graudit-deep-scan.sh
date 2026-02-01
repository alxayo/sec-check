#!/bin/bash
#
# graudit-deep-scan.sh - Comprehensive multi-database security scan
# Part of the graudit-security-scan agent skill
#
# This script runs graudit with multiple signature databases to perform
# a thorough security audit of source code.
#

set -e

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TARGET="$1"
OUTPUT_DIR="${2:-./graudit-report}"

if [[ -z "$TARGET" ]]; then
    echo -e "${RED}Usage: $0 <target_path> [output_directory]${NC}"
    echo ""
    echo "Example: $0 ./myproject ./security-report"
    exit 1
fi

if [[ ! -e "$TARGET" ]]; then
    echo -e "${RED}Error: Target not found: $TARGET${NC}"
    exit 1
fi

# Check if graudit is available
if ! command -v graudit &> /dev/null; then
    echo -e "${RED}Error: graudit not found. Please install it first.${NC}"
    echo "  git clone https://github.com/wireghoul/graudit ~/graudit"
    echo "  export PATH=\"\$HOME/graudit:\$PATH\""
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              GRAUDIT DEEP SECURITY SCAN                      ║"
echo "║         Comprehensive Source Code Security Audit             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}Target:${NC}     $TARGET"
echo -e "${CYAN}Output:${NC}     $OUTPUT_DIR"
echo -e "${CYAN}Started:${NC}    $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Define database categories
CRITICAL_DBS=("secrets" "exec" "sql" "xss")
LANGUAGE_DBS=("python" "js" "typescript" "php" "java" "go" "ruby" "perl" "c" "dotnet")
OTHER_DBS=("default" "android" "ios")

TOTAL_FINDINGS=0
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"

# Initialize summary
cat > "$SUMMARY_FILE" << EOF
GRAUDIT DEEP SCAN REPORT
========================
Target: $TARGET
Date: $(date '+%Y-%m-%d %H:%M:%S')
----------------------------------------

EOF

scan_with_database() {
    local db=$1
    local category=$2
    local output_file="$OUTPUT_DIR/${db}-findings.txt"
    
    echo -ne "${YELLOW}[SCANNING]${NC} $db database... "
    
    # Run graudit and capture output
    local findings
    findings=$(graudit -z -c 2 -d "$db" "$TARGET" 2>/dev/null || true)
    local count=$(echo "$findings" | grep -c "." 2>/dev/null || echo "0")
    
    if [[ -n "$findings" && "$count" -gt 0 ]]; then
        echo -e "${RED}$count finding(s)${NC}"
        echo "$findings" > "$output_file"
        
        # Add to summary
        echo "[$category] $db: $count findings" >> "$SUMMARY_FILE"
        echo "  → See: ${db}-findings.txt" >> "$SUMMARY_FILE"
        
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + count))
        return 1
    else
        echo -e "${GREEN}clean${NC}"
        echo "[$category] $db: 0 findings" >> "$SUMMARY_FILE"
        return 0
    fi
}

# --- Run Critical Security Scans ---
echo -e "\n${BOLD}━━━ CRITICAL SECURITY PATTERNS ━━━${NC}"
for db in "${CRITICAL_DBS[@]}"; do
    scan_with_database "$db" "CRITICAL" || true
done

# --- Run Language-Specific Scans ---
echo -e "\n${BOLD}━━━ LANGUAGE-SPECIFIC PATTERNS ━━━${NC}"

# Auto-detect which languages are present
detect_and_scan() {
    local ext=$1
    local db=$2
    
    if find "$TARGET" -name "*.$ext" -type f 2>/dev/null | head -1 | grep -q .; then
        scan_with_database "$db" "LANGUAGE" || true
    fi
}

# Check for each language
detect_and_scan "py" "python"
detect_and_scan "js" "js"
detect_and_scan "ts" "typescript"
detect_and_scan "php" "php"
detect_and_scan "java" "java"
detect_and_scan "go" "go"
detect_and_scan "rb" "ruby"
detect_and_scan "pl" "perl"
detect_and_scan "c" "c"
detect_and_scan "cs" "dotnet"

# --- Run Default Scan ---
echo -e "\n${BOLD}━━━ GENERAL PATTERNS ━━━${NC}"
scan_with_database "default" "GENERAL" || true

# --- Generate Summary ---
echo "" >> "$SUMMARY_FILE"
echo "========================================" >> "$SUMMARY_FILE"
echo "TOTAL FINDINGS: $TOTAL_FINDINGS" >> "$SUMMARY_FILE"
echo "========================================" >> "$SUMMARY_FILE"

# --- Print Final Summary ---
echo ""
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}${BOLD}                        SCAN COMPLETE                           ${NC}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Total findings:${NC} ${BOLD}$TOTAL_FINDINGS${NC}"
echo -e "${CYAN}Report saved to:${NC} $OUTPUT_DIR/"
echo ""

if [[ $TOTAL_FINDINGS -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}⚠ FINDINGS DETECTED${NC}"
    echo ""
    echo "Review the following report files:"
    ls -la "$OUTPUT_DIR"/*.txt 2>/dev/null | awk '{print "  → " $NF}'
    echo ""
    echo -e "${YELLOW}Important: All findings require manual review.${NC}"
    echo -e "${YELLOW}Graudit uses pattern matching and may produce false positives.${NC}"
    echo ""
    echo "Recommended next steps:"
    echo "  1. Review critical findings first (secrets, exec, sql, xss)"
    echo "  2. Check language-specific findings"
    echo "  3. Verify each finding in context"
    echo "  4. Assess actual exploitability"
    exit 1
else
    echo -e "${GREEN}${BOLD}✓ NO SECURITY ISSUES DETECTED${NC}"
    echo ""
    echo "Note: This scan uses pattern matching and may not catch all vulnerabilities."
    echo "Consider additional security measures:"
    echo "  • Manual code review"
    echo "  • Dynamic application security testing (DAST)"
    echo "  • Penetration testing"
    exit 0
fi
