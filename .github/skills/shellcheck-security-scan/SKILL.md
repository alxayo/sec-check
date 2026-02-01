---
name: shellcheck-security-scan
description: Scan shell scripts for security vulnerabilities using ShellCheck static analysis. Scan files *.sh, *.bash, shell code in Dockerfiles, .github/workflows/*.yml, Makefiles, npm scripts. (1) Detects command injection, arbitrary code execution, reverse shell patterns, data exfiltration, obfuscated payloads (base64/hex), unsafe rm operations, dangerous PATH manipulation. (2) Use for standalone scripts, CI/CD pipelines, installation scripts,build systems. For shell scripts containing embedded Python/other code, also run language-specific scanners. Combine with graudit -d exec for patterns ShellCheck may miss (e.g., base64 | bash).
---

# ShellCheck Security Scan Skill

ShellCheck is a static analysis tool that identifies bugs, security vulnerabilities, and stylistic issues in shell scripts. It supports bash, sh, dash, and ksh scripts.

## When to Use This Skill

Invoke this skill when:
- Analyzing shell scripts (.sh, .bash) for security vulnerabilities
- Checking for command injection risks in shell code
- Detecting unquoted variable expansions that could lead to code execution
- Reviewing installation scripts, CI/CD pipelines, or build scripts
- Scanning for obfuscated or suspicious shell patterns
- Auditing Dockerfiles' RUN commands containing shell code
- Checking shell scripts in package managers (npm scripts, Makefiles)
- Triaging potentially malicious or compromised scripts
- Incident response requiring rapid shell script analysis

## Malicious Code Detection Priority

When scanning for potentially malicious or compromised shell scripts, use this prioritized approach:

### Critical Checks (Always Enable)
| Code | Pattern | Malicious Intent |
|------|---------|------------------|
| SC2091 | `$(curl http://...)` | Remote code execution, payload download |
| SC2086 | `rm -rf $VAR` | Command injection, arbitrary file deletion |
| SC2046 | `cmd $(user_input)` | Subshell injection |
| SC2115 | `rm -rf "$DIR/"*` | Root filesystem wipe when var is empty |

### High-Risk Patterns (Suspicious Behavior)
| Code | Pattern | Indicator |
|------|---------|-----------|
| SC2211 | `*.sh` as command | Arbitrary script execution |
| SC2216 | `find \| xargs rm` | Mass file deletion attack |
| SC2029 | SSH command injection | Remote command confusion |
| SC2087 | Unquoted heredoc | Credential/data injection |

### Indicators of Malicious Intent (Manual Review)
Beyond ShellCheck findings, flag scripts containing:
- **Reverse shells**: `bash -i`, `/dev/tcp/`, `nc -e`, `mkfifo`
- **Data exfiltration**: `curl -d "$(cat /etc/passwd)"`, encoded POST data
- **Obfuscation**: `base64 -d | bash`, `eval "$(printf '\x...')"`, `xxd -r`
- **Persistence**: crontab manipulation, `/etc/init.d/`, systemd service creation
- **Privilege escalation**: SUID manipulation, sudo config changes
- **Defense evasion**: `history -c`, `unset HISTFILE`, log deletion

## Prerequisites

### Installation

**macOS (Homebrew):**
```bash
brew install shellcheck
```

**Ubuntu/Debian:**
```bash
apt-get install shellcheck
```

**Fedora/RHEL:**
```bash
dnf install ShellCheck
```

**Using Cabal (Haskell):**
```bash
cabal update
cabal install ShellCheck
```

**Docker:**
```bash
docker pull koalaman/shellcheck
```

### Verify Installation

```bash
shellcheck --version
```

## Core Commands

### Basic Security Scan

```bash
# Scan a single script
shellcheck script.sh

# Scan with severity threshold (error, warning, info, style)
shellcheck --severity=warning script.sh

# Scan multiple files
shellcheck *.sh

# Scan recursively
find . -name "*.sh" -exec shellcheck {} +
```

### Output Formats

```bash
# JSON output for parsing
shellcheck --format=json script.sh

# SARIF output for security tools
shellcheck --format=sarif script.sh

# GCC-compatible format
shellcheck --format=gcc script.sh

# Checkstyle XML format
shellcheck --format=checkstyle script.sh

# Quiet mode (only show errors)
shellcheck --format=quiet script.sh
```

### Shell Dialect Selection

```bash
# Specify shell dialect
shellcheck --shell=bash script.sh
shellcheck --shell=sh script.sh
shellcheck --shell=dash script.sh
shellcheck --shell=ksh script.sh
```

### Advanced Options

```bash
# Enable all optional checks
shellcheck --enable=all script.sh

# Exclude specific checks
shellcheck --exclude=SC2086,SC2046 script.sh

# Check scripts sourced from stdin
cat script.sh | shellcheck -

# Follow source statements
shellcheck --source-path=SCRIPTDIR script.sh
```

## Deep Security Scan for Malicious Code

### Comprehensive Single-File Analysis
```bash
# Maximum security scan with all checks, filter critical issues
shellcheck --enable=all --severity=style --format=json script.sh | \
  jq '[.[] | select(.code | tostring | test("^20(86|46|91|29|87|68|34|64|89|90)|2115|2116|2211|2216"))]'
```

### Prioritized Critical Check Scan
```bash
# Focus on high-risk injection patterns only
shellcheck --enable=all script.sh 2>&1 | \
  grep -E "SC20(86|46|91)|SC2115|SC2211|SC2216"
```

### Project-Wide Malicious Code Hunt
```bash
# Scan all shell scripts with security focus, exclude vendor
find . -type f \( -name "*.sh" -o -name "*.bash" \) \
  ! -path "./vendor/*" ! -path "./node_modules/*" \
  -exec shellcheck --enable=all --severity=warning --format=gcc {} + 2>&1 | \
  sort -t: -k4 | uniq -c | sort -rn
```

### CI/CD Pipeline Script Audit
```bash
# Extract and scan shell code from GitHub Actions workflows
find .github -name "*.yml" -exec grep -l "run:" {} + | \
  xargs -I{} sh -c 'grep -A5 "run:" "{}" | grep -v "^--$"' | \
  shellcheck --shell=bash -
```

## Detecting Obfuscated Malicious Payloads

ShellCheck's static analysis may miss sophisticated obfuscation. Combine with pattern detection:

### Base64 Payloads
```bash
# Find base64 decode + execute patterns
grep -rn --include="*.sh" -E "(base64\s+(-d|--decode)|decode.*base64).*\|\s*(ba)?sh" .
```

### Hex/Octal Encoding
```bash
# Find printf-based obfuscation
grep -rn --include="*.sh" -E "printf.*\\\\x[0-9a-fA-F]{2}" .
grep -rn --include="*.sh" -E '\$\(printf.*\\[0-7]{3}' .
```

### Reverse Shell Signatures
```bash
# Common reverse shell patterns
grep -rn --include="*.sh" -E "(bash\s+-i|/dev/tcp/|nc\s+(-e|-c)|mkfifo|0<&[0-9])" .
```

### Eval-Based Execution
```bash
# Dangerous eval patterns
grep -rn --include="*.sh" -E "eval\s+['\"]?\\\$\(" .
```

These patterns should trigger manual review even if ShellCheck passes.

## Security-Relevant Checks

| Code | Severity | Description | Security Impact |
|------|----------|-------------|-----------------|
| SC2086 | Warning | Double quote to prevent globbing and word splitting | Command injection, arbitrary file access |
| SC2046 | Warning | Quote to prevent word splitting on command substitution | Command injection |
| SC2091 | Warning | Remove surrounding $() to avoid executing output | Arbitrary code execution |
| SC2155 | Warning | Declare and assign separately to avoid masking return values | Logic bypass |
| SC2012 | Warning | Use find instead of ls to better handle non-alphanumeric filenames | Path traversal |
| SC2029 | Warning | Commands run on client, not server | Unintended local execution |
| SC2034 | Warning | Variable appears unused | Dead code, possible data leak |
| SC2064 | Warning | Use single quotes for trap commands | Unexpected expansion timing |
| SC2068 | Warning | Double quote array expansions | Argument injection |
| SC2087 | Warning | Quote heredoc to prevent variable expansion | Data injection |
| SC2089 | Warning | Quotes/backslashes in variables don't work | Escape bypass |
| SC2090 | Warning | Quotes/backslashes will be treated literally | Command injection |
| SC2116 | Warning | Useless echo? Instead of `echo $(cmd)`, use `cmd` | Unnecessary subshell |
| SC2129 | Style | Consider using redirections instead of pipes | Efficiency |
| SC2145 | Warning | Argument mixes string and array | Unexpected behavior |
| SC2148 | Warning | Tips depend on target shell | Wrong shell execution |
| SC2154 | Warning | Variable is referenced but not assigned | Undefined behavior |
| SC2162 | Warning | read without -r mangles backslashes | Input manipulation |
| SC2174 | Warning | mkdir -m only applies to the deepest directory | Permission bypass |
| SC2206 | Warning | Quote to prevent word splitting | Array injection |
| SC2211 | Warning | Glob used as command name | Arbitrary command execution |
| SC2215 | Warning | Flag appears after filename | Argument confusion |
| SC2216 | Warning | Piping to rm is unsafe | Arbitrary file deletion |
| SC2220 | Warning | Invalid flags | Unexpected behavior |
| SC2222 | Warning | Remove invalid flags | Unexpected behavior |
| SC2223 | Warning | Quote to prevent empty command | Logic errors |
| SC2224 | Warning | Numeric comparison on non-number | Logic bypass |
| SC2225 | Warning | Source outside of subroutine | Scope leakage |
| SC2226 | Warning | Use -exec or -exec + instead of -execdir | Path injection |

### MITRE ATT&CK Mappings

| Technique ID | Technique Name | Relevant Checks |
|--------------|----------------|-----------------|
| T1059.004 | Command and Scripting Interpreter: Unix Shell | SC2086, SC2046, SC2091 |
| T1027 | Obfuscated Files or Information | SC2089, SC2090 |
| T1105 | Ingress Tool Transfer | SC2029 (curl/wget patterns) |
| T1222.002 | File and Directory Permissions Modification | SC2174 |
| T1070.004 | Indicator Removal: File Deletion | SC2216 |
| T1552.001 | Unsecured Credentials: Credentials in Files | SC2034 (unused sensitive vars) |

## Security Triage Workflow

### Step 1: Quick Risk Assessment
```bash
# Count security-relevant findings by severity
shellcheck --enable=all --format=json script.sh | \
  jq -r '.[] | "\(.level): \(.code)"' | sort | uniq -c | sort -rn
```

### Step 2: Critical Issue Identification
```bash
# Extract only critical security issues
shellcheck --enable=all --format=json script.sh | \
  jq -r '.[] | select(.code == 2086 or .code == 2046 or .code == 2091 or .code == 2115) | 
    "[\(.level)] Line \(.line): \(.message)"'
```

### Step 3: Context Analysis
For each critical finding, assess exploitability:
- **SC2086 in `rm`/`curl`/`wget`**: Likely exploitable → HIGH PRIORITY
- **SC2086 in `echo`/`printf`**: Lower risk → MEDIUM PRIORITY  
- **SC2091**: Always critical → IMMEDIATE REVIEW
- **SC2115**: Empty variable + rm = catastrophic → CRITICAL

### Step 4: Malicious Intent Assessment
```bash
# Look for network activity + execution patterns together
grep -E "(curl|wget|nc).*\|.*(ba)?sh" script.sh && echo "⚠️  SUSPICIOUS: Download-and-execute pattern"

# Check for data exfiltration patterns
grep -E "curl.*-d.*\$|wget.*--post-data" script.sh && echo "⚠️  SUSPICIOUS: Data exfiltration pattern"

# Check for persistence mechanisms
grep -E "crontab|/etc/cron|systemctl.*enable|update-rc.d" script.sh && echo "⚠️  CHECK: Persistence mechanism"
```

### Step 5: Generate Security Report
```bash
# Create SARIF report for security tools/SIEM integration
shellcheck --format=sarif --enable=all script.sh > shellcheck-security.sarif

# Or create a summary report
echo "=== ShellCheck Security Report ==="
echo "File: script.sh"
echo "Date: $(date -Iseconds)"
shellcheck --enable=all --format=gcc script.sh 2>&1 | \
  awk -F: '{print $4}' | sort | uniq -c | sort -rn
```

## Interpreting Results

### Output Format

```
In script.sh line 5:
rm -rf $DIR
       ^--^ SC2086: Double quote to prevent globbing and word splitting.
```

### Severity Levels

- **error**: Definite bugs or syntax errors
- **warning**: Likely bugs or problematic patterns (security-relevant)
- **info**: Suggestions for improvement
- **style**: Stylistic issues

### Security Triage Priority

1. **Critical**: SC2091 (executing output), SC2086/SC2046 with user input
2. **High**: Unquoted variables in rm, curl, eval contexts
3. **Medium**: General quoting issues, permission problems
4. **Low**: Style issues, minor suggestions

## Examples and Patterns

See [examples/malicious-patterns.md](examples/malicious-patterns.md) for detailed examples of:
- Command injection vulnerabilities with ShellCheck detection
- Obfuscation patterns and their indicators  
- Before/after secure code patterns
- Risk level classification for common findings

## Integration with Other Security Skills

For comprehensive shell script security analysis, combine ShellCheck with other tools:

| Tool | Use Case | Command |
|------|----------|---------|  
| **graudit** | Detect secrets, backdoors, reverse shells | `graudit -d exec -d secrets script.sh` |
| **bandit** | If script calls Python code | Scan embedded Python separately |
| **grep patterns** | Obfuscation detection | See patterns in "Detecting Obfuscated Malicious Payloads" |

### Recommended Scan Order for Untrusted Scripts
1. **ShellCheck** (syntax + security) → This skill
2. **graudit -d exec** (execution patterns) → Complements static analysis  
3. **graudit -d secrets** (credential detection) → If script handles secrets
4. **Manual review** for findings + obfuscation patterns
5. **Sandbox execution** if script must be tested

## Configuration

### Inline Directives

```bash
# Disable check for next line
# shellcheck disable=SC2086
rm -rf $DIR

# Disable for entire file (place at top)
# shellcheck disable=SC2086,SC2046

# Enable optional checks
# shellcheck enable=require-variable-braces
```

### Configuration File

Create `.shellcheckrc` in project root:

```ini
# Enable all optional checks
enable=all

# Exclude specific checks
exclude=SC2034,SC2129

# Set default shell
shell=bash

# Set severity threshold
severity=warning
```

## Limitations and Blind Spots

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| No runtime analysis | Can't detect dynamic payload generation | Run in sandbox if suspicious |
| No taint tracking | Misses data flow from untrusted sources | Manual code review |
| Limited obfuscation detection | Base64/hex encoding bypasses analysis | Use grep patterns + graudit |
| No network inspection | Can't analyze downloaded payloads | Block/intercept network in sandbox |
| Shell-only analysis | Embedded Python/Perl/Ruby ignored | Use language-specific tools |
| Shebang dependency | May miss shell dialect issues | Explicitly specify `-s shell` |
| False positives | Some warnings may not apply | Context-aware triage |

### What ShellCheck CANNOT Detect
- Obfuscated reverse shells (`echo "YmFzaCAtaS4uLg==" | base64 -d | bash`)
- Legitimate-looking but malicious logic (e.g., conditional backdoors)
- Time bombs or environment-triggered payloads
- Steganographic or external payload retrieval
- Encrypted or compressed payloads
- Social engineering in comments or variable names

## Quick Reference: Security Scan Commands

| Goal | Command |
|------|---------|  
| Full security scan | `shellcheck --enable=all --severity=warning script.sh` |
| JSON for parsing | `shellcheck --enable=all --format=json script.sh` |
| Critical issues only | `shellcheck script.sh 2>&1 \| grep -E "SC20(86\|46\|91)"` |
| Scan all scripts | `find . -name "*.sh" -exec shellcheck {} +` |
| SARIF report | `shellcheck --format=sarif --enable=all script.sh` |
| Exclude false positives | `shellcheck -e SC2034,SC2129 script.sh` |
| Specify shell dialect | `shellcheck -s bash script.sh` |
| Scan from stdin | `cat script.sh \| shellcheck -` |

## Additional Integration Examples

```bash
# Combine with file discovery (exclude vendor directories)
find . -type f \( -name "*.sh" -o -name "*.bash" \) \
  ! -path "*/vendor/*" ! -path "*/node_modules/*" \
  -exec shellcheck {} +

# Check scripts in Dockerfiles
grep -h "RUN" Dockerfile* | sed 's/RUN //' | shellcheck -s bash -

# Pre-commit hook (error severity only for blocking)
shellcheck --severity=error $(git diff --cached --name-only --diff-filter=ACM | grep '\.sh$')

# Batch scan with parallel processing
find . -name "*.sh" -print0 | xargs -0 -P4 -I{} shellcheck --format=gcc {}

# Generate HTML report (requires pandoc)
shellcheck --format=json script.sh | \
  jq -r '.[] | "## Line \(.line)\n**\(.code)**: \(.message)\n"' | \
  pandoc -f markdown -t html > report.html
```
