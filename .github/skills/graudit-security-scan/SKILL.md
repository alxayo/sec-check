---
name: graudit-security-scan
description: Use first-pass security scan on unknown/mixed-language codebases, secrets detection (API keys, passwords, tokens), malicious pattern detection (reverse shells, data exfiltration, obfuscation). (2) SECONDARY use supplement language-specific tools with 'secrets' and 'exec' database scans. Key databases secrets (credentials), exec (command injection), sql, xss, plus language-specific. Use for a lightweight Static Application Security Testing (SAST) and rapid source code auditing to identify "sinks" and dangerous functions that could lead to exploits like SQL injection, XSS, and buffer overflows. It is ideal for broad, multi-language security checks. This skill supports auditing for TypeScript, JavaScript, Python, C/C++, Go, Java, .NET/C#, Perl, PHP, Ruby, and SQL. Do NOT use as sole scanner when bandit (Python .py files) or shellcheck (shell .sh files) are applicable—use graudit alongside then.
---

# Graudit Security Scanning Skill

This skill enables scanning source code for potential security vulnerabilities using **graudit** - a grep-based source code auditing tool that uses regex signature databases to detect dangerous patterns.

## When to Use This Skill

- User asks to scan files for security issues or vulnerabilities
- User wants to audit source code for dangerous patterns
- User asks to check code for malicious content
- User wants to detect risky functions or patterns in scripts
- User needs a quick security review of source files
- User needs to audit untrusted or third-party code
- Incident response requiring rapid code triage

## Malicious Code Detection Priority

When scanning for potentially malicious or compromised code, use this prioritized approach:

### High-Priority Databases (Always Run for Untrusted Code)
| Database | Detects |
|----------|----------|
| `exec` | Command injection, reverse shells, system calls, process spawning |
| `secrets` | Hardcoded credentials, API keys, tokens, passwords |

### Medium-Priority Databases (Context-Dependent)
| Database | Detects |
|----------|----------|
| `sql` | SQL injection patterns, unsafe query construction |
| `xss` | Cross-site scripting, DOM manipulation, unsafe output |
| Language-specific | Language-specific dangerous functions and patterns |

### Indicators of Malicious Intent
Graudit can detect these suspicious patterns:
- **Reverse shells**: `socket.connect`, `/dev/tcp/`, `nc -e`, `bash -i`
- **Data exfiltration**: `curl` with encoded data, network calls with sensitive data
- **Obfuscation**: `base64.b64decode`, `eval(atob())`, `String.fromCharCode`, hex encoding
- **Backdoors**: Hidden command execution, environment variable abuse
- **Persistence**: Cron job creation, startup scripts, service installation
- **Credential theft**: Reading `/etc/passwd`, keychain access, browser data

## Prerequisites

Graudit must be installed. If not available, install it:

```bash
# Clone the repository
git clone https://github.com/wireghoul/graudit ~/graudit

# Add to PATH (add to ~/.bashrc or ~/.zshrc for persistence)
export PATH="$HOME/graudit:$PATH"

# Optionally set signature directory
export GRDIR="$HOME/graudit/signatures"
```

## Available Databases

Graudit includes signature databases for many languages and vulnerability types:

| Database | Description |
|----------|-------------|
| `default` | General security patterns (used if no -d specified) |
| `python` | Python-specific vulnerabilities |
| `js` | JavaScript security issues |
| `php` | PHP security flaws |
| `java` | Java vulnerabilities |
| `c` | C/C++ dangerous patterns |
| `go` | Go language security issues |
| `ruby` | Ruby security patterns |
| `perl` | Perl vulnerabilities |
| `dotnet` | .NET/C# security issues |
| `sql` | SQL injection patterns |
| `xss` | Cross-site scripting patterns |
| `secrets` | Hardcoded secrets/credentials |
| `exec` | Command execution vulnerabilities |
| `android` | Android-specific issues |
| `ios` | iOS-specific issues |
| `typescript` | TypeScript vulnerabilities |

## Database Selection Decision Tree

```
Is code untrusted/potentially malicious?
├── YES → Run: exec + secrets + language-specific + default
│         Use: ./graudit-deep-scan.sh /path/to/code ./report
│
└── NO (routine security audit)
    ├── Know the language?
    │   ├── YES → graudit -d <language> /path
    │   └── NO  → graudit -d default /path
    │
    └── Always add: graudit -d secrets /path
```

## Usage Instructions

### Basic Scan

Scan a file or directory with the default database:

```bash
graudit /path/to/scan
```

### Language-Specific Scan

Use the `-d` flag to specify a database:

```bash
# Python code
graudit -d python /path/to/script.py

# JavaScript/Node.js
graudit -d js /path/to/app.js

# PHP
graudit -d php /path/to/file.php

# Secrets detection
graudit -d secrets /path/to/project
```

### Advanced Options

```bash
# Case-insensitive scan
graudit -i -d python /path/to/scan

# Show more context lines (default is 1)
graudit -c 3 -d js /path/to/scan

# Exclude certain files
graudit -x "*.min.js,*.test.js" -d js /path/to/scan

# Scan all files including binary/difficult ones
graudit -A -d default /path/to/scan

# List available databases
graudit -l

# Suppress colors (for parsing output)
graudit -z -d python /path/to/scan
```

### Multi-Database Deep Scan

For comprehensive security analysis, run multiple databases:

```bash
# Run the helper script for multi-database scan
./graudit-deep-scan.sh /path/to/project
```

## Interpreting Results

Graudit outputs matches in grep format:
```
filename:line_number:matched_line
```

Each match indicates a **potential** security issue that requires manual review. Common patterns detected:

- **Command injection**: `eval()`, `exec()`, `system()`, `shell_exec()`
- **SQL injection**: Unparameterized queries, string concatenation
- **XSS vulnerabilities**: Unescaped output, innerHTML assignments
- **Hardcoded secrets**: API keys, passwords, tokens
- **Dangerous file operations**: `unlink()`, `chmod()`, file includes
- **Deserialization**: `pickle.loads()`, `unserialize()`
- **Path traversal**: User input in file paths

## Recommended Scanning Workflows

### Quick Triage (< 1 minute)
For rapid assessment of unknown or suspicious code:
```bash
# Single command - checks critical patterns first
graudit -d exec /path/to/code && graudit -d secrets /path/to/code
```

### Standard Security Audit (2-5 minutes)
For routine code review:
```bash
# Step 1: Language-specific scan
graudit -d python /path/to/code

# Step 2: Secrets scan (always do this)
graudit -d secrets /path/to/code

# Step 3: Execution vulnerabilities
graudit -d exec /path/to/code
```

### Deep Malicious Code Scan (5-10 minutes)
For untrusted code or incident response:
```bash
# Use the included deep scan script (recommended)
./graudit-deep-scan.sh /path/to/suspicious/code ./report-output

# Or manually run all critical databases
for db in exec secrets sql xss default; do
    echo "=== Scanning with $db ==="
    graudit -c 3 -d $db /path/to/code
done
```

### CI/CD Integration
```bash
# Exit with error if findings detected (for pipelines)
graudit -z -B -d secrets /path/to/code
if [ $? -ne 0 ]; then
    echo "Security findings detected!"
    exit 1
fi
```

## Understanding Output

### Example Output Format
```
src/api/auth.py:45:    password = "admin123"
src/utils/shell.py:23:    os.system(user_input)
src/db/query.py:89:    cursor.execute("SELECT * FROM users WHERE id=" + id)
```

### Severity Assessment Guide
| Pattern Type | Typical Severity | Action Required |
|--------------|------------------|------------------|
| `secrets` findings | HIGH | Immediate rotation of exposed credentials |
| `exec` with user input | CRITICAL | Code remediation required before deployment |
| `sql` string concat | HIGH | Parameterize queries |
| `xss` innerHTML | MEDIUM-HIGH | Sanitize or escape output |
| Generic `default` | VARIABLE | Manual review needed |

### Verification Checklist
For each finding, verify:
- [ ] Is user input involved? (not hardcoded safe values)
- [ ] Can an attacker control the input?
- [ ] Is there sanitization/validation before use?
- [ ] Is it in production code? (not tests/examples)

## Integration with Other Security Tools

For comprehensive security analysis, combine graudit with specialized tools:

| Code Type | Primary Tool | Graudit Role |
|-----------|--------------|---------------|
| Python (.py) | Bandit (AST analysis) | Secondary scan for secrets/exec patterns |
| Shell scripts (.sh) | ShellCheck | Secondary scan for command patterns |
| Dependencies | GuardDog | Graudit for source code after extraction |
| Mixed/Unknown | **Graudit** | Primary scanner |

### Recommended Multi-Tool Workflow
```bash
# 1. Quick graudit pass for immediate red flags
graudit -d exec /path/to/code && graudit -d secrets /path/to/code

# 2. Language-specific deep analysis (if applicable)
bandit -r /path/to/code         # For Python
shellcheck /path/to/*.sh        # For shell scripts

# 3. Dependency audit (if package files exist)
guarddog pypi verify requirements.txt
guarddog npm verify package-lock.json
```

## Handling False Positives

Graudit uses regex patterns and will produce false positives. Use these strategies:

### Common False Positives
- Test files with intentional vulnerable patterns for testing
- Documentation/comments mentioning dangerous functions
- Safely-used functions (e.g., `subprocess.run()` with hardcoded commands)
- Example code in README files

### Exclusion Strategies
```bash
# Exclude test directories
graudit -x "test/*,tests/*,*_test.py,*_spec.js" -d python /path

# Exclude minified/vendor files
graudit -x "*.min.js,vendor/*,node_modules/*,dist/*" -d js /path

# Focus on specific directories only
graudit -d secrets /path/src /path/config
```

## Included Scripts

This skill includes helper scripts for common scanning scenarios:

### [graudit-deep-scan.sh](./graudit-deep-scan.sh)
**Purpose**: Comprehensive multi-database security scan with report generation  
**Use when**: Auditing untrusted code, incident response, thorough security review
```bash
./graudit-deep-scan.sh /path/to/project ./output-report
```
**Output**: Creates `./output-report/` directory with:
- `summary.txt` - Overview of all findings by category
- `{database}-findings.txt` - Detailed findings per database

### [graudit-wrapper.sh](./graudit-wrapper.sh)
**Purpose**: Smart scanning with auto-language detection and flexible options  
**Use when**: Day-to-day security scanning with convenience features
```bash
./graudit-wrapper.sh -a ./project      # Auto-detect language
./graudit-wrapper.sh -f -s ./project   # Full scan with secrets
./graudit-wrapper.sh -d python -x "tests/*" ./src  # Targeted scan
```

## Additional Resources

- [Malicious Patterns Reference](./examples/malicious-patterns.md) - Educational examples of dangerous code patterns including command injection, SQL injection, XSS, hardcoded secrets, reverse shells, and obfuscation techniques. Use this reference to understand what the scanner detects and to educate users about security risks.

## Limitations

- Graudit uses pattern matching (regex), so it **will** produce false positives
- Cannot detect logic flaws or business logic vulnerabilities
- Context-dependent vulnerabilities may be missed
- Cannot analyze obfuscated/encrypted code beyond pattern recognition
- Does not execute code - purely static analysis
- Always perform manual code review for critical applications
- For Python-specific deep analysis, prefer Bandit
- For shell script analysis, prefer ShellCheck
