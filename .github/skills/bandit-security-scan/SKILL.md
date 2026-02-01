---
name: bandit-security-scan
description: Security audit of Python source code (.py, setup.py, pyproject.toml) for security vulnerabilities using Bandit AST analysis. (1) Detects exec/eval code execution, pickle/yaml deserialization, subprocess shell injection, SQL injection, hardcoded credentials, weak cryptography, OWASP Top 10 Python issues. Use for Python security audits, Django/Flask apps, malicious Python code triage, CI/CD pipelines. NOT use for dependency/package audits (use guarddog), non-Python code (use graudit), shell scripts (use shellcheck). For mixed Python projects, combine with graudit -d secrets for comprehensive coverage.
---

# Bandit Security Scanner Skill

Bandit is a security linter designed to find common security issues in Python code. It processes each file, builds an AST, and runs appropriate plugins against the AST nodes.

## When to Use This Skill

Use this skill when:
- Scanning Python code for security vulnerabilities
- Auditing Python projects for hardcoded secrets or credentials
- Detecting dangerous function calls (eval, exec, pickle)
- Finding SQL injection or command injection vulnerabilities
- Checking for weak cryptographic practices
- Reviewing Python packages for malicious patterns
- Performing security code review on Python applications

## Decision Tree: Choosing the Right Tool

```
What are you scanning?
│
├── Python source code (.py files)?
│   ├── Own code security audit → bandit -r /path (THIS SKILL)
│   ├── Untrusted/malicious Python → bandit + graudit -d exec,secrets
│   └── Django/Flask app → bandit -r . -t B201,B701,B703,B610,B611
│
├── Python dependencies (requirements.txt)?
│   └── Use guarddog instead: guarddog pypi verify requirements.txt
│
├── Mixed languages or non-Python?
│   └── Use graudit instead (multi-language support)
│
└── Shell scripts?
    └── Use shellcheck instead
```

## Malicious Code Detection Priority

When scanning for potentially malicious or compromised Python code, prioritize these test IDs:

### Critical - Immediate Red Flags
| Test ID | Detection | Why It's Dangerous |
|---------|-----------|-------------------|
| B102 | `exec()` usage | Arbitrary code execution |
| B307 | `eval()` usage | Arbitrary code execution |
| B602 | `subprocess(shell=True)` | Reverse shells, command injection |
| B605 | `os.system()` | Command injection |
| B301 | `pickle.load()` | Code execution via deserialization |

### High - Data Exfiltration & Backdoors
| Test ID | Detection | MITRE ATT&CK |
|---------|-----------|---------------|
| B310 | `urllib.urlopen` | T1071 - C2 communication |
| B312 | `telnetlib` | T1071 - Unencrypted backdoor |
| B321 | `ftplib` | T1071 - Data exfiltration |
| B105-B107 | Hardcoded passwords | T1552.001 - Embedded credentials |
| B506 | `yaml.load()` | T1059 - Deserialization attack |

### Recommended Command for Malicious Code Triage
```bash
# Critical patterns first (< 30 seconds)
bandit -r . -t B102,B307,B602,B605,B301 -lll --format json

# Full malicious scan with context
bandit -r . -t B102,B105,B106,B107,B301,B307,B310,B312,B321,B506,B602,B605,B608 -f json -o malicious-scan.json
```

## Prerequisites

Install Bandit using pip:

```bash
# Install via pip
pip install bandit

# Or with TOML support for pyproject.toml configuration
pip install bandit[toml]

# Verify installation
bandit --version
```

## Core Commands

### Basic Scanning

```bash
# Scan a single file
bandit target_file.py

# Scan a directory recursively
bandit -r /path/to/project

# Scan with specific severity level (LOW, MEDIUM, HIGH)
bandit -r . -ll  # Only MEDIUM and above
bandit -r . -lll # Only HIGH severity

# Scan with specific confidence level
bandit -r . -ii  # MEDIUM confidence and above
bandit -r . -iii # Only HIGH confidence
```

### Output Formats

```bash
# JSON output (recommended for parsing)
bandit -r . -f json -o bandit-results.json

# SARIF output (for IDE integration)
bandit -r . -f sarif -o bandit-results.sarif

# HTML report
bandit -r . -f html -o bandit-report.html

# CSV output
bandit -r . -f csv -o bandit-results.csv

# Custom format with line numbers
bandit -r . -f custom --msg-template "{relpath}:{line}: {test_id}[{severity}]: {msg}"
```

### Selective Scanning

```bash
# Run only specific tests
bandit -r . -t B101,B102,B103

# Skip specific tests
bandit -r . -s B101,B601

# Scan specific file patterns
bandit -r . --include "*.py"
bandit -r . --exclude "*/tests/*,*/venv/*"
```

### Configuration File

```bash
# Generate sample config
bandit-config-generator -o .bandit

# Use configuration file
bandit -r . -c .bandit

# Use pyproject.toml
bandit -r . -c pyproject.toml
```

## Available Rules/Checks

### Dangerous Function Calls

| Test ID | Description | Severity | MITRE ATT&CK |
|---------|-------------|----------|--------------|
| B101 | assert used | LOW | - |
| B102 | exec used | MEDIUM | T1059 (Command Execution) |
| B103 | set_bad_file_permissions | MEDIUM | T1222 (File Permission Modification) |
| B104 | hardcoded_bind_all_interfaces | MEDIUM | T1071 (Application Layer Protocol) |
| B105 | hardcoded_password_string | LOW | T1552.001 (Credentials in Files) |
| B106 | hardcoded_password_funcarg | LOW | T1552.001 (Credentials in Files) |
| B107 | hardcoded_password_default | LOW | T1552.001 (Credentials in Files) |
| B108 | hardcoded_tmp_directory | MEDIUM | T1074 (Data Staged) |
| B110 | try_except_pass | LOW | - |
| B112 | try_except_continue | LOW | - |

### Injection Vulnerabilities

| Test ID | Description | Severity | MITRE ATT&CK |
|---------|-------------|----------|--------------|
| B201 | flask_debug_true | HIGH | T1190 (Exploit Public-Facing Application) |
| B301 | pickle | MEDIUM | T1059 (Deserialization) |
| B302 | marshal | MEDIUM | T1059 (Deserialization) |
| B303 | md5/sha1 | MEDIUM | T1600 (Weaken Encryption) |
| B304 | insecure_cipher | HIGH | T1600 (Weaken Encryption) |
| B305 | insecure_cipher_mode | MEDIUM | T1600 (Weaken Encryption) |
| B306 | mktemp_q | MEDIUM | T1074 (Data Staged) |
| B307 | eval | MEDIUM | T1059 (Command Execution) |
| B308 | mark_safe | MEDIUM | T1059.007 (JavaScript) |
| B310 | urllib_urlopen | MEDIUM | T1071 (Application Layer Protocol) |
| B311 | random | LOW | T1600 (Weaken Encryption) |
| B312 | telnetlib | HIGH | T1071 (Application Layer Protocol) |
| B313-B320 | xml vulnerabilities | MEDIUM | T1059 (XXE) |
| B321 | ftplib | HIGH | T1071 (Application Layer Protocol) |
| B323 | unverified_context | MEDIUM | T1557 (MITM) |
| B324 | hashlib_insecure | MEDIUM | T1600 (Weaken Encryption) |

### Shell Injection

| Test ID | Description | Severity | MITRE ATT&CK |
|---------|-------------|----------|--------------|
| B601 | paramiko_calls | MEDIUM | T1021.004 (SSH) |
| B602 | subprocess_popen_shell | HIGH | T1059.004 (Unix Shell) |
| B603 | subprocess_without_shell | LOW | T1059 (Command Execution) |
| B604 | any_other_function_shell | MEDIUM | T1059.004 (Unix Shell) |
| B605 | start_process_shell | HIGH | T1059.004 (Unix Shell) |
| B606 | start_process_no_shell | LOW | T1059 (Command Execution) |
| B607 | start_process_partial_path | LOW | T1059 (Command Execution) |
| B608 | hardcoded_sql_expressions | MEDIUM | T1190 (SQL Injection) |
| B609 | linux_commands_wildcard | HIGH | T1059.004 (Unix Shell) |
| B610 | django_extra_used | MEDIUM | T1190 (SQL Injection) |
| B611 | django_rawsql_used | MEDIUM | T1190 (SQL Injection) |

### Cryptographic Issues

| Test ID | Description | Severity | MITRE ATT&CK |
|---------|-------------|----------|--------------|
| B501 | request_with_no_cert_validation | HIGH | T1557 (MITM) |
| B502 | ssl_with_bad_version | HIGH | T1600 (Weaken Encryption) |
| B503 | ssl_with_bad_defaults | MEDIUM | T1600 (Weaken Encryption) |
| B504 | ssl_with_no_version | MEDIUM | T1600 (Weaken Encryption) |
| B505 | weak_cryptographic_key | HIGH | T1600 (Weaken Encryption) |
| B506 | yaml_load | MEDIUM | T1059 (Deserialization) |
| B507 | ssh_no_host_key_verification | HIGH | T1557 (MITM) |
| B508 | snmp_insecure_version | MEDIUM | T1071 (Application Layer Protocol) |
| B509 | snmp_weak_cryptography | MEDIUM | T1600 (Weaken Encryption) |

### Network Security

| Test ID | Description | Severity | MITRE ATT&CK |
|---------|-------------|----------|--------------|
| B701 | jinja2_autoescape_false | HIGH | T1059.007 (XSS) |
| B702 | use_of_mako_templates | MEDIUM | T1059.007 (XSS) |
| B703 | django_mark_safe | MEDIUM | T1059.007 (XSS) |

## Recommended Scanning Workflows

### Quick Triage (< 30 seconds)
For rapid assessment of unknown or suspicious Python code:
```bash
# Check for obvious malicious patterns only
bandit -r . -t B102,B307,B602,B605 -lll
```

### Standard Security Audit (1-2 minutes)
For routine code review:
```bash
# Step 1: High-severity issues
bandit -r . -lll -f json -o high-severity.json

# Step 2: Medium and above with exclusions
bandit -r . -ll --exclude "*/tests/*,*/venv/*"
```

### Deep Malicious Code Scan (5-10 minutes)
For untrusted code or incident response:
```bash
# Comprehensive scan with all context
bandit -r . -f json -o full-scan.json

# Then combine with graudit for non-Python embedded code
graudit -d exec . && graudit -d secrets .
```

### Baseline Workflow
For tracking security improvements over time:
```bash
# Create baseline for existing code
bandit -r . -f json -o baseline.json

# Later scans compare against baseline
bandit -r . -b baseline.json
```

### CI/CD Integration
```bash
# Fail pipeline on HIGH severity with HIGH confidence
bandit -r . -lll -iii || exit 1

# Don't fail on findings (reporting only)
bandit -r . -ll --exit-zero

# Fail on MEDIUM+ findings
bandit -r . -ll
```

## Framework-Specific Scanning

### Django Applications
```bash
bandit -r . -t B201,B608,B610,B611,B701,B703 -f json
# Checks: Debug mode, SQL injection, XSS via mark_safe, raw SQL
```

### Flask Applications
```bash
bandit -r . -t B104,B201,B310,B701 -f json
# Checks: Debug mode, bind all interfaces, Jinja2 XSS
```

### Data Processing / ML Pipelines
```bash
bandit -r . -t B301,B302,B506 -f json
# Checks: pickle, marshal, yaml deserialization
```

### API Services
```bash
bandit -r . -t B105,B106,B107,B501,B502,B503 -f json
# Checks: Hardcoded creds, SSL/TLS issues
```

## Interpreting Results

### Severity Levels
- **HIGH**: Critical security issues requiring immediate attention
- **MEDIUM**: Significant issues that should be addressed
- **LOW**: Minor issues or potential concerns

### Confidence Levels
- **HIGH**: Very confident this is a real issue
- **MEDIUM**: Likely an issue but may need verification
- **LOW**: Possible issue, manual review recommended

### Example Output
```
>> Issue: [B102:exec_used] Use of exec detected.
   Severity: Medium   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   Location: ./malicious.py:15:0
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b102_exec_used.html
```

## Verifying Findings

For each Bandit finding, verify:
- [ ] Is user/external input involved? (not hardcoded safe values)
- [ ] Can an attacker control the input path?
- [ ] Is there sanitization/validation before the dangerous call?
- [ ] Is this production code? (not tests/examples/documentation)
- [ ] Does the confidence level match manual assessment?

### Common False Positives
| Test ID | False Positive Scenario | Recommendation |
|---------|------------------------|----------------|
| B101 | `assert` in test files | Skip with `--exclude "*/tests/*"` |
| B311 | `random` used for non-security purposes (UI, games) | Skip with `-s B311` if confirmed safe |
| B105 | Variables named `password` that aren't credentials | Manual review, consider renaming |
| B602 | `subprocess(shell=True)` with hardcoded commands | Verify no user input reaches command |
| B108 | `/tmp` usage in containerized environments | Context-dependent, may be acceptable |

## Integration with Other Security Tools

For comprehensive security analysis, combine Bandit with other skills:

| Code Type | Primary Tool | Secondary Scan |
|-----------|--------------|----------------|
| Python source (.py) | **Bandit** (this skill) | graudit -d secrets |
| Python packages | guarddog | Extract then Bandit |
| Mixed Python + Shell | Bandit + ShellCheck | graudit -d exec |
| Django/Flask + JS | Bandit | graudit -d js,xss |

### Recommended Multi-Tool Workflow
```bash
# 1. Python-specific deep analysis
bandit -r . -f json -o bandit-results.json

# 2. Secrets scan (catches patterns Bandit might miss)
graudit -d secrets .

# 3. Dependency audit
guarddog pypi verify requirements.txt
```

## Additional Resources

- [Malicious Patterns Reference](./examples/malicious-patterns.md) - Educational examples of dangerous code patterns that Bandit detects, including `exec()`, `eval()`, `pickle`, shell injection, SQL injection, and hardcoded credentials. Use this reference to understand detection capabilities and educate developers about secure coding.

## Limitations

- **Static Analysis Only**: Cannot detect runtime vulnerabilities or dynamic code execution patterns
- **Python Only**: Does not scan other languages in polyglot projects
- **AST-Based**: May miss vulnerabilities in string-constructed code
- **False Positives**: Some patterns (like `random` for non-security uses) may trigger warnings
- **No Data Flow**: Limited taint tracking compared to commercial SAST tools
- **Configuration Required**: May need tuning to reduce noise in large codebases
- **No Dependency Scanning**: Does not check for vulnerable dependencies (use `pip-audit` or `safety` for that)
