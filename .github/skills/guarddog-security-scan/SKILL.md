---
name: guarddog-security-scan
description: Detect malicious packages and supply chain attacks in Python (PyPI) and Node.js (npm) ecosystems.ALWAYS use BEFORE running pip install or npm install on untrusted packages.(1) Primary targets requirements.txt, package.json, package-lock.json, *.tar.gz, *.tgz archives.(2) Detects malware, data exfiltration, reverse shells, backdoors, typosquatting, obfuscated payloads, compromised maintainer accounts.(3) Use for dependency audits, pre-installation checks, investigating suspicious packages, supply chain security. Do NOT use for scanning your own source code vulnerabilities (use bandit for Python, graudit for multi-language).
---

# GuardDog Security Scanning Skill

This skill enables scanning Python and Node.js code for malicious patterns using **GuardDog** - a CLI tool by DataDog designed to identify malicious PyPI and npm packages through source code analysis (Semgrep rules) and metadata heuristics.

> **Key Distinction**: GuardDog detects **malicious intent** (malware, supply chain attacks). For general **vulnerability scanning** of your own code, use `bandit` (Python) or `graudit` (multi-language) instead.

## Quick Reference

| Task | Command |
|------|---------|
| Scan local Python project | `guarddog pypi scan ./project/` |
| Scan local Node.js project | `guarddog npm scan ./project/` |
| Verify Python dependencies | `guarddog pypi verify requirements.txt` |
| Verify npm dependencies | `guarddog npm verify package-lock.json` |
| Check PyPI package before install | `guarddog pypi scan <package-name>` |
| Check npm package before install | `guarddog npm scan <package-name>` |
| JSON output for automation | `--output-format=json` |
| SARIF output for CI/CD | `--output-format=sarif` |

## When to Use This Skill

**PRIMARY USE CASES:**
- Audit dependencies in `requirements.txt`, `package.json`, or `package-lock.json` before installation
- Scan untrusted or third-party packages for malware indicators
- Detect supply chain attacks, typosquatting, and compromised packages
- Verify package integrity before adding new dependencies
- Investigate suspicious packages reported by security alerts

**DO NOT USE FOR:**
- General vulnerability scanning of your own Python code → use `bandit`
- General vulnerability scanning of JavaScript/other code → use `graudit`
- Shell script security auditing → use `shellcheck`
- Scanning for hardcoded secrets in source → use `graudit -d secrets`

## Decision Tree: Choosing the Right Scan

```
What are you scanning?
│
├── Third-party package/dependency?
│   ├── Before installing a new package → guarddog <ecosystem> scan <package-name>
│   ├── Existing requirements.txt/package.json → guarddog <ecosystem> verify <file>
│   └── Downloaded/untrusted code archive → guarddog <ecosystem> scan /path/to/archive
│
├── Your own Python code?
│   └── Use bandit instead: bandit -r ./project
│
├── Your own JavaScript/multi-language code?
│   └── Use graudit instead: graudit -d js ./project
│
└── Mix of own code + dependencies?
    ├── Step 1: guarddog verify dependencies
    └── Step 2: bandit/graudit for your code
```

## Prerequisites

GuardDog must be installed. If not available, install it:

```bash
# Install via pip (requires Python 3.10+)
pip install guarddog

# Or use Docker (isolated, no local install needed)
docker pull ghcr.io/datadog/guarddog
alias guarddog='docker run --rm -v "$(pwd):/workspace" ghcr.io/datadog/guarddog'

# Verify installation
guarddog --version
```

**Troubleshooting Installation:**
```bash
# If pip install fails, ensure Python 3.10+
python --version

# If semgrep dependency issues occur
pip install --upgrade semgrep guarddog

# Check if guarddog is in PATH
which guarddog || echo "Add to PATH or use full path"
```

## Core Scanning Commands

### Scan Local Python Directory or Package

```bash
# Scan a local directory for malicious Python patterns
guarddog pypi scan /path/to/python/project/

# Scan a local .tar.gz package archive
guarddog pypi scan /path/to/package.tar.gz

# Output results as JSON for parsing
guarddog pypi scan /path/to/project --output-format=json
```

### Scan Local Node.js Directory or Package

```bash
# Scan a local directory for malicious JavaScript/Node.js patterns
guarddog npm scan /path/to/nodejs/project/

# Scan a local npm package archive
guarddog npm scan /path/to/package.tgz

# Output results as JSON
guarddog npm scan /path/to/project --output-format=json
```

### Verify Dependency Files (RECOMMENDED FIRST STEP)

```bash
# Scan all packages in requirements.txt (fetches from PyPI)
guarddog pypi verify /path/to/requirements.txt

# Scan all packages in package-lock.json or package.json
guarddog npm verify /path/to/package-lock.json

# Output as SARIF (for CI/CD integration)
guarddog pypi verify requirements.txt --output-format=sarif > guarddog.sarif
```

### Scan Remote Packages Before Installation

```bash
# Check a PyPI package before installing
guarddog pypi scan requests

# Check specific version
guarddog pypi scan requests --version 2.28.1

# Check an npm package before installing
guarddog npm scan express
```

## Available Heuristics/Rules

GuardDog uses two detection mechanisms: **Source Code Rules** (Semgrep-based) and **Metadata Rules** (heuristics).

### Threat Categories by Priority

**🔴 CRITICAL - Immediate Threats (Active Malware)**
| Rule | Ecosystem | Description |
|------|-----------|-------------|
| `exec-base64` / `npm-exec-base64` | Both | Executes obfuscated payloads |
| `exfiltrate-sensitive-data` / `npm-exfiltrate-sensitive-data` | Both | Steals credentials/keys |
| `code-execution` | Python | OS commands in setup.py |
| `download-executable` | Python | Downloads and runs malware |
| `npm-install-script` | npm | Malicious install hooks |

**🟠 HIGH - Supply Chain Risks**
| Rule | Ecosystem | Description |
|------|-----------|-------------|
| `typosquatting` | Both | Impersonates popular packages |
| `repository_integrity_mismatch` | Python | Package differs from GitHub source |
| `cmd-overwrite` | Python | Hijacked install command |
| `potentially_compromised_email_domain` | Both | Maintainer email compromised |

**🟡 MEDIUM - Suspicious Indicators**
| Rule | Ecosystem | Description |
|------|-----------|-------------|
| `obfuscation` / `npm-obfuscation` | Both | Code intentionally obscured |
| `steganography` / `npm-steganography` | Both | Hidden data in images |
| `shady-links` | Both | Suspicious URL patterns |
| `bundled_binary` | Both | Contains binary files |
| `silent-process-execution` / `npm-silent-process-execution` | Both | Hidden process execution |

**🟢 LOW - Quality/Trust Indicators**
| Rule | Ecosystem | Description |
|------|-----------|-------------|
| `empty_information` | Both | Missing description |
| `release_zero` | Both | Version 0.0.0 |
| `single_python_file` | Python | Minimal package |
| `deceptive_author` | Both | Disposable email |

### Python (PyPI) Source Code Rules

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `code-execution` | OS command executed in setup.py | T1059 |
| `cmd-overwrite` | Install command overwritten in setup.py | T1059 |
| `exec-base64` | Dynamically executes base64-encoded code | T1027, T1059 |
| `download-executable` | Downloads and executes remote binary | T1105 |
| `exfiltrate-sensitive-data` | Reads and exfiltrates sensitive data | T1005, T1041 |
| `obfuscation` | Common obfuscation methods used by malware | T1027 |
| `api-obfuscation` | Obfuscated API calls using alternative syntax | T1027 |
| `shady-links` | URLs to suspicious domain extensions | T1071 |
| `clipboard-access` | Reads/writes clipboard data | T1115 |
| `silent-process-execution` | Silently executes an executable | T1059 |
| `dll-hijacking` | Manipulates trusted app to load malicious DLL | T1574.001 |
| `steganography` | Retrieves hidden data from images | T1027.003 |
| `suspicious_passwd_access_linux` | Reads /etc/passwd for credential harvesting | T1555 |
| `unicode` | Suspicious unicode characters hiding malice | T1027 |

### Python (PyPI) Metadata Rules

| Rule | Description |
|------|-------------|
| `typosquatting` | Named similar to popular package |
| `empty_information` | Empty description field |
| `release_zero` | Version 0.0 or 0.0.0 (untested) |
| `potentially_compromised_email_domain` | Maintainer email domain may be compromised |
| `unclaimed_maintainer_email_domain` | Maintainer email domain is unclaimed |
| `repository_integrity_mismatch` | Package has unexpected files vs GitHub repo |
| `single_python_file` | Only one Python file (suspicious) |
| `bundled_binary` | Contains bundled binary files |
| `deceptive_author` | Author uses disposable email |

### Node.js (npm) Source Code Rules

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `npm-exec-base64` | Dynamically executes code through eval | T1059 |
| `npm-install-script` | Pre/post-install script runs commands | T1059 |
| `npm-serialize-environment` | Serializes process.env to exfiltrate | T1082, T1041 |
| `npm-exfiltrate-sensitive-data` | Reads and exfiltrates sensitive data | T1005, T1041 |
| `npm-obfuscation` | Common obfuscation methods | T1027 |
| `npm-silent-process-execution` | Silently executes an executable | T1059 |
| `npm-dll-hijacking` | Manipulates trusted app to load DLL | T1574.001 |
| `npm-steganography` | Hidden data in images | T1027.003 |
| `shady-links` | URLs to suspicious domains | T1071 |
| `suspicious_passwd_access_linux` | Reads /etc/passwd | T1555 |

### Node.js (npm) Metadata Rules

| Rule | Description |
|------|-------------|
| `typosquatting` | Named similar to popular package |
| `empty_information` | Empty description field |
| `release_zero` | Version 0.0 or 0.0.0 |
| `potentially_compromised_email_domain` | Email domain may be compromised |
| `unclaimed_maintainer_email_domain` | Email domain is unclaimed |
| `direct_url_dependency` | Direct URL dependencies (not immutable) |
| `npm_metadata_mismatch` | Mismatch between manifest and package info |
| `bundled_binary` | Contains bundled binaries |
| `deceptive_author` | Author uses disposable email |

## Selective Rule Scanning

```bash
# Scan with specific rules only
guarddog pypi scan /path --rules exec-base64 --rules code-execution

# Scan with all rules except one
guarddog pypi scan /path --exclude-rules repository_integrity_mismatch

# For npm
guarddog npm scan /path --rules npm-exec-base64 --rules npm-serialize-environment
```

## Workflow for Security Audit

### Priority-Based Scanning Strategy

**For URGENT/Incident Response:**
```bash
# Quick scan with JSON output for immediate triage
guarddog pypi scan ./suspicious-package --output-format=json 2>&1 | head -100

# Focus on critical malware rules only
guarddog pypi scan ./project --rules exec-base64 --rules exfiltrate-sensitive-data --rules code-execution --rules download-executable
```

**For Routine Dependency Audit:**
```bash
# Step 1: Verify all dependencies (ALWAYS DO THIS FIRST)
guarddog pypi verify ./requirements.txt
guarddog npm verify ./package-lock.json

# Step 2: Scan local project code
guarddog pypi scan ./src/
guarddog npm scan ./src/
```

**For Pre-Installation Check:**
```bash
# Before pip install <package>
guarddog pypi scan <package-name>

# Check specific version
guarddog pypi scan <package-name> --version X.Y.Z

# Before npm install <package>
guarddog npm scan <package-name>
```

### 1. Quick Local Scan

```bash
# Scan a Python project
guarddog pypi scan ./my-python-project/

# Scan a Node.js project
guarddog npm scan ./my-nodejs-project/
```

### 2. Audit Dependencies Before Use

```bash
# Check Python dependencies
guarddog pypi verify ./requirements.txt

# Check Node.js dependencies
guarddog npm verify ./package-lock.json
```

### 3. Deep Analysis with JSON Output

```bash
# Get detailed JSON report for Python
guarddog pypi scan ./project --output-format=json > python-scan.json

# Get detailed JSON report for Node.js
guarddog npm scan ./project --output-format=json > npm-scan.json
```

### 4. Debug Mode for Verbose Output

```bash
guarddog --log-level debug pypi scan ./project
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  guarddog-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install GuardDog
        run: pip install guarddog
      
      - name: Verify Python Dependencies
        run: guarddog pypi verify requirements.txt --output-format=sarif > guarddog-python.sarif
        continue-on-error: true
      
      - name: Verify npm Dependencies
        run: guarddog npm verify package-lock.json --output-format=sarif > guarddog-npm.sarif
        continue-on-error: true
      
      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guarddog-python.sarif
```

### Pre-commit Hook

```bash
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: guarddog-verify
        name: GuardDog Dependency Check
        entry: guarddog pypi verify requirements.txt
        language: system
        files: requirements\.txt$
        pass_filenames: false
```

## Interpreting Results

GuardDog outputs findings with severity levels:

- **Issues found**: Each rule match indicates a potential malicious pattern
- **Rule name**: Identifies the type of threat detected
- **Location**: File path and matched content

### Example Output

```
Scanning ./malicious-package
Found 2 potentially malicious indicators:
  - exec-base64: Identified base64-encoded code execution in setup.py
  - exfiltrate-sensitive-data: Package reads SSH keys and sends to external URL
```

## Attack Patterns Detected

GuardDog detects threats aligned with common supply chain attack vectors:

| Attack Type | Detection Coverage |
|-------------|-------------------|
| **Reverse Shells** | `code-execution`, `silent-process-execution` |
| **Data Exfiltration** | `exfiltrate-sensitive-data`, `npm-serialize-environment` |
| **Credential Theft** | `suspicious_passwd_access_linux`, `clipboard-access` |
| **Obfuscated Payloads** | `obfuscation`, `exec-base64`, `steganography` |
| **Typosquatting** | `typosquatting` metadata rule |
| **Compromised Packages** | `potentially_compromised_email_domain`, `repository_integrity_mismatch` |
| **Install-time Attacks** | `cmd-overwrite`, `npm-install-script` |


## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GUARDDOG_PARALLELISM` | Threads for parallel processing | CPU count |
| `GUARDDOG_SEMGREP_TIMEOUT` | Max seconds per file per rule | 10 |
| `GUARDDOG_SEMGREP_MAX_TARGET_BYTES` | Max file size to analyze | 10MB |
| `GUARDDOG_MAX_UNCOMPRESSED_SIZE` | Max uncompressed archive size | 2GB |

## Limitations

- GuardDog uses Semgrep rules and heuristics - some patterns may produce false positives
- Metadata checks may have false positives for npm due to API limitations
- Sophisticated obfuscation may evade detection
- Does not detect logic vulnerabilities or runtime-only behavior
- Always perform manual review for critical findings

## Combining with Other Security Tools

For comprehensive security coverage, combine GuardDog with other scanning tools:

| Tool | Use For | Command |
|------|---------|---------|
| **GuardDog** | Malicious packages, supply chain | `guarddog pypi verify requirements.txt` |
| **Bandit** | Python code vulnerabilities | `bandit -r ./src` |
| **Graudit** | Multi-language secrets/patterns | `graudit -d secrets ./` |
| **ShellCheck** | Shell script security | `shellcheck *.sh` |

### Recommended Full Audit Workflow

```bash
# 1. Check dependencies for malware (GuardDog)
guarddog pypi verify requirements.txt
guarddog npm verify package-lock.json

# 2. Scan Python code for vulnerabilities (Bandit)
bandit -r ./src -f json -o bandit-results.json

# 3. Check for hardcoded secrets (Graudit)
graudit -d secrets ./src

# 4. Audit shell scripts (ShellCheck)
find . -name "*.sh" -exec shellcheck {} \;
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `command not found: guarddog` | Run `pip install guarddog` or check PATH |
| Semgrep timeout errors | Set `GUARDDOG_SEMGREP_TIMEOUT=30` |
| Memory issues on large packages | Set `GUARDDOG_MAX_UNCOMPRESSED_SIZE=500000000` |
| Network errors on remote scans | Check internet connection; use `--log-level debug` |
| False positives | Use `--exclude-rules <rule>` to skip specific checks |

### Performance Optimization

```bash
# Increase parallelism for faster scanning
export GUARDDOG_PARALLELISM=8

# Increase timeout for complex files
export GUARDDOG_SEMGREP_TIMEOUT=30

# Limit file size for faster scans
export GUARDDOG_SEMGREP_MAX_TARGET_BYTES=5000000
```

## Additional Resources

- [Malicious Patterns Examples](./examples/malicious-patterns.md) - Example code patterns GuardDog detects
- [GuardDog GitHub Repository](https://github.com/DataDog/guarddog) - Official documentation
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Threat classification reference
