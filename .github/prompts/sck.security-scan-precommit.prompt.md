---
name: sck.precommit-security-scan
description: Pre-commit security check for secrets, malicious patterns, and vulnerabilities
agent: sck.security-scanner
model: Claude Sonnet 4.5
---

# Pre-Commit Security Check

Scan all code in this workspace for security issues before commit.

## Check For

1. **Accidentally committed secrets**
   - API keys and tokens
   - Passwords and credentials
   - Private keys (SSH, GPG, etc.)

2. **Malicious patterns**
   - Reverse shells
   - Data exfiltration
   - Backdoors

3. **Security vulnerabilities**
   - Injection risks
   - Unsafe deserialization
   - Command execution flaws

## Reporting

- Report any **CRITICAL** or **HIGH** severity findings immediately
- Save full results to `.github/.audit/scan-results.md`
