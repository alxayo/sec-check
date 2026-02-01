---
name: sechek.quick-security-scan
description: Quick security scan for malicious patterns, exfiltration, and reverse shells
agent: sechek.security-scanner
model: Claude Sonnet 4.5
---

# Quick Security Scan

Run a security scan on this workspace. Check for:

- Malicious code patterns
- Data exfiltration attempts
- Reverse shells and backdoors
- Suspicious obfuscated code

Save results to `.github/.audit/scan-results.md`
