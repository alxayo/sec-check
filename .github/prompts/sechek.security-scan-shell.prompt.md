---
name: sechek.shell-security-scan
description: Shell script security scan using shellcheck and graudit
agent: sechek.security-scanner
model: Claude Sonnet 4.5
---

# Shell Script Security Scan

Scan all shell scripts (`.sh`, `.bash`, `.zsh`) for security issues.

## Tools to Execute

1. Run shellcheck on all shell files
2. Run graudit with exec and secrets signatures

## Patterns to Detect

- Command injection vulnerabilities
- Unquoted variables
- `curl | bash` patterns (pipe to shell)
- Hardcoded credentials or IPs
- Reverse shell patterns (`/dev/tcp`)
- Unsafe use of `eval`
- World-writable file permissions

Save findings to `.github/.audit/scan-results.md`
