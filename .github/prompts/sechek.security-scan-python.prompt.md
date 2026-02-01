---
name: sechek.python-security-scan
description: Python-focused security scan using bandit and guarddog
agent: sechek.security-scanner
model: Claude Sonnet 4.5
---

# Python Security Scan

Run a Python-focused security scan on this workspace.

## Tools to Execute

1. Execute bandit with full rules: `bandit -r . -f json`
2. Check for guarddog Python package issues

## Patterns to Detect

- `eval()`, `exec()`, `compile()` usage
- `subprocess` with `shell=True`
- `pickle` deserialization (unsafe loading)
- Hardcoded credentials
- Unsafe YAML/XML loading (`yaml.load()` without `Loader`)
- SQL injection vulnerabilities
- Path traversal risks

Save results to `.github/.audit/scan-results.md`
