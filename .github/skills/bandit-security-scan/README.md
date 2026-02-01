# Bandit Security Scan Skill

A VS Code Agent Skill for scanning Python code using Bandit, a security-focused static analysis tool.

## What This Skill Does

This skill enables GitHub Copilot to help you:
- Scan Python projects for security vulnerabilities
- Detect hardcoded credentials and secrets
- Find dangerous function calls (eval, exec, pickle)
- Identify SQL and command injection risks
- Check for weak cryptographic practices
- Review code for OWASP Top 10 Python vulnerabilities

## Requirements

- Python 3.8+
- Bandit (`pip install bandit`)

## Example Prompts

Ask Copilot:
- "Scan this Python project for security vulnerabilities"
- "Check this code for hardcoded passwords"
- "Find any dangerous function calls in my Python files"
- "Run a security audit on this Flask application"
- "Check for SQL injection vulnerabilities"
- "Scan for insecure deserialization"
- "Find any uses of eval or exec"

## Example Commands

```bash
# Basic recursive scan
bandit -r .

# High severity only with JSON output
bandit -r . -lll -f json -o results.json

# Check for specific vulnerabilities
bandit -r . -t B602,B608  # Shell and SQL injection

# Skip test directories
bandit -r . --exclude "*/tests/*"
```

## File Structure

```
.github/skills/bandit-security-scan/
├── SKILL.md                          # Main skill definition
├── README.md                         # This file
└── examples/
    └── malicious-patterns.md         # Detection pattern examples
```

## Related Tools

- **pip-audit**: Check for vulnerable dependencies
- **safety**: Another dependency vulnerability scanner
- **semgrep**: Multi-language static analysis
- **GuardDog**: PyPI package malware detection
