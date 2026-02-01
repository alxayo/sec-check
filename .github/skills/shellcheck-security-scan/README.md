# ShellCheck Security Scan Skill

A VS Code Copilot Agent Skill for scanning shell scripts using ShellCheck static analysis.

## Overview

This skill enables GitHub Copilot to scan bash, sh, dash, and ksh scripts for:
- Security vulnerabilities (command injection, path traversal)
- Dangerous unquoted variable expansions
- Unsafe command patterns
- Potential malicious obfuscation
- Shell scripting bugs and errors

## Requirements

- ShellCheck installed (`brew install shellcheck` on macOS)
- Shell scripts to analyze (.sh, .bash, or scripts with shell shebang)

## Example Prompts

Ask Copilot:
- "Scan this shell script for security vulnerabilities"
- "Check install.sh for command injection risks"
- "Analyze the build scripts for unsafe patterns"
- "Review this bash script for unquoted variable issues"
- "Find security bugs in the CI pipeline scripts"
- "Check if this shell script has any dangerous patterns"

## Example Commands

```bash
# Basic scan
shellcheck script.sh

# Security-focused scan with JSON output
shellcheck --severity=warning --enable=all --format=json script.sh

# Scan all shell scripts in project
find . -name "*.sh" -exec shellcheck {} +

# Generate SARIF report
shellcheck --format=sarif --enable=all script.sh > results.sarif
```

## File Structure

```
.github/skills/shellcheck-security-scan/
├── SKILL.md                          # Main skill definition
├── README.md                         # This file
└── examples/
    └── malicious-patterns.md         # Detection examples
```

## References

- [ShellCheck GitHub](https://github.com/koalaman/shellcheck)
- [ShellCheck Wiki](https://github.com/koalaman/shellcheck/wiki)
- [ShellCheck Error Codes](https://www.shellcheck.net/wiki/)
