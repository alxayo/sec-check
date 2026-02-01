# Bandit Overview

Bandit is a security linter designed to find common security issues in Python code by analyzing the Abstract Syntax Tree (AST) of Python files. It's maintained by the Python Code Quality Authority (PyCQA).

> **Agent Skill Available**: This project includes a [Bandit Agent Skill](../../.github/skills/bandit-security-scan/SKILL.md) for VS Code Copilot that automates security scanning. Ask Copilot to "scan this project for security issues with Bandit" to use it.

## Scanning Capabilities

- Local Files: Bandit scans Python source code files in local directories.
	- Command:
		```bash
		bandit -r /path/to/your/code
		```
- Single Files: You can scan individual Python files for quick security checks.
	- Command:
		```bash
		bandit file.py
		```
- Configuration Files: Supports `.bandit` configuration files and command-line options to customize scanning behavior, exclude paths, or skip specific tests.

## How it Scans

Bandit performs static analysis by processing Python source code:

- AST Analysis: It builds an Abstract Syntax Tree from each Python file and runs security-focused plugins against the AST nodes.
- Plugin-Based Detection: Each security check is implemented as a plugin that identifies specific vulnerability patterns such as:
	- Hardcoded passwords and secrets
	- SQL injection vulnerabilities
	- Shell injection risks
	- Insecure deserialization (pickle, yaml, etc.)
	- Use of weak cryptographic methods
	- Dangerous function calls (eval, exec, etc.)
	- Insecure temporary file creation
	- HTTP connections without SSL/TLS

> Important Note: Bandit is a static analysis tool that scans code without executing it. It helps identify potential security issues during development and code review stages.

## Output Formats

Bandit can generate reports in multiple formats:

- Text output (default): Human-readable console output
- JSON: Machine-readable format for integration with other tools
- CSV: Spreadsheet-compatible format
- HTML: Browser-viewable reports
- XML: Compatible with CI/CD systems

## Installation

Install Bandit via pip:

```bash
pip install bandit
```

Or use it as a container:

```bash
docker pull ghcr.io/pycqa/bandit/bandit
```

## Integration Options

- Pre-commit hooks: Automatically scan code before commits
- CI/CD pipelines: Integrate into GitHub Actions, GitLab CI, Jenkins, etc.
- IDE Integration: Works with VS Code, PyCharm, and other editors
- Custom configurations: Use `.bandit` files or `pyproject.toml` to configure behavior

## Severity Levels

Bandit classifies issues by severity and confidence:

- Severity: LOW, MEDIUM, HIGH
- Confidence: LOW, MEDIUM, HIGH

This helps prioritize which issues to address first.

## Resources

- Repository: https://github.com/PyCQA/bandit

## License

Bandit is open-source software licensed under Apache License 2.0, making it free to use for both private and commercial projects.
