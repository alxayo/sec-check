# Graudit Security Scan Skill

## What this skill is about
This skill uses **graudit**, a grep-based source code auditing tool, to scan code for patterns that may indicate security vulnerabilities or malicious behavior.

## What the original application (graudit) does
Graudit searches source files using signature databases (regex patterns). It reports lines that match known risky patterns such as command execution, SQL injection, XSS, hardcoded secrets, and other dangerous constructs.

## When it is applicable
Use this skill when you need a quick static security scan, for example:
- Auditing a codebase for risky patterns
- Checking for malicious or suspicious code snippets
- Reviewing scripts or applications for common vulnerability signatures

## Supported programming languages
This skill supports graudit signature databases for:
- C/C++
- Go
- Java
- JavaScript
- .NET/C#
- Perl
- PHP
- Python
- Ruby
- SQL
- TypeScript

## How to use it
1. Ensure graudit is installed and on your PATH.
2. Run graudit on a file or directory:
   - `graudit /path/to/scan`
3. For language-specific scans, choose a database:
   - `graudit -d python /path/to/project`
   - `graudit -d js /path/to/project`
4. Review the matches; each hit is a **potential** issue and requires manual validation.

For detailed instructions and advanced options, see [SKILL.md](SKILL.md).
