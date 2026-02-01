# Graudit Overview

Graudit is a simple script and signature sets that allows you to find potential security flaws in source code using the GNU utility grep. It's comparable to other static analysis applications like RATS, SWAAT and flaw-finder while keeping the technical requirements to a minimum and being very flexible.

> **Agent Skill Available**: This project includes a [Graudit Agent Skill](../../.github/skills/graudit-security-scan/SKILL.md) for VS Code Copilot that automates security scanning. Ask Copilot to "scan this project for security vulnerabilities with Graudit" to use it.

## Scanning Capabilities

- Local Files: Graudit scans source code files in local directories using grep-based pattern matching.
	- Command:
		```bash
		graudit /path/to/your/code
		```
- Single Files: You can scan individual files for quick security checks.
	- Command:
		```bash
		graudit file.php
		```
- Database Selection: Supports multiple signature databases for different languages and vulnerability types.
	- Command:
		```bash
		graudit -d php /path/to/code
		```
- File Filtering: Can exclude specific file types or patterns from scanning.
	- Command:
		```bash
		graudit -x "*.js,*.sql" /path/to/code
		```

## How it Scans

Graudit performs static analysis using grep and regular expressions:

- Pattern Matching: Uses extended regular expressions (POSIX) to identify security vulnerabilities in source code without execution.
- Signature Databases: Comes with pre-built databases for multiple languages and vulnerability types:
	- Language-specific: actionscript, android, asp, c, cobol, dotnet, go, java, js, nim, perl, php, python, ruby, scala, typescript
	- Vulnerability-specific: exec (command execution), secrets (hardcoded credentials), sql (SQL injection), xss (cross-site scripting), spsqli (stored procedures)
	- Other: default, eiffel, fruit, ios, strings
- Flexible Configuration: Supports case-insensitive scanning, context lines, and custom database locations via environment variables.

> Important Note: Graudit is a lightweight static analysis tool that relies on grep pattern matching. It's designed to quickly identify potential security issues during development and code review stages without requiring complex dependencies.

## Output Formats

Graudit provides configurable output options:

- Standard text output (default): Console output with file paths and matching lines
- Context lines: Display surrounding code with `-c <num>` option
- Vim-friendly format: Use `-L` for editor integration
- Color options:
	- Default colored output
	- Color blind friendly template (`-b`)
	- Suppress colors (`-z`)
	- High contrast colors (`-Z`)
- Banner suppression: Use `-B` to hide the banner for cleaner output in scripts

## Installation

### Via Git Clone (Recommended)

Cloning the repository is recommended as it includes additional database rules not available in distribution files and enables updates between releases:

```bash
git clone https://github.com/wireghoul/graudit
```

Add graudit to your path:

```bash
echo 'PATH="$HOME/graudit:${PATH:+:${PATH}}"; export PATH;' >> ~/.bashrc
```

Set the GRDIR environment variable if graudit is not in your home directory:

```bash
export GRDIR=/path/to/graudit/signatures
```

### Via Make Install

Installation can be done as a user or globally as root:

```bash
# User installation
make userinstall

# Global installation (requires root)
sudo make install
```

## Database Configuration

Graudit loads databases from multiple locations in order of precedence:

1. Custom location via GRDIR environment variable
2. `/usr/share/graudit/`
3. `$HOME/.graudit/`
4. Relative `signatures/` directory from graudit location
5. Relative `misc/` directory from graudit location
6. `$HOME/graudit/signatures/`
7. Full path specification: `/home/user/my.db`
8. Rules from stdin: `-` or `/dev/stdin`

List available databases:

```bash
graudit -l
```

## Integration Options

- Shell scripts: Set default options via GRARGS environment variable
- CI/CD pipelines: Integrate into build processes with exit codes and grep output
- IDE integration: Vim-friendly output mode with `-L` flag
- Custom rules: Create your own signature databases using extended regular expressions
- Script automation: Banner suppression and color control for automated scanning

## Command-Line Options

```bash
OPTIONS
  -d <dbname>  database to use or /path/to/file.db (uses default if not specified)
  -A           scan unwanted and difficult (ALL) files
  -x           exclude these files (comma separated list: -x *.js,*.sql)
  -i           case in-sensitive scan
  -c <num>     number of lines of context to display, default is 1
  -B           suppress banner
  -L           vim friendly lines
  -b           colour blind friendly template
  -z           suppress colors
  -Z           high contrast colors
  -l           lists databases available
  -v           prints version number
  -h           prints help screen
```

Set default options via environment variable:

```bash
echo 'GRARGS="-b -L"; export GRARGS' >> ~/.bashrc
```

## License

Graudit is open-source software licensed under GPL-3.0 License, making it free to use for both private and commercial projects.

## Resources

- Repository: https://github.com/wireghoul/graudit
- Tutorial Video: https://youtu.be/b8Xbzer1n94
- Author: Wireghoul (@wireghoul)
