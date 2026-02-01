# ShellCheck Overview

ShellCheck is a GPLv3 static analysis tool that gives warnings and suggestions for bash/sh shell scripts. It helps identify and fix typical syntax issues, semantic problems, and subtle pitfalls that may cause scripts to fail or behave unexpectedly.

> **Agent Skill Available**: This project may include a ShellCheck Agent Skill for VS Code Copilot that automates shell script security scanning. Ask Copilot to "scan this project for shell script issues with ShellCheck" to use it.

## Scanning Capabilities

- Local Files: ShellCheck scans shell script files in local directories using AST-based analysis.
	- Command:
		```bash
		shellcheck yourscript.sh
		```
- Recursive Scanning: You can scan multiple files or directories recursively.
	- Command:
		```bash
		shellcheck myscripts/*.sh
		```
- Web-Based Scanning: Instant feedback available at [shellcheck.net](https://www.shellcheck.net/) by pasting your script.
- Shell Dialect Support: Supports different shell dialects based on shebang detection:
	- bash (#!/bin/bash)
	- sh (#!/bin/sh) - POSIX shell with portability warnings
	- dash (#!/bin/dash)
	- ksh (#!/bin/ksh)

## How it Scans

ShellCheck performs static analysis without executing the code:

- AST Analysis: Parses shell scripts into an Abstract Syntax Tree and analyzes patterns that indicate potential issues.
- Pattern Recognition: Detects common mistakes and anti-patterns across multiple categories:
	- **Quoting Issues**: Unquoted variables, incorrect tilde expansion, literal quotes in variables
	- **Conditionals**: Constant test expressions, malformed operators, unsupported syntax
	- **Command Misuse**: Incorrect usage of grep, find, sudo, exec, and other common commands
	- **Beginner Mistakes**: Variable assignment errors, positional parameter issues, function definition problems
	- **Style Issues**: Useless use of cat/echo, old-style backticks, inefficient patterns
	- **Data/Typing Errors**: Array/string confusion, printf mismatches, unassigned variables
	- **Robustness**: Catastrophic rm patterns, glob injection risks, find -exec vulnerabilities
	- **Portability**: Non-POSIX features when using #!/bin/sh shebang
	- **Miscellaneous**: Unicode quotes, DOS line endings, recursive aliases, bad character classes
- Shebang-Aware: Automatically adjusts warnings based on the shell specified in the shebang line.

> Important Note: ShellCheck is a static analysis tool that identifies potential issues without executing scripts. It's designed for use during development and code review to catch problems before deployment.

## Output Formats

ShellCheck provides multiple output formats for different use cases:

- Text output (default): Human-readable console output with or without ANSI colors
- JSON: Machine-readable format for integration with other tools
- CheckStyle XML: Compatible with CI/CD systems and code quality platforms
- GCC-compatible: Warnings in GCC error format for editor integration
- Diff format: Shows issues in unified diff format

## Installation

ShellCheck is available on virtually all platforms:

### Package Managers

```bash
# Debian/Ubuntu/Mint
sudo apt install shellcheck

# macOS with Homebrew
brew install shellcheck

# macOS with MacPorts
sudo port install shellcheck

# Arch Linux
pacman -S shellcheck

# Fedora
dnf install ShellCheck

# FreeBSD
pkg install hs-ShellCheck

# Windows with Chocolatey
choco install shellcheck

# Windows with winget
winget install --id koalaman.shellcheck

# Windows with scoop
scoop install shellcheck

# Conda
conda install -c conda-forge shellcheck

# Snap
snap install --channel=edge shellcheck
```

### From Source

Using Cabal:
```bash
cabal update
cabal install ShellCheck
```

Using Stack:
```bash
stack update
stack install ShellCheck
```

### Pre-compiled Binaries

Download pre-compiled binaries for your platform:
- Linux (x86_64, armv6hf, aarch64) - statically linked
- macOS (x86_64, aarch64)
- Windows (x86)

Available at: [GitHub Releases](https://github.com/koalaman/shellcheck/releases)

### Docker

```bash
docker run --rm -v "$PWD:/mnt" koalaman/shellcheck:stable myscript.sh
```

Or use the Alpine-based image `koalaman/shellcheck-alpine` for a base image to extend.

## Integration Options

- **CI/CD Platforms**: Pre-installed on Travis CI, GitHub Actions (Linux), CircleCI, Codacy, Code Climate, and more
- **Pre-commit Hooks**: Integrate via [pre-commit](https://pre-commit.com/) framework
	```yaml
	repos:
	-   repo: https://github.com/koalaman/shellcheck-precommit
	    rev: v0.7.2
	    hooks:
	    -   id: shellcheck
	```
- **Editor Integration**:
	- Vim: via [ALE](https://github.com/w0rp/ale), [Neomake](https://github.com/neomake/neomake), or [Syntastic](https://github.com/scrooloose/syntastic)
	- Emacs: via [Flycheck](https://github.com/flycheck/flycheck) or [Flymake](https://github.com/federicotdn/flymake-shellcheck)
	- VS Code: via [vscode-shellcheck](https://github.com/timonwong/vscode-shellcheck)
	- Sublime: via [SublimeLinter](https://github.com/SublimeLinter/SublimeLinter-shellcheck)
	- Pulsar Edit (Atom): via [linter-shellcheck-pulsar](https://github.com/pulsar-cooperative/linter-shellcheck-pulsar)
- **Build Systems**: Easily integrate into Makefiles, Travis CI configs, or custom test suites
	```makefile
	check-scripts:
		shellcheck myscripts/*.sh
	```

## Severity and Confidence

ShellCheck uses a code-based severity system:

- **Error (SC1xxx)**: Syntax errors, parsing issues
- **Warning (SC2xxx)**: Typical script problems that should be fixed
- **Info (SC3xxx)**: Minor issues, style suggestions, portability concerns
- **Style (SC4xxx)**: Stylistic recommendations

Each issue includes:
- Error code (e.g., SC2086 for unquoted variables)
- Line number and column
- Description of the issue
- Wiki link with detailed explanation and examples

## Command-Line Options

Common options:

```bash
OPTIONS
  -s shell        Specify shell dialect (sh, bash, dash, ksh)
  -e CODE1,CODE2  Exclude specific error codes
  -f FORMAT       Output format (checkstyle, diff, gcc, json, json1, quiet, tty)
  -S SEVERITY     Minimum severity (error, warning, info, style)
  -x              Follow source'd files
  -a              Include warnings for sourced files
  -C[WHEN]        Enable/disable colored output (auto, always, never)
  --norc          Don't read ~/.shellcheckrc configuration
  --color[=WHEN]  Use colored output
  --list-optional List optional checks
  --enable=CHECK  Enable optional checks
  --wiki-link-count=N  Number of wiki links to show per check
```

## Ignoring Issues

Issues can be ignored in multiple ways:

1. **Inline Directives**: Add comments to ignore specific warnings
	```bash
	# shellcheck disable=SC2086
	echo $var
	```

2. **File-Level Directives**: Disable checks for entire file
	```bash
	# shellcheck disable=SC2148
	```

3. **Configuration File**: Create `~/.shellcheckrc` or `.shellcheckrc`
	```bash
	disable=SC2086,SC2034
	```

4. **Command Line**: Use `-e` flag
	```bash
	shellcheck -e SC2086,SC2034 script.sh
	```

## License

ShellCheck is open-source software licensed under the GNU General Public License v3 (GPLv3), making it free to use for both private and commercial projects.

## Resources

- Repository: https://github.com/koalaman/shellcheck
- Website: https://www.shellcheck.net
- Wiki: https://github.com/koalaman/shellcheck/wiki
- Issue Tracker: https://github.com/koalaman/shellcheck/issues
- Wiki Checks: Long-form descriptions for each warning at https://github.com/koalaman/shellcheck/wiki/Checks
- Author: Vidar 'koala_man' Holen ([@koalaman](https://github.com/koalaman))

## Related Tools

- [shfmt](https://github.com/mvdan/sh): Shell script formatter (ShellCheck focuses on correctness, not formatting)
