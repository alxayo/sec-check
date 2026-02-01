# GuardDog Overview

GuardDog can perform both tasks: it can scan locally stored files and also fetch and scan packages from remote artifact repositories like PyPI.org or npmjs.org.

> **Agent Skill Available**: This project includes a [GuardDog Agent Skill](.github/skills/guarddog-security-scan/SKILL.md) for VS Code Copilot that automates malicious code scanning. Ask Copilot to "scan this project for malicious code" to use it.

## Scanning Capabilities

- Remote Repositories: By default, GuardDog can fetch the latest (or specific) versions of packages directly from public registries.
	- Command:
		```
		guarddog pypi scan <package_name>
		```
- Local Files: It can scan local source code archives (like .tar.gz files) or local directories that contain package source files.
	- Command:
		```
		guarddog pypi scan /path/to/local/package.tar.gz
		```
- Manifest Files: You can also point it at a local requirements.txt file; it will then identify each dependency listed and scan them by fetching their data from the remote repository.

## How it Scans

When scanning, GuardDog analyzes two primary areas to identify malicious intent:

- Source Code: It uses Semgrep rules to find dangerous patterns like silent process execution, reverse shells, or exfiltration of environment variables.
- Package Metadata: It checks remote repository data for suspicious markers such as typosquatting (e.g., "reuqests" vs "requests"), missing documentation, or maintainer accounts that may have been compromised.

> Important Note: GuardDog is primarily designed for pre-install verification. It helps you decide if a package is safe before you run pip install on your local system.

## Node.js (npm) Support

GuardDog (developed by Datadog) fully supports the Node.js (npm) ecosystem.
It identifies malicious JavaScript code and risky metadata patterns in npm packages using the same approach it takes with Python packages.

### Key Node.js Features

- Scanning npm Packages: You can scan individual packages directly from the npm registry.
	- Command:
		```
		guarddog npm scan <package_name>
		```
- Manifest Scanning: You can verify an entire project by scanning the dependencies listed in your package.json file.
	- Command:
		```
		guarddog npm verify package.json
		```
- Node-Specific Heuristics: It includes specialized rules for JavaScript, such as detecting:
	- npm-serialize-environment: Flagging attempts to exfiltrate process.env data.
	- npm-install-script: Identifying packages that use preinstall or postinstall scripts to run commands automatically.
	- npm-silent-process-execution: Catching hidden background processes.

## Semgrep and GuardDog

Semgrep is partially open-source, and it is a critical component used inside GuardDog.

### Is Semgrep free and open-source?

Semgrep follows an "open core" model, meaning it is split into free and paid parts:

- The Engine (Open Source): The core Semgrep scanning engine is open-source and licensed under LGPL 2.1. You can use this for free on private or proprietary code without issue.
- The Rules (Mixed Licensing):
	- Community Rules: Many rules are free to use and modify for internal purposes.
	- Pro Rules: Certain advanced rules maintained by Semgrep, Inc. require a paid license and are not open-source.
- The Platform (Commercial): Advanced features like "inter-file analysis" (scanning how data moves between different files) and the cloud-based dashboard are part of the paid Semgrep AppSec Platform.

### Is Semgrep part of GuardDog?

Yes, GuardDog uses Semgrep as its internal analysis engine.

- Under the Hood: When you run GuardDog, it automatically calls Semgrep to scan the source code of Python or npm packages.
- Rule Engine: GuardDog uses Semgrep rules (written in YAML) to detect malicious patterns like "exfiltrating environment variables" or "silent process execution".
- Installation: When you install GuardDog via pip, it typically installs the semgrep package as a required dependency.

In short: GuardDog is a specialized tool for detecting malware, and it relies on Semgrep's open-source engine to do the heavy lifting of code analysis.

## Resources

- Repository: https://github.com/DataDog/guarddog