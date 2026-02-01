---
name: sck.scan-security
description: Run a comprehensive malicious code scan on the workspace using the sec-check security scanner agent
agent: sck.security-scanner
model: Claude Sonnet 4.5
argument-hint: "[path] or leave empty for full workspace scan"
tools: ['read/problems', 'read/readFile', 'search/codebase', 'search/fileSearch', 'search/textSearch', 'search/usages', 'search/listDirectory', 'todo', 'agent', 'execute', 'edit', 'search']
---

# Security Scan Request

Perform a comprehensive malicious code scan on this workspace: ${input:scanTarget:path or "." for full workspace}

Execute the full startup sequence and scanning workflow as defined in your agent instructions.

## 1. Environment Setup

- Check for available security skills in `.github/skills/`
- Verify which scanning tools are installed (bandit, guarddog, shellcheck, graudit)
- Report your operating mode (Skills-Enhanced or Standalone)

## 2. Full Workspace Scan

Scan ALL code files for:

- **Data Exfiltration**: Secret theft, credential harvesting, environment variable leaks
- **Reverse Shells & Backdoors**: Network connections to external IPs, socket operations
- **Persistence Mechanisms**: Cron jobs, registry modifications, startup scripts
- **Obfuscated Payloads**: Base64 encoded commands, eval/exec patterns, encoded strings
- **System Destruction**: Recursive deletions, shadow copy removal, ransomware patterns
- **Supply Chain Risks**: Suspicious dependencies, typosquatting packages

## 3. Language Coverage

Analyze all detected languages including:

- Python (.py)
- JavaScript/Node.js (.js, .mjs, .cjs)
- Shell scripts (.sh, .bash, .zsh)
- PowerShell (.ps1, .psm1)
- Any other executable code

## 4. Output Requirements

- Save tool scan results to `.github/.audit/tools-audit.md` (if tools available)
- Save final analysis to `.github/.audit/scan-results.md`
- Include severity scores, MITRE ATT&CK mappings, and remediation steps
- Provide an executive summary with risk assessment

## 5. Priority Focus

Flag with highest priority:

1. Secret exfiltration patterns
2. Backdoors and reverse shells
3. Code obfuscation
4. Persistence mechanisms
5. Unusual network activity
6. Suspicious file operations
7. Any code accessing sensitive paths (~/.ssh, ~/.aws, .env files)
8. Network calls to hardcoded IPs or suspicious domains
9. Dynamic code execution (eval, exec, Function constructor)
10. Encoded/obfuscated command strings
11. Process spawning with shell=True or piped commands


## Analysis Depth

- Examine all code files in the directory recursively
- Check for patterns that don't match the project's normal context
- Correlate multiple suspicious patterns (e.g., secret access + network call)

Begin the scan now.