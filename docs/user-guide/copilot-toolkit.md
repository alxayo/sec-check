---
title: Copilot Toolkit
layout: default
parent: User Guide
nav_order: 2
description: "Guide to using Sec-Check's agent, skills, and prompts inside GitHub Copilot Chat."
---

# VS Code Copilot Toolkit
{: .no_toc }

Use the custom agent, security skills, and prompt commands directly in GitHub Copilot Chat.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## Overview

The Copilot Toolkit is a collection of files in the `.github/` directory that teach GitHub Copilot how to perform security scanning. When the repo is open in VS Code, Copilot automatically discovers:

- **1 Custom Agent** — deep security analysis with pattern detection
- **8 Security Skills** — each wraps a specific security scanner tool
- **12 Custom Prompts** — pre-built commands for common scanning workflows

No installation required — just open the repo in VS Code with Copilot enabled.

---

## Custom Agent

### `@sechek.security-scanner`

The **Malicious Code Scanner Agent** performs deep security analysis with pattern detection and remediation guidance.

**How to invoke:** In Copilot Chat, type:

```
@sechek.security-scanner Analyze this workspace for security issues
```

**What it detects:**
- Data exfiltration and credential theft
- Reverse shells and backdoors
- Persistence mechanisms (cron, registry)
- Obfuscated payloads (base64, eval)
- System destruction patterns

The agent can operate **standalone** (using only LLM pattern recognition) or **tool-enhanced** (using the security scanning skills listed below when they are available on the system).

---

## Security Skills

Skills teach Copilot how to invoke specific security tools. Each skill is a markdown file in `.github/skills/` that describes tool installation, usage, and output interpretation.

| Skill | Scanner | Languages / Targets |
|:------|:--------|:--------------------|
| `bandit-security-scan` | [Bandit](https://bandit.readthedocs.io/) | Python — AST analysis for dangerous functions, SQL injection, deserialization |
| `checkov-security-scan` | [Checkov](https://www.checkov.io/) | IaC — Terraform, CloudFormation, K8s manifests, Dockerfiles, Helm |
| `dependency-check-security-scan` | [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | SCA — Java, .NET, JS, Python, Ruby, Go dependencies |
| `eslint-security-scan` | [ESLint](https://eslint.org/) + security plugins | JavaScript / TypeScript — XSS, injection, ReDoS, prototype pollution |
| `guarddog-security-scan` | [GuardDog](https://github.com/DataDog/guarddog) | Supply chain — PyPI & npm malicious package detection |
| `shellcheck-security-scan` | [ShellCheck](https://www.shellcheck.net/) | Shell scripts — command injection, unquoted variables |
| `graudit-security-scan` | [Graudit](https://github.com/wireghoul/graudit) | Multi-language — pattern matching across 15+ languages, secrets detection |
| `trivy-security-scan` | [Trivy](https://trivy.dev/) | Containers, IaC, CVEs, secrets, SBOM — filesystem and image scanning |

{: .note }
> Skills are optional enhancers. If a scanner tool isn't installed on your system, the agent will simply skip that skill and use other available scanners.

---

## Custom Prompts

Prompts are pre-built commands you type in Copilot Chat. They appear as `/sechek.*` commands.

### Scanning Prompts

| Command | Description |
|:--------|:------------|
| `/sechek.security-scan` | Full workspace scan with the security scanner agent |
| `/sechek.security-scan-quick` | Fast scan for malicious patterns, exfiltration, reverse shells |
| `/sechek.security-scan-python` | Python-focused scan using Bandit and GuardDog |
| `/sechek.security-scan-iac` | Infrastructure as Code scan using Checkov |
| `/sechek.security-scan-shell` | Shell script scan using ShellCheck and Graudit |
| `/sechek.security-scan-supply-chain` | Scan dependencies for supply chain attacks |
| `/sechek.security-scan-precommit` | Pre-commit check for secrets and vulnerabilities |

### Tool Management Prompts

| Command | Description |
|:--------|:------------|
| `/sechek.tools-advisor` | Get recommendations on which tools to run based on your codebase |
| `/sechek.tools-scan` | Execute security tools and save results to `tools-audit.md` |

### Remediation Prompts

| Command | Description |
|:--------|:------------|
| `/sechek.plan-fix` | Generate a prioritized remediation plan from scan results |

### Development Prompts

| Command | Description |
|:--------|:------------|
| `/create-security-skill` | Create a new security scanning skill from tool documentation |

---

## Recommended Workflows

### Full Security Audit

```
1. /sechek.tools-advisor              → See which tools are relevant
2. /sechek.tools-scan ./src           → Run all recommended tools
3. @sechek.security-scanner           → Deep LLM analysis of results
4. /sechek.plan-fix                   → Get prioritized remediation plan
```

### Quick Pre-Commit Check

```
/sechek.security-scan-precommit
```

### Language-Specific Scan

```
# Python project
/sechek.security-scan-python

# Shell scripts
/sechek.security-scan-shell

# Infrastructure as Code
/sechek.security-scan-iac

# Dependencies
/sechek.security-scan-supply-chain
```

---

## Output Files

Scans generate Markdown reports saved in your workspace:

| File | Generated By | Contents |
|:-----|:-------------|:---------|
| `.github/.audit/tools-audit.md` | `/sechek.tools-scan` | Raw tool output from all scanners |
| `.github/.audit/scan-results.md` | `@sechek.security-scanner` | Analysis with findings & remediation |
| `.github/.audit/remediation-tasks.md` | `/sechek.plan-fix` | Prioritized fix plan with SLAs |

---

## Remediation Planning

After running scans, use `/sechek.plan-fix` to generate a detailed remediation plan:

The plan includes:
- **Prioritized tasks** grouped by severity (Critical → High → Medium → Low)
- **SLA timelines** (24 hours for Critical, 1 week for High, etc.)
- **Fix patterns** with vulnerable vs. secure code examples
- **Parallel execution opportunities** to speed up remediation
- **Verification commands** to confirm fixes
