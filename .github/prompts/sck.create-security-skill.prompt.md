---
name: sck.skill-create-security
description: Create a VS Code Agent Skill for a security scanning tool
argument-hint: "Provide tool name and documentation URL (e.g., 'bandit https://github.com/PyCQA/bandit')"
agent: agent
tools: ['read/problems', 'read/readFile', 'search/codebase', 'search/fileSearch', 'search/textSearch', 'search/usages', 'search/listDirectory', 'todo', 'agent', 'execute', 'edit', 'search']
---

# Create Security Tool Agent Skill

You are an expert in writing VS Code Agent Skills following the official specification at https://code.visualstudio.com/docs/copilot/customization/agent-skills

## Task

Create a complete Agent Skill for scannning code for security vulnerabilities or malicious patterns using the following security tool:

**Tool Name:** ${input:toolName:Enter the security tool name (e.g., bandit, semgrep, trivy)}
**Documentation URL:** ${input:docUrl:Enter the tool's documentation URL (e.g., https://github.com/org/tool)}

## Instructions

1. **Fetch Documentation**: Use the fetch_webpage tool to retrieve the official documentation from the provided URL. Extract:
   - Installation commands
   - CLI usage and command syntax
   - Available rules/checks/heuristics
   - Output formats (JSON, SARIF, etc.)
   - Configuration options

2. **Review Existing Skills**: Read these reference files to understand the established format:
   - [GuardDog Skill Example](.github/skills/guarddog-security-scan/SKILL.md)
   - [Graudit Skill Example](.github/skills/graudit-security-scan/SKILL.md)
   - [Attack Vectors Context](.github/.context/attack-vectors-general.md)

3. **Create Skill Structure**: Generate files in `.github/skills/<tool-name>-security-scan/`:

### SKILL.md (Required)

Must include YAML frontmatter:
```yaml
---
name: <tool-name>-security-scan
description: <Concise description of tool capabilities and when to use. Max 1024 chars. Include keywords: scan, security, vulnerabilities, malicious, detect>
---
```

Body must contain:
- **When to Use This Skill** - Trigger conditions for Copilot
- **Prerequisites** - Installation commands (pip, npm, brew, docker)
- **Core Commands** - Essential scanning commands with examples
- **Available Rules/Checks** - Table of detection capabilities, mapped to MITRE ATT&CK where applicable
- **Workflow** - Step-by-step scanning procedure
- **Interpreting Results** - How to read output
- **Limitations** - False positives, scope limitations

### examples/malicious-patterns.md (Recommended)

Include code samples showing patterns the tool detects:
- Dangerous function calls
- Obfuscation techniques
- Data exfiltration patterns
- Credential theft
- Command injection

### README.md (Required)

Brief overview with:
- What the skill does
- Requirements
- Example prompts users can ask
- Example CLI commands
- File structure

## Quality Checklist

Before completing, verify:

- [ ] SKILL.md has valid YAML frontmatter with `name` and `description`
- [ ] `name` is lowercase with hyphens, max 64 characters
- [ ] `description` explains both capabilities AND when to use it
- [ ] Installation instructions work on macOS/Linux
- [ ] Commands are tested and accurate
- [ ] Rules/checks table is comprehensive
- [ ] MITRE ATT&CK mappings included where relevant
- [ ] Examples show real detection patterns
- [ ] Limitations are honestly documented

## Output Format

Create the skill files and provide a summary:

```
Created Agent Skill: <tool-name>-security-scan

Files:
- .github/skills/<tool-name>-security-scan/SKILL.md
- .github/skills/<tool-name>-security-scan/README.md  
- .github/skills/<tool-name>-security-scan/examples/malicious-patterns.md

Usage: Ask Copilot to "scan this code for <threat-type>" or "check for <vulnerability-type>"
```
