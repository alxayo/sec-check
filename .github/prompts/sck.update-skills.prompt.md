---
name: add-new-security-skill
description: Template prompt for integrating a new security scanning skill into the tools-advisor and malicious-code-scanner systems
argument-hint: "Provide tool name and of the new skill (e.g., 'checkov')"
agent: agent
tools: ['read/problems', 'read/readFile', 'search/codebase', 'search/fileSearch', 'search/textSearch', 'search/usages', 'search/listDirectory', 'todo', 'edit', 'search']
model: Claude Sonnet 4.5
---

# Adding a New Security Scanning Skill

Use this prompt template when adding a new security scanning skill to ensure it's properly integrated into both the tools-advisor and malicious-code-scanner agent.

## Prerequisites

Before starting, ensure you have:
- [ ] Created the skill in `.github/skills/<skill-name>/SKILL.md`
- [ ] Created the skill README in `.github/skills/<skill-name>/README.md`
- [ ] The skill includes: description, detection capabilities, supported languages/frameworks, MITRE ATT&CK mappings (if applicable)
- [ ] Command examples for using the skill's tool

## Information Gathering Template

Copy this template and fill it out with information from your new skill:

```markdown
## New Skill Information

### Basic Details
- **Skill ID**: `[e.g., checkov-security-scan]`
- **Skill Name**: [e.g., Checkov Security Scan]
- **Tool Command**: [e.g., checkov]
- **Skill File Path**: `.github/skills/[skill-name]/SKILL.md`

### Purpose & Scope
- **Primary Purpose**: [What does this skill scan/detect? e.g., Infrastructure as Code security]
- **Target Type**: [Code/Dependencies/Infrastructure/CI-CD/Other]
- **Best For**: [When should this be the primary tool?]
- **NOT For**: [What should this tool NOT be used for?]

### Supported Formats
- **Languages**: [e.g., Python, JavaScript, or N/A]
- **Frameworks**: [e.g., Terraform, Kubernetes, Django, or N/A]
- **File Types**: [e.g., .tf, .yaml, Dockerfile, etc.]

### Detection Capabilities
List what this skill detects (3-8 bullet points):
- [Capability 1]
- [Capability 2]
- [Capability 3]
- ...

### MITRE ATT&CK Mappings (if applicable)
- [T1234: Technique Name]
- [T5678: Another Technique]
- ...

### Tool Commands
Provide 5-10 example commands for common use cases:

```bash
# Basic scan
[command example]

# Scan specific framework
[command example]

# Output in JSON
[command example]

# CI/CD integration
[command example]

# Advanced usage
[command example]
```

### Tool Installation
```bash
# How to install the tool
[installation command]

# How to verify installation
[verification command]
```

### Key Distinction
How does this tool differ from existing tools?
[e.g., "Checkov scans infrastructure configuration for misconfigurations; other tools scan application code for vulnerabilities"]
```

---

## Prompt for Copilot

Once you've filled out the template above, use this prompt:

```
I need to integrate a new security scanning skill into the security scanning system. Please update both:
1. .github/prompts/sck.tools-advisor.prompt.md
2. .github/agents/sck.malicious-code-scanner.agent.md

Here's the skill information:

[PASTE YOUR FILLED TEMPLATE HERE]

Please update the following sections in both files:

### For sck.tools-advisor.prompt.md:
1. Add new skill entry (Section X) in "Available Security Scanning Skills"
2. Update the "Quick Decision Flowchart" to include decision paths for this skill
3. Add entries to the "Decision Matrix" table
4. Update "Conflict Resolution Rules" if this skill has priority considerations
5. Add to "Risk-Based Priority Matrix" if applicable
6. Update "Step 1: Identify Code Composition" with new file types to detect
7. Update "Step 2: Assess Risk Profile" with new risk areas
8. Add command examples to "Tool-Specific Command Hints"
9. Add to "Tool Limitations" table
10. Update "Anti-Patterns" table if there are common misuses

### For sck.malicious-code-scanner.agent.md:
1. Add to "Operating Modes - Skills Table"
2. Add to "Allowed Terminal Commands ONLY" section
3. Add to "Step 2: Detect Available Tools" version check
4. Add entries to "Tool Execution Priority" table
5. Add to "Phase 3: Recommended Static Analysis Tools" table
6. Update "Scan Configuration" template (Skills Detected table)
7. Add to "Skill File Locations" quick reference table

Use the same format and style as the existing Checkov integration for consistency.
```

---

## Verification Checklist

After integration, verify these updates were made:

### In sck.tools-advisor.prompt.md:
- [ ] New skill listed with full description (skill ID, purpose, capabilities, detection list)
- [ ] Decision flowchart includes new file types/use cases
- [ ] Decision matrix has entries for all relevant code types
- [ ] Conflict resolution rules mention the skill where applicable
- [ ] Risk-based priority matrix updated if relevant
- [ ] File identification section lists file types to detect
- [ ] Risk profile assessment includes related risk areas
- [ ] Command hints section has 5+ example commands
- [ ] Tool limitations documented
- [ ] Anti-patterns table updated if applicable

### In sck.malicious-code-scanner.agent.md:
- [ ] Skill appears in Operating Modes table
- [ ] Tool command whitelisted in "Allowed Terminal Commands"
- [ ] Version check command added to tool detection
- [ ] Tool execution priority table has entries for supported file types
- [ ] Static analysis tools table updated with capabilities
- [ ] Scan configuration template includes the skill
- [ ] Skill file location added to quick reference

### Testing:
- [ ] Ask tools-advisor to analyze a project with files the new skill should detect
- [ ] Verify tools-advisor recommends the new skill
- [ ] Verify malicious-code-scanner agent mentions the skill when appropriate
- [ ] Check that command examples are correct and executable

---

## Example: Adding Checkov (Reference)

Here's an example of how Checkov was integrated:

### In sck.tools-advisor.prompt.md:

**Section Added**: "6. Checkov Security Scan" in Available Security Scanning Skills
```markdown
### 6. Checkov Security Scan
- **Skill**: `checkov-security-scan`
- **Skill file**: [.github/skills/checkov-security-scan/SKILL.md](...)
- **Purpose**: Infrastructure as Code (IaC) security misconfiguration detection
- **Supported frameworks**: Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, GitHub Actions, GitLab CI
- **Detection capabilities**: [list of 8 capabilities]
- **Best for**: IaC security audits, pre-deployment validation
- **NOT for**: Application source code vulnerabilities
```

**Flowchart Updated**:
```
├─► "Are there INFRASTRUCTURE AS CODE (IaC) files?"
│   ├─► Terraform (.tf) → Checkov --framework terraform
│   ├─► Kubernetes manifests → Checkov --framework kubernetes
│   └─► ...
```

**Decision Matrix Added**:
```
| **Terraform** | Checkov (--framework terraform) | Graudit (secrets) | IaC misconfiguration |
| **Dockerfile** | Checkov (--framework dockerfile) | ShellCheck, Graudit | Container best practices |
```

**Command Hints Added**:
```bash
### Checkov
- Quick IaC scan: `checkov -d . --compact`
- Terraform specific: `checkov -d . --framework terraform`
- [8 more examples]
```

### In sck.malicious-code-scanner.agent.md:

**Skills Table Updated**:
```
| **Checkov** | `.github/skills/checkov-security-scan/SKILL.md` | Infrastructure as Code (IaC) security & compliance |
```

**Allowed Commands Updated**:
```
- ✅ `checkov` - Infrastructure as Code security scanner
```

**Tool Execution Priority Added**:
```
| Terraform (.tf) | `checkov -d . --framework terraform` | `graudit -d secrets` | checkov-security-scan |
| Dockerfile | `checkov -f Dockerfile --framework dockerfile` | `shellcheck` | checkov-security-scan |
```

**Static Analysis Tools Added**:
```
| Terraform | **Checkov** | Exposed secrets in IaC, insecure resource configs, public access |
| Kubernetes | **Checkov** | Privileged containers, secrets in manifests, security policies |
```

---

## Quick Integration Command

For a streamlined integration, use this single command format:

```
@workspace Update the security scanning system with a new skill:

Skill: [skill-name]
Tool: [tool-command]
Purpose: [what it scans]
Formats: [file types/frameworks]
Detection: [what it detects]

Update files:
1. .github/prompts/sck.tools-advisor.prompt.md
2. .github/agents/sck.malicious-code-scanner.agent.md

Follow the same integration pattern used for checkov-security-scan as reference.
```

---

## Notes

- Always maintain alphabetical or logical ordering when adding to lists
- Keep descriptions concise (1-2 sentences) in the agent file
- Keep descriptions detailed (3-5 sentences) in the tools-advisor prompt
- Use consistent formatting with existing entries
- Include MITRE ATT&CK mappings when applicable
- Ensure command examples are tested and accurate
- Update version check commands to match the actual tool's syntax
- Consider tool priority relative to existing tools
- Document what the tool CANNOT do, not just what it can do

---

## Support

If you encounter issues during integration:
1. Review the Checkov integration as a reference pattern
2. Check that all sections mentioned in the verification checklist are updated
3. Ensure file paths are correct
4. Verify command examples actually work with the tool
5. Test the integration by asking the tools-advisor to analyze relevant files

---

## Maintenance

When updating an existing skill:
1. Update the skill file in `.github/skills/<skill-name>/SKILL.md` first
2. Use this prompt to propagate changes to tools-advisor and malicious-code-scanner
3. Update version check commands if tool syntax changed
4. Add new commands to the examples sections
5. Update detection capabilities if expanded
6. Re-run verification checklist
