# GuardDog Security Scan Skill

An Agent Skill for VS Code Copilot that scans Python and Node.js code for malicious patterns using [GuardDog](https://github.com/DataDog/guarddog) by DataDog.

## What It Does

Detects supply chain attacks and malicious code including:
- Data exfiltration and credential theft
- Reverse shells and backdoors
- Obfuscated payloads (base64, steganography)
- Typosquatting packages
- Malicious install scripts
- Compromised package maintainers

## Requirements

```bash
pip install guarddog
```

## Usage

Enable `chat.useAgentSkills` in VS Code settings, then ask Copilot:

| Request | What Happens |
|---------|--------------|
| "Scan this project for malicious code" | Scans local Python/Node.js files |
| "Check my requirements.txt for security issues" | Verifies all Python dependencies |
| "Audit package-lock.json for supply chain attacks" | Verifies all npm dependencies |
| "Is the 'requests' package safe to install?" | Scans remote PyPI package |

## Example Commands

```bash
# Scan local Python project
guarddog pypi scan ./my-project/

# Scan local Node.js project
guarddog npm scan ./my-project/

# Verify dependencies
guarddog pypi verify requirements.txt
guarddog npm verify package-lock.json

# Check remote package before installing
guarddog pypi scan some-package
guarddog npm scan some-package
```

## Files

- `SKILL.md` - Full skill instructions and heuristics reference
- `examples/malicious-patterns.md` - Code patterns the scanner detects

## Learn More

- [GuardDog GitHub](https://github.com/DataDog/guarddog)
- [VS Code Agent Skills Docs](https://code.visualstudio.com/docs/copilot/customization/agent-skills)
