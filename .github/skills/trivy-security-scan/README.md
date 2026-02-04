```markdown
# Trivy Security Scan Skill

An Agent Skill for VS Code Copilot that performs comprehensive security scanning using [Trivy](https://github.com/aquasecurity/trivy) by Aqua Security.

## What It Does

Trivy is a multi-target, multi-scanner security tool that detects:

**Vulnerabilities (CVEs):**
- OS packages (Alpine, Debian, Ubuntu, RHEL, etc.)
- Language dependencies (npm, pip, go modules, Maven, etc.)
- Container image layers

**Misconfigurations:**
- Terraform, CloudFormation, AWS CDK
- Kubernetes manifests, Helm charts
- Dockerfiles, Docker Compose

**Secrets:**
- API keys (AWS, GCP, Azure, GitHub, etc.)
- Private keys (SSH, TLS/SSL, PGP)
- Passwords and tokens

**License Compliance:**
- Open source license identification
- Copyleft vs permissive license detection

## Requirements

```bash
# Homebrew (macOS/Linux)
brew install trivy

# Docker (no local install)
docker pull aquasec/trivy

# Binary download
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

## Usage

Enable `chat.useAgentSkills` in VS Code settings, then ask Copilot:

| Request | What Happens |
|---------|--------------|
| "Scan this Docker image for vulnerabilities" | Scans container image for CVEs |
| "Check this project for security issues" | Scans filesystem for vulnerabilities/secrets |
| "Find secrets in this codebase" | Detects hardcoded credentials |
| "Audit my Terraform files for misconfigurations" | Scans IaC for security issues |
| "Scan my Kubernetes manifests" | Checks K8s YAML for misconfigs |
| "Generate an SBOM for this container" | Creates software bill of materials |

## Example Commands

```bash
# Scan container image
trivy image python:3.12-alpine

# Scan filesystem for vulnerabilities and secrets
trivy fs --scanners vuln,secret ./

# Scan IaC files (Terraform, K8s, Dockerfile)
trivy config ./infra/

# Scan remote Git repository
trivy repo https://github.com/org/repo

# Scan Kubernetes cluster
trivy k8s --report summary cluster

# Generate SBOM
trivy image --format spdx-json -o sbom.json nginx:latest

# CI/CD: Fail on critical vulnerabilities
trivy image --exit-code 1 --severity CRITICAL myapp:latest

# Output formats
trivy image --format json -o results.json alpine:latest
trivy image --format sarif -o trivy.sarif alpine:latest
```

## Targets and Scanners

| Target | Command | Use Case |
|--------|---------|----------|
| Container Image | `trivy image <image>` | Pre-deployment container security |
| Filesystem | `trivy fs <path>` | Project dependency audit |
| Git Repository | `trivy repo <url>` | Remote code scanning |
| IaC Files | `trivy config <path>` | Terraform/K8s misconfigs |
| Kubernetes | `trivy k8s cluster` | Cluster security assessment |
| SBOM | `trivy sbom <file>` | Scan existing SBOMs |

## Files

- `SKILL.md` - Full skill instructions, CLI reference, and scanner documentation
- `examples/malicious-patterns.md` - Patterns and issues Trivy detects

## Learn More

- [Trivy Documentation](https://trivy.dev/docs/latest/)
- [Trivy GitHub](https://github.com/aquasecurity/trivy)
- [GitHub Action](https://github.com/aquasecurity/trivy-action)
- [VS Code Agent Skills Docs](https://code.visualstudio.com/docs/copilot/customization/agent-skills)
```
