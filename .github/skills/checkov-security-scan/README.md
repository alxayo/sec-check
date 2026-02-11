# Checkov Security Scan Skill

An Agent Skill for VS Code Copilot that scans Infrastructure as Code (IaC) for security misconfigurations and compliance violations using [Checkov](https://github.com/bridgecrewio/checkov) by Bridgecrew/Palo Alto Networks.

## What It Does

Scans IaC configurations for security issues including:
- Overly permissive IAM policies and access controls
- Unencrypted storage (S3, EBS, RDS)
- Publicly accessible resources
- Security group misconfigurations (open ports)
- Container security issues (privileged, root user)
- Missing health checks and logging
- Hardcoded secrets in configuration
- CI/CD workflow security issues

## Supported Frameworks

| Framework | File Types |
|-----------|------------|
| Terraform | `.tf`, `.tf.json`, plan files |
| CloudFormation | `.yaml`, `.yml`, `.json`, `.template` |
| Kubernetes | K8s manifests, Helm charts, Kustomize |
| Dockerfile | `Dockerfile`, `Dockerfile.*` |
| ARM/Bicep | Azure templates |
| GitHub Actions | `.github/workflows/*.yml` |
| GitLab CI | `.gitlab-ci.yml` |
| Serverless | `serverless.yml` |
| And more | Ansible, Argo, OpenAPI, etc. |

## Requirements

```bash
pip install checkov
```

## Usage

Enable `chat.useAgentSkills` in VS Code settings, then ask Copilot:

| Request | What Happens |
|---------|--------------|
| "Scan this Terraform for security issues" | Scans Terraform configurations |
| "Check my Kubernetes manifests for vulnerabilities" | Scans K8s YAML files |
| "Audit my Dockerfile for security best practices" | Checks Dockerfile security |
| "Is my CloudFormation template secure?" | Scans CFN templates |
| "Check my GitHub Actions for security issues" | Audits workflow files |

## Example Commands

```bash
# Scan a directory (auto-detects frameworks)
checkov -d /path/to/iac/

# Scan specific framework
checkov -d . --framework terraform
checkov -d ./k8s --framework kubernetes
checkov -f Dockerfile --framework dockerfile

# Output formats
checkov -d . -o json
checkov -d . -o sarif

# Skip specific checks
checkov -d . --skip-check CKV_AWS_1,CKV_DOCKER_7

# Only fail on critical issues
checkov -d . --hard-fail-on HIGH,CRITICAL

# List all available checks
checkov --list
```

## Check Categories

| Prefix | Description |
|--------|-------------|
| `CKV_AWS_*` | AWS security checks |
| `CKV_AZURE_*` | Azure security checks |
| `CKV_GCP_*` | GCP security checks |
| `CKV_K8S_*` | Kubernetes security checks |
| `CKV_DOCKER_*` | Dockerfile best practices |
| `CKV_GHA_*` | GitHub Actions security |
| `CKV_SECRET_*` | Secrets detection |

## Files

- `SKILL.md` - Full skill instructions and checks reference
- `examples/misconfiguration-patterns.md` - IaC patterns the scanner detects

## Learn More

- [Checkov GitHub](https://github.com/bridgecrewio/checkov)
- [Bridgecrew Documentation](https://docs.prismacloud.io/en/enterprise-edition/content-collections/application-security)
- [VS Code Agent Skills Docs](https://code.visualstudio.com/docs/copilot/customization/agent-skills)
