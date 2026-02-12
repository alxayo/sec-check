---
name: template-analyzer-security-scan
description: Scan ARM (Azure Resource Manager) and Bicep Infrastructure-as-Code templates for security misconfigurations and best practice violations. (1) Primary targets *.json ARM templates, *.bicep files, Azure deployment templates. (2) Detects HTTPS/TLS enforcement issues, missing encryption, overly permissive CORS, disabled auditing, missing managed identities, RBAC misconfigurations, insecure API settings. (3) Use for Azure IaC security audits, pre-deployment validation, compliance checks. Do NOT use for application source code (use bandit, graudit) or non-Azure IaC (use checkov, trivy).
---

# Template Analyzer Security Scanning Skill

This skill enables scanning Azure ARM and Bicep Infrastructure-as-Code (IaC) templates for security misconfigurations using **Template Analyzer** - Microsoft's official tool for validating Azure deployment templates against security and best practice rules.

> **Key Distinction**: Template Analyzer is Azure-specific and focuses on ARM/Bicep templates. For multi-cloud IaC (Terraform, CloudFormation, Kubernetes), use `checkov` or `trivy` instead.

## Quick Reference

| Task | Command |
|------|---------|
| Scan single template | `TemplateAnalyzer analyze-template ./azuredeploy.json` |
| Scan with parameters | `TemplateAnalyzer analyze-template ./azuredeploy.json -p ./parameters.json` |
| Scan directory (recursive) | `TemplateAnalyzer analyze-directory ./templates/` |
| SARIF output for CI/CD | `TemplateAnalyzer analyze-template ./template.json --report-format Sarif -o results.sarif` |
| Include non-security rules | `TemplateAnalyzer analyze-template ./template.json --include-non-security-rules` |
| Verbose output | `TemplateAnalyzer analyze-template ./template.json -v` |

## When to Use This Skill

**PRIMARY USE CASES:**
- Audit ARM templates (`.json` with Azure schema) for security issues
- Audit Bicep templates (`.bicep`) for security misconfigurations
- Pre-deployment security validation of Azure infrastructure
- CI/CD pipeline security gates for Azure deployments
- Compliance checks against Azure security baselines
- Detect missing encryption, insecure protocols, overly permissive access

**DO NOT USE FOR:**
- General application source code → use `bandit`, `graudit`
- Terraform/CloudFormation/Kubernetes → use `checkov`, `trivy`
- Azure runtime security issues → use Azure Security Center
- Dependency vulnerabilities → use `guarddog`, `dependency-check`

## Decision Tree: Choosing the Right Scanner

```
What are you scanning?
│
├── Azure ARM/Bicep templates?
│   └── Use Template Analyzer (this skill)
│
├── Terraform, CloudFormation, Helm, Kubernetes YAML?
│   └── Use checkov or trivy
│
├── Dockerfiles?
│   └── Use trivy or checkov
│
├── Application source code?
│   ├── Python → bandit
│   ├── JavaScript/TypeScript → eslint-security
│   └── Multi-language → graudit
│
└── Package dependencies?
    └── Use guarddog, dependency-check
```

## Prerequisites

Template Analyzer must be installed. Download from [GitHub releases](https://github.com/Azure/template-analyzer/releases):

### Linux Installation

```bash
# Download latest release (x64)
curl -L -o TemplateAnalyzer.zip \
  https://github.com/Azure/template-analyzer/releases/latest/download/TemplateAnalyzer-linux-x64.zip

# Extract
unzip TemplateAnalyzer.zip -d ~/template-analyzer

# Make executable
chmod +x ~/template-analyzer/TemplateAnalyzer

# Add to PATH (add to ~/.bashrc for persistence)
export PATH="$HOME/template-analyzer:$PATH"

# Verify installation
TemplateAnalyzer --help
```

### macOS Installation

```bash
# Download for macOS (arm64 for Apple Silicon, x64 for Intel)
curl -L -o TemplateAnalyzer.zip \
  https://github.com/Azure/template-analyzer/releases/latest/download/TemplateAnalyzer-osx-arm64.zip

# Extract and setup
unzip TemplateAnalyzer.zip -d ~/template-analyzer
chmod +x ~/template-analyzer/TemplateAnalyzer
export PATH="$HOME/template-analyzer:$PATH"
```

### Windows Installation

```powershell
# Download Windows release
Invoke-WebRequest -Uri "https://github.com/Azure/template-analyzer/releases/latest/download/TemplateAnalyzer-win-x64.zip" -OutFile "TemplateAnalyzer.zip"

# Extract
Expand-Archive -Path TemplateAnalyzer.zip -DestinationPath "$env:USERPROFILE\template-analyzer"

# Add to PATH
$env:PATH += ";$env:USERPROFILE\template-analyzer"
```

### Docker Usage

```bash
# Pull the official image (if available) or run in container
docker run --rm -v "$(pwd):/templates" mcr.microsoft.com/templateanalyzer \
  analyze-directory /templates
```

## Core Scanning Commands

### Scan Single ARM Template

```bash
# Basic scan
TemplateAnalyzer analyze-template ./azuredeploy.json

# With parameter file for accurate evaluation
TemplateAnalyzer analyze-template ./azuredeploy.json -p ./azuredeploy.parameters.json

# Verbose output showing all rule evaluations
TemplateAnalyzer analyze-template ./azuredeploy.json -v
```

### Scan Bicep Template

```bash
# Bicep templates are automatically detected by .bicep extension
TemplateAnalyzer analyze-template ./main.bicep

# With parameter file
TemplateAnalyzer analyze-template ./main.bicep -p ./parameters.json
```

### Scan Directory

```bash
# Recursively scan all ARM and Bicep templates
TemplateAnalyzer analyze-directory ./infrastructure/

# Include parameter files automatically (follows naming conventions)
TemplateAnalyzer analyze-directory ./azure-templates/
```

### Generate SARIF Report

```bash
# Output in SARIF format for CI/CD tools
TemplateAnalyzer analyze-template ./azuredeploy.json \
  --report-format Sarif \
  -o template-analyzer-results.sarif

# Scan directory with SARIF output
TemplateAnalyzer analyze-directory ./templates/ \
  --report-format Sarif \
  -o scan-results.sarif
```

### Use Custom Rules

```bash
# Apply custom JSON rules file
TemplateAnalyzer analyze-template ./azuredeploy.json \
  --custom-json-rules-path ./custom-rules.json

# Use custom configuration file
TemplateAnalyzer analyze-template ./azuredeploy.json \
  -c ./template-analyzer-config.json
```

## Built-in Security Rules

Template Analyzer includes JSON-based rules and integrates with PSRule for Azure for comprehensive coverage.

### Rule Severity Levels
- **1 = High**: Critical security issues requiring immediate attention
- **2 = Medium**: Significant security concerns to address
- **3 = Low**: Best practice recommendations

### High Severity Rules (Critical)

| Rule ID | Description | MITRE ATT&CK |
|---------|-------------|--------------|
| TA-000003 | FTPS not enforced in API app | T1071 (Application Layer Protocol) |
| TA-000005 | Latest TLS version not used in API app | T1557 (MITM) |
| TA-000009 | FTPS not enforced in function app | T1071 |
| TA-000011 | Latest TLS version not used in function app | T1557 |
| TA-000015 | FTPS not enforced in web app | T1071 |
| TA-000017 | Latest TLS version not used in web app | T1557 |
| TA-000021 | Automation account variables not encrypted | T1552 (Unsecured Credentials) |
| TA-000022 | Redis Cache allows non-SSL connections | T1557 |
| TA-000023 | Kubernetes - No authorized IP ranges | T1190 (Exploit Public-Facing App) |
| TA-000024 | Kubernetes - RBAC not enabled | T1078 (Valid Accounts) |
| TA-000025 | Kubernetes uses vulnerable version | T1203 (Exploitation) |
| TA-000026 | Service Fabric - AAD not required | T1078 |
| TA-000029 | API Management APIs not using HTTPS only | T1557 |
| TA-000030 | Classic Compute VM (not ARM) | T1078 |
| TA-000031 | Classic Storage Account (not ARM) | T1078 |

### Medium Severity Rules

| Rule ID | Description | MITRE ATT&CK |
|---------|-------------|--------------|
| TA-000001 | Diagnostic logs not enabled in App Service | T1562 (Impair Defenses) |
| TA-000004 | API app not requiring HTTPS | T1557 |
| TA-000007 | Managed identity not used in API app | T1552 |
| TA-000010 | Function app not requiring HTTPS | T1557 |
| TA-000013 | Managed identity not used in function app | T1552 |
| TA-000016 | Web app not requiring HTTPS | T1557 |
| TA-000019 | Managed identity not used in web app | T1552 |
| TA-000032 | API Management bypasses cert validation | T1557 |
| TA-000034 | API Management min API version too low | T1552 |
| TA-000035 | API Management secrets not in Key Vault | T1552 |
| TA-000036 | API Management not using VNet | T1190 |
| TA-000037 | API Management subscription scoped to all APIs | T1078 |

### Low Severity Rules (Best Practices)

| Rule ID | Description |
|---------|-------------|
| TA-000002 | Remote debugging enabled in API app |
| TA-000006 | CORS allows all origins in API app |
| TA-000008 | Remote debugging enabled in function app |
| TA-000012 | CORS allows all origins in function app |
| TA-000014 | Remote debugging enabled in web app |
| TA-000018 | CORS allows all origins in web app |
| TA-000020 | Custom RBAC roles used instead of built-in |
| TA-000027 | TDE not enabled on SQL databases |
| TA-000028 | SQL auditing retention less than 90 days |
| TA-000033 | API Management direct management endpoint enabled |

### PSRule for Azure Integration

Template Analyzer integrates with [PSRule for Azure](https://aka.ms/ps-rule-azure) for additional security rules under the Security pillar. Use `--include-non-security-rules` to also check Well-Architected Framework pillars (Reliability, Cost, Operational Excellence, Performance).

## Workflow for Security Audit

### Quick Pre-Deployment Check

```bash
# Validate template before deployment
TemplateAnalyzer analyze-template ./azuredeploy.json -p ./params.json

# Check exit code (20 = violations found)
if [ $? -eq 20 ]; then
    echo "Security violations found - do not deploy!"
    exit 1
fi
```

### Comprehensive Audit

```bash
# Step 1: Scan all templates in directory
TemplateAnalyzer analyze-directory ./infrastructure/ -v

# Step 2: Generate SARIF report for documentation
TemplateAnalyzer analyze-directory ./infrastructure/ \
  --report-format Sarif -o scan-report.sarif

# Step 3: Include non-security rules for full compliance
TemplateAnalyzer analyze-directory ./infrastructure/ \
  --include-non-security-rules
```

### CI/CD Pipeline Integration

```bash
# Run in CI - fail pipeline on violations
TemplateAnalyzer analyze-directory ./templates/ \
  --report-format Sarif -o results.sarif

# Exit codes:
# 0  = Success, no violations
# 20 = Violations found
# 21 = Errors during analysis
# 22 = Both violations and errors
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Azure Template Security Scan
on: [push, pull_request]

jobs:
  template-analyzer:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Download Template Analyzer
        run: |
          curl -L -o TemplateAnalyzer.zip \
            https://github.com/Azure/template-analyzer/releases/latest/download/TemplateAnalyzer-linux-x64.zip
          unzip TemplateAnalyzer.zip -d $HOME/template-analyzer
          chmod +x $HOME/template-analyzer/TemplateAnalyzer
          echo "$HOME/template-analyzer" >> $GITHUB_PATH
      
      - name: Scan ARM/Bicep Templates
        run: |
          TemplateAnalyzer analyze-directory ./infrastructure/ \
            --report-format Sarif -o results.sarif
        continue-on-error: true
      
      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Azure DevOps Pipeline

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: Bash@3
    displayName: 'Install Template Analyzer'
    inputs:
      targetType: 'inline'
      script: |
        curl -L -o TemplateAnalyzer.zip \
          https://github.com/Azure/template-analyzer/releases/latest/download/TemplateAnalyzer-linux-x64.zip
        unzip TemplateAnalyzer.zip -d $(Agent.ToolsDirectory)/template-analyzer
        chmod +x $(Agent.ToolsDirectory)/template-analyzer/TemplateAnalyzer
        echo "##vso[task.prependpath]$(Agent.ToolsDirectory)/template-analyzer"

  - task: Bash@3
    displayName: 'Scan Templates'
    inputs:
      targetType: 'inline'
      script: |
        TemplateAnalyzer analyze-directory ./infrastructure/ \
          --report-format Sarif -o $(Build.ArtifactStagingDirectory)/template-analyzer.sarif

  - task: PublishBuildArtifacts@1
    inputs:
      pathtoPublish: '$(Build.ArtifactStagingDirectory)/template-analyzer.sarif'
      artifactName: 'SecurityScanResults'
```

## Interpreting Results

### Console Output Example

```
>TemplateAnalyzer analyze-template "azuredeploy.json"

File: azuredeploy.json

        TA-000004: API app should only be accessible over HTTPS
                Severity: Medium
                Recommendation: Use HTTPS to ensure server/service authentication 
                and protect data in transit from network layer eavesdropping attacks
                More information: https://github.com/Azure/template-analyzer/blob/main/docs/built-in-rules.md#ta-000004
                Result: Failed
                Line: 67

        TA-000017: Latest TLS version should be used in your web app
                Severity: High
                Recommendation: Set minTlsVersion to 1.2
                Result: Failed
                Line: 89

        Rules passed: 16

Execution summary:
        The execution completed successfully
```

### Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success - no violations |
| 1 | Invalid command |
| 2 | Invalid file/directory path |
| 3 | Missing file/directory path |
| 4 | Configuration file error |
| 10 | Invalid ARM template |
| 11 | Invalid Bicep template |
| 20 | **Violations found** |
| 21 | Analysis error |
| 22 | Both violations and errors |

### Remediation Priority

1. **Exit code 20 (Violations)**: Review and fix security issues before deployment
2. **High severity (1)**: Address immediately - encryption, TLS, authentication
3. **Medium severity (2)**: Address before production - HTTPS, managed identity
4. **Low severity (3)**: Best practices - disable debugging, restrict CORS

## Configuration File

Create `configuration.json` to customize rule behavior:

```json
{
  "rules": {
    "TA-000002": {
      "enabled": false
    },
    "TA-000006": {
      "severity": 2
    }
  }
}
```

Apply with `-c` flag:

```bash
TemplateAnalyzer analyze-template ./template.json -c ./configuration.json
```

## Custom Rules

Create custom JSON rules for organization-specific checks. See [authoring-json-rules.md](https://github.com/Azure/template-analyzer/blob/main/docs/authoring-json-rules.md).

Example custom rule:

```json
{
  "name": "CUSTOM-001",
  "description": "Storage accounts must use customer-managed keys",
  "recommendation": "Enable customer-managed key encryption",
  "severity": 1,
  "resourceType": "Microsoft.Storage/storageAccounts",
  "jsonPath": "$.properties.encryption.keySource",
  "expectedValue": "Microsoft.Keyvault"
}
```

## Combining with Other Tools

For comprehensive Azure security, combine Template Analyzer with:

| Tool | Use For |
|------|---------|
| **Template Analyzer** | ARM/Bicep template security before deployment |
| **Checkov** | Multi-cloud IaC (Terraform, CloudFormation) + comprehensive checks |
| **Trivy** | Container images, SBOM, broader IaC coverage |
| **Azure Policy** | Runtime compliance enforcement |
| **Microsoft Defender for Cloud** | Runtime security posture management |

### Recommended Azure IaC Audit Workflow

```bash
# 1. Scan ARM/Bicep with Template Analyzer (Azure-specific deep rules)
TemplateAnalyzer analyze-directory ./azure-templates/

# 2. Cross-check with Checkov (broader coverage, CIS benchmarks)
checkov -d ./azure-templates/ --framework arm

# 3. Scan for secrets (shouldn't be in templates)
graudit -d secrets ./azure-templates/
```

## Limitations

- **Azure-only**: Only scans ARM and Bicep templates, not Terraform/CloudFormation/Kubernetes
- **Static analysis**: Cannot detect runtime issues or actual deployment state
- **Parameter-dependent**: Some rules evaluate differently based on parameter values provided
- **No secrets detection**: Does not check for hardcoded secrets (use graudit -d secrets)
- **Bicep compilation**: Requires .NET runtime for Bicep template compilation
- **Rule coverage**: Not all Azure services have dedicated rules yet

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Invalid ARM template` | Verify JSON schema contains valid `$schema` property |
| `Invalid Bicep template` | Ensure Bicep CLI is available for compilation |
| Slow directory scans | Reduce scope or exclude test/example directories |
| False positives | Use configuration file to disable specific rules |
| Missing rule violations | Provide parameter file for accurate evaluation |

## Additional Resources

- [Misconfiguration Examples](./examples/misconfigurations.md) - Common ARM/Bicep misconfigurations
- [Template Analyzer GitHub](https://github.com/Azure/template-analyzer) - Official repository
- [Built-in Rules Reference](https://github.com/Azure/template-analyzer/blob/main/docs/built-in-rules.md) - Full rule documentation
- [PSRule for Azure](https://aka.ms/ps-rule-azure) - Additional integrated rules
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Threat classification reference
