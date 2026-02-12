# Template Analyzer Security Scan Skill

An Agent Skill for scanning Azure ARM and Bicep Infrastructure-as-Code templates for security misconfigurations using Microsoft's Template Analyzer.

## What This Skill Does

- Scans ARM templates (`.json`) for security violations
- Scans Bicep templates (`.bicep`) for security misconfigurations
- Detects missing encryption, insecure protocols, overly permissive access
- Validates against Azure security best practices
- Integrates with PSRule for Azure for comprehensive rule coverage
- Outputs results in console or SARIF format for CI/CD integration

## Requirements

- **Template Analyzer** binary (download from [GitHub releases](https://github.com/Azure/template-analyzer/releases))
- Linux, macOS, or Windows
- .NET runtime (bundled with Template Analyzer)

### Quick Install (Linux/macOS)

```bash
curl -L -o TemplateAnalyzer.zip \
  https://github.com/Azure/template-analyzer/releases/latest/download/TemplateAnalyzer-linux-x64.zip
unzip TemplateAnalyzer.zip -d ~/template-analyzer
chmod +x ~/template-analyzer/TemplateAnalyzer
export PATH="$HOME/template-analyzer:$PATH"
```

## Example Prompts for Copilot

- "Scan this ARM template for security issues"
- "Check my Bicep files for misconfigurations"
- "Validate Azure infrastructure templates before deployment"
- "Find security violations in my Azure templates directory"
- "Check if my web app template enforces HTTPS"
- "Audit my Azure Resource Manager templates"

## Example CLI Commands

```bash
# Scan single ARM template
TemplateAnalyzer analyze-template ./azuredeploy.json

# Scan with parameters for accurate evaluation
TemplateAnalyzer analyze-template ./main.bicep -p ./parameters.json

# Scan entire directory recursively
TemplateAnalyzer analyze-directory ./infrastructure/

# Generate SARIF report for CI/CD
TemplateAnalyzer analyze-template ./template.json --report-format Sarif -o results.sarif

# Include non-security rules (reliability, cost, performance)
TemplateAnalyzer analyze-directory ./templates/ --include-non-security-rules
```

## File Structure

```
template-analyzer-security-scan/
├── SKILL.md                        # Full skill documentation
├── README.md                       # This file
└── examples/
    └── misconfigurations.md        # Example vulnerable templates
```

## Key Detection Categories

| Category | Examples |
|----------|----------|
| **Transport Security** | Missing HTTPS enforcement, outdated TLS versions |
| **Authentication** | Missing managed identities, AAD not required |
| **Encryption** | Unencrypted storage, missing TDE on databases |
| **Access Control** | Overly permissive CORS, missing RBAC, no IP restrictions |
| **Auditing** | Disabled diagnostic logs, insufficient retention |
| **Network Security** | No VNet integration, exposed management endpoints |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - no violations |
| 20 | **Security violations found** |
| 21 | Analysis errors |
| 22 | Both violations and errors |

## Related Tools

- **Checkov**: Multi-cloud IaC scanning (Terraform, CloudFormation, ARM)
- **Trivy**: Container and IaC scanning with broader coverage
- **Azure Policy**: Runtime compliance enforcement
- **Microsoft Defender for Cloud**: Runtime security posture

## Resources

- [Template Analyzer GitHub](https://github.com/Azure/template-analyzer)
- [Built-in Rules Documentation](https://github.com/Azure/template-analyzer/blob/main/docs/built-in-rules.md)
- [PSRule for Azure](https://aka.ms/ps-rule-azure)
