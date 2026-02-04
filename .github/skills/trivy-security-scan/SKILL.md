```skill
---
name: trivy-security-scan
description: Comprehensive security scanner for container images, filesystems, Git repositories, Kubernetes, and IaC. (1) Detects known vulnerabilities (CVEs) in OS packages and dependencies. (2) Scans for IaC misconfigurations (Terraform, CloudFormation, Helm, Kubernetes YAML). (3) Detects hardcoded secrets (API keys, passwords, tokens). (4) Identifies license compliance issues. Use for container security, cloud-native security, DevSecOps pipelines, pre-deployment scans. Targets: Docker images, filesystem directories, remote Git repos, Kubernetes clusters, SBOM files. Do NOT use for Python source code vulnerabilities (use bandit), shell script issues (use shellcheck), or malicious package detection (use guarddog).
---

# Trivy Comprehensive Security Scanning Skill

This skill enables scanning container images, filesystems, Git repositories, Kubernetes clusters, and Infrastructure as Code for security issues using **Trivy** - a comprehensive security scanner by Aqua Security.

> **Key Distinction**: Trivy is a **multi-target, multi-scanner** tool. It detects CVEs, misconfigurations, secrets, and license issues across containers, filesystems, and cloud-native infrastructure. For **Python source code** vulnerabilities use `bandit`. For **malicious package detection** use `guarddog`.

## Quick Reference

| Task | Command |
|------|---------|
| Scan container image | `trivy image python:3.12-alpine` |
| Scan filesystem | `trivy fs --scanners vuln,secret,misconfig ./` |
| Scan Git repository | `trivy repo https://github.com/org/repo` |
| Scan Kubernetes cluster | `trivy k8s --report summary cluster` |
| Scan IaC files | `trivy config ./terraform/` |
| Generate SBOM | `trivy image --format spdx-json -o sbom.json nginx:latest` |
| JSON output | `trivy image --format json alpine:latest` |
| SARIF output | `trivy image --format sarif alpine:latest` |
| Filter critical only | `trivy image --severity CRITICAL alpine:latest` |
| Exit code on findings | `trivy image --exit-code 1 alpine:latest` |

## When to Use This Skill

**PRIMARY USE CASES:**
- Scan container images for OS and package vulnerabilities before deployment
- Audit project filesystems for CVEs in dependencies
- Detect hardcoded secrets (API keys, passwords, tokens) in code
- Find IaC misconfigurations in Terraform, CloudFormation, Kubernetes manifests
- Generate Software Bill of Materials (SBOM) for compliance
- Kubernetes cluster security assessment
- CI/CD security gates for container builds

**TARGETS (What Trivy Can Scan):**
- Container images (Docker, OCI, Podman)
- Filesystems and project directories
- Remote Git repositories
- Kubernetes clusters
- Virtual machine images (AWS AMI, etc.)
- SBOM files (SPDX, CycloneDX)

**SCANNERS (What Trivy Detects):**
- `vuln` - Known vulnerabilities (CVEs) in OS packages and language dependencies
- `misconfig` - IaC misconfigurations (Terraform, CloudFormation, Dockerfile, Kubernetes, Helm)
- `secret` - Hardcoded secrets (API keys, passwords, private keys, tokens)
- `license` - Software license compliance issues

**DO NOT USE FOR:**
- Python source code vulnerabilities → use `bandit`
- Shell script security → use `shellcheck`
- Malicious package detection → use `guarddog`
- Multi-language source code pattern matching → use `graudit`

## Decision Tree: Choosing the Right Tool

```
What are you scanning?
│
├── Container image / Docker?
│   └── trivy image <image>
│
├── Project filesystem for CVEs?
│   └── trivy fs --scanners vuln ./
│
├── IaC files (Terraform, K8s YAML)?
│   └── trivy config ./infra/
│
├── Kubernetes cluster?
│   └── trivy k8s cluster
│
├── Secrets in code?
│   └── trivy fs --scanners secret ./
│
├── Python source code security?
│   └── bandit -r ./src (not Trivy)
│
├── Malicious npm/PyPI packages?
│   └── guarddog pypi/npm scan (not Trivy)
│
└── Comprehensive audit?
    ├── trivy image <image>           # Container
    ├── trivy fs --scanners vuln,secret ./  # Project
    ├── trivy config ./infra/         # IaC
    └── bandit/graudit for source code
```

## Prerequisites

Trivy must be installed. If not available, install it:

### Installation Options

**Homebrew (macOS/Linux - Recommended)**
```bash
brew install trivy
```

**APT (Debian/Ubuntu)**
```bash
sudo apt-get install wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

**YUM (RHEL/CentOS/Fedora)**
```bash
sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.58.2/trivy_0.58.2_Linux-64bit.rpm
```

**Docker (No Local Install)**
```bash
docker pull aquasec/trivy:latest

# Run via Docker
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $(pwd):/workspace aquasec/trivy:latest image alpine:latest

# Create alias for convenience
alias trivy='docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/workspace -w /workspace aquasec/trivy:latest'
```

**Binary Download**
```bash
# Download latest release
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
trivy --version
```

## Core Scanning Commands

### Scan Container Images

```bash
# Scan a public image
trivy image python:3.12-alpine

# Scan a local image
trivy image myapp:latest

# Scan image from registry
trivy image registry.example.com/myapp:v1.0

# Scan with specific severity filter
trivy image --severity HIGH,CRITICAL nginx:latest

# Scan and fail if vulnerabilities found (for CI/CD)
trivy image --exit-code 1 --severity CRITICAL alpine:latest

# Output as JSON
trivy image --format json -o results.json ubuntu:22.04

# Output as SARIF (for GitHub Security)
trivy image --format sarif -o trivy.sarif python:3.12
```

### Scan Filesystems / Project Directories

```bash
# Scan current directory for vulnerabilities, secrets, and misconfigs
trivy fs --scanners vuln,secret,misconfig ./

# Scan for vulnerabilities only
trivy fs --scanners vuln ./myproject

# Scan for secrets only
trivy fs --scanners secret ./

# Scan with JSON output
trivy fs --scanners vuln --format json -o vulns.json ./

# Scan specific files
trivy fs --scanners vuln package-lock.json requirements.txt
```

### Scan Git Repositories (Remote)

```bash
# Scan a public GitHub repository
trivy repo https://github.com/aquasecurity/trivy

# Scan a specific branch
trivy repo --branch develop https://github.com/org/repo

# Scan a specific commit
trivy repo --commit abc1234 https://github.com/org/repo

# Scan a specific tag
trivy repo --tag v1.0.0 https://github.com/org/repo

# With authentication (private repos)
trivy repo --token $GITHUB_TOKEN https://github.com/org/private-repo
```

### Scan Infrastructure as Code (IaC)

```bash
# Scan Terraform files
trivy config ./terraform/

# Scan Kubernetes manifests
trivy config ./k8s/manifests/

# Scan Helm charts
trivy config ./helm/charts/myapp/

# Scan CloudFormation templates
trivy config ./cloudformation/

# Scan Dockerfiles
trivy config ./

# Scan with specific severity
trivy config --severity HIGH,CRITICAL ./infra/

# Output as JSON
trivy config --format json -o misconfig.json ./terraform/
```

### Scan Kubernetes Clusters

```bash
# Scan entire cluster (summary report)
trivy k8s --report summary cluster

# Scan specific namespace
trivy k8s --namespace production cluster

# Scan all resources with detailed report
trivy k8s --report all cluster

# Scan specific workload
trivy k8s deployment/myapp -n default

# Output compliance report
trivy k8s --compliance k8s-cis-1.23 cluster

# JSON output
trivy k8s --format json -o k8s-scan.json cluster
```

### Generate SBOM (Software Bill of Materials)

```bash
# Generate SPDX SBOM for container image
trivy image --format spdx-json -o sbom.spdx.json nginx:latest

# Generate CycloneDX SBOM
trivy image --format cyclonedx -o sbom.cdx.json nginx:latest

# Generate SBOM for filesystem
trivy fs --format spdx-json -o sbom.json ./

# Scan existing SBOM file for vulnerabilities
trivy sbom ./sbom.spdx.json
```

## Available Scanners

### Vulnerability Scanner (`vuln`)

Detects known CVEs in:

| Package Type | Examples |
|--------------|----------|
| **OS Packages** | Alpine apk, Debian/Ubuntu apt, RHEL/CentOS rpm, Amazon Linux, SUSE |
| **Language Packages** | npm, pip, gem, cargo, go modules, NuGet, Maven, Gradle |
| **Application Dependencies** | package-lock.json, requirements.txt, Gemfile.lock, go.sum, Cargo.lock |

**Vulnerability Sources:**
- NVD (National Vulnerability Database)
- GitHub Advisory Database
- Alpine SecDB
- Red Hat Security Data
- Debian Security Tracker
- Ubuntu CVE Tracker
- Amazon ALAS
- OS-specific advisories

### Misconfiguration Scanner (`misconfig`)

Detects security misconfigurations in:

| IaC Type | File Patterns |
|----------|---------------|
| **Terraform** | *.tf, *.tfvars |
| **CloudFormation** | *.yaml, *.yml, *.json (CFN templates) |
| **Kubernetes** | *.yaml, *.yml (K8s manifests) |
| **Helm** | Chart.yaml, values.yaml, templates/ |
| **Dockerfile** | Dockerfile, *.dockerfile |
| **Docker Compose** | docker-compose.yaml |
| **AWS CDK** | cdk.json |
| **Azure ARM** | *.json (ARM templates) |

**Common Misconfigurations Detected:**
- Containers running as root
- Privileged containers
- Missing resource limits
- Exposed secrets in ConfigMaps
- Insecure network policies
- Public S3 buckets
- Unencrypted storage
- Missing logging/monitoring
- Over-permissive IAM policies

### Secret Scanner (`secret`)

Detects hardcoded secrets:

| Secret Type | Examples |
|-------------|----------|
| **API Keys** | AWS, GCP, Azure, GitHub, Slack, Stripe, SendGrid |
| **Tokens** | JWT, OAuth, Personal access tokens |
| **Credentials** | Passwords, database connection strings |
| **Private Keys** | SSH keys, TLS/SSL certificates, PGP keys |
| **Cloud Credentials** | AWS access keys, GCP service accounts, Azure credentials |

### License Scanner (`license`)

Identifies software licenses for compliance:

| License Category | Risk Level |
|------------------|------------|
| **Permissive** | MIT, Apache-2.0, BSD | Low |
| **Copyleft** | GPL, LGPL, AGPL | Medium-High (requires disclosure) |
| **Proprietary** | Commercial licenses | Requires review |
| **Unknown** | Unidentified licenses | Review required |

## MITRE ATT&CK Mappings

| Technique ID | Name | Trivy Detection |
|--------------|------|-----------------|
| **T1195.001** | Supply Chain Compromise: Dependencies | CVEs in packages |
| **T1195.002** | Supply Chain Compromise: Software | Container image vulnerabilities |
| **T1552.001** | Credentials in Files | Secret scanner |
| **T1552.004** | Private Keys | SSH/TLS key detection |
| **T1190** | Exploit Public-Facing Application | CVEs in web frameworks |
| **T1610** | Deploy Container | Dockerfile misconfigs |
| **T1613** | Container and Resource Discovery | K8s misconfigs |
| **T1552** | Unsecured Credentials | Exposed secrets in ConfigMaps |

## CLI Options Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--severity <LEVELS>` | Filter by severity: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL |
| `--format <FORMAT>` | Output format: table, json, sarif, cyclonedx, spdx-json, template |
| `--output <FILE>` / `-o` | Write output to file |
| `--exit-code <CODE>` | Exit code when vulnerabilities found (default: 0) |
| `--ignore-unfixed` | Ignore vulnerabilities without fixes |
| `--scanners <TYPES>` | Scanners: vuln, misconfig, secret, license |
| `--timeout <DURATION>` | Scan timeout (default: 5m) |
| `--quiet` / `-q` | Suppress progress output |
| `--debug` / `-d` | Enable debug logging |
| `--cache-dir <DIR>` | Cache directory |
| `--skip-dirs <DIRS>` | Directories to skip |
| `--skip-files <FILES>` | Files to skip |

### Image-Specific Options

| Option | Description |
|--------|-------------|
| `--input <FILE>` | Scan image from tarball |
| `--platform <PLATFORM>` | Target platform (linux/amd64, linux/arm64) |
| `--removed-pkgs` | Include removed packages (history layer) |
| `--offline-scan` | Scan without network access (use cached DB) |

### Filesystem/Repo Options

| Option | Description |
|--------|-------------|
| `--skip-dirs <DIRS>` | Skip directories (comma-separated) |
| `--skip-files <FILES>` | Skip files (comma-separated) |
| `--file-patterns <PATTERNS>` | File patterns to scan |

### Kubernetes Options

| Option | Description |
|--------|-------------|
| `--namespace <NS>` | Specific namespace to scan |
| `--kubeconfig <FILE>` | Path to kubeconfig |
| `--context <NAME>` | Kubernetes context to use |
| `--report <TYPE>` | Report type: summary, all |
| `--compliance <SPEC>` | Compliance spec: k8s-cis-1.23, k8s-nsa, etc. |

## Workflow for Security Audit

### Quick Image Scan (Development)

```bash
# Fast scan of an image
trivy image --severity HIGH,CRITICAL nginx:latest
```

### Pre-Deployment Container Scan (CI/CD)

```bash
# Comprehensive image scan with CI exit code
trivy image \
    --exit-code 1 \
    --severity CRITICAL \
    --ignore-unfixed \
    --format sarif \
    -o trivy.sarif \
    myapp:latest
```

### Full Project Security Audit

```bash
# Step 1: Scan filesystem for vulnerabilities and secrets
trivy fs --scanners vuln,secret --format json -o fs-scan.json ./

# Step 2: Scan IaC for misconfigurations
trivy config --format json -o config-scan.json ./infra/

# Step 3: If Docker project, scan the built image
trivy image --format json -o image-scan.json myapp:latest

# Step 4: Generate SBOM for compliance
trivy image --format spdx-json -o sbom.json myapp:latest
```

### Kubernetes Cluster Audit

```bash
# Comprehensive K8s security assessment
trivy k8s --report summary cluster

# Compliance check against CIS benchmark
trivy k8s --compliance k8s-cis-1.23 --report all cluster

# Scan specific namespace
trivy k8s --namespace production --report summary cluster
```

### Combined Security Audit Workflow

```bash
#!/bin/bash
# Complete security audit for cloud-native projects

echo "=== Step 1: Filesystem Vulnerability Scan ==="
trivy fs --scanners vuln --severity HIGH,CRITICAL ./

echo "=== Step 2: Secret Detection ==="
trivy fs --scanners secret ./

echo "=== Step 3: IaC Misconfiguration Scan ==="
trivy config --severity HIGH,CRITICAL ./infra/

echo "=== Step 4: Container Image Scan ==="
trivy image --severity HIGH,CRITICAL myapp:latest

echo "=== Step 5: Python Source Code (if applicable) ==="
[ -f requirements.txt ] && bandit -r ./src || echo "No Python code"

echo "=== Step 6: Supply Chain Check ==="
[ -f requirements.txt ] && guarddog pypi verify requirements.txt
[ -f package-lock.json ] && guarddog npm verify package-lock.json

echo "=== Security Audit Complete ==="
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  trivy-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
          ignore-unfixed: true

      - name: Upload Trivy scan results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

      - name: Scan IaC files
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-config.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Scan filesystem for secrets
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          scanners: 'secret'
          format: 'table'
```

### GitLab CI

```yaml
stages:
  - security

trivy-image-scan:
  stage: security
  image:
    name: aquasec/trivy:latest
    entrypoint: [""]
  script:
    - trivy image --exit-code 1 --severity CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  allow_failure: true

trivy-fs-scan:
  stage: security
  image:
    name: aquasec/trivy:latest
    entrypoint: [""]
  script:
    - trivy fs --exit-code 1 --scanners vuln,secret --severity HIGH,CRITICAL .
  artifacts:
    reports:
      container_scanning: trivy-report.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }
        stage('Security Scan') {
            steps {
                sh '''
                    trivy image \
                        --exit-code 1 \
                        --severity CRITICAL \
                        --format json \
                        -o trivy-report.json \
                        myapp:${BUILD_NUMBER}
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-report.json'
                }
            }
        }
    }
}
```

## Ignoring Findings

### Using .trivyignore File

Create `.trivyignore` in your project root:

```
# Ignore specific CVEs
CVE-2023-12345
CVE-2024-67890

# Ignore by ID pattern
GHSA-*

# Ignore secret findings by ID
generic-api-key
aws-access-key-id

# Ignore misconfig by ID
DS002
KSV001
```

### Using Inline Annotations

In Dockerfile:
```dockerfile
# trivy:ignore:DS002
USER root
```

In Kubernetes YAML:
```yaml
metadata:
  annotations:
    # trivy:ignore:KSV001
    app: myapp
```

In Terraform:
```hcl
# trivy:ignore:AVD-AWS-0086
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
```

### Command Line Filtering

```bash
# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed alpine:latest

# Use custom ignore file
trivy image --ignorefile .trivyignore-custom alpine:latest

# Skip specific vulnerabilities
trivy image --skip-vuln-ids CVE-2023-12345 alpine:latest
```

## Interpreting Results

### Severity Levels

| Severity | CVSS Score | Description | Action |
|----------|------------|-------------|--------|
| **CRITICAL** | 9.0 - 10.0 | Exploitable, high impact | Immediate fix required |
| **HIGH** | 7.0 - 8.9 | Significant risk | Fix before deployment |
| **MEDIUM** | 4.0 - 6.9 | Moderate risk | Plan remediation |
| **LOW** | 0.1 - 3.9 | Limited risk | Document and monitor |
| **UNKNOWN** | N/A | CVSS not available | Manual assessment |

### Example JSON Output Analysis

```bash
# Get summary of vulnerabilities by severity
cat results.json | jq '.Results[].Vulnerabilities | group_by(.Severity) | map({severity: .[0].Severity, count: length})'

# List all CRITICAL vulnerabilities
cat results.json | jq '.Results[].Vulnerabilities[] | select(.Severity == "CRITICAL") | {package: .PkgName, vuln: .VulnerabilityID, title: .Title}'

# Get fixable vulnerabilities
cat results.json | jq '.Results[].Vulnerabilities[] | select(.FixedVersion != null) | {vuln: .VulnerabilityID, current: .InstalledVersion, fixed: .FixedVersion}'
```

### Understanding Secret Findings

```
SECRET DETECTION OUTPUT:
+----------+-------------------------------------------+----------+
| Category |            Secret                         | Severity |
+----------+-------------------------------------------+----------+
| AWS      | AKIAIOSFODNN7EXAMPLE                      | CRITICAL |
| GitHub   | ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  | HIGH     |
| Generic  | password = "admin123"                     | MEDIUM   |
+----------+-------------------------------------------+----------+
```

### Understanding Misconfiguration Findings

```
MISCONFIGURATION OUTPUT:
+----------+------------------------------------------+----------+---------+
| Type     | Title                                    | Severity | Success |
+----------+------------------------------------------+----------+---------+
| Dockerfile| Ensure COPY --chown flag is used        | LOW      | FAIL    |
| Dockerfile| Ensure non-root user is used            | HIGH     | FAIL    |
| Terraform | S3 bucket has logging disabled          | MEDIUM   | FAIL    |
| K8s      | Container should not run as root         | HIGH     | FAIL    |
+----------+------------------------------------------+----------+---------+
```

## Limitations

### Known Limitations

1. **No Source Code Vulnerability Scanning**: Trivy analyzes package manifests and dependencies, not source code logic. Use `bandit` for Python, `graudit` for multi-language.

2. **No Malware Detection**: Detects known CVEs and secrets, not actively malicious code. Use `guarddog` for malicious package detection.

3. **Database Freshness**: Vulnerability database must be updated for latest CVEs. Use `trivy image --download-db-only` to pre-fetch.

4. **False Positives in Secrets**: Generic regex may flag non-sensitive strings. Review findings manually.

5. **Limited Custom Rule Support**: Built-in checks; custom rules require Rego policies.

6. **Network Required for DB Updates**: First run downloads vulnerability database (~200MB). Use `--offline-scan` with cached DB for air-gapped environments.

7. **Platform-Specific Results**: Container scans detect vulnerabilities for scanned platform. Use `--platform` to specify target.

### Performance Optimization

```bash
# Download database in advance
trivy image --download-db-only

# Use offline scan with cached database
trivy image --offline-scan alpine:latest

# Skip package types not needed
trivy fs --pkg-types os ./

# Increase timeout for large images
trivy image --timeout 15m large-image:latest

# Use cache directory for faster subsequent scans
trivy image --cache-dir ~/.trivy/cache alpine:latest
```

## Combining with Other Security Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| **Trivy** | Container/IaC/secrets scanning | All cloud-native projects |
| **Bandit** | Python source code vulnerabilities | Python projects |
| **GuardDog** | Malicious package detection | Before installing deps |
| **Dependency-Check** | Java/.NET CVE scanning | Java/.NET projects |
| **Graudit** | Multi-language code patterns | Source code audit |
| **ShellCheck** | Shell script security | CI/CD scripts |

### Recommended Combined Audit

```bash
#!/bin/bash
# Comprehensive security audit

echo "=== Trivy: Container Image ==="
trivy image myapp:latest

echo "=== Trivy: Filesystem Dependencies ==="
trivy fs --scanners vuln ./

echo "=== Trivy: Secrets ==="
trivy fs --scanners secret ./

echo "=== Trivy: IaC Misconfigurations ==="
trivy config ./infra/

echo "=== Bandit: Python Code ==="
[ -d ./src ] && bandit -r ./src

echo "=== GuardDog: Package Integrity ==="
[ -f requirements.txt ] && guarddog pypi verify requirements.txt
[ -f package-lock.json ] && guarddog npm verify package-lock.json
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Slow first scan | DB download required; use `trivy image --download-db-only` to pre-fetch |
| No vulnerabilities found | Check if packages are detected: `trivy image --list-all-pkgs <image>` |
| Permission denied (Docker) | Run with sudo or add user to docker group |
| Cannot pull image | Check registry credentials, use `--username` and `--password` |
| Timeout errors | Increase with `--timeout 15m` |
| Air-gapped environment | Pre-download DB, then use `--offline-scan` |
| Too many findings | Use `--severity HIGH,CRITICAL` and `--ignore-unfixed` |
| Secret false positives | Add entries to `.trivyignore` |

## Additional Resources

- [Official Documentation](https://trivy.dev/docs/latest/)
- [GitHub Repository](https://github.com/aquasecurity/trivy)
- [GitHub Action](https://github.com/aquasecurity/trivy-action)
- [VS Code Extension](https://github.com/aquasecurity/trivy-vscode-extension)
- [Kubernetes Operator](https://github.com/aquasecurity/trivy-operator)
- [Scanning Coverage](https://trivy.dev/docs/latest/coverage/)
- [Examples: Malicious Patterns](./examples/malicious-patterns.md)
```
