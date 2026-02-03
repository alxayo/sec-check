---
name: dependency-check-security-scan
description: Scan project dependencies for known vulnerabilities (CVEs) using OWASP Dependency-Check. (1) Primary use for Software Composition Analysis (SCA) of Java (.jar, .war, .ear), .NET (.dll, .exe, .nupkg), JavaScript (package.json, .js), Python (requirements.txt), Ruby (Gemfile.lock), and Go (go.mod) projects. (2) Detects CVEs from NVD, CISA KEV, OSS Index, RetireJS. (3) Use for dependency audits, CI/CD security gates, compliance scanning, supply chain risk assessment. Do NOT use for source code vulnerabilities (use bandit, graudit) or malicious package detection (use guarddog).
---

# OWASP Dependency-Check Security Scanning Skill

This skill enables scanning project dependencies for **known vulnerabilities** using **OWASP Dependency-Check** - a Software Composition Analysis (SCA) tool that identifies CVEs in third-party libraries by matching dependencies to the National Vulnerability Database (NVD).

> **Key Distinction**: Dependency-Check detects **known vulnerabilities (CVEs)** in dependencies. For **malicious package detection** (malware, supply chain attacks), use `guarddog`. For **source code vulnerabilities**, use `bandit` (Python), `graudit` (multi-language), or `shellcheck` (shell scripts).

## Quick Reference

| Task | Command |
|------|---------|
| Scan project directory | `dependency-check.sh --scan ./ --out ./reports` |
| Scan with NVD API key | `dependency-check.sh --scan ./ --nvdApiKey YOUR_KEY` |
| Fail on high severity (CVSS ≥ 7) | `dependency-check.sh --scan ./ --failOnCVSS 7` |
| JSON output | `dependency-check.sh --scan ./ --format JSON --prettyPrint` |
| SARIF output for CI/CD | `dependency-check.sh --scan ./ --format SARIF` |
| Update database only | `dependency-check.sh --updateonly` |
| Use suppression file | `dependency-check.sh --scan ./ --suppression ./suppression.xml` |
| Docker scan | `docker run -v $(pwd):/src owasp/dependency-check --scan /src` |

## When to Use This Skill

**PRIMARY USE CASES:**
- Audit third-party dependencies for known CVEs before deployment
- CI/CD security gates requiring vulnerability-free dependencies
- Compliance scanning (SOC2, PCI-DSS, HIPAA) requiring SCA
- Supply chain risk assessment for software bill of materials (SBOM)
- Investigating security advisories for affected dependencies
- Pre-merge checks for dependency updates

**SUPPORTED ECOSYSTEMS:**
- Java/Kotlin: .jar, .war, .ear, Maven pom.xml, Gradle
- .NET/C#: .dll, .exe, .nupkg, packages.config, *.csproj
- JavaScript/Node.js: package.json, package-lock.json, .js files
- Python: requirements.txt, setup.py, PKG-INFO (experimental)
- Ruby: Gemfile.lock, *.gemspec (experimental)
- Go: go.mod, Gopkg.lock (experimental)
- PHP: composer.lock (experimental)
- Swift: Package.swift (experimental)
- Dart: pubspec.yaml (experimental)

**DO NOT USE FOR:**
- Detecting malicious packages/malware → use `guarddog`
- Scanning your own source code for vulnerabilities → use `bandit`, `graudit`
- Shell script security → use `shellcheck`
- Secrets detection → use `graudit -d secrets`

## Decision Tree: Choosing the Right Tool

```
What are you analyzing?
│
├── Third-party dependencies for KNOWN CVEs?
│   └── dependency-check --scan ./project
│
├── Third-party packages for MALWARE/supply chain attacks?
│   └── guarddog pypi/npm scan <package>
│
├── Your own source code?
│   ├── Python → bandit -r ./src
│   ├── Multi-language → graudit -d <lang> ./src
│   └── Shell scripts → shellcheck *.sh
│
└── Combined audit?
    ├── Step 1: dependency-check (CVEs in dependencies)
    ├── Step 2: guarddog (malware in packages)
    └── Step 3: bandit/graudit (source code vulnerabilities)
```

## Prerequisites

### Installation Options

**Option 1: Homebrew (macOS - Recommended)**
```bash
brew install dependency-check
dependency-check --help
```

**Option 2: CLI Standalone Download**
```bash
# Get latest version
VERSION=$(curl -s https://dependency-check.github.io/DependencyCheck/current.txt)

# Download and extract
curl -Ls "https://github.com/dependency-check/DependencyCheck/releases/download/v$VERSION/dependency-check-$VERSION-release.zip" -o dependency-check.zip
unzip dependency-check.zip

# Run (Linux/macOS)
./dependency-check/bin/dependency-check.sh --help

# Run (Windows)
.\dependency-check\bin\dependency-check.bat --help
```

**Option 3: Docker (No Local Install)**
```bash
docker pull owasp/dependency-check:latest

# Create alias for convenience
alias dependency-check='docker run --rm -v "$(pwd):/src" -v "$HOME/.dependency-check:/usr/share/dependency-check/data" owasp/dependency-check'
```

**Option 4: Maven Plugin**
```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>12.2.0</version>
</plugin>
```
```bash
mvn org.owasp:dependency-check-maven:check
```

**Option 5: Gradle Plugin**
```groovy
plugins {
    id 'org.owasp.dependencycheck' version '12.2.0'
}
```
```bash
./gradlew dependencyCheckAnalyze
```

### NVD API Key (Highly Recommended)

**Without an API key, database updates are extremely slow (rate limited).**

1. Register at: https://nvd.nist.gov/developers/request-an-api-key
2. Set via command line: `--nvdApiKey YOUR_KEY`
3. Or environment variable: `export NVD_API_KEY=your-key`

## Core Scanning Commands

### Basic Project Scan

```bash
# Scan current directory with HTML report
dependency-check.sh --scan ./ --out ./reports --project "MyProject"

# Scan specific paths
dependency-check.sh --scan ./lib --scan ./target --out ./reports

# Scan with NVD API key (recommended)
dependency-check.sh --scan ./ --out ./reports --nvdApiKey $NVD_API_KEY
```

### Output Formats

```bash
# HTML report (default, human-readable)
dependency-check.sh --scan ./ --format HTML --out ./reports

# JSON report (for automation)
dependency-check.sh --scan ./ --format JSON --prettyPrint --out ./reports

# SARIF report (for GitHub Security, CI/CD)
dependency-check.sh --scan ./ --format SARIF --out ./reports

# Multiple formats at once
dependency-check.sh --scan ./ --format HTML --format JSON --format SARIF --out ./reports

# All formats
dependency-check.sh --scan ./ --format ALL --out ./reports
```

### CI/CD Integration Commands

```bash
# Fail build if any CVE has CVSS score >= 7 (HIGH or CRITICAL)
dependency-check.sh --scan ./ --failOnCVSS 7 --format SARIF --out ./reports

# Fail on CRITICAL only (CVSS >= 9)
dependency-check.sh --scan ./ --failOnCVSS 9 --format JSON --out ./reports

# With suppression file for known false positives
dependency-check.sh --scan ./ --suppression ./suppression.xml --failOnCVSS 7
```

### Docker Scanning

```bash
# Basic Docker scan
docker run --rm \
    -v $(pwd):/src:z \
    -v $(pwd)/reports:/report:z \
    -v $HOME/.dependency-check:/usr/share/dependency-check/data:z \
    owasp/dependency-check:latest \
    --scan /src \
    --format HTML \
    --format JSON \
    --out /report \
    --project "MyProject"

# With NVD API key
docker run --rm \
    -e NVD_API_KEY=$NVD_API_KEY \
    -v $(pwd):/src:z \
    -v $(pwd)/reports:/report:z \
    owasp/dependency-check:latest \
    --scan /src \
    --nvdApiKey $NVD_API_KEY \
    --out /report
```

### Database Management

```bash
# Update database only (no scan)
dependency-check.sh --updateonly --nvdApiKey $NVD_API_KEY

# Purge and rebuild database
dependency-check.sh --purge
dependency-check.sh --updateonly --nvdApiKey $NVD_API_KEY

# Skip update during scan (use cached data)
dependency-check.sh --scan ./ --noupdate
```

## CLI Options Reference

| Short | Long | Description |
|-------|------|-------------|
| `-s` | `--scan <path>` | Path to scan (can specify multiple) |
| `-o` | `--out <path>` | Output directory for reports |
| `-f` | `--format <fmt>` | Output format: HTML, XML, CSV, JSON, JUNIT, SARIF, GITLAB, ALL |
| | `--project <name>` | Project name for reports |
| | `--nvdApiKey <key>` | NVD API key (highly recommended) |
| | `--failOnCVSS <score>` | Exit code 1 if CVSS >= score (0-10) |
| | `--suppression <file>` | Path to suppression XML file |
| | `--exclude <pattern>` | Ant-style pattern to exclude |
| `-n` | `--noupdate` | Skip database update |
| | `--updateonly` | Update database only, no scan |
| | `--purge` | Delete local database |
| | `--prettyPrint` | Format JSON/XML output |
| | `--enableExperimental` | Enable experimental analyzers |
| `-l` | `--log <file>` | Write verbose log to file |
| `-h` | `--help` | Show help |
| | `--advancedHelp` | Show all options |

## Available Analyzers

### Production Analyzers (Enabled by Default)

| Analyzer | File Types | Description |
|----------|------------|-------------|
| **Archive** | .zip, .tar, .gz, .jar, .war, .ear | Extracts and scans archive contents |
| **Jar** | .jar, .war, .ear | Analyzes Java artifacts via manifest/pom |
| **Node.js** | package.json | Parses npm dependencies |
| **Node Audit** | package-lock.json | Queries npm audit API |
| **Assembly (.NET)** | .dll, .exe | Analyzes .NET assemblies (requires dotnet 8.0) |
| **Nuget** | packages.config, .nuspec | .NET package dependencies |
| **MSBuild** | .csproj, .vbproj | .NET project files |
| **RetireJS** | .js | Detects vulnerable JavaScript libraries |
| **OSS Index** | All | Queries Sonatype vulnerability database |
| **Ruby Bundler** | Gemfile.lock | Ruby dependencies (requires bundle-audit) |

### Experimental Analyzers (Enable with `--enableExperimental`)

| Analyzer | File Types |
|----------|------------|
| Python | requirements.txt, setup.py, PKG-INFO |
| Go mod | go.mod |
| Composer (PHP) | composer.lock |
| CocoaPods | .podspec |
| Swift | Package.swift |
| Dart | pubspec.yaml, pubspec.lock |
| CMake | CMakeLists.txt |
| Autoconf | configure, configure.ac |

## Vulnerability Sources

OWASP Dependency-Check aggregates vulnerability data from multiple sources:

| Source | Description | Data Type |
|--------|-------------|-----------|
| **NVD (NIST)** | National Vulnerability Database - primary CVE source | CVE, CVSS, CPE |
| **CISA KEV** | Known Exploited Vulnerabilities catalog | Actively exploited CVEs |
| **Sonatype OSS Index** | Supplemental vulnerability database | Additional CVEs |
| **RetireJS** | JavaScript-specific vulnerability database | JS library CVEs |
| **NPM Audit** | GitHub Advisory Database via npm | Node.js CVEs |

## MITRE ATT&CK Mappings

Vulnerabilities detected by Dependency-Check map to these attack techniques:

| Technique ID | Name | Relevance |
|--------------|------|-----------|
| **T1195.001** | Supply Chain Compromise: Compromise Software Dependencies | Primary - vulnerable dependencies |
| **T1195.002** | Supply Chain Compromise: Compromise Software Supply Chain | Compromised package versions |
| **T1190** | Exploit Public-Facing Application | Web framework/library vulnerabilities |
| **T1203** | Exploitation for Client Execution | Client-side library vulnerabilities |
| **T1059** | Command and Scripting Interpreter | CVEs enabling code execution |

## Workflow for Security Audit

### Quick Scan (Development)

```bash
# Fast scan with cached database
dependency-check.sh --scan ./ --noupdate --format HTML --out ./reports
```

### Standard Scan (Pre-Deployment)

```bash
# Full scan with latest data
dependency-check.sh --scan ./ \
    --nvdApiKey $NVD_API_KEY \
    --format HTML --format JSON \
    --out ./reports \
    --project "MyApp-v1.0"
```

### CI/CD Gate Scan

```bash
# Fail on high/critical vulnerabilities
dependency-check.sh --scan ./ \
    --nvdApiKey $NVD_API_KEY \
    --failOnCVSS 7 \
    --suppression ./suppression.xml \
    --format SARIF \
    --out ./reports
```

### Complete Security Audit Workflow

```bash
# Step 1: Scan dependencies for known CVEs
dependency-check.sh --scan ./ --format JSON --out ./reports --nvdApiKey $NVD_API_KEY

# Step 2: Check for malicious packages (if Python/Node.js)
guarddog pypi verify requirements.txt
guarddog npm verify package-lock.json

# Step 3: Scan source code for vulnerabilities
bandit -r ./src -f json -o bandit-report.json  # Python
graudit -d secrets ./src                        # Secrets detection

# Step 4: Review results
cat ./reports/dependency-check-report.json | jq '.dependencies[] | select(.vulnerabilities)'
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Dependency Check

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Cache Dependency-Check data
        uses: actions/cache@v4
        with:
          path: ~/.dependency-check
          key: ${{ runner.os }}-dc-${{ github.run_id }}
          restore-keys: ${{ runner.os }}-dc-
      
      - name: Run Dependency-Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: '${{ github.repository }}'
          path: '.'
          format: 'HTML,JSON,SARIF'
          args: >
            --nvdApiKey ${{ secrets.NVD_API_KEY }}
            --failOnCVSS 7
            --enableExperimental
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/dependency-check-report.sarif
      
      - name: Upload Reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: dependency-check-reports
          path: reports/
```

### GitLab CI

```yaml
dependency-check:
  image: owasp/dependency-check:latest
  stage: test
  script:
    - /usr/share/dependency-check/bin/dependency-check.sh
        --scan .
        --format GITLAB
        --format JSON
        --out ./reports
        --nvdApiKey $NVD_API_KEY
        --failOnCVSS 7
  artifacts:
    paths:
      - reports/
    reports:
      dependency_scanning: reports/dependency-check-report.json
  allow_failure: true
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Dependency Check') {
            steps {
                dependencyCheck additionalArguments: '''
                    --scan .
                    --format HTML
                    --format JSON
                    --nvdApiKey ${NVD_API_KEY}
                    --failOnCVSS 7
                ''', odcInstallation: 'dependency-check'
            }
            post {
                always {
                    dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                }
            }
        }
    }
}
```

## Managing False Positives

### Suppression File Format

Create `suppression.xml` to exclude known false positives:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd">
   
   <!-- Suppress by SHA1 hash and CPE -->
   <suppress>
      <notes><![CDATA[False positive - driver CVE applies to server, not client]]></notes>
      <sha1>66734244CE86857018B023A8C56AE0635C56B6A1</sha1>
      <cpe>cpe:/a:mysql:mysql:5.7</cpe>
   </suppress>
   
   <!-- Suppress specific CVE -->
   <suppress>
      <notes><![CDATA[Not applicable - we don't use the affected feature]]></notes>
      <cve>CVE-2024-12345</cve>
   </suppress>
   
   <!-- Suppress by file path pattern -->
   <suppress>
      <notes><![CDATA[Test dependencies only]]></notes>
      <filePath regex="true">.*test.*\.jar</filePath>
      <cvssBelow>7</cvssBelow>
   </suppress>
   
   <!-- Temporary suppression with expiration -->
   <suppress until="2026-06-01Z">
      <notes><![CDATA[Pending upgrade - ticket PROJ-123]]></notes>
      <gav regex="true">^com\.example:vulnerable-lib:.*$</gav>
   </suppress>
   
</suppressions>
```

### Using Suppression File

```bash
dependency-check.sh --scan ./ --suppression ./suppression.xml --out ./reports
```

## Interpreting Results

### HTML Report Sections

1. **Summary**: Total dependencies, vulnerable count, severity breakdown
2. **Dependencies**: List of all scanned files with identification confidence
3. **Vulnerabilities**: CVE details with CVSS scores, descriptions, references

### JSON Report Key Fields

```bash
# Extract vulnerable dependencies
cat report.json | jq '.dependencies[] | select(.vulnerabilities != null) | {file: .fileName, vulns: [.vulnerabilities[].name]}'

# List all HIGH/CRITICAL CVEs
cat report.json | jq '.dependencies[].vulnerabilities[]? | select(.cvssv3.baseScore >= 7) | {cve: .name, score: .cvssv3.baseScore}'

# Count by severity
cat report.json | jq '[.dependencies[].vulnerabilities[]?] | group_by(.severity) | map({severity: .[0].severity, count: length})'
```

### Severity Levels

| CVSS Score | Severity | Action Required |
|------------|----------|-----------------|
| 9.0 - 10.0 | CRITICAL | Immediate remediation required |
| 7.0 - 8.9 | HIGH | Remediate before next release |
| 4.0 - 6.9 | MEDIUM | Plan remediation |
| 0.1 - 3.9 | LOW | Assess risk, document decision |
| 0.0 | NONE | Informational only |

## Limitations

### Known Limitations

1. **False Positives**: CPE-based matching can incorrectly identify libraries. Database drivers often match server CVEs. Use suppression files.

2. **False Negatives**: Libraries with insufficient metadata may not be identified. Built-from-source artifacts may differ from published versions.

3. **No Hash-Based Matching**: Does not use file hashes for identification, relying on metadata/evidence instead.

4. **Initial Download Time**: First run requires 5-20 minutes to download NVD data (faster with API key).

5. **Rate Limiting**: NVD API enforces rate limits. Multiple concurrent builds with same API key may fail with 403 errors.

6. **Internet Required**: Must access NVD, CISA, OSS Index for vulnerability data.

7. **External Tool Dependencies**:
   - .NET analysis requires dotnet 8.0 runtime
   - Ruby analysis requires bundle-audit gem
   - Node.js analysis requires npm/yarn

8. **No Malware Detection**: Detects only known CVEs, not malicious code. Use `guarddog` for malware detection.

### Performance Optimization

```bash
# Parallel execution (set Java heap)
export JAVA_OPTS="-Xmx4g"

# Use NVD API key (required for reasonable speed)
dependency-check.sh --scan ./ --nvdApiKey $NVD_API_KEY

# Cache database between runs
# Database stored in ~/.dependency-check by default

# Skip update for quick scans (use cached data)
dependency-check.sh --scan ./ --noupdate
```

## Combining with Other Security Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| **Dependency-Check** | Known CVEs in dependencies | Every build/release |
| **GuardDog** | Malicious packages | Before installing new deps |
| **Bandit** | Python code vulnerabilities | Python projects |
| **Graudit** | Multi-language code audit | All source code |
| **ShellCheck** | Shell script security | CI/CD scripts, installers |

### Complete Supply Chain Audit

```bash
#!/bin/bash
# Full supply chain security audit

echo "=== Step 1: Dependency CVE Scan ==="
dependency-check.sh --scan ./ --format JSON --out ./reports --nvdApiKey $NVD_API_KEY

echo "=== Step 2: Malicious Package Detection ==="
[ -f requirements.txt ] && guarddog pypi verify requirements.txt
[ -f package-lock.json ] && guarddog npm verify package-lock.json

echo "=== Step 3: Source Code Security ==="
find . -name "*.py" -type f | head -1 && bandit -r ./src -f json -o bandit.json
graudit -d secrets ./

echo "=== Step 4: Shell Script Audit ==="
find . -name "*.sh" -exec shellcheck {} \;

echo "=== Audit Complete ==="
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Very slow database update | Use NVD API key: `--nvdApiKey YOUR_KEY` |
| 403 Forbidden errors | Rate limited - wait or use dedicated API key per pipeline |
| .NET assemblies not scanned | Install dotnet 8.0 runtime |
| Package not identified | Low evidence - library built from source or missing metadata |
| Too many false positives | Create suppression.xml file |
| Out of memory | Set `JAVA_OPTS="-Xmx4g"` |
| Experimental analyzers needed | Add `--enableExperimental` flag |

## Additional Resources

- [Official Documentation](https://owasp.org/www-project-dependency-check/)
- [GitHub Repository](https://github.com/dependency-check/DependencyCheck)
- [NVD API Key Registration](https://nvd.nist.gov/developers/request-an-api-key)
- [Suppression File Examples](https://jeremylong.github.io/DependencyCheck/general/suppression.html)
- [Common Vulnerabilities Reference](./examples/common-vulnerabilities.md)
