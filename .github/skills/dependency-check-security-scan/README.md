# OWASP Dependency-Check Security Scan Skill

This Agent Skill enables GitHub Copilot to scan project dependencies for known vulnerabilities (CVEs) using OWASP Dependency-Check - an industry-standard Software Composition Analysis (SCA) tool.

## What This Skill Does

- Scans project dependencies against the National Vulnerability Database (NVD)
- Identifies libraries with known CVEs across multiple ecosystems
- Generates reports in HTML, JSON, SARIF formats for CI/CD integration
- Maps vulnerabilities to CVSS scores for prioritization
- Supports suppression files for managing false positives

## Supported Ecosystems

| Ecosystem | Files Analyzed |
|-----------|----------------|
| Java/Kotlin | .jar, .war, .ear, pom.xml, build.gradle |
| .NET/C# | .dll, .exe, .nupkg, packages.config, *.csproj |
| JavaScript/Node.js | package.json, package-lock.json, .js files |
| Python | requirements.txt, setup.py (experimental) |
| Ruby | Gemfile.lock (experimental) |
| Go | go.mod (experimental) |
| PHP | composer.lock (experimental) |

## Requirements

- OWASP Dependency-Check CLI, Maven plugin, Gradle plugin, or Docker
- NVD API key (highly recommended for performance)
- Java 8+ runtime (for CLI)

### Quick Install

```bash
# macOS
brew install dependency-check

# Docker
docker pull owasp/dependency-check:latest

# Manual download
VERSION=$(curl -s https://dependency-check.github.io/DependencyCheck/current.txt)
curl -Ls "https://github.com/dependency-check/DependencyCheck/releases/download/v$VERSION/dependency-check-$VERSION-release.zip" -o dc.zip && unzip dc.zip
```

## Example Prompts

Ask Copilot things like:

- "Scan this project for vulnerable dependencies"
- "Check my dependencies for CVEs"
- "Run a Software Composition Analysis on this project"
- "Find known vulnerabilities in my npm packages"
- "Generate a dependency security report"
- "Check if any Java libraries have security issues"
- "Fail the build if there are high severity CVEs"

## Example CLI Commands

```bash
# Basic scan with HTML report
dependency-check.sh --scan ./ --out ./reports --project "MyApp"

# Scan with NVD API key (recommended)
dependency-check.sh --scan ./ --nvdApiKey YOUR_KEY --out ./reports

# JSON + SARIF output for CI/CD
dependency-check.sh --scan ./ --format JSON --format SARIF --out ./reports

# Fail on high/critical vulnerabilities
dependency-check.sh --scan ./ --failOnCVSS 7 --out ./reports

# Docker scan
docker run -v $(pwd):/src owasp/dependency-check --scan /src --out /src/reports
```

## File Structure

```
.github/skills/dependency-check-security-scan/
├── README.md                         # This file
├── SKILL.md                          # Main skill instructions
└── examples/
    └── common-vulnerabilities.md     # Reference vulnerability patterns
```

## Related Tools

| Tool | Use Case |
|------|----------|
| **Dependency-Check** | Known CVEs in dependencies |
| **GuardDog** | Malicious package detection |
| **Bandit** | Python source code vulnerabilities |
| **Graudit** | Multi-language code audit |

## Resources

- [Official Documentation](https://owasp.org/www-project-dependency-check/)
- [GitHub Repository](https://github.com/dependency-check/DependencyCheck)
- [NVD API Key Registration](https://nvd.nist.gov/developers/request-an-api-key)
