---
title: Scanners
layout: default
nav_order: 5
description: "Reference for all security scanners supported by Sec-Check — what they detect, languages they cover, and how to install them."
---

# Security Scanners Reference
{: .no_toc }

Sec-Check orchestrates these industry-standard security tools. Install the ones relevant to your stack for best results.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## Scanner Overview

| Scanner | Languages / Targets | Detection Focus | Required? |
|:--------|:-------------------|:----------------|:----------|
| [Bandit](#bandit) | Python | AST analysis — dangerous functions, injection, deserialization | No |
| [Graudit](#graudit) | 15+ languages | Pattern matching — secrets, credentials, sinks | No |
| [GuardDog](#guarddog) | PyPI, npm | Supply chain — malicious packages, typosquatting | No |
| [ShellCheck](#shellcheck) | Bash, sh | Shell scripts — injection, unquoted variables | No |
| [Trivy](#trivy) | Containers, IaC, deps | CVEs, secrets, SBOM, misconfigurations | No |
| [ESLint](#eslint) | JavaScript, TypeScript | XSS, injection, ReDoS, prototype pollution | No |
| [Checkov](#checkov) | IaC (Terraform, K8s, etc.) | Cloud misconfigurations, compliance | No |
| [Dependency-Check](#dependency-check) | Java, .NET, JS, Python, Ruby, Go | Known CVEs in dependencies (NVD) | No |

{: .note }
> No scanners are strictly required. Sec-Check works with whatever is available — the agent automatically detects installed tools and adapts its scanning strategy. However, more tools = better coverage.

---

## Bandit
{: #bandit }

**Python AST-based security analysis**

Bandit performs abstract syntax tree (AST) analysis of Python code to find common security issues.

### What It Detects

- `eval()`, `exec()`, `compile()` usage
- Pickle/YAML deserialization
- Subprocess with `shell=True`
- SQL injection patterns
- Hardcoded passwords and secrets
- Weak cryptography (MD5, SHA1 for security)
- Assert statements used for security checks

### Installation

```bash
pip install bandit
```

### Verification

```bash
bandit --version
# bandit 1.9.x
```

### Manual Usage

```bash
bandit -r ./my_project -f json
```

---

## Graudit
{: #graudit }

**Multi-language pattern-based security auditing**

Graudit uses grep-based pattern matching against databases of known dangerous patterns across 15+ programming languages.

### What It Detects

- Credentials and secrets (API keys, passwords, tokens)
- SQL injection sinks
- XSS sinks
- Command execution functions
- Buffer overflow functions (C/C++)
- Dangerous functions per language

### Supported Languages

C/C++, Go, Java, JavaScript, TypeScript, Python, PHP, Ruby, Perl, .NET/C#, SQL, and more.

### Installation

```bash
git clone https://github.com/wireghoul/graudit.git ~/graudit
export PATH="$PATH:$HOME/graudit"
```

Add the `export` line to your `.bashrc` or `.zshrc` for persistence.

### Verification

```bash
graudit --version
# graudit 4.0
```

### Manual Usage

```bash
graudit -d secrets ./my_project   # Scan for secrets
graudit -d sql ./my_project       # Scan for SQL injection
graudit -d xss ./my_project       # Scan for XSS
```

---

## GuardDog
{: #guarddog }

**Supply chain and malicious package detection**

GuardDog detects malicious packages and supply chain attacks in Python (PyPI) and Node.js (npm) ecosystems.

### What It Detects

- Malware and backdoors in packages
- Data exfiltration and reverse shells
- Typosquatting (packages with similar names to popular ones)
- Obfuscated payloads
- Compromised maintainer accounts
- Post-install script attacks

### Installation

```bash
pip install guarddog
```

### Verification

```bash
guarddog --version
# guarddog 2.x.x
```

### Manual Usage

```bash
guarddog pypi verify requests          # Check a specific package
guarddog pypi scan requirements.txt    # Scan a requirements file
guarddog npm verify lodash             # Check an npm package
```

---

## ShellCheck
{: #shellcheck }

**Shell script static analysis**

ShellCheck analyzes bash/sh scripts for bugs, pitfalls, and security issues.

### What It Detects

- Command injection via unquoted variables
- Arbitrary code execution patterns
- Unsafe `rm` operations
- Dangerous `PATH` manipulation
- Reverse shell patterns
- Data exfiltration via curl/wget

### Installation

```bash
# Ubuntu/Debian
sudo apt install shellcheck

# macOS
brew install shellcheck

# Other
# See https://github.com/koalaman/shellcheck#installing
```

### Verification

```bash
shellcheck --version
# ShellCheck 0.11.x
```

### Manual Usage

```bash
shellcheck ./script.sh
shellcheck -f json ./script.sh  # JSON output
```

---

## Trivy
{: #trivy }

**Comprehensive vulnerability scanner**

Trivy scans containers, filesystems, IaC, and dependencies for vulnerabilities, misconfigurations, and secrets.

### What It Detects

- CVEs in OS packages and application dependencies
- Hardcoded secrets and credentials
- IaC misconfigurations (Terraform, Kubernetes, Dockerfile)
- SBOM (Software Bill of Materials) generation
- License compliance issues

### Installation

See the [official installation guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/).

```bash
# Ubuntu/Debian
sudo apt-get install trivy

# macOS
brew install trivy

# Docker
docker pull aquasec/trivy
```

### Verification

```bash
trivy --version
```

### Manual Usage

```bash
trivy fs ./my_project                    # Filesystem scan
trivy image my-app:latest                # Container image scan
trivy config ./terraform/                # IaC scan
trivy fs --scanners secret ./my_project  # Secrets only
```

---

## ESLint
{: #eslint }

**JavaScript/TypeScript security analysis**

ESLint with security plugins detects vulnerabilities in JavaScript and TypeScript code.

### What It Detects

- Code injection (`eval`, `Function`, `setTimeout` with strings)
- XSS (`innerHTML`, `dangerouslySetInnerHTML`)
- Command injection (`child_process` with user input)
- Regular expression denial of service (ReDoS)
- Path traversal
- Insecure cryptography
- Prototype pollution

### Installation

```bash
npm install -g eslint eslint-plugin-security eslint-plugin-no-unsanitized
```

### Verification

```bash
eslint --version
```

---

## Checkov
{: #checkov }

**Infrastructure as Code security analysis**

Checkov scans IaC files for security misconfigurations and compliance violations.

### What It Detects

- Cloud misconfigurations (AWS, Azure, GCP)
- Exposed secrets in IaC
- Overly permissive IAM policies
- Unencrypted storage
- Public access risks
- Container security issues
- Compliance violations (CIS, SOC2, HIPAA, PCI-DSS)

### Supported Frameworks

Terraform, CloudFormation, Kubernetes, Dockerfiles, Helm charts, ARM/Bicep templates, GitHub Actions, GitLab CI.

### Installation

```bash
pip install checkov
```

### Verification

```bash
checkov --version
```

### Manual Usage

```bash
checkov -d ./terraform/
checkov -f Dockerfile
checkov --framework kubernetes -d ./k8s/
```

---

## Dependency-Check
{: #dependency-check }

**Software Composition Analysis (SCA)**

OWASP Dependency-Check identifies known vulnerabilities (CVEs) in project dependencies.

### What It Detects

- Known CVEs from NVD, CISA KEV, OSS Index
- Vulnerable library versions
- Retired JavaScript libraries (via RetireJS)

### Supported Ecosystems

Java (.jar, .war, .ear), .NET (.dll, .exe, .nupkg), JavaScript (package.json), Python (requirements.txt), Ruby (Gemfile.lock), Go (go.mod).

### Installation

See the [official installation guide](https://owasp.org/www-project-dependency-check/).

### Manual Usage

```bash
dependency-check --project my-app --scan ./my_project
```

---

## Scanner Selection

Sec-Check automatically selects scanners based on the file types found:

| File Type | Scanners Used |
|:----------|:-------------|
| `.py` | Bandit, Graudit |
| `.js`, `.ts`, `.jsx`, `.tsx` | ESLint, Graudit |
| `.sh`, `.bash` | ShellCheck, Graudit |
| `requirements.txt`, `package.json` | GuardDog, Dependency-Check |
| `Dockerfile`, `*.tf`, `*.yaml` (K8s) | Checkov, Trivy |
| `.java`, `.cs`, `.go`, `.rb`, `.php` | Graudit |
| Container images | Trivy |
| All files | Graudit (secrets database) |
