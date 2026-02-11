---
name: sck.tools-advisor
description: Analyze code structure and recommend the best security scanning skill(s) to detect malicious or harmful patterns
argument-hint: '[path to analyze]'
agent: agent
tools: ['read/problems', 'read/readFile', 'search/codebase', 'search/fileSearch', 'search/textSearch', 'search/usages', 'search/listDirectory', 'todo', 'agent', 'execute', 'edit', 'search']
model: Claude Sonnet 4.5
---

# Security Audit Analysis

Analyze the target codebase (${input:target-path:workspace root}) and recommend the optimal security scanning skill(s) to detect malicious, harmful, or vulnerable code patterns.

## Your Task

1. **Analyze** the target codebase to identify languages, frameworks, and dependency files
2. **Review** the available security scanning skills in `.github/skills/`
3. **Recommend** the best skill or combination of skills for comprehensive security coverage
4. **Provide** specific execution guidance for each recommended skill

**Important**: Only analyze and recommend. Do NOT execute the security scans. Your recommendations will be used to run the actual security scans.

---

## Available Security Scanning Skills

Review these skills from the `.github/skills/` folder:

### 1. Bandit Security Scan
- **Skill**: `bandit-security-scan`
- **Skill file**: [.github/skills/bandit-security-scan/SKILL.md](.github/skills/bandit-security-scan/SKILL.md)
- **Language**: Python only
- **Detection capabilities**:
  - Hardcoded passwords and secrets (B105-B107)
  - SQL injection vulnerabilities (B608, B610, B611)
  - Shell injection risks (B602, B605, B609)
  - Insecure deserialization (pickle B301, yaml B506, marshal B302)
  - Weak cryptographic methods (B303-B305, B324)
  - Dangerous function calls (eval B307, exec B102, assert B101)
  - Insecure temporary file creation (B108, B306)
  - Network security issues (B310-B312, B321, B501-B509)
  - XSS vulnerabilities in templates (B701-B703)
- **Framework support**: Django (-t B201,B610,B611,B701,B703), Flask (-t B104,B201,B310,B701)
- **MITRE ATT&CK mapped**: Yes (T1059, T1552, T1190, T1557, T1600, etc.)
- **Best for**: Deep Python code security analysis, AST-based detection
- **NOT for**: Dependencies (use GuardDog), non-Python code (use Graudit)

### 2. GuardDog Security Scan
- **Skill**: `guarddog-security-scan`
- **Skill file**: [.github/skills/guarddog-security-scan/SKILL.md](.github/skills/guarddog-security-scan/SKILL.md)
- **Languages**: Python (PyPI), Node.js (npm)
- **Scan modes**:
  - `scan` - Scan local directory, package archive, or remote package by name
  - `verify` - Audit dependency files (requirements.txt, package-lock.json)
- **Detection capabilities** (Source Code Rules):
  - Malware and malicious packages (`exec-base64`, `code-execution`)
  - Data exfiltration attempts (`exfiltrate-sensitive-data`, `npm-serialize-environment`)
  - Backdoors and reverse shells (`silent-process-execution`, `download-executable`)
  - Credential theft patterns (`suspicious_passwd_access_linux`, `clipboard-access`)
  - Obfuscated code (`obfuscation`, `api-obfuscation`, `steganography`)
  - DLL hijacking (`dll-hijacking`)
- **Detection capabilities** (Metadata Rules):
  - Typosquatting packages (`typosquatting`)
  - Compromised maintainer detection (`potentially_compromised_email_domain`)
  - Repository integrity issues (`repository_integrity_mismatch`)
  - Suspicious package attributes (`release_zero`, `single_python_file`, `bundled_binary`)
- **MITRE ATT&CK mapped**: Yes (T1059, T1027, T1041, T1071, T1574, etc.)
- **Best for**: Supply chain security, malicious package detection, dependency verification, pre-install checks
- **NOT for**: Scanning your own source code vulnerabilities (use Bandit for Python, Graudit for others)

### 3. ShellCheck Security Scan
- **Skill**: `shellcheck-security-scan`
- **Skill file**: [.github/skills/shellcheck-security-scan/SKILL.md](.github/skills/shellcheck-security-scan/SKILL.md)
- **Languages**: Bash, sh, dash, ksh
- **File types**: `*.sh`, `*.bash`, Dockerfiles (RUN commands), `.github/workflows/*.yml`, Makefiles, npm scripts
- **Critical security checks**:
  - SC2086: Unquoted variable expansion (command injection)
  - SC2046: Unquoted command substitution (subshell injection)
  - SC2091: Executing command output (arbitrary code execution)
  - SC2115: Empty variable in `rm -rf` (filesystem wipe)
  - SC2216: Piping to rm (arbitrary file deletion)
  - SC2211: Glob used as command name (arbitrary execution)
  - SC2029: SSH command injection
- **Detection capabilities**:
  - Command injection vulnerabilities
  - Unquoted variable expansions
  - Unsafe glob patterns
  - Dangerous redirections
  - Race conditions
- **MITRE ATT&CK mapped**: Yes (T1059.004, T1027, T1105, T1222.002, T1070.004)
- **Best for**: Shell script security, CI/CD pipelines, Dockerfiles, build scripts
- **Limitations**: Cannot detect obfuscated payloads (base64|bash), use Graudit exec database as complement

### 4. Graudit Security Scan
- **Skill**: `graudit-security-scan`
- **Skill file**: [.github/skills/graudit-security-scan/SKILL.md](.github/skills/graudit-security-scan/SKILL.md)
- **Languages**: Multi-language (17+ supported)
- **Detection capabilities**:
  - Security vulnerabilities via regex pattern matching
  - Dangerous functions across languages
  - Hardcoded secrets and credentials
  - SQL injection patterns
  - Cross-site scripting (XSS)
  - Command execution vulnerabilities
  - Reverse shells, backdoors, data exfiltration patterns
  - Obfuscation (base64, hex encoding, String.fromCharCode)
- **Databases available**:
  - **High priority** (always run for untrusted code): `exec`, `secrets`
  - **Language-specific**: `python`, `js`, `typescript`, `php`, `java`, `c`, `go`, `ruby`, `perl`, `dotnet`
  - **Vulnerability-specific**: `sql`, `xss`
  - **Platform-specific**: `android`, `ios`
  - **General**: `default`
- **Helper scripts**: `graudit-deep-scan.sh` (multi-db scan), `graudit-wrapper.sh` (auto-detect)
- **Best for**: Quick multi-language audits, broad vulnerability sweeps, unknown/mixed codebases, rapid triage
- **NOT for**: Sole scanner when Bandit (Python .py) or ShellCheck (shell .sh) are applicable—use alongside them

### 5. Dependency-Check Security Scan
- **Skill**: `dependency-check-security-scan`
- **Skill file**: [.github/skills/dependency-check-security-scan/SKILL.md](.github/skills/dependency-check-security-scan/SKILL.md)
- **Purpose**: Software Composition Analysis (SCA) for known CVEs in dependencies
- **Supported ecosystems**:
  - **Production**: Java (.jar, .war, .ear, pom.xml, Gradle), .NET (.dll, .exe, .nupkg, packages.config, *.csproj), JavaScript (package.json, package-lock.json), Ruby (Gemfile.lock)
  - **Experimental** (enable with `--enableExperimental`): Python (requirements.txt, setup.py), Go (go.mod), PHP (composer.lock), Swift (Package.swift), Dart (pubspec.yaml)
- **Vulnerability sources**:
  - NVD (NIST) - primary CVE source with CVSS scores
  - CISA KEV - Known Exploited Vulnerabilities catalog
  - Sonatype OSS Index - supplemental vulnerability database
  - RetireJS - JavaScript-specific vulnerabilities
  - NPM Audit - GitHub Advisory Database
- **Output formats**: HTML, JSON, SARIF (for CI/CD), XML, CSV, JUNIT, GITLAB
- **Key features**:
  - CI/CD gates with `--failOnCVSS <score>` (fail on severity threshold)
  - Suppression files for false positive management
  - Docker scanning support
  - SBOM (Software Bill of Materials) generation
- **MITRE ATT&CK mapped**: Yes (T1195.001, T1195.002, T1190, T1203, T1059)
- **Best for**: Compliance scanning (SOC2, PCI-DSS, HIPAA), pre-deployment CVE audits, CI/CD security gates, supply chain risk assessment
- **NOT for**: Malicious package detection (use GuardDog), source code vulnerabilities (use Bandit/Graudit)
- **Key distinction from GuardDog**: Dependency-Check detects **known CVEs** in dependencies; GuardDog detects **malicious packages/malware**

### 6. Checkov Security Scan
- **Skill**: `checkov-security-scan`
- **Skill file**: [.github/skills/checkov-security-scan/SKILL.md](.github/skills/checkov-security-scan/SKILL.md)
- **Purpose**: Infrastructure as Code (IaC) security misconfiguration and compliance violation detection
- **Supported frameworks**:
  - **Terraform**: `.tf`, `.tf.json`, plan files
  - **CloudFormation**: `.yaml`, `.yml`, `.json`, `.template` templates
  - **Kubernetes**: Manifests, Helm charts, Kustomize
  - **Dockerfile**: `Dockerfile`, `Dockerfile.*`
  - **ARM/Bicep**: Azure templates
  - **CI/CD**: GitHub Actions (`.github/workflows/*.yml`), GitLab CI (`.gitlab-ci.yml`), Azure Pipelines, CircleCI, Bitbucket
  - **Other**: Ansible, Argo Workflows, Serverless Framework, OpenAPI/Swagger
- **Detection capabilities**:
  - Overly permissive IAM policies and access controls
  - Unencrypted storage (S3, EBS, RDS, Azure Storage, GCS)
  - Publicly accessible resources (security groups, storage buckets)
  - Security group misconfigurations (open ports 22, 3389, etc.)
  - Container security issues (privileged mode, root user)
  - Missing health checks, logging, and monitoring
  - Hardcoded secrets in IaC configuration
  - CI/CD workflow security issues (unpinned actions, shell injection)
- **Check categories**: 1000+ built-in checks (CKV_AWS_*, CKV_AZURE_*, CKV_GCP_*, CKV_K8S_*, CKV_DOCKER_*, CKV_GHA_*, CKV_SECRET_*)
- **Output formats**: CLI, JSON, SARIF, JUnit XML, CycloneDX SBOM
- **Compliance frameworks**: CIS benchmarks, SOC2, HIPAA, PCI-DSS, ISO 27001
- **MITRE ATT&CK mapped**: Yes (T1530, T1078, T1046, T1190, T1562, T1552, T1610)
- **Best for**: IaC security audits, pre-deployment validation, cloud misconfiguration detection, compliance scanning, CI/CD security gates
- **NOT for**: Application source code vulnerabilities (use Bandit/Graudit), dependency/package audits (use GuardDog/Dependency-Check)
- **Key distinction**: Checkov scans **infrastructure configuration** for misconfigurations; other tools scan **application code** for vulnerabilities

### 7. ESLint Security Scan
- **Skill**: `eslint-security-scan`
- **Skill file**: [.github/skills/eslint-security-scan/SKILL.md](.github/skills/eslint-security-scan/SKILL.md)
- **Purpose**: Security analysis of JavaScript/TypeScript code for vulnerabilities using ESLint with security plugins
- **Languages**: JavaScript, TypeScript
- **File types**: `.js`, `.jsx`, `.ts`, `.tsx`
- **Frameworks supported**: React, Vue, Angular, Node.js, Express, Next.js
- **Detection capabilities**:
  - Code injection (`eval()`, `Function()`, `new Function()`)
  - XSS vulnerabilities (`innerHTML`, `dangerouslySetInnerHTML`, `insertAdjacentHTML`)
  - Command injection (`child_process.exec()`, `child_process.spawn()`)
  - ReDoS (Regular Expression Denial of Service)
  - Path traversal and unsafe file operations
  - Insecure cryptography and weak PRNG
  - Prototype pollution risks
  - Dynamic require/import statements
  - Unsafe regex patterns
  - Timing attack vulnerabilities
- **Security plugins**: eslint-plugin-security, eslint-plugin-no-unsanitized, @typescript-eslint/eslint-plugin
- **Output formats**: JSON, SARIF, HTML, compact, Unix-style
- **MITRE ATT&CK mapped**: Yes (T1059.007, T1059.004, T1083, T1499, T1552, T1129)
- **Best for**: Web apps (React/Vue/Angular), Node.js services, npm package triage, malicious code detection, OWASP Top 10 JavaScript issues
- **NOT for**: Dependency CVEs (use npm audit/Dependency-Check), non-JavaScript code, minified/heavily obfuscated code, malicious npm packages (use GuardDog)
- **Key distinction**: ESLint scans **JavaScript/TypeScript source code** for vulnerabilities; GuardDog detects **malicious npm packages**; Dependency-Check finds **known CVEs**

---

## Quick Decision Flowchart

Use this flowchart for rapid tool selection:

```
START: What's the primary concern?
│
├─► "Is code UNTRUSTED or potentially MALICIOUS?"
│   └─► YES → Graudit (exec+secrets) FIRST, then others
│
├─► "Are there INFRASTRUCTURE AS CODE (IaC) files?"
│   ├─► Terraform (.tf) → Checkov --framework terraform
│   ├─► Kubernetes manifests → Checkov --framework kubernetes
│   ├─► CloudFormation (.yaml/.json) → Checkov --framework cloudformation
│   ├─► Dockerfile → Checkov --framework dockerfile
│   ├─► Helm charts → Checkov --framework helm
│   ├─► GitHub Actions workflows → Checkov --framework github_actions
│   └─► Mixed IaC → Checkov -d . (auto-detect)
│
├─► "Are there DEPENDENCY FILES?" (requirements.txt, package.json, etc.)
│   ├─► Need MALWARE/supply chain attack detection?
│   │   └─► YES → GuardDog verify FIRST
│   └─► Need KNOWN CVE/vulnerability detection?
│       └─► YES → Dependency-Check FIRST
│   (For comprehensive audit: run BOTH GuardDog + Dependency-Check)
│
├─► "Is COMPLIANCE required?" (SOC2, PCI-DSS, HIPAA)
│   ├─► IaC compliance → Checkov with compliance framework flags
│   └─► Dependency compliance → Dependency-Check with --failOnCVSS threshold
│
├─► "What LANGUAGE is the code?"
│   ├─► Python (.py) → Bandit (primary) + Graudit (secrets)
│   ├─► JavaScript/TypeScript (.js, .jsx, .ts, .tsx) → ESLint (primary) + GuardDog (packages) + Graudit (secrets)
│   ├─► Shell (.sh, .bash) → ShellCheck (primary) + Graudit (exec)
│   ├─► Java/.NET/Go/Ruby → Dependency-Check + Graudit (language-specific)
│   ├─► Mixed/Unknown → Graudit (default) first, then language-specific
│   └─► Other (PHP, etc.) → Graudit (language-specific db)
│
└─► "Are there CI/CD or BUILD files?"
    ├─► GitHub Actions workflows → Checkov --framework github_actions
    ├─► GitLab CI (.gitlab-ci.yml) → Checkov --framework gitlab_ci
    ├─► Dockerfile → Checkov --framework dockerfile + ShellCheck for RUN commands
    └─► Shell scripts in CI → ShellCheck + Graudit (exec)
```

---

## Decision Matrix

Use this matrix to determine optimal skill selection:

| Code Type | Primary Skill | Secondary Skill(s) | Rationale |
|-----------|---------------|-------------------|-----------|
| **Python** | Bandit | Graudit (secrets) | AST-based deep analysis |
| **Python + deps** | GuardDog (verify) → Bandit | Dependency-Check, Graudit (secrets) | Malware + CVEs + source |
| **JavaScript/TypeScript** | ESLint | Graudit (js/typescript), GuardDog (packages) | AST-based vulnerability detection |
| **Node.js + deps** | GuardDog (verify) + Dependency-Check → ESLint | Graudit (js, secrets) | Malware + CVEs + source |
| **React/Vue/Angular** | ESLint | Graudit (xss, secrets) | Framework-specific security |
| **npm packages** | GuardDog (scan) → ESLint | Graudit (js, exec) | Malware detection + source |
| **Java + deps** | Dependency-Check | Graudit (java, secrets) | Strong Java CVE detection |
| **.NET + deps** | Dependency-Check | Graudit (dotnet, secrets) | Strong .NET CVE detection |
| **Go + deps** | Dependency-Check (experimental) | Graudit (go, secrets) | CVE detection for go.mod |
| **Ruby + deps** | Dependency-Check | Graudit (ruby, secrets) | CVE detection for Gemfile |
| **Shell scripts** | ShellCheck | Graudit (exec) | AST + obfuscation patterns |
| **CI/CD / Dockerfiles** | ShellCheck | Graudit (exec, secrets) | Embedded shell commands |
| **Django/Flask** | Bandit (framework flags) | Graudit (xss, sql) | Framework-specific tests |
| **Mixed languages** | Graudit (default) | Language-specific tools | Broad sweep first |
| **Unknown/untrusted** | Graudit (exec, secrets) | All applicable tools | Quick triage |
| **Mobile (Android/iOS)** | Graudit (android/ios) | Graudit (secrets) | Platform-specific |
| **PHP** | Graudit (php) | Dependency-Check (experimental), Graudit (secrets, sql) | CVE + pattern matching |
| **Terraform** | Checkov (--framework terraform) | Graudit (secrets) | IaC misconfiguration detection |
| **CloudFormation** | Checkov (--framework cloudformation) | Graudit (secrets) | AWS IaC security |
| **Kubernetes manifests** | Checkov (--framework kubernetes) | Graudit (secrets) | K8s security policies |
| **Dockerfile** | Checkov (--framework dockerfile) | ShellCheck (RUN commands), Graudit (secrets) | Container best practices |
| **Helm charts** | Checkov (--framework helm) | Graudit (secrets) | Helm security |
| **GitHub Actions** | Checkov (--framework github_actions) | ShellCheck (run steps), Graudit (exec, secrets) | CI/CD workflow security |
| **GitLab CI** | Checkov (--framework gitlab_ci) | ShellCheck (scripts), Graudit (exec, secrets) | CI/CD pipeline security |
| **Mixed IaC + code** | Checkov (IaC) → Language-specific | All applicable tools | Infrastructure + application |
| **Compliance required** | Dependency-Check (--failOnCVSS) + Checkov (IaC) | All applicable source scanners | CVE gates + IaC compliance + code review |

---

## Conflict Resolution Rules

When multiple tools could apply, use these priority rules:

1. **Untrusted code always wins**: If origin is unknown/suspicious → Start with Graudit (exec+secrets)
2. **IaC before application code**: If IaC files exist → Checkov FIRST to catch infrastructure misconfigurations
3. **Dependencies before source**: If dependency files exist → GuardDog verify (malware) AND/OR Dependency-Check (CVEs) before scanning source
4. **CVE detection vs Malware detection**: Use BOTH GuardDog (malware) + Dependency-Check (CVEs) for comprehensive supply chain security
5. **AST tools over regex**: For Python use Bandit over Graudit; for Shell use ShellCheck over Graudit; for IaC use Checkov over Graudit
6. **Graudit complements, not replaces**: Always add Graudit `secrets` as secondary scan
7. **Specificity over generality**: Framework-specific tool > Language-specific database > `default` database
8. **Compliance requirements**: If SOC2/PCI-DSS/HIPAA required → Dependency-Check with `--failOnCVSS` + Checkov for IaC compliance
9. **Java/.NET projects**: Dependency-Check is primary for dependencies (strongest support for these ecosystems)
10. **Cloud deployments**: Always run Checkov for Terraform/CloudFormation/K8s before deployment

---

## Risk-Based Priority Matrix

When time is limited, prioritize scans based on risk profile:

| Risk Profile | Scan Order | Time Estimate |
|--------------|------------|---------------|
| **Urgent Triage** (incident response) | 1. Graudit (exec+secrets) → 2. GuardDog verify | < 2 min |
| **Pre-Installation** (new dependency) | 1. GuardDog scan \<pkg\> → 2. Graudit (exec) | < 1 min |
| **Routine Audit** (own code) | 1. Language-specific → 2. Graudit (secrets) | 5-10 min |
| **Deep Analysis** (security review) | All tools, all databases | 15-30 min |
| **Supply Chain Focus** | 1. GuardDog verify → 2. Dependency-Check → 3. Graudit (secrets) | 5-15 min |
| **Compliance Audit** (SOC2/PCI-DSS) | 1. Dependency-Check (--failOnCVSS 7) → 2. Checkov (IaC) → 3. All source scanners | 15-25 min |
| **Java/.NET Enterprise** | 1. Dependency-Check → 2. Graudit (language+secrets) | 5-15 min |
| **Pre-Deployment Gate** | 1. Checkov (IaC) → 2. Dependency-Check (--failOnCVSS 7) → 3. GuardDog verify → 4. Source scan | 15-25 min |
| **IaC Security Audit** | 1. Checkov (all frameworks) → 2. Graudit (secrets) | 5-10 min |
| **Cloud Migration** | 1. Checkov (--framework terraform,cloudformation) → 2. All applicable tools | 10-20 min |

---

## Analysis Workflow

Follow these steps:

### Step 1: Identify Code Composition

Search the target path for:

**Programming Languages** (by file extension):
- `.py` → Python (use Bandit)
- `.js`, `.mjs`, `.cjs`, `.jsx` → JavaScript (use ESLint)
- `.ts`, `.tsx` → TypeScript (use ESLint)
- `.sh`, `.bash` → Shell/Bash (use ShellCheck)
- `.php` → PHP (use Graudit)
- `.java` → Java (use Dependency-Check + Graudit)
- `.go` → Go (use Dependency-Check + Graudit)
- `.rb` → Ruby (use Dependency-Check + Graudit)
- `.c`, `.h`, `.cpp`, `.hpp` → C/C++ (use Graudit)
- `.cs` → C#/.NET (use Dependency-Check + Graudit)

**Dependency Files**:
- `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py` → Python dependencies
- `package.json`, `package-lock.json`, `yarn.lock` → Node.js dependencies
- `Gemfile` → Ruby dependencies
- `go.mod` → Go dependencies
- `pom.xml`, `build.gradle` → Java dependencies
- `composer.json` → PHP dependencies

**Infrastructure as Code (IaC) Files**:
- `.tf`, `.tf.json` → Terraform configurations
- `.yaml`, `.yml`, `.json`, `.template` (in cloud dirs) → CloudFormation templates
- Kubernetes manifests (deployments, services, pods, etc.)
- `Dockerfile`, `Dockerfile.*` → Container definitions
- `Chart.yaml`, `values.yaml` (in Helm directories) → Helm charts
- `kustomization.yaml` → Kustomize
- `.bicep` → Azure Bicep templates
- `serverless.yml` → Serverless Framework

**CI/CD & Build Files**:
- `.github/workflows/*.yml` → GitHub Actions (may contain shell + IaC)
- `.gitlab-ci.yml` → GitLab CI
- `azure-pipelines.yml` → Azure Pipelines
- `.circleci/config.yml` → CircleCI
- `bitbucket-pipelines.yml` → Bitbucket Pipelines
- `Dockerfile`, `.dockerignore` → Docker (shell commands in RUN)
- `Makefile` → Make (shell commands)
- `Jenkinsfile` → Jenkins (Groovy + shell)

### Step 2: Assess Risk Profile

Determine the risk areas:
- **Infrastructure risk**: IaC files present? → Checkov priority for cloud misconfigurations
- **Supply chain risk**: Dependencies present? → GuardDog priority (verify before scan)
- **Code vulnerabilities**: Custom code present? → Language-specific tools (ESLint for JS/TS, Bandit for Python, etc.)
- **JavaScript/TypeScript vulnerabilities**: Web apps or Node.js? → ESLint for XSS, injection, ReDoS
- **CI/CD security**: Workflow files? → Checkov for workflow security + ShellCheck for embedded shell
- **Container security**: Dockerfiles? → Checkov for best practices + ShellCheck for RUN commands
- **Secrets exposure**: Any code/IaC files? → Graudit secrets database + Checkov secrets checks
- **Untrusted/malicious code**: Unknown origin? → Graudit (exec+secrets) first for quick triage
- **Framework-specific**: Django/Flask? → Bandit with targeted test IDs; React/Vue/Angular? → ESLint with no-unsanitized
- **Mobile apps**: Android/iOS code? → Graudit (android/ios databases)
- **Cloud compliance**: SOC2/HIPAA/PCI-DSS? → Checkov with compliance framework flags

### Step 2.5: Check for Red Flags (Escalate to Urgent Triage)

If ANY of these are present, treat as **untrusted code** and start with Graudit (exec+secrets):
- [ ] Code from unknown/unverified source
- [ ] Recently reported security incident
- [ ] Package names similar to popular packages (typosquatting)
- [ ] Obfuscated filenames or encoded content visible
- [ ] `setup.py` or `package.json` with `postinstall` scripts
- [ ] Base64 strings or hex-encoded content in source
- [ ] Network calls (`curl`, `wget`, `requests`) combined with `eval`/`exec`

### Step 3: Generate Recommendations

Provide recommendations in this format:

```markdown
## Analysis Summary

| Attribute | Value |
|-----------|-------|
| **Target** | [path analyzed] |
| **Languages detected** | [list of languages] |
| **Dependency files** | [list or "None found"] |
| **Shell/CI files** | [list or "None found"] |
| **Risk profile** | [supply chain / code vulnerabilities / infrastructure / mixed] |

---

## Recommended Skills

### Primary: [Skill Name]
- **Skill**: `[skill-id]`
- **Reason**: [why this skill is primary]
- **Target files**: [what to scan]

### Secondary: [Skill Name] (if applicable)
- **Skill**: `[skill-id]`
- **Reason**: [why this skill adds value]
- **Target files**: [what to scan]

### Additional: [Skill Name] (if applicable)
- **Skill**: `[skill-id]`
- **Reason**: [specific coverage gap it fills]
- **Target files**: [what to scan]

---

## Execution Order

1. [First skill] - [brief reason]
2. [Second skill] - [brief reason]
3. [Third skill] - [brief reason]

---

## Notes

[Any special considerations, limitations, or additional context]

---

## Tool-Specific Command Hints

When recommending skills, include these optimized commands:

### Bandit
- Quick triage: `bandit -r . -t B102,B307,B602,B605 -lll`
- Django apps: `bandit -r . -t B201,B608,B610,B611,B701,B703`
- Flask apps: `bandit -r . -t B104,B201,B310,B701`
- Full JSON report: `bandit -r . -f json -o bandit-results.json`

### GuardDog
- Verify Python deps: `guarddog pypi verify requirements.txt`
- Verify npm deps: `guarddog npm verify package-lock.json`
- Scan local project: `guarddog pypi scan ./project/`
- Check package before install: `guarddog pypi scan <package-name>`
- Critical rules only: `--rules exec-base64 --rules code-execution --rules exfiltrate-sensitive-data`

### ShellCheck
- Full security scan: `shellcheck --enable=all --severity=warning script.sh`
- Critical injection check: `shellcheck script.sh 2>&1 | grep -E "SC20(86|46|91)|SC2115"`
- Scan all scripts: `find . -name "*.sh" -exec shellcheck {} +`
- Extract from GitHub Actions: `grep -A5 "run:" .github/workflows/*.yml | shellcheck -s bash -`

### Graudit
- Quick triage: `graudit -d exec . && graudit -d secrets .`
- Language-specific: `graudit -d python ./src`
- Deep scan (use helper): `./graudit-deep-scan.sh /path/to/code ./report`
- Exclude tests: `graudit -x "test/*,tests/*" -d secrets .`

### Dependency-Check
- Basic scan: `dependency-check.sh --scan ./ --out ./reports --project "MyProject"`
- With NVD API key (recommended): `dependency-check.sh --scan ./ --nvdApiKey $NVD_API_KEY --out ./reports`
- CI/CD gate (fail on HIGH): `dependency-check.sh --scan ./ --failOnCVSS 7 --format SARIF --out ./reports`
- CI/CD gate (fail on CRITICAL): `dependency-check.sh --scan ./ --failOnCVSS 9 --format JSON --out ./reports`
- Multiple formats: `dependency-check.sh --scan ./ --format HTML --format JSON --format SARIF --out ./reports`
- With suppression file: `dependency-check.sh --scan ./ --suppression ./suppression.xml --failOnCVSS 7`
- Enable experimental analyzers: `dependency-check.sh --scan ./ --enableExperimental --out ./reports`
- Docker scan: `docker run -v $(pwd):/src owasp/dependency-check --scan /src --out /src/reports`
- Quick scan (cached DB): `dependency-check.sh --scan ./ --noupdate --format HTML --out ./reports`

### Checkov
- Quick IaC scan: `checkov -d . --compact`
- Terraform specific: `checkov -d . --framework terraform`
- Kubernetes manifests: `checkov -d ./k8s --framework kubernetes`
- Dockerfile security: `checkov -f Dockerfile --framework dockerfile`
- GitHub Actions: `checkov -d .github/workflows --framework github_actions`
- Multiple frameworks: `checkov -d . --framework terraform,kubernetes,dockerfile`
- JSON output: `checkov -d . -o json -o cli --output-file-path results.json,console`
- SARIF for CI/CD: `checkov -d . -o sarif --output-file-path results.sarif`
- Fail on HIGH/CRITICAL: `checkov -d . --hard-fail-on HIGH,CRITICAL`
- Skip specific checks: `checkov -d . --skip-check CKV_AWS_1,CKV_DOCKER_7`
- Terraform plan scan: `terraform show -json tfplan > tfplan.json && checkov -f tfplan.json --framework terraform_plan`
- With external modules: `checkov -d . --download-external-modules true`
- List all checks: `checkov --list --framework terraform`

### ESLint
- Full security scan: `eslint --config .eslintrc.security.json --ext .js,.jsx,.ts,.tsx src/`
- JSON output: `eslint --format json --output-file results.json src/`
- Critical issues only: `eslint --rule 'no-eval: error' --rule 'no-implied-eval: error' src/`
- SARIF report: `eslint --format @microsoft/eslint-formatter-sarif --output-file results.sarif src/`
- Prevent bypassing: `eslint --no-inline-config src/`
- Fail on warnings: `eslint --max-warnings 0 src/`
- React/JSX scan: `eslint --ext .jsx,.tsx --rule 'no-unsanitized/property: error' src/`
- Node.js backend: `eslint --ext .js,.ts --rule 'security/detect-child-process: error' api/`
- Quick triage: `eslint --rule 'no-eval: error' --format compact .`
- All JS/TS files: `eslint --ext .js,.jsx,.ts,.tsx .`

---

## Next Steps

To execute these recommended scans:
1. Review the recommendations above
2. Run each skill manually by invoking it via Copilot: `@security-scan-executor run [skill-name] on [target-path]`
3. Save results to `.github/.audit/tools-audit.md` for review
```

---

## Important Constraints

1. **Read-only analysis**: You analyze code structure and recommend skills. You do NOT execute scans.
2. **Skill-based recommendations**: Only recommend skills that exist in `.github/skills/`
3. **Specific guidance**: Always specify which files/directories each skill should target
4. **Execution order matters**: Recommend fastest/broadest scans first, then deep analysis
5. **Coverage gaps**: Note if any code types lack appropriate skill coverage
6. **Tool limitations**: Always mention relevant blind spots (see below)

### Anti-Patterns (Never Do These)

| ❌ Don't | ✅ Do Instead |
|----------|---------------|
| Use Bandit for non-Python files | Use Graudit with appropriate database |
| Use GuardDog to scan your own source code | Use Bandit (Python) or Graudit (others) |
| Use Checkov for application source code | Checkov is for IaC only—use Bandit/Graudit for app code |
| Use only Graudit for JavaScript when ESLint is available | Use ESLint as primary, Graudit as secondary |
| Use ESLint for npm package malware detection | ESLint scans source code—use GuardDog for malicious packages |
| Use only Graudit for Python when Bandit is available | Use Bandit as primary, Graudit as secondary |
| Use only Graudit for IaC when Checkov is available | Use Checkov as primary for IaC, Graudit for secrets |
| Skip GuardDog when dependency files exist | Always verify dependencies first |
| Skip Checkov when IaC files exist | Always scan IaC before deployment |
| Use ShellCheck alone for obfuscated scripts | Add Graudit (exec) for base64/hex patterns |
| Recommend `graudit -d default` when language is known | Use language-specific database |
| Skip secrets scan | Always include Graudit (secrets) + Checkov secrets checks |
| Use GuardDog alone for CVE detection | GuardDog detects malware, not CVEs—add Dependency-Check |
| Use Dependency-Check for malware detection | Dependency-Check detects CVEs, not malware—add GuardDog |
| Skip Dependency-Check for Java/.NET projects | These ecosystems have strongest Dependency-Check support |
| Skip Checkov for Terraform/K8s/CloudFormation | These are primary Checkov targets |
| Ignore compliance requirements | Use Dependency-Check with --failOnCVSS + Checkov for IaC compliance |

---

## Tool Limitations to Consider

When making recommendations, account for these limitations:

| Tool | Cannot Detect | Mitigation |
|------|---------------|------------|
| **Bandit** | Non-Python code, runtime vulnerabilities, obfuscated string code, vulnerable dependencies | Add Graudit for embedded code, GuardDog/Dependency-Check for deps |
| **GuardDog** | Logic vulnerabilities, runtime-only behavior, sophisticated obfuscation, your own code vulns, known CVEs | Use Bandit/Graudit for source code, Dependency-Check for CVEs |
| **ShellCheck** | Base64/hex obfuscated payloads, dynamic payload generation, embedded Python/Perl/Ruby | Add `graudit -d exec`, run in sandbox |
| **Graudit** | Logic flaws, obfuscated/encrypted code beyond patterns, context-dependent vulns | Manual review, combine with AST tools |
| **Dependency-Check** | Malicious packages (malware), source code vulnerabilities, false positives from CPE matching, zero-day vulnerabilities not yet in NVD | Use GuardDog for malware, Bandit/Graudit for source code, suppression.xml for false positives |
| **Checkov** | Runtime misconfigurations, logic flaws in application code, dynamic/computed values, actual deployed state vs declared config, secrets in encrypted/base64 beyond patterns | Static analysis only - validate with cloud security posture tools, combine with Graudit for secrets, cannot scan application source code |
| **ESLint** | Runtime vulnerabilities, sophisticated obfuscation, dependency CVEs, minified code, behavioral analysis, malicious npm packages | Static pattern-based only - add npm audit/Dependency-Check for CVEs, GuardDog for malware, manual review for obfuscated code |

### Combined Blind Spots
All tools are static analysis only - they cannot detect:
- Time bombs or environment-triggered payloads
- Legitimate-looking but malicious logic
- Steganographic or external payload retrieval
- Encrypted/compressed payloads
- Social engineering in comments

---

## Expected Output Format

Your recommendation MUST include these sections in order:

### Required Sections
1. **Analysis Summary** - Table with target, languages, deps, risk profile
2. **Recommended Skills** - Primary, Secondary, Additional with skill ID, reason, targets
3. **Execution Order** - Numbered list with time estimates
4. **Command Hints** - Specific commands for each recommended skill
5. **Limitations** - What these tools will NOT catch for this codebase
6. **Next Steps** - How to execute the recommendations

### Checklist Before Submitting
- ✅ Graudit databases specified (exec, secrets, language-specific)
- ✅ Bandit test IDs included if Python detected (e.g., `-t B102,B307`)
- ✅ ShellCheck severity specified if shell detected (`--severity=warning`)
- ✅ GuardDog mode specified (scan vs verify, pypi vs npm)
- ✅ Time estimates for each scan step
- ✅ At least one blind spot/limitation mentioned
