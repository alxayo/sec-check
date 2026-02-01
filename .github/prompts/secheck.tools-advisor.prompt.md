---
name: sechek.tools-advisor
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

---

## Quick Decision Flowchart

Use this flowchart for rapid tool selection:

```
START: What's the primary concern?
│
├─► "Is code UNTRUSTED or potentially MALICIOUS?"
│   └─► YES → Graudit (exec+secrets) FIRST, then others
│
├─► "Are there DEPENDENCY FILES?" (requirements.txt, package.json, etc.)
│   └─► YES → GuardDog verify FIRST
│
├─► "What LANGUAGE is the code?"
│   ├─► Python (.py) → Bandit (primary) + Graudit (secrets)
│   ├─► JavaScript/TypeScript → GuardDog + Graudit (js/typescript)
│   ├─► Shell (.sh, .bash) → ShellCheck (primary) + Graudit (exec)
│   ├─► Mixed/Unknown → Graudit (default) first, then language-specific
│   └─► Other (PHP, Java, Go, etc.) → Graudit (language-specific db)
│
└─► "Are there CI/CD or INFRASTRUCTURE files?"
    └─► YES → ShellCheck for shell in workflows/Dockerfiles
```

---

## Decision Matrix

Use this matrix to determine optimal skill selection:

| Code Type | Primary Skill | Secondary Skill(s) | Rationale |
|-----------|---------------|-------------------|-----------|
| **Python** | Bandit | Graudit (secrets) | AST-based deep analysis |
| **Python + deps** | GuardDog (verify) → Bandit | Graudit (secrets) | Supply chain first |
| **JavaScript/TypeScript** | GuardDog | Graudit (js/typescript) | Malware + pattern matching |
| **Node.js + deps** | GuardDog (verify) → GuardDog (scan) | Graudit (js) | Verify deps, then source |
| **Shell scripts** | ShellCheck | Graudit (exec) | AST + obfuscation patterns |
| **CI/CD / Dockerfiles** | ShellCheck | Graudit (exec, secrets) | Embedded shell commands |
| **Django/Flask** | Bandit (framework flags) | Graudit (xss, sql) | Framework-specific tests |
| **Mixed languages** | Graudit (default) | Language-specific tools | Broad sweep first |
| **Unknown/untrusted** | Graudit (exec, secrets) | All applicable tools | Quick triage |
| **Mobile (Android/iOS)** | Graudit (android/ios) | Graudit (secrets) | Platform-specific |
| **PHP/Java/Go/Ruby/.NET** | Graudit (language db) | Graudit (secrets, sql) | No specialized tool |

---

## Conflict Resolution Rules

When multiple tools could apply, use these priority rules:

1. **Untrusted code always wins**: If origin is unknown/suspicious → Start with Graudit (exec+secrets)
2. **Dependencies before source**: If dependency files exist → GuardDog verify before scanning source
3. **AST tools over regex**: For Python use Bandit over Graudit; for Shell use ShellCheck over Graudit
4. **Graudit complements, not replaces**: Always add Graudit `secrets` as secondary scan
5. **Specificity over generality**: Language-specific database > `default` database

---

## Risk-Based Priority Matrix

When time is limited, prioritize scans based on risk profile:

| Risk Profile | Scan Order | Time Estimate |
|--------------|------------|---------------|
| **Urgent Triage** (incident response) | 1. Graudit (exec+secrets) → 2. GuardDog verify | < 2 min |
| **Pre-Installation** (new dependency) | 1. GuardDog scan \<pkg\> → 2. Graudit (exec) | < 1 min |
| **Routine Audit** (own code) | 1. Language-specific → 2. Graudit (secrets) | 5-10 min |
| **Deep Analysis** (security review) | All tools, all databases | 15-30 min |
| **Supply Chain Focus** | 1. GuardDog verify → 2. Graudit (secrets) → 3. Bandit | 5-10 min |

---

## Analysis Workflow

Follow these steps:

### Step 1: Identify Code Composition

Search the target path for:

**Programming Languages** (by file extension):
- `.py` → Python
- `.js`, `.mjs`, `.cjs`, `.jsx` → JavaScript
- `.ts`, `.tsx` → TypeScript
- `.sh`, `.bash` → Shell/Bash
- `.php` → PHP
- `.java` → Java
- `.go` → Go
- `.rb` → Ruby
- `.c`, `.h`, `.cpp`, `.hpp` → C/C++
- `.cs` → C#/.NET

**Dependency Files**:
- `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py` → Python dependencies
- `package.json`, `package-lock.json`, `yarn.lock` → Node.js dependencies
- `Gemfile` → Ruby dependencies
- `go.mod` → Go dependencies
- `pom.xml`, `build.gradle` → Java dependencies
- `composer.json` → PHP dependencies

**CI/CD & Build Files**:
- `.github/workflows/*.yml` → GitHub Actions (may contain shell)
- `Dockerfile`, `.dockerignore` → Docker (shell commands in RUN)
- `Makefile` → Make (shell commands)
- `Jenkinsfile` → Jenkins (Groovy + shell)

### Step 2: Assess Risk Profile

Determine the risk areas:
- **Supply chain risk**: Dependencies present? → GuardDog priority (verify before scan)
- **Code vulnerabilities**: Custom code present? → Language-specific tools
- **Infrastructure risk**: Shell/CI files? → ShellCheck priority
- **Secrets exposure**: Any code files? → Graudit secrets database
- **Untrusted/malicious code**: Unknown origin? → Graudit (exec+secrets) first for quick triage
- **Framework-specific**: Django/Flask? → Bandit with targeted test IDs
- **Mobile apps**: Android/iOS code? → Graudit (android/ios databases)

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
| Use only Graudit for Python when Bandit is available | Use Bandit as primary, Graudit as secondary |
| Skip GuardDog when dependency files exist | Always verify dependencies first |
| Use ShellCheck alone for obfuscated scripts | Add Graudit (exec) for base64/hex patterns |
| Recommend `graudit -d default` when language is known | Use language-specific database |
| Skip secrets scan | Always include Graudit (secrets) as secondary |

---

## Tool Limitations to Consider

When making recommendations, account for these limitations:

| Tool | Cannot Detect | Mitigation |
|------|---------------|------------|
| **Bandit** | Non-Python code, runtime vulnerabilities, obfuscated string code, vulnerable dependencies | Add Graudit for embedded code, GuardDog for deps |
| **GuardDog** | Logic vulnerabilities, runtime-only behavior, sophisticated obfuscation, your own code vulns | Use Bandit/Graudit for source code |
| **ShellCheck** | Base64/hex obfuscated payloads, dynamic payload generation, embedded Python/Perl/Ruby | Add `graudit -d exec`, run in sandbox |
| **Graudit** | Logic flaws, obfuscated/encrypted code beyond patterns, context-dependent vulns | Manual review, combine with AST tools |

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
