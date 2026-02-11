---
name: eslint-security-scan
description: Security analysis of JavaScript/TypeScript code (.js, .jsx, .ts, .tsx) for vulnerabilities using ESLint with security plugins. (1) Detects code injection (eval, Function), XSS (innerHTML, dangerouslySetInnerHTML), command injection (child_process), ReDoS, path traversal, insecure crypto, prototype pollution. Use for web apps, Node.js services, React/Vue/Angular projects, npm packages, malicious code triage. NOT use for dependency CVEs (use npm audit), non-JavaScript code (use language-specific tools), minified code. For full coverage combine with npm audit or OWASP Dependency-Check for supply chain security.
---

# ESLint Security Scanner Skill

ESLint is a static analysis tool for identifying problematic patterns in JavaScript and TypeScript code. With security-focused plugins, it detects injection vulnerabilities, XSS, dangerous API usage, and malicious patterns in web and Node.js applications.

## When to Use This Skill

Use this skill when:
- Scanning JavaScript/TypeScript projects for security vulnerabilities
- Auditing web applications for XSS and injection flaws
- Detecting dangerous code patterns (eval, innerHTML, child_process)
- Reviewing React/Vue/Angular components for security issues
- Checking Node.js backend code for command injection
- Triaging potentially malicious JavaScript packages or scripts
- Code review for OWASP Top 10 JavaScript vulnerabilities
- CI/CD security gates for JavaScript/TypeScript codebases
- Detecting obfuscated malicious code in npm packages

## Decision Tree: Choosing the Right Tool

```
What are you scanning?
│
├── JavaScript/TypeScript source code?
│   ├── Web application (React/Vue/Angular) → eslint + security plugins (THIS SKILL)
│   ├── Node.js backend → eslint + security/detect-child-process
│   ├── npm package source → eslint + guarddog for full analysis
│   └── Minified/obfuscated code → graudit -d js (ESLint may fail)
│
├── JavaScript dependencies (package.json)?
│   └── Use guarddog or npm audit for CVE/malware detection
│
├── Mixed language project?
│   ├── JS/TS files → eslint (THIS SKILL)
│   ├── Shell scripts → shellcheck
│   └── Python → bandit
│
└── Browser extensions or userscripts?
    └── eslint + no-unsanitized plugin for XSS
```

## Malicious Code Detection Priority

When scanning for potentially malicious or compromised JavaScript code, prioritize these patterns:

### Critical - Immediate Red Flags
| Rule ID | Detection | Why It's Dangerous | MITRE ATT&CK |
|---------|-----------|-------------------|--------------|
| `no-eval` | `eval()` usage | Arbitrary code execution | T1059.007 (JavaScript) |
| `no-implied-eval` | `setTimeout/setInterval` with strings | Time-delayed code execution | T1059.007 |
| `no-new-func` | `new Function()` | Dynamic function creation | T1059.007 |
| `security/detect-eval-with-expression` | `eval()` with external input | Code injection vector | T1059.007 |
| `security/detect-child-process` | `child_process.exec()` | Command injection, reverse shells | T1059.004 (Unix Shell) |

### High - Data Exfiltration & XSS
| Rule ID | Detection | MITRE ATT&CK |
|---------|-----------|--------------|
| `no-unsanitized/property` | Unsafe `innerHTML`/`outerHTML` | T1059.007 (XSS) |
| `no-unsanitized/method` | `insertAdjacentHTML` without sanitization | T1059.007 (XSS) |
| `no-script-url` | `javascript:` URLs | T1059.007 (XSS) |
| `security/detect-non-literal-fs-filename` | Dynamic file paths | T1083 (File Discovery) |
| `security/detect-possible-timing-attacks` | String comparison vulnerabilities | T1552 (Credential Access) |

### Medium - Injection & Unsafe Patterns
| Rule ID | Detection | Risk |
|---------|-----------|------|
| `security/detect-non-literal-require` | Dynamic `require()` | Arbitrary module loading |
| `security/detect-non-literal-regexp` | Dynamic RegExp construction | ReDoS potential |
| `security/detect-unsafe-regex` | Catastrophic backtracking patterns | ReDoS (Denial of Service) |
| `security/detect-object-injection` | Bracket notation with variables | Prototype pollution risk |
| `security/detect-new-buffer` | Unsafe Buffer constructors | Memory exposure |
| `security/detect-pseudoRandomBytes` | Weak PRNG for security | Predictable values |

### Recommended Command for Malicious Code Triage
```bash
# Critical patterns first (< 1 minute)
eslint --format json \
  --rule 'no-eval: error' \
  --rule 'no-implied-eval: error' \
  --rule 'no-new-func: error' \
  --ext .js,.jsx,.ts,.tsx \
  src/

# Full malicious scan with security plugins
eslint --format json \
  --output-file malicious-scan.json \
  --config .eslintrc.security.json \
  --no-inline-config \
  --ext .js,.jsx,.ts,.tsx \
  .
```

## Prerequisites

### Installation

Install ESLint with security plugins:

```bash
# Local installation (recommended)
npm install --save-dev \
  eslint \
  eslint-plugin-security \
  eslint-plugin-no-unsanitized \
  @typescript-eslint/parser \
  @typescript-eslint/eslint-plugin

# Global installation
npm install -g eslint eslint-plugin-security eslint-plugin-no-unsanitized

# Verify installation
eslint --version
```

### Security Plugins

- **eslint-plugin-security**: Detects Node.js security vulnerabilities
- **eslint-plugin-no-unsanitized**: Prevents XSS via DOM manipulation
- **@typescript-eslint/eslint-plugin**: TypeScript-specific security rules

## Core Commands

### Basic Scanning

```bash
# Scan a single file
eslint file.js

# Scan directory recursively
eslint src/

# Scan with specific extensions
eslint --ext .js,.jsx,.ts,.tsx src/

# Scan with severity threshold
eslint --quiet src/  # Errors only, suppress warnings

# Fail on any warnings
eslint --max-warnings 0 src/
```

### Security-Focused Scanning

```bash
# Use security configuration
eslint --config .eslintrc.security.json src/

# Prevent bypassing rules via inline comments
eslint --no-inline-config src/

# Report unused disable directives
eslint --report-unused-disable-directives src/

# Scan with specific security rules only
eslint \
  --rule 'no-eval: error' \
  --rule 'no-implied-eval: error' \
  --rule 'security/detect-child-process: error' \
  src/
```

### Output Formats

```bash
# JSON output (recommended for automation)
eslint --format json --output-file results.json src/

# SARIF format (for security tools)
npm install --save-dev @microsoft/eslint-formatter-sarif
eslint --format @microsoft/eslint-formatter-sarif --output-file results.sarif src/

# HTML report
eslint --format html --output-file report.html src/

# Compact format
eslint --format compact src/

# Unix format (for CI/CD)
eslint --format unix src/
```

### Complete Security Scan Command
```bash
eslint \
  --ext .js,.jsx,.ts,.tsx \
  --format json \
  --output-file security-scan.json \
  --config .eslintrc.security.json \
  --no-inline-config \
  --report-unused-disable-directives \
  --max-warnings 0 \
  --cache \
  src/
```

## Available Rules/Checks

### Core Security Rules (Built-in)

| Rule ID | Description | Severity | CWE |
|---------|-------------|----------|-----|
| `no-eval` | Disallow `eval()` | CRITICAL | CWE-95 (Code Injection) |
| `no-implied-eval` | Disallow `setTimeout/setInterval` with strings | CRITICAL | CWE-95 |
| `no-new-func` | Disallow `new Function()` | CRITICAL | CWE-95 |
| `no-script-url` | Disallow `javascript:` URLs | HIGH | CWE-79 (XSS) |
| `no-with` | Disallow `with` statements | MEDIUM | CWE-758 |
| `no-proto` | Disallow `__proto__` | MEDIUM | CWE-1321 (Prototype Pollution) |
| `no-extend-native` | Disallow extending native prototypes | MEDIUM | CWE-1321 |
| `no-caller` | Disallow `arguments.caller/callee` | MEDIUM | CWE-676 |

### eslint-plugin-security Rules

| Rule ID | Description | Severity | MITRE ATT&CK |
|---------|-------------|----------|--------------|
| `security/detect-eval-with-expression` | Detect `eval()` with variables | CRITICAL | T1059.007 |
| `security/detect-child-process` | Detect `child_process` usage | HIGH | T1059.004 |
| `security/detect-unsafe-regex` | Detect ReDoS-vulnerable regex | HIGH | T1499 (DoS) |
| `security/detect-non-literal-require` | Detect dynamic `require()` | HIGH | T1129 (Module Load) |
| `security/detect-non-literal-fs-filename` | Detect dynamic file paths | HIGH | T1083 |
| `security/detect-possible-timing-attacks` | Detect timing attack vulnerabilities | MEDIUM | T1552 |
| `security/detect-non-literal-regexp` | Detect dynamic RegExp construction | MEDIUM | T1499 |
| `security/detect-object-injection` | Detect bracket notation with variables | MEDIUM | CWE-1321 |
| `security/detect-new-buffer` | Detect unsafe Buffer constructors | MEDIUM | CWE-665 |
| `security/detect-buffer-noassert` | Detect Buffer with noAssert flag | MEDIUM | CWE-120 |
| `security/detect-pseudoRandomBytes` | Detect weak PRNG | LOW | CWE-338 |
| `security/detect-no-csrf-before-method-override` | Detect CSRF misconfiguration | MEDIUM | CWE-352 |
| `security/detect-disable-mustache-escape` | Detect disabled escaping | MEDIUM | CWE-79 |

### eslint-plugin-no-unsanitized Rules

| Rule ID | Description | Severity | CWE |
|---------|-------------|----------|-----|
| `no-unsanitized/method` | Disallow unsafe DOM manipulation methods | HIGH | CWE-79 (XSS) |
| `no-unsanitized/property` | Disallow unsafe `innerHTML`/`outerHTML` | HIGH | CWE-79 (XSS) |

## Security Configuration

### .eslintrc.security.json (Recommended)

Create a dedicated security configuration:

```json
{
  "env": {
    "browser": true,
    "node": true,
    "es2021": true
  },
  "extends": [
    "eslint:recommended",
    "plugin:security/recommended"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": 2021,
    "sourceType": "module",
    "ecmaFeatures": {
      "jsx": true
    }
  },
  "plugins": [
    "security",
    "no-unsanitized",
    "@typescript-eslint"
  ],
  "rules": {
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error",
    "no-script-url": "error",
    "no-proto": "error",
    "no-extend-native": "error",
    "no-with": "error",
    "security/detect-eval-with-expression": "error",
    "security/detect-child-process": "error",
    "security/detect-unsafe-regex": "error",
    "security/detect-non-literal-require": "error",
    "security/detect-non-literal-fs-filename": "error",
    "security/detect-non-literal-regexp": "error",
    "security/detect-possible-timing-attacks": "error",
    "security/detect-new-buffer": "error",
    "security/detect-buffer-noassert": "error",
    "security/detect-pseudoRandomBytes": "error",
    "security/detect-object-injection": "warn",
    "no-unsanitized/method": "error",
    "no-unsanitized/property": "error"
  },
  "ignorePatterns": [
    "node_modules/",
    "dist/",
    "build/",
    "*.min.js",
    "coverage/"
  ]
}
```

### Flat Config (ESLint 9+)

```javascript
import js from '@eslint/js';
import security from 'eslint-plugin-security';
import noUnsanitized from 'eslint-plugin-no-unsanitized';

export default [
  js.configs.recommended,
  {
    files: ['**/*.{js,jsx,ts,tsx}'],
    plugins: {
      security,
      'no-unsanitized': noUnsanitized
    },
    rules: {
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'security/detect-child-process': 'error',
      'security/detect-unsafe-regex': 'error',
      'no-unsanitized/method': 'error',
      'no-unsanitized/property': 'error'
    }
  },
  {
    ignores: ['node_modules/', 'dist/', 'build/']
  }
];
```

## Recommended Scanning Workflows

### Quick Triage (< 30 seconds)
For rapid assessment of untrusted JavaScript code:
```bash
# Check for critical code execution patterns only
eslint \
  --rule 'no-eval: error' \
  --rule 'no-implied-eval: error' \
  --rule 'no-new-func: error' \
  --ext .js,.jsx,.ts,.tsx \
  --format compact \
  .
```

### Standard Security Audit (1-2 minutes)
For routine code review:
```bash
# Step 1: Run with security configuration
eslint --config .eslintrc.security.json --format json --output-file scan.json src/

# Step 2: Check error count
ERROR_COUNT=$(jq '[.[].errorCount] | add' scan.json)
echo "Security errors found: $ERROR_COUNT"
```

### Deep Malicious Code Scan (5-10 minutes)
For untrusted code or incident response:
```bash
# Comprehensive scan with all checks
eslint \
  --config .eslintrc.security.json \
  --format json \
  --output-file full-scan.json \
  --no-inline-config \
  --report-unused-disable-directives \
  --ext .js,.jsx,.ts,.tsx \
  .

# Combine with dependency check
npm audit --json > npm-audit.json

# Check for obfuscated patterns
grep -r -E "(eval|Function|atob|btoa|unescape)" --include="*.js" .
```

### CI/CD Integration
```bash
# Fail pipeline on any security errors
eslint \
  --config .eslintrc.security.json \
  --max-warnings 0 \
  --ext .js,.jsx,.ts,.tsx \
  src/ || exit 1

# Generate SARIF for GitHub Code Scanning
eslint \
  --format @microsoft/eslint-formatter-sarif \
  --output-file eslint.sarif \
  --config .eslintrc.security.json \
  src/
```

## Framework-Specific Scanning

### React Applications
```bash
eslint \
  --ext .jsx,.tsx \
  --config .eslintrc.security.json \
  --rule 'no-unsanitized/property: error' \
  --rule 'react/no-danger: error' \
  src/
```

### Node.js Backend
```bash
eslint \
  --ext .js,.ts \
  --config .eslintrc.security.json \
  --rule 'security/detect-child-process: error' \
  --rule 'security/detect-non-literal-require: error' \
  api/ server/
```

### Vue.js Applications
```bash
npm install --save-dev eslint-plugin-vue
eslint \
  --ext .vue,.js \
  --config .eslintrc.security.json \
  --plugin vue \
  src/
```

### npm Packages
```bash
# Scan package source
eslint --config .eslintrc.security.json lib/ src/

# Also scan with guarddog for malicious patterns
guarddog npm verify package.json
```

## Interpreting Results

### Severity Mapping

ESLint severity levels:
- **2 (error)**: Must be fixed - blocks execution
- **1 (warning)**: Should be reviewed - doesn't block
- **0 (off)**: Rule disabled

### Security Severity Classification

Map ESLint findings to security severity:

| ESLint Rule | Security Severity | Exploitability |
|-------------|------------------|----------------|
| `no-eval`, `no-implied-eval` | **CRITICAL** | Immediate RCE |
| `security/detect-child-process` | **HIGH** | Command injection |
| `security/detect-unsafe-regex` | **HIGH** | ReDoS (DoS) |
| `no-unsanitized/*` | **HIGH** | XSS |
| `security/detect-non-literal-require` | **MEDIUM** | Module hijacking |
| `security/detect-object-injection` | **LOW-MEDIUM** | Context-dependent |

### Example Output

```json
[
  {
    "filePath": "/path/to/vulnerable.js",
    "messages": [
      {
        "ruleId": "no-eval",
        "severity": 2,
        "message": "eval can be harmful.",
        "line": 15,
        "column": 5,
        "nodeType": "CallExpression"
      }
    ],
    "errorCount": 1,
    "warningCount": 0
  }
]
```

## Verifying Findings

For each ESLint finding, verify:
- [ ] Is external/user input involved? (not hardcoded safe values)
- [ ] Can an attacker control the input path?
- [ ] Is there validation/sanitization before the dangerous call?
- [ ] Is this production code? (not tests/documentation)
- [ ] Does the context make it exploitable?

### Common False Positives

| Rule ID | False Positive Scenario | Recommendation |
|---------|------------------------|----------------|
| `security/detect-object-injection` | Static object keys, array indices | Review context, use `// eslint-disable-next-line` with justification |
| `security/detect-non-literal-require` | Build-time dynamic imports | Acceptable if inputs are static/validated |
| `no-eval` | Safe JSON parsing alternatives | Use `JSON.parse()` instead |
| `security/detect-unsafe-regex` | Simple patterns without alternation | Verify with regex testing tools |

### Handling False Positives

```javascript
// Acceptable with justification
// eslint-disable-next-line security/detect-object-injection -- Array index from validated loop
const value = array[index];

// Better: Refactor to avoid pattern
const value = array.at(index);
```

## Integration with Other Security Tools

For comprehensive security analysis, combine ESLint with other skills:

| Code Type | Primary Tool | Secondary Scan |
|-----------|--------------|----------------|
| JavaScript/TypeScript | **ESLint** (this skill) | guarddog (packages), npm audit (CVEs) |
| npm packages | guarddog | ESLint (source code) |
| Node.js + Shell | ESLint | ShellCheck (scripts) |
| Full-stack (JS + Python) | ESLint + Bandit | dependency-check |

### Recommended Multi-Tool Workflow

```bash
# 1. JavaScript source code analysis
eslint --config .eslintrc.security.json --format json src/ > eslint-results.json

# 2. Dependency vulnerability check
npm audit --json > npm-audit.json

# 3. Malicious package detection (if scanning npm package)
guarddog npm verify package.json

# 4. OWASP dependency check for CVEs
dependency-check --scan . --format JSON --out dependency-check.json
```

## Additional Resources

- [Malicious Patterns Reference](./examples/malicious-patterns.md) - Educational examples of dangerous JavaScript patterns that ESLint detects, including eval(), XSS vectors, command injection, ReDoS, and obfuscation techniques. Use this reference to understand detection capabilities and educate developers about secure coding.

## Limitations

- **Static Analysis Only**: Cannot detect runtime vulnerabilities or dynamic code generation
- **JavaScript/TypeScript Only**: Does not scan other languages or dependencies for CVEs
- **Pattern-Based**: May miss sophisticated obfuscation or novel attack vectors
- **No Dataflow Analysis**: Limited taint tracking compared to advanced SAST tools
- **False Positives**: `security/detect-object-injection` has high false positive rate
- **Configuration Required**: Needs proper setup with security plugins for comprehensive coverage
- **Minified Code**: May fail to parse heavily obfuscated or minified JavaScript
- **No Behavioral Analysis**: Cannot detect malicious intent, only dangerous patterns
- **Dependency Scanning**: Does not check for vulnerable npm packages (use npm audit/guarddog)

## Quick Reference: Security Scan Commands

| Goal | Command |
|------|---------|
| Full security scan | `eslint --config .eslintrc.security.json --ext .js,.jsx,.ts,.tsx src/` |
| JSON output | `eslint --format json --output-file results.json src/` |
| Critical issues only | `eslint --rule 'no-eval: error' --rule 'no-implied-eval: error' src/` |
| SARIF report | `eslint --format @microsoft/eslint-formatter-sarif --output-file results.sarif src/` |
| Prevent bypassing | `eslint --no-inline-config src/` |
| Fail on warnings | `eslint --max-warnings 0 src/` |
| Scan all JS/TS | `eslint --ext .js,.jsx,.ts,.tsx .` |

````