# ESLint Security Scanner Skill

An agentic skill for scanning JavaScript and TypeScript code for security vulnerabilities using ESLint with security-focused plugins.

## What This Skill Does

This skill enables GitHub Copilot to perform comprehensive security scans on JavaScript/TypeScript codebases using ESLint. It detects:

- **Code Injection**: `eval()`, `Function()`, `setTimeout` with strings
- **XSS Vulnerabilities**: Unsafe `innerHTML`, `dangerouslySetInnerHTML`
- **Command Injection**: Unsafe `child_process.exec()` usage
- **ReDoS**: Regular expressions with catastrophic backtracking
- **Path Traversal**: Dynamic file path construction
- **Prototype Pollution**: Unsafe object manipulation
- **Weak Cryptography**: Usage of `pseudoRandomBytes`
- **Timing Attacks**: String comparison vulnerabilities

## Requirements

- **Node.js**: 14.x or higher
- **npm** or **yarn**: For package management
- **ESLint**: 8.x or 9.x
- **Security Plugins**:
  - `eslint-plugin-security`
  - `eslint-plugin-no-unsanitized`
  - `@typescript-eslint/eslint-plugin` (for TypeScript)

## Installation

```bash
# Install ESLint with security plugins
npm install --save-dev \
  eslint \
  eslint-plugin-security \
  eslint-plugin-no-unsanitized \
  @typescript-eslint/parser \
  @typescript-eslint/eslint-plugin

# Or globally
npm install -g eslint eslint-plugin-security eslint-plugin-no-unsanitized
```

## Example Prompts

Ask GitHub Copilot:

- "Scan this JavaScript code for security vulnerabilities"
- "Check for XSS vulnerabilities in React components"
- "Look for command injection risks in this Node.js code"
- "Audit this TypeScript project for dangerous patterns"
- "Find eval() and other code execution vulnerabilities"
- "Scan for ReDoS-vulnerable regular expressions"
- "Check this npm package for malicious JavaScript patterns"

## Example CLI Commands

### Basic Security Scan
```bash
eslint --ext .js,.jsx,.ts,.tsx --config .eslintrc.security.json src/
```

### JSON Output for Automation
```bash
eslint --format json --output-file security-scan.json --config .eslintrc.security.json src/
```

### Critical Issues Only
```bash
eslint \
  --rule 'no-eval: error' \
  --rule 'no-implied-eval: error' \
  --rule 'no-new-func: error' \
  --ext .js,.jsx,.ts,.tsx \
  src/
```

### Prevent Rule Bypassing
```bash
eslint \
  --no-inline-config \
  --report-unused-disable-directives \
  --max-warnings 0 \
  --config .eslintrc.security.json \
  src/
```

### SARIF Output for GitHub Code Scanning
```bash
npm install --save-dev @microsoft/eslint-formatter-sarif
eslint \
  --format @microsoft/eslint-formatter-sarif \
  --output-file eslint-security.sarif \
  --config .eslintrc.security.json \
  src/
```

## Quick Start Configuration

Create `.eslintrc.security.json`:

```json
{
  "extends": ["eslint:recommended", "plugin:security/recommended"],
  "plugins": ["security", "no-unsanitized"],
  "rules": {
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error",
    "no-script-url": "error",
    "security/detect-child-process": "error",
    "security/detect-unsafe-regex": "error",
    "security/detect-eval-with-expression": "error",
    "no-unsanitized/method": "error",
    "no-unsanitized/property": "error"
  }
}
```

## File Structure

```
.github/skills/eslint-security-scan/
├── SKILL.md                          # Main skill documentation (agentic skill spec)
├── README.md                         # This file
├── eslint.md                         # Comprehensive ESLint security reference
└── examples/
    └── malicious-patterns.md         # Code examples of detectable vulnerabilities
```

## Key Features

### Detection Capabilities
- ✅ Code injection (eval, Function constructor)
- ✅ XSS vulnerabilities (innerHTML, DOM manipulation)
- ✅ Command injection (child_process)
- ✅ ReDoS (Regular expression Denial of Service)
- ✅ Path traversal vulnerabilities
- ✅ Unsafe cryptography usage
- ✅ Prototype pollution risks
- ✅ Timing attack vulnerabilities

### Supported Languages
- JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`)
- TypeScript (`.ts`, `.tsx`)
- Vue Single File Components (`.vue` with plugin)
- React JSX/TSX

### Output Formats
- JSON (machine-readable)
- SARIF (security tool standard)
- HTML (interactive reports)
- Compact/Unix (CI/CD friendly)

## Integration Examples

### CI/CD Pipeline (GitHub Actions)
```yaml
- name: ESLint Security Scan
  run: |
    npm install
    npx eslint \
      --ext .js,.jsx,.ts,.tsx \
      --format json \
      --output-file eslint-security.json \
      --config .eslintrc.security.json \
      --no-inline-config \
      --max-warnings 0 \
      src/
```

### Pre-commit Hook (Husky)
```json
{
  "husky": {
    "hooks": {
      "pre-commit": "eslint --config .eslintrc.security.json --max-warnings 0 $(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(js|jsx|ts|tsx)$')"
    }
  }
}
```

### Docker Container
```dockerfile
FROM node:18-alpine
RUN npm install -g eslint eslint-plugin-security eslint-plugin-no-unsanitized
COPY .eslintrc.security.json /app/
ENTRYPOINT ["eslint", "--config", "/app/.eslintrc.security.json"]
```

## Use Cases

### Web Application Security
- Scan React/Vue/Angular projects for XSS
- Detect unsafe DOM manipulation
- Find client-side code injection

### Node.js Backend Security
- Command injection detection
- Path traversal vulnerabilities
- Unsafe file system operations

### npm Package Auditing
- Scan package source before publishing
- Detect malicious patterns in dependencies
- Combine with `guarddog` for comprehensive analysis

### Malicious Code Triage
- Rapid assessment of suspicious JavaScript
- Obfuscation pattern detection
- Incident response for compromised packages

## Limitations

- **Static analysis only** - Cannot detect runtime vulnerabilities
- **Pattern-based detection** - May miss novel attack vectors
- **False positives** - `security/detect-object-injection` in particular
- **No dependency scanning** - Use `npm audit` or `guarddog` for CVE detection
- **Minified code** - May fail to parse heavily obfuscated JavaScript
- **Configuration required** - Needs proper setup for comprehensive coverage

## Complementary Tools

Use ESLint alongside:
- **npm audit / yarn audit** - Dependency CVE scanning
- **guarddog** - Malicious package detection
- **OWASP Dependency-Check** - Software composition analysis
- **Snyk** - Advanced vulnerability scanning
- **SonarQube** - Comprehensive code quality analysis
- **Semgrep** - Custom security pattern matching

## Additional Resources

- [ESLint Official Documentation](https://eslint.org/)
- [eslint-plugin-security](https://github.com/nodesecurity/eslint-plugin-security)
- [eslint-plugin-no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)

## License

This skill follows the same license as the sec-check repository.

## Contributing

When enhancing this skill:
1. Add new security rules as they become available
2. Update MITRE ATT&CK mappings
3. Include real-world vulnerability examples
4. Test against known vulnerable code samples
5. Document false positive patterns
