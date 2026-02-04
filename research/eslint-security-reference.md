# ESLint Security Scanning Reference

## Overview
ESLint is a static code analysis tool for identifying problematic patterns in JavaScript/TypeScript code. For security scanning, ESLint can detect dangerous patterns, code injection vulnerabilities, and other security issues through its extensive rule system and security-focused plugins.

## Installation

### NPM Installation
```bash
# Local installation (recommended)
npm install eslint --save-dev

# Global installation
npm install -g eslint

# With security plugins
npm install --save-dev eslint eslint-plugin-security eslint-plugin-no-unsanitized
```

### Yarn Installation
```bash
yarn add --dev eslint
yarn add --dev eslint-plugin-security eslint-plugin-no-unsanitized
```

## Core CLI Commands

### Basic Usage
```bash
# Scan single file
eslint file.js

# Scan directory
eslint src/

# Scan with glob patterns
eslint "**/*.js"

# Multiple paths
eslint src/ lib/ test/
```

### Important Security-Focused Flags

#### Output & Formatting
```bash
# JSON output (machine-readable, best for automation)
eslint --format json file.js

# JSON output to file
eslint --format json --output-file results.json src/

# SARIF format (Static Analysis Results Interchange Format)
eslint --format @microsoft/eslint-formatter-sarif --output-file results.sarif src/

# Compact format (concise output)
eslint --format compact src/

# HTML report
eslint --format html --output-file report.html src/
```

#### Configuration & Rules
```bash
# Specify config file
eslint --config .eslintrc.security.json src/

# Use specific rules inline
eslint --rule 'no-eval: error' --rule 'no-implied-eval: error' file.js

# Disable inline comments (prevent bypassing rules)
eslint --no-inline-config src/

# Report unused disable directives
eslint --report-unused-disable-directives src/
```

#### File Selection
```bash
# Include specific file extensions
eslint --ext .js,.jsx,.ts,.tsx src/

# Ignore patterns
eslint --ignore-pattern "node_modules/" --ignore-pattern "dist/" src/

# Disable default ignore patterns
eslint --no-ignore src/
```

#### Error Handling
```bash
# Exit with error only on errors (not warnings)
eslint --quiet src/

# Set max warnings (fail if exceeded)
eslint --max-warnings 0 src/

# Continue on errors
eslint --no-error-on-unmatched-pattern src/
```

#### Cache & Performance
```bash
# Enable caching (faster repeated scans)
eslint --cache --cache-location .eslintcache src/

# Debug mode
eslint --debug src/
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

## Security-Focused Plugins

### 1. eslint-plugin-security
**Purpose**: Detect security vulnerabilities and bad practices in Node.js code

**Installation**:
```bash
npm install --save-dev eslint-plugin-security
```

**Key Rules**:
- `security/detect-unsafe-regex` - Detect potentially catastrophic exponential-time regular expressions
- `security/detect-buffer-noassert` - Detect calls to buffer with noAssert flag set
- `security/detect-child-process` - Detect instances of child_process & non-literal exec()
- `security/detect-disable-mustache-escape` - Detect Mustache escaping disabled
- `security/detect-eval-with-expression` - Detect eval() with variable expressions
- `security/detect-new-buffer` - Detect insecure Buffer constructors
- `security/detect-no-csrf-before-method-override` - Detect CSRF protection placed after method override
- `security/detect-non-literal-fs-filename` - Detect variable used in fs calls
- `security/detect-non-literal-regexp` - Detect RegExp constructed from variable
- `security/detect-non-literal-require` - Detect require() with variable
- `security/detect-object-injection` - Detect object injection (bracket notation with variable)
- `security/detect-possible-timing-attacks` - Detect string comparisons that may lead to timing attacks
- `security/detect-pseudoRandomBytes` - Detect pseudoRandomBytes() which is unsafe

**Configuration**:
```json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-require": "error"
  }
}
```

### 2. eslint-plugin-no-unsanitized
**Purpose**: Disallow unsanitized code in DOM manipulation (XSS prevention)

**Installation**:
```bash
npm install --save-dev eslint-plugin-no-unsanitized
```

**Key Rules**:
- `no-unsanitized/method` - Disallow unsanitized method calls (insertAdjacentHTML, etc.)
- `no-unsanitized/property` - Disallow setting innerHTML, outerHTML without sanitization

**Configuration**:
```json
{
  "plugins": ["no-unsanitized"],
  "rules": {
    "no-unsanitized/method": "error",
    "no-unsanitized/property": "error"
  }
}
```

### 3. @typescript-eslint/eslint-plugin
**Purpose**: TypeScript-specific rules, including security-relevant ones

**Installation**:
```bash
npm install --save-dev @typescript-eslint/parser @typescript-eslint/eslint-plugin
```

**Security-Relevant Rules**:
- `@typescript-eslint/no-implied-eval` - Disallow eval-like methods
- `@typescript-eslint/no-unsafe-assignment` - Disallow assignment of any type
- `@typescript-eslint/no-unsafe-call` - Disallow calling any type
- `@typescript-eslint/no-unsafe-member-access` - Disallow member access on any type
- `@typescript-eslint/no-unsafe-return` - Disallow returning any type

### 4. eslint-plugin-react-security
**Purpose**: React-specific security rules

**Key Rules**:
- Detect dangerous JSX props (dangerouslySetInnerHTML)
- Prevent XSS in React components
- Detect unsafe href values

### 5. eslint-plugin-scanjs-rules
**Purpose**: Security-focused rules from Mozilla's ScanJS project

**Key Detection Areas**:
- Unsafe dynamic code execution
- Insecure authentication patterns
- Dangerous API usage

## Built-in ESLint Security Rules

### Code Execution & Injection
```json
{
  "rules": {
    "no-eval": "error",                        // Disallow eval()
    "no-implied-eval": "error",                // Disallow setTimeout/setInterval with strings
    "no-new-func": "error",                    // Disallow Function constructor
    "no-script-url": "error",                  // Disallow javascript: URLs
    "no-return-await": "error"                 // Disallow unnecessary await expressions
  }
}
```

### Dangerous Patterns
```json
{
  "rules": {
    "no-caller": "error",                      // Disallow arguments.caller/callee
    "no-extend-native": "error",               // Disallow extending native prototypes
    "no-extra-bind": "error",                  // Disallow unnecessary .bind()
    "no-global-assign": "error",               // Disallow assignment to native objects
    "no-iterator": "error",                    // Disallow __iterator__ property
    "no-labels": "error",                      // Disallow labeled statements
    "no-lone-blocks": "error",                 // Disallow unnecessary nested blocks
    "no-proto": "error",                       // Disallow __proto__ property
    "no-self-compare": "error",                // Disallow self-comparison
    "no-sequences": "error",                   // Disallow comma operator
    "no-throw-literal": "error",               // Require throwing Error objects
    "no-useless-call": "error",                // Disallow unnecessary .call()/.apply()
    "no-void": "error",                        // Disallow void operator
    "no-with": "error"                         // Disallow with statements
  }
}
```

### Regular Expressions
```json
{
  "rules": {
    "no-control-regex": "error",               // Disallow control chars in regex
    "no-div-regex": "error",                   // Disallow ambiguous division regex
    "no-empty-character-class": "error",       // Disallow empty character classes in regex
    "no-invalid-regexp": "error",              // Disallow invalid regex
    "no-regex-spaces": "error",                // Disallow multiple spaces in regex
    "prefer-regex-literals": "error"           // Prefer regex literals over constructors
  }
}
```

### Variable & Scope Issues
```json
{
  "rules": {
    "no-shadow": "error",                      // Disallow variable shadowing
    "no-shadow-restricted-names": "error",     // Disallow shadowing restricted names
    "no-undef": "error",                       // Disallow undefined variables
    "no-undefined": "error",                   // Disallow use of undefined
    "no-unused-vars": "error",                 // Disallow unused variables
    "no-use-before-define": "error"            // Disallow use before definition
  }
}
```

## Output Formats

### JSON Format (Recommended for Automation)
```bash
eslint --format json src/ > results.json
```

**Output Structure**:
```json
[
  {
    "filePath": "/path/to/file.js",
    "messages": [
      {
        "ruleId": "no-eval",
        "severity": 2,
        "message": "eval can be harmful.",
        "line": 10,
        "column": 5,
        "nodeType": "CallExpression",
        "messageId": "unexpected",
        "endLine": 10,
        "endColumn": 15
      }
    ],
    "errorCount": 1,
    "warningCount": 0,
    "fixableErrorCount": 0,
    "fixableWarningCount": 0,
    "source": "..."
  }
]
```

### SARIF Format (Industry Standard)
```bash
npm install --save-dev @microsoft/eslint-formatter-sarif
eslint --format @microsoft/eslint-formatter-sarif src/ > results.sarif
```

### Other Useful Formats
- **compact**: Concise one-line-per-issue format
- **unix**: Unix-style output (file:line:column: message)
- **stylish**: Human-readable colored output (default)
- **html**: HTML report with interactive UI
- **checkstyle**: Checkstyle XML format
- **jslint-xml**: JSLint XML format
- **junit**: JUnit XML format
- **tap**: Test Anything Protocol format

## Configuration Options

### .eslintrc.json (Legacy Config)
```json
{
  "env": {
    "browser": true,
    "node": true,
    "es2021": true
  },
  "extends": [
    "eslint:recommended",
    "plugin:security/recommended",
    "plugin:@typescript-eslint/recommended"
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
    // Code execution
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error",
    "no-script-url": "error",
    
    // Security plugins
    "security/detect-object-injection": "warn",
    "security/detect-non-literal-require": "error",
    "security/detect-non-literal-regexp": "error",
    "security/detect-unsafe-regex": "error",
    "security/detect-child-process": "error",
    "security/detect-eval-with-expression": "error",
    "security/detect-non-literal-fs-filename": "error",
    "security/detect-possible-timing-attacks": "error",
    
    // XSS prevention
    "no-unsanitized/method": "error",
    "no-unsanitized/property": "error",
    
    // Dangerous patterns
    "no-with": "error",
    "no-proto": "error",
    "no-extend-native": "error"
  },
  "ignorePatterns": [
    "node_modules/",
    "dist/",
    "build/",
    "*.min.js"
  ]
}
```

### eslint.config.js (Flat Config - ESLint 9+)
```javascript
import js from '@eslint/js';
import security from 'eslint-plugin-security';
import noUnsanitized from 'eslint-plugin-no-unsanitized';
import typescript from '@typescript-eslint/eslint-plugin';
import typescriptParser from '@typescript-eslint/parser';

export default [
  js.configs.recommended,
  {
    files: ['**/*.{js,jsx,ts,tsx}'],
    plugins: {
      security,
      'no-unsanitized': noUnsanitized,
      '@typescript-eslint': typescript
    },
    languageOptions: {
      parser: typescriptParser,
      ecmaVersion: 2021,
      sourceType: 'module',
      globals: {
        // Define global variables
        window: 'readonly',
        document: 'readonly',
        process: 'readonly'
      }
    },
    rules: {
      // Security rules
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'security/detect-object-injection': 'warn',
      'security/detect-unsafe-regex': 'error',
      'no-unsanitized/method': 'error',
      'no-unsanitized/property': 'error'
    }
  },
  {
    ignores: ['node_modules/', 'dist/', 'build/', '*.min.js']
  }
];
```

### Security-Focused Configuration
```json
{
  "extends": [
    "plugin:security/recommended"
  ],
  "plugins": ["security", "no-unsanitized"],
  "rules": {
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error",
    "no-script-url": "error",
    "security/detect-buffer-noassert": "error",
    "security/detect-child-process": "error",
    "security/detect-disable-mustache-escape": "error",
    "security/detect-eval-with-expression": "error",
    "security/detect-new-buffer": "error",
    "security/detect-no-csrf-before-method-override": "error",
    "security/detect-non-literal-fs-filename": "error",
    "security/detect-non-literal-regexp": "error",
    "security/detect-non-literal-require": "error",
    "security/detect-object-injection": "warn",
    "security/detect-possible-timing-attacks": "error",
    "security/detect-pseudoRandomBytes": "error",
    "security/detect-unsafe-regex": "error",
    "no-unsanitized/method": "error",
    "no-unsanitized/property": "error"
  },
  "settings": {
    "no-unsanitized": {
      "escape": {
        "methods": ["escapeHTML", "sanitizeHTML"]
      }
    }
  }
}
```

## Best Practices for Security Scanning

### 1. Use Security-Focused Configuration
Create a dedicated `.eslintrc.security.json` that focuses exclusively on security rules:
- Enable all security plugins
- Set security rules to "error" not "warn"
- Disable inline config to prevent bypassing
- Report unused disable directives

### 2. Integrate into CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Security Scan with ESLint
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
    
    # Parse results and fail on HIGH/CRITICAL issues
    if [ -f eslint-security.json ]; then
      ERROR_COUNT=$(jq '[.[].errorCount] | add' eslint-security.json)
      if [ "$ERROR_COUNT" -gt 0 ]; then
        echo "Security issues found: $ERROR_COUNT errors"
        exit 1
      fi
    fi
```

### 3. Layer Multiple Security Tools
ESLint should be part of a defense-in-depth strategy:
- **ESLint**: JavaScript/TypeScript source code analysis
- **npm audit / yarn audit**: Dependency vulnerability scanning
- **Snyk / WhiteSource**: Advanced dependency & license scanning
- **SonarQube**: Comprehensive code quality & security
- **OWASP Dependency-Check**: CVE detection in dependencies

### 4. Categorize Findings by Severity
Map ESLint rules to security severity levels:
- **CRITICAL**: `no-eval`, `no-implied-eval`, `no-new-func`, `security/detect-eval-*`
- **HIGH**: `security/detect-child-process`, `security/detect-unsafe-regex`, `no-unsanitized/*`
- **MEDIUM**: `security/detect-non-literal-require`, `security/detect-non-literal-regexp`
- **LOW**: `security/detect-object-injection` (many false positives)

### 5. Handle False Positives
Use ESLint's disable syntax responsibly:
```javascript
// Acceptable (with justification)
// eslint-disable-next-line security/detect-object-injection -- Validated input from trusted source
const value = obj[sanitizedKey];

// Better: Use --report-unused-disable-directives to catch forgotten disables
```

### 6. Scan Both Source and Dependencies
```bash
# Scan application code
eslint --config .eslintrc.security.json src/

# Scan node_modules for malicious patterns (use with caution, slow)
eslint --no-ignore node_modules/ --config .eslintrc.security.json
```

### 7. Parse and Report Results
```bash
# Generate human-readable report from JSON
eslint --format json src/ | jq -r '.[] | select(.errorCount > 0) | 
  "File: \(.filePath)\nErrors: \(.errorCount)\nIssues:\n" + 
  ([.messages[] | "  [\(.severity)] \(.ruleId): \(.message) (Line \(.line))"] | join("\n"))'
```

### 8. Monitor Specific Vulnerability Patterns
Focus on OWASP Top 10 and CWE categories:
- **A03: Injection** → `no-eval`, `no-implied-eval`, `security/detect-*-require`
- **A07: XSS** → `no-unsanitized/*`, `no-script-url`
- **A08: Insecure Deserialization** → Custom rules for JSON.parse, eval
- **A09: Using Components with Known Vulnerabilities** → Use npm audit alongside
- **A10: ReDoS** → `security/detect-unsafe-regex`

### 9. Configure for Different Environments
```json
{
  "overrides": [
    {
      "files": ["**/*.test.js", "**/*.spec.js"],
      "rules": {
        "no-eval": "off"  // Allow in tests if needed
      }
    },
    {
      "files": ["**/*.config.js"],
      "rules": {
        "security/detect-non-literal-require": "off"
      }
    }
  ]
}
```

### 10. Regular Updates
Keep ESLint and plugins updated:
```bash
# Check for updates
npm outdated eslint eslint-plugin-security

# Update
npm update eslint eslint-plugin-security eslint-plugin-no-unsanitized
```

## Security Scanning Workflow

### Complete Automated Security Scan Script
```bash
#!/bin/bash
# eslint-security-scan.sh

set -e

REPORT_DIR="security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
JSON_OUTPUT="$REPORT_DIR/eslint-$TIMESTAMP.json"
HTML_OUTPUT="$REPORT_DIR/eslint-$TIMESTAMP.html"
SARIF_OUTPUT="$REPORT_DIR/eslint-$TIMESTAMP.sarif"

mkdir -p "$REPORT_DIR"

echo "🔍 Running ESLint Security Scan..."

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
  echo "📦 Installing dependencies..."
  npm install
fi

# Run ESLint with multiple output formats
echo "📊 Generating reports..."

# JSON format
npx eslint \
  --ext .js,.jsx,.ts,.tsx \
  --format json \
  --output-file "$JSON_OUTPUT" \
  --config .eslintrc.security.json \
  --no-inline-config \
  --report-unused-disable-directives \
  src/ || true

# HTML format
npx eslint \
  --ext .js,.jsx,.ts,.tsx \
  --format html \
  --output-file "$HTML_OUTPUT" \
  --config .eslintrc.security.json \
  src/ || true

# SARIF format (if available)
if npm list @microsoft/eslint-formatter-sarif &>/dev/null; then
  npx eslint \
    --ext .js,.jsx,.ts,.tsx \
    --format @microsoft/eslint-formatter-sarif \
    --output-file "$SARIF_OUTPUT" \
    --config .eslintrc.security.json \
    src/ || true
fi

# Parse results
if [ -f "$JSON_OUTPUT" ]; then
  ERROR_COUNT=$(jq '[.[].errorCount] | add // 0' "$JSON_OUTPUT")
  WARNING_COUNT=$(jq '[.[].warningCount] | add // 0' "$JSON_OUTPUT")
  FILE_COUNT=$(jq 'length' "$JSON_OUTPUT")
  
  echo "✅ Scan complete!"
  echo "📄 Files scanned: $FILE_COUNT"
  echo "❌ Errors: $ERROR_COUNT"
  echo "⚠️  Warnings: $WARNING_COUNT"
  echo ""
  echo "📁 Reports generated:"
  echo "  - JSON: $JSON_OUTPUT"
  echo "  - HTML: $HTML_OUTPUT"
  [ -f "$SARIF_OUTPUT" ] && echo "  - SARIF: $SARIF_OUTPUT"
  
  # Exit with error if issues found
  if [ "$ERROR_COUNT" -gt 0 ]; then
    echo ""
    echo "🚨 Security issues detected! Review reports for details."
    exit 1
  fi
else
  echo "❌ Scan failed - no output generated"
  exit 1
fi
```

## Language Support

### Supported File Types
- JavaScript: `.js`, `.jsx`, `.mjs`, `.cjs`
- TypeScript: `.ts`, `.tsx`
- Vue: `.vue` (with eslint-plugin-vue)
- HTML: Inline scripts with plugins

### Parser Configuration
```json
{
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": 2021,
    "sourceType": "module",
    "ecmaFeatures": {
      "jsx": true,
      "globalReturn": false,
      "impliedStrict": true
    },
    "project": "./tsconfig.json"
  }
}
```

## Integration Examples

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

### VS Code Integration
```json
{
  "eslint.validate": [
    "javascript",
    "javascriptreact",
    "typescript",
    "typescriptreact"
  ],
  "eslint.options": {
    "configFile": ".eslintrc.security.json"
  },
  "eslint.run": "onSave"
}
```

### Docker Container
```dockerfile
FROM node:18-alpine

WORKDIR /app

# Install ESLint and security plugins
RUN npm install -g eslint \
    eslint-plugin-security \
    eslint-plugin-no-unsanitized \
    @typescript-eslint/parser \
    @typescript-eslint/eslint-plugin

# Copy security config
COPY .eslintrc.security.json /app/

# Scan command
ENTRYPOINT ["eslint", "--config", "/app/.eslintrc.security.json"]
```

## Common Security Vulnerabilities Detected

| Vulnerability Type | ESLint Rules | Severity |
|-------------------|--------------|----------|
| Code Injection | `no-eval`, `no-implied-eval`, `no-new-func` | CRITICAL |
| Command Injection | `security/detect-child-process` | HIGH |
| XSS | `no-unsanitized/*`, `no-script-url` | HIGH |
| Path Traversal | `security/detect-non-literal-fs-filename` | HIGH |
| ReDoS | `security/detect-unsafe-regex` | HIGH |
| Timing Attacks | `security/detect-possible-timing-attacks` | MEDIUM |
| Weak Crypto | `security/detect-pseudoRandomBytes` | MEDIUM |
| Unsafe Require | `security/detect-non-literal-require` | MEDIUM |
| Buffer Overflow | `security/detect-buffer-noassert`, `security/detect-new-buffer` | MEDIUM |
| Object Injection | `security/detect-object-injection` | LOW-MEDIUM |
| Prototype Pollution | `no-proto`, `no-extend-native` | MEDIUM |

## Limitations

1. **Static Analysis Only**: Cannot detect runtime vulnerabilities
2. **False Positives**: Especially with `security/detect-object-injection`
3. **No Dataflow Analysis**: Limited ability to track tainted data
4. **Configuration Required**: Needs proper setup for comprehensive scanning
5. **JavaScript/TypeScript Only**: Doesn't scan other languages
6. **No Dependency Scanning**: Doesn't check for vulnerable npm packages (use npm audit)
7. **Pattern-Based**: May miss novel vulnerability patterns

## Complementary Tools

Use ESLint alongside:
- **npm audit / yarn audit** - Dependency vulnerabilities
- **Snyk** - Advanced vulnerability scanning
- **SonarQube** - Comprehensive code analysis
- **Semgrep** - Custom security patterns
- **CodeQL** - Advanced semantic analysis
- **OWASP Dependency-Check** - CVE scanning
- **RetireJS** - JavaScript library vulnerabilities

## References

- Official Docs: https://eslint.org/docs/latest/
- GitHub: https://github.com/eslint/eslint
- Security Plugin: https://github.com/nodesecurity/eslint-plugin-security
- No Unsanitized: https://github.com/mozilla/eslint-plugin-no-unsanitized
- TypeScript ESLint: https://typescript-eslint.io/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE: https://cwe.mitre.org/
