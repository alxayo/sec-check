# Tasks: Security Vulnerability Remediation - Production Hardening

**Generated**: February 2, 2026  
**Input**: Security scan results from `.github/.audit/scan-results.md`  
**Repository**: bookstore-verbose-octo-potato  
**Prerequisites**: Access to affected source files, test environment for validation, Maven 3.6+, Java 11+  
**Validation**: Security re-scan after each phase to verify fixes

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Vulnerabilities** | 5 confirmed |
| **Critical (P0)** | 1 - SQL Injection |
| **High (P1)** | 1 - Hardcoded Secret |
| **Medium (P2)** | 3 - Outdated Dependency (2 CVEs), Shell Issues |
| **Estimated Total Effort** | 5-7 business days |
| **Target Completion** | 1 month from start |
| **Risk if Unaddressed** | Database compromise, credential theft, HTTP smuggling |

### Vulnerability Distribution

```
🔴 Critical (P0): ████████████████████ 20%
🟠 High (P1):     ████████████████████ 20%
🟡 Medium (P2):   ████████████████████████████████████████████████████████████ 60%
```

### Timeline Overview

| Phase | Priority | Duration | SLA | Status |
|-------|----------|----------|-----|--------|
| Phase 1: Triage | ALL | 2 hours | Immediate | 🔲 Not Started |
| Phase 2: SQL Injection | P0 | 8 hours | 24 hours | 🔲 Not Started |
| Phase 3: Secrets | P1 | 1-2 days | 1 week | 🔲 Not Started |
| Phase 4: Hardening | P2 | 2-3 days | 2 weeks | 🔲 Not Started |
| Phase 5: Enhancements | P3 | 3-5 days | 1 month | 🔲 Not Started |
| Phase 6: Validation | ALL | 2 days | 1 month | 🔲 Not Started |

---

## Format: `[ID] [P?] [Severity] Description`

**Legend:**
- **[P]**: Can run in parallel (different files, no dependencies)
- **[Severity]**: CRIT, HIGH, MED, LOW - maps to vulnerability severity
- **File paths**: Absolute from repository root
- **Line numbers**: 1-indexed, as reported in scan results

---

## Phase 1: Triage & Assessment (Immediate - 2 Hours)

**Purpose**: Validate findings and assess blast radius before remediation

**⚠️ BLOCKING**: Must complete before any code changes

- [ ] **T001** [CRIT] Review `.github/.audit/scan-results.md` and confirm all critical findings
  - Verify SQL injection at `src/main/java/com/github/demo/service/BookDatabaseImpl.java:118`
  - Confirm vulnerability exists in current main branch
  - Document affected endpoints: `/books` search functionality

- [ ] **T002** [P] [CRIT] Verify affected endpoints are not publicly exposed
  - Check firewall rules and network topology
  - Review ingress controllers / load balancer configs
  - If exposed: consider temporary WAF rule to block SQL injection patterns

- [ ] **T003** [P] [CRIT] Check for active exploitation indicators in logs
  - Search application logs for suspicious SQL patterns: `' OR '1'='1`, `UNION SELECT`, `--`
  - Check database query logs for malformed queries
  - Review access logs for unusual traffic patterns to `/books` endpoint

- [ ] **T004** [CRIT] Create security incident ticket for tracking
  - Document all findings with severity/CVSS scores
  - Assign to security/ops team for visibility
  - Set up communication channel for incident response
  - Log: 1 CRIT (SQL Injection), 1 HIGH (Secret), 2 MED (Jetty CVEs), 1 MED (Shell)

**Checkpoint**: ✅ All critical vulnerabilities confirmed, no active exploitation detected, incident tracking established

---

## Phase 2: Critical Fixes (P0 - Within 24 Hours) 🚨

**Purpose**: Remediate CRITICAL SQL Injection vulnerability immediately

**⚠️ CRITICAL**: This fix MUST be deployed before any other work proceeds

### SQL Injection - BookDatabaseImpl.java:118

**Finding Reference**: CWE-89, MITRE ATT&CK T1190  
**CVSS Score**: 9.0 (Critical)  
**Impact**: Complete database compromise, data exfiltration, authentication bypass

#### Vulnerability Details

**Current Vulnerable Code** (Line 118):
```java
String query = "SELECT * FROM books WHERE title LIKE '%" + name + "%'";
ResultSet results = stmt.executeQuery(query);
```

**Exploit Examples:**
- Bypass: `' OR '1'='1 --` → Returns all books
- Extract: `' UNION SELECT password FROM users --` → Steal credentials
- Blind: `' AND (SELECT COUNT(*) FROM books) > 10 --` → Boolean-based enumeration

---

#### Remediation Tasks

- [ ] **T005** [CRIT] Create failing security test for SQL injection vulnerability
  - **File**: Create new file `src/test/java/com/github/demo/service/BookDatabaseSecurityTest.java`
  - **Test cases to implement**:
    ```java
    @Test(expected = BookServiceException.class)
    public void testSQLInjection_SingleQuoteBypass() {
        // Payload: ' OR '1'='1 --
        service.getBooksByTitle("' OR '1'='1 --");
    }
    
    @Test(expected = BookServiceException.class)
    public void testSQLInjection_UnionAttack() {
        // Payload: ' UNION SELECT 'a','b','c' --
        service.getBooksByTitle("' UNION SELECT 'a','b','c' --");
    }
    
    @Test(expected = BookServiceException.class)
    public void testSQLInjection_CommentInjection() {
        service.getBooksByTitle("test'; DROP TABLE books; --");
    }
    
    @Test
    public void testValidInput_AcceptsAlphanumeric() {
        // Should work: normal search
        List<Book> books = service.getBooksByTitle("Java");
        assertNotNull(books);
    }
    ```
  - **Expected**: All injection tests should FAIL (return data or execute) initially
  - **Run**: `mvn test -Dtest=BookDatabaseSecurityTest` → Verify tests fail

- [ ] **T006** [CRIT] Fix SQL injection in `src/main/java/com/github/demo/service/BookDatabaseImpl.java:118`
  - **Replace** vulnerable code (lines 113-119):
    ```java
    Statement stmt = null;

    try {
        stmt = connection.createStatement();
        String query = "SELECT * FROM books WHERE title LIKE '%" + name + "%'";

        ResultSet results = stmt.executeQuery(query);
    ```
  - **With** secure parameterized query:
    ```java
    PreparedStatement stmt = null;

    try {
        String query = "SELECT * FROM books WHERE title LIKE ?";
        stmt = connection.prepareStatement(query);
        stmt.setString(1, "%" + name + "%");

        ResultSet results = stmt.executeQuery();
    ```
  - **Update** cleanup block (lines 135-143) to use PreparedStatement instead of Statement
  - **Change**: `if (stmt != null) { stmt.close(); }` → works for both Statement and PreparedStatement

- [ ] **T007** [CRIT] Add input validation for book title search parameter
  - **File**: `src/main/java/com/github/demo/service/BookDatabaseImpl.java`
  - **Location**: Add validation at start of `getBooksByTitle()` method (after line 107)
  - **Validation logic**:
    ```java
    // Input validation
    if (name == null) {
        throw new BookServiceException("Search parameter cannot be null");
    }
    if (name.length() > 100) {
        throw new BookServiceException("Search parameter exceeds maximum length");
    }
    // Reject known SQL injection patterns as defense-in-depth
    String[] sqlKeywords = {"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_", "UNION", "SELECT", "DROP", "DELETE", "INSERT", "UPDATE"};
    for (String keyword : sqlKeywords) {
        if (name.toUpperCase().contains(keyword)) {
            logger.warn("Rejected potentially malicious input: {}", name);
            throw new BookServiceException("Invalid search parameter");
        }
    }
    ```
  - **Note**: Parameterized queries are the primary defense; this is defense-in-depth

- [ ] **T008** [CRIT] Update BookServlet to handle validation exceptions properly
  - **File**: `src/main/java/com/github/demo/servlet/BookServlet.java`
  - **Add**: Proper error handling for invalid input
  - **Return**: HTTP 400 Bad Request for validation failures (not 500 Internal Error)
  - **Log**: Security events for rejected requests

- [ ] **T009** [CRIT] Run security tests to verify fix
  - **Command**: `mvn clean test -Dtest=BookDatabaseSecurityTest`
  - **Expected**: All SQL injection tests should PASS (properly reject malicious input)
  - **Expected**: Valid input test should PASS (normal searches still work)
  - **Verify**: No SQL exceptions in logs, proper validation messages

- [ ] **T010** [CRIT] Run graudit SQL database scan to verify no other SQL injection vulnerabilities
  - **Command**: `graudit -d sql src/main/java/`
  - **Review**: Any findings related to SQL construction
  - **Expected**: No HIGH/CRITICAL findings in database interaction code
  - **Note**: Lines using PreparedStatement are safe (like line 165)

- [ ] **T011** [CRIT] Manual penetration testing of fixed endpoint
  - **Start application**: `mvn clean package && java -jar target/bookstore-*.jar`
  - **Test payloads** against `/books` endpoint:
    ```bash
    # Should be safely rejected/escaped
    curl "http://localhost:8080/books?title=' OR '1'='1 --"
    curl "http://localhost:8080/books?title=' UNION SELECT username,password,email FROM users--"
    curl "http://localhost:8080/books?title=test'; DROP TABLE books; --"
    
    # Should work normally
    curl "http://localhost:8080/books?title=Java"
    curl "http://localhost:8080/books?title=Design Patterns"
    ```
  - **Expected**: Malicious requests return 400 error or no results (not 500)
  - **Expected**: Normal requests return book results successfully

- [ ] **T012** [CRIT] Security code review approval required
  - **Reviewers**: Minimum 2 (1 senior developer + 1 security team member)
  - **Focus areas**:
    - Verify PreparedStatement implementation correctness
    - Confirm no other user input concatenation in SQL
    - Review error handling doesn't leak sensitive info
    - Validate input sanitization logic
  - **Documentation**: Link review to security incident ticket

**Checkpoint**: ✅ SQL Injection vulnerability remediated, all security tests passing, peer-reviewed, ready for deployment

---

## Phase 3: High Priority Fixes (P1 - Within 1 Week)

**Purpose**: Remediate HIGH severity hardcoded credential vulnerability

### Hardcoded API Token - BookServiceTest.java:18

**Finding Reference**: CWE-798 (Use of Hard-coded Credentials)  
**MITRE ATT&CK**: T1552.001 (Credentials In Files)  
**CVSS Score**: 7.5 (High)  
**Impact**: API key exposure, potential service abuse, credential theft from version control

#### Vulnerability Details

**Current Code** (Line 18):
```java
// Testing API token key
private static final String API_TOKEN = "AIzaSyAQfxPJiounkhOjODEO5ZieffeBv6yft2Q";
```

**Risk**: Even in test code, hardcoded secrets can:
- Leak in public repositories
- Be discovered in git history
- Be reused in production by mistake
- Grant unauthorized API access

---

#### Remediation Tasks

- [ ] **T013** [P] [HIGH] Create security test to detect hardcoded secrets
  - **File**: Create new `src/test/java/com/github/demo/SecurityPolicyTest.java`
  - **Test**: Scan test files for hardcoded patterns
  - **Implementation**:
    ```java
    @Test
    public void testNoHardcodedSecrets() throws IOException {
        // Grep for potential API keys, tokens, passwords
        Pattern apiKeyPattern = Pattern.compile(
            "(?i)(api[_-]?key|token|password|secret)\\s*[:=]\\s*['\"][^'\"]+['\"]"
        );
        // Scan all test files
        // Fail if patterns found
    }
    ```
  - **Purpose**: Prevent regression

- [ ] **T014** [HIGH] Remove hardcoded API token from `src/test/java/com/github/demo/service/BookServiceTest.java`
  - **Remove** lines 17-18:
    ```java
    // Testing API token key
    private static final String API_TOKEN = "AIzaSyAQfxPJiounkhOjODEO5ZieffeBv6yft2Q";
    ```
  - **Add** environment-based retrieval if actually needed:
    ```java
    // Load from environment for integration tests only
    private String getApiToken() {
        String token = System.getenv("TEST_API_TOKEN");
        if (token == null) {
            // Skip tests that require API token
            org.junit.Assume.assumeTrue("TEST_API_TOKEN not set, skipping API tests", false);
        }
        return token;
    }
    ```
  - **Note**: If token is not actually used in tests, remove entirely

- [ ] **T015** [HIGH] Verify token is not used anywhere in test code
  - **Command**: `grep -r "API_TOKEN" src/test/`
  - **Expected**: No references after removal
  - **If found**: Update all usages to use environment variable pattern

- [ ] **T016** [HIGH] Rotate the exposed Google API credential
  - **Action**: Revoke `AIzaSyAQfxPJiounkhOjODEO5ZieffeBv6yft2Q` in Google Cloud Console
  - **Generate**: New API key if actually needed for testing
  - **Store**: In CI/CD secrets manager (GitHub Secrets, Vault, etc.)
  - **Document**: Secret rotation procedure for team

- [ ] **T017** [HIGH] Clean git history to remove exposed secret (if repository is public)
  - **Warning**: This is a destructive operation, coordinate with team
  - **Tool**: BFG Repo-Cleaner or `git filter-branch`
  - **Command**:
    ```bash
    # Using BFG (recommended)
    bfg --replace-text secrets.txt  # contains: AIzaSyAQfxPJiounkhOjODEO5ZieffeBv6yft2Q==>REMOVED
    git reflog expire --expire=now --all
    git gc --prune=now --aggressive
    
    # Force push required (use with caution)
    git push --force
    ```
  - **Alternative**: If force push is not acceptable, document that secret is invalidated

- [ ] **T018** [HIGH] Enable GitHub Secret Scanning push protection
  - **Navigate**: Repository Settings → Security → Code security and analysis
  - **Enable**: 
    - Secret scanning
    - Push protection for secret scanning
  - **Configure**: Custom patterns if needed for internal secrets
  - **Test**: Attempt to commit a fake API key pattern, verify rejection

- [ ] **T019** [HIGH] Add pre-commit hook for local secret detection
  - **File**: Create `.githooks/pre-commit`
  - **Implementation**:
    ```bash
    #!/bin/bash
    # Check for potential secrets before commit
    if git diff --cached | grep -iE "(api[_-]?key|token|password|secret).*=.*['\"].*['\"]"; then
        echo "❌ Potential secret detected in staged files"
        echo "Please remove secrets and use environment variables"
        exit 1
    fi
    ```
  - **Install**: `git config core.hooksPath .githooks`
  - **Document**: In README.md for team members

- [ ] **T020** [HIGH] Update documentation for secret management best practices
  - **File**: Create or update `docs/SECURITY.md`
  - **Sections**:
    - Never commit secrets to version control
    - Use environment variables for all credentials
    - Use GitHub Secrets / CI secrets managers
    - How to rotate compromised credentials
    - Secret scanning tools and policies
  - **Audience**: All developers and contributors

**Checkpoint**: ✅ All hardcoded secrets removed, git history cleaned (if applicable), secret scanning enabled, team documentation updated

---

## Phase 4: Medium Priority Fixes (P2 - Within 2 Weeks)

**Purpose**: Remediate MEDIUM severity vulnerabilities and harden infrastructure

### 4A: Outdated Jetty Dependency - pom.xml:21

**Finding Reference**: CVE-2021-34429 (CVSS 5.3), CVE-2021-28169 (CVSS 5.3)  
**Current Version**: 10.0.0  
**Impact**: HTTP request smuggling, authorization bypass, cache poisoning

#### Vulnerability Details

**CVE-2021-34429**: For Eclipse Jetty versions <= 10.0.2, URIs can be crafted using some encoded characters to access protected resources
**CVE-2021-28169**: Jetty requests can be crafted using a suspicious characters like `\0` that can lead to ambiguous URI parsing

---

#### Remediation Tasks

- [ ] **T021** [P] [MED] Research Jetty version compatibility and migration path
  - **Current**: 10.0.0
  - **Check**: Latest stable in 10.x series (likely 10.0.18+)
  - **Review**: Jetty 10.x release notes for breaking changes
  - **Test**: Verify Java 11 compatibility
  - **Document**: Any API changes that might affect code

- [ ] **T022** [MED] Update Jetty version in `pom.xml`
  - **File**: `pom.xml`
  - **Change** line 21:
    ```xml
    <!-- FROM -->
    <jetty.version>10.0.0</jetty.version>
    
    <!-- TO (use latest 10.x version) -->
    <jetty.version>10.0.18</jetty.version>
    ```
  - **Note**: Check Maven Central for latest: https://mvnrepository.com/artifact/org.eclipse.jetty/jetty-server

- [ ] **T023** [MED] Run Maven dependency vulnerability check
  - **Add plugin** to `pom.xml` (in `<build><plugins>` section):
    ```xml
    <plugin>
        <groupId>org.owasp</groupId>
        <artifactId>dependency-check-maven</artifactId>
        <version>8.4.0</version>
        <executions>
            <execution>
                <goals>
                    <goal>check</goal>
                </goals>
            </execution>
        </executions>
        <configuration>
            <failBuildOnCVSS>7</failBuildOnCVSS>
        </configuration>
    </plugin>
    ```
  - **Run**: `mvn dependency-check:check`
  - **Review**: Generated report at `target/dependency-check-report.html`
  - **Expected**: No HIGH/CRITICAL CVEs in Jetty after upgrade

- [ ] **T024** [MED] Run full test suite after Jetty upgrade
  - **Command**: `mvn clean test`
  - **Expected**: All existing tests pass
  - **If failures**: Investigate API changes, update code accordingly
  - **Specific test**: `BookServiceTest.java` and servlet tests

- [ ] **T025** [MED] Manual functional testing after Jetty upgrade
  - **Build**: `mvn clean package`
  - **Run**: `java -jar target/bookstore-*.jar`
  - **Test**:
    ```bash
    # Basic functionality
    curl http://localhost:8080/status
    curl http://localhost:8080/books
    curl "http://localhost:8080/books?title=Java"
    
    # Static resources
    curl http://localhost:8080/static/books.html
    ```
  - **Expected**: All endpoints respond correctly
  - **Check**: No regression in functionality

- [ ] **T026** [MED] Update dependency in CI/CD pipeline
  - **File**: `.github/workflows/*.yml` dependency review workflow
  - **Verify**: Dependabot is configured for Maven
  - **Enable**: Automated PR creation for future Jetty updates
  - **Configure**: Dependabot to check weekly

---

### 4B: Shell Script Quoting Issues

**Finding Reference**: SC2046 (unquoted command substitution), SC2034 (unused variable)  
**Files Affected**:
- `patches/create_patch_set.sh:38,41`
- `patches/apply_patch_set_in_branch.sh:21`
**Impact**: Word splitting, potential command injection if attacker controls input

---

#### Remediation Tasks

- [ ] **T027** [P] [MED] Fix unquoted variable in `patches/create_patch_set.sh`
  - **File**: `patches/create_patch_set.sh`
  - **Fix line 38** (pushd command):
    ```bash
    # FROM
    pushd $(dirname ${sources}) > /dev/null
    
    # TO (quote command substitution and variable)
    pushd "$(dirname "${sources}")" > /dev/null
    ```
  - **Fix line 41** (tar command):
    ```bash
    # FROM
    COPYFILE_DISABLE=1 tar --no-xattrs -cvpzf ${DIR}/${patch_set_name}/patches.tgz $(basename ${sources})
    
    # TO
    COPYFILE_DISABLE=1 tar --no-xattrs -cvpzf "${DIR}/${patch_set_name}/patches.tgz" "$(basename "${sources}")"
    ```
  - **Rationale**: Prevents word splitting if paths contain spaces

- [ ] **T028** [P] [MED] Fix unquoted variable in `patches/apply_patch_set_in_branch.sh`
  - **File**: `patches/apply_patch_set_in_branch.sh`
  - **Fix line 21** (git branch command):
    ```bash
    # FROM
    feature_branch_result=`git branch --list ${feature_branch_name}`
    
    # TO (use $() instead of backticks, add quotes)
    feature_branch_result=$(git branch --list "${feature_branch_name}")
    ```
  - **Fix line 22** (conditional variable name bug):
    ```bash
    # FROM (BUG: uses wrong variable name)
    if  [[ -z $feature_branch_exists ]]; then
    
    # TO
    if [[ -z $feature_branch_result ]]; then
    ```
  - **Note**: This is also a logic bug, not just security

- [ ] **T029** [MED] Run ShellCheck on all shell scripts
  - **Command**: `shellcheck patches/*.sh`
  - **Expected**: No HIGH/CRITICAL issues after fixes
  - **Review**: Any WARNING level issues and fix if relevant
  - **Add to CI**:
    ```yaml
    # .github/workflows/shellcheck.yml
    name: ShellCheck
    on: [push, pull_request]
    jobs:
      shellcheck:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Run ShellCheck
            uses: ludeeus/action-shellcheck@master
            with:
              scandir: './patches'
    ```

- [ ] **T030** [MED] Add shell script unit tests (optional but recommended)
  - **Tool**: BATS (Bash Automated Testing System)
  - **File**: Create `patches/test_patch_scripts.bats`
  - **Tests**:
    ```bash
    @test "create_patch_set handles spaces in paths" {
      # Test with directory name containing spaces
    }
    
    @test "apply_patch_set_in_branch validates input" {
      # Test with malicious input
    }
    ```
  - **Run**: `bats patches/test_patch_scripts.bats`

**Checkpoint**: ✅ Jetty upgraded to patched version (10.0.18+), all shell scripts properly quoted, ShellCheck passing

---

## Phase 5: Low Priority & Hardening (P3 - Within 1 Month)

**Purpose**: Implement defense-in-depth and improve security posture

### General Security Hardening

- [ ] **T031** [P] [LOW] Add security headers to HTTP responses
  - **File**: Update `src/main/java/com/github/demo/servlet/BookServlet.java`
  - **Add** in `doGet()` method:
    ```java
    // Security headers
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("X-XSS-Protection", "1; mode=block");
    response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    ```
  - **Apply to all servlets**: BookServlet, StatusServlet
  - **Test**: Verify headers in response: `curl -I http://localhost:8080/books`

- [ ] **T032** [P] [LOW] Implement security audit logging
  - **File**: Update `src/main/resources/log4j2.xml`
  - **Add** security event logger:
    ```xml
    <Logger name="SECURITY" level="warn" additivity="false">
        <AppenderRef ref="SecurityFile"/>
    </Logger>
    ```
  - **Create security appender**: Separate log file for security events
  - **Log events**:
    - Failed SQL injection attempts (from input validation)
    - Invalid authentication attempts
    - Suspicious request patterns
    - Rate limit violations

- [ ] **T033** [P] [LOW] Add rate limiting for search endpoint
  - **File**: Create `src/main/java/com/github/demo/servlet/filter/RateLimitFilter.java`
  - **Implementation**: Simple in-memory rate limiter (or use library like Bucket4j)
  - **Configuration**: 
    - 100 requests per minute per IP
    - 1000 requests per minute per application
  - **Response**: HTTP 429 Too Many Requests when exceeded
  - **Purpose**: Mitigate brute-force SQL injection attempts

- [ ] **T034** [P] [LOW] Add input length limits to all user inputs
  - **Files**: All servlet files
  - **Limits**:
    - Book title search: 100 characters (already in T007)
    - Other text fields: Define reasonable limits
  - **Validation**: Centralized validation utility class
  - **Response**: HTTP 400 with clear error message

- [ ] **T035** [P] [LOW] Review and update database connection security
  - **File**: `src/main/java/com/github/demo/service/BookDatabaseImpl.java`
  - **Review**:
    - SSL connection enforcement (line 59: currently disabled)
    - Connection string validation
    - Credential storage (currently uses environment variables ✅)
  - **Recommendation**: Enable SSL for production database connections
  - **Update** line 59:
    ```java
    // FROM
    props.setProperty("ssl", "false");
    
    // TO (for production profile)
    props.setProperty("ssl", "true");
    props.setProperty("sslmode", "require");
    ```

- [ ] **T036** [LOW] Update security documentation
  - **File**: `docs/SECURITY.md` (created in T020)
  - **Add sections**:
    - Secure coding guidelines for SQL queries
    - Input validation best practices
    - Secret management policy
    - Security testing requirements
    - Vulnerability disclosure policy
    - Security contact information
  - **Link**: From README.md

- [ ] **T037** [LOW] Create security checklist for code reviews
  - **File**: Create `.github/PULL_REQUEST_TEMPLATE.md`
  - **Security section**:
    ```markdown
    ## Security Checklist
    - [ ] No SQL queries with string concatenation
    - [ ] All user input validated and sanitized
    - [ ] No hardcoded secrets or credentials
    - [ ] Security headers added for new endpoints
    - [ ] Dependencies have no known HIGH/CRITICAL CVEs
    - [ ] Security tests added for new features
    ```

- [ ] **T038** [LOW] Configure Dependabot for automated dependency updates
  - **File**: Create `.github/dependabot.yml`
  - **Configuration**:
    ```yaml
    version: 2
    updates:
      - package-ecosystem: "maven"
        directory: "/"
        schedule:
          interval: "weekly"
        open-pull-requests-limit: 10
        labels:
          - "dependencies"
          - "security"
        reviewers:
          - "security-team"
    ```
  - **Enable**: Security updates (auto-merge minor/patch for security)

**Checkpoint**: ✅ Defense-in-depth measures implemented, security documentation complete, automated updates configured

---

## Phase 6: Validation & Prevention (Final Phase)

**Purpose**: Verify all fixes and prevent regression

### Comprehensive Security Validation

- [ ] **T039** [P] [CRIT] Run full graudit security scan on all code
  - **Command**:
    ```bash
    # SQL injection patterns
    graudit -d sql src/main/java/ > .github/.audit/graudit-sql-rescan.txt
    
    # Secrets detection
    graudit -d secrets . > .github/.audit/graudit-secrets-rescan.txt
    
    # Command execution patterns
    graudit -d exec src/ patches/ > .github/.audit/graudit-exec-rescan.txt
    ```
  - **Expected**: Zero HIGH/CRITICAL findings
  - **Document**: Any acceptable LOW/INFO findings with justification

- [ ] **T040** [P] [CRIT] Run Maven OWASP dependency check
  - **Command**: `mvn dependency-check:check`
  - **Review**: `target/dependency-check-report.html`
  - **Expected**: No CVEs with CVSS >= 7.0
  - **Document**: Any acceptable lower-severity CVEs with mitigation notes

- [ ] **T041** [P] [CRIT] Execute all security test suites
  - **Command**: `mvn clean test`
  - **Specific tests**:
    - `BookDatabaseSecurityTest` → SQL injection prevention
    - `SecurityPolicyTest` → No hardcoded secrets
    - All functional tests → No regression
  - **Coverage**: Verify security-critical code has >= 80% coverage
  - **Report**: `target/site/jacoco/index.html`

- [ ] **T042** [MED] Execute penetration testing on running application
  - **Setup**: Deploy to test environment
  - **Automated tool**: OWASP ZAP or Burp Suite Community
  - **Manual tests**:
    ```bash
    # SQL injection attempts (should be blocked)
    curl "http://localhost:8080/books?title=' OR '1'='1 --"
    curl "http://localhost:8080/books?title=' UNION SELECT * FROM users--"
    
    # Path traversal
    curl "http://localhost:8080/static/../../etc/passwd"
    
    # XSS attempts
    curl "http://localhost:8080/books?title=<script>alert('xss')</script>"
    
    # Header injection
    curl -H "X-Forwarded-For: 127.0.0.1; DROP TABLE books;" http://localhost:8080/status
    ```
  - **Expected**: All attacks properly mitigated
  - **Document**: Test results and evidence of prevention

- [ ] **T043** [MED] Set up Git pre-commit hooks for secret scanning
  - **Tool**: Gitleaks or git-secrets
  - **Installation**:
    ```bash
    # Using gitleaks
    brew install gitleaks  # or appropriate package manager
    
    # Configure pre-commit hook
    cat > .githooks/pre-commit << 'EOF'
    #!/bin/bash
    gitleaks protect --staged --verbose
    if [ $? -eq 1 ]; then
        echo "❌ Gitleaks detected secrets in staged files"
        exit 1
    fi
    EOF
    chmod +x .githooks/pre-commit
    git config core.hooksPath .githooks
    ```
  - **Test**: Attempt to commit file with fake secret
  - **Document**: Setup instructions in README.md

- [ ] **T044** [MED] Configure CI/CD security scanning integration
  - **CodeQL**: Already configured, verify it's running
  - **Container scanning**: Verify Trivy or similar is scanning Docker images
  - **Add**: SAST tool (SpotBugs + FindSecBugs for Java)
    ```xml
    <!-- Add to pom.xml -->
    <plugin>
        <groupId>com.github.spotbugs</groupId>
        <artifactId>spotbugs-maven-plugin</artifactId>
        <version>4.7.3.6</version>
        <dependencies>
            <dependency>
                <groupId>com.h3xstream.findsecbugs</groupId>
                <artifactId>findsecbugs-plugin</artifactId>
                <version>1.12.0</version>
            </dependency>
        </dependencies>
    </plugin>
    ```
  - **GitHub Action**: Add security scanning to PR workflow

- [ ] **T045** [LOW] Update README.md with security information
  - **File**: `README.md`
  - **Add badge**: Security scan status
  - **Add section**: "Security"
    ```markdown
    ## Security
    
    For security vulnerabilities, please see [SECURITY.md](docs/SECURITY.md).
    
    This project uses:
    - GitHub CodeQL for static analysis
    - OWASP Dependency Check for CVE detection
    - Secret scanning with push protection
    - Automated security testing in CI/CD
    ```

- [ ] **T046** [LOW] Schedule security review meeting with team
  - **Purpose**: Present remediation results and lessons learned
  - **Attendees**: Dev team, security team, ops/SRE
  - **Agenda**:
    - Summary of vulnerabilities and fixes
    - Demo of security testing
    - Review new security policies and tools
    - Q&A on secure coding practices
  - **Output**: Action items for ongoing security improvement

- [ ] **T047** [LOW] Create runbook for security incident response
  - **File**: `docs/INCIDENT_RESPONSE.md`
  - **Sections**:
    - Severity classification
    - Escalation procedures
    - Communication templates
    - Rollback procedures
    - Post-incident review template
  - **Practice**: Schedule security drill/tabletop exercise

**Checkpoint**: ✅ All vulnerabilities remediated and verified, preventive measures operational, team trained

---

## Dependencies & Execution Order

### Phase Dependencies

```
Phase 1 (Triage)
    ↓
Phase 2 (SQL Injection) ← BLOCKING - Must complete before Phase 3-5
    ↓
    ├─→ Phase 3 (Secrets) ────┐
    ├─→ Phase 4A (Jetty) ─────┤
    ├─→ Phase 4B (Shell) ─────┤
    └─→ Phase 5 (Hardening) ──┘
              ↓
        Phase 6 (Validation)
```

### Critical Path

1. **T001-T004**: Triage (2 hours) → BLOCKS all development
2. **T005-T012**: SQL Injection (8 hours) → BLOCKS deployment
3. **T013-T020**: Secrets (1-2 days) → Can run parallel with Phase 4
4. **T021-T030**: Dependencies + Shell (2-3 days) → Run parallel
5. **T031-T038**: Hardening (3-5 days) → Run parallel
6. **T039-T047**: Validation (2 days) → Depends on all previous phases

### Parallel Execution Opportunities

**During Phase 3-5 (after SQL injection is fixed):**

| Task Group | Tasks | Owner | Duration |
|------------|-------|-------|----------|
| Secrets Removal | T013-T020 | Dev A | 1-2 days |
| Jetty Upgrade | T021-T026 | Dev B | 2-3 days |
| Shell Hardening | T027-T030 | Dev C | 1 day |
| Security Features | T031-T035 | Dev D | 3-5 days |
| Documentation | T036-T038 | Dev E | 2-3 days |

**All groups can work in parallel since they modify different files**

---

## Vulnerability-Specific Remediation Patterns

### SQL Injection (CWE-89) - Applied in Phase 2

**Fix Pattern:**
1. ✅ Replace string concatenation with `PreparedStatement`
2. ✅ Use `setString()` for binding parameters
3. ✅ Add input validation as defense-in-depth
4. ✅ Implement query logging for monitoring
5. ✅ Write security tests that verify injection is blocked

**Java Example:**
```java
// ❌ VULNERABLE
String query = "SELECT * FROM books WHERE title LIKE '%" + userInput + "%'";
ResultSet rs = stmt.executeQuery(query);

// ✅ SECURE
String query = "SELECT * FROM books WHERE title LIKE ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, "%" + validateInput(userInput) + "%");
ResultSet rs = pstmt.executeQuery();
```

---

### Hardcoded Secrets (CWE-798) - Applied in Phase 3

**Fix Pattern:**
1. ✅ Remove secret from source code immediately
2. ✅ Rotate the exposed credential (invalidate old one)
3. ✅ Use environment variables or secret manager
4. ✅ Add secret scanning to CI/CD pipeline
5. ✅ Clean git history if repository is public
6. ✅ Document secret management policy

**Java Example:**
```java
// ❌ VULNERABLE
private static final String API_KEY = "AIzaSyAQfxPJiounkhOjODEO5ZieffeBv6yft2Q";

// ✅ SECURE
private String getApiKey() {
    String key = System.getenv("API_KEY");
    if (key == null) {
        throw new IllegalStateException("API_KEY environment variable not set");
    }
    return key;
}
```

---

### Outdated Dependencies - Applied in Phase 4

**Fix Pattern:**
1. ✅ Review CVEs for current version (NVD, GitHub Security Advisories)
2. ✅ Update to patched version (check compatibility)
3. ✅ Run full test suite to verify no breaking changes
4. ✅ Enable automated dependency updates (Dependabot, Renovate)
5. ✅ Configure CVSS threshold for automatic blocking

**Maven Example:**
```xml
<!-- ❌ VULNERABLE -->
<jetty.version>10.0.0</jetty.version>

<!-- ✅ SECURE -->
<jetty.version>10.0.18</jetty.version>

<!-- Add OWASP Dependency Check -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>8.4.0</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
    </configuration>
</plugin>
```

---

### Shell Script Issues (CWE-78 potential) - Applied in Phase 4

**Fix Pattern:**
1. ✅ Quote all variable expansions: `"${variable}"` not `$variable`
2. ✅ Quote command substitutions: `"$(command)"` not `` `command` ``
3. ✅ Use arrays for multi-word arguments
4. ✅ Validate input parameters before use
5. ✅ Use ShellCheck in CI/CD
6. ✅ Avoid `eval` and shell=True in subprocess calls

**Bash Example:**
```bash
# ❌ VULNERABLE
pushd $(dirname ${sources})
tar -czf ${output} $(basename ${input})

# ✅ SECURE
pushd "$(dirname "${sources}")" || exit 1
tar -czf "${output}" "$(basename "${input}")"
```

---

## Verification Commands Reference

### Security Testing Commands

```bash
# SQL Injection Testing
mvn test -Dtest=BookDatabaseSecurityTest
graudit -d sql src/main/java/

# Secret Scanning
graudit -d secrets .
gitleaks detect --source . --verbose

# Dependency Vulnerability Scanning
mvn dependency-check:check
mvn versions:display-dependency-updates

# Shell Script Linting
shellcheck patches/*.sh

# Full Build with Security Checks
mvn clean verify
mvn spotbugs:check

# Code Coverage (including security tests)
mvn clean test jacoco:report
open target/site/jacoco/index.html
```

### Manual Penetration Testing

```bash
# Start application
mvn clean package
java -jar target/bookstore-*.jar &
APP_PID=$!

# Wait for startup
sleep 5

# Test SQL Injection (should be rejected)
echo "Testing SQL Injection..."
curl -v "http://localhost:8080/books?title=' OR '1'='1 --"
curl -v "http://localhost:8080/books?title=' UNION SELECT 'a','b','c' --"

# Test valid requests (should work)
echo "Testing valid requests..."
curl -v "http://localhost:8080/books?title=Java"
curl -v "http://localhost:8080/status"

# Test security headers
echo "Checking security headers..."
curl -I http://localhost:8080/books | grep -E "(X-.*:|Content-Security-Policy)"

# Cleanup
kill $APP_PID
```

### CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Java
        uses: actions/setup-java@v3
        with:
          java-version: '11'
          
      - name: Run OWASP Dependency Check
        run: mvn dependency-check:check
        
      - name: Run Security Tests
        run: mvn test -Dtest=*SecurityTest
        
      - name: ShellCheck
        run: shellcheck patches/*.sh
        
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
```

---

## Risk Assessment Matrix

| Vulnerability | Pre-Fix Risk | Post-Fix Risk | Risk Reduction |
|---------------|--------------|---------------|----------------|
| SQL Injection | 🔴 Critical (9.0) | 🟢 Low (2.0) | 77% |
| Hardcoded Secret | 🟠 High (7.5) | 🟢 Low (1.5) | 80% |
| Jetty CVEs | 🟡 Medium (5.3) | 🟢 Low (0.0) | 100% |
| Shell Quoting | 🟡 Medium (4.0) | 🟢 Low (1.0) | 75% |

**Overall Security Posture:**
- **Before**: 🔴 Critical - Not production ready
- **After**: 🟢 Low - Production ready with defense-in-depth

---

## Success Criteria

### Phase Completion Checklist

- [ ] **Phase 1**: All findings triaged, no active exploitation detected
- [ ] **Phase 2**: SQL injection fixed, security tests passing, deployed to production
- [ ] **Phase 3**: All secrets removed, git history cleaned, scanning enabled
- [ ] **Phase 4**: Jetty upgraded, shell scripts hardened, all tests passing
- [ ] **Phase 5**: Security features implemented, documentation complete
- [ ] **Phase 6**: Full security scan shows zero HIGH/CRITICAL findings

### Production Readiness Gates

- ✅ Zero CRITICAL vulnerabilities
- ✅ Zero HIGH vulnerabilities in production code
- ✅ All security tests passing
- ✅ Code coverage >= 80% for security-critical code
- ✅ Security code review completed
- ✅ Penetration testing completed with no critical findings
- ✅ Incident response runbook in place
- ✅ Security monitoring and logging operational

---

## Notes

- This plan assumes standard development tools (Maven, Git, Java 11, bash)
- All line numbers are 1-indexed as reported in original scan results
- Some tasks marked [P] can run in parallel to save time
- Security-critical tasks (CRIT) should have dual review
- After Phase 2, the application can be deployed to production (with fixes from Phase 3-5 following)
- Regular security re-scans recommended quarterly even after remediation

**Estimated Total Timeline**: 3-4 weeks from start to full completion
**Estimated Effort**: 5-7 business days of engineering time (can be parallelized)

---

*Generated by Security Remediation Planning Agent*  
*For questions or clarifications, contact security team*
