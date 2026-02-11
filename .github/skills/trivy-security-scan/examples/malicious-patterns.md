```markdown
# Patterns and Issues Detected by Trivy

This document provides examples of security issues that Trivy can detect across its four scanners: vulnerabilities, misconfigurations, secrets, and licenses.

## Vulnerability Detection

Trivy detects known CVEs in OS packages and language dependencies.

### Vulnerable Package Examples

```
# Python - requests with CVE
requests==2.19.0  # CVE-2018-18074: Bypass of proxy settings

# Node.js - lodash with CVE
"lodash": "4.17.15"  # CVE-2021-23337: Prototype pollution

# Go - yaml with CVE
gopkg.in/yaml.v2 v2.2.2  # CVE-2019-11253: Billion laughs DoS

# Java - log4j with CVE
log4j-core:2.14.0  # CVE-2021-44228: Log4Shell RCE

# Ruby - rack with CVE
rack (2.0.5)  # CVE-2019-16782: Session hijacking
```

### Example Trivy Vulnerability Output

```
Python (requirements.txt)
========================
Total: 3 (HIGH: 2, CRITICAL: 1)

┌──────────────┬────────────────┬──────────┬───────────────────┬───────────────┬────────────────────────────────────────┐
│   Library    │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                 Title                  │
├──────────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────────┤
│ requests     │ CVE-2018-18074 │ HIGH     │ 2.19.0            │ 2.20.0        │ python-requests: Incorrect proxy...    │
│ django       │ CVE-2021-35042 │ CRITICAL │ 3.1.0             │ 3.1.13        │ SQL Injection via QuerySet.order_by    │
│ pyyaml       │ CVE-2020-14343 │ HIGH     │ 5.3.0             │ 5.4           │ Arbitrary code execution via yaml.load │
└──────────────┴────────────────┴──────────┴───────────────────┴───────────────┴────────────────────────────────────────┘
```

## Secret Detection

Trivy identifies hardcoded secrets in code, configuration files, and container images.

### Hardcoded Secrets Patterns

#### AWS Credentials
```python
# DETECTED: AWS Access Key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# In environment files
# .env
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
```

#### API Tokens
```javascript
// DETECTED: GitHub Personal Access Token
const GITHUB_TOKEN = "ghp_EXAMPLETOKEN1234567890abcdefghijk";

// DETECTED: Slack Token
const SLACK_TOKEN = "xoxb-EXAMPLE-TOKEN-PLACEHOLDER";

// DETECTED: Stripe API Key
const STRIPE_KEY = "sk_test_EXAMPLE_KEY_PLACEHOLDER";
```

#### Database Credentials
```yaml
# DETECTED: Hardcoded database password
database:
  host: localhost
  username: admin
  password: SuperSecret123!
  connection_string: "postgresql://admin:SuperSecret123!@db.example.com:5432/prod"
```

#### Private Keys
```
# DETECTED: SSH Private Key
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----

# DETECTED: TLS Private Key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBg...
-----END PRIVATE KEY-----
```

#### JWT Secrets
```javascript
// DETECTED: JWT Secret
const JWT_SECRET = "my-super-secret-jwt-signing-key-12345";

// DETECTED: Azure connection string
const AZURE_CONN = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123...";
```

### Example Trivy Secret Output

```
secretscan/config.py (secrets)
==============================
Total: 4 (HIGH: 2, CRITICAL: 2)

┌────────────────────────┬───────────┬────────┬────────────────────────────────────────────────┐
│        Rule ID         │  Category │  Line  │                    Match                       │
├────────────────────────┼───────────┼────────┼────────────────────────────────────────────────┤
│ aws-access-key-id      │ AWS       │   15   │ AKIAIOSFODNN7EXAMPLE                           │
│ aws-secret-access-key  │ AWS       │   16   │ wJalrXUtnFEMI/K7MDENG/bPxRfiCY...              │
│ github-pat             │ GitHub    │   23   │ ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx               │
│ generic-api-key        │ Generic   │   45   │ api_key = "sk_live_xxxxxx"                     │
└────────────────────────┴───────────┴────────┴────────────────────────────────────────────────┘
```

## Misconfiguration Detection

Trivy detects security misconfigurations in Infrastructure as Code.

### Dockerfile Misconfigurations

```dockerfile
# DETECTED: DS002 - Running as root user
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y nginx
# Missing: USER nonroot

# DETECTED: DS001 - Using latest tag (unpinned)
FROM python:latest

# DETECTED: DS005 - ADD used instead of COPY
ADD https://example.com/file.tar.gz /app/

# DETECTED: DS026 - Healthcheck missing
# No HEALTHCHECK instruction

# BETTER PRACTICE:
FROM python:3.12-slim
RUN useradd -m appuser
USER appuser
COPY --chown=appuser:appuser . /app/
HEALTHCHECK CMD curl --fail http://localhost:8080/health || exit 1
```

### Kubernetes Misconfigurations

```yaml
# DETECTED: KSV001 - Container running as root
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsUser: 0  # Running as root!
      
# DETECTED: KSV003 - Container has SYS_ADMIN capability
    securityContext:
      capabilities:
        add: ["SYS_ADMIN"]

# DETECTED: KSV006 - Privileged container
    securityContext:
      privileged: true

# DETECTED: KSV012 - No resource limits
    # Missing: resources.limits

# DETECTED: KSV014 - Root filesystem not read-only
    # Missing: readOnlyRootFilesystem: true

# DETECTED: KSV021 - Using default namespace
metadata:
  namespace: default  # Should use dedicated namespace

# BETTER PRACTICE:
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
      requests:
        memory: "128Mi"
        cpu: "250m"
```

### Terraform Misconfigurations

```hcl
# DETECTED: AVD-AWS-0086 - S3 bucket has public access
resource "aws_s3_bucket" "data" {
  bucket = "my-public-bucket"
  acl    = "public-read"  # Public access!
}

# DETECTED: AVD-AWS-0088 - S3 logging disabled
resource "aws_s3_bucket" "logs" {
  bucket = "my-logs-bucket"
  # Missing: logging configuration
}

# DETECTED: AVD-AWS-0089 - S3 versioning disabled
resource "aws_s3_bucket" "backups" {
  bucket = "my-backups"
  # Missing: versioning { enabled = true }
}

# DETECTED: AVD-AWS-0057 - RDS instance publicly accessible
resource "aws_db_instance" "database" {
  identifier     = "production-db"
  engine         = "mysql"
  instance_class = "db.t3.micro"
  publicly_accessible = true  # Should be false!
}

# DETECTED: AVD-AWS-0080 - Security group allows all ingress
resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Open to the world!
  }
}

# DETECTED: AVD-AWS-0025 - EC2 instance has no IAM role
resource "aws_instance" "server" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  # Missing: iam_instance_profile
}

# BETTER PRACTICE:
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```

### Helm Chart Misconfigurations

```yaml
# values.yaml with security issues

# DETECTED: KSV001 - Running as root
securityContext:
  runAsUser: 0

# DETECTED: Resource limits not set
resources: {}

# DETECTED: No network policy
networkPolicy:
  enabled: false

# BETTER PRACTICE:
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
    
networkPolicy:
  enabled: true
```

### CloudFormation Misconfigurations

```yaml
# DETECTED: AVD-AWS-0086 - S3 bucket without encryption
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-unencrypted-bucket
      # Missing: BucketEncryption

# DETECTED: AVD-AWS-0080 - Security group with open ingress
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Web server security group
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0  # SSH open to world!
```

### Example Trivy Misconfiguration Output

```
Dockerfile (dockerfile)
=======================
Tests: 26 (SUCCESSES: 22, FAILURES: 4)
Failures: 4 (HIGH: 2, MEDIUM: 2)

┌──────────┬────────────────────────────────────────────────────────────────┬──────────┬────────┐
│  ID      │                            Title                               │ Severity │  Line  │
├──────────┼────────────────────────────────────────────────────────────────┼──────────┼────────┤
│ DS002    │ Image user should not be 'root'                                │ HIGH     │   N/A  │
│ DS001    │ ':latest' tag used                                             │ MEDIUM   │   1    │
│ DS005    │ ADD instead of COPY                                            │ MEDIUM   │   5    │
│ DS026    │ No HEALTHCHECK defined                                         │ HIGH     │   N/A  │
└──────────┴────────────────────────────────────────────────────────────────┴──────────┴────────┘
```

## License Detection

Trivy identifies software licenses for compliance auditing.

### License Categories

| Category | Examples | Risk Level |
|----------|----------|------------|
| **Permissive** | MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC | Low - Generally safe for commercial use |
| **Weak Copyleft** | LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-1.0 | Medium - May require source disclosure for modified files |
| **Strong Copyleft** | GPL-2.0, GPL-3.0, AGPL-3.0 | High - May require full source disclosure |
| **Proprietary** | Commercial licenses | Requires review and possibly payment |
| **Unknown** | License not detected | Requires manual investigation |

### Example License Output

```
Python (requirements.txt)
=========================
License scan found issues

┌──────────────┬───────────────┬─────────────┬────────────────────┐
│   Library    │    Version    │   License   │     Category       │
├──────────────┼───────────────┼─────────────┼────────────────────┤
│ numpy        │ 1.24.0        │ BSD-3       │ Permissive         │
│ requests     │ 2.31.0        │ Apache-2.0  │ Permissive         │
│ psycopg2     │ 2.9.9         │ LGPL-3.0    │ Weak Copyleft      │
│ pyqt6        │ 6.6.0         │ GPL-3.0     │ Strong Copyleft    │
│ custom-lib   │ 1.0.0         │ Unknown     │ Unknown            │
└──────────────┴───────────────┴─────────────┴────────────────────┘
```

## Container Image Layers

Trivy scans all layers of container images, detecting issues introduced at any stage.

### Multi-Stage Build Example

```dockerfile
# Build stage - vulnerabilities here won't be in final image
FROM python:3.12 AS builder
RUN pip install build
COPY . /src
RUN python -m build

# Final stage - this is what gets scanned
FROM python:3.12-slim
# DETECTED: Installing vulnerable package
RUN pip install requests==2.19.0

# DETECTED: Secrets in environment
ENV API_KEY=sk_live_xxxxxxxx

# DETECTED: Running as root
COPY --from=builder /src/dist/*.whl /app/
RUN pip install /app/*.whl
```

## How to Test Trivy Detection

### Create Test Files

```bash
# Create a project with detectable issues
mkdir trivy-test && cd trivy-test

# Create vulnerable requirements.txt
cat > requirements.txt << 'EOF'
requests==2.19.0
django==3.1.0
pyyaml==5.3.0
EOF

# Create file with secrets
cat > config.py << 'EOF'
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
EOF

# Create insecure Dockerfile
cat > Dockerfile << 'EOF'
FROM python:latest
COPY . /app
RUN pip install -r /app/requirements.txt
EOF

# Create insecure K8s manifest
cat > deployment.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: insecure
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsUser: 0
      privileged: true
EOF
```

### Run Trivy Scans

```bash
# Scan for vulnerabilities
trivy fs --scanners vuln ./

# Scan for secrets
trivy fs --scanners secret ./

# Scan for misconfigurations
trivy config ./

# Comprehensive scan
trivy fs --scanners vuln,secret,misconfig ./
```

### Expected Output

```
requirements.txt (python)
=========================
Total: 3 (HIGH: 2, CRITICAL: 1)

config.py (secrets)
===================
Total: 3 (CRITICAL: 3)

Dockerfile (dockerfile)
=======================
Failures: 2 (HIGH: 1, MEDIUM: 1)

deployment.yaml (kubernetes)
============================
Failures: 2 (HIGH: 2)
```

## Summary of Detection Capabilities

| Scanner | What It Finds | File Types |
|---------|---------------|------------|
| **vuln** | CVEs in packages | package.json, requirements.txt, go.sum, pom.xml, Gemfile.lock, etc. |
| **secret** | Hardcoded credentials | All text files |
| **misconfig** | IaC security issues | Dockerfile, *.tf, *.yaml (K8s), Chart.yaml, *.json (CFN) |
| **license** | License compliance | Package manifests |

## Related Resources

- [Trivy Documentation](https://trivy.dev/docs/latest/)
- [CVE Details](https://www.cvedetails.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [OWASP Top 10](https://owasp.org/Top10/)
```
