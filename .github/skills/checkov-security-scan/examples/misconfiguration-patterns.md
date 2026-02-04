# IaC Misconfiguration Patterns Detected by Checkov

This reference shows example Infrastructure as Code (IaC) misconfigurations that Checkov detects. Use these examples to understand what the scanner looks for and how to remediate issues.

## Terraform (AWS) Patterns

### CKV_AWS_1: Overly Permissive IAM Policy

```hcl
# INSECURE: Full admin privileges ("*" actions on "*" resources)
resource "aws_iam_policy" "admin_policy" {
  name = "full-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"           # <- Issue: Allows all actions
        Resource = "*"           # <- Issue: On all resources
      }
    ]
  })
}

# SECURE: Least privilege - only required permissions
resource "aws_iam_policy" "minimal_policy" {
  name = "s3-read-only"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
      }
    ]
  })
}
```

### CKV_AWS_20: Publicly Readable S3 Bucket

```hcl
# INSECURE: S3 bucket with public-read ACL
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
}

resource "aws_s3_bucket_acl" "public_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read"    # <- Issue: World-readable
}

# SECURE: Private bucket with explicit block
resource "aws_s3_bucket" "private_bucket" {
  bucket = "my-private-bucket"
}

resource "aws_s3_bucket_public_access_block" "private_bucket_block" {
  bucket = aws_s3_bucket.private_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### CKV_AWS_19: S3 Bucket Without Encryption

```hcl
# INSECURE: No server-side encryption configured
resource "aws_s3_bucket" "unencrypted" {
  bucket = "my-unencrypted-bucket"
}

# SECURE: Server-side encryption enabled
resource "aws_s3_bucket" "encrypted" {
  bucket = "my-encrypted-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted" {
  bucket = aws_s3_bucket.encrypted.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
```

### CKV_AWS_24: Security Group Allows SSH from Internet

```hcl
# INSECURE: SSH open to the world
resource "aws_security_group" "ssh_open" {
  name = "allow-ssh-anywhere"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # <- Issue: Open to internet
  }
}

# SECURE: SSH restricted to trusted IPs
resource "aws_security_group" "ssh_restricted" {
  name = "allow-ssh-trusted"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal network only
  }
}
```

### CKV_AWS_3: Unencrypted EBS Volume

```hcl
# INSECURE: EBS volume without encryption
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false  # <- Issue: Data at rest not encrypted
}

# SECURE: Encrypted EBS volume
resource "aws_ebs_volume" "encrypted" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs_key.arn
}
```

### CKV2_AWS_6: S3 Bucket Without Logging

```hcl
# INSECURE: No access logging configured
resource "aws_s3_bucket" "no_logging" {
  bucket = "my-bucket-no-logging"
}

# SECURE: Access logging enabled
resource "aws_s3_bucket" "with_logging" {
  bucket = "my-bucket-with-logging"
}

resource "aws_s3_bucket_logging" "with_logging" {
  bucket = aws_s3_bucket.with_logging.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "access-logs/"
}
```

---

## Kubernetes Patterns

### CKV_K8S_2: Privileged Container

```yaml
# INSECURE: Container runs with full host privileges
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true        # <- Issue: Full host access

---
# SECURE: Non-privileged container
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 1000
```

### CKV_K8S_3: Container Running as Root

```yaml
# INSECURE: Container runs as root user
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
spec:
  containers:
    - name: app
      image: nginx
      # No securityContext - defaults to root

---
# SECURE: Container runs as non-root
apiVersion: v1
kind: Pod
metadata:
  name: nonroot-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
    - name: app
      image: nginx
      securityContext:
        allowPrivilegeEscalation: false
```

### CKV_K8S_8: Missing Liveness Probe

```yaml
# INSECURE: No health checks configured
apiVersion: v1
kind: Pod
metadata:
  name: no-probes
spec:
  containers:
    - name: app
      image: myapp:latest
      ports:
        - containerPort: 8080

---
# SECURE: Liveness and readiness probes configured
apiVersion: v1
kind: Pod
metadata:
  name: with-probes
spec:
  containers:
    - name: app
      image: myapp:latest
      ports:
        - containerPort: 8080
      livenessProbe:
        httpGet:
          path: /health
          port: 8080
        initialDelaySeconds: 30
        periodSeconds: 10
      readinessProbe:
        httpGet:
          path: /ready
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 5
```

### CKV_K8S_21: Using Default Namespace

```yaml
# INSECURE: Deploying to default namespace
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: default        # <- Issue: Default namespace

---
# SECURE: Using dedicated namespace
apiVersion: v1
kind: Namespace
metadata:
  name: myapp-production

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: myapp-production  # Dedicated namespace
```

### CKV_K8S_35: Secrets in Environment Variables

```yaml
# INSECURE: Hardcoded secrets in environment
apiVersion: v1
kind: Pod
metadata:
  name: hardcoded-secrets
spec:
  containers:
    - name: app
      image: myapp
      env:
        - name: DATABASE_PASSWORD
          value: "super-secret-password"  # <- Issue: Hardcoded secret

---
# SECURE: Using Kubernetes Secrets
apiVersion: v1
kind: Pod
metadata:
  name: using-secrets
spec:
  containers:
    - name: app
      image: myapp
      env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
```

### CKV_K8S_22: Read-Only Filesystem

```yaml
# INSECURE: Writable container filesystem
apiVersion: v1
kind: Pod
metadata:
  name: writable-fs
spec:
  containers:
    - name: app
      image: nginx

---
# SECURE: Read-only root filesystem with emptyDir volumes
apiVersion: v1
kind: Pod
metadata:
  name: readonly-fs
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        readOnlyRootFilesystem: true
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /var/cache/nginx
  volumes:
    - name: tmp
      emptyDir: {}
    - name: cache
      emptyDir: {}
```

---

## Dockerfile Patterns

### CKV_DOCKER_1: SSH Port Exposed

```dockerfile
# INSECURE: Exposing SSH port
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y openssh-server
EXPOSE 22        # <- Issue: SSH should not be in containers

# SECURE: No SSH, use kubectl exec or docker exec
FROM ubuntu:20.04
# Don't install or expose SSH
EXPOSE 8080      # Only expose application port
```

### CKV_DOCKER_3: Missing USER Instruction

```dockerfile
# INSECURE: Container runs as root
FROM python:3.9
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
# <- Issue: No USER instruction, runs as root

# SECURE: Create and use non-root user
FROM python:3.9
RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /app
COPY --chown=appuser:appuser . .
RUN pip install -r requirements.txt
USER appuser                 # Run as non-root
CMD ["python", "app.py"]
```

### CKV_DOCKER_7: Using Latest Tag

```dockerfile
# INSECURE: Using latest tag (mutable)
FROM python:latest           # <- Issue: Unpredictable, could change

# SECURE: Pin specific version
FROM python:3.9.18-slim      # Specific version
# Or use SHA digest for immutability
FROM python@sha256:1a2b3c4d5e6f...
```

### CKV_DOCKER_9: Using ADD Instead of COPY

```dockerfile
# INSECURE: ADD can execute remote URLs and extract archives
FROM ubuntu:20.04
ADD https://example.com/app.tar.gz /app/    # <- Issue: Security risk
ADD app.tar.gz /app/                         # <- Issue: Auto-extracts

# SECURE: Use COPY and explicit extraction
FROM ubuntu:20.04
COPY app.tar.gz /tmp/
RUN tar -xzf /tmp/app.tar.gz -C /app && rm /tmp/app.tar.gz
COPY local-files/ /app/
```

### CKV_DOCKER_10: Secrets in Dockerfile

```dockerfile
# INSECURE: Hardcoded secrets
FROM python:3.9
ENV DATABASE_PASSWORD=supersecret123    # <- Issue: Secret in image
ARG API_KEY=sk-12345                     # <- Issue: Secret in build args

# SECURE: Use runtime secrets
FROM python:3.9
# Pass secrets at runtime, not build time
# docker run -e DATABASE_PASSWORD=$SECRET myimage
# Or use Docker secrets / mounted files
```

### CKV_DOCKER_8: Package Manager Cache Not Cleaned

```dockerfile
# INSECURE: Leaves package manager cache
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3
# <- Issue: Cache files increase image size and attack surface

# SECURE: Clean up in same layer
FROM ubuntu:20.04
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
```

---

## GitHub Actions Patterns

### CKV_GHA_1: Shell Injection in Run Step

```yaml
# INSECURE: Unquoted user input in shell
name: Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.pull_request.title }}
      # <- Issue: Title could contain shell commands like `; rm -rf /`

# SECURE: Quote variables or use environment
name: Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$TITLE"
        env:
          TITLE: ${{ github.event.pull_request.title }}
```

### CKV_GHA_2: Unpinned Action Versions

```yaml
# INSECURE: Using mutable tags
steps:
  - uses: actions/checkout@v4      # <- Issue: v4 could change
  - uses: actions/setup-node@main  # <- Issue: main branch

# SECURE: Pin to specific SHA
steps:
  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
  - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8  # v4.0.2
```

### CKV2_GHA_1: Overly Permissive Workflow Permissions

```yaml
# INSECURE: Default write-all permissions
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    # <- Issue: No permissions block = write-all

# SECURE: Read-only permissions with explicit grants
name: Build
on: push
permissions:
  contents: read          # Minimal default
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write     # Only what's needed
```

---

## CloudFormation Patterns

### CKV_AWS_53: RDS Without Encryption

```yaml
# INSECURE: RDS instance without encryption
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      MasterUsername: admin
      MasterUserPassword: !Ref DBPassword
      # <- Issue: No StorageEncrypted property

# SECURE: RDS with encryption enabled
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      MasterUsername: admin
      MasterUserPassword: !Ref DBPassword
      StorageEncrypted: true
      KmsKeyId: !Ref MyKMSKey
```

### CKV_AWS_46: CloudWatch Logs Not Encrypted

```yaml
# INSECURE: Log group without KMS encryption
Resources:
  MyLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /my/app/logs
      # <- Issue: No KmsKeyId

# SECURE: Log group with KMS encryption
Resources:
  MyLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /my/app/logs
      KmsKeyId: !GetAtt LogEncryptionKey.Arn
      RetentionInDays: 90
```

---

## Common Remediation Patterns

### Encryption at Rest
- S3: Enable `ServerSideEncryptionConfiguration`
- EBS: Set `encrypted = true`
- RDS: Enable `StorageEncrypted`
- CloudWatch: Add `KmsKeyId`

### Encryption in Transit
- ALB/NLB: Use HTTPS listeners
- S3: Enforce `aws:SecureTransport` in bucket policy
- API Gateway: Require HTTPS/TLS

### Access Control
- Use principle of least privilege
- Avoid `*` in IAM policies
- Use specific resource ARNs
- Enable MFA for sensitive operations

### Network Security
- Restrict security group ingress to specific CIDRs
- Never open 22 (SSH) or 3389 (RDP) to 0.0.0.0/0
- Use VPC endpoints for AWS services

### Container Security
- Run as non-root user
- Use read-only root filesystem
- Add health checks (liveness/readiness probes)
- Pin image versions with SHA digests

---

## Detection Tips

When Checkov detects these patterns:

1. **Assess the risk** - Is this intentional or a misconfiguration?
2. **Check compensating controls** - Are there other security measures in place?
3. **Evaluate compliance requirements** - Does this violate any standards?
4. **Plan remediation** - Prioritize by severity and blast radius
5. **Test changes** - Validate fixes don't break functionality

## Learn More

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
