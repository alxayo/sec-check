---
name: sechek.supply-chain-security-scan
description: Scan dependencies for supply chain attacks, typosquatting, and malicious packages
agent: sechek.security-scanner
model: Claude Sonnet 4.5
---

# Supply Chain Security Scan

Run a supply chain security scan on this workspace:

## Python Dependencies

Use guarddog to verify all Python dependencies:
- `requirements.txt`
- `setup.py`
- `pyproject.toml`

## Node.js Dependencies

Use guarddog to verify all Node.js dependencies:
- `package.json`
- `package-lock.json`

## Check For

- Typosquatting package names
- Known malicious packages
- Suspicious install/post-install scripts
- Dependency confusion risks

Save findings to `.github/.audit/scan-results.md` with remediation steps.
