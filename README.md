# Sec-Check

![sec-check agent](media/sec-check.png)

Scan untrusted code for red flags before you run it—exfiltration, reverse shells, backdoors, and supply-chain traps.

Available as a **VS Code Copilot toolkit** (interactive) AND as a **standalone CLI tool** (automated).

## What It Does

Sec-Check provides security scanning capabilities to detect dangerous patterns in code—credential theft, reverse shells, backdoors, and supply chain attacks. Use it to review scripts from the internet or untrusted sources before execution.

> :warning: **Warning**: This tool catches common red flags, not sophisticated attacks. Always use manual review and sandboxing for high-risk code.

---

![sec-check](media/sec-check.jpeg)

[View results of a full scan here](audit-results/scan-results.md)

---

## Components

### VS Code Copilot Toolkit

#### Custom Agent

**`@sechek.security-scanner`** — Malicious Code Scanner Agent

Deep security analysis with pattern detection and remediation guidance. Detects:
- Data exfiltration and credential theft
- Reverse shells and backdoors
- Persistence mechanisms (cron, registry)
- Obfuscated payloads (base64, eval)
- System destruction patterns

Can operate standalone or use security scanning tools (Bandit, GuardDog, ShellCheck, Graudit) when available.

---

#### Security Skills

Skills teach Copilot how to use specific security tools:

| Skill | Purpose | Use For |
|-------|---------|---------|
| **bandit-security-scan** | Python AST-based security analysis | Python code vulnerabilities, dangerous functions (eval, exec, pickle), SQL injection |
| **checkov-security-scan** | Infrastructure as Code security analysis | Terraform, CloudFormation, Kubernetes manifests, Dockerfiles, cloud misconfigurations, IAM policies |
| **dependency-check-security-scan** | Software Composition Analysis (SCA) for known CVEs | Java, .NET, JavaScript, Python, Ruby, Go dependencies, NVD/CISA KEV vulnerability detection |
| **eslint-security-scan** | JavaScript/TypeScript security analysis | JS/TS code vulnerabilities, code injection, XSS, command injection, ReDoS, prototype pollution |
| **guarddog-security-scan** | Supply chain & malware detection | Dependencies (`requirements.txt`, `package.json`), typosquatting, malicious packages |
| **shellcheck-security-scan** | Shell script static analysis | Bash/sh scripts, command injection, unquoted variables |
| **graudit-security-scan** | Multi-language pattern matching | Quick scans on unknown codebases, secrets detection, 15+ languages |
| **trivy-security-scan** | Container, IaC, CVE & secret scanning | Container images, filesystem dependencies, Kubernetes clusters, IaC misconfigurations, hardcoded secrets, SBOM generation |

---

#### Custom Prompts

| Prompt | When to Use |
|--------|-------------|
| **`/sechek.tools-advisor`** | Get recommendations on which tools to run based on your codebase |
| **`/sechek.tools-scan`** | Execute security tools and save results to `tools-audit.md` |
| **`/sechek.security-scan`** | Full workspace scan with the security scanner agent |
| **`/sechek.security-scan-quick`** | Fast scan for malicious patterns, exfiltration, reverse shells |
| **`/sechek.security-scan-python`** | Python-focused scan using Bandit and GuardDog |
| **`/sechek.security-scan-iac`** | Infrastructure as Code scan using Checkov for cloud misconfigurations |
| **`/sechek.security-scan-shell`** | Shell script scan using ShellCheck and Graudit |
| **`/sechek.security-scan-supply-chain`** | Scan dependencies for supply chain attacks |
| **`/sechek.security-scan-precommit`** | Pre-commit check for secrets and vulnerabilities |
| **`/sechek.plan-fix`** | Generate a prioritized remediation plan from scan results |
| **`/create-security-skill`** | Create a new security scanning skill from tool documentation |

---

#### Security Remediation Planning

After running security scans, use `/sechek.plan-fix` to generate a detailed remediation plan with prioritized tasks, timelines, and fix patterns.

![Security Remediation Planning](media/sec-plan.png)

[View a sample remediation plan here](audit-results/remediation-tasks.md)

The plan includes:
- **Prioritized tasks** grouped by severity (Critical -> High -> Medium -> Low)
- **SLA timelines** (24 hours for Critical, 1 week for High, etc.)
- **Fix patterns** with vulnerable vs. secure code examples
- **Parallel execution opportunities** to speed up remediation
- **Verification commands** to confirm fixes

---

### Standalone CLI Tool (AgentSec)

AgentSec is a standalone CLI tool built with the GitHub Copilot SDK that automates security scanning programmatically.

#### Prerequisites

- Python 3.12+ (3.11 minimum)
- GitHub Copilot subscription
- GitHub Copilot CLI installed and authenticated

#### Quick Start

```bash
# Install packages
pip install -e ./core
pip install -e ./cli

# Scan a folder
agentsec scan ./test-scan

# Scan with parallel mode
agentsec scan ./test-scan --parallel

# See all options
agentsec --help
```

#### What Gets Scanned

AgentSec uses **Copilot CLI built-in tools** (`bash`, `skill`, `view`) to invoke real security scanners and analyze your code. The agent follows a structured workflow:

1. **File Discovery** — Uses `bash` with `find` to discover all files in the target folder
2. **Security Scanning** — Invokes Copilot CLI agentic skills and/or runs scanner CLIs directly:
   - **bandit** for Python AST security analysis
   - **graudit** for multi-language pattern-based auditing
   - **guarddog** for supply chain / malicious package detection
   - **shellcheck** for shell script analysis
   - **trivy** for container & filesystem scanning
   - **eslint** for JavaScript/TypeScript security
   - And more (checkov, dependency-check, template-analyzer)
3. **Manual Inspection** — Uses `view` to read suspicious files for deeper LLM analysis
4. **Report Generation** — Compiles all findings into a structured Markdown report with severity levels, line numbers, code snippets, and remediation advice

#### Parallel Scanning Mode

By default, AgentSec runs all scanners sequentially in a single LLM session. With `--parallel`, it uses a **sub-agent orchestration** pattern that runs multiple scanners concurrently for faster results:

```bash
# Run available scanners in parallel (default: 3 concurrent)
agentsec scan ./my_project --parallel

# Allow up to 5 scanners at once
agentsec scan ./my_project --parallel --max-concurrent 5
```

**How parallel mode works** (3-phase workflow):

1. **Discovery** — Walks the target folder, classifies files by type, determines which scanners are relevant and available, builds a scan plan
2. **Parallel Scan** — Spawns one sub-agent session per relevant scanner. Each session focuses on exactly one scanner tool. Sessions run concurrently via `asyncio.gather` with a semaphore to cap parallelism
3. **Synthesis** — Feeds all sub-agent findings into a synthesis session that deduplicates, normalizes severity, and compiles a single consolidated Markdown report

#### Reliability Features

- **Activity-based stall detection**: Monitors SDK events continuously; nudges are sent after 120s of inactivity; after 3 unresponsive nudges the session is aborted
- **Transient error retry**: Rate limits (429), 5xx, and other transient session errors are automatically retried with exponential backoff
- **Configurable timeout**: Default 1800s safety ceiling; partial results returned on timeout
- **Safety guardrails**: System message prevents execution of scanned code, blocks dangerous commands, and defends against prompt injection
- **Dynamic system message**: Available scanner skills are discovered at runtime and injected into the system message
- **Per-sub-agent isolation** (parallel mode): Each sub-agent runs in its own session; failures in one scanner don't affect others

#### Progress Tracking

AgentSec provides real-time progress feedback during scans:

```
Spinning Starting security scan of ./my_project

  folder Found 15 files to scan

  Spinning [progress bar] 50% Scanning (8/15): app.py
  warning Finished app.py: 2 issues found

check Scan complete: 15 files scanned, 5 issues found (23s)
```

#### Configuration

AgentSec can be configured via:

1. **YAML config file** (`agentsec.yaml`) — Set default system message and initial prompt
2. **CLI arguments** — Override config file settings per-run
3. **External prompt files** — Store long prompts in separate files

See [agentsec.example.yaml](agentsec.example.yaml) for a full example with comments.

**CLI Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--config FILE` | `-c` | Path to YAML config file |
| `--system-message TEXT` | `-s` | Override system message |
| `--system-message-file FILE` | `-sf` | Load system message from file |
| `--prompt TEXT` | `-p` | Override initial prompt template |
| `--prompt-file FILE` | `-pf` | Load initial prompt from file |
| `--parallel` | | Run scanners concurrently as sub-agents |
| `--max-concurrent N` | | Max parallel scanners (default 3, requires `--parallel`) |
| `--verbose` | `-v` | Enable debug logging |
| `--timeout SECONDS` | | Safety ceiling timeout (default 1800) |
| `--model MODEL` | `-m` | Override LLM model (default gpt-5) |

---

## Quick Start

### Option A: VS Code Copilot Toolkit

```
/sechek.security-scan
```
Runs comprehensive analysis using available tools and pattern detection.

**Targeted Scans:**
```
/sechek.security-scan-python       # Python code
/sechek.security-scan-shell        # Shell scripts
/sechek.security-scan-supply-chain # Dependencies
```

**Tool Workflow:**
```
/sechek.tools-advisor              # Get tool recommendations
/sechek.tools-scan ./src           # Run recommended tools
@sechek.security-scanner           # Deep analysis with tool output
```

### Option B: Standalone CLI

```bash
# Install
pip install -e ./core
pip install -e ./cli

# Scan
agentsec scan ./test-scan

# Parallel mode
agentsec scan ./test-scan --parallel
```

For detailed setup instructions, see [SETUP.md](SETUP.md).

---

## Output

| File | Generated By | Contents |
|------|--------------|----------|
| `.github/.audit/tools-audit.md` | `/sechek.tools-scan` | Raw tool output |
| `.github/.audit/scan-results.md` | `@sechek.security-scanner` | Analysis with findings & remediation |

---

## Repository Structure

```
.github/
+-- copilot-instructions.md          # AI coding guide (comprehensive)
+-- agents/
|   +-- sechek.malicious-code-scanner.agent.md  # Security scanner agent
|   +-- implementation.agent.md                 # Dev task agent
|   +-- orchestrator.agent.md                   # Dev orchestrator agent
|   +-- context/                                # SDK reference docs
+-- skills/
|   +-- copilot-sdk/                            # SDK development skill
|   +-- bandit-security-scan/                   # Python security
|   +-- checkov-security-scan/                  # IaC security
|   +-- dependency-check-security-scan/         # SCA / CVE detection
|   +-- eslint-security-scan/                   # JavaScript/TypeScript
|   +-- guarddog-security-scan/                 # Supply chain
|   +-- shellcheck-security-scan/               # Shell scripts
|   +-- graudit-security-scan/                  # Multi-language
|   +-- trivy-security-scan/                    # Container & cloud-native
+-- prompts/                                    # Custom prompts
+-- .context/                                   # Attack patterns reference
core/                                           # SDK agent library (Python)
+-- agentsec/
|   +-- agent.py, config.py, orchestrator.py
|   +-- session_runner.py, session_logger.py
|   +-- skill_discovery.py, tool_health.py
|   +-- progress.py, skills.py
+-- tests/
cli/                                            # CLI wrapper (Python)
+-- agentsec_cli/main.py
spec/                                           # Architecture docs
research/                                       # Security research notes
audit-results/                                  # Example scan reports
test-scan/                                      # Test data
```

---

## Setup & Development

See [SETUP.md](SETUP.md) for detailed setup instructions, including virtual environment creation, package installation, and development workflow.

For the architecture guide and SDK patterns, see [.github/copilot-instructions.md](.github/copilot-instructions.md).

---

## Limitations

- Pattern-based detection only—may miss obfuscated or novel attacks
- No guarantee of safety—use as first-pass filter, not final decision
- Requires manual review for context-dependent vulnerabilities

For production or high-security environments, combine with professional security audits and isolated testing.

## License

Coming soon.
