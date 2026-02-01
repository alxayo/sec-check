# Attack Detection Checklist

To automate the detection of the attack vectors previously identified, you should implement a multi-layered scanning pipeline. This checklist combines **Static Analysis (SAST)** to find suspicious code patterns and **Dynamic Analysis (Sandboxing)** to observe actual behavior without risking your host system.

## Phase 1: Automated Static Analysis (SAST)

Before executing any script, run it through these automated scanners to flag dangerous functions and suspicious syntax.

### Python
- Use **Bandit** to find common security issues like `eval()`, `subprocess.Popen(shell=True)`, and hardcoded passwords.
- Use **Semgrep** with security-focused rulesets to detect data exfiltration patterns.

### Node.js
- Run `npm audit` to check for known vulnerabilities in third-party dependencies.
- Use **ESLint** with security plugins (e.g., `eslint-plugin-security`) to flag dangerous methods like `child_process.exec()`.

### PowerShell
- Use **PSScriptAnalyzer** to identify risky cmdlets like `Invoke-Expression` (IEX) and `Set-ExecutionPolicy`.

### Bash
- Use **ShellCheck** to detect common scripting errors that could lead to security holes, such as unquoted variables that allow command injection.
- Use **Graudit**, a grep-based tool, to search for high-risk signatures like `/dev/tcp/`.

## Phase 2: Behavioral Observation (Sandboxing)

If the static scan passes but you still have doubts, run the script in a controlled environment to monitor its actions.

### Execution Monitoring
- Use **ANY.RUN** to execute scripts in an interactive cloud sandbox. It provides a visual process tree and maps behaviors directly to the MITRE ATT&CK Framework.
- On Windows, use **Microsoft Process Monitor (ProcMon)** to record real-time file system, registry, and network activity.

### Network Containment
- Run the script inside a Docker container with restricted networking (`--network none`) to prevent any potential data exfiltration or reverse shell attempts.

## Phase 3: High-Risk Pattern Checklist

Configure your automated tools (or a custom script) to flag these specific keywords across all languages:

### Obfuscation
- `base64`, `b64decode`, `EncodedCommand`, `char()`, `eval()`

### Network Calls
- `curl`, `wget`, `socket`, `Invoke-WebRequest`, `requests.post`, `net.connect`

### File Access
- Sensitive paths like `/etc/shadow`, `~/.ssh/`, `~/.aws/`, and Windows Registry keys

### System Modification
- `sudo`, `crontab`, `Set-ItemProperty`, `rm -rf`, `vssadmin` (which deletes backups) 