# Secure Script Evaluation & Sandboxing Guide

This guide provides step-by-step instructions for safely executing potentially malicious scripts in isolated environments. Whether you're analyzing malware, testing suspicious code, or evaluating untrusted programs, these sandboxing techniques will protect your system from harm.

## Table of Contents
1. [Quick Start with Docker](#1-docker-sandbox-recommended)
2. [Windows Sandbox](#2-windows-sandbox)
3. [macOS Sandbox](#3-macos-sandbox)
4. [Linux Sandbox Options](#4-linux-sandbox-options)
5. [Static Analysis Pre-Check](#5-static-analysis-pre-check)
6. [Complete Audit Workflow](#6-recommended-audit-workflow)

---

## 1. Docker Sandbox (Recommended)

Docker provides the **easiest and most consistent** cross-platform isolation for testing untrusted scripts. It works on Linux, macOS, and Windows.

### Why Docker?
- ✅ Cross-platform (works everywhere)
- ✅ Network isolation built-in
- ✅ No permanent changes to your system
- ✅ Automatic cleanup after execution

### Quick Setup

#### Step 1: Create the Sandbox Image

Create a file named `Dockerfile`:

```dockerfile
# Use a lightweight base with multiple runtimes
FROM python:3.11-slim

# Install Node.js and basic tools
RUN apt-get update && apt-get install -y nodejs npm bash \
    && rm -rf /var/lib/apt/lists/*

# Create a non-privileged user for execution
RUN useradd -m sandboxuser
USER sandboxuser
WORKDIR /home/sandboxuser
```

Build the image:
```bash
docker build -t script-sandbox .
```

#### Step 2: Run Untrusted Scripts

Execute a script with full isolation:

```bash
# Python script
docker run --rm \
    --network none \
    --memory "128m" \
    --cpus "0.5" \
    -v "$(pwd)/suspicious_script.py:/home/sandboxuser/script.py:ro" \
    script-sandbox \
    python3 script.py

# JavaScript/Node.js script
docker run --rm \
    --network none \
    --memory "128m" \
    --cpus "0.5" \
    -v "$(pwd)/suspicious_script.js:/home/sandboxuser/script.js:ro" \
    script-sandbox \
    node script.js

# Shell script
docker run --rm \
    --network none \
    --memory "128m" \
    --cpus "0.5" \
    -v "$(pwd)/suspicious_script.sh:/home/sandboxuser/script.sh:ro" \
    script-sandbox \
    bash script.sh
```

#### Security Features Explained
- `--network none` → No internet access (blocks data exfiltration)
- `--memory "128m"` → Prevents memory exhaustion attacks
- `--cpus "0.5"` → Limits CPU usage (prevents system hang)
- `--rm` → Auto-cleanup after execution
- `:ro` → Read-only mount (script cannot modify itself)
- `USER sandboxuser` → Non-root execution

#### Automated Wrapper Script

Create `safe-run.sh` for easier usage:

```bash
#!/bin/bash
IMAGE_NAME="script-sandbox"
FILE=$1

if [[ -z "$FILE" || ! -f "$FILE" ]]; then
    echo "Usage: $0 <script_file>"
    exit 1
fi

# Build the sandbox if it doesn't exist
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]]; then
    echo "[*] Building security sandbox image..."
    docker build -t $IMAGE_NAME .
fi

echo "[*] Launching in network-isolated container..."

docker run --rm \
    --network none \
    --memory "128m" \
    --cpus "0.5" \
    -v "$(pwd)/$FILE:/home/sandboxuser/target_script:ro" \
    $IMAGE_NAME \
    /bin/bash -c "
        case '$FILE' in
            *.py)  python3 target_script ;;
            *.js)  node target_script ;;
            *.sh)  bash target_script ;;
            *)     echo 'Unsupported format' ;;
        esac
    "
```

Make it executable: `chmod +x safe-run.sh`

Usage: `./safe-run.sh suspicious_script.py`

---

## 2. Windows Sandbox

Windows Sandbox provides **hardware-level isolation** using Hyper-V virtualization. The environment is completely destroyed after each use.

### Requirements
- Windows 10 Pro/Enterprise (Build 18362+) or Windows 11
- Virtualization enabled in BIOS
- At least 4GB RAM

### Setup

#### Step 1: Enable Windows Sandbox
1. Open **Turn Windows features on or off**
2. Check **Windows Sandbox**
3. Restart your computer

#### Step 2: Create Configuration File

Create `test-script.wsb`:

```xml
<Configuration>
  <Networking>Disable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Scripts</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File C:\Users\WDAGUtilityAccount\Desktop\Scripts\suspicious.ps1</Command>
  </LogonCommand>
</Configuration>
```

#### Step 3: Launch Sandbox

**Option A:** Double-click the `.wsb` file

**Option B:** Command line:
```powershell
start test-script.wsb
```

**Option C:** Manual launch:
```powershell
# Start Windows Sandbox
WindowsSandbox.exe
```

### Key Features
- ✅ Complete OS isolation (VM-level)
- ✅ Automatic cleanup on close
- ✅ Network can be disabled
- ✅ Read-only folder mapping

---

## 3. macOS Sandbox

macOS uses the **Seatbelt** framework for application sandboxing via the `sandbox-exec` command.

### Basic Usage

```bash
# Deny network access and file system access
sandbox-exec -p '(version 1) (deny default) (allow process*)' python3 suspicious_script.py
```

### Network Isolation Profile

```bash
sandbox-exec -p "(version 1)
                 (allow default)
                 (deny network*)" \
    python3 suspicious_script.py
```

### File System Protection

Protect sensitive directories:

```bash
sandbox-exec -p "(version 1)
                 (allow default)
                 (deny network*)
                 (deny file-read* (regex #\"^/Users/$USER/(Documents|Desktop|Downloads)\"))
                 (deny file-write* (regex #\"^/Users\"))" \
    bash suspicious_script.sh
```

### Complete Lockdown Profile

Create `lockdown.sb`:

```scheme
(version 1)
(deny default)
(allow process*)
(allow sysctl-read)
(deny network*)
(deny file-write*)
(allow file-read* (literal "/dev/null"))
(allow file-read* (literal "/dev/random"))
(allow file-read* (literal "/dev/urandom"))
```

Use it:
```bash
sandbox-exec -f lockdown.sb python3 suspicious_script.py
```

### Advanced Tool: Alcoholless

For more user-friendly CLI sandboxing on macOS:
```bash
# Install via Homebrew
brew install alcoholless

# Use it
alcoholless --no-network python3 suspicious_script.py
```

---

## 4. Linux Sandbox Options

Linux offers multiple native sandboxing methods, from simple to advanced.

### Option A: Firejail (Easiest)

**Firejail** is the most user-friendly option with pre-made security profiles.

Install:
```bash
# Debian/Ubuntu
sudo apt install firejail

# Fedora
sudo dnf install firejail

# Arch
sudo pacman -S firejail
```

Usage:
```bash
# Basic isolation
firejail python3 suspicious_script.py

# No network access
firejail --net=none python3 suspicious_script.py

# Private /tmp and no network
firejail --net=none --private-tmp bash suspicious_script.sh
```

### Option B: Bubblewrap (Most Secure)

**Bubblewrap** (bwrap) is used by Flatpak and requires no sudo for execution.

Install:
```bash
# Debian/Ubuntu
sudo apt install bubblewrap

# Fedora
sudo dnf install bubblewrap
```

Usage:
```bash
bwrap --unshare-all \
      --share-net none \
      --tmpfs /tmp \
      --ro-bind /usr /usr \
      --ro-bind /lib /lib \
      --ro-bind /lib64 /lib64 \
      --bind . /home/sandboxuser \
      bash ./suspicious_script.sh
```

**Key flags:**
- `--unshare-all` → Strip all privileges
- `--share-net none` → Disable network
- `--ro-bind` → Read-only bind mount

### Option C: unshare (Direct Kernel Method)

**unshare** is built into Linux and requires no installation.

```bash
# Network-isolated execution
unshare --user --map-root-user --net --mount --pid --fork --mount-proc \
    bash ./suspicious_script.sh
```

**Verify isolation:**
```bash
# Inside the sandbox, these should fail:
ping google.com  # No network
ps aux          # Can't see host processes
```

### Option D: systemd-run (Modern SystemD Method)

**systemd-run** leverages cgroups for resource control.

```bash
systemd-run --user --scope \
    -p PrivateNetwork=yes \
    -p PrivateTmp=yes \
    -p ProtectHome=read-only \
    -p ProtectSystem=strict \
    bash ./suspicious_script.sh
```

**Security features:**
- `PrivateNetwork=yes` → Network namespace isolation
- `ProtectHome=read-only` → Can't modify /home
- `ProtectSystem=strict` → /usr, /boot, /etc read-only

### Option E: Chroot + Unshare (Maximum Isolation)

Create a minimal filesystem jail:

```bash
# Create jail directory
mkdir -p jail/{bin,lib,lib64,usr}
cp /bin/bash jail/bin/
ldd /bin/bash  # Copy required libraries to jail/lib

# Execute in jail
sudo unshare --net --uts --mount --pid --fork \
    chroot /path/to/jail /bin/bash
```

### Option F: NSJail (Google's Advanced Sandbox)

**NSJail** provides precision sandboxing with detailed resource limits.

Install:
```bash
git clone https://github.com/google/nsjail.git
cd nsjail
make
sudo make install
```

Usage:
```bash
nsjail --chroot /tmp \
       --user 99999 \
       --group 99999 \
       -R /bin \
       -R /lib \
       -R /usr \
       --time_limit 30 \
       -- /bin/bash suspicious_script.sh
```

### Linux Comparison Table

| Tool | Difficulty | Use Case |
|------|-----------|----------|
| **Firejail** | Easy | Quick isolation for everyday scripts |
| **Bubblewrap** | Medium | High-security unprivileged sandboxing |
| **unshare** | Medium | Raw kernel namespace experimentation |
| **systemd-run** | Medium | Resource limits + OS-level security |
| **Chroot** | Hard | Complete filesystem isolation |
| **NSJail** | Hard | Precision isolation for automation |

---

## 5. Static Analysis Pre-Check

Before running any script in a sandbox, perform a quick static analysis to identify dangerous patterns.

### Critical Red Flags

| Attack Vector | Patterns to Watch For |
|--------------|----------------------|
| **Persistence** | `crontab`, `reg add`, `LaunchAgents`, `systemd` units |
| **Exfiltration** | `curl`, `wget`, `requests.post`, `Invoke-RestMethod`, `/dev/tcp` |
| **Remote Access** | `socket.connect`, `net.connect`, `bash -i >& /dev/tcp` |
| **Obfuscation** | `base64`, `eval()`, `iex`, `EncodedCommand`, `b64decode` |
| **Destruction** | `rm -rf /`, `vssadmin delete shadows`, `os.rename` |

### Quick Grep Check

```bash
# Check for dangerous patterns
FILE="suspicious_script.py"
PATTERNS=("base64" "eval" "socket" "curl" "wget" "/dev/tcp" "rm -rf")

for pattern in "${PATTERNS[@]}"; do
    grep -qi "$pattern" "$FILE" && echo "[!] DANGER: Found '$pattern'"
done
```

### Automated Security Scanners

Use these tools for comprehensive analysis:

```bash
# Python scripts
bandit suspicious_script.py

# Shell scripts
shellcheck suspicious_script.sh

# General source code
graudit -d default suspicious_script.py

# Python/Node.js packages
guarddog scan suspicious_package/
```

---

## 6. Recommended Audit Workflow
---

## Platform Comparison Summary

| Platform | Tool | Primary Benefit | Difficulty |
|----------|------|----------------|-----------|
| **All** | Docker | Cross-platform, consistent | Easy |
| **Windows** | Windows Sandbox | VM-level isolation, auto-cleanup | Easy |
| **macOS** | sandbox-exec | Native OS integration | Medium |
| **Linux** | Firejail | User-friendly, pre-made profiles | Easy |
| **Linux** | Bubblewrap | No sudo required, very secure | Medium |
| **Linux** | unshare | Direct kernel access, no dependencies | Hard |

---

## Quick Reference Commands

### Docker
```bash
docker run --rm --network none -v "$(pwd)/script.py:/script.py:ro" script-sandbox python3 /script.py
```

### Windows
```powershell
start test-script.wsb
```

### macOS
```bash
sandbox-exec -p '(version 1) (deny default) (allow process*) (deny network*)' python3 script.py
```

### Linux (Firejail)
```bash
firejail --net=none --private-tmp python3 script.py
```

### Linux (Bubblewrap)
```bash
bwrap --unshare-all --share-net none --tmpfs /tmp bash script.sh
```

---

## Additional Resources

- **MITRE ATT&CK Framework:** [attack.mitre.org](https://attack.mitre.org)
- **Docker Security:** [docs.docker.com/engine/security](https://docs.docker.com/engine/security/)
- **Apple Sandbox Guide:** [developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide)
- **Linux Namespaces:** [man7.org/linux/man-pages/man7/namespaces.7.html](https://man7.org/linux/man-pages/man7/namespaces.7.html)

---

**⚠️ Important:** Always assume untrusted scripts are malicious. Never run them on production systems or with access to sensitive data, even in a sandbox. 