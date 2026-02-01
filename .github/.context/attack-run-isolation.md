# Running Untrusted Scripts Safely in Isolation

To run untrusted scripts safely, you must combine static analysis (checking the code) with dynamic sandboxing (isolating the execution). The following automated solution uses a Docker container with zero network access, a non-root user, and resource limits to prevent the script from damaging your host or leaking data.

## 1. The Sandbox Image (Dockerfile)

Create a file named `Dockerfile` in your working directory. This image includes all necessary runtimes but runs as a restricted user.

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

# Entrypoint will be set by the wrapper script
```

## 2. The Integrated Scanner & Sandbox (safe-run.sh)

This script first performs the "Red-Flag" check and then executes the code in the isolated Docker environment.

```bash
#!/bin/bash
# --- Configuration ---
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

echo "--- [STEP 1: STATIC SCAN] ---"
# Fast grep for critical danger patterns
DANGER_ZONE=("base64" "eval" "socket" "curl" "wget" "/dev/tcp" "IEX")
for pattern in "${DANGER_ZONE[@]}"; do
    grep -qi "$pattern" "$FILE" && echo -e "\033[0;31m[!] DANGER: Found '$pattern'\033[0m"
done

echo -e "\n--- [STEP 2: ISOLATED EXECUTION] ---"
echo "[*] Launching in network-isolated container..."

# Docker execution flags explained:
# --rm: Clean up container after exit
# --network none: Disable all internet/local network access
# --memory 128m: Prevent memory exhaustion attacks
# --cpus 0.5: Limit CPU to prevent system hang
# -v: Mount only the specific script as read-only

docker run --rm \
    --network none \
    --memory "128m" \
    --cpus "0.5" \
    --volume "$(pwd)/$FILE:/home/sandboxuser/target_script:ro" \
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

## Key Security Safeguards Provided

- **Network Isolation**: The `--network none` flag ensures that even if a script contains a reverse shell or data exfiltration logic, it cannot reach the outside world.
- **No Persistence**: The `--rm` flag and lack of persistent volume mounts mean any files the script tries to delete or modify are destroyed when the container closes.
- **Non-Root Execution**: The script runs as `sandboxuser`. Even if there is a "container escape" vulnerability, the attacker starts with no privileges on your host machine.
- **Read-Only Access**: The `:ro` flag on the volume mount prevents the script from modifying the original source file on your computer.

## Next Steps

Would you like to add a timeout feature to the script to automatically kill any process that runs longer than 30 seconds (preventing infinite loops or cryptominers)?
