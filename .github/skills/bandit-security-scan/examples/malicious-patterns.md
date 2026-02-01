# Malicious Patterns Detected by Bandit

This document shows code patterns that Bandit detects, useful for understanding what the tool catches.

## Dangerous Function Calls

### B102: exec() Usage
```python
# DETECTED: Code execution via exec
user_input = input("Enter code: ")
exec(user_input)  # B102: Use of exec detected

# DETECTED: Dynamic code execution
code = compile(source, '<string>', 'exec')
exec(code)  # B102
```

### B307: eval() Usage
```python
# DETECTED: Arbitrary code execution
user_expression = request.args.get('expr')
result = eval(user_expression)  # B307: Use of eval detected

# DETECTED: eval in data processing
data = eval(config_string)  # B307
```

## Hardcoded Credentials

### B105/B106/B107: Password Detection
```python
# DETECTED: Hardcoded password string
password = "SuperSecret123!"  # B105: Possible hardcoded password

# DETECTED: Password in function argument
connect(host="db.example.com", password="admin123")  # B106

# DETECTED: Default password parameter
def login(user, password="default"):  # B107: Possible hardcoded password
    pass
```

## Insecure Deserialization

### B301: Pickle Usage
```python
import pickle

# DETECTED: Unsafe deserialization
with open('data.pkl', 'rb') as f:
    data = pickle.load(f)  # B301: Pickle usage detected

# DETECTED: Loading untrusted pickle data
user_data = pickle.loads(request.data)  # B301
```

### B506: Unsafe YAML Load
```python
import yaml

# DETECTED: Unsafe YAML loading
with open('config.yaml') as f:
    config = yaml.load(f)  # B506: Use of unsafe yaml load

# SAFE: Using safe_load
config = yaml.safe_load(f)  # Not flagged
```

## Shell Injection

### B602: Shell=True in subprocess
```python
import subprocess

# DETECTED: Shell injection risk
user_cmd = input("Command: ")
subprocess.call(user_cmd, shell=True)  # B602: subprocess with shell=True

# DETECTED: Variable in shell command
filename = request.args.get('file')
subprocess.Popen(f"cat {filename}", shell=True)  # B602
```

### B605: os.system() Usage
```python
import os

# DETECTED: Command injection
user_file = input("Filename: ")
os.system(f"rm {user_file}")  # B605: Starting process with shell

# DETECTED: Unsanitized input
os.system("grep " + search_term + " /var/log/*")  # B605
```

## SQL Injection

### B608: Hardcoded SQL Expressions
```python
# DETECTED: SQL injection vulnerability
user_id = request.args.get('id')
query = "SELECT * FROM users WHERE id = " + user_id  # B608: SQL injection
cursor.execute(query)

# DETECTED: f-string SQL injection
query = f"SELECT * FROM users WHERE name = '{username}'"  # B608
cursor.execute(query)

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # Not flagged
```

## Weak Cryptography

### B303: MD5/SHA1 for Security
```python
import hashlib

# DETECTED: Weak hash for password
password_hash = hashlib.md5(password.encode()).hexdigest()  # B303

# DETECTED: SHA1 for security purposes
token = hashlib.sha1(secret.encode()).hexdigest()  # B303
```

### B304/B305: Insecure Cipher Usage
```python
from Crypto.Cipher import DES, AES

# DETECTED: Insecure cipher
cipher = DES.new(key, DES.MODE_ECB)  # B304: Use of insecure cipher

# DETECTED: Insecure mode
cipher = AES.new(key, AES.MODE_ECB)  # B305: Use of insecure cipher mode
```

## Network Security Issues

### B501: No Certificate Validation
```python
import requests

# DETECTED: SSL verification disabled
response = requests.get(url, verify=False)  # B501: No cert validation

# DETECTED: In session
session = requests.Session()
session.verify = False  # B501
```

### B104: Binding to All Interfaces
```python
# DETECTED: Binding to 0.0.0.0
app.run(host="0.0.0.0", port=5000)  # B104: Hardcoded bind all interfaces

# DETECTED: Socket binding
sock.bind(("0.0.0.0", 8080))  # B104
```

## Web Framework Issues

### B201: Flask Debug Mode
```python
from flask import Flask
app = Flask(__name__)

# DETECTED: Debug mode in production
app.run(debug=True)  # B201: Flask debug=True

# DETECTED: Debug in config
app.config['DEBUG'] = True  # B201
```

### B701: Jinja2 Autoescape Disabled
```python
from jinja2 import Environment

# DETECTED: XSS vulnerability
env = Environment(autoescape=False)  # B701: Jinja2 autoescape disabled

# SAFE: Autoescape enabled
env = Environment(autoescape=True)  # Not flagged
```

## Data Exfiltration Patterns

### B310: URL Open with User Input
```python
import urllib.request

# DETECTED: SSRF potential
user_url = input("URL: ")
response = urllib.request.urlopen(user_url)  # B310: urllib URL open

# DETECTED: Arbitrary URL fetch
urllib.request.urlopen(request.args.get('callback'))  # B310
```

### B312: Telnet Usage
```python
import telnetlib

# DETECTED: Insecure protocol
tn = telnetlib.Telnet(host)  # B312: Telnet usage (unencrypted)
```

## Temporary File Issues

### B108: Hardcoded Temp Directory
```python
# DETECTED: Predictable temp file
temp_file = "/tmp/myapp_cache"  # B108: Hardcoded temp directory

# SAFE: Using tempfile module
import tempfile
temp_file = tempfile.mktemp()  # Proper temp file handling
```

### B306: mktemp Usage
```python
import tempfile

# DETECTED: Race condition vulnerability
filename = tempfile.mktemp()  # B306: Use of mktemp (deprecated)

# SAFE: Using mkstemp
fd, filename = tempfile.mkstemp()  # Not flagged
```
