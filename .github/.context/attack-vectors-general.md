Running scripts locally grants them the same privileges as your user account, allowing them to bypass many traditional security layers. Below is a precise list of attack vectors categorized by their impact, mapped to common scripting languages and the MITRE ATT&CK Framework.

## 1. Execution & Persistence (Staying on the System)

- **Command & Scripting Interpreter (T1059):** Scripts use native tools like powershell.exe or node.exe to execute malicious logic without downloading external binaries, often called "Living off the Land".
- **Scheduled Task/Job (T1053):** Modifying crontabs (Bash) or creating Windows Scheduled Tasks (PowerShell) to ensure the script runs every time you reboot or log in.
- **Registry Run Keys / Startup Folder (T1547.001):** Modifying the Windows Registry to launch a script automatically on startup.

## 2. Data Exfiltration & Credential Theft

- **Credentials from Password Stores (T1555):** Python or Node.js scripts can easily access browser profile folders (e.g., Chrome/Firefox) to steal saved passwords, cookies, and session tokens.
- **Search Local System (T1005):** Bash and Python are frequently used to scan the file system for sensitive files like .ssh/id_rsa, .env files, or .aws/credentials.
- **Exfiltration Over C2 Channel (T1041):** Data is sent to an external server by embedding it in HTTP headers or using standard protocols like curl, wget, or Python's requests library.

## 3. Remote Access & Backdoors

- **Reverse Shells:** A single line in Python or Bash can open a connection to a remote server, giving an attacker a command prompt on your machine.
- **Non-Standard Port Communication:** Scripts may use WebSockets or raw TCP/UDP sockets to create stealthy tunnels that bypass simple firewalls.
- **Protocol Tunneling (T1572):** Encapsulating commands within standard DNS or HTTP traffic to hide a remote control session.

## 4. Defense Evasion (Hiding the Malice)

- **Obfuscated Files or Information (T1027):** Using Base64 encoding, string manipulation (e.g., $a='p'; $b='s'; &$a$b...), or character replacement to hide keywords like "download" or "socket".
- **Fileless Execution:** Running code directly in memory using PowerShell's Invoke-Expression (IEX) or Node's eval(), leaving no physical file for antivirus to scan.

## 5. System Impact & Destruction

- **Inhibit System Recovery (T1490):** PowerShell scripts can delete Volume Shadow Copies to prevent you from restoring files after a destructive action.
- **Account Lockout:** Modifying security policies or repeatedly attempting logins to lock you out of your own administrative account.
- **Data Destruction (T1485):** Simple recursive deletion commands (e.g., rm -rf / or Remove-Item -Recurse) that target user documents or system configuration files.

## Specific Code Review Red Flags

| Language | Watch out for... |
| --- | --- |
| Bash | curl \| bash, base64 -d, uses of /dev/tcp/, and sudo commands. |
| PowerShell | IEX, DownloadString, EncodedCommand, and Set-ExecutionPolicy. |
| Python | os.system(), subprocess.Popen(), requests.post(), and eval(). |
| Node.js | child_process.exec(), fs.writeFile() to system paths, and vm.runInContext(). |